//! Property-based tests for range proof soundness and completeness

use crate::{RangeProver, RangeVerifier, RangeProof};
use bulletproofs_core::GeneratorSet;
use proptest::prelude::*;
use rand::thread_rng;

/// Test that valid range proofs always verify
proptest! {
    #[test]
    fn test_completeness(
        value in 0u64..256,
        bit_length in 8usize..16,
    ) {
        // Only test values that are actually in range
        prop_assume!(value < (1u64 << bit_length));
        
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, bit_length * 2);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        // Generate and verify proof
        let proof = prover.prove_range(value, bit_length, None, &mut rng)?;
        prop_assert!(verifier.verify_range(&proof, bit_length).is_ok());
    }
}

/// Test that out-of-range values cannot be proven
proptest! {
    #[test]
    fn test_soundness_out_of_range(
        bit_length in 1usize..8,
        excess in 1u64..1000,
    ) {
        let max_value = (1u64 << bit_length) - 1;
        let invalid_value = max_value.saturating_add(excess);
        
        // Skip if overflow would occur
        prop_assume!(invalid_value > max_value);
        
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, bit_length * 2);
        
        // Should fail to generate proof for out-of-range value
        prop_assert!(prover.prove_range(invalid_value, bit_length, None, &mut rng).is_err());
    }
}

/// Test that proofs for different bit lengths don't cross-verify
proptest! {
    #[test]
    fn test_bit_length_specificity(
        value in 0u64..64,
        prove_bits in 6usize..10,
        verify_bits in 6usize..10,
    ) {
        prop_assume!(prove_bits != verify_bits);
        prop_assume!(value < (1u64 << prove_bits.min(verify_bits)));
        
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, prove_bits.max(verify_bits) * 2);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        // Generate proof with one bit length
        let proof = prover.prove_range(value, prove_bits, None, &mut rng)?;
        
        // Should fail when verifying with different bit length
        prop_assert!(verifier.verify_range(&proof, verify_bits).is_err());
    }
}

/// Test consistency across multiple proofs of the same value
proptest! {
    #[test]
    fn test_consistency(
        value in 0u64..128,
        bit_length in 7usize..12,
    ) {
        prop_assume!(value < (1u64 << bit_length));
        
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, bit_length * 2);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        // Generate multiple proofs for the same value
        let proof1 = prover.prove_range(value, bit_length, None, &mut rng)?;
        let proof2 = prover.prove_range(value, bit_length, None, &mut rng)?;
        
        // Both should verify
        prop_assert!(verifier.verify_range(&proof1, bit_length).is_ok());
        prop_assert!(verifier.verify_range(&proof2, bit_length).is_ok());
        
        // Proofs should be different (probabilistic due to randomness)
        prop_assert_ne!(proof1.to_bytes(), proof2.to_bytes());
    }
}

/// Test edge cases: minimum and maximum values
proptest! {
    #[test]
    fn test_edge_cases(bit_length in 1usize..16) {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, bit_length * 2);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        // Test minimum value (0)
        let proof_min = prover.prove_range(0, bit_length, None, &mut rng)?;
        prop_assert!(verifier.verify_range(&proof_min, bit_length).is_ok());
        
        // Test maximum value for this bit length
        if bit_length < 64 { // Avoid overflow
            let max_value = (1u64 << bit_length) - 1;
            let proof_max = prover.prove_range(max_value, bit_length, None, &mut rng)?;
            prop_assert!(verifier.verify_range(&proof_max, bit_length).is_ok());
        }
    }
}

/// Test proof serialization and deserialization
proptest! {
    #[test]
    fn test_serialization_roundtrip(
        value in 0u64..256,
        bit_length in 8usize..12,
    ) {
        prop_assume!(value < (1u64 << bit_length));
        
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, bit_length * 2);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        // Generate proof
        let original_proof = prover.prove_range(value, bit_length, None, &mut rng)?;
        
        // Serialize and deserialize
        let proof_bytes = original_proof.to_bytes();
        let deserialized_proof = RangeProof::from_bytes(&proof_bytes)?;
        
        // Deserialized proof should still verify
        prop_assert!(verifier.verify_range(&deserialized_proof, bit_length).is_ok());
        
        // Round-trip should be identical
        prop_assert_eq!(original_proof.to_bytes(), deserialized_proof.to_bytes());
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    
    #[test]
    fn test_deterministic_failure() {
        // Test that a known out-of-range value always fails
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 16);
        
        // 256 is too large for 8 bits (max = 255)
        assert!(prover.prove_range(256, 8, None, &mut rng).is_err());
    }
    
    #[test]
    fn test_zero_bit_length_fails() {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 16);
        
        // Zero bit length should fail
        assert!(prover.prove_range(0, 0, None, &mut rng).is_err());
    }
    
    #[test]
    fn test_large_bit_length_fails() {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 128);
        
        // > 64 bit length should fail
        assert!(prover.prove_range(0, 65, None, &mut rng).is_err());
    }
}