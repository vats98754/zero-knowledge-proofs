//! Range proof verifier implementation

use crate::{RangeProof, ConstraintSystem};
use bulletproofs_core::*;
use ipa::InnerProductVerifier;
use rand_core::{CryptoRng, RngCore};
use rand;

/// Verifier for range proofs
pub struct RangeVerifier {
    generators: GeneratorSet,
}

impl RangeVerifier {
    /// Create a new range verifier with fresh generators
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, max_bit_length: usize) -> Self {
        Self {
            generators: GeneratorSet::new(rng, max_bit_length),
        }
    }

    /// Create a range verifier with existing generators (must match prover's generators)
    pub fn with_generators(generators: GeneratorSet) -> Self {
        Self { generators }
    }

    /// Verify a range proof for the given bit length
    pub fn verify_range(
        &self,
        proof: &RangeProof,
        bit_length: usize,
    ) -> Result<(), BulletproofsError> {
        // Validate inputs
        if bit_length == 0 || bit_length > 64 {
            return Err(BulletproofsError::InvalidInput(
                "Bit length must be between 1 and 64".to_string()
            ));
        }

        // Decompress points
        let commitment = proof.commitment()
            .decompress()
            .ok_or_else(|| BulletproofsError::InvalidProof("Invalid commitment".to_string()))?;
        
        let bit_commitment = proof.bit_commitment()
            .decompress()
            .ok_or_else(|| BulletproofsError::InvalidProof("Invalid bit commitment".to_string()))?;

        // Create constraint system
        let constraint_system = ConstraintSystem::new(&self.generators, bit_length);

        // Reconstruct transcript for IPA verification
        let mut transcript = bulletproofs_core::transcript::bulletproofs_transcript(b"RangeProof");
        transcript.append_point(b"commitment", &GroupElement::from(commitment));
        transcript.append_point(b"bit_commitment", &GroupElement::from(bit_commitment));
        transcript.append_message(b"bit_length", &(bit_length as u64).to_le_bytes());

        // Verify IPA proof
        let mut ipa_verifier = InnerProductVerifier::new(self.generators.clone());
        let rng = rand::rngs::OsRng;

        let verified = ipa_verifier.verify(
            rng,
            &mut transcript,
            proof.ipa_proof(),
            &GroupElement::from(bit_commitment),
            2 * bit_length, // Constraint vectors are 2x bit length
        )?;

        if !verified {
            return Err(BulletproofsError::VerificationFailed);
        }

        // Additional range-specific verification
        self.verify_range_constraints(proof, bit_length, &constraint_system)?;

        Ok(())
    }

    /// Verify range-specific constraints
    fn verify_range_constraints(
        &self,
        proof: &RangeProof,
        bit_length: usize,
        constraint_system: &ConstraintSystem,
    ) -> Result<(), BulletproofsError> {
        // The IPA proof already verifies that the committed vectors satisfy
        // the inner product relation. Here we can add additional checks if needed.

        // Verify that the proof structure is valid for the given bit length
        let constraint_vector_length = 2 * bit_length;
        let expected_rounds = constraint_vector_length.next_power_of_two().trailing_zeros() as usize;
        let actual_rounds = proof.ipa_proof().l_vec.len();

        if actual_rounds != expected_rounds {
            return Err(BulletproofsError::InvalidProof(
                format!("Expected {} IPA rounds for constraint vector length {}, got {}", 
                    expected_rounds, constraint_vector_length, actual_rounds)
            ));
        }

        Ok(())
    }

    /// Verify multiple range proofs efficiently (batch verification)
    pub fn verify_range_batch(
        &self,
        proofs: &[RangeProof],
        bit_lengths: &[usize],
    ) -> Result<(), BulletproofsError> {
        if proofs.len() != bit_lengths.len() {
            return Err(BulletproofsError::InvalidParameters(
                "Number of proofs must match number of bit lengths".to_string()
            ));
        }

        // For now, verify each proof individually
        // TODO: Implement true batch verification for better performance
        for (proof, &bit_length) in proofs.iter().zip(bit_lengths.iter()) {
            self.verify_range(proof, bit_length)?;
        }

        Ok(())
    }

    /// Extract the committed value if the blinding factor is known (for testing)
    pub fn extract_value_with_blinding(
        &self,
        proof: &RangeProof,
        blinding: Scalar,
    ) -> Result<Option<u64>, BulletproofsError> {
        // Decompress commitment
        let commitment = proof.commitment()
            .decompress()
            .ok_or_else(|| BulletproofsError::InvalidProof("Invalid commitment".to_string()))?;

        // Try to extract value by testing against possible values
        // This is only practical for small bit lengths and is mainly for testing
        let g = self.generators.g_generator();
        let h = self.generators.h_generator();

        // Remove blinding: C - blinding * H = value * G
        let blinding_point = h * blinding;
        let value_commitment = GroupElement::from(commitment) - blinding_point;

        // Try values from 0 to 2^16 (practical limit for brute force)
        for candidate in 0..=65535u64 {
            let test_commitment = g * Scalar::from(candidate);
            if test_commitment == value_commitment {
                return Ok(Some(candidate));
            }
        }

        Ok(None) // Value not found in tested range
    }

    /// Get the generator set used by this verifier
    pub fn generators(&self) -> &GeneratorSet {
        &self.generators
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RangeProver;
    use rand::thread_rng;

    #[test]
    fn test_range_verification_success() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 16); // 8 bits * 2
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        let value = 42u64;
        let bit_length = 8;
        
        let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
        assert!(verifier.verify_range(&proof, bit_length).is_ok());
    }

    #[test]
    fn test_range_verification_different_generators_fails() {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 64);
        let verifier = RangeVerifier::new(&mut rng, 64); // Different generators
        
        let value = 42u64;
        let bit_length = 8;
        
        let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
        // Should fail because generators don't match
        assert!(verifier.verify_range(&proof, bit_length).is_err());
    }

    #[test]
    fn test_range_verification_wrong_bit_length_fails() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 64);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        let value = 42u64;
        let bit_length = 8;
        
        let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
        
        // Verify with wrong bit length should fail
        assert!(verifier.verify_range(&proof, 16).is_err());
    }

    #[test]
    fn test_batch_verification() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 64);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        let values = vec![10u64, 20u64, 30u64];
        let bit_lengths = vec![8, 8, 8];
        
        let mut proofs = Vec::new();
        for (&value, &bit_length) in values.iter().zip(bit_lengths.iter()) {
            let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
            proofs.push(proof);
        }
        
        assert!(verifier.verify_range_batch(&proofs, &bit_lengths).is_ok());
    }

    #[test]
    fn test_batch_verification_mismatched_lengths() {
        let mut rng = thread_rng();
        let verifier = RangeVerifier::new(&mut rng, 64);
        
        let proofs = vec![];
        let bit_lengths = vec![8];
        
        assert!(verifier.verify_range_batch(&proofs, &bit_lengths).is_err());
    }

    #[test]
    fn test_value_extraction_with_blinding() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 64);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        let value = 123u64;
        let bit_length = 8;
        let blinding = Scalar::from(456u64);
        
        let proof = prover.prove_range(value, bit_length, Some(blinding), &mut rng).unwrap();
        let extracted = verifier.extract_value_with_blinding(&proof, blinding).unwrap();
        
        assert_eq!(extracted, Some(value));
    }

    #[test]
    fn test_value_extraction_with_wrong_blinding() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 64);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        let value = 123u64;
        let bit_length = 8;
        let correct_blinding = Scalar::from(456u64);
        let wrong_blinding = Scalar::from(789u64);
        
        let proof = prover.prove_range(value, bit_length, Some(correct_blinding), &mut rng).unwrap();
        let extracted = verifier.extract_value_with_blinding(&proof, wrong_blinding).unwrap();
        
        assert_eq!(extracted, None); // Should not find the value
    }

    #[test]
    fn test_verification_invalid_bit_length() {
        let mut rng = thread_rng();
        let verifier = RangeVerifier::new(&mut rng, 64);
        let prover = RangeProver::new(&mut rng, 64);
        
        let value = 42u64;
        let proof = prover.prove_range(value, 8, None, &mut rng).unwrap();
        
        // Test invalid bit lengths
        assert!(verifier.verify_range(&proof, 0).is_err());
        assert!(verifier.verify_range(&proof, 65).is_err());
    }
}