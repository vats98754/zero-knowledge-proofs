//! Range proof prover implementation

use crate::{RangeProof, ConstraintSystem, bit_decompose};
use bulletproofs_core::*;
use ipa::InnerProductProver;
use rand_core::{CryptoRng, RngCore};
use curve25519_dalek::traits::VartimeMultiscalarMul;

/// Prover for generating range proofs
pub struct RangeProver {
    generators: GeneratorSet,
}

impl RangeProver {
    /// Create a new range prover with fresh generators
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, max_bit_length: usize) -> Self {
        Self {
            generators: GeneratorSet::new(rng, max_bit_length),
        }
    }

    /// Create a range prover with existing generators
    pub fn with_generators(generators: GeneratorSet) -> Self {
        Self { generators }
    }

    /// Prove that a value lies in the range [0, 2^bit_length)
    pub fn prove_range<R: RngCore + CryptoRng>(
        &self,
        value: u64,
        bit_length: usize,
        blinding: Option<Scalar>,
        rng: &mut R,
    ) -> Result<RangeProof, BulletproofsError> {
        // Validate inputs
        if bit_length == 0 || bit_length > 64 {
            return Err(BulletproofsError::InvalidInput(
                "Bit length must be between 1 and 64".to_string()
            ));
        }

        let max_value = (1u64 << bit_length) - 1;
        if value > max_value {
            return Err(BulletproofsError::InvalidInput(
                format!("Value {} exceeds maximum for {} bits", value, bit_length)
            ));
        }

        // Generate blinding factor if not provided
        let blinding = blinding.unwrap_or_else(|| Scalar::random(rng));

        // Decompose value into bits
        let bits = bit_decompose(value, bit_length);
        let value_scalar = Scalar::from(value);

        // Create constraint system
        let constraint_system = ConstraintSystem::new(&self.generators, bit_length);

        // Generate constraint vectors
        let (a_vector, b_vector) = constraint_system.generate_constraint_vectors(&bits, value_scalar);

        // Create commitments
        let commitment = self.commit_to_value(value_scalar, blinding)?;
        let bit_commitment = constraint_system.commit_to_vectors(&a_vector, &b_vector, blinding)?;

        // Create IPA proof for the constraint vectors
        let mut transcript = bulletproofs_core::transcript::bulletproofs_transcript(b"RangeProof");
        transcript.append_point(b"commitment", &GroupElement::from(commitment));
        transcript.append_point(b"bit_commitment", &GroupElement::from(bit_commitment));
        transcript.append_message(b"bit_length", &(bit_length as u64).to_le_bytes());

        let mut ipa_prover = InnerProductProver::new(self.generators.clone());

        let ipa_proof = ipa_prover.prove(
            rng,
            &mut transcript,
            &a_vector,
            &b_vector,
        )?;

        Ok(RangeProof::new(
            commitment.compress(),
            bit_commitment.compress(),
            ipa_proof,
            blinding,
        ))
    }

    /// Commit to a value: C = value * G + blinding * H
    fn commit_to_value(&self, value: Scalar, blinding: Scalar) -> Result<RistrettoPoint, BulletproofsError> {
        let g = self.generators.g_generator();
        let h = self.generators.h_generator();
        
        Ok(RistrettoPoint::vartime_multiscalar_mul(
            &[value, blinding],
            &[g.into(), h.into()],
        ))
    }

    /// Get the generator set used by this prover
    pub fn generators(&self) -> &GeneratorSet {
        &self.generators
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RangeVerifier;
    use rand::thread_rng;

    #[test]
    fn test_range_proof_generation() {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 64);
        
        let value = 42u64;
        let bit_length = 8;
        
        let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
        
        // Basic validation
        assert!(proof.commitment().decompress().is_some());
        assert!(proof.bit_commitment().decompress().is_some());
        assert!(!proof.ipa_proof().l_vec.is_empty() || !proof.ipa_proof().r_vec.is_empty());
    }

    #[test]
    fn test_range_proof_roundtrip() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 64); // Support up to 64-bit ranges
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        let value = 15u64;
        let bit_length = 4;
        
        let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
        assert!(verifier.verify_range(&proof, bit_length).is_ok());
    }

    #[test]
    fn test_range_proof_different_bit_lengths() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 64); // Support up to 64-bit ranges
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        // Test various bit lengths
        let test_cases = vec![
            (0u64, 1),
            (1u64, 1),
            (3u64, 2),
            (15u64, 4),
            (255u64, 8),
            (1023u64, 10),
        ];
        
        for (value, bit_length) in test_cases {
            let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
            assert!(verifier.verify_range(&proof, bit_length).is_ok(), 
                    "Failed for value {} with {} bits", value, bit_length);
        }
    }

    #[test]
    fn test_range_proof_fails_for_out_of_range_value() {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 64);
        
        let value = 256u64; // Too large for 8 bits
        let bit_length = 8;
        
        let result = prover.prove_range(value, bit_length, None, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_range_proof_fails_for_invalid_bit_length() {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 64);
        
        let value = 42u64;
        
        // Test bit length 0
        let result = prover.prove_range(value, 0, None, &mut rng);
        assert!(result.is_err());
        
        // Test bit length > 64
        let result = prover.prove_range(value, 65, None, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_range_proof_with_custom_blinding() {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 64);
        
        let value = 42u64;
        let bit_length = 8;
        let custom_blinding = Scalar::from(12345u64);
        
        let proof = prover.prove_range(value, bit_length, Some(custom_blinding), &mut rng).unwrap();
        assert_eq!(*proof.blinding(), custom_blinding);
    }

    #[test]
    fn test_edge_case_values() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 16); // 8 bits * 2
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        
        // Test minimum value (0)
        let proof = prover.prove_range(0, 8, None, &mut rng).unwrap();
        assert!(verifier.verify_range(&proof, 8).is_ok());
        
        // Test maximum value for bit length
        let max_value = (1u64 << 8) - 1; // 255
        let proof = prover.prove_range(max_value, 8, None, &mut rng).unwrap();
        assert!(verifier.verify_range(&proof, 8).is_ok());
    }
}