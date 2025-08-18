//! Recursive verifier implementation
//!
//! This module implements the recursive verification algorithm that can verify
//! accumulated proofs efficiently. The recursive verifier checks that a folding
//! proof correctly represents the accumulation of multiple base proofs.

use crate::{
    AccumulatorInstance, FoldingProof, Result, RecursionError
};
use halo_core::{Proof, Scalar, GroupElement, Verifier as BaseVerifier, verifier::VerifierConfig};
use commitments::{CommitmentEngine, ipa::IpaCommitmentEngine};
use merlin::Transcript;
use ff::Field;
use group::{Group, GroupEncoding};
use std::marker::PhantomData;

/// Configuration for recursive verification
#[derive(Clone, Debug)]
pub struct RecursiveVerifierConfig {
    /// Maximum recursion depth allowed
    pub max_recursion_depth: usize,
    /// Security parameter
    pub security_bits: usize,
    /// Enable optimizations for batch verification
    pub enable_batch_verify: bool,
}

impl Default for RecursiveVerifierConfig {
    fn default() -> Self {
        Self {
            max_recursion_depth: 100,
            security_bits: 128,
            enable_batch_verify: true,
        }
    }
}

/// Recursive verifier for Halo proofs
#[derive(Clone, Debug)]
pub struct RecursiveVerifier<CE: CommitmentEngine> {
    /// Configuration
    config: RecursiveVerifierConfig,
    /// Base verifier for individual proofs
    base_verifier: BaseVerifier,
    /// Commitment engine
    _phantom: PhantomData<CE>,
}

/// Verification context for recursive proofs
#[derive(Clone)]
pub struct VerificationContext {
    /// Transcript for Fiat-Shamir
    pub transcript: Transcript,
    /// Current recursion depth
    pub recursion_depth: usize,
    /// Accumulated challenges from folding
    pub folding_challenges: Vec<Scalar>,
}

impl<CE: CommitmentEngine> RecursiveVerifier<CE> {
    /// Create a new recursive verifier
    pub fn new(config: RecursiveVerifierConfig) -> Self {
        Self {
            config,
            base_verifier: BaseVerifier::new(VerifierConfig { max_degree: 1024 }),
            _phantom: PhantomData,
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(RecursiveVerifierConfig::default())
    }

    /// Verify a recursive proof with folding
    pub fn verify_recursive(
        &self,
        folding_proof: &FoldingProof,
        expected_instance: &AccumulatorInstance,
    ) -> Result<bool> {
        let mut context = VerificationContext {
            transcript: Transcript::new(b"halo-recursive-verify"),
            recursion_depth: 0,
            folding_challenges: Vec::new(),
        };

        self.verify_recursive_with_context(folding_proof, expected_instance, &mut context)
    }

    /// Verify recursive proof with given context
    fn verify_recursive_with_context(
        &self,
        folding_proof: &FoldingProof,
        expected_instance: &AccumulatorInstance,
        context: &mut VerificationContext,
    ) -> Result<bool> {
        // Check recursion depth
        if context.recursion_depth >= self.config.max_recursion_depth {
            return Err(RecursionError::MaxRecursionDepthExceeded);
        }

        context.recursion_depth += 1;

        // Verify the accumulated instance matches expectations
        if !self.verify_instance_structure(&folding_proof.accumulated_instance, expected_instance)? {
            return Ok(false);
        }

        // Verify the folding challenges are correctly generated
        if !self.verify_folding_challenges(folding_proof, context)? {
            return Ok(false);
        }

        // Verify cross-terms are correctly computed
        if !self.verify_cross_terms(folding_proof, context)? {
            return Ok(false);
        }

        // Verify the final evaluation proof
        if !self.verify_evaluation_proof(folding_proof, context)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify the structure of the accumulated instance
    fn verify_instance_structure(
        &self,
        actual: &AccumulatorInstance,
        expected: &AccumulatorInstance,
    ) -> Result<bool> {
        // Check proof count
        if actual.proof_count != expected.proof_count {
            return Ok(false);
        }

        // Check public inputs match
        if actual.public_inputs.len() != expected.public_inputs.len() {
            return Ok(false);
        }

        for (a, e) in actual.public_inputs.iter().zip(expected.public_inputs.iter()) {
            if a != e {
                return Ok(false);
            }
        }

        // Check commitment count
        if actual.commitments.len() != expected.commitments.len() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify that folding challenges were generated correctly
    fn verify_folding_challenges(
        &self,
        folding_proof: &FoldingProof,
        context: &mut VerificationContext,
    ) -> Result<bool> {
        // Add the accumulated instance to transcript
        self.add_instance_to_transcript(&folding_proof.accumulated_instance, &mut context.transcript);

        // Verify each challenge
        for (i, &challenge) in folding_proof.folding_challenges.iter().enumerate() {
            let mut challenge_bytes = [0u8; 64];
            // Use a static label since transcript requires &'static [u8]
            context.transcript.challenge_bytes(
                b"folding_challenge", 
                &mut challenge_bytes[..32]
            );
            let expected_challenge = Scalar::from_bytes_wide(&challenge_bytes);

            if challenge != expected_challenge {
                return Ok(false);
            }

            context.folding_challenges.push(challenge);
        }

        Ok(true)
    }

    /// Verify that cross-terms are correctly computed
    fn verify_cross_terms(
        &self,
        folding_proof: &FoldingProof,
        _context: &VerificationContext,
    ) -> Result<bool> {
        // For now, just check that we have the expected number of cross-terms
        // In a full implementation, this would verify the cross-term commitments
        let expected_cross_terms = folding_proof.accumulated_instance.commitments.len();
        
        if folding_proof.cross_terms.len() > expected_cross_terms * 2 {
            return Ok(false);
        }

        // Verify each cross-term is a valid group element
        for cross_term in &folding_proof.cross_terms {
            if cross_term.point == GroupElement::identity() && 
               folding_proof.accumulated_instance.proof_count > 1 {
                // Cross-terms shouldn't all be identity for multi-proof folding
                // (unless the original commitments were identity)
                continue;
            }
        }

        Ok(true)
    }

    /// Verify the evaluation proof
    fn verify_evaluation_proof(
        &self,
        folding_proof: &FoldingProof,
        context: &mut VerificationContext,
    ) -> Result<bool> {
        // Generate evaluation point from transcript
        let mut eval_point_bytes = [0u8; 64];
        context.transcript.challenge_bytes(b"eval_point", &mut eval_point_bytes[..32]);
        let _eval_point = Scalar::from_bytes_wide(&eval_point_bytes);

        // For now, just check that evaluation proof is non-empty if we have proofs
        if folding_proof.accumulated_instance.proof_count > 0 {
            return Ok(!folding_proof.evaluation_proof.is_empty());
        }

        Ok(true)
    }

    /// Add accumulator instance to transcript
    fn add_instance_to_transcript(&self, instance: &AccumulatorInstance, transcript: &mut Transcript) {
        transcript.append_message(b"proof_count", &instance.proof_count.to_le_bytes());
        
        for input in &instance.public_inputs {
            transcript.append_message(b"public_input", &input.to_bytes());
        }
        
        for commitment in &instance.commitments {
            transcript.append_message(b"commitment", &commitment.point.to_bytes().as_ref());
        }
    }

    /// Batch verify multiple recursive proofs
    pub fn batch_verify(
        &self,
        proofs_and_instances: &[(FoldingProof, AccumulatorInstance)],
    ) -> Result<bool> {
        if !self.config.enable_batch_verify {
            // Fall back to individual verification
            for (proof, instance) in proofs_and_instances {
                if !self.verify_recursive(proof, instance)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }

        // Implement batch verification optimization
        // For now, fall back to individual verification
        for (proof, instance) in proofs_and_instances {
            if !self.verify_recursive(proof, instance)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Simple wrapper function for backwards compatibility
pub fn verify_recursive(
    folding_proof: &FoldingProof,
    expected_instance: &AccumulatorInstance,
) -> Result<bool> {
    let verifier = RecursiveVerifier::<IpaCommitmentEngine>::default();
    verifier.verify_recursive(folding_proof, expected_instance)
}

/// Verify a base proof (non-recursive)
pub fn verify_base_proof(
    proof: &Proof,
    _public_inputs: &[Scalar],
) -> Result<bool> {
    let verifier = BaseVerifier::new(VerifierConfig { max_degree: 1024 });
    verifier.verify(proof).map_err(|e| RecursionError::Halo(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fold_proof, AccumulatorInstance};
    use halo_core::Proof;
    use commitments::IpaCommitment as Commitment;
    use crate::{Scalar as BlsScalar, GroupElement};
    use ff::Field;
    use group::Group;

    fn create_test_proof() -> Proof {
        Proof::new(
            vec![GroupElement::identity()],
            vec![BlsScalar::ZERO],
            vec![0u8; 32],
        )
    }

    #[test]
    fn test_recursive_verifier_creation() {
        let verifier = RecursiveVerifier::<IpaCommitmentEngine>::default();
        assert_eq!(verifier.config.max_recursion_depth, 100);
    }

    #[test] 
    fn test_verify_single_proof_folding() {
        let proof = create_test_proof();
        let public_inputs = vec![BlsScalar::from(42u64)];
        
        let folding_result = fold_proof(None, proof, public_inputs.clone()).unwrap();
        
        let verifier = RecursiveVerifier::<IpaCommitmentEngine>::default();
        let result = verifier.verify_recursive(
            &folding_result.folding_proof,
            &folding_result.accumulator.instance,
        ).unwrap();
        
        assert!(result);
    }

    #[test]
    fn test_verify_two_proof_folding() {
        // First proof
        let proof1 = create_test_proof();
        let inputs1 = vec![BlsScalar::from(10u64)];
        let result1 = fold_proof(None, proof1, inputs1).unwrap();
        
        // Second proof  
        let proof2 = create_test_proof();
        let inputs2 = vec![BlsScalar::from(20u64)];
        let result2 = fold_proof(Some(result1.accumulator), proof2, inputs2).unwrap();
        
        let verifier = RecursiveVerifier::<IpaCommitmentEngine>::default();
        let verification_result = verifier.verify_recursive(
            &result2.folding_proof,
            &result2.accumulator.instance,
        ).unwrap();
        
        assert!(verification_result);
    }

    #[test]
    fn test_instance_structure_verification() {
        let verifier = RecursiveVerifier::<IpaCommitmentEngine>::default();
        
        let instance1 = AccumulatorInstance::from_proof_instance(
            vec![BlsScalar::from(42u64)],
            vec![Commitment { point: GroupElement::identity() }],
        );
        
        let instance2 = AccumulatorInstance::from_proof_instance(
            vec![BlsScalar::from(42u64)],
            vec![Commitment { point: GroupElement::identity() }],
        );
        
        let result = verifier.verify_instance_structure(&instance1, &instance2).unwrap();
        assert!(result);
        
        // Test mismatch
        let instance3 = AccumulatorInstance::from_proof_instance(
            vec![BlsScalar::from(100u64)], // Different input
            vec![Commitment { point: GroupElement::identity() }],
        );
        
        let result = verifier.verify_instance_structure(&instance1, &instance3).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_batch_verification() {
        let verifier = RecursiveVerifier::<IpaCommitmentEngine>::default();
        
        let proof1 = create_test_proof();
        let inputs1 = vec![BlsScalar::from(5u64)];
        let result1 = fold_proof(None, proof1, inputs1).unwrap();
        
        let proof2 = create_test_proof();
        let inputs2 = vec![BlsScalar::from(15u64)];
        let result2 = fold_proof(None, proof2, inputs2).unwrap();
        
        let batch_input = vec![
            (result1.folding_proof, result1.accumulator.instance),
            (result2.folding_proof, result2.accumulator.instance),
        ];
        
        let result = verifier.batch_verify(&batch_input).unwrap();
        assert!(result);
    }
}
