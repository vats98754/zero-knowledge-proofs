//! Proof folding implementation
//!
//! This module implements the core folding algorithm that allows combining
//! multiple proofs into a single accumulator. This is the foundation of
//! Halo's recursive proof aggregation.

use crate::{Accumulator, AccumulatorInstance, Result};
use halo_core::{Proof, Scalar, GroupElement};
use commitments::IpaCommitment as Commitment;
use merlin::Transcript;
use ff::Field;
use group::{Group, GroupEncoding};

/// A folding proof that demonstrates correct folding of multiple proofs
#[derive(Clone, Debug)]
pub struct FoldingProof {
    /// The accumulated instance after folding
    pub accumulated_instance: AccumulatorInstance,
    /// Cross-term commitments for the folding
    pub cross_terms: Vec<Commitment>,
    /// Random scalars used in folding
    pub folding_challenges: Vec<Scalar>,
    /// Final evaluation proof
    pub evaluation_proof: Vec<u8>,
}

/// Result of a folding operation
#[derive(Clone, Debug)]
pub struct FoldingResult {
    /// The folded accumulator
    pub accumulator: Accumulator,
    /// Proof of correct folding
    pub folding_proof: FoldingProof,
}

/// Configuration for the folding process
#[derive(Clone, Debug)]
pub struct FoldingConfig {
    /// Maximum number of proofs to fold in one step
    pub max_fold_size: usize,
    /// Security parameter for challenge generation
    pub security_bits: usize,
}

impl Default for FoldingConfig {
    fn default() -> Self {
        Self {
            max_fold_size: 2,
            security_bits: 128,
        }
    }
}

/// Fold a new proof into an existing accumulator
pub fn fold_proof(
    prev_accumulator: Option<Accumulator>,
    new_proof: Proof,
    public_inputs: Vec<Scalar>,
) -> Result<FoldingResult> {
    let config = FoldingConfig::default();
    fold_proof_with_config(prev_accumulator, new_proof, public_inputs, &config)
}

/// Fold a proof with custom configuration
pub fn fold_proof_with_config(
    prev_accumulator: Option<Accumulator>,
    new_proof: Proof,
    public_inputs: Vec<Scalar>,
    config: &FoldingConfig,
) -> Result<FoldingResult> {
    let mut transcript = Transcript::new(b"halo-folding");
    
    // Create accumulator instance from the new proof
    let new_instance = proof_to_accumulator_instance(new_proof, public_inputs)?;
    let new_accumulator = Accumulator::new(new_instance);
    
    match prev_accumulator {
        None => {
            // First proof - no folding needed
            let folding_proof = FoldingProof {
                accumulated_instance: new_accumulator.instance.clone(),
                cross_terms: Vec::new(),
                folding_challenges: Vec::new(),
                evaluation_proof: Vec::new(),
            };
            
            Ok(FoldingResult {
                accumulator: new_accumulator,
                folding_proof,
            })
        },
        Some(prev_acc) => {
            // Fold the new proof with the previous accumulator
            fold_accumulators(prev_acc, new_accumulator, &mut transcript, config)
        }
    }
}

/// Fold two accumulators together
fn fold_accumulators(
    acc1: Accumulator,
    acc2: Accumulator,
    transcript: &mut Transcript,
    config: &FoldingConfig,
) -> Result<FoldingResult> {
    // Add instances to transcript
    add_accumulator_to_transcript(&acc1.instance, transcript);
    add_accumulator_to_transcript(&acc2.instance, transcript);
    
    // Generate folding challenge
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"folding_challenge", &mut challenge_bytes[..32]);
    let folding_challenge = Scalar::from_bytes_wide(&challenge_bytes);
    
    // Perform the folding
    let folded_accumulator = acc1.fold_with(&acc2, folding_challenge)?;
    
    // Verify the folding was done correctly
    folded_accumulator.verify_structure()?;
    
    // Generate cross-terms for the folding proof
    let cross_terms = generate_cross_terms(&acc1, &acc2, folding_challenge)?;
    
    // Create evaluation proof (simplified for now)
    let evaluation_proof = create_evaluation_proof(&folded_accumulator, transcript)?;
    
    let folding_proof = FoldingProof {
        accumulated_instance: folded_accumulator.instance.clone(),
        cross_terms,
        folding_challenges: vec![folding_challenge],
        evaluation_proof,
    };
    
    Ok(FoldingResult {
        accumulator: folded_accumulator,
        folding_proof,
    })
}

/// Convert a proof to an accumulator instance
fn proof_to_accumulator_instance(
    proof: Proof,
    public_inputs: Vec<Scalar>,
) -> Result<AccumulatorInstance> {
    // Extract commitments from the proof
    let commitments: Vec<Commitment> = proof.commitments
        .into_iter()
        .map(|c| Commitment { point: c })
        .collect();
    
    Ok(AccumulatorInstance::from_proof_instance(public_inputs, commitments))
}

/// Add accumulator instance to transcript for Fiat-Shamir
fn add_accumulator_to_transcript(instance: &AccumulatorInstance, transcript: &mut Transcript) {
    transcript.append_message(b"proof_count", &instance.proof_count.to_le_bytes());
    
    for input in &instance.public_inputs {
        transcript.append_message(b"public_input", &input.to_bytes());
    }
    
    for commitment in &instance.commitments {
        transcript.append_message(b"commitment", &commitment.point.to_bytes().as_ref());
    }
}

/// Generate cross-terms for the folding proof
fn generate_cross_terms(
    acc1: &Accumulator,
    acc2: &Accumulator,
    challenge: Scalar,
) -> Result<Vec<Commitment>> {
    let mut cross_terms = Vec::new();
    
    // For each pair of commitments, compute the cross-term
    let max_len = acc1.instance.commitments.len().max(acc2.instance.commitments.len());
    
    for i in 0..max_len {
        let commit1 = acc1.instance.commitments.get(i)
            .map(|c| c.point)
            .unwrap_or(GroupElement::identity());
        let commit2 = acc2.instance.commitments.get(i)
            .map(|c| c.point)
            .unwrap_or(GroupElement::identity());
            
        // Cross-term: commitment to the product of the two polynomials
        let cross_term = commit1 * challenge + commit2;
        cross_terms.push(Commitment { point: cross_term.into() });
    }
    
    Ok(cross_terms)
}

/// Create an evaluation proof for the folded accumulator
fn create_evaluation_proof(
    accumulator: &Accumulator,
    transcript: &mut Transcript,
) -> Result<Vec<u8>> {
    // Generate random evaluation point
    let mut eval_point_bytes = [0u8; 64];
    transcript.challenge_bytes(b"eval_point", &mut eval_point_bytes[..32]);
    let _eval_point = Scalar::from_bytes_wide(&eval_point_bytes);
    
    // For now, return a placeholder evaluation proof
    // In a full implementation, this would contain an evaluation proof
    // showing that the folded polynomial evaluates correctly
    Ok(vec![0u8; 32]) // Placeholder
}

/// Verify a folding proof
pub fn verify_folding_proof(
    proof: &FoldingProof,
    prev_instance: Option<&AccumulatorInstance>,
    new_instance: &AccumulatorInstance,
) -> Result<bool> {
    let mut transcript = Transcript::new(b"halo-folding");
    
    match prev_instance {
        None => {
            // First proof - just check it matches
            Ok(proof.accumulated_instance.public_inputs == new_instance.public_inputs &&
               proof.accumulated_instance.commitments.len() == new_instance.commitments.len())
        },
        Some(prev_inst) => {
            // Add instances to transcript
            add_accumulator_to_transcript(prev_inst, &mut transcript);
            add_accumulator_to_transcript(new_instance, &mut transcript);
            
            // Regenerate folding challenge
            let mut challenge_bytes = [0u8; 64];
            transcript.challenge_bytes(b"folding_challenge", &mut challenge_bytes[..32]);
            let expected_challenge = Scalar::from_bytes_wide(&challenge_bytes);
            
            // Verify the challenge matches
            if proof.folding_challenges.is_empty() || 
               proof.folding_challenges[0] != expected_challenge {
                return Ok(false);
            }
            
            // Verify the folded result
            let expected_folded = prev_inst.fold_with(new_instance, expected_challenge)?;
            
            // Check if the accumulated instance matches expected
            Ok(instances_equal(&proof.accumulated_instance, &expected_folded))
        }
    }
}

/// Check if two accumulator instances are equal
fn instances_equal(a: &AccumulatorInstance, b: &AccumulatorInstance) -> bool {
    a.public_inputs == b.public_inputs &&
    a.commitments.len() == b.commitments.len() &&
    a.proof_count == b.proof_count &&
    a.commitments.iter().zip(b.commitments.iter())
        .all(|(c1, c2)| c1.point == c2.point)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_fold_single_proof() {
        let proof = create_test_proof();
        let public_inputs = vec![BlsScalar::from(42u64)];
        
        let result = fold_proof(None, proof, public_inputs).unwrap();
        
        assert_eq!(result.accumulator.instance.proof_count, 1);
        assert_eq!(result.accumulator.instance.public_inputs[0], BlsScalar::from(42u64));
    }

    #[test]
    fn test_fold_two_proofs() {
        // First proof
        let proof1 = create_test_proof();
        let inputs1 = vec![BlsScalar::from(10u64)];
        let result1 = fold_proof(None, proof1, inputs1).unwrap();
        
        // Second proof
        let proof2 = create_test_proof();
        let inputs2 = vec![BlsScalar::from(20u64)];
        let result2 = fold_proof(Some(result1.accumulator), proof2, inputs2).unwrap();
        
        assert_eq!(result2.accumulator.instance.proof_count, 2);
        assert!(!result2.folding_proof.folding_challenges.is_empty());
    }

    #[test]
    fn test_folding_proof_verification() {
        let proof1 = create_test_proof();
        let inputs1 = vec![BlsScalar::from(5u64)];
        let result1 = fold_proof(None, proof1, inputs1.clone()).unwrap();
        
        let proof2 = create_test_proof();
        let inputs2 = vec![BlsScalar::from(15u64)];
        let result2 = fold_proof(Some(result1.accumulator.clone()), proof2, inputs2.clone()).unwrap();
        
        let new_instance = AccumulatorInstance::from_proof_instance(
            inputs2,
            vec![Commitment { point: GroupElement::identity() }],
        );
        
        let verification_result = verify_folding_proof(
            &result2.folding_proof,
            Some(&result1.accumulator.instance),
            &new_instance,
        ).unwrap();
        
        assert!(verification_result);
    }

    #[test]
    fn test_proof_to_accumulator_conversion() {
        let proof = create_test_proof();
        let public_inputs = vec![BlsScalar::from(100u64)];
        
        let instance = proof_to_accumulator_instance(proof, public_inputs.clone()).unwrap();
        
        assert_eq!(instance.public_inputs, public_inputs);
        assert_eq!(instance.proof_count, 1);
    }
}
