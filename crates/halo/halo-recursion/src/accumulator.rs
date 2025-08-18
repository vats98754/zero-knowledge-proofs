//! Accumulator for recursive proofs
//!
//! The accumulator maintains the state needed for folding multiple proofs
//! into a single recursive proof. This is the core of Halo's recursive
//! aggregation capability.

use crate::{Scalar, GroupElement, Result, RecursionError};
use commitments::IpaCommitment as Commitment;
use ff::Field;
use group::{Group, GroupEncoding};

/// Accumulator instance containing public data for a folded proof
#[derive(Clone, Debug)]
pub struct AccumulatorInstance {
    /// Public inputs to the accumulated circuit
    pub public_inputs: Vec<Scalar>,
    /// Commitments to the accumulated polynomials
    pub commitments: Vec<Commitment>,
    /// Random challenges used in folding
    pub challenges: Vec<Scalar>,
    /// Number of proofs accumulated so far
    pub proof_count: usize,
}

/// Accumulator for folding proofs with witness data
#[derive(Clone, Debug)]
pub struct Accumulator {
    /// Public instance data
    pub instance: AccumulatorInstance,
    /// Private witness polynomials (if available)
    pub witness_polynomials: Option<Vec<Vec<Scalar>>>,
    /// Running error terms from folding
    pub error_terms: Vec<Scalar>,
}

impl AccumulatorInstance {
    /// Create a new empty accumulator instance
    pub fn empty() -> Self {
        Self {
            public_inputs: Vec::new(),
            commitments: Vec::new(),
            challenges: Vec::new(),
            proof_count: 0,
        }
    }

    /// Create accumulator instance from a single proof
    pub fn from_proof_instance(
        public_inputs: Vec<Scalar>,
        commitments: Vec<Commitment>,
    ) -> Self {
        Self {
            public_inputs,
            commitments,
            challenges: Vec::new(),
            proof_count: 1,
        }
    }

    /// Check if this accumulator is empty (no proofs accumulated)
    pub fn is_empty(&self) -> bool {
        self.proof_count == 0
    }

    /// Fold two accumulator instances together
    pub fn fold_with(
        &self,
        other: &AccumulatorInstance,
        challenge: Scalar,
    ) -> Result<AccumulatorInstance> {
        if self.is_empty() {
            return Ok(other.clone());
        }
        if other.is_empty() {
            return Ok(self.clone());
        }

        // Combine public inputs linearly
        let mut combined_inputs = Vec::new();
        let max_len = self.public_inputs.len().max(other.public_inputs.len());
        
        for i in 0..max_len {
            let a = self.public_inputs.get(i).copied().unwrap_or(Scalar::ZERO);
            let b = other.public_inputs.get(i).copied().unwrap_or(Scalar::ZERO);
            combined_inputs.push(a + challenge * b);
        }

        // Combine commitments
        let mut combined_commitments = Vec::new();
        let max_commit_len = self.commitments.len().max(other.commitments.len());
        
        for i in 0..max_commit_len {
            let commitment_a = self.commitments.get(i)
                .map(|c| c.point)
                .unwrap_or(GroupElement::identity());
            let commitment_b = other.commitments.get(i)
                .map(|c| c.point)
                .unwrap_or(GroupElement::identity());
                
            let combined = commitment_a + commitment_b * challenge;
            combined_commitments.push(Commitment { point: combined.into() });
        }

        // Combine challenges
        let mut combined_challenges = self.challenges.clone();
        combined_challenges.extend_from_slice(&other.challenges);
        combined_challenges.push(challenge);

        Ok(AccumulatorInstance {
            public_inputs: combined_inputs,
            commitments: combined_commitments,
            challenges: combined_challenges,
            proof_count: self.proof_count + other.proof_count,
        })
    }
}

impl Accumulator {
    /// Create a new empty accumulator
    pub fn empty() -> Self {
        Self {
            instance: AccumulatorInstance::empty(),
            witness_polynomials: None,
            error_terms: Vec::new(),
        }
    }

    /// Create a new accumulator from an instance
    pub fn new(instance: AccumulatorInstance) -> Self {
        Self {
            instance,
            witness_polynomials: None,
            error_terms: Vec::new(),
        }
    }

    /// Create accumulator with witness data
    pub fn with_witness(
        instance: AccumulatorInstance,
        witness_polynomials: Vec<Vec<Scalar>>,
    ) -> Self {
        Self {
            instance,
            witness_polynomials: Some(witness_polynomials),
            error_terms: Vec::new(),
        }
    }

    /// Fold this accumulator with another accumulator
    pub fn fold_with(
        &self,
        other: &Accumulator,
        challenge: Scalar,
    ) -> Result<Accumulator> {
        let folded_instance = self.instance.fold_with(&other.instance, challenge)?;
        
        // Fold witness polynomials if both have them
        let folded_witness = match (&self.witness_polynomials, &other.witness_polynomials) {
            (Some(witness_a), Some(witness_b)) => {
                let mut folded = Vec::new();
                let max_polys = witness_a.len().max(witness_b.len());
                
                for i in 0..max_polys {
                    let poly_a = witness_a.get(i);
                    let poly_b = witness_b.get(i);
                    
                    match (poly_a, poly_b) {
                        (Some(a), Some(b)) => {
                            let max_len = a.len().max(b.len());
                            let mut folded_poly = Vec::new();
                            
                            for j in 0..max_len {
                                let coeff_a = a.get(j).copied().unwrap_or(Scalar::ZERO);
                                let coeff_b = b.get(j).copied().unwrap_or(Scalar::ZERO);
                                folded_poly.push(coeff_a + challenge * coeff_b);
                            }
                            folded.push(folded_poly);
                        },
                        (Some(a), None) => folded.push(a.clone()),
                        (None, Some(b)) => {
                            let scaled_b: Vec<Scalar> = b.iter().map(|&x| challenge * x).collect();
                            folded.push(scaled_b);
                        },
                        (None, None) => {}
                    }
                }
                Some(folded)
            },
            (Some(witness), None) | (None, Some(witness)) => Some(witness.clone()),
            (None, None) => None,
        };

        // Combine error terms
        let mut combined_errors = self.error_terms.clone();
        combined_errors.extend_from_slice(&other.error_terms);

        Ok(Accumulator {
            instance: folded_instance,
            witness_polynomials: folded_witness,
            error_terms: combined_errors,
        })
    }

    /// Check if the accumulator contains valid folded proofs
    pub fn verify_structure(&self) -> Result<bool> {
        // Basic structural checks
        if self.instance.public_inputs.is_empty() && self.instance.proof_count > 0 {
            return Err(RecursionError::InvalidAccumulator("Non-empty accumulator with no public inputs".to_string()));
        }

        if self.instance.commitments.len() > 100 {
            return Err(RecursionError::InvalidAccumulator("Too many commitments".to_string()));
        }

        // Check witness polynomial consistency
        if let Some(ref witness) = self.witness_polynomials {
            if witness.len() != self.instance.commitments.len() {
                return Err(RecursionError::InvalidAccumulator("Witness polynomial count mismatch".to_string()));
            }
        }

        Ok(true)
    }

    /// Extract final instance for verification
    pub fn into_instance(self) -> AccumulatorInstance {
        self.instance
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commitments::IpaCommitment as Commitment;
    use crate::{Scalar as BlsScalar, GroupElement};
    use ff::Field;
    use group::Group;

    #[test]
    fn test_empty_accumulator() {
        let acc = Accumulator::empty();
        assert!(acc.instance.is_empty());
        assert_eq!(acc.instance.proof_count, 0);
    }

    #[test]
    fn test_accumulator_folding() {
        let instance1 = AccumulatorInstance::from_proof_instance(
            vec![BlsScalar::from(42u64)],
            vec![Commitment { point: GroupElement::identity() }],
        );
        
        let instance2 = AccumulatorInstance::from_proof_instance(
            vec![BlsScalar::from(100u64)],
            vec![Commitment { point: GroupElement::identity() }],
        );

        let acc1 = Accumulator::new(instance1);
        let acc2 = Accumulator::new(instance2);
        
        let challenge = BlsScalar::from(2u64);
        let folded = acc1.fold_with(&acc2, challenge).unwrap();
        
        assert_eq!(folded.instance.proof_count, 2);
        assert_eq!(folded.instance.public_inputs.len(), 1);
        // Should be 42 + 2 * 100 = 242
        assert_eq!(folded.instance.public_inputs[0], BlsScalar::from(242u64));
    }

    #[test]
    fn test_accumulator_structure_validation() {
        let acc = Accumulator::empty();
        assert!(acc.verify_structure().unwrap());
        
        let instance = AccumulatorInstance::from_proof_instance(
            vec![BlsScalar::from(42u64)],
            vec![Commitment { point: GroupElement::identity() }],
        );
        let acc = Accumulator::new(instance);
        assert!(acc.verify_structure().unwrap());
    }
}