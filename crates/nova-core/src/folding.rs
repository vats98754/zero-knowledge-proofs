//! Core folding operations for Nova incremental verifiable computation.
//!
//! This module implements the fundamental folding scheme that enables Nova's
//! incremental verification. The folding operation compresses multiple instances
//! and witnesses into a single instance and witness while preserving correctness.

use crate::fields::{NovaField, inner_product};
use crate::instances::{Instance, Relation};
use crate::witnesses::{Witness, FoldedWitness};
use crate::transcripts::Transcript;
use crate::errors::{NovaError, NovaResult};
use ark_std::{vec::Vec, Zero, One};
use ark_ff::Field;
use rayon::prelude::*;

/// The core folding operation that compresses instances and witnesses.
/// 
/// This operation is the heart of Nova's incremental verification scheme.
/// It takes two compatible instances and their witnesses, along with randomness,
/// and produces a single folded instance and witness.
/// 
/// # Correctness Theorem
/// 
/// If the original instances are satisfiable with their respective witnesses,
/// then the folded instance is satisfiable with the folded witness if and only
/// if the original instances were both satisfiable.
#[derive(Debug, Clone)]
pub struct FoldingScheme {
    /// The relation used for folding
    pub relation: Relation,
    /// Folding parameters
    pub parameters: FoldingParameters,
}

/// Parameters for the folding scheme
#[derive(Debug, Clone)]
pub struct FoldingParameters {
    /// Security parameter (affects challenge space size)
    pub security_parameter: usize,
    /// Enable parallel folding optimizations
    pub enable_parallel: bool,
    /// Maximum folding depth
    pub max_depth: usize,
}

impl Default for FoldingParameters {
    fn default() -> Self {
        Self {
            security_parameter: 128,
            enable_parallel: true,
            max_depth: 64,
        }
    }
}

impl FoldingScheme {
    /// Creates a new folding scheme with the given relation
    pub fn new(relation: Relation) -> Self {
        Self {
            relation,
            parameters: FoldingParameters::default(),
        }
    }

    /// Creates a new folding scheme with custom parameters
    pub fn with_parameters(relation: Relation, parameters: FoldingParameters) -> Self {
        Self {
            relation,
            parameters,
        }
    }

    /// Performs the core folding operation.
    /// 
    /// This function implements the `compress(instance, witness, randomness)` operation
    /// from the problem specification. It takes two instances and witnesses and
    /// produces a single folded instance and witness.
    /// 
    /// # Arguments
    /// 
    /// * `instance1` - First instance to fold
    /// * `witness1` - Witness for the first instance  
    /// * `instance2` - Second instance to fold
    /// * `witness2` - Witness for the second instance
    /// * `transcript` - Transcript for generating randomness
    /// 
    /// # Returns
    /// 
    /// A tuple `(folded_instance, folded_witness)` representing the compressed computation.
    pub fn fold(
        &self,
        instance1: &Instance,
        witness1: &Witness,
        instance2: &Instance,
        witness2: &Witness,
        transcript: &mut Transcript,
    ) -> NovaResult<(Instance, FoldedWitness)> {
        // Validate inputs
        self.validate_folding_inputs(instance1, witness1, instance2, witness2)?;

        // Add instances to transcript
        transcript.append_label("folding");
        transcript.append_field_elements(&instance1.public_inputs);
        transcript.append_field_elements(&instance1.commitments);
        transcript.append_field_elements(&instance2.public_inputs);
        transcript.append_field_elements(&instance2.commitments);

        // Generate folding challenge
        let challenge = transcript.challenge_field_element("folding-challenge");

        // Perform the actual folding
        let (folded_instance, folded_witness) = self.fold_with_challenge(
            instance1, witness1, instance2, witness2, challenge
        )?;

        Ok((folded_instance, folded_witness))
    }

    /// Performs folding with a specific challenge (for deterministic testing)
    pub fn fold_with_challenge(
        &self,
        instance1: &Instance,
        witness1: &Witness,
        instance2: &Instance,
        witness2: &Witness,
        challenge: NovaField,
    ) -> NovaResult<(Instance, FoldedWitness)> {
        // Fold public inputs: folded_input = input1 + challenge * input2
        let folded_public_inputs = if self.parameters.enable_parallel {
            self.fold_vectors_parallel(&instance1.public_inputs, &instance2.public_inputs, challenge)
        } else {
            self.fold_vectors(&instance1.public_inputs, &instance2.public_inputs, challenge)
        };

        // Fold commitments: folded_comm = comm1 + challenge * comm2
        let folded_commitments = if self.parameters.enable_parallel {
            self.fold_vectors_parallel(&instance1.commitments, &instance2.commitments, challenge)
        } else {
            self.fold_vectors(&instance1.commitments, &instance2.commitments, challenge)
        };

        // Fold witness assignments: folded_assignment = assignment1 + challenge * assignment2
        let folded_assignment = if self.parameters.enable_parallel {
            self.fold_vectors_parallel(&witness1.assignment, &witness2.assignment, challenge)
        } else {
            self.fold_vectors(&witness1.assignment, &witness2.assignment, challenge)
        };

        // Create folded instance
        let folded_instance = Instance::new(
            folded_public_inputs,
            folded_commitments,
            instance1.size.num_vars,
            instance1.size.num_constraints,
        );

        // Create folded witness
        let folded_witness = FoldedWitness::new(
            folded_assignment,
            vec![challenge], // Store the folding randomness
            vec![witness1.clone(), witness2.clone()],
        );

        // Verify folding correctness
        self.verify_folding_correctness(&folded_instance, &folded_witness)?;

        Ok((folded_instance, folded_witness))
    }

    /// Folds two vectors using linear combination with challenge
    fn fold_vectors(
        &self,
        vec1: &[NovaField],
        vec2: &[NovaField],
        challenge: NovaField,
    ) -> Vec<NovaField> {
        assert_eq!(vec1.len(), vec2.len(), "Vectors must have the same length");
        
        vec1.iter()
            .zip(vec2.iter())
            .map(|(&a, &b)| a + challenge * b)
            .collect()
    }

    /// Parallel version of vector folding for better performance
    fn fold_vectors_parallel(
        &self,
        vec1: &[NovaField],
        vec2: &[NovaField],
        challenge: NovaField,
    ) -> Vec<NovaField> {
        assert_eq!(vec1.len(), vec2.len(), "Vectors must have the same length");
        
        vec1.par_iter()
            .zip(vec2.par_iter())
            .map(|(&a, &b)| a + challenge * b)
            .collect()
    }

    /// Validates that the inputs to folding are compatible
    fn validate_folding_inputs(
        &self,
        instance1: &Instance,
        witness1: &Witness,
        instance2: &Instance,
        witness2: &Witness,
    ) -> NovaResult<()> {
        // Check instance compatibility
        if !instance1.is_compatible_for_folding(instance2) {
            return Err(NovaError::incompatible_instances(
                "Instances are not compatible for folding"
            ));
        }

        // Validate instances
        instance1.validate()?;
        instance2.validate()?;

        // Validate witnesses against the relation
        witness1.validate_against_relation(&self.relation)?;
        witness2.validate_against_relation(&self.relation)?;

        // Check witness assignment lengths
        if witness1.assignment_len() != witness2.assignment_len() {
            return Err(NovaError::invalid_witness(
                "Witness assignments must have the same length"
            ));
        }

        if witness1.assignment_len() != self.relation.num_vars() {
            return Err(NovaError::invalid_witness(
                "Witness assignment length does not match relation variables"
            ));
        }

        Ok(())
    }

    /// Verifies that the folding operation was performed correctly
    fn verify_folding_correctness(
        &self,
        folded_instance: &Instance,
        folded_witness: &FoldedWitness,
    ) -> NovaResult<()> {
        // Validate the folded witness structure
        folded_witness.validate()?;

        // Check that the folded instance is valid
        folded_instance.validate()?;

        // Verify that the folded witness satisfies the relation
        if !self.relation.is_satisfied(&folded_witness.folded_assignment) {
            return Err(NovaError::folding_error(
                "Folded witness does not satisfy the relation"
            ));
        }

        Ok(())
    }

    /// Computes the folding error (for analysis and debugging)
    pub fn compute_folding_error(
        &self,
        _instance1: &Instance,
        witness1: &Witness,
        _instance2: &Instance,
        witness2: &Witness,
        challenge: NovaField,
    ) -> NovaResult<Vec<NovaField>> {
        // Evaluate constraints on both original witnesses
        let eval1 = self.relation.evaluate_constraints(&witness1.assignment);
        let eval2 = self.relation.evaluate_constraints(&witness2.assignment);

        // Compute expected folded evaluation: eval1 + challenge * eval2
        let expected_folded_eval = self.fold_vectors(&eval1, &eval2, challenge);

        // Compute actual folded witness
        let folded_assignment = self.fold_vectors(&witness1.assignment, &witness2.assignment, challenge);
        let actual_folded_eval = self.relation.evaluate_constraints(&folded_assignment);

        // Compute error
        let error: Vec<NovaField> = expected_folded_eval
            .iter()
            .zip(actual_folded_eval.iter())
            .map(|(&expected, &actual)| expected - actual)
            .collect();

        Ok(error)
    }

    /// Returns the relation used by this folding scheme
    pub fn relation(&self) -> &Relation {
        &self.relation
    }

    /// Returns the folding parameters
    pub fn parameters(&self) -> &FoldingParameters {
        &self.parameters
    }
}

/// Accumulator for managing folded instances and witnesses
#[derive(Debug, Clone)]
pub struct FoldingAccumulator {
    /// Current accumulated instance
    pub instance: Option<Instance>,
    /// Current accumulated witness
    pub witness: Option<FoldedWitness>,
    /// Folding scheme used for accumulation
    folding_scheme: FoldingScheme,
    /// Accumulation depth
    depth: usize,
}

impl FoldingAccumulator {
    /// Creates a new folding accumulator
    pub fn new(folding_scheme: FoldingScheme) -> Self {
        Self {
            instance: None,
            witness: None,
            folding_scheme,
            depth: 0,
        }
    }

    /// Adds a new instance and witness to the accumulator
    pub fn accumulate(
        &mut self,
        new_instance: Instance,
        new_witness: Witness,
        transcript: &mut Transcript,
    ) -> NovaResult<()> {
        match (&self.instance, &self.witness) {
            (None, None) => {
                // First accumulation - just store the instance and witness
                self.instance = Some(new_instance);
                self.witness = Some(FoldedWitness::new(
                    new_witness.assignment.clone(),
                    Vec::new(),
                    vec![new_witness],
                ));
                self.depth = 1;
            }
            (Some(acc_instance), Some(acc_witness)) => {
                // Fold with existing accumulation
                let acc_witness_regular = acc_witness.to_witness();
                let (folded_instance, folded_witness) = self.folding_scheme.fold(
                    acc_instance,
                    &acc_witness_regular,
                    &new_instance,
                    &new_witness,
                    transcript,
                )?;
                
                self.instance = Some(folded_instance);
                self.witness = Some(folded_witness);
                self.depth += 1;
            }
            _ => {
                return Err(NovaError::internal_error(
                    "Accumulator in inconsistent state"
                ));
            }
        }

        // Check depth limits
        if self.depth > self.folding_scheme.parameters.max_depth {
            return Err(NovaError::resource_exhaustion(
                "Maximum folding depth exceeded"
            ));
        }

        Ok(())
    }

    /// Returns the current accumulated instance and witness
    pub fn current(&self) -> Option<(&Instance, &FoldedWitness)> {
        match (&self.instance, &self.witness) {
            (Some(instance), Some(witness)) => Some((instance, witness)),
            _ => None,
        }
    }

    /// Returns the current accumulation depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Checks if the accumulator is empty
    pub fn is_empty(&self) -> bool {
        self.instance.is_none() && self.witness.is_none()
    }

    /// Resets the accumulator
    pub fn reset(&mut self) {
        self.instance = None;
        self.witness = None;
        self.depth = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instances::Relation;
    use crate::fields::{NovaField, MultilinearPolynomial};
    use ark_std::{vec, Zero, One};

    fn create_test_relation() -> Relation {
        // Simple linear relation: x + y - z = 0
        // This is a 3-variable multilinear polynomial: f(x,y,z) = x + y - z
        // Evaluations at (0,0,0), (1,0,0), (0,1,0), (1,1,0), (0,0,1), (1,0,1), (0,1,1), (1,1,1)
        // f(0,0,0) = 0, f(1,0,0) = 1, f(0,1,0) = 1, f(1,1,0) = 2
        // f(0,0,1) = -1, f(1,0,1) = 0, f(0,1,1) = 0, f(1,1,1) = 1
        let evaluations = vec![
            NovaField::zero(),          // (0,0,0): 0 + 0 - 0 = 0
            NovaField::one(),           // (1,0,0): 1 + 0 - 0 = 1
            NovaField::one(),           // (0,1,0): 0 + 1 - 0 = 1
            NovaField::from(2u64),      // (1,1,0): 1 + 1 - 0 = 2
            -NovaField::one(),          // (0,0,1): 0 + 0 - 1 = -1
            NovaField::zero(),          // (1,0,1): 1 + 0 - 1 = 0
            NovaField::zero(),          // (0,1,1): 0 + 1 - 1 = 0
            NovaField::one(),           // (1,1,1): 1 + 1 - 1 = 1
        ];
        
        let constraint = MultilinearPolynomial::new(evaluations);
        Relation::new(vec![constraint], vec![2]).unwrap()
    }

    fn create_test_instances_and_witnesses() -> (Instance, Witness, Instance, Witness) {
        // First instance: 2 + 3 = 5
        let witness1 = Witness::new(vec![
            NovaField::from(2u64), // x
            NovaField::from(3u64), // y
            NovaField::from(5u64), // z
        ]);
        let instance1 = Instance::new(
            vec![NovaField::from(5u64)], // z is public
            vec![NovaField::zero()],
            3,
            1,
        );

        // Second instance: 4 + 1 = 5
        let witness2 = Witness::new(vec![
            NovaField::from(4u64), // x
            NovaField::from(1u64), // y
            NovaField::from(5u64), // z
        ]);
        let instance2 = Instance::new(
            vec![NovaField::from(5u64)], // z is public
            vec![NovaField::zero()],
            3,
            1,
        );

        (instance1, witness1, instance2, witness2)
    }

    #[test]
    fn test_folding_scheme_creation() {
        let relation = create_test_relation();
        let folding_scheme = FoldingScheme::new(relation);
        
        assert_eq!(folding_scheme.relation.num_vars(), 3);
        assert_eq!(folding_scheme.relation.num_constraints(), 1);
        assert!(folding_scheme.parameters.enable_parallel);
    }

    #[test]
    fn test_vector_folding() {
        let relation = create_test_relation();
        let folding_scheme = FoldingScheme::new(relation);
        
        let vec1 = vec![NovaField::from(1u64), NovaField::from(2u64)];
        let vec2 = vec![NovaField::from(3u64), NovaField::from(4u64)];
        let challenge = NovaField::from(5u64);
        
        let result = folding_scheme.fold_vectors(&vec1, &vec2, challenge);
        
        // Expected: [1 + 5*3, 2 + 5*4] = [16, 22]
        assert_eq!(result[0], NovaField::from(16u64));
        assert_eq!(result[1], NovaField::from(22u64));
    }

    #[test]
    fn test_folding_with_challenge() {
        let relation = create_test_relation();
        let folding_scheme = FoldingScheme::new(relation);
        let (instance1, witness1, instance2, witness2) = create_test_instances_and_witnesses();
        
        let challenge = NovaField::from(7u64);
        let result = folding_scheme.fold_with_challenge(
            &instance1, &witness1, &instance2, &witness2, challenge
        );
        
        if let Err(e) = &result {
            println!("Folding error: {:?}", e);
        }
        assert!(result.is_ok());
        let (folded_instance, folded_witness) = result.unwrap();
        
        // Check that folded witness has correct structure
        assert_eq!(folded_witness.num_folded_witnesses(), 2);
        assert_eq!(folded_witness.folding_randomness, vec![challenge]);
        
        // Check that folded instance has correct public input
        // Expected: 5 + 7 * 5 = 40
        assert_eq!(folded_instance.public_inputs[0], NovaField::from(40u64));
    }

    #[test]
    fn test_folding_with_transcript() {
        let relation = create_test_relation();
        let folding_scheme = FoldingScheme::new(relation.clone());
        let (instance1, witness1, instance2, witness2) = create_test_instances_and_witnesses();
        
        let mut transcript = Transcript::new("test-folding");
        let result = folding_scheme.fold(
            &instance1, &witness1, &instance2, &witness2, &mut transcript
        );
        
        assert!(result.is_ok());
        let (folded_instance, folded_witness) = result.unwrap();
        
        // Verify that the folded witness satisfies the relation
        assert!(relation.is_satisfied(&folded_witness.folded_assignment));
        
        // Verify instance structure
        assert_eq!(folded_instance.size.num_vars, 3);
        assert_eq!(folded_instance.size.num_constraints, 1);
        assert_eq!(folded_instance.size.num_public_inputs, 1);
    }

    #[test]
    fn test_folding_validation() {
        let relation = create_test_relation();
        let folding_scheme = FoldingScheme::new(relation);
        
        // Create incompatible instances
        let instance1 = Instance::new(
            vec![NovaField::from(6u64)],
            vec![NovaField::zero()],
            3, // 3 variables
            1,
        );
        let instance2 = Instance::new(
            vec![NovaField::from(20u64)],
            vec![NovaField::zero()],
            4, // 4 variables - incompatible!
            1,
        );
        
        let witness1 = Witness::new(vec![
            NovaField::from(2u64),
            NovaField::from(3u64),
            NovaField::from(6u64),
        ]);
        let witness2 = Witness::new(vec![
            NovaField::from(4u64),
            NovaField::from(5u64),
            NovaField::from(20u64),
            NovaField::from(0u64), // Extra variable
        ]);
        
        let mut transcript = Transcript::new("test");
        let result = folding_scheme.fold(&instance1, &witness1, &instance2, &witness2, &mut transcript);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_folding_accumulator() {
        let relation = create_test_relation();
        let folding_scheme = FoldingScheme::new(relation);
        let mut accumulator = FoldingAccumulator::new(folding_scheme);
        
        assert!(accumulator.is_empty());
        assert_eq!(accumulator.depth(), 0);
        
        // Add first instance: 2 + 3 = 5
        let witness1 = Witness::new(vec![
            NovaField::from(2u64),
            NovaField::from(3u64),
            NovaField::from(5u64),
        ]);
        let instance1 = Instance::new(
            vec![NovaField::from(5u64)],
            vec![NovaField::zero()],
            3,
            1,
        );
        
        let mut transcript = Transcript::new("test");
        let result = accumulator.accumulate(instance1, witness1, &mut transcript);
        assert!(result.is_ok());
        assert_eq!(accumulator.depth(), 1);
        assert!(!accumulator.is_empty());
        
        // Add second instance: 4 + 1 = 5
        let witness2 = Witness::new(vec![
            NovaField::from(4u64),
            NovaField::from(1u64),
            NovaField::from(5u64),
        ]);
        let instance2 = Instance::new(
            vec![NovaField::from(5u64)],
            vec![NovaField::zero()],
            3,
            1,
        );
        
        let result = accumulator.accumulate(instance2, witness2, &mut transcript);
        if let Err(e) = &result {
            println!("Accumulator error: {:?}", e);
        }
        assert!(result.is_ok());
        assert_eq!(accumulator.depth(), 2);
        
        // Check current state
        let current = accumulator.current();
        assert!(current.is_some());
        let (_current_instance, current_witness) = current.unwrap();
        assert_eq!(current_witness.num_folded_witnesses(), 2);
    }

    #[test]
    fn test_compute_folding_error() {
        let relation = create_test_relation();
        let folding_scheme = FoldingScheme::new(relation);
        let (instance1, witness1, instance2, witness2) = create_test_instances_and_witnesses();
        
        let challenge = NovaField::from(7u64);
        let error = folding_scheme.compute_folding_error(
            &instance1, &witness1, &instance2, &witness2, challenge
        ).unwrap();
        
        // For a correct folding, the error should be zero
        assert_eq!(error[0], NovaField::zero());
    }
}