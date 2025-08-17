//! Witness data structures and operations for Nova.
//!
//! This module defines witness representations and operations for Nova's
//! incremental verifiable computation scheme.

use crate::fields::NovaField;
use crate::instances::{Instance, Relation};
use crate::errors::NovaError;
use ark_std::{vec::Vec, Zero};

/// Represents witness data for a computational instance.
/// 
/// A witness contains the private data needed to satisfy the constraints
/// of a computational relation. It includes both the variable assignments
/// and any auxiliary data needed for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// Variable assignments that satisfy the relation
    pub assignment: Vec<NovaField>,
    /// Auxiliary data for the witness (e.g., randomness, intermediate values)
    pub auxiliary: Vec<NovaField>,
}

impl Witness {
    /// Creates a new witness with the given assignment
    pub fn new(assignment: Vec<NovaField>) -> Self {
        Self {
            assignment,
            auxiliary: Vec::new(),
        }
    }

    /// Creates a new witness with assignment and auxiliary data
    pub fn with_auxiliary(assignment: Vec<NovaField>, auxiliary: Vec<NovaField>) -> Self {
        Self {
            assignment,
            auxiliary,
        }
    }

    /// Returns the length of the main assignment
    pub fn assignment_len(&self) -> usize {
        self.assignment.len()
    }

    /// Returns the length of auxiliary data
    pub fn auxiliary_len(&self) -> usize {
        self.auxiliary.len()
    }

    /// Validates the witness against a relation
    pub fn validate_against_relation(&self, relation: &Relation) -> Result<(), NovaError> {
        if self.assignment.len() != relation.num_vars() {
            return Err(NovaError::InvalidWitness(
                format!(
                    "Witness assignment length {} does not match relation variables {}",
                    self.assignment.len(),
                    relation.num_vars()
                )
            ));
        }

        if !relation.is_satisfied(&self.assignment) {
            return Err(NovaError::InvalidWitness(
                "Witness does not satisfy the relation".to_string()
            ));
        }

        Ok(())
    }

    /// Extracts public inputs according to the relation's public input indices
    pub fn extract_public_inputs(&self, public_input_indices: &[usize]) -> Result<Vec<NovaField>, NovaError> {
        let mut public_inputs = Vec::new();
        
        for &idx in public_input_indices {
            if idx >= self.assignment.len() {
                return Err(NovaError::InvalidWitness(
                    format!("Public input index {} out of range", idx)
                ));
            }
            public_inputs.push(self.assignment[idx]);
        }

        Ok(public_inputs)
    }

    /// Adds auxiliary data to the witness
    pub fn add_auxiliary(&mut self, aux_data: Vec<NovaField>) {
        self.auxiliary.extend(aux_data);
    }

    /// Gets a specific auxiliary value by index
    pub fn get_auxiliary(&self, index: usize) -> Option<NovaField> {
        self.auxiliary.get(index).copied()
    }
}

/// Represents a folded witness that results from the folding operation.
/// 
/// When two witnesses are folded together, the result contains the combined
/// information needed to verify both original computations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedWitness {
    /// The folded assignment
    pub folded_assignment: Vec<NovaField>,
    /// Randomness used in the folding process
    pub folding_randomness: Vec<NovaField>,
    /// Original witnesses that were folded (for debugging/verification)
    pub original_witnesses: Vec<Witness>,
}

impl FoldedWitness {
    /// Creates a new folded witness
    pub fn new(
        folded_assignment: Vec<NovaField>,
        folding_randomness: Vec<NovaField>,
        original_witnesses: Vec<Witness>,
    ) -> Self {
        Self {
            folded_assignment,
            folding_randomness,
            original_witnesses,
        }
    }

    /// Returns the number of original witnesses that were folded
    pub fn num_folded_witnesses(&self) -> usize {
        self.original_witnesses.len()
    }

    /// Validates the folded witness structure
    pub fn validate(&self) -> Result<(), NovaError> {
        if self.original_witnesses.is_empty() {
            return Err(NovaError::InvalidWitness(
                "Folded witness must contain at least one original witness".to_string()
            ));
        }

        // Check that all original witnesses have the same assignment length
        let expected_len = self.original_witnesses[0].assignment_len();
        for (i, witness) in self.original_witnesses.iter().enumerate() {
            if witness.assignment_len() != expected_len {
                return Err(NovaError::InvalidWitness(
                    format!("Original witness {} has inconsistent assignment length", i)
                ));
            }
        }

        if self.folded_assignment.len() != expected_len {
            return Err(NovaError::InvalidWitness(
                "Folded assignment length does not match original witnesses".to_string()
            ));
        }

        Ok(())
    }

    /// Converts the folded witness back to a regular witness
    pub fn to_witness(&self) -> Witness {
        Witness::with_auxiliary(
            self.folded_assignment.clone(),
            self.folding_randomness.clone(),
        )
    }
}

/// Witness accumulator for managing multiple witnesses in recursive proofs.
/// 
/// The accumulator maintains a collection of witnesses and their associated
/// metadata throughout the recursive proving process.
#[derive(Debug, Clone)]
pub struct WitnessAccumulator {
    /// Stack of witnesses from the recursive computation
    pub witness_stack: Vec<Witness>,
    /// Folded witnesses at each level
    pub folded_witnesses: Vec<FoldedWitness>,
    /// Metadata about the accumulation process
    pub metadata: AccumulatorMetadata,
}

/// Metadata for the witness accumulator
#[derive(Debug, Clone)]
pub struct AccumulatorMetadata {
    /// Current depth in the recursion
    pub depth: usize,
    /// Total number of computation steps accumulated
    pub total_steps: usize,
    /// Maximum depth reached
    pub max_depth: usize,
}

impl WitnessAccumulator {
    /// Creates a new empty witness accumulator
    pub fn new() -> Self {
        Self {
            witness_stack: Vec::new(),
            folded_witnesses: Vec::new(),
            metadata: AccumulatorMetadata {
                depth: 0,
                total_steps: 0,
                max_depth: 0,
            },
        }
    }

    /// Adds a witness to the accumulator
    pub fn push_witness(&mut self, witness: Witness) {
        self.witness_stack.push(witness);
        self.metadata.depth += 1;
        self.metadata.total_steps += 1;
        self.metadata.max_depth = self.metadata.max_depth.max(self.metadata.depth);
    }

    /// Removes and returns the top witness from the accumulator
    pub fn pop_witness(&mut self) -> Option<Witness> {
        if let Some(witness) = self.witness_stack.pop() {
            if self.metadata.depth > 0 {
                self.metadata.depth -= 1;
            }
            Some(witness)
        } else {
            None
        }
    }

    /// Adds a folded witness to the accumulator
    pub fn push_folded_witness(&mut self, folded_witness: FoldedWitness) {
        self.folded_witnesses.push(folded_witness);
    }

    /// Returns the current depth of the accumulator
    pub fn depth(&self) -> usize {
        self.metadata.depth
    }

    /// Returns the total number of steps accumulated
    pub fn total_steps(&self) -> usize {
        self.metadata.total_steps
    }

    /// Checks if the accumulator is empty
    pub fn is_empty(&self) -> bool {
        self.witness_stack.is_empty() && self.folded_witnesses.is_empty()
    }

    /// Returns the size of the witness stack
    pub fn stack_size(&self) -> usize {
        self.witness_stack.len()
    }

    /// Returns the number of folded witnesses
    pub fn num_folded(&self) -> usize {
        self.folded_witnesses.len()
    }

    /// Validates the entire accumulator structure
    pub fn validate(&self) -> Result<(), NovaError> {
        // Validate all folded witnesses
        for (i, folded_witness) in self.folded_witnesses.iter().enumerate() {
            folded_witness.validate().map_err(|e| {
                NovaError::InvalidWitness(format!("Folded witness {} is invalid: {}", i, e))
            })?;
        }

        // Check metadata consistency
        if self.metadata.depth != self.witness_stack.len() {
            return Err(NovaError::InvalidWitness(
                "Accumulator depth does not match witness stack size".to_string()
            ));
        }

        if self.metadata.max_depth < self.metadata.depth {
            return Err(NovaError::InvalidWitness(
                "Maximum depth is less than current depth".to_string()
            ));
        }

        Ok(())
    }
}

impl Default for WitnessAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::NovaField;
    use ark_std::{vec, Zero, One};

    #[test]
    fn test_witness_creation() {
        let assignment = vec![
            NovaField::from(1u64),
            NovaField::from(2u64),
            NovaField::from(3u64),
        ];
        let witness = Witness::new(assignment.clone());

        assert_eq!(witness.assignment, assignment);
        assert_eq!(witness.assignment_len(), 3);
        assert_eq!(witness.auxiliary_len(), 0);
    }

    #[test]
    fn test_witness_with_auxiliary() {
        let assignment = vec![NovaField::from(1u64), NovaField::from(2u64)];
        let auxiliary = vec![NovaField::from(99u64)];
        let witness = Witness::with_auxiliary(assignment.clone(), auxiliary.clone());

        assert_eq!(witness.assignment, assignment);
        assert_eq!(witness.auxiliary, auxiliary);
        assert_eq!(witness.assignment_len(), 2);
        assert_eq!(witness.auxiliary_len(), 1);
    }

    #[test]
    fn test_witness_extract_public_inputs() {
        let assignment = vec![
            NovaField::from(1u64),
            NovaField::from(2u64),
            NovaField::from(3u64),
        ];
        let witness = Witness::new(assignment);
        
        let public_input_indices = vec![0, 2];
        let public_inputs = witness.extract_public_inputs(&public_input_indices).unwrap();
        
        assert_eq!(public_inputs, vec![NovaField::from(1u64), NovaField::from(3u64)]);
    }

    #[test]
    fn test_witness_extract_public_inputs_out_of_range() {
        let assignment = vec![NovaField::from(1u64), NovaField::from(2u64)];
        let witness = Witness::new(assignment);
        
        let public_input_indices = vec![0, 3]; // Index 3 is out of range
        let result = witness.extract_public_inputs(&public_input_indices);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_add_auxiliary() {
        let assignment = vec![NovaField::from(1u64)];
        let mut witness = Witness::new(assignment);
        
        witness.add_auxiliary(vec![NovaField::from(10u64), NovaField::from(20u64)]);
        
        assert_eq!(witness.auxiliary_len(), 2);
        assert_eq!(witness.get_auxiliary(0), Some(NovaField::from(10u64)));
        assert_eq!(witness.get_auxiliary(1), Some(NovaField::from(20u64)));
        assert_eq!(witness.get_auxiliary(2), None);
    }

    #[test]
    fn test_folded_witness_creation() {
        let assignment1 = vec![NovaField::from(1u64), NovaField::from(2u64)];
        let assignment2 = vec![NovaField::from(3u64), NovaField::from(4u64)];
        let witness1 = Witness::new(assignment1);
        let witness2 = Witness::new(assignment2);
        
        let folded_assignment = vec![NovaField::from(5u64), NovaField::from(6u64)];
        let randomness = vec![NovaField::from(99u64)];
        
        let folded_witness = FoldedWitness::new(
            folded_assignment.clone(),
            randomness.clone(),
            vec![witness1, witness2],
        );

        assert_eq!(folded_witness.folded_assignment, folded_assignment);
        assert_eq!(folded_witness.folding_randomness, randomness);
        assert_eq!(folded_witness.num_folded_witnesses(), 2);
    }

    #[test]
    fn test_folded_witness_validation() {
        let assignment1 = vec![NovaField::from(1u64), NovaField::from(2u64)];
        let assignment2 = vec![NovaField::from(3u64), NovaField::from(4u64)];
        let witness1 = Witness::new(assignment1);
        let witness2 = Witness::new(assignment2);
        
        let folded_assignment = vec![NovaField::from(5u64), NovaField::from(6u64)];
        let randomness = vec![NovaField::from(99u64)];
        
        let folded_witness = FoldedWitness::new(
            folded_assignment,
            randomness,
            vec![witness1, witness2],
        );

        assert!(folded_witness.validate().is_ok());
    }

    #[test]
    fn test_folded_witness_invalid_length() {
        let assignment1 = vec![NovaField::from(1u64), NovaField::from(2u64)];
        let assignment2 = vec![NovaField::from(3u64)]; // Different length
        let witness1 = Witness::new(assignment1);
        let witness2 = Witness::new(assignment2);
        
        let folded_assignment = vec![NovaField::from(5u64), NovaField::from(6u64)];
        let randomness = vec![NovaField::from(99u64)];
        
        let folded_witness = FoldedWitness::new(
            folded_assignment,
            randomness,
            vec![witness1, witness2],
        );

        assert!(folded_witness.validate().is_err());
    }

    #[test]
    fn test_witness_accumulator() {
        let mut accumulator = WitnessAccumulator::new();
        
        assert!(accumulator.is_empty());
        assert_eq!(accumulator.depth(), 0);
        assert_eq!(accumulator.total_steps(), 0);

        // Add some witnesses
        let witness1 = Witness::new(vec![NovaField::from(1u64)]);
        let witness2 = Witness::new(vec![NovaField::from(2u64)]);
        
        accumulator.push_witness(witness1.clone());
        assert_eq!(accumulator.depth(), 1);
        assert_eq!(accumulator.total_steps(), 1);
        assert_eq!(accumulator.stack_size(), 1);

        accumulator.push_witness(witness2);
        assert_eq!(accumulator.depth(), 2);
        assert_eq!(accumulator.total_steps(), 2);
        assert_eq!(accumulator.stack_size(), 2);

        // Pop a witness
        let popped = accumulator.pop_witness();
        assert!(popped.is_some());
        assert_eq!(accumulator.depth(), 1);
        assert_eq!(accumulator.total_steps(), 2); // Total steps don't decrease
        assert_eq!(accumulator.stack_size(), 1);

        assert!(accumulator.validate().is_ok());
    }

    #[test]
    fn test_witness_accumulator_folded() {
        let mut accumulator = WitnessAccumulator::new();
        
        let witness1 = Witness::new(vec![NovaField::from(1u64)]);
        let witness2 = Witness::new(vec![NovaField::from(2u64)]);
        let folded_assignment = vec![NovaField::from(3u64)];
        let randomness = vec![NovaField::from(99u64)];
        
        let folded_witness = FoldedWitness::new(
            folded_assignment,
            randomness,
            vec![witness1, witness2],
        );

        accumulator.push_folded_witness(folded_witness);
        assert_eq!(accumulator.num_folded(), 1);
        assert!(!accumulator.is_empty());
    }
}