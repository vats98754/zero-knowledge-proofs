//! Benchmarks for Nova incremental verifiable computation.

pub use nova_core::*;
use ark_std::{vec, Zero, One};

/// Helper function to create a simple test relation with the given number of variables
pub fn create_test_relation(num_vars: usize) -> Relation {
    // Create a simple constraint: sum of all variables = 0
    let mut coeffs = vec![NovaField::zero(); 1 << num_vars];
    
    // Set coefficient for each individual variable to 1
    for i in 0..num_vars {
        let index = 1 << i;
        if index < coeffs.len() {
            coeffs[index] = NovaField::one();
        }
    }
    
    let constraint = MultilinearPolynomial::new(coeffs);
    let constraints = vec![constraint];
    let public_input_indices = vec![0]; // First variable is public
    
    Relation::new(constraints, public_input_indices).expect("Failed to create test relation")
}

/// Helper function to create a simple test instance
pub fn create_test_instance(relation: &Relation, _witness_size: usize) -> Instance {
    let public_inputs = vec![NovaField::zero()]; // Single public input
    let commitments = vec![]; // No commitments for simple test
    
    Instance::new(
        public_inputs,
        commitments,
        relation.num_vars(),
        relation.num_constraints(),
    )
}

/// Helper function to fold two vectors with a scalar challenge
pub fn fold_vectors(a: &[NovaField], b: &[NovaField], challenge: NovaField) -> Vec<NovaField> {
    assert_eq!(a.len(), b.len(), "Vectors must have the same length");
    
    a.iter()
        .zip(b.iter())
        .map(|(&a_i, &b_i)| a_i + challenge * b_i)
        .collect()
}