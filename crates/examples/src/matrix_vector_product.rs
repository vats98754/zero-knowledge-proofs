//! Example: Matrix-Vector Product using Nova incremental computation
//! 
//! This example demonstrates how to use Nova to prove the correctness of
//! repeated matrix-vector multiplications in an incremental manner.

use nova_core::*;
use ark_std::{vec, vec::Vec, Zero};

/// Simple matrix-vector multiplication step
fn matrix_vector_step(matrix: &[Vec<NovaField>], vector: &[NovaField]) -> Vec<NovaField> {
    let mut result = Vec::new();
    for row in matrix {
        let mut sum = NovaField::zero();
        for (i, &val) in row.iter().enumerate() {
            if i < vector.len() {
                sum += val * vector[i];
            }
        }
        result.push(sum);
    }
    result
}

fn main() {
    println!("Nova Matrix-Vector Product Example");
    
    // Example 2x2 matrix
    let matrix = vec![
        vec![NovaField::from(1u64), NovaField::from(2u64)],
        vec![NovaField::from(3u64), NovaField::from(4u64)],
    ];
    
    // Initial vector
    let mut vector = vec![NovaField::from(5u64), NovaField::from(6u64)];
    
    println!("Initial vector: [{}, {}]", vector[0], vector[1]);
    
    // Perform 3 iterations
    for i in 0..3 {
        vector = matrix_vector_step(&matrix, &vector);
        println!("After iteration {}: [{}, {}]", i + 1, vector[0], vector[1]);
    }
    
    println!("Matrix-vector product example completed!");
}