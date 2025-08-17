//! Example: Matrix-vector product using Nova incremental computation
//! 
//! This example demonstrates computing y = Ax incrementally where:
//! - A is an m×n matrix
//! - x is an n-dimensional vector  
//! - y is the resulting m-dimensional vector
//!
//! The computation is folded using Nova's incremental system.

use nova_core::*;
use ark_std::{vec::Vec, One, Zero};

/// Matrix-vector computation circuit
pub struct MatrixVectorCircuit {
    /// The matrix A (row-major order)
    pub matrix: Vec<Vec<NovaField>>,
    /// The input vector x
    pub vector: Vec<NovaField>,
    /// Current row being computed
    pub current_row: usize,
    /// Accumulated result vector
    pub result: Vec<NovaField>,
}

impl MatrixVectorCircuit {
    /// Create a new matrix-vector circuit
    pub fn new(matrix: Vec<Vec<NovaField>>, vector: Vec<NovaField>) -> Self {
        let m = matrix.len();
        Self {
            matrix,
            vector,
            current_row: 0,
            result: vec![NovaField::zero(); m],
        }
    }

    /// Compute one step: result[current_row] = sum(matrix[current_row][j] * vector[j])
    pub fn step(&mut self) -> NovaResult<bool> {
        if self.current_row >= self.matrix.len() {
            return Ok(true); // Computation complete
        }

        let row = &self.matrix[self.current_row];
        let mut dot_product = NovaField::zero();
        
        for (j, &matrix_val) in row.iter().enumerate() {
            if j >= self.vector.len() {
                break;
            }
            dot_product += matrix_val * self.vector[j];
        }
        
        self.result[self.current_row] = dot_product;
        self.current_row += 1;
        
        Ok(false) // Not complete yet
    }

    /// Get the current state as witness
    pub fn to_witness(&self) -> Witness {
        let mut witness_data = Vec::new();
        
        // Add current row index
        witness_data.push(NovaField::from(self.current_row as u64));
        
        // Add result vector
        witness_data.extend_from_slice(&self.result);
        
        // Add matrix (flattened)
        for row in &self.matrix {
            witness_data.extend_from_slice(row);
        }
        
        // Add input vector
        witness_data.extend_from_slice(&self.vector);
        
        Witness::new(witness_data)
    }

    /// Create instance for this step
    pub fn to_instance(&self) -> NovaResult<Instance> {
        let m = self.matrix.len();
        let n = if m > 0 { self.matrix[0].len() } else { 0 };
        
        // Instance size includes: current_row + result_vector + matrix + input_vector
        let instance_size = 1 + m + (m * n) + n;
        let relation = Relation::new(instance_size);
        
        Instance::new(relation, instance_size)
    }
}

/// Demonstrate incremental matrix-vector multiplication
pub fn demo_matrix_vector_folding() -> NovaResult<()> {
    println!("🔢 Nova Matrix-Vector Product Demo");
    println!("==================================");
    
    // Create a 3x3 matrix and 3-element vector
    let matrix = vec![
        vec![NovaField::one(), NovaField::from(2u64), NovaField::from(3u64)],
        vec![NovaField::from(4u64), NovaField::from(5u64), NovaField::from(6u64)],
        vec![NovaField::from(7u64), NovaField::from(8u64), NovaField::from(9u64)],
    ];
    
    let vector = vec![
        NovaField::one(),
        NovaField::from(2u64),
        NovaField::from(3u64),
    ];
    
    println!("Matrix A:");
    for (i, row) in matrix.iter().enumerate() {
        print!("  [");
        for (j, val) in row.iter().enumerate() {
            print!("{}", val);
            if j < row.len() - 1 {
                print!(", ");
            }
        }
        println!("]");
    }
    
    println!("\nVector x: {:?}", vector);
    
    // Initialize the circuit
    let mut circuit = MatrixVectorCircuit::new(matrix.clone(), vector.clone());
    
    // Create folding scheme
    let folding_scheme = FoldingScheme::new();
    
    // Initial instance and witness
    let initial_instance = circuit.to_instance()?;
    let initial_witness = circuit.to_witness();
    
    println!("\n🔄 Starting incremental computation...");
    
    // Create accumulator for folding
    let mut accumulator = FoldingAccumulator::new(initial_instance.clone(), initial_witness.clone());
    
    let mut step_count = 0;
    
    // Perform incremental computation
    loop {
        let is_complete = circuit.step()?;
        step_count += 1;
        
        println!("Step {}: Computing row {}", step_count, circuit.current_row - 1);
        println!("  Current result: {:?}", &circuit.result[..circuit.current_row]);
        
        // Create new instance and witness for this step
        let step_instance = circuit.to_instance()?;
        let step_witness = circuit.to_witness();
        
        // Fold this step into the accumulator
        let randomness = NovaField::from((step_count * 17 + 42) as u64); // Deterministic for demo
        accumulator.fold_instance(step_instance, step_witness, randomness)?;
        
        println!("  ✅ Folded step {} into accumulator", step_count);
        
        if is_complete {
            break;
        }
    }
    
    println!("\n🎯 Final result: {:?}", circuit.result);
    
    // Verify the computation manually
    let mut expected = vec![NovaField::zero(); matrix.len()];
    for (i, row) in matrix.iter().enumerate() {
        for (j, &matrix_val) in row.iter().enumerate() {
            expected[i] += matrix_val * vector[j];
        }
    }
    
    println!("Expected result: {:?}", expected);
    
    // Check if results match
    let results_match = circuit.result.iter().zip(expected.iter()).all(|(a, b)| a == b);
    
    if results_match {
        println!("✅ Computation verified successfully!");
    } else {
        println!("❌ Computation verification failed!");
        return Err(NovaError::ValidationFailed("Matrix-vector computation mismatch".to_string()));
    }
    
    println!("\n📊 Folding Statistics:");
    println!("  Total steps: {}", step_count);
    println!("  Accumulator instances folded: {}", step_count);
    println!("  Final accumulator witness size: {}", accumulator.current_witness().data().len());
    
    Ok(())
}

fn main() -> NovaResult<()> {
    demo_matrix_vector_folding()
}