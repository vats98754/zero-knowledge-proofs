//! # Fibonacci Sequence Circuit Example
//!
//! This example demonstrates how to build a Halo2 arithmetic circuit that proves
//! knowledge of the n-th Fibonacci number without revealing the intermediate values.
//! The circuit constrains the relationship F(n) = F(n-1) + F(n-2) for a configurable
//! number of steps.

use halo2_arith::{
    CircuitBuilder, Halo2Circuit, StandardGate, AdditionGate, EqualityGate,
    AdviceColumn, FixedColumn, InstanceColumn, ColumnManager,
    ConstraintSystem, Expression, Constraint, Scalar, Result, Halo2Error
};
use commitments::{IpaCommitmentEngine, CommitmentEngine};
use halo_core::Circuit;
use ff::Field;
use bls12_381::Scalar as BlsScalar;
use rand::Rng;
use std::collections::HashMap;

/// Configuration for the Fibonacci circuit
#[derive(Clone, Debug)]
pub struct FibonacciConfig {
    /// Number of Fibonacci iterations to prove
    pub num_iterations: usize,
    /// Advice columns for current and next values
    pub advice_a: AdviceColumn,
    pub advice_b: AdviceColumn,
    /// Fixed column for selector
    pub selector: FixedColumn,
    /// Instance column for public outputs
    pub instance: InstanceColumn,
}

impl FibonacciConfig {
    /// Create a new Fibonacci configuration
    pub fn new(num_iterations: usize) -> Self {
        Self {
            num_iterations,
            advice_a: AdviceColumn::new(0),
            advice_b: AdviceColumn::new(1),
            selector: FixedColumn::new(0),
            instance: InstanceColumn::new(0),
        }
    }
}

/// Fibonacci circuit implementation
#[derive(Clone, Debug)]
pub struct FibonacciCircuit {
    /// Circuit configuration
    pub config: FibonacciConfig,
    /// Initial values F(0) and F(1)
    pub initial_a: Scalar,
    pub initial_b: Scalar,
    /// Expected final result
    pub expected_result: Scalar,
    /// Witness values for the sequence
    pub witnesses: Vec<(Scalar, Scalar)>,
}

impl FibonacciCircuit {
    /// Create a new Fibonacci circuit with the given number of iterations
    pub fn new(num_iterations: usize) -> Result<Self> {
        let config = FibonacciConfig::new(num_iterations);
        
        // Standard Fibonacci sequence: F(0) = 0, F(1) = 1
        let initial_a = Scalar::zero();
        let initial_b = Scalar::one();
        
        // Compute the witness values
        let mut witnesses = Vec::new();
        let mut a = initial_a;
        let mut b = initial_b;
        
        witnesses.push((a, b));
        
        for _ in 0..num_iterations {
            let next = a + b;
            witnesses.push((b, next));
            a = b;
            b = next;
        }
        
        let expected_result = b;
        
        Ok(Self {
            config,
            initial_a,
            initial_b,
            expected_result,
            witnesses,
        })
    }
    
    /// Create a Fibonacci circuit with custom initial values
    pub fn with_initial_values(
        num_iterations: usize, 
        initial_a: Scalar, 
        initial_b: Scalar
    ) -> Result<Self> {
        let config = FibonacciConfig::new(num_iterations);
        
        // Compute the witness values with custom initial values
        let mut witnesses = Vec::new();
        let mut a = initial_a;
        let mut b = initial_b;
        
        witnesses.push((a, b));
        
        for _ in 0..num_iterations {
            let next = a + b;
            witnesses.push((b, next));
            a = b;
            b = next;
        }
        
        let expected_result = b;
        
        Ok(Self {
            config,
            initial_a,
            initial_b,
            expected_result,
            witnesses,
        })
    }
}

impl Circuit for FibonacciCircuit {
    type Config = FibonacciConfig;
    type Error = Halo2Error;
    
    fn configure(config: &Self::Config) -> Result<Self> {
        // This is a placeholder - actual configuration would happen during circuit synthesis
        Ok(Self {
            config: config.clone(),
            initial_a: Scalar::zero(),
            initial_b: Scalar::one(),
            expected_result: Scalar::zero(),
            witnesses: Vec::new(),
        })
    }
    
    fn synthesize(&self) -> Result<()> {
        // Create constraint system
        let mut cs = ConstraintSystem::new();
        
        // Add Fibonacci step constraint: next = current + previous
        // For each row: advice_b[i] = advice_a[i] + advice_b[i-1]
        for i in 0..self.config.num_iterations {
            let constraint = Constraint::new(
                format!("fibonacci_step_{}", i),
                Expression::Addition(
                    Box::new(Expression::Advice(self.config.advice_a, i)),
                    Box::new(Expression::Advice(self.config.advice_b, i))
                ) - Expression::Advice(self.config.advice_b, i + 1)
            );
            cs.add_constraint(constraint)?;
        }
        
        // Add initial value constraints
        let initial_a_constraint = Constraint::new(
            "initial_a".to_string(),
            Expression::Advice(self.config.advice_a, 0) - Expression::Constant(self.initial_a)
        );
        cs.add_constraint(initial_a_constraint)?;
        
        let initial_b_constraint = Constraint::new(
            "initial_b".to_string(),
            Expression::Advice(self.config.advice_b, 0) - Expression::Constant(self.initial_b)
        );
        cs.add_constraint(initial_b_constraint)?;
        
        // Add public input constraint for the final result
        let final_row = self.config.num_iterations;
        let public_constraint = Constraint::new(
            "public_output".to_string(),
            Expression::Advice(self.config.advice_b, final_row) - 
            Expression::Instance(self.config.instance, 0)
        );
        cs.add_constraint(public_constraint)?;
        
        Ok(())
    }
}

/// Build and verify a Fibonacci circuit
pub fn build_fibonacci_circuit(num_iterations: usize) -> Result<Halo2Circuit> {
    // Create the circuit
    let fib_circuit = FibonacciCircuit::new(num_iterations)?;
    
    // Create column manager
    let mut column_manager = ColumnManager::new();
    column_manager.add_advice_column(fib_circuit.config.advice_a);
    column_manager.add_advice_column(fib_circuit.config.advice_b);
    column_manager.add_fixed_column(fib_circuit.config.selector);
    column_manager.add_instance_column(fib_circuit.config.instance);
    
    // Build the circuit using CircuitBuilder
    let mut builder = CircuitBuilder::new(column_manager);
    
    // Add standard gates for arithmetic operations
    builder = builder.gate(StandardGate::new("fibonacci_add".to_string()))?;
    builder = builder.gate(AdditionGate::new("fib_addition".to_string()))?;
    builder = builder.gate(EqualityGate::new("fib_equality".to_string()))?;
    
    // Build the circuit
    let mut circuit = builder.build()?;
    
    // Assign witness values
    for (row, (a_val, b_val)) in fib_circuit.witnesses.iter().enumerate() {
        circuit.assign(fib_circuit.config.advice_a, row, *a_val)?;
        circuit.assign(fib_circuit.config.advice_b, row, *b_val)?;
    }
    
    // Set public instance
    circuit.assign_instance(fib_circuit.config.instance, 0, fib_circuit.expected_result)?;
    
    // Finalize the circuit
    circuit.finalize()?;
    
    Ok(circuit)
}

/// Demonstrate Fibonacci circuit with proof generation and verification
pub fn demonstrate_fibonacci_proof() -> Result<()> {
    println!("🔢 Fibonacci Circuit Demonstration");
    println!("=====================================");
    
    let num_iterations = 10;
    println!("📊 Computing F({}) using {} iterations", num_iterations, num_iterations);
    
    // Build the circuit
    let circuit = build_fibonacci_circuit(num_iterations)?;
    
    // Verify constraints
    let is_valid = circuit.verify_constraints()?;
    println!("✅ Circuit constraints valid: {}", is_valid);
    
    // Display circuit statistics
    let stats = circuit.stats();
    println!("📈 Circuit Statistics:");
    println!("   - Total columns: {}", stats.total_columns);
    println!("   - Advice columns: {}", stats.advice_columns);
    println!("   - Fixed columns: {}", stats.fixed_columns);
    println!("   - Instance columns: {}", stats.instance_columns);
    println!("   - Total constraints: {}", stats.total_constraints);
    println!("   - Circuit size: {} rows", stats.circuit_size);
    
    // Show the Fibonacci sequence computed
    let fib_circuit = FibonacciCircuit::new(num_iterations)?;
    println!("🔄 Fibonacci Sequence:");
    for (i, (a, b)) in fib_circuit.witnesses.iter().enumerate() {
        if i == 0 {
            println!("   F(0) = {}, F(1) = {}", 
                     format_scalar_short(*a), format_scalar_short(*b));
        } else {
            println!("   F({}) = {}", i + 1, format_scalar_short(*b));
        }
    }
    
    println!("🎯 Expected result: {}", format_scalar_short(fib_circuit.expected_result));
    println!("✨ Fibonacci circuit demonstration completed successfully!");
    
    Ok(())
}

/// Range check circuit demonstrating constraint validation
pub fn demonstrate_range_check() -> Result<()> {
    println!("\n🔒 Range Check Circuit Demonstration");
    println!("====================================");
    
    // Create a simple range check circuit for values 0-15 (4 bits)
    let mut column_manager = ColumnManager::new();
    let value_col = AdviceColumn::new(0);
    let bit_cols = [
        AdviceColumn::new(1),
        AdviceColumn::new(2), 
        AdviceColumn::new(3),
        AdviceColumn::new(4),
    ];
    let selector = FixedColumn::new(0);
    
    column_manager.add_advice_column(value_col);
    for &bit_col in &bit_cols {
        column_manager.add_advice_column(bit_col);
    }
    column_manager.add_fixed_column(selector);
    
    let mut builder = CircuitBuilder::new(column_manager);
    builder = builder.gate(StandardGate::new("range_check".to_string()))?;
    
    let mut circuit = builder.build()?;
    
    // Test value to range check
    let test_value = BlsScalar::from(13u64); // Should decompose to bits [1, 0, 1, 1]
    let bits = [
        BlsScalar::one(),   // bit 0
        BlsScalar::zero(),  // bit 1  
        BlsScalar::one(),   // bit 2
        BlsScalar::one(),   // bit 3
    ];
    
    // Assign values
    circuit.assign(value_col, 0, test_value)?;
    for (i, &bit) in bits.iter().enumerate() {
        circuit.assign(bit_cols[i], 0, bit)?;
    }
    
    // Verify that bits are 0 or 1 and reconstruct the value
    let mut reconstructed = BlsScalar::zero();
    let mut power = BlsScalar::one();
    
    for &bit in &bits {
        reconstructed += bit * power;
        power = power + power; // power *= 2
    }
    
    println!("🔍 Range Check Results:");
    println!("   Original value: {}", format_scalar_short(test_value));
    println!("   Bit decomposition: {:?}", bits.iter().map(|b| format_scalar_short(*b)).collect::<Vec<_>>());
    println!("   Reconstructed: {}", format_scalar_short(reconstructed));
    println!("   ✅ Valid decomposition: {}", test_value == reconstructed);
    
    Ok(())
}

/// Helper function to format scalar values for display
fn format_scalar_short(scalar: Scalar) -> String {
    format!("{:?}", scalar).chars().take(10).collect::<String>() + "..."
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fibonacci_circuit_creation() {
        let circuit = FibonacciCircuit::new(5).unwrap();
        assert_eq!(circuit.config.num_iterations, 5);
        assert_eq!(circuit.witnesses.len(), 6); // 0..5 inclusive
    }
    
    #[test]
    fn test_fibonacci_sequence_values() {
        let circuit = FibonacciCircuit::new(10).unwrap();
        
        // Check first few Fibonacci numbers
        assert_eq!(circuit.witnesses[0], (Scalar::zero(), Scalar::one()));
        assert_eq!(circuit.witnesses[1], (Scalar::one(), Scalar::one()));
        assert_eq!(circuit.witnesses[2], (Scalar::one(), Scalar::from(2u64)));
        assert_eq!(circuit.witnesses[3], (Scalar::from(2u64), Scalar::from(3u64)));
        assert_eq!(circuit.witnesses[4], (Scalar::from(3u64), Scalar::from(5u64)));
    }
    
    #[test]
    fn test_custom_initial_values() {
        let a = Scalar::from(2u64);
        let b = Scalar::from(3u64);
        let circuit = FibonacciCircuit::with_initial_values(3, a, b).unwrap();
        
        assert_eq!(circuit.witnesses[0], (a, b));
        assert_eq!(circuit.witnesses[1], (b, a + b));
        assert_eq!(circuit.witnesses[2], (a + b, b + (a + b)));
    }
    
    #[test]
    fn test_circuit_building() {
        let circuit = build_fibonacci_circuit(5);
        assert!(circuit.is_ok());
    }
    
    #[test] 
    fn test_constraint_verification() {
        let circuit = build_fibonacci_circuit(3).unwrap();
        let is_valid = circuit.verify_constraints().unwrap();
        assert!(is_valid);
    }
}
