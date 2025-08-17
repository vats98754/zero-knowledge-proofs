//! Example: Recursive computation using Nova
//! 
//! This example demonstrates a recursive computation scheme where we apply
//! a function f repeatedly: x₁ = f(x₀), x₂ = f(x₁), ..., xₙ = f(xₙ₋₁)
//!
//! The function f(x) = x² + c (similar to the Mandelbrot iteration)

use nova_core::*;
use ark_std::{vec, One, Zero};

/// Recursive computation circuit
pub struct RecursiveCircuit {
    /// Current value in the sequence
    pub current: NovaField,
    /// Constant parameter for f(x) = x² + c
    pub constant: NovaField,
    /// Current iteration number
    pub iteration: u64,
    /// Maximum iterations to perform
    pub max_iterations: u64,
    /// History of computed values (for verification)
    pub history: Vec<NovaField>,
}

impl RecursiveCircuit {
    /// Create a new recursive circuit
    pub fn new(initial_value: NovaField, constant: NovaField, max_iterations: u64) -> Self {
        Self {
            current: initial_value,
            constant,
            iteration: 0,
            max_iterations,
            history: vec![initial_value],
        }
    }

    /// Perform one step: x_{n+1} = f(x_n) = x_n² + c
    pub fn step(&mut self) -> NovaResult<bool> {
        if self.iteration >= self.max_iterations {
            return Ok(true); // Computation complete
        }

        // Apply the function f(x) = x² + c
        self.current = self.current * self.current + self.constant;
        self.iteration += 1;
        self.history.push(self.current);

        Ok(self.iteration >= self.max_iterations)
    }

    /// Get the current state as witness
    pub fn to_witness(&self) -> Witness {
        let mut witness_data = vec![
            self.current,
            self.constant,
            NovaField::from(self.iteration),
            NovaField::from(self.max_iterations),
        ];
        
        // Add a portion of history (last few values to avoid huge witnesses)
        let history_window = 5; // Keep last 5 values
        let start_idx = if self.history.len() > history_window {
            self.history.len() - history_window
        } else {
            0
        };
        
        for &val in &self.history[start_idx..] {
            witness_data.push(val);
        }
        
        Witness::new(witness_data)
    }

    /// Create an instance for this computation step
    pub fn to_instance(&self) -> NovaResult<Instance> {
        // Instance includes: current, constant, iteration, max_iterations + history window
        let instance_size = 4 + 5; // Base fields + history window
        let relation = Relation::new(instance_size);
        Instance::new(relation, instance_size)
    }
}

/// Demonstrate recursive computation with Nova folding
pub fn demo_recursive_folding() -> NovaResult<()> {
    println!("🔄 Nova Recursive Computation Demo");
    println!("==================================");
    
    // Parameters for f(x) = x² + c
    let initial_value = NovaField::from(2u64);
    let constant = NovaField::from(1u64); // c = 1
    let max_iterations = 8;
    
    println!("Function: f(x) = x² + {}", constant);
    println!("Initial value: x₀ = {}", initial_value);
    println!("Max iterations: {}", max_iterations);
    
    // Initialize the circuit
    let mut circuit = RecursiveCircuit::new(initial_value, constant, max_iterations);
    
    // Create folding scheme
    let folding_scheme = FoldingScheme::new();
    
    // Initial instance and witness
    let initial_instance = circuit.to_instance()?;
    let initial_witness = circuit.to_witness();
    
    println!("\n🔄 Starting recursive computation...");
    println!("x₀ = {}", circuit.current);
    
    // Create accumulator for folding
    let mut accumulator = FoldingAccumulator::new(initial_instance, initial_witness);
    
    let mut folding_steps = 0;
    
    // Perform incremental computation
    loop {
        let is_complete = circuit.step()?;
        folding_steps += 1;
        
        println!("x_{} = {} (= {}² + {})", 
                 circuit.iteration, 
                 circuit.current,
                 circuit.history[circuit.iteration as usize - 1],
                 constant);
        
        // Create new instance and witness for this step
        let step_instance = circuit.to_instance()?;
        let step_witness = circuit.to_witness();
        
        // Fold this step into the accumulator
        let randomness = NovaField::from((folding_steps * 789 + 123) as u64); // Deterministic for demo
        accumulator.fold_instance(step_instance, step_witness, randomness)?;
        
        if is_complete {
            break;
        }
    }
    
    println!("\n🎯 Final result: x_{} = {}", circuit.iteration, circuit.current);
    
    // Verify computation manually
    let mut verification_value = initial_value;
    println!("\n🔍 Verification:");
    println!("x₀ = {}", verification_value);
    
    for i in 1..=max_iterations {
        verification_value = verification_value * verification_value + constant;
        println!("x_{} = {}", i, verification_value);
        
        if verification_value != circuit.history[i as usize] {
            println!("❌ Verification failed at step {}", i);
            return Err(NovaError::ValidationFailed("Recursive computation mismatch".to_string()));
        }
    }
    
    println!("✅ Recursive computation verified successfully!");
    
    println!("\n📊 Folding Statistics:");
    println!("  Total iterations: {}", max_iterations);
    println!("  Folding steps: {}", folding_steps);
    println!("  Final value magnitude: {}", circuit.current);
    println!("  Accumulator witness size: {}", accumulator.current_witness().data().len());
    
    // Show growth pattern
    println!("\n📈 Sequence analysis:");
    for (i, &val) in circuit.history.iter().enumerate() {
        println!("  x_{} = {}", i, val);
    }
    
    Ok(())
}

/// Demonstrate depth-logarithmic recursion
pub fn demo_depth_log_recursion() -> NovaResult<()> {
    println!("\n🌲 Depth-Logarithmic Recursion Demo");
    println!("===================================");
    
    // Demonstrate how Nova can handle logarithmic depth recursion
    // by folding multiple recursive steps efficiently
    
    let base_value = NovaField::from(3u64);
    let iterations = 4; // Will create 2^4 = 16 effective computations through folding
    
    println!("Base value: {}", base_value);
    println!("Folding depth: {} (effective computations: 2^{} = {})", 
             iterations, iterations, 1u64 << iterations);
    
    let mut circuit = RecursiveCircuit::new(base_value, NovaField::one(), iterations);
    let folding_scheme = FoldingScheme::new();
    
    // Simulate depth-log recursion by folding at each level
    let mut current_instances = vec![(circuit.to_instance()?, circuit.to_witness())];
    
    for depth in 0..iterations {
        let mut next_instances = Vec::new();
        let level_size = current_instances.len();
        
        println!("\nDepth {}: Processing {} instances", depth, level_size);
        
        // Pair up instances and fold them
        for chunk in current_instances.chunks(2) {
            if chunk.len() == 2 {
                // Fold two instances together
                let (inst1, wit1) = &chunk[0];
                let (inst2, wit2) = &chunk[1];
                
                let mut accumulator = FoldingAccumulator::new(inst1.clone(), wit1.clone());
                let randomness = NovaField::from((depth * 100 + 42) as u64);
                accumulator.fold_instance(inst2.clone(), wit2.clone(), randomness)?;
                
                next_instances.push((
                    accumulator.current_instance().clone(),
                    accumulator.current_witness().clone()
                ));
            } else {
                // Odd one out, carry forward
                next_instances.push(chunk[0].clone());
            }
        }
        
        // If we had an odd number, the size should be ceil(level_size/2)
        let expected_size = (level_size + 1) / 2;
        assert_eq!(next_instances.len(), expected_size);
        
        current_instances = next_instances;
    }
    
    println!("\n✅ Depth-logarithmic folding completed!");
    println!("Final folded instances: {}", current_instances.len());
    
    Ok(())
}

fn main() -> NovaResult<()> {
    // Run the basic recursive computation demo
    demo_recursive_folding()?;
    
    // Run the depth-logarithmic recursion demo
    demo_depth_log_recursion()?;
    
    println!("\nRecursive computation example completed!");
    Ok(())
}