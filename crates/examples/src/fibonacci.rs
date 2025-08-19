//! Example: Fibonacci sequence using Nova incremental computation
//! 
//! This example shows how to compute Fibonacci numbers incrementally with Nova,
//! demonstrating the folding scheme in action.

use nova_core::*;
use ark_std::{vec, One, Zero};

/// Fibonacci computation circuit for Nova
pub struct FibonacciCircuit {
    /// Current Fibonacci number F(n)
    pub current: NovaField,
    /// Previous Fibonacci number F(n-1)
    pub previous: NovaField,
    /// Current step number
    pub step: u64,
    /// Target step to compute
    pub target: u64,
}

impl FibonacciCircuit {
    /// Create a new Fibonacci circuit to compute F(target)
    pub fn new(target: u64) -> Self {
        Self {
            current: NovaField::one(),   // F(1) = 1
            previous: NovaField::zero(), // F(0) = 0
            step: 1,
            target,
        }
    }

    /// Perform one Fibonacci step: F(n+1) = F(n) + F(n-1)
    pub fn step(&mut self) -> NovaResult<bool> {
        if self.step >= self.target {
            return Ok(true); // Computation complete
        }

        let next = self.current + self.previous;
        self.previous = self.current;
        self.current = next;
        self.step += 1;

        Ok(self.step >= self.target)
    }

    /// Get the current state as a witness
    pub fn to_witness(&self) -> Witness {
        let witness_data = vec![
            self.current,
            self.previous,
            NovaField::from(self.step),
            NovaField::from(self.target),
        ];
        Witness::new(witness_data)
    }

    /// Create an instance for this computation
    pub fn to_instance(&self) -> NovaResult<Instance> {
        let relation = Relation::new(4); // current, previous, step, target
        Instance::new(relation, 4)
    }

    /// Create the relation for this computation
    pub fn to_relation(&self) -> NovaResult<Relation> {
        Ok(Relation::new(4)) // current, previous, step, target
    }
}

/// Demonstrate incremental Fibonacci computation with Nova folding
pub fn demo_fibonacci_folding(n: u64) -> NovaResult<()> {
    println!("🌀 Nova Fibonacci Demo - Computing F({})", n);
    println!("==========================================");

    // Initialize the Fibonacci circuit
    let mut circuit = FibonacciCircuit::new(n);
    
    // Create folding scheme
    let relation = circuit.to_relation()?;
    let folding_scheme = FoldingScheme::new(relation);
    
    // Initial instance and witness
    let initial_instance = circuit.to_instance()?;
    let initial_witness = circuit.to_witness();
    
    println!("F({}) = {}", circuit.step - 1, circuit.current);
    
    // Create accumulator for folding
    let mut accumulator = FoldingAccumulator::new(folding_scheme);
    let mut transcript = Transcript::new("fibonacci-folding");
    accumulator.accumulate(initial_instance, initial_witness, &mut transcript)?;
    
    // Perform incremental computation
    let mut folding_steps = 0;
    loop {
        let is_complete = circuit.step()?;
        folding_steps += 1;
        
        println!("F({}) = {}", circuit.step - 1, circuit.current);
        
        // Create new instance and witness for this step
        let step_instance = circuit.to_instance()?;
        let step_witness = circuit.to_witness();
        
        // Fold this step into the accumulator
        accumulator.accumulate(step_instance, step_witness, &mut transcript)?;
        
        if is_complete {
            break;
        }
    }
    
    println!("\n🎯 Final result: F({}) = {}", n, circuit.current);
    
    // Verify against standard Fibonacci computation
    let expected = fibonacci_standard(n);
    let computed = circuit.current;
    
    println!("Expected: {}", expected);
    println!("Computed: {}", computed);
    
    if expected == computed {
        println!("✅ Fibonacci computation verified successfully!");
    } else {
        println!("❌ Fibonacci computation verification failed!");
        return Err(NovaError::computation_error("Fibonacci mismatch"));
    }
    
    println!("\n📊 Folding Statistics:");
    println!("  Target Fibonacci number: F({})", n);
    println!("  Computation steps: {}", folding_steps);
    if let Some((_, folded_witness)) = accumulator.current() {
        println!("  Accumulator witness size: {}", folded_witness.original_witnesses.len());
    }
    
    Ok(())
}

/// Standard Fibonacci computation for verification
fn fibonacci_standard(n: u64) -> NovaField {
    if n == 0 {
        return NovaField::zero();
    }
    if n == 1 {
        return NovaField::one();
    }
    
    let mut prev = NovaField::zero();
    let mut curr = NovaField::one();
    
    for _ in 2..=n {
        let next = prev + curr;
        prev = curr;
        curr = next;
    }
    
    curr
}

fn main() -> NovaResult<()> {
    println!("Nova Fibonacci Example");
    
    // Compute different Fibonacci numbers
    let targets = [5, 10, 15];
    
    for &n in &targets {
        demo_fibonacci_folding(n)?;
        println!();
    }
    
    println!("Fibonacci example completed!");
    Ok(())
}