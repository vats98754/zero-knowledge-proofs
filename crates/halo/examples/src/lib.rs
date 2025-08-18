//! # Halo Examples
//!
//! Examples demonstrating usage of Halo and Halo2 proof systems.
//! 
//! ## Available Examples
//! 
//! ### Arithmetic Circuits
//! - **Fibonacci**: Demonstrates recursive constraint verification for Fibonacci sequences
//! - **Scalar Multiplication**: Proves knowledge of elliptic curve scalar multiplication
//! - **Lookup Tables**: Showcases efficient range checks and table-based proofs
//! 
//! ### Recursive Proofs
//! - **Proof Folding**: Aggregation of multiple proofs into a single compact proof
//! - **Batch Verification**: Efficient verification of multiple related proofs
//! 
//! ## Usage
//! 
//! Each example can be run independently to demonstrate specific features:
//! 
//! ```rust
//! use halo_examples::fibonacci::demonstrate_fibonacci_proof;
//! use halo_examples::scalar_multiplication::demonstrate_scalar_multiplication;
//! use halo_examples::lookup_demo::run_all_lookup_demos;
//! 
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Run Fibonacci circuit demonstration
//!     demonstrate_fibonacci_proof()?;
//!     
//!     // Run scalar multiplication proof
//!     demonstrate_scalar_multiplication()?;
//!     
//!     // Run all lookup table demonstrations
//!     run_all_lookup_demos()?;
//!     
//!     Ok(())
//! }
//! ```

pub mod scalar_multiplication;
pub mod fibonacci;
pub mod lookup_demo;

// Re-export for convenience
pub use halo_core;
pub use halo_recursion;
pub use halo2_arith;
pub use commitments;

/// Comprehensive example runner that demonstrates all major features
pub fn run_all_examples() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 Halo/Halo2 Comprehensive Example Suite");
    println!("=========================================\n");
    
    // Run Fibonacci demonstration
    println!("1️⃣ Running Fibonacci Circuit Example...");
    fibonacci::demonstrate_fibonacci_proof()?;
    
    println!("\n{}\n", "=".repeat(50));
    
    // Run scalar multiplication demonstration
    println!("2️⃣ Running Scalar Multiplication Example...");
    scalar_multiplication::demonstrate_scalar_multiplication()?;
    
    println!("\n{}\n", "=".repeat(50));
    
    // Run range check demonstration
    println!("3️⃣ Running Range Check Example...");
    fibonacci::demonstrate_range_check()?;
    
    println!("\n{}\n", "=".repeat(50));
    
    // Run bit decomposition demonstration
    println!("4️⃣ Running Bit Decomposition Example...");
    scalar_multiplication::demonstrate_bit_decomposition()?;
    
    println!("\n{}\n", "=".repeat(50));
    
    // Run all lookup demonstrations
    println!("5️⃣ Running Lookup Table Examples...");
    lookup_demo::run_all_lookup_demos()?;
    
    println!("\n{}\n", "=".repeat(50));
    
    println!("🎉 All examples completed successfully!");
    println!("\n💡 Key Takeaways:");
    println!("   🔐 Halo2 enables complex arithmetic circuit proofs");
    println!("   📊 Lookup tables provide efficient constraint verification");
    println!("   🔄 Recursive aggregation scales to large proof systems");
    println!("   ⚡ Transparent setup requires no trusted ceremony");
    println!("   🛡️  Strong cryptographic guarantees with practical performance");
    
    Ok(())
}

/// Quick start example showing basic circuit usage
pub fn quick_start_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Halo2 Quick Start Example");
    println!("============================");
    
    // Simple Fibonacci circuit
    let fib_circuit = fibonacci::build_fibonacci_circuit(5)?;
    println!("✅ Built Fibonacci circuit with 5 iterations");
    
    let is_valid = fib_circuit.verify_constraints()?;
    println!("✅ Circuit constraints valid: {}", is_valid);
    
    let stats = fib_circuit.stats();
    println!("📊 Circuit has {} constraints across {} columns", 
             stats.total_constraints, stats.total_columns);
    
    println!("🎯 Quick start completed - circuit built and verified!");
    
    Ok(())
}

/// Benchmark runner for performance demonstrations
pub fn run_performance_demos() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚡ Performance Demonstration Suite");
    println!("=================================");
    
    let start = std::time::Instant::now();
    
    // Test different circuit sizes
    let sizes = vec![5, 10, 20, 50];
    
    for size in sizes {
        println!("\n📊 Testing Fibonacci circuit with {} iterations:", size);
        
        let circuit_start = std::time::Instant::now();
        let circuit = fibonacci::build_fibonacci_circuit(size)?;
        let build_time = circuit_start.elapsed();
        
        let verify_start = std::time::Instant::now();
        let is_valid = circuit.verify_constraints()?;
        let verify_time = verify_start.elapsed();
        
        let stats = circuit.stats();
        
        println!("   🔨 Build time: {:?}", build_time);
        println!("   ✅ Verify time: {:?}", verify_time);
        println!("   📈 Constraints: {}", stats.total_constraints);
        println!("   📊 Columns: {}", stats.total_columns);
        println!("   🎯 Valid: {}", is_valid);
    }
    
    let total_time = start.elapsed();
    println!("\n⏱️  Total benchmark time: {:?}", total_time);
    
    Ok(())
}