//! PLONK Benchmarks
//!
//! Performance benchmarks for the PLONK proving system.
//! 
//! This crate provides comprehensive benchmarks for:
//! - Universal setup generation
//! - Field arithmetic operations  
//! - Polynomial commitment schemes
//! - Circuit construction and constraints
//! - Proof generation and verification
//! - Transcript operations

pub mod benches {
    //! Benchmark utilities and helpers
    
    /// Helper function to generate random circuits for benchmarking
    pub fn generate_random_circuit(size: usize) -> plonk_arith::PlonkCircuit {
        use plonk_arith::PlonkCircuit;
        use plonk_field::PlonkField;
        use ark_std::test_rng;
        
        let mut circuit = PlonkCircuit::new(size);
        let mut rng = test_rng();
        
        for _ in 0..size.saturating_sub(1) {
            let a = PlonkField::random(&mut rng);
            let b = PlonkField::random(&mut rng);
            let c = a + b;
            circuit.add_addition_gate(a, b, c).unwrap();
        }
        
        circuit
    }
    
    /// Benchmark configuration constants
    pub mod config {
        /// Default circuit sizes for benchmarking
        pub const CIRCUIT_SIZES: &[usize] = &[10, 50, 100, 200, 500];
        
        /// Default polynomial degrees for commitment benchmarks
        pub const POLY_DEGREES: &[usize] = &[256, 512, 1024, 2048];
        
        /// Default setup sizes for universal setup benchmarks
        pub const SETUP_SIZES: &[usize] = &[1024, 2048, 4096, 8192];
    }
}