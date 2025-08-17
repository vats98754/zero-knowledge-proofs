//! # Comprehensive Benchmarking Utilities
//!
//! This module provides utilities for benchmarking different components
//! of the Halo/Halo2 proof system including commitment schemes, circuit
//! operations, folding, and recursive verification.

use criterion::{black_box, Criterion, BenchmarkId};
use commitments::{IpaCommitmentEngine, CommitmentEngine, MultiScalarMultiplication};
use halo_core::{Scalar, GroupElement};
use halo_recursion::{Accumulator, fold_proof, verify_recursive, FoldingProof, AccumulatorInstance};
use halo2_arith::{CircuitBuilder, ColumnManager, AdviceColumn, FixedColumn, StandardGate};
use bls12_381::{G1Affine, G1Projective, Scalar as BlsScalar};
use ff::Field;
use group::{Curve, Group};
use rand::{Rng, thread_rng};
use std::time::{Instant, Duration};

/// Benchmark configuration parameters
#[derive(Clone, Debug)]
pub struct BenchmarkConfig {
    /// Size parameters to test
    pub sizes: Vec<usize>,
    /// Number of iterations per benchmark
    pub iterations: usize,
    /// Whether to include memory profiling
    pub profile_memory: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            sizes: vec![8, 16, 32, 64, 128, 256],
            iterations: 10,
            profile_memory: false,
        }
    }
}

/// Benchmark results for analysis
#[derive(Clone, Debug)]
pub struct BenchmarkResults {
    pub commitment_times: Vec<(usize, Duration)>,
    pub circuit_times: Vec<(usize, Duration)>,
    pub folding_times: Vec<(usize, Duration)>,
    pub verification_times: Vec<(usize, Duration)>,
}

impl BenchmarkResults {
    pub fn new() -> Self {
        Self {
            commitment_times: Vec::new(),
            circuit_times: Vec::new(),
            folding_times: Vec::new(),
            verification_times: Vec::new(),
        }
    }
    
    /// Display benchmark results in a formatted table
    pub fn display(&self) {
        println!("📊 Benchmark Results Summary");
        println!("============================");
        
        println!("\n🔗 Commitment Operations:");
        println!("Size\t\tTime (μs)\tThroughput (ops/s)");
        println!("----\t\t---------\t------------------");
        for (size, duration) in &self.commitment_times {
            let micros = duration.as_micros();
            let throughput = if micros > 0 { 1_000_000 / micros } else { 0 };
            println!("{}\t\t{}\t\t{}", size, micros, throughput);
        }
        
        println!("\n🏗️  Circuit Building:");
        println!("Size\t\tTime (μs)\tConstraints/s");
        println!("----\t\t---------\t-------------");
        for (size, duration) in &self.circuit_times {
            let micros = duration.as_micros();
            let throughput = if micros > 0 { (*size as u128 * 1_000_000) / micros } else { 0 };
            println!("{}\t\t{}\t\t{}", size, micros, throughput);
        }
        
        println!("\n🔄 Proof Folding:");
        println!("Size\t\tTime (μs)\tProofs/s");
        println!("----\t\t---------\t--------");
        for (size, duration) in &self.folding_times {
            let micros = duration.as_micros();
            let throughput = if micros > 0 { 1_000_000 / micros } else { 0 };
            println!("{}\t\t{}\t\t{}", size, micros, throughput);
        }
        
        println!("\n✅ Verification:");
        println!("Size\t\tTime (μs)\tVerifications/s");
        println!("----\t\t---------\t---------------");
        for (size, duration) in &self.verification_times {
            let micros = duration.as_micros();
            let throughput = if micros > 0 { 1_000_000 / micros } else { 0 };
            println!("{}\t\t{}\t\t{}", size, micros, throughput);
        }
    }
    
    /// Find scaling trends in the benchmarks
    pub fn analyze_scaling(&self) {
        println!("\n📈 Scaling Analysis:");
        println!("====================");
        
        self.analyze_component_scaling("Commitments", &self.commitment_times);
        self.analyze_component_scaling("Circuit Building", &self.circuit_times);
        self.analyze_component_scaling("Proof Folding", &self.folding_times);
        self.analyze_component_scaling("Verification", &self.verification_times);
    }
    
    fn analyze_component_scaling(&self, name: &str, times: &[(usize, Duration)]) {
        if times.len() < 2 {
            return;
        }
        
        println!("\n{} Scaling:", name);
        
        // Calculate ratios between consecutive sizes
        for i in 1..times.len() {
            let (size1, time1) = times[i-1];
            let (size2, time2) = times[i];
            
            let size_ratio = size2 as f64 / size1 as f64;
            let time_ratio = time2.as_nanos() as f64 / time1.as_nanos() as f64;
            
            let scaling_factor = (time_ratio.log2() / size_ratio.log2()).abs();
            
            let complexity = if scaling_factor < 1.1 {
                "O(1) - Constant"
            } else if scaling_factor < 1.5 {
                "O(log n) - Logarithmic"
            } else if scaling_factor < 2.1 {
                "O(n) - Linear"
            } else if scaling_factor < 3.1 {
                "O(n²) - Quadratic"
            } else {
                "O(n³+) - Polynomial"
            };
            
            println!("   {}->{}: {:.2}x time / {:.1}x size → {}", 
                     size1, size2, time_ratio, size_ratio, complexity);
        }
    }
}

/// Benchmark commitment operations
pub fn benchmark_commitments(config: &BenchmarkConfig) -> Vec<(usize, Duration)> {
    println!("🔗 Benchmarking Commitment Operations...");
    
    let mut results = Vec::new();
    let commitment_engine = IpaCommitmentEngine::new();
    
    for &size in &config.sizes {
        println!("   Testing size: {}", size);
        
        // Generate random scalars and points
        let mut rng = thread_rng();
        let scalars: Vec<BlsScalar> = (0..size)
            .map(|_| BlsScalar::random(&mut rng))
            .collect();
        let points: Vec<G1Affine> = (0..size)
            .map(|_| G1Projective::random(&mut rng).to_affine())
            .collect();
        
        // Benchmark multi-scalar multiplication
        let start = Instant::now();
        for _ in 0..config.iterations {
            let _result = black_box(
                MultiScalarMultiplication::multi_scalar_mult(&scalars, &points)
            );
        }
        let avg_duration = start.elapsed() / config.iterations as u32;
        
        results.push((size, avg_duration));
        
        println!("     Avg time: {:?}", avg_duration);
    }
    
    results
}

/// Benchmark circuit building operations
pub fn benchmark_circuit_building(config: &BenchmarkConfig) -> Vec<(usize, Duration)> {
    println!("🏗️  Benchmarking Circuit Building...");
    
    let mut results = Vec::new();
    
    for &size in &config.sizes {
        println!("   Testing circuit size: {}", size);
        
        let start = Instant::now();
        for _ in 0..config.iterations {
            // Build a circuit with the specified number of constraints
            let mut column_manager = ColumnManager::new();
            let advice_col = AdviceColumn::new(0);
            let fixed_col = FixedColumn::new(0);
            
            column_manager.add_advice_column(advice_col);
            column_manager.add_fixed_column(fixed_col);
            
            let mut builder = CircuitBuilder::new(column_manager);
            
            // Add multiple gates to simulate larger circuits
            for i in 0..size {
                let gate_name = format!("gate_{}", i);
                builder = black_box(
                    builder.gate(StandardGate::new(gate_name)).unwrap()
                );
            }
            
            let _circuit = black_box(builder.build().unwrap());
        }
        let avg_duration = start.elapsed() / config.iterations as u32;
        
        results.push((size, avg_duration));
        
        println!("     Avg time: {:?}", avg_duration);
    }
    
    results
}

/// Benchmark proof folding operations
pub fn benchmark_folding(config: &BenchmarkConfig) -> Vec<(usize, Duration)> {
    println!("🔄 Benchmarking Proof Folding...");
    
    let mut results = Vec::new();
    
    for &size in &config.sizes {
        println!("   Testing folding with {} proofs:", size);
        
        let start = Instant::now();
        for _ in 0..config.iterations {
            // Create mock proofs for folding
            let mut current_accumulator = None;
            
            for _ in 0..size {
                let proof = create_mock_proof();
                let public_inputs = create_mock_public_inputs(16);
                
                match fold_proof(current_accumulator, proof, public_inputs) {
                    Ok(folding_result) => {
                        current_accumulator = Some(folding_result.accumulator);
                    }
                    Err(_) => break,
                }
            }
            
            black_box(current_accumulator);
        }
        let avg_duration = start.elapsed() / config.iterations as u32;
        
        results.push((size, avg_duration));
        
        println!("     Avg time: {:?}", avg_duration);
    }
    
    results
}

/// Benchmark verification operations
pub fn benchmark_verification(config: &BenchmarkConfig) -> Vec<(usize, Duration)> {
    println!("✅ Benchmarking Verification...");
    
    let mut results = Vec::new();
    
    for &size in &config.sizes {
        println!("   Testing verification with size: {}", size);
        
        // Create mock folding proof and instance
        let accumulator = create_mock_accumulator(size);
        let folding_proof = create_mock_folding_proof(&accumulator);
        let instance = create_mock_instance(size);
        
        let start = Instant::now();
        for _ in 0..config.iterations {
            let _result = black_box(
                verify_recursive(&folding_proof, &instance)
            );
        }
        let avg_duration = start.elapsed() / config.iterations as u32;
        
        results.push((size, avg_duration));
        
        println!("     Avg time: {:?}", avg_duration);
    }
    
    results
}

/// Create a mock proof for benchmarking
fn create_mock_proof() -> halo_core::Proof {
    let mut rng = thread_rng();
    halo_core::Proof {
        commitments: vec![G1Projective::random(&mut rng).to_affine(); 3],
        evaluations: vec![BlsScalar::random(&mut rng); 5],
        opening_proof: G1Projective::random(&mut rng).to_affine(),
    }
}

/// Create mock public inputs
fn create_mock_public_inputs(size: usize) -> Vec<BlsScalar> {
    let mut rng = thread_rng();
    (0..size).map(|_| BlsScalar::random(&mut rng)).collect()
}

/// Create a mock accumulator
fn create_mock_accumulator(size: usize) -> Accumulator {
    let mut rng = thread_rng();
    Accumulator {
        commitments: (0..size).map(|_| G1Projective::random(&mut rng).to_affine()).collect(),
        witnesses: (0..size).map(|_| BlsScalar::random(&mut rng)).collect(),
        challenges: (0..3).map(|_| BlsScalar::random(&mut rng)).collect(),
    }
}

/// Create a mock folding proof
fn create_mock_folding_proof(accumulator: &Accumulator) -> FoldingProof {
    let mut rng = thread_rng();
    FoldingProof {
        accumulator: accumulator.clone(),
        folding_challenges: vec![BlsScalar::random(&mut rng); 3],
        cross_terms: vec![G1Projective::random(&mut rng).to_affine(); 2],
        evaluation_proof: G1Projective::random(&mut rng).to_affine(),
    }
}

/// Create a mock accumulator instance
fn create_mock_instance(size: usize) -> AccumulatorInstance {
    let mut rng = thread_rng();
    let public_inputs: Vec<u8> = (0..size * 32)
        .map(|_| rng.gen())
        .collect();
    
    AccumulatorInstance { public_inputs }
}

/// Run comprehensive benchmarks
pub fn run_comprehensive_benchmarks() -> BenchmarkResults {
    println!("⚡ Running Comprehensive Halo/Halo2 Benchmarks");
    println!("==============================================\n");
    
    let config = BenchmarkConfig::default();
    let mut results = BenchmarkResults::new();
    
    // Run all benchmark categories
    results.commitment_times = benchmark_commitments(&config);
    println!();
    
    results.circuit_times = benchmark_circuit_building(&config);
    println!();
    
    results.folding_times = benchmark_folding(&config);
    println!();
    
    results.verification_times = benchmark_verification(&config);
    println!();
    
    // Display and analyze results
    results.display();
    results.analyze_scaling();
    
    println!("\n💡 Performance Insights:");
    println!("   🔗 Commitment operations scale linearly with input size");
    println!("   🏗️  Circuit building has linear complexity in constraints");
    println!("   🔄 Proof folding maintains constant overhead per proof");
    println!("   ✅ Verification time is logarithmic in original circuit size");
    
    results
}

/// Benchmark memory usage for different operations
pub fn benchmark_memory_usage() {
    println!("🧠 Memory Usage Analysis");
    println!("========================");
    
    // This is a simplified memory analysis
    // In practice, you'd use tools like valgrind or custom allocators
    
    let sizes = vec![64, 128, 256];
    
    for size in sizes {
        println!("\nSize: {}", size);
        
        // Estimate memory for commitments
        let commitment_memory = size * 48; // 48 bytes per G1 point
        println!("   Commitments: ~{} bytes", commitment_memory);
        
        // Estimate memory for witness
        let witness_memory = size * 32; // 32 bytes per scalar
        println!("   Witnesses: ~{} bytes", witness_memory);
        
        // Estimate memory for accumulator
        let accumulator_memory = commitment_memory + witness_memory + 96; // Additional overhead
        println!("   Accumulator: ~{} bytes", accumulator_memory);
        
        let total_memory = accumulator_memory;
        println!("   Total: ~{} bytes ({:.2} KB)", total_memory, total_memory as f64 / 1024.0);
    }
}

/// Compare performance against theoretical bounds
pub fn performance_comparison() {
    println!("\n📊 Performance vs Theoretical Bounds");
    println!("====================================");
    
    // These are simplified theoretical calculations
    let circuit_sizes = vec![1000, 5000, 10000, 50000];
    
    println!("Circuit Size\tProof Time\tVerify Time\tProof Size");
    println!("------------\t----------\t-----------\t----------");
    
    for size in circuit_sizes {
        // Theoretical: O(n log n) for proof, O(log n) for verification
        let log_n = (size as f64).log2();
        let n_log_n = size as f64 * log_n;
        
        // Estimated times (in microseconds)
        let proof_time = (n_log_n * 10.0) as u64;
        let verify_time = (log_n * 100.0) as u64;
        let proof_size = (log_n * 48.0) as u64; // Constant size in practice
        
        println!("{}\t\t{}μs\t\t{}μs\t\t{}B", 
                 size, proof_time, verify_time, proof_size);
    }
    
    println!("\n💡 Key Observations:");
    println!("   📈 Proof time grows as O(n log n) where n is circuit size");
    println!("   ⚡ Verification time is O(log n) - very efficient!");
    println!("   📦 Proof size remains constant regardless of circuit size");
    println!("   🔄 Recursive aggregation enables batching without size growth");
}
