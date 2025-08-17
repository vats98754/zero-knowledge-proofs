//! PLONK Performance Benchmarks
//!
//! Comprehensive benchmarks for PLONK proving system components:
//! - Universal setup generation
//! - Circuit compilation and constraint generation
//! - Proof generation (prover performance)
//! - Proof verification (verifier performance)
//! - Polynomial commitment operations
//! - Field arithmetic operations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use plonk_field::PlonkField;
use plonk_pc::{KZGEngine, UniversalSetup, CommitmentEngine, Transcript};
use plonk_arith::PlonkCircuit;
use plonk_prover::KZGPlonkProver;
use plonk_verifier::{KZGPlonkVerifier, SelectorCommitments};
use ark_std::test_rng;
use ark_bls12_381::G1Affine;

/// Benchmark universal setup generation for different circuit sizes
fn bench_universal_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("universal_setup");
    
    for circuit_size in [1024, 2048, 4096, 8192].iter() {
        group.throughput(Throughput::Elements(*circuit_size as u64));
        group.bench_with_input(
            BenchmarkId::new("generate", circuit_size),
            circuit_size,
            |b, &size| {
                b.iter(|| {
                    let mut rng = test_rng();
                    UniversalSetup::<KZGEngine>::new(size, &mut rng).unwrap()
                });
            },
        );
    }
    group.finish();
}

/// Benchmark field arithmetic operations
fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_operations");
    
    let mut rng = test_rng();
    let a = PlonkField::random(&mut rng);
    let b = PlonkField::random(&mut rng);
    
    group.bench_function("addition", |bench| {
        bench.iter(|| a + b)
    });
    
    group.bench_function("multiplication", |bench| {
        bench.iter(|| a * b)
    });
    
    group.bench_function("inversion", |bench| {
        bench.iter(|| a.inverse().unwrap())
    });
    
    group.bench_function("square", |bench| {
        bench.iter(|| a.square())
    });
    
    group.finish();
}

/// Benchmark polynomial commitment operations
fn bench_polynomial_commitment(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial_commitment");
    let mut rng = test_rng();
    
    for degree in [256, 512, 1024, 2048].iter() {
        let setup = UniversalSetup::<KZGEngine>::new(*degree, &mut rng).unwrap();
        let (committer_key, _) = setup.extract_keys(*degree).unwrap();
        
        // Create a random polynomial
        let coeffs: Vec<PlonkField> = (0..*degree)
            .map(|_| PlonkField::random(&mut rng))
            .collect();
        let poly = plonk_field::Polynomial::new(coeffs);
        
        group.throughput(Throughput::Elements(*degree as u64));
        
        group.bench_with_input(
            BenchmarkId::new("commit", degree),
            degree,
            |b, _| {
                b.iter(|| {
                    KZGEngine::commit(&committer_key, &poly).unwrap()
                });
            },
        );
        
        // Benchmark opening proof generation
        let commitment = KZGEngine::commit(&committer_key, &poly).unwrap();
        let point = PlonkField::random(&mut rng);
        let evaluation = poly.evaluate(point);
        
        group.bench_with_input(
            BenchmarkId::new("open", degree),
            degree,
            |b, _| {
                b.iter(|| {
                    KZGEngine::open(&committer_key, &poly, point).unwrap()
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark circuit construction for different sizes
fn bench_circuit_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("circuit_construction");
    
    for num_gates in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*num_gates as u64));
        group.bench_with_input(
            BenchmarkId::new("build_addition_circuit", num_gates),
            num_gates,
            |b, &gates| {
                b.iter(|| {
                    let mut circuit = PlonkCircuit::new(gates + 1);
                    let mut rng = test_rng();
                    
                    for _ in 0..gates {
                        let a = PlonkField::random(&mut rng);
                        let b = PlonkField::random(&mut rng);
                        let c = a + b;
                        circuit.add_addition_gate(a, b, c).unwrap();
                    }
                    circuit
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("build_multiplication_circuit", num_gates),
            num_gates,
            |b, &gates| {
                b.iter(|| {
                    let mut circuit = PlonkCircuit::new(gates + 1);
                    let mut rng = test_rng();
                    
                    for _ in 0..gates {
                        let a = PlonkField::random(&mut rng);
                        let b = PlonkField::random(&mut rng);
                        let c = a * b;
                        circuit.add_multiplication_gate(a, b, c).unwrap();
                    }
                    circuit
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark PLONK proof generation
fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");
    
    for num_gates in [10, 50, 100, 200].iter() {
        let mut rng = test_rng();
        let max_degree = 1024; // Large enough for test circuits
        
        // Setup prover
        let prover = KZGPlonkProver::setup(max_degree, &mut rng).unwrap();
        
        // Create test circuit
        let mut circuit = PlonkCircuit::new(num_gates + 1);
        for _ in 0..*num_gates {
            let a = PlonkField::random(&mut rng);
            let b = PlonkField::random(&mut rng);
            let c = a + b;
            circuit.add_addition_gate(a, b, c).unwrap();
        }
        
        group.throughput(Throughput::Elements(*num_gates as u64));
        group.bench_with_input(
            BenchmarkId::new("prove", num_gates),
            &(prover, circuit),
            |b, (prover, circuit)| {
                b.iter(|| {
                    let mut transcript = Transcript::new(b"plonk_bench");
                    prover.prove(circuit, &mut transcript).unwrap()
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark PLONK proof verification
fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_verification");
    
    for num_gates in [10, 50, 100, 200].iter() {
        let mut rng = test_rng();
        let max_degree = 1024;
        
        // Setup
        let prover = KZGPlonkProver::setup(max_degree, &mut rng).unwrap();
        let setup = UniversalSetup::<KZGEngine>::new(max_degree, &mut rng).unwrap();
        
        // Create circuit and proof
        let mut circuit = PlonkCircuit::new(num_gates + 1);
        for _ in 0..*num_gates {
            let a = PlonkField::random(&mut rng);
            let b = PlonkField::random(&mut rng);
            let c = a + b;
            circuit.add_addition_gate(a, b, c).unwrap();
        }
        
        let mut prove_transcript = Transcript::new(b"plonk_bench");
        let proof = prover.prove(&circuit, &mut prove_transcript).unwrap();
        
        // Create verifier
        let dummy_commitment = plonk_pc::KZGCommitmentWrapper {
            point: G1Affine::default(),
        };
        let selector_commitments = SelectorCommitments {
            q_m: dummy_commitment.clone(),
            q_l: dummy_commitment.clone(),
            q_r: dummy_commitment.clone(),
            q_o: dummy_commitment.clone(),
            q_c: dummy_commitment,
        };
        
        let verifier = KZGPlonkVerifier::from_setup(
            &setup,
            selector_commitments,
            *num_gates + 1,
            3,
        ).unwrap();
        
        let public_inputs = vec![];
        
        group.throughput(Throughput::Elements(*num_gates as u64));
        group.bench_with_input(
            BenchmarkId::new("verify", num_gates),
            &(verifier, proof, public_inputs),
            |b, (verifier, proof, public_inputs)| {
                b.iter(|| {
                    let mut transcript = Transcript::new(b"plonk_bench");
                    verifier.verify(proof, public_inputs, &mut transcript).unwrap()
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark transcript operations
fn bench_transcript_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("transcript");
    
    group.bench_function("challenge_generation", |b| {
        b.iter(|| {
            let mut transcript = Transcript::new(b"benchmark");
            let mut local_rng = test_rng();
            let field_val = PlonkField::random(&mut local_rng);
            transcript.append_field(b"commitment", field_val);
            transcript.challenge_field(b"challenge")
        });
    });
    
    group.bench_function("multiple_challenges", |b| {
        b.iter(|| {
            let mut transcript = Transcript::new(b"benchmark");
            let mut local_rng = test_rng();
            for i in 0..10 {
                let field_val = PlonkField::random(&mut local_rng);
                transcript.append_field(&format!("field_{}", i).as_bytes(), field_val);
            }
            (0..5).map(|i| transcript.challenge_field(&format!("challenge_{}", i).as_bytes())).collect::<Vec<_>>()
        });
    });
    
    group.finish();
}

criterion_group!(
    plonk_benchmarks,
    bench_universal_setup,
    bench_field_operations,
    bench_polynomial_commitment,
    bench_circuit_construction,
    bench_proof_generation,
    bench_proof_verification,
    bench_transcript_operations
);
criterion_main!(plonk_benchmarks);