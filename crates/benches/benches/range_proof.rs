//! Benchmarks for range proof generation and verification

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use range::{RangeProver, RangeVerifier};
use bulletproofs_core::GeneratorSet;
use rand::thread_rng;

fn bench_range_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_generation");
    
    for bit_length in [8, 16, 32, 64] {
        group.throughput(Throughput::Elements(bit_length as u64));
        
        group.bench_with_input(
            BenchmarkId::new("prove", bit_length),
            &bit_length,
            |b, &bit_length| {
                let mut rng = thread_rng();
                let prover = RangeProver::new(&mut rng, 128); // Support up to 64 bit ranges
                let value = (1u64 << (bit_length - 1)) - 1; // Near max value
                
                b.iter(|| {
                    let proof = prover.prove_range(
                        black_box(value),
                        black_box(bit_length),
                        None,
                        &mut rng,
                    ).unwrap();
                    black_box(proof)
                });
            },
        );
    }
    
    group.finish();
}

fn bench_range_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_verification");
    
    for bit_length in [8, 16, 32, 64] {
        group.throughput(Throughput::Elements(bit_length as u64));
        
        // Pre-generate proof for verification benchmark
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, bit_length * 2);
        let prover = RangeProver::with_generators(generators.clone());
        let verifier = RangeVerifier::with_generators(generators);
        let value = (1u64 << (bit_length - 1)) - 1;
        let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("verify", bit_length),
            &bit_length,
            |b, &bit_length| {
                b.iter(|| {
                    verifier.verify_range(black_box(&proof), black_box(bit_length)).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

fn bench_range_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proof_size");
    
    let mut rng = thread_rng();
    
    for bit_length in [8, 16, 32, 64] {
        let mut rng = thread_rng();
        let prover = RangeProver::new(&mut rng, 128); // Support up to 64 bit ranges
        let value = (1u64 << (bit_length - 1)) - 1;
        let proof = prover.prove_range(value, bit_length, None, &mut rng).unwrap();
        let size = proof.to_bytes().len();
        
        println!("Range proof size for {} bits: {} bytes", bit_length, size);
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_range_proof_generation,
    bench_range_proof_verification,
    bench_range_proof_size
);
criterion_main!(benches);