//! Benchmarks for inner product argument

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ipa::{InnerProductProver, InnerProductVerifier};
use bulletproofs_core::{GeneratorSet, Scalar, TranscriptProtocol};
use merlin::Transcript;
use rand::thread_rng;

fn bench_ipa_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipa_generation");
    
    for vector_length in [8, 16, 32, 64, 128] {
        group.throughput(Throughput::Elements(vector_length as u64));
        
        group.bench_with_input(
            BenchmarkId::new("prove", vector_length),
            &vector_length,
            |b, &vector_length| {
                let mut rng = thread_rng();
                let generators = GeneratorSet::new(&mut rng, vector_length);
                let mut prover = InnerProductProver::new(generators);
                
                // Generate random vectors
                let a: Vec<Scalar> = (0..vector_length).map(|_| Scalar::random(&mut rng)).collect();
                let b: Vec<Scalar> = (0..vector_length).map(|_| Scalar::random(&mut rng)).collect();
                
                b.iter(|| {
                    let mut transcript = Transcript::new(b"ipa_benchmark");
                    let proof = prover.prove(
                        &mut rng,
                        &mut transcript,
                        black_box(&a),
                        black_box(&b),
                    ).unwrap();
                    black_box(proof)
                });
            },
        );
    }
    
    group.finish();
}

fn bench_ipa_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipa_verification");
    
    for vector_length in [8, 16, 32, 64, 128] {
        group.throughput(Throughput::Elements(vector_length as u64));
        
        // Pre-generate proof for verification benchmark
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, vector_length);
        let mut prover = InnerProductProver::new(generators.clone());
        let verifier = InnerProductVerifier::new(generators);
        
        let a: Vec<Scalar> = (0..vector_length).map(|_| Scalar::random(&mut rng)).collect();
        let b: Vec<Scalar> = (0..vector_length).map(|_| Scalar::random(&mut rng)).collect();
        
        let mut transcript = Transcript::new(b"ipa_benchmark");
        let proof = prover.prove(&mut rng, &mut transcript, &a, &b).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("verify", vector_length),
            &vector_length,
            |b, &_vector_length| {
                b.iter(|| {
                    let mut transcript = Transcript::new(b"ipa_benchmark");
                    verifier.verify(&mut transcript, black_box(&proof)).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

fn bench_ipa_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipa_proof_size");
    
    let mut rng = thread_rng();
    
    for vector_length in [8, 16, 32, 64, 128] {
        let generators = GeneratorSet::new(&mut rng, vector_length);
        let mut prover = InnerProductProver::new(generators);
        
        let a: Vec<Scalar> = (0..vector_length).map(|_| Scalar::random(&mut rng)).collect();
        let b: Vec<Scalar> = (0..vector_length).map(|_| Scalar::random(&mut rng)).collect();
        
        let mut transcript = Transcript::new(b"ipa_benchmark");
        let proof = prover.prove(&mut rng, &mut transcript, &a, &b).unwrap();
        let size = proof.size_bytes();
        
        println!("IPA proof size for vector length {}: {} bytes", vector_length, size);
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_ipa_generation,
    bench_ipa_verification,
    bench_ipa_proof_size
);
criterion_main!(benches);