use criterion::{criterion_group, criterion_main, Criterion, black_box, BenchmarkId};
use commitments::*;
use nova_core::*;
use ark_std::test_rng;
use ark_ff::{Field, UniformRand};

fn bench_commitment_scheme_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_operations");
    let mut rng = test_rng();
    
    // Test different polynomial sizes
    let polynomial_sizes = [8, 16, 32, 64, 128];
    
    for &size in &polynomial_sizes {
        // Create test polynomial
        let coefficients: Vec<NovaField> = (0..size)
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        let polynomial = MultilinearPolynomial::new(coefficients);
        
        let commitment_scheme = BasicKzgCommitment::new();
        
        group.bench_with_input(
            BenchmarkId::new("commitment_generation", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = commitment_scheme.commit(black_box(&polynomial));
                });
            },
        );
        
        // Test commitment verification if supported
        let commitment = commitment_scheme.commit(&polynomial).unwrap();
        let evaluation_point: Vec<NovaField> = (0..polynomial.num_vars())
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        let evaluation = polynomial.evaluate(&evaluation_point);
        
        group.bench_with_input(
            BenchmarkId::new("commitment_verification", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = commitment_scheme.verify_evaluation(
                        black_box(&commitment),
                        black_box(&evaluation_point),
                        black_box(evaluation),
                        black_box(&polynomial), // In real scheme this would be a proof
                    );
                });
            },
        );
    }
    
    group.finish();
}

fn bench_commitment_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_batch_operations");
    let mut rng = test_rng();
    
    let batch_sizes = [1, 4, 8, 16, 32];
    let poly_size = 32; // Fixed polynomial size
    
    for &batch_size in &batch_sizes {
        let polynomials: Vec<MultilinearPolynomial> = (0..batch_size)
            .map(|_| {
                let coefficients: Vec<NovaField> = (0..poly_size)
                    .map(|_| NovaField::rand(&mut rng))
                    .collect();
                MultilinearPolynomial::new(coefficients)
            })
            .collect();
        
        let commitment_scheme = BasicKzgCommitment::new();
        
        group.bench_with_input(
            BenchmarkId::new("batch_commitment", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    for poly in black_box(&polynomials) {
                        let _ = commitment_scheme.commit(poly);
                    }
                });
            },
        );
        
        // Benchmark memory usage for batch commitments
        group.bench_with_input(
            BenchmarkId::new("batch_commitment_memory", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    let commitments: Vec<_> = polynomials
                        .iter()
                        .map(|poly| commitment_scheme.commit(poly).unwrap())
                        .collect();
                    commitments.len()
                });
            },
        );
    }
    
    group.finish();
}

fn bench_commitment_scheme_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_scaling");
    let mut rng = test_rng();
    
    // Test scaling with polynomial degree (2^degree coefficients)
    let degrees = [3, 4, 5, 6, 7, 8]; // 8, 16, 32, 64, 128, 256 coefficients
    
    for &degree in &degrees {
        let poly_size = 1 << degree;
        let coefficients: Vec<NovaField> = (0..poly_size)
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        let polynomial = MultilinearPolynomial::new(coefficients);
        
        let commitment_scheme = BasicKzgCommitment::new();
        
        group.bench_with_input(
            BenchmarkId::new("commit_time_vs_degree", degree),
            &degree,
            |b, _| {
                b.iter(|| {
                    let _ = commitment_scheme.commit(black_box(&polynomial));
                });
            },
        );
        
        // Test evaluation time scaling
        let evaluation_point: Vec<NovaField> = (0..polynomial.num_vars())
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("evaluation_time_vs_degree", degree),
            &degree,
            |b, _| {
                b.iter(|| {
                    let _ = polynomial.evaluate(black_box(&evaluation_point));
                });
            },
        );
    }
    
    group.finish();
}

fn bench_commitment_integration_with_folding(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_folding_integration");
    let mut rng = test_rng();
    
    let sizes = [8, 16, 32];
    
    for &size in &sizes {
        group.bench_with_input(
            BenchmarkId::new("folding_with_commitments", size),
            &size,
            |b, _| {
                b.iter(|| {
                    // Create Nova instances with commitment support
                    let relation = Relation::new(size);
                    let folding_scheme = FoldingScheme::new(relation.clone());
                    
                    let instance1 = Instance::new(relation.clone(), size).unwrap();
                    let witness1_data: Vec<NovaField> = (0..size)
                        .map(|_| NovaField::rand(&mut rng))
                        .collect();
                    let witness1 = Witness::new(witness1_data);
                    
                    let instance2 = Instance::new(relation, size).unwrap();
                    let witness2_data: Vec<NovaField> = (0..size)
                        .map(|_| NovaField::rand(&mut rng))
                        .collect();
                    let witness2 = Witness::new(witness2_data);
                    
                    let mut transcript = Transcript::new("nova-commitment-folding");
                    
                    // Time the complete folding operation with commitments
                    let _ = folding_scheme.fold(
                        black_box(&instance1),
                        black_box(&witness1),
                        black_box(&instance2),
                        black_box(&witness2),
                        black_box(&mut transcript),
                    );
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_commitment_scheme_operations,
    bench_commitment_batch_operations,
    bench_commitment_scheme_scaling,
    bench_commitment_integration_with_folding
);
criterion_main!(benches);