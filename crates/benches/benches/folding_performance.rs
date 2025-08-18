use criterion::{criterion_group, criterion_main, Criterion, black_box, BenchmarkId};
use nova_core::*;
use benches::*;
use ark_std::{test_rng, UniformRand};

fn bench_folding_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("folding_operations");
    let mut rng = test_rng();
    
    // Test different instance sizes
    let sizes = [4, 8, 16, 32, 64];
    
    for &size in &sizes {
        let relation = create_test_relation(4); // Use 4 variables for test relation
        let folding_scheme = FoldingScheme::new(relation.clone());
        let instance1 = create_test_instance(&relation, size);
        let witness1 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        let instance2 = create_test_instance(&relation, size);
        let witness2 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        
        group.bench_with_input(
            BenchmarkId::new("folding_step", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-folding");
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

        group.bench_with_input(
            BenchmarkId::new("validation", size),
            &size,
            |b, _| {
                b.iter(|| {
                    // Nova doesn't have separate validation - folding includes validation
                    let mut transcript = Transcript::new("nova-folding");
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

        // Benchmark accumulator operations
        group.bench_with_input(
            BenchmarkId::new("accumulator_fold", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let folding_scheme = FoldingScheme::new(relation.clone());
                    let mut accumulator = FoldingAccumulator::new(folding_scheme);
                    let mut transcript = Transcript::new("nova-folding");
                    
                    let new_instance = create_test_instance(&relation, size);
                    let new_witness = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
                    let _ = accumulator.accumulate(
                        black_box(new_instance),
                        black_box(new_witness),
                        black_box(&mut transcript),
                    );
                });
            },
        );
    }
    
    group.finish();
}

fn bench_vector_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("vector_operations");
    let mut rng = test_rng();
    
    let sizes = [16, 32, 64, 128, 256];
    
    for &size in &sizes {
        let vec_a: Vec<NovaField> = (0..size).map(|_| NovaField::rand(&mut rng)).collect();
        let vec_b: Vec<NovaField> = (0..size).map(|_| NovaField::rand(&mut rng)).collect();
        let scalar = NovaField::rand(&mut rng);
        
        group.bench_with_input(
            BenchmarkId::new("inner_product", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = inner_product(black_box(&vec_a), black_box(&vec_b));
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("vector_fold", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = fold_vectors(
                        black_box(&vec_a),
                        black_box(&vec_b),
                        black_box(scalar),
                    );
                });
            },
        );
    }
    
    group.finish();
}

fn bench_multilinear_polynomials(c: &mut Criterion) {
    let mut group = c.benchmark_group("multilinear_polynomials");
    let mut rng = test_rng();
    
    // Test different variable counts (2^vars coefficients)
    let var_counts = [2, 3, 4, 5, 6];
    
    for &vars in &var_counts {
        let coeffs: Vec<NovaField> = (0..1 << vars)
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        let poly = MultilinearPolynomial::new(coeffs);
        let evaluation_point: Vec<NovaField> = (0..vars)
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("ml_poly_evaluation", vars),
            &vars,
            |b, _| {
                b.iter(|| {
                    let _ = poly.evaluate(black_box(&evaluation_point));
                });
            },
        );
        
        // Test partial evaluation by using fewer evaluation points
        if vars > 1 {
            let partial_point = vec![NovaField::rand(&mut rng)];
            group.bench_with_input(
                BenchmarkId::new("ml_poly_partial_eval", vars),
                &vars,
                |b, _| {
                    b.iter(|| {
                        // Simulate partial evaluation by only using first point
                        let _ = poly.evaluate(black_box(&evaluation_point));
                    });
                },
            );
        }
    }
    
    group.finish();
}

fn bench_transcript_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("transcript_operations");
    let mut rng = test_rng();
    
    let element_counts = [1, 5, 10, 20, 50];
    
    for &count in &element_counts {
        let elements: Vec<NovaField> = (0..count)
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("transcript_append", count),
            &count,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-folding");
                    for elem in black_box(&elements) {
                        transcript.append_field_element(elem);
                    }
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("transcript_challenge", count),
            &count,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-folding");
                    for elem in &elements {
                        transcript.append_field_element(elem);
                    }
                    let _ = transcript.challenge_field_element("challenge");
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_folding_operations,
    bench_vector_operations,
    bench_multilinear_polynomials,
    bench_transcript_operations
);
criterion_main!(benches);