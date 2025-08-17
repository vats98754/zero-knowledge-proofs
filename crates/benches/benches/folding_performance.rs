use criterion::{criterion_group, criterion_main, Criterion, black_box, BenchmarkId};
use nova_core::*;
use ark_std::test_rng;
use ark_ff::Field;

fn bench_folding_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("folding_operations");
    let mut rng = test_rng();
    
    // Test different instance sizes
    let sizes = [4, 8, 16, 32, 64];
    
    for &size in &sizes {
        // Create test instances
        let relation = Relation::new(size);
        let instance = Instance::new(relation, size).unwrap();
        let witness = Witness::new(vec![NovaField::rand(&mut rng); size]);
        
        group.bench_with_input(
            BenchmarkId::new("folding_step", size),
            &size,
            |b, _| {
                let folding_scheme = FoldingScheme::new();
                b.iter(|| {
                    let randomness = NovaField::rand(&mut rng);
                    let _ = folding_scheme.fold_step(
                        black_box(&instance),
                        black_box(&witness),
                        black_box(randomness),
                    );
                });
            },
        );

        let folding_scheme = FoldingScheme::new();
        let randomness = NovaField::rand(&mut rng);
        let (folded_instance, folded_witness) = folding_scheme
            .fold_step(&instance, &witness, randomness)
            .unwrap();

        group.bench_with_input(
            BenchmarkId::new("validation", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = folding_scheme.validate_folding(
                        black_box(&instance),
                        black_box(&folded_instance),
                        black_box(randomness),
                    );
                });
            },
        );

        // Benchmark accumulator operations
        let mut accumulator = FoldingAccumulator::new(instance.clone(), witness.clone());
        
        group.bench_with_input(
            BenchmarkId::new("accumulator_fold", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let new_instance = Instance::new(Relation::new(size), size).unwrap();
                    let new_witness = Witness::new(vec![NovaField::rand(&mut rng); size]);
                    let randomness = NovaField::rand(&mut rng);
                    let _ = accumulator.fold_instance(
                        black_box(new_instance),
                        black_box(new_witness),
                        black_box(randomness),
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
        
        group.bench_with_input(
            BenchmarkId::new("ml_poly_partial_eval", vars),
            &vars,
            |b, _| {
                let partial_point = vec![NovaField::rand(&mut rng)];
                b.iter(|| {
                    let _ = poly.partial_evaluate(black_box(&partial_point));
                });
            },
        );
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
                    let mut transcript = Transcript::new(b"nova-folding");
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
                    let mut transcript = Transcript::new(b"nova-folding");
                    for elem in &elements {
                        transcript.append_field_element(elem);
                    }
                    let _ = transcript.get_challenge();
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