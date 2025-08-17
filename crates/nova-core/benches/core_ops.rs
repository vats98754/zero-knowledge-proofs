use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nova_core::{NovaField, MultilinearPolynomial, inner_product};
use ark_std::{vec, UniformRand};
use ark_std::test_rng;

fn benchmark_multilinear_evaluation(c: &mut Criterion) {
    let mut rng = test_rng();
    
    c.bench_function("multilinear_poly_evaluate_4_vars", |b| {
        let size = 1 << 4; // 4 variables
        let evaluations: Vec<NovaField> = (0..size).map(|_| NovaField::rand(&mut rng)).collect();
        let poly = MultilinearPolynomial::new(evaluations);
        let point: Vec<NovaField> = (0..4).map(|_| NovaField::rand(&mut rng)).collect();
        
        b.iter(|| {
            black_box(poly.evaluate(black_box(&point)))
        });
    });

    c.bench_function("multilinear_poly_evaluate_8_vars", |b| {
        let size = 1 << 8; // 8 variables
        let evaluations: Vec<NovaField> = (0..size).map(|_| NovaField::rand(&mut rng)).collect();
        let poly = MultilinearPolynomial::new(evaluations);
        let point: Vec<NovaField> = (0..8).map(|_| NovaField::rand(&mut rng)).collect();
        
        b.iter(|| {
            black_box(poly.evaluate(black_box(&point)))
        });
    });
}

fn benchmark_inner_product(c: &mut Criterion) {
    let mut rng = test_rng();
    
    c.bench_function("inner_product_1024", |b| {
        let a: Vec<NovaField> = (0..1024).map(|_| NovaField::rand(&mut rng)).collect();
        let b: Vec<NovaField> = (0..1024).map(|_| NovaField::rand(&mut rng)).collect();
        
        b.iter(|| {
            black_box(inner_product(black_box(&a), black_box(&b)))
        });
    });

    c.bench_function("inner_product_4096", |b| {
        let a: Vec<NovaField> = (0..4096).map(|_| NovaField::rand(&mut rng)).collect();
        let b: Vec<NovaField> = (0..4096).map(|_| NovaField::rand(&mut rng)).collect();
        
        b.iter(|| {
            black_box(inner_product(black_box(&a), black_box(&b)))
        });
    });
}

criterion_group!(benches, benchmark_multilinear_evaluation, benchmark_inner_product);
criterion_main!(benches);