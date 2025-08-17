use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use zkp_field::{Scalar, bls12_381::Bls12381Field, batch::BatchOps};
use ark_std::test_rng;
use ark_ff::Field;

fn bench_field_operations(c: &mut Criterion) {
    let mut rng = test_rng();
    
    let mut group = c.benchmark_group("field_ops");
    
    for size in [100, 1000, 10000].iter() {
        let elements: Vec<Scalar> = (0..*size).map(|_| Scalar::rand(&mut rng)).collect();
        
        group.bench_with_input(
            BenchmarkId::new("batch_invert", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let mut test_elements = elements.clone();
                    BatchOps::batch_invert(&mut test_elements).unwrap();
                });
            },
        );
        
        let other_elements: Vec<Scalar> = (0..*size).map(|_| Scalar::rand(&mut rng)).collect();
        
        group.bench_with_input(
            BenchmarkId::new("inner_product", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    BatchOps::inner_product(&elements, &other_elements).unwrap();
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_field_operations);
criterion_main!(benches);