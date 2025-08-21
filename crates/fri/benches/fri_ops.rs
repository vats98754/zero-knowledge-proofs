use criterion::{criterion_group, criterion_main, Criterion};

fn fri_ops(_c: &mut Criterion) {
    // Benchmarks for FRI operations will be implemented later
}

criterion_group!(benches, fri_ops);
criterion_main!(benches);