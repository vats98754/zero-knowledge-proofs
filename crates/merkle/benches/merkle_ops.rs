use criterion::{criterion_group, criterion_main, Criterion};

fn merkle_ops(_c: &mut Criterion) {
    // Benchmarks for Merkle operations will be implemented later
}

criterion_group!(benches, merkle_ops);
criterion_main!(benches);