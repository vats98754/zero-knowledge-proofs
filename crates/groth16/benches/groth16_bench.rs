use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_groth16(_c: &mut Criterion) {
    // TODO: Implement Groth16 benchmarks
}

criterion_group!(benches, benchmark_groth16);
criterion_main!(benches);