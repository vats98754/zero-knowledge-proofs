use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_placeholder(_c: &mut Criterion) {
    // TODO: Implement benchmarks
}

criterion_group!(benches, benchmark_placeholder);
criterion_main!(benches);