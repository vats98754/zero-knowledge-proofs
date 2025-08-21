use criterion::{criterion_group, criterion_main, Criterion};

fn stark_benchmarks(_c: &mut Criterion) {
    // Benchmarks will be implemented later
}

criterion_group!(benches, stark_benchmarks);
criterion_main!(benches);