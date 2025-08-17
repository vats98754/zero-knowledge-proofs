use criterion::{criterion_group, criterion_main, Criterion, black_box};

fn bench_smoke_test(c: &mut Criterion) {
    c.bench_function("smoke_test", |b| {
        b.iter(|| {
            // Simple smoke test that does minimal work
            black_box(1 + 1)
        })
    });
}

criterion_group!(benches, bench_smoke_test);
criterion_main!(benches);