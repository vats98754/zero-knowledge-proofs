use criterion::{criterion_group, criterion_main, Criterion};
use compiler::compile_to_trace;

fn bench_simple_trace_generation(c: &mut Criterion) {
    let assembly = r#"
        ADD R0, R1, R2
        SUB R3, R0, R1
        MUL R4, R1, R2
        HALT
    "#;
    
    c.bench_function("simple_trace_generation", |b| {
        b.iter(|| compile_to_trace(assembly).unwrap())
    });
}

criterion_group!(benches, bench_simple_trace_generation);
criterion_main!(benches);