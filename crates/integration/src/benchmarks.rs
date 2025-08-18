#[cfg(feature = "bench")]
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

/// Benchmark trace generation for different program sizes
#[cfg(feature = "bench")]
pub fn bench_trace_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("trace_generation");
    
    for size in [10, 50, 100, 200].iter() {
        let mut assembly = String::new();
        for i in 0..*size {
            assembly.push_str(&format!("ADD R{}, R{}, R{}\n", i % 8, (i + 1) % 8, (i + 2) % 8));
        }
        assembly.push_str("HALT\n");

        group.bench_with_input(
            BenchmarkId::new("instructions", size),
            &assembly,
            |b, assembly| {
                b.iter(|| compile_to_trace(assembly).unwrap())
            },
        );
    }
    
    group.finish();
}

/// Benchmark PLONK proof generation
#[cfg(feature = "bench")]
pub fn bench_plonk_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("plonk_proving");
    
    // Setup once
    let assembly = r#"
        ADD R0, R1, R2
        MUL R3, R0, R1
        SUB R4, R3, R2
        HALT
    "#;
    
    let trace = compile_to_trace(assembly).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut backend = PlonkBackend::new();
    let constraints = zkvm_core::ConstraintGenerator::generate_plonk_constraints(&trace);
    backend.setup(&constraints, &mut rng).unwrap();

    group.bench_function("prove", |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
            backend.prove(&trace, &mut rng).unwrap()
        })
    });
    
    group.finish();
}

/// Benchmark token contract operations
#[cfg(feature = "bench")]
pub fn bench_token_contract(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_contract");
    let contract = TokenContract::new();

    group.bench_function("simple_transfer", |b| {
        b.iter(|| contract.execute_transfer(1, 2, 100).unwrap())
    });

    group.bench_function("batch_transfer", |b| {
        let transfers = vec![(1, 2, 50), (2, 3, 25), (3, 1, 10)];
        b.iter(|| contract.execute_batch_transfer(&transfers).unwrap())
    });

    group.bench_function("balance_verification", |b| {
        b.iter(|| contract.execute_verify_balance(1, 1000).unwrap())
    });
    
    group.finish();
}

/// Benchmark constraint generation
#[cfg(feature = "bench")]
pub fn bench_constraint_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("constraint_generation");
    
    let assembly = r#"
        ADD R0, R1, R2
        MUL R3, R0, R1
        DIV R4, R3, R2
        LOAD R5, R0
        STORE R1, R5
        HALT
    "#;
    
    let trace = compile_to_trace(assembly).unwrap();

    group.bench_function("plonk_constraints", |b| {
        b.iter(|| zkvm_core::ConstraintGenerator::generate_plonk_constraints(&trace))
    });

    group.bench_function("stark_constraints", |b| {
        b.iter(|| zkvm_core::ConstraintGenerator::generate_stark_constraints(&trace))
    });
    
    group.finish();
}

/// Smoke benchmark for CI
#[cfg(feature = "bench")]
pub fn bench_smoke(c: &mut Criterion) {
    let assembly = "ADD R0, R1, R2\nHALT\n";
    let trace = compile_to_trace(assembly).unwrap();
    
    c.bench_function("smoke_compile", |b| {
        b.iter(|| compile_to_trace(assembly).unwrap())
    });
}

#[cfg(feature = "bench")]
criterion_group!(
    benches,
    bench_trace_generation,
    bench_plonk_proving,
    bench_token_contract,
    bench_constraint_generation,
    bench_smoke
);

#[cfg(feature = "bench")]
criterion_main!(benches);