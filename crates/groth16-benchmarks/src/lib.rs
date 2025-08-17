//! Benchmarks for Groth16 components.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use groth16_field::{F, FieldLike};
use groth16_r1cs::{R1CS, LinearCombination};
use groth16_qap::QAP;
use groth16_setup::CRS;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::thread_rng;

/// Benchmark R1CS constraint satisfaction
pub fn bench_r1cs(c: &mut Criterion) {
    let mut group = c.benchmark_group("r1cs");
    
    for size in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::new("constraint_satisfaction", size), size, |b, &size| {
            // Create R1CS with 'size' multiplication constraints
            let mut r1cs = R1CS::<F>::new(0);
            let mut assignments = vec![<F as FieldLike>::one()]; // constant
            
            for _ in 0..size {
                let x = r1cs.allocate_variable();
                let y = r1cs.allocate_variable();
                let z = r1cs.allocate_variable();
                
                r1cs.enforce_multiplication(
                    LinearCombination::from_variable(x),
                    LinearCombination::from_variable(y),
                    LinearCombination::from_variable(z)
                );
                
                // Add satisfying assignment: 2 * 3 = 6
                assignments.push(F::from(2u64)); // x
                assignments.push(F::from(3u64)); // y
                assignments.push(F::from(6u64)); // z
            }
            
            b.iter(|| {
                r1cs.is_satisfied(&assignments).unwrap()
            });
        });
    }
    
    group.finish();
}

/// Benchmark QAP conversion
pub fn bench_qap_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("qap");
    
    for size in [10, 100].iter() {
        group.bench_with_input(BenchmarkId::new("r1cs_to_qap", size), size, |b, &size| {
            // Create R1CS with 'size' constraints
            let mut r1cs = R1CS::<F>::new(0);
            
            for _ in 0..size {
                let x = r1cs.allocate_variable();
                let y = r1cs.allocate_variable();
                let z = r1cs.allocate_variable();
                
                r1cs.enforce_multiplication(
                    LinearCombination::from_variable(x),
                    LinearCombination::from_variable(y),
                    LinearCombination::from_variable(z)
                );
            }
            
            b.iter(|| {
                QAP::from_r1cs(&r1cs).unwrap()
            });
        });
    }
    
    group.finish();
}

/// Benchmark trusted setup
pub fn bench_trusted_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("trusted_setup");
    
    for size in [10, 50].iter() {
        group.bench_with_input(BenchmarkId::new("crs_generation", size), size, |b, &size| {
            // Create QAP
            let mut r1cs = R1CS::<F>::new(0);
            
            for _ in 0..size {
                let x = r1cs.allocate_variable();
                let y = r1cs.allocate_variable();
                let z = r1cs.allocate_variable();
                
                r1cs.enforce_multiplication(
                    LinearCombination::from_variable(x),
                    LinearCombination::from_variable(y),
                    LinearCombination::from_variable(z)
                );
            }
            
            let qap = QAP::from_r1cs(&r1cs).unwrap();
            let mut rng = thread_rng();
            
            b.iter(|| {
                CRS::generate_random(&qap, 1, &mut rng).unwrap()
            });
        });
    }
    
    group.finish();
}

/// Benchmark field operations
pub fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_operations");
    
    let a = F::from(12345u64);
    let b = F::from(67890u64);
    
    group.bench_function("addition", |bench| {
        bench.iter(|| a + b)
    });
    
    group.bench_function("multiplication", |bench| {
        bench.iter(|| a * b)
    });
    
    group.bench_function("inversion", |bench| {
        bench.iter(|| a.inverse().unwrap())
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_field_operations,
    bench_r1cs,
    bench_qap_conversion,
    bench_trusted_setup
);
criterion_main!(benches);