//! Main benchmark file for Groth16 components.

use groth16_benchmarks::*;

criterion::criterion_main! {
    bench_field_operations,
    bench_r1cs, 
    bench_qap_conversion,
    bench_trusted_setup
}