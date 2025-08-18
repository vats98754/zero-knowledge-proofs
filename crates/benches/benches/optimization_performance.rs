use criterion::{criterion_group, criterion_main, Criterion, black_box, BenchmarkId};
use nova_core::*;
use benches::*;
use ark_std::{test_rng, UniformRand};

/// Benchmark parallel vs sequential folding performance
fn bench_parallel_folding(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_folding");
    let mut rng = test_rng();
    
    let sizes = [64, 128, 256, 512, 1024];
    
    for &size in &sizes {
        let relation = create_test_relation(8); // Larger relation for parallel benefits
        
        // Sequential folding scheme
        let sequential_params = FoldingParameters {
            security_parameter: 128,
            enable_parallel: false,
            max_depth: 64,
        };
        let sequential_scheme = FoldingScheme::with_parameters(relation.clone(), sequential_params);
        
        // Parallel folding scheme  
        let parallel_params = FoldingParameters {
            security_parameter: 128,
            enable_parallel: true,
            max_depth: 64,
        };
        let parallel_scheme = FoldingScheme::with_parameters(relation.clone(), parallel_params);
        
        let instance1 = create_test_instance(&relation, size);
        let witness1 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        let instance2 = create_test_instance(&relation, size);
        let witness2 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        
        group.bench_with_input(
            BenchmarkId::new("sequential_folding", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-sequential");
                    let _ = sequential_scheme.fold(
                        black_box(&instance1),
                        black_box(&witness1),
                        black_box(&instance2),
                        black_box(&witness2),
                        black_box(&mut transcript),
                    );
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("parallel_folding", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-parallel");
                    let _ = parallel_scheme.fold(
                        black_box(&instance1),
                        black_box(&witness1),
                        black_box(&instance2),
                        black_box(&witness2),
                        black_box(&mut transcript),
                    );
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark memory efficiency with different witness sizes
fn bench_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");
    let mut rng = test_rng();
    
    let witness_sizes = [100, 500, 1000, 2000, 5000];
    
    for &size in &witness_sizes {
        let relation = create_test_relation(6);
        let folding_scheme = FoldingScheme::new(relation.clone());
        
        group.bench_with_input(
            BenchmarkId::new("memory_usage_single_fold", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let instance1 = create_test_instance(&relation, size);
                    let witness1 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
                    let instance2 = create_test_instance(&relation, size);
                    let witness2 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
                    let mut transcript = Transcript::new("nova-memory");
                    
                    let _ = folding_scheme.fold(
                        black_box(&instance1),
                        black_box(&witness1),
                        black_box(&instance2),
                        black_box(&witness2),
                        black_box(&mut transcript),
                    );
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("memory_usage_accumulator_growth", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut accumulator = FoldingAccumulator::new(folding_scheme.clone());
                    let mut transcript = Transcript::new("nova-memory-growth");
                    
                    // Add multiple instances to measure memory growth
                    for i in 0..10 {
                        let instance = create_test_instance(&relation, size);
                        let witness = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
                        
                        accumulator.accumulate(instance, witness, &mut transcript).unwrap();
                        
                        // Early exit for large sizes to avoid excessive memory usage
                        if size > 2000 && i > 4 {
                            break;
                        }
                    }
                    
                    accumulator.depth()
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark depth scaling for recursive computations
fn bench_recursion_depth_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("recursion_depth_scaling");
    let mut rng = test_rng();
    
    let depths = [2, 4, 8, 16, 32];
    let base_size = 50; // Moderate witness size
    
    for &depth in &depths {
        group.bench_with_input(
            BenchmarkId::new("depth_scaling", depth),
            &depth,
            |b, _| {
                b.iter(|| {
                    let relation = create_test_relation(4);
                    let folding_scheme = FoldingScheme::new(relation.clone());
                    let mut accumulator = FoldingAccumulator::new(folding_scheme);
                    let mut transcript = Transcript::new("nova-depth-scaling");
                    
                    // Perform folding to specified depth
                    for step in 0..black_box(depth) {
                        let instance = create_test_instance(&relation, base_size);
                        let witness = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
                        
                        accumulator.accumulate(instance, witness, &mut transcript).unwrap();
                    }
                    
                    accumulator.depth()
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark different security parameter settings
fn bench_security_parameter_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_parameter_scaling");
    let mut rng = test_rng();
    
    let security_params = [80, 128, 192, 256];
    let size = 100;
    
    for &security_param in &security_params {
        let relation = create_test_relation(4);
        let params = FoldingParameters {
            security_parameter: security_param,
            enable_parallel: true,
            max_depth: 64,
        };
        let folding_scheme = FoldingScheme::with_parameters(relation.clone(), params);
        
        let instance1 = create_test_instance(&relation, size);
        let witness1 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        let instance2 = create_test_instance(&relation, size);
        let witness2 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        
        group.bench_with_input(
            BenchmarkId::new("security_param", security_param),
            &security_param,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-security");
                    let _ = folding_scheme.fold(
                        black_box(&instance1),
                        black_box(&witness1),
                        black_box(&instance2),
                        black_box(&witness2),
                        black_box(&mut transcript),
                    );
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark witness size scaling
fn bench_witness_size_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("witness_size_scaling");
    let mut rng = test_rng();
    
    // Test logarithmic scaling of witness sizes  
    let witness_variable_counts = [3, 4, 5, 6, 7, 8]; // 2^n variables
    
    for &var_count in &witness_variable_counts {
        let relation = create_test_relation(var_count);
        let folding_scheme = FoldingScheme::new(relation.clone());
        
        let instance1 = create_test_instance(&relation, 1 << var_count);
        let witness1 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        let instance2 = create_test_instance(&relation, 1 << var_count);
        let witness2 = Witness::new(vec![NovaField::rand(&mut rng); relation.num_vars()]);
        
        group.bench_with_input(
            BenchmarkId::new("witness_vars", 1 << var_count),
            &var_count,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-witness-scaling");
                    let _ = folding_scheme.fold(
                        black_box(&instance1),
                        black_box(&witness1),
                        black_box(&instance2),
                        black_box(&witness2),
                        black_box(&mut transcript),
                    );
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark transcript operation performance
fn bench_transcript_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("transcript_performance");
    let mut rng = test_rng();
    
    let element_counts = [10, 50, 100, 500, 1000];
    
    for &count in &element_counts {
        let elements: Vec<NovaField> = (0..count)
            .map(|_| NovaField::rand(&mut rng))
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("transcript_throughput", count),
            &count,
            |b, _| {
                b.iter(|| {
                    let mut transcript = Transcript::new("nova-throughput");
                    for elem in black_box(&elements) {
                        transcript.append_field_element(elem);
                    }
                    for i in 0..5 {
                        let _ = transcript.challenge_field_element(&format!("challenge-{}", i));
                    }
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    optimization_benches,
    bench_parallel_folding,
    bench_memory_efficiency,
    bench_recursion_depth_scaling,
    bench_security_parameter_scaling,
    bench_witness_size_scaling,
    bench_transcript_performance
);
criterion_main!(optimization_benches);