use criterion::{criterion_group, criterion_main, Criterion, black_box, BenchmarkId};
use nova_core::*;
use ark_std::{test_rng, UniformRand};

/// Benchmark end-to-end Nova computation including folding and verification
fn bench_end_to_end_nova(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end_nova");
    let mut rng = test_rng();
    
    // Test different computation sizes
    let computation_sizes = [4, 8, 16, 32];
    
    for &size in &computation_sizes {
        // Create computation: matrix-vector product of size x size
        let matrix: Vec<Vec<NovaField>> = (0..size)
            .map(|_| (0..size).map(|_| NovaField::rand(&mut rng)).collect())
            .collect();
        
        let vector: Vec<NovaField> = (0..size).map(|_| NovaField::rand(&mut rng)).collect();
        
        group.bench_with_input(
            BenchmarkId::new("complete_computation", size),
            &size,
            |b, _| {
                b.iter(|| {
                    // Create folding scheme
                    let folding_scheme = FoldingScheme::new();
                    
                    // Create initial instance and witness
                    let relation = Relation::new(size * size + size + 1); // matrix + vector + result_index
                    let instance = Instance::new(relation, size * size + size + 1).unwrap();
                    
                    let mut witness_data = vec![NovaField::zero()]; // result index
                    for row in black_box(&matrix) {
                        witness_data.extend_from_slice(row);
                    }
                    witness_data.extend_from_slice(black_box(&vector));
                    
                    let witness = Witness::new(witness_data);
                    
                    // Simulate folding steps
                    let mut accumulator = FoldingAccumulator::new(instance, witness);
                    
                    for step in 1..=size {
                        // Create step instance and witness
                        let step_relation = Relation::new(size * size + size + 1);
                        let step_instance = Instance::new(step_relation, size * size + size + 1).unwrap();
                        
                        let mut step_witness_data = vec![NovaField::from(step as u64)];
                        for row in &matrix {
                            step_witness_data.extend_from_slice(row);
                        }
                        step_witness_data.extend_from_slice(&vector);
                        
                        let step_witness = Witness::new(step_witness_data);
                        let randomness = NovaField::from((step * 123) as u64);
                        
                        accumulator.fold_instance(step_instance, step_witness, randomness).unwrap();
                    }
                    
                    accumulator
                });
            },
        );
        
        // Benchmark just the folding operations
        group.bench_with_input(
            BenchmarkId::new("folding_only", size),
            &size,
            |b, _| {
                // Setup
                let relation = Relation::new(size);
                let instance = Instance::new(relation, size).unwrap();
                let witness_data: Vec<NovaField> = (0..size).map(|_| NovaField::rand(&mut rng)).collect();
                let witness = Witness::new(witness_data);
                
                b.iter(|| {
                    let folding_scheme = FoldingScheme::new();
                    let randomness = NovaField::rand(&mut rng);
                    
                    folding_scheme.fold_step(
                        black_box(&instance),
                        black_box(&witness),
                        black_box(randomness),
                    )
                });
            },
        );
        
        // Benchmark verification
        group.bench_with_input(
            BenchmarkId::new("verification", size),
            &size,
            |b, _| {
                // Setup
                let folding_scheme = FoldingScheme::new();
                let relation = Relation::new(size);
                let instance = Instance::new(relation, size).unwrap();
                let witness_data: Vec<NovaField> = (0..size).map(|_| NovaField::rand(&mut rng)).collect();
                let witness = Witness::new(witness_data);
                let randomness = NovaField::rand(&mut rng);
                
                let (folded_instance, _) = folding_scheme.fold_step(&instance, &witness, randomness).unwrap();
                
                b.iter(|| {
                    folding_scheme.validate_folding(
                        black_box(&instance),
                        black_box(&folded_instance),
                        black_box(randomness),
                    )
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark Nova's recursion depth scaling
fn bench_recursion_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("recursion_depth");
    let mut rng = test_rng();
    
    let depths = [2, 4, 8, 16];
    let base_size = 8; // Fixed witness size
    
    for &depth in &depths {
        group.bench_with_input(
            BenchmarkId::new("recursive_folding", depth),
            &depth,
            |b, _| {
                b.iter(|| {
                    // Create initial instances
                    let relation = Relation::new(base_size);
                    let mut instances = Vec::new();
                    
                    // Create 2^depth instances to fold
                    let num_instances = 1 << std::cmp::min(depth, 6); // Cap at 2^6 = 64 for performance
                    
                    for _ in 0..num_instances {
                        let instance = Instance::new(relation.clone(), base_size).unwrap();
                        let witness_data: Vec<NovaField> = (0..base_size)
                            .map(|_| NovaField::rand(&mut rng))
                            .collect();
                        let witness = Witness::new(witness_data);
                        instances.push((instance, witness));
                    }
                    
                    // Perform tree-like folding (simulating recursive depth)
                    let mut current_level = instances;
                    let mut level = 0;
                    
                    while current_level.len() > 1 && level < black_box(depth) {
                        let mut next_level = Vec::new();
                        
                        for chunk in current_level.chunks(2) {
                            if chunk.len() == 2 {
                                let (inst1, wit1) = &chunk[0];
                                let (inst2, wit2) = &chunk[1];
                                
                                let mut accumulator = FoldingAccumulator::new(inst1.clone(), wit1.clone());
                                let randomness = NovaField::from((level * 100 + 42) as u64);
                                accumulator.fold_instance(inst2.clone(), wit2.clone(), randomness).unwrap();
                                
                                next_level.push((
                                    accumulator.current_instance().clone(),
                                    accumulator.current_witness().clone(),
                                ));
                            } else {
                                next_level.push(chunk[0].clone());
                            }
                        }
                        
                        current_level = next_level;
                        level += 1;
                    }
                    
                    current_level
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark memory usage patterns
fn bench_memory_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_scaling");
    let mut rng = test_rng();
    
    let witness_sizes = [16, 32, 64, 128, 256];
    
    for &size in &witness_sizes {
        group.bench_with_input(
            BenchmarkId::new("accumulator_growth", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let relation = Relation::new(size);
                    let instance = Instance::new(relation, size).unwrap();
                    let witness_data: Vec<NovaField> = (0..size)
                        .map(|_| NovaField::rand(&mut rng))
                        .collect();
                    let witness = Witness::new(witness_data);
                    
                    let mut accumulator = FoldingAccumulator::new(instance.clone(), witness.clone());
                    
                    // Fold multiple instances to see memory growth
                    for i in 1..=10 {
                        let step_witness_data: Vec<NovaField> = (0..size)
                            .map(|_| NovaField::rand(&mut rng))
                            .collect();
                        let step_witness = Witness::new(step_witness_data);
                        let randomness = NovaField::from((i * 789) as u64);
                        
                        accumulator.fold_instance(
                            black_box(instance.clone()),
                            black_box(step_witness),
                            black_box(randomness),
                        ).unwrap();
                    }
                    
                    accumulator.current_witness().data().len()
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_end_to_end_nova,
    bench_recursion_depth,
    bench_memory_scaling
);
criterion_main!(benches);