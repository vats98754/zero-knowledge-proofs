use criterion::{criterion_group, criterion_main, Criterion, black_box, BenchmarkId};
use commitments::*;
use ark_std::test_rng;
use ark_poly::Polynomial;
use ark_bls12_381::Fr as BlsFr;
use ark_ff::Field;

fn bench_commitment_schemes(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_schemes");
    let mut rng = test_rng();
    
    // Test different polynomial degrees
    let degrees = [4, 8, 16, 32, 64];
    
    for &degree in &degrees {
        // KZG benchmarks
        let kzg_params = NovaKZG::setup(degree, &mut rng).unwrap();
        let (kzg_ck, kzg_vk) = NovaKZG::trim(&kzg_params, degree).unwrap();
        
        let poly = ark_poly::univariate::DensePolynomial::from_coefficients_vec(
            (0..=degree).map(|_| BlsFr::rand(&mut rng)).collect()
        );
        
        group.bench_with_input(
            BenchmarkId::new("kzg_commit", degree),
            &degree,
            |b, _| {
                b.iter(|| {
                    let _ = NovaKZG::commit(&kzg_ck, black_box(&poly));
                });
            },
        );

        let commitment = NovaKZG::commit(&kzg_ck, &poly).unwrap();
        let point = BlsFr::rand(&mut rng);
        
        group.bench_with_input(
            BenchmarkId::new("kzg_open", degree),
            &degree,
            |b, _| {
                b.iter(|| {
                    let _ = NovaKZG::open(&kzg_ck, black_box(&poly), &commitment, black_box(point));
                });
            },
        );

        let proof = NovaKZG::open(&kzg_ck, &poly, &commitment, point).unwrap();
        let value = poly.evaluate(&point);
        
        group.bench_with_input(
            BenchmarkId::new("kzg_verify", degree),
            &degree,
            |b, _| {
                b.iter(|| {
                    let _ = NovaKZG::verify(&kzg_vk, &commitment, black_box(point), black_box(value), &proof);
                });
            },
        );
    }
    
    group.finish();
}

fn bench_setup_schemes(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup_schemes");
    let mut rng = test_rng();
    
    let degrees = [16, 32, 64, 128];
    
    for &degree in &degrees {
        group.bench_with_input(
            BenchmarkId::new("kzg_setup", degree),
            &degree,
            |b, &d| {
                b.iter(|| {
                    let _ = NovaKZG::setup(black_box(d), &mut rng);
                });
            },
        );
    }
    
    group.finish();
}

fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");
    let mut rng = test_rng();
    
    let degree = 16;
    let batch_sizes = [1, 5, 10, 20];
    
    for &batch_size in &batch_sizes {
        let params = NovaKZG::setup(degree, &mut rng).unwrap();
        let (ck, vk) = NovaKZG::trim(&params, degree).unwrap();
        
        let polys: Vec<_> = (0..batch_size)
            .map(|_| {
                ark_poly::univariate::DensePolynomial::from_coefficients_vec(
                    (0..=degree).map(|_| BlsFr::rand(&mut rng)).collect()
                )
            })
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("batch_commit", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    for poly in black_box(&polys) {
                        let _ = NovaKZG::commit(&ck, poly);
                    }
                });
            },
        );
        
        let commitments: Vec<_> = polys
            .iter()
            .map(|poly| NovaKZG::commit(&ck, poly).unwrap())
            .collect();
        
        let point = BlsFr::rand(&mut rng);
        
        group.bench_with_input(
            BenchmarkId::new("batch_open", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    for (poly, commitment) in black_box(&polys).iter().zip(black_box(&commitments).iter()) {
                        let _ = NovaKZG::open(&ck, poly, commitment, point);
                    }
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_commitment_schemes, bench_setup_schemes, bench_batch_operations);
criterion_main!(benches);