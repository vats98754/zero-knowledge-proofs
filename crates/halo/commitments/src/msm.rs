//! Multi-scalar multiplication utilities
//!
//! This module provides efficient implementations of multi-scalar multiplication (MSM)
//! operations that are crucial for the performance of commitment schemes.

use crate::{Scalar, GroupElement, GroupProjective, Result, CommitmentError};
use ff::PrimeField;
use group::prime::PrimeCurveAffine;
use rayon::prelude::*;
use std::cmp;

/// Performs multi-scalar multiplication: sum_i(scalars[i] * points[i])
///
/// This is a performance-critical operation used throughout commitment schemes.
/// We use a sliding window algorithm for efficiency.
pub fn msm(scalars: &[Scalar], points: &[GroupElement]) -> Result<GroupProjective> {
    if scalars.len() != points.len() {
        return Err(CommitmentError::MsmError(
            "Scalars and points must have the same length".to_string()
        ));
    }
    
    if scalars.is_empty() {
        return Ok(GroupProjective::identity());
    }
    
    // For small inputs, use the simple algorithm
    if scalars.len() <= 32 {
        return Ok(simple_msm(scalars, points));
    }
    
    // For larger inputs, use Pippenger's algorithm
    pippenger_msm(scalars, points)
}

/// Simple MSM implementation for small inputs
fn simple_msm(scalars: &[Scalar], points: &[GroupElement]) -> GroupProjective {
    scalars
        .iter()
        .zip(points.iter())
        .map(|(scalar, point)| point.to_curve() * scalar)
        .fold(GroupProjective::identity(), |acc, point| acc + point)
}

/// Pippenger's algorithm for efficient MSM with large inputs
fn pippenger_msm(scalars: &[Scalar], points: &[GroupElement]) -> Result<GroupProjective> {
    let n = scalars.len();
    
    // Choose window size based on input size
    let window_size = optimal_window_size(n);
    let num_windows = (256 + window_size - 1) / window_size;
    
    // Convert points to projective for faster arithmetic
    let proj_points: Vec<GroupProjective> = points
        .par_iter()
        .map(|p| p.to_curve())
        .collect();
    
    // Process each window
    let mut result = GroupProjective::identity();
    
    for window_idx in 0..num_windows {
        let bit_start = window_idx * window_size;
        let bit_end = cmp::min(bit_start + window_size, 256);
        
        // Double the accumulator for the new window
        for _ in 0..(bit_end - bit_start) {
            result = result.double();
        }
        
        // Process buckets for this window
        let bucket_result = process_window(&scalars, &proj_points, bit_start, bit_end)?;
        result += bucket_result;
    }
    
    Ok(result)
}

/// Process a single window in Pippenger's algorithm
fn process_window(
    scalars: &[Scalar],
    points: &[GroupProjective],
    bit_start: usize,
    bit_end: usize,
) -> Result<GroupProjective> {
    let window_size = bit_end - bit_start;
    let num_buckets = (1 << window_size) - 1; // 2^window_size - 1
    
    // Initialize buckets
    let mut buckets = vec![GroupProjective::identity(); num_buckets];
    
    // Distribute points into buckets
    for (scalar, point) in scalars.iter().zip(points.iter()) {
        let bucket_idx = extract_window_bits(scalar, bit_start, bit_end);
        if bucket_idx > 0 {
            buckets[bucket_idx - 1] += point;
        }
    }
    
    // Combine buckets using the bucket method
    let mut result = GroupProjective::identity();
    let mut running_sum = GroupProjective::identity();
    
    for bucket in buckets.into_iter().rev() {
        running_sum += bucket;
        result += running_sum;
    }
    
    Ok(result)
}

/// Extract a window of bits from a scalar
fn extract_window_bits(scalar: &Scalar, bit_start: usize, bit_end: usize) -> usize {
    let repr = scalar.to_repr();
    let mut result = 0usize;
    
    for bit_idx in bit_start..bit_end {
        let byte_idx = bit_idx / 8;
        let bit_offset = bit_idx % 8;
        
        if byte_idx < repr.len() {
            let bit = (repr[byte_idx] >> bit_offset) & 1;
            result |= (bit as usize) << (bit_idx - bit_start);
        }
    }
    
    result
}

/// Determine optimal window size based on input size
fn optimal_window_size(n: usize) -> usize {
    if n <= 1 {
        1
    } else if n <= 32 {
        3
    } else if n <= 128 {
        4
    } else if n <= 512 {
        5
    } else if n <= 2048 {
        6
    } else if n <= 8192 {
        7
    } else {
        8
    }
}

/// Parallel MSM for very large inputs
pub fn parallel_msm(scalars: &[Scalar], points: &[GroupElement]) -> Result<GroupProjective> {
    if scalars.len() != points.len() {
        return Err(CommitmentError::MsmError(
            "Scalars and points must have the same length".to_string()
        ));
    }
    
    if scalars.is_empty() {
        return Ok(GroupProjective::identity());
    }
    
    // For small inputs, use regular MSM
    if scalars.len() <= 1024 {
        return msm(scalars, points);
    }
    
    // Split into chunks for parallel processing
    let chunk_size = cmp::max(1024, scalars.len() / rayon::current_num_threads());
    
    let partial_results: Result<Vec<GroupProjective>> = scalars
        .par_chunks(chunk_size)
        .zip(points.par_chunks(chunk_size))
        .map(|(scalar_chunk, point_chunk)| msm(scalar_chunk, point_chunk))
        .collect();
    
    let partial_results = partial_results?;
    
    // Combine partial results
    Ok(partial_results
        .into_iter()
        .fold(GroupProjective::identity(), |acc, partial| acc + partial))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::{Group, Curve};
    use rand::thread_rng;
    
    #[test]
    fn test_msm_simple() {
        let mut rng = thread_rng();
        
        let scalars: Vec<Scalar> = (0..10).map(|_| Scalar::random(&mut rng)).collect();
        let points: Vec<GroupElement> = (0..10)
            .map(|_| GroupProjective::random(&mut rng).to_affine())
            .collect();
        
        let result1 = msm(&scalars, &points).unwrap();
        let result2 = simple_msm(&scalars, &points);
        
        assert_eq!(result1, result2);
    }
    
    #[test]
    fn test_msm_empty() {
        let scalars = Vec::new();
        let points = Vec::new();
        
        let result = msm(&scalars, &points).unwrap();
        assert_eq!(result, GroupProjective::identity());
    }
    
    #[test]
    fn test_msm_single() {
        let mut rng = thread_rng();
        
        let scalar = Scalar::random(&mut rng);
        let point = GroupProjective::random(&mut rng).to_affine();
        
        let result = msm(&[scalar], &[point]).unwrap();
        let expected = point.to_curve() * scalar;
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_msm_length_mismatch() {
        let scalars = vec![Scalar::one()];
        let points = vec![];
        
        let result = msm(&scalars, &points);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_extract_window_bits() {
        let scalar = Scalar::from(0b11010110u64);
        
        // Extract bits 0-3 (should be 0110 = 6)
        assert_eq!(extract_window_bits(&scalar, 0, 4), 6);
        
        // Extract bits 4-7 (should be 1101 = 13) 
        assert_eq!(extract_window_bits(&scalar, 4, 8), 13);
    }
    
    #[test]
    fn test_parallel_msm() {
        let mut rng = thread_rng();
        
        let scalars: Vec<Scalar> = (0..2000).map(|_| Scalar::random(&mut rng)).collect();
        let points: Vec<GroupElement> = (0..2000)
            .map(|_| GroupProjective::random(&mut rng).to_affine())
            .collect();
        
        let result1 = msm(&scalars, &points).unwrap();
        let result2 = parallel_msm(&scalars, &points).unwrap();
        
        assert_eq!(result1, result2);
    }
}