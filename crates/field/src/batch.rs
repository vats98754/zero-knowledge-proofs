//! Batch operations for improved performance in zero-knowledge proofs

use crate::{Scalar, FieldError, Result};
use ark_ff::{Field, Zero, One};
use rayon::prelude::*;

/// Batch operations for field elements
pub struct BatchOps;

impl BatchOps {
    /// Performs batch inversion using Montgomery's trick
    pub fn batch_invert(elements: &mut [Scalar]) -> Result<()> {
        if elements.is_empty() {
            return Ok(());
        }
        
        // Check for zeros
        for elem in elements.iter() {
            if elem.is_zero() {
                return Err(FieldError::DivisionByZero);
            }
        }
        
        ark_ff::batch_inversion(elements);
        Ok(())
    }
    
    /// Batch inversion that skips zero elements
    pub fn batch_invert_safe(elements: &mut [Option<Scalar>]) {
        // Collect non-zero elements
        let mut to_invert = Vec::new();
        let mut indices = Vec::new();
        
        for (i, elem) in elements.iter().enumerate() {
            if let Some(val) = elem {
                if !val.is_zero() {
                    to_invert.push(*val);
                    indices.push(i);
                }
            }
        }
        
        // Batch invert
        ark_ff::batch_inversion(&mut to_invert);
        
        // Put back the inverted values
        for (idx, inv_val) in indices.into_iter().zip(to_invert.into_iter()) {
            elements[idx] = Some(inv_val);
        }
    }
    
    /// Computes multiple linear combinations in parallel
    pub fn batch_linear_combinations(
        coeffs_list: &[&[Scalar]],
        points_list: &[&[Scalar]],
    ) -> Result<Vec<Scalar>> {
        if coeffs_list.len() != points_list.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        coeffs_list.par_iter()
            .zip(points_list.par_iter())
            .map(|(coeffs, points)| {
                if coeffs.len() != points.len() {
                    return Err(FieldError::DegreeMismatch);
                }
                
                Ok(coeffs.iter()
                    .zip(points.iter())
                    .map(|(c, p)| *c * *p)
                    .fold(Scalar::zero(), |acc, x| acc + x))
            })
            .collect()
    }
    
    /// Performs batch scalar multiplication
    pub fn batch_scalar_mul(scalars: &[Scalar], base: &Scalar) -> Vec<Scalar> {
        scalars.par_iter()
            .map(|scalar| *scalar * *base)
            .collect()
    }
    
    /// Computes batch powers: [base^0, base^1, base^2, ..., base^(n-1)]
    pub fn batch_powers(base: &Scalar, n: usize) -> Vec<Scalar> {
        if n == 0 {
            return vec![];
        }
        
        let mut powers = vec![Scalar::one()];
        
        for i in 1..n {
            powers.push(powers[i - 1] * base);
        }
        
        powers
    }
    
    /// Computes batch powers in parallel for large n
    pub fn batch_powers_parallel(base: &Scalar, n: usize) -> Vec<Scalar> {
        if n == 0 {
            return vec![];
        }
        
        if n <= 1000 {
            return Self::batch_powers(base, n);
        }
        
        // For large n, use parallel computation with chunking
        let chunk_size = (n + rayon::current_num_threads() - 1) / rayon::current_num_threads();
        
        (0..n).into_par_iter()
            .chunks(chunk_size)
            .map(|chunk| {
                let start = chunk[0];
                let base_power = base.pow(&[start as u64]);
                
                let mut local_powers = vec![base_power];
                for i in 1..chunk.len() {
                    local_powers.push(local_powers[i - 1] * base);
                }
                local_powers
            })
            .flatten()
            .collect()
    }
    
    /// Computes the sum of products: sum(a[i] * b[i])
    pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Result<Scalar> {
        if a.len() != b.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x * *y)
            .reduce(|| Scalar::zero(), |acc, x| acc + x))
    }
    
    /// Computes multiple inner products in parallel
    pub fn batch_inner_products(
        a_vectors: &[&[Scalar]],
        b_vectors: &[&[Scalar]],
    ) -> Result<Vec<Scalar>> {
        if a_vectors.len() != b_vectors.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        a_vectors.par_iter()
            .zip(b_vectors.par_iter())
            .map(|(a, b)| Self::inner_product(a, b))
            .collect()
    }
    
    /// Computes elementwise operations between vectors
    pub fn elementwise_add(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x + *y)
            .collect())
    }
    
    pub fn elementwise_sub(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x - *y)
            .collect())
    }
    
    pub fn elementwise_mul(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x * *y)
            .collect())
    }
    
    /// Scales a vector by a scalar
    pub fn scale_vector(vector: &[Scalar], scalar: &Scalar) -> Vec<Scalar> {
        vector.par_iter()
            .map(|x| *x * *scalar)
            .collect()
    }
    
    /// Computes prefix sums (cumulative sums)
    pub fn prefix_sums(elements: &[Scalar]) -> Vec<Scalar> {
        if elements.is_empty() {
            return vec![];
        }
        
        let mut sums = vec![Scalar::zero(); elements.len()];
        sums[0] = elements[0];
        
        for i in 1..elements.len() {
            sums[i] = sums[i - 1] + elements[i];
        }
        
        sums
    }
    
    /// Computes suffix sums (reverse cumulative sums)
    pub fn suffix_sums(elements: &[Scalar]) -> Vec<Scalar> {
        if elements.is_empty() {
            return vec![];
        }
        
        let mut sums = vec![Scalar::zero(); elements.len()];
        let last_idx = elements.len() - 1;
        sums[last_idx] = elements[last_idx];
        
        for i in (0..last_idx).rev() {
            sums[i] = sums[i + 1] + elements[i];
        }
        
        sums
    }
}

/// Parallel computation utilities
pub struct ParallelOps;

impl ParallelOps {
    /// Parallel map operation
    pub fn parallel_map<F>(input: &[Scalar], f: F) -> Vec<Scalar>
    where
        F: Fn(&Scalar) -> Scalar + Sync + Send,
    {
        input.par_iter().map(f).collect()
    }
    
    /// Parallel reduce operation
    pub fn parallel_reduce<F>(input: &[Scalar], identity: Scalar, f: F) -> Scalar
    where
        F: Fn(Scalar, Scalar) -> Scalar + Sync + Send,
    {
        input.par_iter()
            .copied()
            .reduce(|| identity, f)
    }
    
    /// Parallel scan (prefix sum with custom operation)
    pub fn parallel_scan<F>(input: &[Scalar], identity: Scalar, f: F) -> Vec<Scalar>
    where
        F: Fn(Scalar, Scalar) -> Scalar + Sync + Send,
    {
        // For now, implement sequentially (parallel scan is complex)
        let mut result = vec![identity; input.len()];
        if !input.is_empty() {
            result[0] = input[0];
            for i in 1..input.len() {
                result[i] = f(result[i - 1], input[i]);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::{Zero, One, UniformRand};
    
    #[test]
    fn test_batch_invert() {
        let mut rng = test_rng();
        let mut elements: Vec<Scalar> = (0..100)
            .map(|_| {
                let mut val = Scalar::rand(&mut rng);
                while val.is_zero() {
                    val = Scalar::rand(&mut rng);
                }
                val
            })
            .collect();
        
        let originals = elements.clone();
        BatchOps::batch_invert(&mut elements).unwrap();
        
        for (orig, inv) in originals.iter().zip(elements.iter()) {
            assert_eq!(*orig * *inv, Scalar::one());
        }
    }
    
    #[test]
    fn test_batch_invert_safe() {
        let mut rng = test_rng();
        let mut elements: Vec<Option<Scalar>> = (0..100)
            .map(|i| {
                if i % 10 == 0 {
                    None // Some None values
                } else if i % 13 == 0 {
                    Some(Scalar::zero()) // Some zero values
                } else {
                    Some(Scalar::rand(&mut rng))
                }
            })
            .collect();
        
        let originals = elements.clone();
        BatchOps::batch_invert_safe(&mut elements);
        
        for (orig, inv) in originals.iter().zip(elements.iter()) {
            match (orig, inv) {
                (Some(o), Some(i)) if !o.is_zero() => {
                    assert_eq!(*o * *i, Scalar::one());
                }
                (None, None) => {}, // Should remain None
                (Some(o), Some(_)) if o.is_zero() => {}, // Zero should remain unchanged
                _ => {}
            }
        }
    }
    
    #[test]
    fn test_batch_powers() {
        let base = Scalar::from(3u64);
        let powers = BatchOps::batch_powers(&base, 10);
        
        assert_eq!(powers[0], Scalar::one());
        assert_eq!(powers[1], base);
        assert_eq!(powers[2], base * base);
        assert_eq!(powers[3], base * base * base);
        
        // Test parallel version gives same result
        let powers_parallel = BatchOps::batch_powers_parallel(&base, 10);
        assert_eq!(powers, powers_parallel);
    }
    
    #[test]
    fn test_inner_product() {
        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];
        
        let result = BatchOps::inner_product(&a, &b).unwrap();
        let expected = Scalar::from(1u64 * 4u64 + 2u64 * 5u64 + 3u64 * 6u64); // 32
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_elementwise_operations() {
        let a = vec![Scalar::from(10u64), Scalar::from(20u64), Scalar::from(30u64)];
        let b = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        
        let sum = BatchOps::elementwise_add(&a, &b).unwrap();
        assert_eq!(sum, vec![Scalar::from(11u64), Scalar::from(22u64), Scalar::from(33u64)]);
        
        let diff = BatchOps::elementwise_sub(&a, &b).unwrap();
        assert_eq!(diff, vec![Scalar::from(9u64), Scalar::from(18u64), Scalar::from(27u64)]);
        
        let prod = BatchOps::elementwise_mul(&a, &b).unwrap();
        assert_eq!(prod, vec![Scalar::from(10u64), Scalar::from(40u64), Scalar::from(90u64)]);
    }
    
    #[test]
    fn test_prefix_suffix_sums() {
        let elements = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
        
        let prefix = BatchOps::prefix_sums(&elements);
        assert_eq!(prefix, vec![Scalar::from(1u64), Scalar::from(3u64), Scalar::from(6u64), Scalar::from(10u64)]);
        
        let suffix = BatchOps::suffix_sums(&elements);
        assert_eq!(suffix, vec![Scalar::from(10u64), Scalar::from(9u64), Scalar::from(7u64), Scalar::from(4u64)]);
    }
    
    #[test]
    fn test_scale_vector() {
        let vector = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let scalar = Scalar::from(5u64);
        
        let scaled = BatchOps::scale_vector(&vector, &scalar);
        assert_eq!(scaled, vec![Scalar::from(5u64), Scalar::from(10u64), Scalar::from(15u64)]);
    }
}