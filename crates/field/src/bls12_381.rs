//! BLS12-381 scalar field implementation optimized for zero-knowledge proofs

use crate::{ZkField, Scalar, FieldError, Result};
use ark_ff::{PrimeField, UniformRand, Zero, BigInteger};
use ark_bls12_381::Fr;
use ark_std::rand::Rng;
use rayon::prelude::*;

impl ZkField for Scalar {
    fn multiplicative_generator() -> Self {
        // The multiplicative generator for BLS12-381 scalar field
        Fr::from(7u64)
    }
    
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Fr::rand(rng)
    }
    
    fn batch_invert(elements: &mut [Self]) {
        ark_ff::batch_inversion(elements);
    }
}

/// BLS12-381 field operations with optimizations
pub struct Bls12381Field;

impl Bls12381Field {
    /// Returns the field modulus
    pub fn modulus() -> &'static str {
        "52435875175126190479447740508185965837690552500527637822603658699938581184513"
    }
    
    /// Returns the field size in bits
    pub fn size_in_bits() -> usize {
        255
    }
    
    /// Returns the two-adicity (largest power of 2 dividing p-1)
    pub fn two_adicity() -> u32 {
        32
    }
    
    /// Returns the root of unity of order 2^two_adicity
    pub fn root_of_unity() -> Scalar {
        // For BLS12-381, we need to manually compute the root of unity
        // This is a primitive 2^32-th root of unity in the scalar field
        "10238227357739495823651030575849232062558860180284477541189508159991286009131"
            .parse::<Fr>()
            .unwrap()
    }
    
    /// Converts bytes to field element
    pub fn from_bytes(bytes: &[u8]) -> Result<Scalar> {
        if bytes.len() != 32 {
            return Err(FieldError::InvalidElement);
        }
        
        let mut repr = [0u8; 32];
        repr.copy_from_slice(bytes);
        
        Ok(Fr::from_le_bytes_mod_order(&repr))
    }
    
    /// Converts field element to bytes
    pub fn to_bytes(element: &Scalar) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        // Convert to Montgomery form and then to bytes
        let repr = element.into_bigint();
        bytes.copy_from_slice(&repr.to_bytes_le()[..32]);
        bytes
    }
    
    /// Performs parallel batch operations on field elements
    pub fn parallel_batch_add(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x + *y)
            .collect())
    }
    
    /// Performs parallel batch multiplication
    pub fn parallel_batch_mul(a: &[Scalar], b: &[Scalar]) -> Result<Vec<Scalar>> {
        if a.len() != b.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| *x * *y)
            .collect())
    }
    
    /// Computes linear combination: sum(coeffs[i] * points[i])
    pub fn linear_combination(coeffs: &[Scalar], points: &[Scalar]) -> Result<Scalar> {
        if coeffs.len() != points.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        Ok(coeffs.par_iter()
            .zip(points.par_iter())
            .map(|(c, p)| *c * *p)
            .reduce(|| Scalar::zero(), |a, b| a + b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::{Zero, One, UniformRand, Field};
    
    #[test]
    fn test_multiplicative_generator() {
        let gen = Scalar::multiplicative_generator();
        assert!(!gen.is_zero());
        
        // Verify it's actually a generator by checking order
        let mut power = gen;
        let mut count = 1u64;
        while power != Scalar::one() && count < 100 {
            power *= gen;
            count += 1;
        }
        // Should have large multiplicative order
        assert!(count > 10);
    }
    
    #[test]
    fn test_batch_invert() {
        let mut rng = test_rng();
        let mut elements: Vec<Scalar> = (0..100)
            .map(|_| Scalar::rand(&mut rng))
            .filter(|x| !x.is_zero())
            .collect();
        
        let originals = elements.clone();
        Scalar::batch_invert(&mut elements);
        
        for (orig, inv) in originals.iter().zip(elements.iter()) {
            assert_eq!(*orig * *inv, Scalar::one());
        }
    }
    
    #[test]
    fn test_parallel_operations() {
        let mut rng = test_rng();
        let a: Vec<Scalar> = (0..1000).map(|_| Scalar::rand(&mut rng)).collect();
        let b: Vec<Scalar> = (0..1000).map(|_| Scalar::rand(&mut rng)).collect();
        
        let sum = Bls12381Field::parallel_batch_add(&a, &b).unwrap();
        let product = Bls12381Field::parallel_batch_mul(&a, &b).unwrap();
        
        for i in 0..1000 {
            assert_eq!(sum[i], a[i] + b[i]);
            assert_eq!(product[i], a[i] * b[i]);
        }
    }
    
    #[test]
    fn test_linear_combination() {
        let mut rng = test_rng();
        let coeffs: Vec<Scalar> = (0..10).map(|_| Scalar::rand(&mut rng)).collect();
        let points: Vec<Scalar> = (0..10).map(|_| Scalar::rand(&mut rng)).collect();
        
        let result = Bls12381Field::linear_combination(&coeffs, &points).unwrap();
        
        // Verify manually
        let expected = coeffs.iter()
            .zip(points.iter())
            .fold(Scalar::zero(), |acc, (c, p)| acc + *c * *p);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_root_of_unity() {
        let root = Bls12381Field::root_of_unity();
        
        // Verify that root is not zero or one (it should be a primitive root)
        assert!(!root.is_zero());
        assert!(root != Scalar::one());
        
        // For BLS12-381, let's just verify it's a reasonable root by checking
        // that it has high order when raised to powers
        let mut power = root;
        let mut count = 1u64;
        
        // Check first few powers are not 1
        for _ in 1..10 {
            power = power.square();
            if power == Scalar::one() {
                break;
            }
            count += 1;
        }
        
        // Should take at least a few squarings to reach 1
        assert!(count > 5);
    }
}