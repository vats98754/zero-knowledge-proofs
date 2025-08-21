//! Field operations and traits for Groth16 zk-SNARK implementation.
//! 
//! This crate provides the field arithmetic foundation using BLS12-381 scalar field
//! and defines the `FieldLike` trait for field operations.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ark_ff::{Field, PrimeField, Zero, One};
use ark_bls12_381::Fr as Bls12381Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fmt::{Debug, Display};

pub use ark_bls12_381::Fr;

/// Alias for the default field used in Groth16 implementation: BLS12-381 scalar field
pub type F = Bls12381Fr;

/// Trait representing field-like operations needed for Groth16
/// 
/// This trait provides a convenient abstraction over arkworks field operations
/// and ensures compatibility with our constraint system and polynomial operations.
pub trait FieldLike: 
    Field + 
    PrimeField +
    CanonicalSerialize + 
    CanonicalDeserialize + 
    Debug + 
    Display + 
    Send + 
    Sync + 
    'static 
{
    /// Returns the zero element of the field
    fn zero() -> Self {
        <Self as Zero>::zero()
    }
    
    /// Returns the one element of the field  
    fn one() -> Self {
        <Self as One>::one()
    }
    
    /// Check if the element is zero
    fn is_zero(&self) -> bool {
        <Self as Zero>::is_zero(self)
    }
    
    /// Check if the element is one
    fn is_one(&self) -> bool {
        <Self as One>::is_one(self)
    }
    
    /// Compute the multiplicative inverse
    fn inverse(&self) -> Option<Self> {
        <Self as Field>::inverse(self)
    }
    
    /// Generate a random field element
    fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self::rand(rng)
    }
    
    /// Convert from a u64 value
    fn from_u64(val: u64) -> Self {
        Self::from(val)
    }
    
    /// Raise to a power (using square-and-multiply)
    fn pow<T: AsRef<[u64]>>(&self, exp: T) -> Self {
        <Self as Field>::pow(self, exp.as_ref())
    }
}

// Implement FieldLike for the BLS12-381 scalar field
impl FieldLike for Bls12381Fr {}

/// Field element operations for vectors and slices
pub trait FieldVec<F: FieldLike> {
    /// Compute the inner product of two field vectors
    fn inner_product(&self, other: &[F]) -> Result<F, FieldError>;
    
    /// Scalar multiplication of a vector
    fn scalar_mul(&self, scalar: &F) -> Vec<F>;
    
    /// Add two field vectors element-wise
    fn add_vec(&self, other: &[F]) -> Result<Vec<F>, FieldError>;
}

impl<F: FieldLike> FieldVec<F> for [F] {
    fn inner_product(&self, other: &[F]) -> Result<F, FieldError> {
        if self.len() != other.len() {
            return Err(FieldError::DimensionMismatch { 
                left: self.len(), 
                right: other.len() 
            });
        }
        
        let mut result = <F as FieldLike>::zero();
        for (a, b) in self.iter().zip(other.iter()) {
            result += *a * *b;
        }
        Ok(result)
    }
    
    fn scalar_mul(&self, scalar: &F) -> Vec<F> {
        self.iter().map(|x| *x * scalar).collect()
    }
    
    fn add_vec(&self, other: &[F]) -> Result<Vec<F>, FieldError> {
        if self.len() != other.len() {
            return Err(FieldError::DimensionMismatch { 
                left: self.len(), 
                right: other.len() 
            });
        }
        
        Ok(self.iter().zip(other.iter()).map(|(a, b)| *a + *b).collect())
    }
}

/// Errors that can occur in field operations
#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    /// Dimension mismatch in vector operations
    #[error("Dimension mismatch: left has {left} elements, right has {right} elements")]
    DimensionMismatch { 
        /// Number of elements in left vector
        left: usize, 
        /// Number of elements in right vector
        right: usize 
    },
    
    /// Invalid field element
    #[error("Invalid field element")]
    InvalidElement,
    
    /// Division by zero
    #[error("Division by zero")]
    DivisionByZero,
}

/// Utility functions for field operations
pub mod utils {
    use super::*;
    
    /// Generate a vector of random field elements
    pub fn random_field_vec<F: FieldLike, R: rand::Rng + ?Sized>(
        size: usize, 
        rng: &mut R
    ) -> Vec<F> {
        (0..size).map(|_| F::random(rng)).collect()
    }
    
    /// Create a vector from a slice of u64 values
    pub fn field_vec_from_u64<F: FieldLike>(values: &[u64]) -> Vec<F> {
        values.iter().map(|&x| F::from_u64(x)).collect()
    }
    
    /// Evaluate a polynomial at a given point using Horner's method
    pub fn evaluate_polynomial<F: FieldLike>(coeffs: &[F], point: &F) -> F {
        if coeffs.is_empty() {
            return <F as FieldLike>::zero();
        }
        
        let mut result = coeffs[coeffs.len() - 1];
        for coeff in coeffs.iter().rev().skip(1) {
            result = result * point + coeff;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn test_field_basic_operations() {
        let a = F::from(5u64);
        let b = F::from(3u64);
        
        assert_eq!(a + b, F::from(8u64));
        assert_eq!(a * b, F::from(15u64));
        assert_eq!(a - b, F::from(2u64));
        
        assert!(!<F as FieldLike>::is_zero(&a));
        assert!(<F as FieldLike>::is_zero(&<F as FieldLike>::zero()));
        assert!(<F as FieldLike>::is_one(&<F as FieldLike>::one()));
    }
    
    #[test]
    fn test_field_inverse() {
        let a = F::from(5u64);
        let inv_a = <F as FieldLike>::inverse(&a).unwrap();
        assert_eq!(a * inv_a, <F as FieldLike>::one());
    }
    
    #[test]
    fn test_vector_operations() {
        let a = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        let b = vec![F::from(4u64), F::from(5u64), F::from(6u64)];
        
        // Inner product: 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        let inner = a.inner_product(&b).unwrap();
        assert_eq!(inner, F::from(32u64));
        
        // Scalar multiplication
        let scalar = F::from(2u64);
        let scaled = a.scalar_mul(&scalar);
        assert_eq!(scaled, vec![F::from(2u64), F::from(4u64), F::from(6u64)]);
    }
    
    #[test]
    fn test_random_field_elements() {
        let mut rng = thread_rng();
        let random_vec = utils::random_field_vec::<F, _>(10, &mut rng);
        assert_eq!(random_vec.len(), 10);
        
        // Check that elements are likely different (very low probability of collision)
        let all_same = random_vec.iter().all(|&x| x == random_vec[0]);
        assert!(!all_same);
    }
    
    #[test]
    fn test_polynomial_evaluation() {
        // Test polynomial 2x^2 + 3x + 1 at x = 2
        // Expected: 2*4 + 3*2 + 1 = 8 + 6 + 1 = 15
        let coeffs = vec![F::from(1u64), F::from(3u64), F::from(2u64)]; // constant term first
        let point = F::from(2u64);
        let result = utils::evaluate_polynomial(&coeffs, &point);
        assert_eq!(result, F::from(15u64));
    }
}