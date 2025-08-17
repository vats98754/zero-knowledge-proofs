//! # Zero-Knowledge Proof Field Operations
//!
//! This crate provides efficient field arithmetic and polynomial operations
//! optimized for zero-knowledge proof systems, particularly Marlin and Sonic.
//!
//! ## Features
//!
//! - BLS12-381 scalar field operations
//! - Optimized polynomial arithmetic with FFT
//! - Batch operations for improved performance
//! - Thread-safe parallel operations

pub mod bls12_381;
pub mod polynomial;
pub mod fft;
pub mod batch;

use ark_ff::Field;
use ark_bls12_381::Fr as Bls12381Fr;

/// The scalar field used in BLS12-381 curve
pub type Scalar = Bls12381Fr;

/// Trait for field operations required by zero-knowledge proof systems
pub trait ZkField: Field + Send + Sync {
    /// Returns the multiplicative generator of the field
    fn multiplicative_generator() -> Self;
    
    /// Returns a random field element
    fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self;
    
    /// Performs batch inversion of field elements
    fn batch_invert(elements: &mut [Self]);
}

/// Error types for field operations
#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    #[error("Invalid field element")]
    InvalidElement,
    #[error("Division by zero")]
    DivisionByZero,
    #[error("FFT size must be a power of two")]
    InvalidFftSize,
    #[error("Polynomial degree mismatch")]
    DegreeMismatch,
}

pub type Result<T> = std::result::Result<T, FieldError>;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::{Zero, One, UniformRand, Field};
    
    #[test]
    fn test_field_basic_ops() {
        let mut rng = test_rng();
        let a = Scalar::rand(&mut rng);
        let b = Scalar::rand(&mut rng);
        
        // Test basic arithmetic
        let sum = a + b;
        let diff = a - b;
        let prod = a * b;
        
        // Verify properties
        assert_eq!(a + b, b + a); // Commutativity
        assert_eq!(a * b, b * a); // Commutativity
        
        if !b.is_zero() {
            let quotient = a / b;
            assert_eq!(quotient * b, a); // Division correctness
        }
    }
}