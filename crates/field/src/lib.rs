//! Field arithmetic for PLONK using BLS12-381 scalar field
//!
//! This crate provides a clean interface for field operations in PLONK,
//! built on top of the arkworks BLS12-381 scalar field implementation.

use ark_bls12_381::Fr as ArkFr;
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::*, rand::Rng, vec::Vec, Zero, One};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The scalar field element used in PLONK
/// This is a wrapper around arkworks BLS12-381 scalar field
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct PlonkField(pub ArkFr);

impl PlonkField {
    /// Create a new field element from an ark_bls12_381::Fr
    pub fn new(f: ArkFr) -> Self {
        Self(f)
    }

    /// Create a random field element
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Self(ArkFr::rand(rng))
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FieldError> {
        let field = ArkFr::deserialize_compressed(&mut &bytes[..])
            .map_err(|_| FieldError::InvalidBytes)?;
        Ok(Self(field))
    }

    /// Convert to the underlying arkworks field element
    pub fn inner(&self) -> ArkFr {
        self.0
    }

    /// Create from a u64 value
    pub fn from_u64(val: u64) -> Self {
        Self(ArkFr::from(val))
    }

    /// Check if this is zero
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Check if this is one
    pub fn is_one(&self) -> bool {
        self.0.is_one()
    }

    /// Compute the multiplicative inverse
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Self)
    }

    /// Raise to a power
    pub fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        Self(self.0.pow(exp))
    }

    /// Square the element
    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    /// Double the element
    pub fn double(&self) -> Self {
        Self(self.0.double())
    }
}

/// Error types for field operations
#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    #[error("Invalid bytes for field element")]
    InvalidBytes,
    #[error("Division by zero")]
    DivisionByZero,
}

// Implement standard traits for PlonkField

impl Default for PlonkField {
    fn default() -> Self {
        Self(ArkFr::zero())
    }
}

impl Zero for PlonkField {
    fn zero() -> Self {
        Self(ArkFr::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl One for PlonkField {
    fn one() -> Self {
        Self(ArkFr::one())
    }

    fn is_one(&self) -> bool {
        self.0.is_one()
    }
}

impl From<u64> for PlonkField {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl From<ArkFr> for PlonkField {
    fn from(f: ArkFr) -> Self {
        Self(f)
    }
}

impl From<PlonkField> for ArkFr {
    fn from(f: PlonkField) -> Self {
        f.0
    }
}

// Custom serde implementation
impl Serialize for PlonkField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PlonkField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

// Arithmetic operations

impl Add for PlonkField {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl AddAssign for PlonkField {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl Sub for PlonkField {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl SubAssign for PlonkField {
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl Mul for PlonkField {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl MulAssign for PlonkField {
    fn mul_assign(&mut self, other: Self) {
        self.0 *= other.0;
    }
}

impl Div for PlonkField {
    type Output = Result<Self, FieldError>;

    fn div(self, other: Self) -> Self::Output {
        if other.is_zero() {
            Err(FieldError::DivisionByZero)
        } else {
            Ok(Self(self.0 / other.0))
        }
    }
}

impl Neg for PlonkField {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}

/// A polynomial over the PLONK field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    /// Coefficients of the polynomial in ascending order of powers
    /// coeffs[i] is the coefficient of x^i
    pub coeffs: Vec<PlonkField>,
}

impl Polynomial {
    /// Create a new polynomial from coefficients
    pub fn new(coeffs: Vec<PlonkField>) -> Self {
        Self { coeffs }
    }

    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self { coeffs: vec![] }
    }

    /// Create a constant polynomial
    pub fn constant(c: PlonkField) -> Self {
        if c.is_zero() {
            Self::zero()
        } else {
            Self { coeffs: vec![c] }
        }
    }

    /// Get the degree of the polynomial (-1 for zero polynomial)
    pub fn degree(&self) -> isize {
        if self.coeffs.is_empty() {
            -1
        } else {
            (self.coeffs.len() - 1) as isize
        }
    }

    /// Evaluate the polynomial at a given point
    pub fn evaluate(&self, x: PlonkField) -> PlonkField {
        if self.coeffs.is_empty() {
            PlonkField::zero()
        } else {
            // Horner's method for efficient evaluation
            let mut result = *self.coeffs.last().unwrap();
            for coeff in self.coeffs.iter().rev().skip(1) {
                result = result * x + *coeff;
            }
            result
        }
    }

    /// Trim leading zeros
    pub fn trim(&mut self) {
        while !self.coeffs.is_empty() && self.coeffs.last().unwrap().is_zero() {
            self.coeffs.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_field_arithmetic() {
        let mut rng = test_rng();
        let a = PlonkField::random(&mut rng);
        let b = PlonkField::random(&mut rng);

        // Test basic arithmetic
        let sum = a + b;
        let diff = a - b;
        let prod = a * b;

        assert_eq!(sum - b, a);
        assert_eq!(diff + b, a);
        assert_eq!(prod * b.inverse().unwrap(), a);
    }

    #[test]
    fn test_field_constants() {
        let zero = PlonkField::zero();
        let one = PlonkField::one();

        assert!(zero.is_zero());
        assert!(one.is_one());
        assert_eq!(zero + one, one);
        assert_eq!(one * one, one);
    }

    #[test]
    fn test_polynomial_evaluation() {
        // Test polynomial: 2x^2 + 3x + 1
        let poly = Polynomial::new(vec![
            PlonkField::one(),              // x^0 coefficient
            PlonkField::from_u64(3),       // x^1 coefficient  
            PlonkField::from_u64(2),       // x^2 coefficient
        ]);

        let x = PlonkField::from_u64(5);
        let expected = PlonkField::from_u64(2) * x.square() + PlonkField::from_u64(3) * x + PlonkField::one();
        assert_eq!(poly.evaluate(x), expected);
    }

    #[test]
    fn test_serialization() {
        let mut rng = test_rng();
        let field = PlonkField::random(&mut rng);
        
        let bytes = field.to_bytes();
        let recovered = PlonkField::from_bytes(&bytes).unwrap();
        
        assert_eq!(field, recovered);
    }
}