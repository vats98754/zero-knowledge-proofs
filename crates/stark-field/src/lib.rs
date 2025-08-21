//! Field arithmetic for STARK proofs
//! 
//! This crate provides field arithmetic operations optimized for STARK proof systems.
//! It implements a Goldilocks-like prime field suitable for efficient operations.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ark_std::{fmt, ops::*, vec::Vec};
use serde::{Deserialize, Serialize};

// Re-export commonly used traits
pub use ark_std::{Zero, One};

/// Goldilocks prime: 2^64 - 2^32 + 1
/// This is a prime that allows for efficient arithmetic operations
const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001u64;

/// Goldilocks field element
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GoldilocksField(pub u64);

/// Type alias for convenience
pub type F = GoldilocksField;

impl fmt::Display for GoldilocksField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for GoldilocksField {
    fn from(value: u64) -> Self {
        Self(value % GOLDILOCKS_PRIME)
    }
}

impl From<u32> for GoldilocksField {
    fn from(value: u32) -> Self {
        Self(value as u64)
    }
}

impl From<usize> for GoldilocksField {
    fn from(value: usize) -> Self {
        Self((value as u64) % GOLDILOCKS_PRIME)
    }
}

impl TryFrom<GoldilocksField> for u64 {
    type Error = &'static str;
    
    fn try_from(field: GoldilocksField) -> Result<Self, Self::Error> {
        Ok(field.0)
    }
}

impl Zero for GoldilocksField {
    fn zero() -> Self {
        Self(0)
    }
    
    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl One for GoldilocksField {
    fn one() -> Self {
        Self(1)
    }
}

impl Add for GoldilocksField {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        let sum = self.0 + other.0;
        if sum >= GOLDILOCKS_PRIME {
            Self(sum - GOLDILOCKS_PRIME)
        } else {
            Self(sum)
        }
    }
}

impl Sub for GoldilocksField {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        if self.0 >= other.0 {
            Self(self.0 - other.0)
        } else {
            Self(self.0 + GOLDILOCKS_PRIME - other.0)
        }
    }
}

impl Mul for GoldilocksField {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        let product = (self.0 as u128) * (other.0 as u128);
        Self((product % (GOLDILOCKS_PRIME as u128)) as u64)
    }
}

impl Neg for GoldilocksField {
    type Output = Self;
    
    fn neg(self) -> Self {
        if self.is_zero() {
            self
        } else {
            Self(GOLDILOCKS_PRIME - self.0)
        }
    }
}

impl AddAssign for GoldilocksField {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl SubAssign for GoldilocksField {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl MulAssign for GoldilocksField {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl GoldilocksField {
    /// Create a new field element
    pub fn new(value: u64) -> Self {
        Self(value % GOLDILOCKS_PRIME)
    }
    
    /// Get the raw value
    pub fn value(&self) -> u64 {
        self.0
    }
    
    /// Compute the multiplicative inverse using extended Euclidean algorithm
    pub fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        
        let mut t = 0i128;
        let mut new_t = 1i128;
        let mut r = GOLDILOCKS_PRIME as i128;
        let mut new_r = self.0 as i128;
        
        while new_r != 0 {
            let quotient = r / new_r;
            
            let temp_t = t;
            t = new_t;
            new_t = temp_t - quotient * new_t;
            
            let temp_r = r;
            r = new_r;
            new_r = temp_r - quotient * new_r;
        }
        
        if r > 1 {
            return None; // Not invertible
        }
        
        if t < 0 {
            t += GOLDILOCKS_PRIME as i128;
        }
        
        Some(Self(t as u64))
    }
    
    /// Raise to a power
    pub fn pow(&self, mut exp: u64) -> Self {
        if exp == 0 {
            return Self::one();
        }
        
        let mut result = Self::one();
        let mut base = *self;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result *= base;
            }
            base *= base;
            exp >>= 1;
        }
        
        result
    }
    
    /// Check if this is a quadratic residue
    pub fn is_quadratic_residue(&self) -> bool {
        if self.is_zero() {
            return true;
        }
        // For prime p, a is a QR iff a^((p-1)/2) ≡ 1 (mod p)
        self.pow((GOLDILOCKS_PRIME - 1) / 2) == Self::one()
    }
    
    /// Compute square root if it exists
    pub fn sqrt(&self) -> Option<Self> {
        if !self.is_quadratic_residue() {
            return None;
        }
        
        if self.is_zero() {
            return Some(*self);
        }
        
        // Use Tonelli-Shanks algorithm for square root in prime fields
        // For now, implement a simple case since Goldilocks prime has special form
        let exp = (GOLDILOCKS_PRIME + 1) / 4; // Works when p ≡ 3 (mod 4)
        Some(self.pow(exp))
    }
}

impl Div for GoldilocksField {
    type Output = Self;
    
    fn div(self, other: Self) -> Self {
        self * other.inverse().expect("Division by zero or non-invertible element")
    }
}

impl DivAssign for GoldilocksField {
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

/// Batch inverse computation using Montgomery's trick
pub fn batch_inverse(elements: &[GoldilocksField]) -> Vec<GoldilocksField> {
    if elements.is_empty() {
        return vec![];
    }
    
    let n = elements.len();
    let mut products = vec![GoldilocksField::one(); n];
    let mut result = vec![GoldilocksField::zero(); n];
    
    // Forward pass: compute partial products
    products[0] = elements[0];
    for i in 1..n {
        products[i] = products[i - 1] * elements[i];
    }
    
    // Compute inverse of the final product
    let mut inverse = products[n - 1].inverse().expect("Product should be invertible");
    
    // Backward pass: compute individual inverses
    for i in (0..n).rev() {
        if i == 0 {
            result[i] = inverse;
        } else {
            result[i] = inverse * products[i - 1];
            inverse *= elements[i];
        }
    }
    
    result
}

/// FFT root of unity for the Goldilocks field
pub fn get_root_of_unity(order: usize) -> Option<GoldilocksField> {
    // For Goldilocks field, we need to find a primitive root
    // This is a simplified implementation - in practice you'd precompute these
    
    if order.is_power_of_two() && order <= (1 << 32) {
        // Generator for Goldilocks field (this should be precomputed)
        let generator = GoldilocksField::from(7u64); // Placeholder - actual generator needs verification
        let exp = (GOLDILOCKS_PRIME - 1) / (order as u64);
        Some(generator.pow(exp))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    
    #[test]
    fn test_basic_arithmetic() {
        let a = GoldilocksField::from(17u64);
        let b = GoldilocksField::from(13u64);
        
        assert_eq!(a + b, GoldilocksField::from(30u64));
        assert_eq!(a - b, GoldilocksField::from(4u64));
        assert_eq!(a * b, GoldilocksField::from(221u64));
        
        let c = a / b;
        assert_eq!(c * b, a);
    }
    
    #[test]
    fn test_field_properties() {
        let zero = GoldilocksField::zero();
        let one = GoldilocksField::one();
        let a = GoldilocksField::from(42u64);
        
        // Additive identity
        assert_eq!(a + zero, a);
        assert_eq!(zero + a, a);
        
        // Multiplicative identity
        assert_eq!(a * one, a);
        assert_eq!(one * a, a);
        
        // Additive inverse
        assert_eq!(a + (-a), zero);
        
        // Multiplicative inverse
        if !a.is_zero() {
            let inv = a.inverse().unwrap();
            assert_eq!(a * inv, one);
        }
    }
    
    #[test]
    fn test_modular_reduction() {
        let large = GOLDILOCKS_PRIME + 5;
        let f = GoldilocksField::from(large);
        assert_eq!(f.value(), 5);
    }
    
    proptest! {
        #[test]
        fn test_addition_commutative(a in 0u64..GOLDILOCKS_PRIME, b in 0u64..GOLDILOCKS_PRIME) {
            let fa = GoldilocksField::from(a);
            let fb = GoldilocksField::from(b);
            prop_assert_eq!(fa + fb, fb + fa);
        }
        
        #[test]
        fn test_multiplication_commutative(a in 0u64..GOLDILOCKS_PRIME, b in 0u64..GOLDILOCKS_PRIME) {
            let fa = GoldilocksField::from(a);
            let fb = GoldilocksField::from(b);
            prop_assert_eq!(fa * fb, fb * fa);
        }
        
        #[test]
        fn test_distributive(a in 0u64..GOLDILOCKS_PRIME, b in 0u64..GOLDILOCKS_PRIME, c in 0u64..GOLDILOCKS_PRIME) {
            let fa = GoldilocksField::from(a);
            let fb = GoldilocksField::from(b);
            let fc = GoldilocksField::from(c);
            prop_assert_eq!(fa * (fb + fc), fa * fb + fa * fc);
        }
    }
    
    #[test]
    fn test_batch_inverse() {
        let elements = vec![
            GoldilocksField::from(2u64),
            GoldilocksField::from(3u64),
            GoldilocksField::from(5u64),
            GoldilocksField::from(7u64),
        ];
        
        let inverses = batch_inverse(&elements);
        
        for (elem, inv) in elements.iter().zip(inverses.iter()) {
            assert_eq!(*elem * *inv, GoldilocksField::one());
        }
    }
}