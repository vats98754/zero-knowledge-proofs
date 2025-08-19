//! Utility functions for Bulletproofs operations

use crate::BulletproofsResult;
use curve25519_dalek::scalar::Scalar;

/// Compute powers of a scalar: [1, x, x^2, x^3, ..., x^(n-1)]
pub fn scalar_powers(x: &Scalar, n: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(n);
    let mut current = Scalar::ONE;
    
    for _ in 0..n {
        powers.push(current);
        current *= x;
    }
    
    powers
}

/// Compute the inner product of two scalar vectors
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> BulletproofsResult<Scalar> {
    if a.len() != b.len() {
        return Err(crate::BulletproofsError::VectorLengthMismatch {
            expected: a.len(),
            actual: b.len(),
        });
    }

    Ok(a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum())
}

/// Hadamard (element-wise) product of two scalar vectors
pub fn hadamard_product(a: &[Scalar], b: &[Scalar]) -> BulletproofsResult<Vec<Scalar>> {
    if a.len() != b.len() {
        return Err(crate::BulletproofsError::VectorLengthMismatch {
            expected: a.len(),
            actual: b.len(),
        });
    }

    Ok(a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).collect())
}

/// Add two scalar vectors element-wise
pub fn vector_add(a: &[Scalar], b: &[Scalar]) -> BulletproofsResult<Vec<Scalar>> {
    if a.len() != b.len() {
        return Err(crate::BulletproofsError::VectorLengthMismatch {
            expected: a.len(),
            actual: b.len(),
        });
    }

    Ok(a.iter().zip(b.iter()).map(|(ai, bi)| ai + bi).collect())
}

/// Subtract two scalar vectors element-wise: a - b
pub fn vector_sub(a: &[Scalar], b: &[Scalar]) -> BulletproofsResult<Vec<Scalar>> {
    if a.len() != b.len() {
        return Err(crate::BulletproofsError::VectorLengthMismatch {
            expected: a.len(),
            actual: b.len(),
        });
    }

    Ok(a.iter().zip(b.iter()).map(|(ai, bi)| ai - bi).collect())
}

/// Scale a vector by a scalar
pub fn vector_scale(vec: &[Scalar], scalar: &Scalar) -> Vec<Scalar> {
    vec.iter().map(|v| v * scalar).collect()
}

/// Construct the bit decomposition of a value
pub fn bit_decomposition(value: u64, bits: usize) -> Vec<Scalar> {
    let mut result = Vec::with_capacity(bits);
    let mut v = value;
    
    for _ in 0..bits {
        result.push(Scalar::from((v & 1) as u64));
        v >>= 1;
    }
    
    result
}

/// Verify that a vector represents a valid bit decomposition
pub fn verify_bit_vector(bits: &[Scalar]) -> bool {
    bits.iter().all(|bit| *bit == Scalar::ZERO || *bit == Scalar::ONE)
}

/// Compute the value represented by a bit vector (little-endian)
pub fn bits_to_value(bits: &[Scalar]) -> Option<u64> {
    if !verify_bit_vector(bits) || bits.len() > 64 {
        return None;
    }
    
    let mut value = 0u64;
    for (i, bit) in bits.iter().enumerate() {
        if *bit == Scalar::ONE {
            value |= 1u64 << i;
        }
    }
    
    Some(value)
}

/// Check if a number is a power of 2
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Find the next power of 2 greater than or equal to n
pub fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    
    let mut power = 1;
    while power < n {
        power <<= 1;
    }
    power
}

/// Pad a vector to the next power of 2 length with zeros
pub fn pad_to_power_of_two(mut vec: Vec<Scalar>) -> Vec<Scalar> {
    let target_len = next_power_of_two(vec.len());
    vec.resize(target_len, Scalar::ZERO);
    vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_powers() {
        let x = Scalar::from(3u64);
        let powers = scalar_powers(&x, 4);
        
        assert_eq!(powers.len(), 4);
        assert_eq!(powers[0], Scalar::ONE);
        assert_eq!(powers[1], Scalar::from(3u64));
        assert_eq!(powers[2], Scalar::from(9u64));
        assert_eq!(powers[3], Scalar::from(27u64));
    }

    #[test]
    fn test_inner_product() {
        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];
        
        let result = inner_product(&a, &b).unwrap();
        assert_eq!(result, Scalar::from(32u64)); // 1*4 + 2*5 + 3*6 = 32
    }

    #[test]
    fn test_hadamard_product() {
        let a = vec![Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64)];
        
        let result = hadamard_product(&a, &b).unwrap();
        assert_eq!(result, vec![Scalar::from(8u64), Scalar::from(15u64)]);
    }

    #[test]
    fn test_bit_decomposition() {
        let bits = bit_decomposition(13, 8); // 13 = 1101 in binary
        
        // Little-endian: [1, 0, 1, 1, 0, 0, 0, 0]
        assert_eq!(bits[0], Scalar::ONE);   // bit 0
        assert_eq!(bits[1], Scalar::ZERO);  // bit 1
        assert_eq!(bits[2], Scalar::ONE);   // bit 2
        assert_eq!(bits[3], Scalar::ONE);   // bit 3
        for i in 4..8 {
            assert_eq!(bits[i], Scalar::ZERO);
        }
    }

    #[test]
    fn test_bits_to_value() {
        let bits = vec![
            Scalar::ONE,   // bit 0
            Scalar::ZERO,  // bit 1  
            Scalar::ONE,   // bit 2
            Scalar::ONE,   // bit 3
        ];
        
        let value = bits_to_value(&bits).unwrap();
        assert_eq!(value, 13); // 1 + 4 + 8 = 13
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(8));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(5));
        assert!(!is_power_of_two(0));
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(8), 8);
    }

    #[test]
    fn test_pad_to_power_of_two() {
        let vec = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let padded = pad_to_power_of_two(vec);
        
        assert_eq!(padded.len(), 4);
        assert_eq!(padded[0], Scalar::from(1u64));
        assert_eq!(padded[1], Scalar::from(2u64));
        assert_eq!(padded[2], Scalar::from(3u64));
        assert_eq!(padded[3], Scalar::ZERO);
    }
}