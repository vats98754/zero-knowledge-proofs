//! Constraint system for range proofs
//!
//! This module implements the constraint system used in range proofs to ensure
//! that bit decomposition is valid and constraints are satisfied.

use bulletproofs_core::*;
use curve25519_dalek::{traits::VartimeMultiscalarMul, ristretto::RistrettoPoint};

/// Constraint system for enforcing range proof constraints
pub struct ConstraintSystem {
    /// Generators for left vector commitments
    pub g_generators: Vec<RistrettoPoint>,
    /// Generators for right vector commitments
    pub h_generators: Vec<RistrettoPoint>,
    /// Generator for inner product
    pub u_generator: RistrettoPoint,
    /// Number of bits in the range proof
    pub bit_length: usize,
}

impl ConstraintSystem {
    /// Create a new constraint system for the given bit length
    pub fn new(generators: &GeneratorSet, bit_length: usize) -> Self {
        // We need 2 * bit_length generators for the constraint system
        // - bit_length for bit values
        // - bit_length for constraint enforcement
        let required_generators = 2 * bit_length;
        
        // Get generators, extending if necessary
        let g_generators = if generators.vector_length() >= required_generators {
            generators.g_vec[..required_generators].to_vec()
        } else {
            // For this implementation, just repeat generators if we don't have enough
            let mut gens = Vec::with_capacity(required_generators);
            for i in 0..required_generators {
                gens.push(generators.g_vec[i % generators.g_vec.len()]);
            }
            gens
        };
        
        let h_generators = if generators.vector_length() >= required_generators {
            generators.h_vec[..required_generators].to_vec()
        } else {
            let mut gens = Vec::with_capacity(required_generators);
            for i in 0..required_generators {
                gens.push(generators.h_vec[i % generators.h_vec.len()]);
            }
            gens
        };
        
        Self {
            g_generators,
            h_generators,
            u_generator: generators.u,
            bit_length,
        }
    }

    /// Generate constraint vectors for bit decomposition
    /// Returns (a_vector, b_vector) where the constraints are:
    /// - a_i * b_i = 0 for binary constraint (b_i * (b_i - 1) = 0)
    /// - Sum constraint for value decomposition
    pub fn generate_constraint_vectors(&self, bits: &[Scalar], value: Scalar) -> (Vec<Scalar>, Vec<Scalar>) {
        let n = self.bit_length;
        let mut a_vector = Vec::with_capacity(2 * n);
        let mut b_vector = Vec::with_capacity(2 * n);

        // First n constraints: binary constraints b_i * (b_i - 1) = 0
        // We rewrite as: b_i * (b_i - 1) = b_i^2 - b_i = 0
        // Or: b_i * b_i - b_i * 1 = 0
        for i in 0..n {
            a_vector.push(bits[i]); // a_i = b_i
            b_vector.push(bits[i] - Scalar::ONE); // b_i = (b_i - 1)
        }

        // Second n constraints: powers of 2 for value reconstruction
        // Sum(b_i * 2^i) = value
        // We create constraint: (b_0, b_1, ..., b_{n-1}) · (2^0, 2^1, ..., 2^{n-1}) = value
        for i in 0..n {
            let power_of_two = {
                let mut power = Scalar::ONE;
                for _ in 0..i {
                    power = power + power; // Equivalent to power *= 2
                }
                power
            };
            a_vector.push(bits[i]); // bit values
            b_vector.push(power_of_two); // powers of 2
        }

        (a_vector, b_vector)
    }

    /// Generate commitment to the constraint vectors
    pub fn commit_to_vectors(
        &self,
        a_vector: &[Scalar],
        b_vector: &[Scalar],
        blinding: Scalar,
    ) -> Result<RistrettoPoint, BulletproofsError> {
        if a_vector.len() != 2 * self.bit_length || b_vector.len() != 2 * self.bit_length {
            return Err(BulletproofsError::InvalidParameters(
                "Vector length mismatch".to_string()
            ));
        }

        // Compute P = g^a * h^b * u^<a,b> where <a,b> is inner product
        let inner_product = inner_product(a_vector, b_vector);
        
        let mut scalars = Vec::with_capacity(2 * self.bit_length + 2);
        let mut points = Vec::with_capacity(2 * self.bit_length + 2);

        // Add g^a terms
        scalars.extend_from_slice(a_vector);
        points.extend_from_slice(&self.g_generators);

        // Add h^b terms
        scalars.extend_from_slice(b_vector);
        points.extend_from_slice(&self.h_generators);

        // Add u^<a,b> term
        scalars.push(inner_product);
        points.push(self.u_generator);

        // Add blinding term (we use the first h generator for blinding)
        if !self.h_generators.is_empty() {
            scalars.push(blinding);
            points.push(self.h_generators[0]);
        }

        Ok(RistrettoPoint::vartime_multiscalar_mul(&scalars, &points))
    }

    /// Verify that the constraint vectors satisfy the range proof constraints
    pub fn verify_constraints(
        &self,
        a_vector: &[Scalar],
        b_vector: &[Scalar],
        value: Scalar,
    ) -> Result<(), BulletproofsError> {
        if a_vector.len() != 2 * self.bit_length || b_vector.len() != 2 * self.bit_length {
            return Err(BulletproofsError::InvalidParameters(
                "Vector length mismatch".to_string()
            ));
        }

        let n = self.bit_length;

        // Check binary constraints: b_i * (b_i - 1) = 0 for i = 0..n
        for i in 0..n {
            let bit_value = a_vector[i];
            let constraint_value = b_vector[i];
            
            // Verify this is a valid bit (0 or 1)
            if bit_value != Scalar::ZERO && bit_value != Scalar::ONE {
                return Err(BulletproofsError::InvalidProof(
                    format!("Invalid bit value at position {}", i)
                ));
            }
            
            // Verify constraint: bit * (bit - 1) = 0
            if bit_value * constraint_value != Scalar::ZERO {
                return Err(BulletproofsError::InvalidProof(
                    format!("Binary constraint failed at position {}", i)
                ));
            }
        }

        // Check value reconstruction constraint
        let mut computed_value = Scalar::ZERO;
        for i in 0..n {
            let bit_value = a_vector[i];
            let power_of_two = b_vector[n + i];
            computed_value += bit_value * power_of_two;
        }

        if computed_value != value {
            return Err(BulletproofsError::InvalidProof(
                "Value reconstruction constraint failed".to_string()
            ));
        }

        Ok(())
    }
}

/// Compute inner product of two scalar vectors
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len(), "Vector lengths must match");
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).fold(Scalar::ZERO, |acc, x| acc + x)
}

/// Decompose a value into bits (little-endian)
pub fn bit_decompose(value: u64, bit_length: usize) -> Vec<Scalar> {
    let mut bits = Vec::with_capacity(bit_length);
    for i in 0..bit_length {
        let bit = (value >> i) & 1;
        bits.push(Scalar::from(bit));
    }
    bits
}

/// Compose bits back into a value (little-endian)
pub fn bit_compose(bits: &[Scalar]) -> u64 {
    let mut value = 0u64;
    for (i, bit) in bits.iter().enumerate() {
        if *bit == Scalar::ONE {
            value |= 1u64 << i;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_bit_decompose_compose() {
        let value = 42u64;
        let bit_length = 8;
        
        let bits = bit_decompose(value, bit_length);
        let recovered = bit_compose(&bits);
        
        assert_eq!(value, recovered);
        assert_eq!(bits.len(), bit_length);
    }

    #[test]
    fn test_inner_product() {
        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];
        
        let result = inner_product(&a, &b);
        let expected = Scalar::from(1u64 * 4u64 + 2u64 * 5u64 + 3u64 * 6u64); // 32
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_constraint_generation() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 8); // 4 bits * 2
        let bit_length = 4;
        let value = 5u64; // 0101 in binary
        
        let constraint_system = ConstraintSystem::new(&generators, bit_length);
        let bits = bit_decompose(value, bit_length);
        let value_scalar = Scalar::from(value);
        
        let (a_vector, b_vector) = constraint_system.generate_constraint_vectors(&bits, value_scalar);
        
        // Verify constraints
        assert!(constraint_system.verify_constraints(&a_vector, &b_vector, value_scalar).is_ok());
    }

    #[test]
    fn test_constraint_verification_fails_for_invalid_bits() {
        let mut rng = thread_rng();
        let generators = GeneratorSet::new(&mut rng, 8); // 4 bits * 2
        let bit_length = 4;
        
        let constraint_system = ConstraintSystem::new(&generators, bit_length);
        
        // Create invalid bit vector with value 2 (not 0 or 1)
        let mut invalid_bits = vec![Scalar::ZERO; bit_length];
        invalid_bits[0] = Scalar::from(2u64); // Invalid bit value
        
        let (a_vector, b_vector) = constraint_system.generate_constraint_vectors(&invalid_bits, Scalar::ZERO);
        
        // Should fail verification
        assert!(constraint_system.verify_constraints(&a_vector, &b_vector, Scalar::ZERO).is_err());
    }
}