//! Generator management and precomputation for optimized multi-scalar multiplication

use crate::{BulletproofsError, BulletproofsResult, GroupElement};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

/// Generator set for Bulletproofs operations
#[derive(Debug, Clone)]
pub struct GeneratorSet {
    /// Primary generator G
    pub g: RistrettoPoint,
    /// Secondary generator H  
    pub h: RistrettoPoint,
    /// Vector generators for left side
    pub g_vec: Vec<RistrettoPoint>,
    /// Vector generators for right side
    pub h_vec: Vec<RistrettoPoint>,
    /// Generator for inner product
    pub u: RistrettoPoint,
    /// Precomputed tables for fast MSM (optional optimization)
    precomputed_tables: Option<HashMap<usize, PrecomputedTable>>,
}

/// Precomputed table for fast multi-scalar multiplication
#[derive(Debug, Clone)]
struct PrecomputedTable {
    // In a production implementation, this would contain
    // precomputed combinations of generators for windowed MSM
    generators: Vec<RistrettoPoint>,
    window_size: usize,
}

impl GeneratorSet {
    /// Hash arbitrary bytes to a RistrettoPoint (deterministic)
    fn hash_to_point(data: &[u8]) -> RistrettoPoint {
        let mut hasher = Sha256::new();
        hasher.update(b"bulletproofs_generator_");
        hasher.update(data);
        let hash = hasher.finalize();
        
        // Create a 64-byte array from the hash by repeating it
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&hash);
        bytes[32..].copy_from_slice(&hash);
        
        RistrettoPoint::from_uniform_bytes(&bytes)
    }

    /// Create a new generator set with the specified vector length
    pub fn new<R: RngCore + CryptoRng>(_rng: R, vector_length: usize) -> Self {
        // Use standard Ristretto basepoint as G
        let g = RISTRETTO_BASEPOINT_POINT;
        
        // Generate H deterministically from G
        let h = Self::hash_to_point(b"bulletproofs_h_generator");
        
        // Generate vector generators deterministically
        let mut g_vec = Vec::with_capacity(vector_length);
        let mut h_vec = Vec::with_capacity(vector_length);
        
        for i in 0..vector_length {
            let g_label = format!("bulletproofs_g_{}", i);
            let h_label = format!("bulletproofs_h_{}", i);
            
            g_vec.push(Self::hash_to_point(g_label.as_bytes()));
            h_vec.push(Self::hash_to_point(h_label.as_bytes()));
        }
        
        // Generate U for inner product
        let u = Self::hash_to_point(b"bulletproofs_u_generator");
        
        Self {
            g,
            h,
            g_vec,
            h_vec,
            u,
            precomputed_tables: None,
        }
    }

    /// Get the vector length
    pub fn vector_length(&self) -> usize {
        self.g_vec.len()
    }

    /// Get the G generator (used for value commitments)
    pub fn g_generator(&self) -> GroupElement {
        GroupElement::from(self.g)
    }

    /// Get the H generator (used for blinding factor commitments)
    pub fn h_generator(&self) -> GroupElement {
        GroupElement::from(self.h)
    }

    /// Get the U generator (used for inner product commitments)
    pub fn u_generator(&self) -> GroupElement {
        GroupElement::from(self.u)
    }

    /// Get a slice of the G vector generators
    pub fn g_vec(&self) -> &[RistrettoPoint] {
        &self.g_vec
    }

    /// Get a slice of the H vector generators
    pub fn h_vec(&self) -> &[RistrettoPoint] {
        &self.h_vec
    }

    /// Ensure we have enough generators for the given length
    pub fn ensure_capacity<R: RngCore + CryptoRng>(&mut self, _rng: R, length: usize) -> BulletproofsResult<()> {
        if self.vector_length() >= length {
            return Ok(());
        }

        // Extend generator vectors
        let current_len = self.vector_length();
        for i in current_len..length {
            let g_label = format!("bulletproofs_g_{}", i);
            let h_label = format!("bulletproofs_h_{}", i);
            
            self.g_vec.push(Self::hash_to_point(g_label.as_bytes()));
            self.h_vec.push(Self::hash_to_point(h_label.as_bytes()));
        }

        // Invalidate precomputed tables since generators changed
        self.precomputed_tables = None;
        
        Ok(())
    }

    /// Compute vector commitment: g^a * h^b where a, b are vectors
    pub fn vector_commit(&self, a: &[Scalar], b: &[Scalar]) -> BulletproofsResult<GroupElement> {
        if a.len() != b.len() {
            return Err(BulletproofsError::VectorLengthMismatch {
                expected: a.len(),
                actual: b.len(),
            });
        }

        if a.len() > self.vector_length() {
            return Err(BulletproofsError::InsufficientGenerators {
                needed: a.len(),
                available: self.vector_length(),
            });
        }

        // Compute g^a * h^b using multi-scalar multiplication
        let scalars = a.iter().chain(b.iter()).cloned();
        let points = self.g_vec[..a.len()].iter().chain(self.h_vec[..b.len()].iter()).cloned();
        
        Ok(GroupElement::multiscalar_mul(scalars, points))
    }

    /// Compute inner product commitment: g^a * h^b * u^<a,b>
    pub fn inner_product_commit(&self, a: &[Scalar], b: &[Scalar]) -> BulletproofsResult<GroupElement> {
        let vector_commit = self.vector_commit(a, b)?;
        
        // Compute inner product <a,b>
        let inner_product = a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum::<Scalar>();
        
        Ok(vector_commit + GroupElement::from(self.u * inner_product))
    }

    /// Precompute tables for fast MSM (optimization)
    pub fn precompute_tables(&mut self, window_size: usize) {
        // In a production implementation, this would precompute
        // windowed combinations of generators for faster MSM
        // For now, we'll store a simplified version
        
        let mut tables = HashMap::new();
        
        // Create table for g_vec
        if !self.g_vec.is_empty() {
            tables.insert(0, PrecomputedTable {
                generators: self.g_vec.clone(),
                window_size,
            });
        }
        
        // Create table for h_vec  
        if !self.h_vec.is_empty() {
            tables.insert(1, PrecomputedTable {
                generators: self.h_vec.clone(),
                window_size,
            });
        }
        
        self.precomputed_tables = Some(tables);
    }
    
    /// Create a subset of generators with the specified length
    pub fn subset(&self, length: usize) -> BulletproofsResult<GeneratorSet> {
        if length > self.vector_length() {
            return Err(BulletproofsError::InsufficientGenerators {
                needed: length,
                available: self.vector_length(),
            });
        }
        
        Ok(GeneratorSet {
            g: self.g,
            h: self.h,
            g_vec: self.g_vec[..length].to_vec(),
            h_vec: self.h_vec[..length].to_vec(),
            u: self.u,
            precomputed_tables: None,
        })
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_generator_set_creation() {
        let generators = GeneratorSet::new(OsRng, 8);
        assert_eq!(generators.vector_length(), 8);
        assert_eq!(generators.g_vec.len(), 8);
        assert_eq!(generators.h_vec.len(), 8);
    }

    #[test]
    fn test_vector_commit() {
        let generators = GeneratorSet::new(OsRng, 4);
        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
        let b = vec![Scalar::from(5u64), Scalar::from(6u64), Scalar::from(7u64), Scalar::from(8u64)];
        
        let commitment = generators.vector_commit(&a, &b).unwrap();
        
        // Verify it's not the identity (basic sanity check)
        assert_ne!(commitment.0, RistrettoPoint::identity());
    }

    #[test]
    fn test_inner_product_commit() {
        let generators = GeneratorSet::new(OsRng, 2);
        let a = vec![Scalar::from(3u64), Scalar::from(4u64)];
        let b = vec![Scalar::from(5u64), Scalar::from(6u64)];
        
        let commitment = generators.inner_product_commit(&a, &b).unwrap();
        
        // Manually compute expected: g_0^3 * g_1^4 * h_0^5 * h_1^6 * u^(3*5 + 4*6)
        let expected_inner_product = Scalar::from(3u64 * 5u64 + 4u64 * 6u64); // 39
        let expected = GroupElement::multiscalar_mul(
            [Scalar::from(3u64), Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64), expected_inner_product],
            [generators.g_vec[0], generators.g_vec[1], generators.h_vec[0], generators.h_vec[1], generators.u]
        );
        
        assert_eq!(commitment, expected);
    }
}