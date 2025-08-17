//! Inner Product Argument proof structure

use bulletproofs_core::{GroupElement, BulletproofsResult, BulletproofsError};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use serde::{Deserialize, Serialize};

/// An inner product argument proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerProductProof {
    /// L values from each folding round (log_2(n) elements)
    pub l_vec: Vec<CompressedRistretto>,
    /// R values from each folding round (log_2(n) elements)
    pub r_vec: Vec<CompressedRistretto>,
    /// Final scalar value a
    pub a: Scalar,
    /// Final scalar value b
    pub b: Scalar,
}

impl InnerProductProof {
    /// Create a new inner product proof
    pub fn new(l_vec: Vec<GroupElement>, r_vec: Vec<GroupElement>, a: Scalar, b: Scalar) -> Self {
        Self {
            l_vec: l_vec.iter().map(|p| p.compress()).collect(),
            r_vec: r_vec.iter().map(|p| p.compress()).collect(),
            a,
            b,
        }
    }

    /// Get the number of folding rounds
    pub fn num_rounds(&self) -> usize {
        self.l_vec.len()
    }

    /// Validate proof structure
    pub fn validate_structure(&self) -> BulletproofsResult<()> {
        if self.l_vec.len() != self.r_vec.len() {
            return Err(BulletproofsError::InvalidProof(
                "L and R vectors must have the same length".to_string(),
            ));
        }

        // Empty L/R vectors are valid for base case (vector length 1)
        Ok(())
    }

    /// Decompress L values
    pub fn decompress_l_vec(&self) -> BulletproofsResult<Vec<GroupElement>> {
        self.l_vec
            .iter()
            .map(|compressed| GroupElement::from_compressed(compressed))
            .collect()
    }

    /// Decompress R values
    pub fn decompress_r_vec(&self) -> BulletproofsResult<Vec<GroupElement>> {
        self.r_vec
            .iter()
            .map(|compressed| GroupElement::from_compressed(compressed))
            .collect()
    }

    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        // Each compressed point is 32 bytes, each scalar is 32 bytes
        self.l_vec.len() * 32 + self.r_vec.len() * 32 + 64
    }

    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Write number of rounds
        result.extend_from_slice(&(self.l_vec.len() as u32).to_le_bytes());
        
        // Write L points
        for point in &self.l_vec {
            result.extend_from_slice(point.as_bytes());
        }
        
        // Write R points
        for point in &self.r_vec {
            result.extend_from_slice(point.as_bytes());
        }
        
        // Write scalars a and b
        result.extend_from_slice(self.a.as_bytes());
        result.extend_from_slice(self.b.as_bytes());
        
        result
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> BulletproofsResult<Self> {
        if bytes.len() < 4 {
            return Err(BulletproofsError::InvalidProof("Insufficient bytes for proof".to_string()));
        }

        let mut offset = 0;
        
        // Read number of rounds
        let num_rounds = u32::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]
        ]) as usize;
        offset += 4;

        let expected_size = 4 + num_rounds * 64 + 64; // 4 + 2*rounds*32 + 2*32
        if bytes.len() != expected_size {
            return Err(BulletproofsError::InvalidProof(
                format!("Invalid proof size: expected {}, got {}", expected_size, bytes.len())
            ));
        }

        // Read L points
        let mut l_vec = Vec::with_capacity(num_rounds);
        for _ in 0..num_rounds {
            let point_bytes: [u8; 32] = bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| BulletproofsError::InvalidProof("Invalid point bytes".to_string()))?;
            l_vec.push(CompressedRistretto::from_slice(&point_bytes).unwrap());
            offset += 32;
        }

        // Read R points
        let mut r_vec = Vec::with_capacity(num_rounds);
        for _ in 0..num_rounds {
            let point_bytes: [u8; 32] = bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| BulletproofsError::InvalidProof("Invalid point bytes".to_string()))?;
            r_vec.push(CompressedRistretto::from_slice(&point_bytes).unwrap());
            offset += 32;
        }

        // Read scalar a
        let a_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| BulletproofsError::InvalidProof("Invalid scalar a".to_string()))?;
        let a = Scalar::from_bytes_mod_order(a_bytes);
        offset += 32;

        // Read scalar b
        let b_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| BulletproofsError::InvalidProof("Invalid scalar b".to_string()))?;
        let b = Scalar::from_bytes_mod_order(b_bytes);

        Ok(Self { l_vec, r_vec, a, b })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, traits::Identity};

    #[test]
    fn test_proof_creation() {
        let l_vec = vec![GroupElement::from(RistrettoPoint::identity())];
        let r_vec = vec![GroupElement::from(RistrettoPoint::identity())];
        let a = Scalar::from(42u64);
        let b = Scalar::from(37u64);

        let proof = InnerProductProof::new(l_vec, r_vec, a, b);

        assert_eq!(proof.num_rounds(), 1);
        assert_eq!(proof.a, a);
        assert_eq!(proof.b, b);
    }

    #[test]
    fn test_proof_validation() {
        let l_vec = vec![GroupElement::from(RistrettoPoint::identity())];
        let r_vec = vec![GroupElement::from(RistrettoPoint::identity())];
        let proof = InnerProductProof::new(l_vec, r_vec, Scalar::from(1u64), Scalar::from(2u64));

        assert!(proof.validate_structure().is_ok());
    }

    #[test]
    fn test_invalid_proof_structure() {
        // Test mismatched L and R vector lengths
        let proof = InnerProductProof {
            l_vec: vec![CompressedRistretto::default()],
            r_vec: vec![], // Different length
            a: Scalar::from(1u64),
            b: Scalar::from(2u64),
        };

        assert!(proof.validate_structure().is_err());
    }

    #[test]
    fn test_proof_size() {
        let l_vec = vec![GroupElement::from(RistrettoPoint::identity()); 3];
        let r_vec = vec![GroupElement::from(RistrettoPoint::identity()); 3];
        let proof = InnerProductProof::new(l_vec, r_vec, Scalar::from(1u64), Scalar::from(2u64));

        // 3 L values + 3 R values + 2 scalars = 6*32 + 64 = 256 bytes
        assert_eq!(proof.size_bytes(), 256);
    }
}