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