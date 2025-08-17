//! Range proof structure and serialization

use bulletproofs_core::*;
use ipa::InnerProductProof;
use serde::{Deserialize, Serialize};

/// A range proof that proves a committed value lies in [0, 2^n)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    /// Commitment to the value being proven
    pub commitment: CompressedRistretto,
    /// Commitment to the bit vector decomposition
    pub bit_commitment: CompressedRistretto,
    /// Inner product argument proof for the constraint system
    pub ipa_proof: IpaProof,
    /// Blinding factor for the commitment
    pub blinding: Scalar,
}

impl RangeProof {
    /// Create a new range proof
    pub fn new(
        commitment: CompressedRistretto,
        bit_commitment: CompressedRistretto,
        ipa_proof: IpaProof,
        blinding: Scalar,
    ) -> Self {
        Self {
            commitment,
            bit_commitment,
            ipa_proof,
            blinding,
        }
    }

    /// Get the commitment to the value
    pub fn commitment(&self) -> &CompressedRistretto {
        &self.commitment
    }

    /// Get the bit commitment
    pub fn bit_commitment(&self) -> &CompressedRistretto {
        &self.bit_commitment
    }

    /// Get the IPA proof
    pub fn ipa_proof(&self) -> &IpaProof {
        &self.ipa_proof
    }

    /// Get the blinding factor
    pub fn blinding(&self) -> &Scalar {
        &self.blinding
    }

    /// Serialize the proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.commitment.as_bytes());
        bytes.extend_from_slice(self.bit_commitment.as_bytes());
        
        // Serialize IPA proof
        let ipa_bytes = self.ipa_proof.to_bytes();
        bytes.extend_from_slice(&(ipa_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&ipa_bytes);
        
        bytes.extend_from_slice(self.blinding.as_bytes());
        bytes
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BulletproofsError> {
        if bytes.len() < 32 + 32 + 4 + 32 {
            return Err(BulletproofsError::InvalidProof("Insufficient bytes".to_string()));
        }

        let mut offset = 0;

        // Parse commitment
        let commitment = CompressedRistretto::from_slice(&bytes[offset..offset + 32])
            .map_err(|_| BulletproofsError::InvalidProof("Invalid commitment".to_string()))?;
        offset += 32;

        // Parse bit commitment
        let bit_commitment = CompressedRistretto::from_slice(&bytes[offset..offset + 32])
            .map_err(|_| BulletproofsError::InvalidProof("Invalid bit commitment".to_string()))?;
        offset += 32;

        // Parse IPA proof length
        let ipa_len = u32::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]
        ]) as usize;
        offset += 4;

        if bytes.len() < offset + ipa_len + 32 {
            return Err(BulletproofsError::InvalidProof("Insufficient bytes for IPA proof".to_string()));
        }

        // Parse IPA proof
        let ipa_proof = IpaProof::from_bytes(&bytes[offset..offset + ipa_len])?;
        offset += ipa_len;

        // Parse blinding factor
        let blinding_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| BulletproofsError::InvalidProof("Invalid blinding factor".to_string()))?;
        let blinding = Scalar::from_bytes_mod_order(blinding_bytes);

        Ok(Self {
            commitment,
            bit_commitment,
            ipa_proof,
            blinding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::thread_rng;

    #[test]
    fn test_range_proof_serialization() {
        let mut rng = thread_rng();
        
        // Create dummy proof components
        let commitment = RistrettoPoint::random(&mut rng).compress();
        let bit_commitment = RistrettoPoint::random(&mut rng).compress();
        let blinding = Scalar::random(&mut rng);
        
        // Create minimal IPA proof for testing
        let ipa_proof = InnerProductProof::new(vec![], vec![], Scalar::ONE, Scalar::ONE);
        
        let proof = RangeProof::new(commitment, bit_commitment, ipa_proof, blinding);
        
        // Test serialization roundtrip
        let bytes = proof.to_bytes();
        let deserialized = RangeProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(proof.commitment.as_bytes(), deserialized.commitment.as_bytes());
        assert_eq!(proof.bit_commitment.as_bytes(), deserialized.bit_commitment.as_bytes());
        assert_eq!(proof.blinding, deserialized.blinding);
    }
}