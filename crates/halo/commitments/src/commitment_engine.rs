//! Core commitment engine trait and types
//!
//! This module defines the [`CommitmentEngine`] trait that abstracts over different
//! polynomial commitment schemes, making them interchangeable and recursion-friendly.

use crate::{Scalar, GroupElement, GroupProjective, Result};
use ff::PrimeField;
use group::prime::PrimeCurveAffine;
use rand_core::RngCore;

/// A polynomial commitment
pub trait Commitment: Clone + Send + Sync {
    /// Serialize the commitment to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Deserialize the commitment from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// An opening proof for a commitment
pub trait Opening: Clone + Send + Sync {
    /// Serialize the opening to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Deserialize the opening from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// Core trait for polynomial commitment schemes
///
/// This trait abstracts over different commitment schemes (IPA, KZG, etc.)
/// to provide a unified interface for Halo's recursion system.
pub trait CommitmentEngine: Clone + Send + Sync {
    /// The type of commitments produced by this engine
    type Commitment: Commitment;
    
    /// The type of opening proofs produced by this engine
    type Opening: Opening;
    
    /// Parameters needed for the commitment scheme
    type Params: Clone + Send + Sync;
    
    /// Setup the commitment scheme for polynomials of degree up to `max_degree`
    fn setup(max_degree: usize, rng: &mut impl RngCore) -> Result<Self::Params>;
    
    /// Commit to a polynomial represented by its coefficients
    fn commit(
        params: &Self::Params,
        coefficients: &[Scalar],
        blinding: Option<Scalar>,
    ) -> Result<Self::Commitment>;
    
    /// Create an opening proof for a polynomial at a given point
    fn open(
        params: &Self::Params,
        coefficients: &[Scalar],
        blinding: Option<Scalar>,
        point: Scalar,
    ) -> Result<(Scalar, Self::Opening)>;
    
    /// Verify an opening proof
    fn verify(
        params: &Self::Params,
        commitment: &Self::Commitment,
        point: Scalar,
        evaluation: Scalar,
        opening: &Self::Opening,
    ) -> Result<bool>;
    
    /// Batch verify multiple opening proofs (more efficient than individual verification)
    fn batch_verify(
        params: &Self::Params,
        commitments: &[Self::Commitment],
        points: &[Scalar],
        evaluations: &[Scalar],
        openings: &[Self::Opening],
    ) -> Result<bool> {
        // Default implementation: verify each individually
        for (((commitment, &point), &evaluation), opening) in commitments
            .iter()
            .zip(points.iter())
            .zip(evaluations.iter())
            .zip(openings.iter())
        {
            if !Self::verify(params, commitment, point, evaluation, opening)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Simple commitment implementation for IPA
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleCommitment(pub GroupElement);

impl Commitment for SimpleCommitment {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_compressed().to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 48 {
            return Err(crate::CommitmentError::InvalidParameters(
                "Invalid commitment byte length".to_string()
            ));
        }
        
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        
        GroupElement::from_compressed(&arr)
            .into_option()
            .map(SimpleCommitment)
            .ok_or_else(|| crate::CommitmentError::InvalidParameters(
                "Invalid commitment encoding".to_string()
            ))
    }
}

/// Simple opening implementation for IPA
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleOpening {
    /// The opening proof elements
    pub proof_elements: Vec<GroupElement>,
    /// Scalar challenges used in the proof
    pub challenges: Vec<Scalar>,
}

impl Opening for SimpleOpening {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Encode number of proof elements
        bytes.extend_from_slice(&(self.proof_elements.len() as u32).to_le_bytes());
        
        // Encode proof elements
        for element in &self.proof_elements {
            bytes.extend_from_slice(&element.to_compressed());
        }
        
        // Encode number of challenges
        bytes.extend_from_slice(&(self.challenges.len() as u32).to_le_bytes());
        
        // Encode challenges
        for challenge in &self.challenges {
            bytes.extend_from_slice(&challenge.to_repr());
        }
        
        bytes
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(crate::CommitmentError::InvalidParameters(
                "Opening bytes too short".to_string()
            ));
        }
        
        let mut pos = 0;
        
        // Decode number of proof elements
        let num_elements = u32::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]
        ]) as usize;
        pos += 4;
        
        // Decode proof elements
        let mut proof_elements = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            if pos + 48 > bytes.len() {
                return Err(crate::CommitmentError::InvalidParameters(
                    "Insufficient bytes for proof elements".to_string()
                ));
            }
            
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&bytes[pos..pos + 48]);
            pos += 48;
            
            let element = GroupElement::from_compressed(&arr)
                .into_option()
                .ok_or_else(|| crate::CommitmentError::InvalidParameters(
                    "Invalid proof element encoding".to_string()
                ))?;
            proof_elements.push(element);
        }
        
        // Decode number of challenges
        if pos + 4 > bytes.len() {
            return Err(crate::CommitmentError::InvalidParameters(
                "Insufficient bytes for challenge count".to_string()
            ));
        }
        
        let num_challenges = u32::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]
        ]) as usize;
        pos += 4;
        
        // Decode challenges
        let mut challenges = Vec::with_capacity(num_challenges);
        for _ in 0..num_challenges {
            if pos + 32 > bytes.len() {
                return Err(crate::CommitmentError::InvalidParameters(
                    "Insufficient bytes for challenges".to_string()
                ));
            }
            
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            
            let challenge = Scalar::from_repr(arr)
                .into_option()
                .ok_or_else(|| crate::CommitmentError::InvalidParameters(
                    "Invalid challenge encoding".to_string()
                ))?;
            challenges.push(challenge);
        }
        
        Ok(SimpleOpening {
            proof_elements,
            challenges,
        })
    }
}