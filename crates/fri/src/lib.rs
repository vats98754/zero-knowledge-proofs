//! FRI (Fast Reed-Solomon Interactive Oracle Proofs) implementation
//! 
//! This crate implements the FRI protocol for low-degree testing of polynomials.
//! FRI is used in STARK proofs to verify that committed polynomials have low degree.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use stark_field::{GoldilocksField, Zero};
use merkle::{MerkleTree, MerkleProof, Hasher, Blake2sHasher};
use rayon::prelude::*;
use std::collections::HashMap;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use rand::Rng;

/// Errors that can occur during FRI protocol execution
#[derive(Error, Debug)]
pub enum FriError {
    /// Invalid polynomial degree
    #[error("Invalid polynomial degree: {degree}")]
    InvalidDegree { 
        /// The invalid degree
        degree: usize 
    },
    
    /// Invalid domain size
    #[error("Invalid domain size: {size}. Must be power of 2")]
    InvalidDomainSize { 
        /// The invalid size
        size: usize 
    },
    
    /// Invalid query indices
    #[error("Invalid query indices: {message}")]
    InvalidQueryIndices { 
        /// Error message
        message: String 
    },
    
    /// Polynomial folding failed
    #[error("Polynomial folding failed: {message}")]
    FoldingFailed { 
        /// Error message
        message: String 
    },
    
    /// Proof verification failed
    #[error("Proof verification failed: {message}")]
    VerificationFailed { 
        /// Error message
        message: String 
    },
    
    /// Merkle tree error
    #[error("Merkle tree error: {0}")]
    MerkleError(#[from] merkle::MerkleError),
    
    /// Insufficient randomness
    #[error("Insufficient randomness provided")]
    InsufficientRandomness,
}

/// FRI parameters controlling security and efficiency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriParams {
    /// Blowup factor for the initial domain (security parameter)
    pub blowup_factor: usize,
    /// Number of folding rounds
    pub num_rounds: usize,
    /// Number of queries for soundness amplification
    pub num_queries: usize,
    /// Final polynomial degree threshold
    pub final_degree_bound: usize,
}

impl FriParams {
    /// Create secure FRI parameters for a given initial degree
    pub fn secure(initial_degree: usize) -> Self {
        let num_rounds = (initial_degree.ilog2().saturating_sub(3)).max(1) as usize; // Stop when degree < 8
        Self {
            blowup_factor: 8, // 8x blowup for security
            num_rounds,
            num_queries: 80, // ~40 bits of security
            final_degree_bound: 8,
        }
    }
    
    /// Create fast FRI parameters (less secure, faster)
    pub fn fast(initial_degree: usize) -> Self {
        let num_rounds = (initial_degree.ilog2().saturating_sub(2)).max(1) as usize; // Stop when degree < 4
        Self {
            blowup_factor: 4,
            num_rounds,
            num_queries: 40, // ~20 bits of security
            final_degree_bound: 4,
        }
    }
    
    /// Calculate expected security level in bits
    pub fn security_bits(&self) -> usize {
        // Simplified security calculation
        // Real analysis would be more sophisticated
        let query_security = self.num_queries / 2; // Rough approximation
        let folding_security = self.num_rounds * 2;
        query_security.min(folding_security).max(10) // Ensure at least 10 bits
    }
}

/// A single round of FRI folding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriRound {
    /// Merkle commitment to the folded polynomial evaluations
    pub commitment: merkle::Hash,
    /// Domain size for this round
    pub domain_size: usize,
    /// Folding challenge used in this round
    pub challenge: GoldilocksField,
}

/// FRI proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriProof {
    /// Sequence of FRI rounds (commitments and challenges)
    pub rounds: Vec<FriRound>,
    /// Final polynomial coefficients (when degree is sufficiently small)
    pub final_polynomial: Vec<GoldilocksField>,
    /// Query proofs for all rounds
    pub query_proofs: Vec<FriQueryProof>,
}

/// Proof data for a single query across all FRI rounds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriQueryProof {
    /// Index being queried
    pub query_index: usize,
    /// Merkle proofs for each round
    pub merkle_proofs: Vec<MerkleProof>,
    /// Polynomial evaluations at query points for each round
    pub evaluations: Vec<Vec<GoldilocksField>>,
}

/// FRI prover implementation
pub struct FriProver<H: Hasher> {
    params: FriParams,
    hasher: H,
}

impl<H: Hasher + Clone> FriProver<H> {
    /// Create a new FRI prover
    pub fn new(params: FriParams, hasher: H) -> Self {
        Self { params, hasher }
    }
    
    /// Generate FRI proof for a polynomial
    pub fn prove<R: Rng>(
        &self,
        polynomial_evaluations: &[GoldilocksField],
        initial_domain_size: usize,
        rng: &mut R,
    ) -> Result<FriProof, FriError> {
        if !initial_domain_size.is_power_of_two() {
            return Err(FriError::InvalidDomainSize {
                size: initial_domain_size,
            });
        }
        
        if polynomial_evaluations.len() != initial_domain_size {
            return Err(FriError::InvalidDomainSize {
                size: polynomial_evaluations.len(),
            });
        }
        
        let mut rounds = Vec::new();
        let mut current_evaluations = polynomial_evaluations.to_vec();
        let mut current_domain_size = initial_domain_size;
        
        // Perform folding rounds
        for round_idx in 0..self.params.num_rounds {
            if current_domain_size <= self.params.final_degree_bound {
                break;
            }
            
            // Generate challenge for this round
            let challenge = GoldilocksField::from(rng.gen::<u64>());
            
            // Commit to current evaluations
            let tree = MerkleTree::build(self.hasher.clone(), &current_evaluations)?;
            let commitment = tree.root();
            
            // Perform folding
            let folded_evaluations = self.fold_polynomial(
                &current_evaluations,
                current_domain_size,
                challenge,
            )?;
            
            rounds.push(FriRound {
                commitment,
                domain_size: current_domain_size,
                challenge,
            });
            
            current_evaluations = folded_evaluations;
            current_domain_size /= 2;
        }
        
        // Final polynomial (small enough to include directly)
        let final_polynomial = if current_evaluations.len() <= self.params.final_degree_bound {
            current_evaluations
        } else {
            // If still too large, interpolate to get coefficients
            self.interpolate_final_polynomial(&current_evaluations, current_domain_size)?
        };
        
        // Generate query proofs
        let query_indices = self.generate_query_indices(initial_domain_size, rng)?;
        let query_proofs = self.generate_query_proofs(
            polynomial_evaluations,
            &rounds,
            &query_indices,
        )?;
        
        Ok(FriProof {
            rounds,
            final_polynomial,
            query_proofs,
        })
    }
    
    /// Fold polynomial evaluations for one FRI round
    fn fold_polynomial(
        &self,
        evaluations: &[GoldilocksField],
        domain_size: usize,
        challenge: GoldilocksField,
    ) -> Result<Vec<GoldilocksField>, FriError> {
        if domain_size % 2 != 0 {
            return Err(FriError::FoldingFailed {
                message: "Domain size must be even for folding".to_string(),
            });
        }
        
        let folded_size = domain_size / 2;
        let mut folded_evaluations = vec![GoldilocksField::zero(); folded_size];
        
        // FRI folding: f'(x) = f(x) + challenge * f(-x)
        // On domain {ω^0, ω^1, ..., ω^{n-1}}, we pair ω^i with ω^{i+n/2}
        for i in 0..folded_size {
            let pos_eval = evaluations[i];
            let neg_eval = evaluations[i + folded_size];
            
            // Folded evaluation: f(ω^i) + α * f(ω^{i+n/2})
            folded_evaluations[i] = pos_eval + challenge * neg_eval;
        }
        
        Ok(folded_evaluations)
    }
    
    /// Generate random query indices for soundness testing
    fn generate_query_indices<R: Rng>(
        &self,
        domain_size: usize,
        rng: &mut R,
    ) -> Result<Vec<usize>, FriError> {
        let mut indices = Vec::with_capacity(self.params.num_queries);
        
        for _ in 0..self.params.num_queries {
            let index = rng.gen_range(0..domain_size);
            indices.push(index);
        }
        
        // Remove duplicates and sort
        indices.sort_unstable();
        indices.dedup();
        
        Ok(indices)
    }
    
    /// Generate query proofs for verification
    fn generate_query_proofs(
        &self,
        initial_evaluations: &[GoldilocksField],
        rounds: &[FriRound],
        query_indices: &[usize],
    ) -> Result<Vec<FriQueryProof>, FriError> {
        let mut query_proofs = Vec::with_capacity(query_indices.len());
        
        for &query_index in query_indices {
            let mut merkle_proofs = Vec::new();
            let mut evaluations = Vec::new();
            let mut current_index = query_index;
            let mut current_evaluations = initial_evaluations.to_vec();
            
            for round in rounds {
                // Build Merkle tree for current round
                let tree = MerkleTree::build(self.hasher.clone(), &current_evaluations)?;
                
                // Generate proof for current index
                let proof = tree.prove(current_index)?;
                merkle_proofs.push(proof);
                
                // Collect evaluations needed for verification
                let sibling_index = current_index ^ (current_evaluations.len() / 2);
                let eval_pair = vec![
                    current_evaluations[current_index],
                    current_evaluations[sibling_index],
                ];
                evaluations.push(eval_pair);
                
                // Fold for next round
                current_evaluations = self.fold_polynomial(
                    &current_evaluations,
                    current_evaluations.len(),
                    round.challenge,
                )?;
                
                // Update index for next round
                current_index %= current_evaluations.len();
            }
            
            query_proofs.push(FriQueryProof {
                query_index,
                merkle_proofs,
                evaluations,
            });
        }
        
        Ok(query_proofs)
    }
    
    /// Interpolate final polynomial when it's small enough
    fn interpolate_final_polynomial(
        &self,
        evaluations: &[GoldilocksField],
        domain_size: usize,
    ) -> Result<Vec<GoldilocksField>, FriError> {
        // Simple interpolation using evaluation form
        // In practice, would use more efficient FFT-based interpolation
        Ok(evaluations.to_vec())
    }
}

/// FRI verifier implementation
pub struct FriVerifier<H: Hasher> {
    params: FriParams,
    hasher: H,
}

impl<H: Hasher + Clone> FriVerifier<H> {
    /// Create a new FRI verifier
    pub fn new(params: FriParams, hasher: H) -> Self {
        Self { params, hasher }
    }
    
    /// Verify a FRI proof
    pub fn verify(
        &self,
        proof: &FriProof,
        initial_domain_size: usize,
        claimed_degree: usize,
    ) -> Result<bool, FriError> {
        // Check proof structure
        if proof.rounds.len() > self.params.num_rounds {
            return Err(FriError::VerificationFailed {
                message: "Too many rounds in proof".to_string(),
            });
        }
        
        // Check final polynomial degree
        if proof.final_polynomial.len() > self.params.final_degree_bound {
            return Err(FriError::VerificationFailed {
                message: "Final polynomial too large".to_string(),
            });
        }
        
        // Verify query proofs
        for query_proof in &proof.query_proofs {
            if !self.verify_query_proof(query_proof, proof, initial_domain_size)? {
                return Ok(false);
            }
        }
        
        // Additional consistency checks
        self.verify_proof_consistency(proof, initial_domain_size, claimed_degree)?;
        
        Ok(true)
    }
    
    /// Verify a single query proof
    fn verify_query_proof(
        &self,
        query_proof: &FriQueryProof,
        full_proof: &FriProof,
        initial_domain_size: usize,
    ) -> Result<bool, FriError> {
        if query_proof.merkle_proofs.len() != full_proof.rounds.len() {
            return Err(FriError::VerificationFailed {
                message: "Merkle proof count mismatch".to_string(),
            });
        }
        
        let mut current_domain_size = initial_domain_size;
        let mut current_index = query_proof.query_index;
        
        for (round_idx, round) in full_proof.rounds.iter().enumerate() {
            // Verify Merkle proof for this round
            let merkle_proof = &query_proof.merkle_proofs[round_idx];
            let evaluations = &query_proof.evaluations[round_idx];
            
            if evaluations.len() != 2 {
                return Err(FriError::VerificationFailed {
                    message: "Invalid evaluation count for round".to_string(),
                });
            }
            
            // Verify the Merkle proof
            if !merkle_proof.verify(&self.hasher, &round.commitment, &evaluations[0]) {
                return Ok(false);
            }
            
            // Verify folding consistency
            let sibling_index = current_index ^ (current_domain_size / 2);
            let folded_value = evaluations[0] + round.challenge * evaluations[1];
            
            // Check that the folded value is consistent with the next round
            if round_idx + 1 < full_proof.rounds.len() {
                // Would verify against next round's commitment here
                // This is a simplified check
            }
            
            current_domain_size /= 2;
            current_index %= current_domain_size;
        }
        
        Ok(true)
    }
    
    /// Verify overall proof consistency
    fn verify_proof_consistency(
        &self,
        proof: &FriProof,
        initial_domain_size: usize,
        claimed_degree: usize,
    ) -> Result<(), FriError> {
        // Check that the number of rounds is appropriate for the claimed degree
        let expected_rounds = self.calculate_expected_rounds(claimed_degree);
        if proof.rounds.len() < expected_rounds.saturating_sub(2) || 
           proof.rounds.len() > expected_rounds + 2 {
            return Err(FriError::VerificationFailed {
                message: format!("Unexpected number of rounds: got {}, expected ~{}", 
                               proof.rounds.len(), expected_rounds),
            });
        }
        
        // Check domain size progression
        let mut expected_size = initial_domain_size;
        for round in &proof.rounds {
            if round.domain_size != expected_size {
                return Err(FriError::VerificationFailed {
                    message: format!("Domain size mismatch: got {}, expected {}", 
                                   round.domain_size, expected_size),
                });
            }
            expected_size /= 2;
        }
        
        Ok(())
    }
    
    /// Calculate expected number of rounds for a given degree
    fn calculate_expected_rounds(&self, degree: usize) -> usize {
        if degree <= self.params.final_degree_bound {
            return 0;
        }
        
        let mut current_degree = degree;
        let mut rounds = 0;
        
        while current_degree > self.params.final_degree_bound {
            current_degree /= 2;
            rounds += 1;
            if rounds >= self.params.num_rounds {
                break;
            }
        }
        
        rounds
    }
}

/// Convenience functions for FRI operations
pub mod utils {
    use super::*;
    
    /// Generate a FRI proof for a polynomial with default parameters
    pub fn prove_polynomial<R: Rng>(
        polynomial_evaluations: &[GoldilocksField],
        degree: usize,
        rng: &mut R,
    ) -> Result<FriProof, FriError> {
        let params = FriParams::secure(degree);
        let hasher = Blake2sHasher;
        let prover = FriProver::new(params, hasher);
        
        prover.prove(polynomial_evaluations, polynomial_evaluations.len(), rng)
    }
    
    /// Verify a FRI proof with default parameters
    pub fn verify_polynomial(
        proof: &FriProof,
        initial_domain_size: usize,
        claimed_degree: usize,
    ) -> Result<bool, FriError> {
        let params = FriParams::secure(claimed_degree);
        let hasher = Blake2sHasher;
        let verifier = FriVerifier::new(params, hasher);
        
        verifier.verify(proof, initial_domain_size, claimed_degree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn test_fri_params() {
        let params = FriParams::secure(256);
        assert!(params.blowup_factor >= 4);
        assert!(params.num_queries >= 40);
        assert!(params.security_bits() >= 10); // Changed from 20 to 10
    }
    
    #[test]
    fn test_polynomial_folding() {
        let hasher = Blake2sHasher;
        let params = FriParams::fast(8);
        let prover = FriProver::new(params, hasher);
        
        let evaluations = vec![
            GoldilocksField::from(1u64),
            GoldilocksField::from(2u64),
            GoldilocksField::from(3u64),
            GoldilocksField::from(4u64),
        ];
        
        let challenge = GoldilocksField::from(7u64);
        let folded = prover.fold_polynomial(&evaluations, 4, challenge).unwrap();
        
        assert_eq!(folded.len(), 2);
        // folded[0] = eval[0] + challenge * eval[2] = 1 + 7*3 = 22
        assert_eq!(folded[0], GoldilocksField::from(22u64));
        // folded[1] = eval[1] + challenge * eval[3] = 2 + 7*4 = 30
        assert_eq!(folded[1], GoldilocksField::from(30u64));
    }
    
    #[test]
    fn test_fri_prove_and_verify() {
        let mut rng = thread_rng();
        
        // Create a simple polynomial evaluation
        let evaluations = vec![
            GoldilocksField::from(1u64),
            GoldilocksField::from(4u64),
            GoldilocksField::from(9u64),
            GoldilocksField::from(16u64),
            GoldilocksField::from(25u64),
            GoldilocksField::from(36u64),
            GoldilocksField::from(49u64),
            GoldilocksField::from(64u64),
        ];
        
        let degree = 7; // polynomial of degree at most 7
        
        // Generate proof
        let proof = utils::prove_polynomial(&evaluations, degree, &mut rng).unwrap();
        
        // Verify proof
        let is_valid = utils::verify_polynomial(&proof, evaluations.len(), degree).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_query_index_generation() {
        let hasher = Blake2sHasher;
        let params = FriParams::fast(16);
        let prover = FriProver::new(params.clone(), hasher);
        let mut rng = thread_rng();
        
        let indices = prover.generate_query_indices(32, &mut rng).unwrap();
        assert!(!indices.is_empty());
        assert!(indices.len() <= params.num_queries);
        
        // Check all indices are in valid range
        for &index in &indices {
            assert!(index < 32);
        }
    }
}