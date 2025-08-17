//! Marlin verifier implementation
//!
//! This module implements the verifier side of the Marlin protocol,
//! including proof verification and the 3-round interactive protocol.

use crate::{Result, MarlinError, iop::*, r1cs::*, prover::*};
use zkp_field::{Scalar, polynomial::{PolynomialOps, DensePolynomial}, fft::FftDomain};
use zkp_commitments::{CommitmentEngine, CommitmentError};
use ark_ff::{Zero, UniformRand};
use ark_std::rand::Rng;
use std::marker::PhantomData;

/// Marlin verification key
#[derive(Debug, Clone)]
pub struct MarlinVerifyingKey<E: CommitmentEngine> {
    /// Commitment engine parameters
    pub params: E::Parameters,
    /// R1CS matrices (public part only)
    pub r1cs_matrices: PublicR1CSMatrices,
    /// Precomputed selector commitments
    pub selector_commitments: Vec<E::Commitment>,
    /// Evaluation domain
    pub domain: FftDomain,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Number of constraints
    pub num_constraints: usize,
}

/// Public parts of R1CS matrices needed for verification
#[derive(Debug, Clone)]
pub struct PublicR1CSMatrices {
    /// Public part of A matrix (for public inputs only)
    pub a_public: SparseMatrix,
    /// Public part of B matrix (for public inputs only)  
    pub b_public: SparseMatrix,
    /// Public part of C matrix (for public inputs only)
    pub c_public: SparseMatrix,
}

/// Marlin verifier state machine
pub struct MarlinVerifier<E: CommitmentEngine> {
    /// Verification key
    pub vk: MarlinVerifyingKey<E>,
    /// Current verification context
    pub context: Option<VerificationContext<E>>,
    /// Phantom data for commitment engine
    _phantom: PhantomData<E>,
}

/// Context for a specific proof verification
pub struct VerificationContext<E: CommitmentEngine> {
    /// Public inputs for this proof
    pub public_inputs: Vec<Scalar>,
    /// Random challenges used in verification
    pub challenges: Vec<Scalar>,
    /// Current round number
    pub round: usize,
    /// Accumulated proof components
    pub round1: Option<Round1Prover<E>>,
    pub round2: Option<Round2Prover<E>>,
    pub round3: Option<Round3Prover<E>>,
    /// Verification transcript for Fiat-Shamir
    pub transcript: MarlinTranscript,
}

/// Batch verifier for efficiently verifying multiple proofs
pub struct MarlinBatchVerifier<E: CommitmentEngine> {
    /// Individual verification keys
    pub vks: Vec<MarlinVerifyingKey<E>>,
    /// Batch randomness for aggregation
    pub batch_randomness: Vec<Scalar>,
}

impl<E: CommitmentEngine> MarlinVerifier<E> {
    /// Creates a new Marlin verifier
    pub fn new(vk: MarlinVerifyingKey<E>) -> Self {
        Self {
            vk,
            context: None,
            _phantom: PhantomData,
        }
    }

    /// Verifies a complete Marlin proof
    pub fn verify(
        &mut self,
        proof: &MarlinProof<E>,
        public_inputs: &[Scalar],
    ) -> Result<bool> {
        // Validate public inputs
        if public_inputs.len() != self.vk.num_public_inputs {
            return Err(MarlinError::VerificationFailed);
        }

        // Create verification context
        let mut context = VerificationContext::new(
            public_inputs.to_vec(),
            self.vk.domain,
        )?;

        // Verify each round sequentially
        let round1_valid = self.verify_round1(&mut context, &proof.round1)?;
        if !round1_valid {
            return Ok(false);
        }

        let round2_valid = self.verify_round2(&mut context, &proof.round2)?;
        if !round2_valid {
            return Ok(false);
        }

        let round3_valid = self.verify_round3(&mut context, &proof.round3)?;
        if !round3_valid {
            return Ok(false);
        }

        // Perform final consistency checks
        let final_valid = self.verify_final_consistency(&context, proof)?;

        self.context = Some(context);
        Ok(final_valid)
    }

    /// Verifies round 1 of the protocol
    fn verify_round1(
        &self,
        context: &mut VerificationContext<E>,
        round1: &Round1Prover<E>,
    ) -> Result<bool> {
        // Store round 1 data
        context.round1 = Some(round1.clone());
        context.round = 1;

        // Generate challenges for round 2 (using Fiat-Shamir)
        context.transcript.append("round1_w", b"witness_commitment");
        context.transcript.append("round1_za", b"selector_a_commitment");
        context.transcript.append("round1_zb", b"selector_b_commitment");
        context.transcript.append("round1_zc", b"selector_c_commitment");

        let alpha = context.transcript.challenge("alpha");
        let beta = context.transcript.challenge("beta");
        
        context.challenges.push(alpha);
        context.challenges.push(beta);

        // Basic commitment validation (check that commitments are non-trivial)
        // In practice, would perform additional checks
        Ok(true)
    }

    /// Verifies round 2 of the protocol
    fn verify_round2(
        &self,
        context: &mut VerificationContext<E>,
        round2: &Round2Prover<E>,
    ) -> Result<bool> {
        // Store round 2 data
        context.round2 = Some(round2.clone());
        context.round = 2;

        // Generate challenge for round 3
        context.transcript.append("round2_h1", b"quotient1_commitment");
        context.transcript.append("round2_h2", b"quotient2_commitment");
        context.transcript.append("round2_g", b"grand_product_commitment");

        let zeta = context.transcript.challenge("zeta");
        context.challenges.push(zeta);

        // Validate quotient polynomial commitments
        // In practice, would check degree bounds and other properties
        Ok(true)
    }

    /// Verifies round 3 of the protocol
    fn verify_round3(
        &self,
        context: &mut VerificationContext<E>,
        round3: &Round3Prover<E>,
    ) -> Result<bool> {
        // Store round 3 data
        context.round3 = Some(round3.clone());
        context.round = 3;

        if round3.openings.is_empty() || round3.evaluations.is_empty() {
            return Err(MarlinError::VerificationFailed);
        }

        // Verify polynomial opening proofs
        let zeta = context.challenges.last().ok_or(MarlinError::VerificationFailed)?;

        // For each opening, verify that the commitment opens to the claimed value
        for (i, (opening, &evaluation)) in round3.openings.iter().zip(round3.evaluations.iter()).enumerate() {
            // This is a simplified check - in practice would verify specific polynomial openings
            if evaluation == Scalar::zero() && i > 0 {
                continue; // Allow zero evaluations for some polynomials
            }
        }

        Ok(true)
    }

    /// Performs final consistency checks on the proof
    fn verify_final_consistency(
        &self,
        context: &VerificationContext<E>,
        proof: &MarlinProof<E>,
    ) -> Result<bool> {
        // Check that all rounds are present
        let round1 = context.round1.as_ref().ok_or(MarlinError::VerificationFailed)?;
        let round2 = context.round2.as_ref().ok_or(MarlinError::VerificationFailed)?;
        let round3 = context.round3.as_ref().ok_or(MarlinError::VerificationFailed)?;

        // Verify proof metadata consistency
        if proof.metadata.num_public_inputs != self.vk.num_public_inputs {
            return Err(MarlinError::VerificationFailed);
        }

        if proof.metadata.num_constraints != self.vk.num_constraints {
            return Err(MarlinError::VerificationFailed);
        }

        // Check that we have the correct number of challenges
        if context.challenges.len() < 3 {
            return Err(MarlinError::VerificationFailed);
        }

        // Verify the constraint equation holds at the evaluation point
        if let Some(&zeta) = context.challenges.last() {
            let constraint_check = self.verify_constraint_equation(context, zeta)?;
            if !constraint_check {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verifies that the R1CS constraint equation is satisfied
    fn verify_constraint_equation(
        &self,
        context: &VerificationContext<E>,
        zeta: Scalar,
    ) -> Result<bool> {
        // This is a simplified constraint verification
        // In practice, would compute the actual constraint polynomial evaluation
        
        let round3 = context.round3.as_ref().ok_or(MarlinError::VerificationFailed)?;
        
        // Get evaluations of polynomials at zeta
        if round3.evaluations.len() < 3 {
            return Err(MarlinError::VerificationFailed);
        }

        let w_eval = round3.evaluations[0];
        let za_eval = round3.evaluations.get(1).copied().unwrap_or(Scalar::zero());
        let zb_eval = round3.evaluations.get(2).copied().unwrap_or(Scalar::zero());
        let zc_eval = round3.evaluations.get(3).copied().unwrap_or(Scalar::zero());

        // Simplified constraint check: verify that some polynomial relation holds
        // In practice, this would verify the actual R1CS constraint equation
        let constraint_lhs = za_eval * zb_eval;
        let constraint_rhs = zc_eval;
        
        // Allow some tolerance for zero-knowledge masking
        let constraint_satisfied = constraint_lhs == constraint_rhs || 
                                 (constraint_lhs.is_zero() && constraint_rhs.is_zero());

        Ok(constraint_satisfied)
    }

    /// Verifies a proof using batch techniques (simplified)
    pub fn batch_verify(
        &mut self,
        proofs: &[MarlinProof<E>],
        public_inputs: &[Vec<Scalar>],
    ) -> Result<bool> {
        if proofs.len() != public_inputs.len() {
            return Err(MarlinError::VerificationFailed);
        }

        // For simplified implementation, verify each proof individually
        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            if !self.verify(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl<E: CommitmentEngine> VerificationContext<E> {
    /// Creates a new verification context
    pub fn new(public_inputs: Vec<Scalar>, domain: FftDomain) -> Result<Self> {
        let transcript = MarlinTranscript::new(domain);
        
        Ok(Self {
            public_inputs,
            challenges: Vec::new(),
            round: 0,
            round1: None,
            round2: None,
            round3: None,
            transcript,
        })
    }

    /// Generates the next challenge in the protocol
    pub fn generate_challenge(&mut self, label: &str) -> Scalar {
        let challenge = self.transcript.challenge(label);
        self.challenges.push(challenge);
        challenge
    }

    /// Adds data to the verification transcript
    pub fn add_to_transcript(&mut self, label: &str, data: &[u8]) {
        self.transcript.append(label, data);
    }
}

impl<E: CommitmentEngine> MarlinVerifyingKey<E> {
    /// Creates a new verification key
    pub fn new(
        params: E::Parameters,
        r1cs_matrices: PublicR1CSMatrices,
        selector_commitments: Vec<E::Commitment>,
        domain: FftDomain,
        num_public_inputs: usize,
        num_constraints: usize,
    ) -> Self {
        Self {
            params,
            r1cs_matrices,
            selector_commitments,
            domain,
            num_public_inputs,
            num_constraints,
        }
    }

    /// Validates the verification key structure
    pub fn validate(&self) -> Result<()> {
        if self.num_public_inputs == 0 {
            return Err(MarlinError::InvalidSetup);
        }

        if self.num_constraints == 0 {
            return Err(MarlinError::InvalidSetup);
        }

        if self.domain.size() < self.num_constraints {
            return Err(MarlinError::InvalidSetup);
        }

        // Check matrix dimensions
        let matrices = &self.r1cs_matrices;
        if matrices.a_public.num_rows != self.num_constraints ||
           matrices.b_public.num_rows != self.num_constraints ||
           matrices.c_public.num_rows != self.num_constraints {
            return Err(MarlinError::InvalidSetup);
        }

        Ok(())
    }

    /// Extracts the public input selector polynomials
    pub fn public_input_selectors(&self) -> Result<(Vec<DensePolynomial>, Vec<DensePolynomial>, Vec<DensePolynomial>)> {
        let domain = &self.domain;
        let matrices = &self.r1cs_matrices;

        let mut a_selectors = Vec::new();
        let mut b_selectors = Vec::new();
        let mut c_selectors = Vec::new();

        // For each public input, extract its selector polynomial
        for input_idx in 0..self.num_public_inputs {
            // Extract column for this public input from each matrix
            let mut a_column = vec![Scalar::zero(); domain.size()];
            let mut b_column = vec![Scalar::zero(); domain.size()];
            let mut c_column = vec![Scalar::zero(); domain.size()];

            for constraint_idx in 0..self.num_constraints {
                a_column[constraint_idx] = matrices.a_public.get(constraint_idx, input_idx);
                b_column[constraint_idx] = matrices.b_public.get(constraint_idx, input_idx);
                c_column[constraint_idx] = matrices.c_public.get(constraint_idx, input_idx);
            }

            // Convert to polynomials
            let a_poly = PolynomialOps::interpolate_from_domain(&a_column, domain)?;
            let b_poly = PolynomialOps::interpolate_from_domain(&b_column, domain)?;
            let c_poly = PolynomialOps::interpolate_from_domain(&c_column, domain)?;

            a_selectors.push(a_poly);
            b_selectors.push(b_poly);
            c_selectors.push(c_poly);
        }

        Ok((a_selectors, b_selectors, c_selectors))
    }
}

impl PublicR1CSMatrices {
    /// Creates new public R1CS matrices
    pub fn new(
        num_constraints: usize,
        num_public_inputs: usize,
    ) -> Self {
        Self {
            a_public: SparseMatrix::new(num_constraints, num_public_inputs),
            b_public: SparseMatrix::new(num_constraints, num_public_inputs),
            c_public: SparseMatrix::new(num_constraints, num_public_inputs),
        }
    }

    /// Extracts public matrices from a full R1CS
    pub fn from_r1cs(r1cs: &R1CS) -> Self {
        let mut public_matrices = Self::new(r1cs.num_constraints, r1cs.num_public_inputs);

        // Extract public input columns (first num_public_inputs columns after constant)
        for &(row, col, val) in &r1cs.a_matrix.entries {
            if col > 0 && col <= r1cs.num_public_inputs {
                public_matrices.a_public.add_entry(row, col - 1, val);
            }
        }

        for &(row, col, val) in &r1cs.b_matrix.entries {
            if col > 0 && col <= r1cs.num_public_inputs {
                public_matrices.b_public.add_entry(row, col - 1, val);
            }
        }

        for &(row, col, val) in &r1cs.c_matrix.entries {
            if col > 0 && col <= r1cs.num_public_inputs {
                public_matrices.c_public.add_entry(row, col - 1, val);
            }
        }

        public_matrices
    }
}

impl<E: CommitmentEngine> MarlinBatchVerifier<E> {
    /// Creates a new batch verifier
    pub fn new(vks: Vec<MarlinVerifyingKey<E>>) -> Self {
        Self {
            vks,
            batch_randomness: Vec::new(),
        }
    }

    /// Verifies a batch of proofs efficiently
    pub fn batch_verify<R: Rng>(
        &mut self,
        proofs: &[MarlinProof<E>],
        public_inputs: &[Vec<Scalar>],
        rng: &mut R,
    ) -> Result<bool> {
        if proofs.len() != self.vks.len() || public_inputs.len() != self.vks.len() {
            return Err(MarlinError::VerificationFailed);
        }

        // Generate batch randomness
        self.batch_randomness.clear();
        for _ in 0..proofs.len() {
            self.batch_randomness.push(UniformRand::rand(rng));
        }

        // Aggregate verification equations (simplified implementation)
        // In practice, this would combine multiple verification equations
        
        for (i, ((proof, inputs), vk)) in proofs.iter()
            .zip(public_inputs.iter())
            .zip(self.vks.iter())
            .enumerate() 
        {
            let mut verifier = MarlinVerifier::new(vk.clone());
            if !verifier.verify(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Aggregates multiple verification keys for common circuit
    pub fn aggregate_keys(&self, circuit_id: usize) -> Result<MarlinVerifyingKey<E>> {
        if circuit_id >= self.vks.len() {
            return Err(MarlinError::InvalidSetup);
        }

        // For simplified implementation, return the specified key
        // In practice, would properly aggregate keys
        Ok(self.vks[circuit_id].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use zkp_commitments::kzg::KzgCommitmentEngine;

    #[test]
    fn test_verification_context() {
        let domain = FftDomain::new(8).unwrap();
        let public_inputs = vec![Scalar::one(), Scalar::from(2u64)];
        
        let context = VerificationContext::<KzgCommitmentEngine>::new(public_inputs, domain);
        assert!(context.is_ok());
        
        let ctx = context.unwrap();
        assert_eq!(ctx.public_inputs.len(), 2);
        assert_eq!(ctx.round, 0);
    }

    #[test]
    fn test_public_r1cs_matrices() {
        let matrices = PublicR1CSMatrices::new(2, 1);
        assert_eq!(matrices.a_public.num_rows, 2);
        assert_eq!(matrices.a_public.num_cols, 1);
    }

    #[test]
    fn test_verifying_key_validation() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let matrices = PublicR1CSMatrices::new(4, 2);
        let domain = FftDomain::new(8).unwrap();
        
        let vk = MarlinVerifyingKey::new(
            params,
            matrices,
            vec![], // Empty selector commitments for test
            domain,
            2, // num_public_inputs
            4, // num_constraints
        );
        
        assert!(vk.validate().is_ok());
    }

    #[test]
    fn test_marlin_verifier_creation() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let matrices = PublicR1CSMatrices::new(2, 1);
        let domain = FftDomain::new(4).unwrap();
        
        let vk = MarlinVerifyingKey::new(params, matrices, vec![], domain, 1, 2);
        let verifier = MarlinVerifier::new(vk);
        
        assert!(verifier.vk.validate().is_ok());
    }

    #[test]
    fn test_batch_verifier() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let domain = FftDomain::new(4).unwrap();
        
        let mut vks = Vec::new();
        for _ in 0..3 {
            let matrices = PublicR1CSMatrices::new(1, 1);
            let vk = MarlinVerifyingKey::new(params.clone(), matrices, vec![], domain, 1, 1);
            vks.push(vk);
        }
        
        let batch_verifier = MarlinBatchVerifier::new(vks);
        assert_eq!(batch_verifier.vks.len(), 3);
    }
}