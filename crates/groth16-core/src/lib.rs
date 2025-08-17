//! Core Groth16 prover and verifier implementation.
//! 
//! This crate provides the main Groth16 proving and verification algorithms.
//! The implementation follows the original Groth16 paper with optimizations
//! for practical performance.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use groth16_field::FieldLike;
use groth16_setup::{ProvingKey, VerificationKey};
use groth16_qap::QAP;
use ark_ff::PrimeField;
use ark_ec::{CurveGroup, AffineRepr, VariableBaseMSM, pairing::Pairing};
use ark_poly::{EvaluationDomain, DenseUVPolynomial};
use ark_bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine, Fr, Bls12_381};
use ark_std::{vec::Vec, Zero, One, UniformRand};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rand::Rng;
use rayon::prelude::*;

pub use groth16_field;
pub use groth16_r1cs;
pub use groth16_qap;
pub use groth16_setup;

/// A Groth16 proof
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    /// π_A in G1
    pub a: G1Affine,
    /// π_B in G2
    pub b: G2Affine,
    /// π_C in G1
    pub c: G1Affine,
}

/// Witness for the circuit
#[derive(Debug, Clone)]
pub struct Witness<F: FieldLike> {
    /// Full variable assignment (including public inputs)
    pub assignment: Vec<F>,
    /// Number of public inputs (not including the constant)
    pub num_public: usize,
}

/// Errors that can occur during proving or verification
#[derive(Debug, thiserror::Error)]
pub enum GrothError {
    /// Setup error
    #[error("Setup error: {0}")]
    SetupError(#[from] groth16_setup::SetupError),
    
    /// QAP error
    #[error("QAP error: {0}")]
    QAPError(#[from] groth16_qap::QAPError),
    
    /// Field operation error
    #[error("Field error: {0}")]
    FieldError(#[from] groth16_field::FieldError),
    
    /// Invalid witness
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),
    
    /// Proof verification failed
    #[error("Proof verification failed")]
    VerificationFailed,
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    
    /// MSM computation error
    #[error("MSM computation error: {0}")]
    MSMError(String),
}

impl<F: FieldLike> Witness<F> {
    /// Create a new witness
    pub fn new(assignment: Vec<F>, num_public: usize) -> Result<Self, GrothError> {
        if num_public >= assignment.len() {
            return Err(GrothError::InvalidWitness(
                "Number of public inputs must be less than total assignment length".to_string()
            ));
        }
        
        // Ensure first element is 1 (constant)
        if assignment.is_empty() || assignment[0] != <F as FieldLike>::one() {
            return Err(GrothError::InvalidWitness(
                "First element of assignment must be 1 (constant)".to_string()
            ));
        }
        
        Ok(Self {
            assignment,
            num_public,
        })
    }
    
    /// Get public inputs (excluding constant)
    pub fn public_inputs(&self) -> &[F] {
        &self.assignment[1..=self.num_public]
    }
    
    /// Get private inputs
    pub fn private_inputs(&self) -> &[F] {
        &self.assignment[self.num_public + 1..]
    }
    
    /// Validate witness against QAP
    pub fn validate(&self, qap: &QAP<F>) -> Result<(), GrothError> {
        if self.assignment.len() != qap.num_variables {
            return Err(GrothError::InvalidWitness(format!(
                "Assignment length {} does not match QAP variables {}",
                self.assignment.len(), qap.num_variables
            )));
        }
        
        // Check that witness satisfies QAP at domain points
        let omega = qap.domain.group_gen();
        let eval = qap.evaluate_at(omega, &self.assignment)?;
        
        if !qap.verify_evaluation(&eval) {
            return Err(GrothError::InvalidWitness(
                "Witness does not satisfy QAP constraints".to_string()
            ));
        }
        
        Ok(())
    }
}

/// Groth16 prover
pub struct Prover;

impl Prover {
    /// Generate a proof for the given witness and proving key
    pub fn prove<F, R>(
        pk: &ProvingKey<F>,
        witness: &Witness<F>,
        rng: &mut R,
    ) -> Result<Proof, GrothError>
    where
        F: FieldLike + PrimeField,
        R: Rng + ?Sized,
    {
        // Validate witness
        witness.validate(&pk.qap)?;
        
        // Generate random elements
        let r = Fr::rand(rng);
        let s = Fr::rand(rng);
        
        // Convert field elements to Fr for group operations
        let assignment_fr: Vec<Fr> = witness.assignment.iter()
            .map(|&x| {
                let x_bigint = x.into_bigint();
                Fr::from(x_bigint.as_ref()[0])
            })
            .collect();
        
        // Compute π_A = α + Σ a_i(s) * w_i + r * δ
        let mut a_contributions: Vec<(Fr, G1Affine)> = Vec::new();
        
        // Add α term
        a_contributions.push((ark_ff::One::one(), pk.alpha_g1));
        
        // Add witness terms
        for (i, &w_i) in assignment_fr.iter().enumerate() {
            if !ark_ff::Zero::is_zero(&w_i) && i < pk.a_g1.len() {
                a_contributions.push((w_i, pk.a_g1[i]));
            }
        }
        
        // Add random term r * δ
        a_contributions.push((r, pk.delta_g1));
        
        let pi_a = Self::multi_scalar_mult_g1(&a_contributions)?;
        
        // Compute π_B = β + Σ b_i(s) * w_i + s * δ
        let mut b_contributions: Vec<(Fr, G2Affine)> = Vec::new();
        
        // Add β term
        b_contributions.push((ark_ff::One::one(), pk.beta_g2));
        
        // Add witness terms
        for (i, &w_i) in assignment_fr.iter().enumerate() {
            if !ark_ff::Zero::is_zero(&w_i) && i < pk.b_g2.len() {
                b_contributions.push((w_i, pk.b_g2[i]));
            }
        }
        
        // Add random term s * δ
        b_contributions.push((s, pk.delta_g2));
        
        let pi_b = Self::multi_scalar_mult_g2(&b_contributions)?;
        
        // Compute quotient polynomial H(x)
        let h_poly = pk.qap.compute_quotient_polynomial(&witness.assignment)?;
        
        // Evaluate H at powers of s (using precomputed values)
        let h_coeffs: Vec<Fr> = h_poly.coeffs().iter()
            .map(|&c| {
                let c_bigint = c.into_bigint();
                Fr::from(c_bigint.as_ref()[0])
            })
            .collect();
        
        // Compute [H(s)]₁ using precomputed powers
        let h_contributions: Vec<(Fr, G1Affine)> = h_coeffs.iter()
            .zip(pk.h_g1.iter())
            .filter(|(&coeff, _)| !ark_ff::Zero::is_zero(&coeff))
            .map(|(&coeff, &point)| (coeff, point))
            .collect();
        
        let h_s_g1 = if h_contributions.is_empty() {
            G1Projective::zero().into_affine()
        } else {
            Self::multi_scalar_mult_g1(&h_contributions)?
        };
        
        // Compute π_C = Σ_{i∈private} [(β*A_i(s) + α*B_i(s) + C_i(s))/δ] * w_i + H(s) + s*π_A + r*π_B'
        let mut c_contributions: Vec<(Fr, G1Affine)> = Vec::new();
        
        // Add private variable contributions
        for i in (pk.num_public + 1)..assignment_fr.len() {
            let w_i = assignment_fr[i];
            if !ark_ff::Zero::is_zero(&w_i) && (i - pk.num_public - 1) < pk.ic_g1.len() {
                c_contributions.push((w_i, pk.ic_g1[i - pk.num_public - 1]));
            }
        }
        
        // Add H(s) term
        if !ark_ec::AffineRepr::is_zero(&h_s_g1) {
            c_contributions.push((ark_ff::One::one(), h_s_g1));
        }
        
        // Add s * π_A term
        if !ark_ec::AffineRepr::is_zero(&pi_a) {
            c_contributions.push((s, pi_a));
        }
        
        // Add r * π_B' term (convert π_B from G2 to G1)
        // For this we need [B(s)]₁ computation
        let mut b1_contributions: Vec<(Fr, G1Affine)> = Vec::new();
        b1_contributions.push((ark_ff::One::one(), pk.beta_g1));
        
        for (i, &w_i) in assignment_fr.iter().enumerate() {
            if !ark_ff::Zero::is_zero(&w_i) && i < pk.b_g1.len() {
                b1_contributions.push((w_i, pk.b_g1[i]));
            }
        }
        
        let pi_b_g1 = Self::multi_scalar_mult_g1(&b1_contributions)?;
        
        if !ark_ec::AffineRepr::is_zero(&pi_b_g1) {
            c_contributions.push((r, pi_b_g1));
        }
        
        let pi_c = if c_contributions.is_empty() {
            G1Projective::zero().into_affine()
        } else {
            Self::multi_scalar_mult_g1(&c_contributions)?
        };
        
        Ok(Proof {
            a: pi_a,
            b: pi_b,
            c: pi_c,
        })
    }
    
    /// Optimized multi-scalar multiplication for G1
    fn multi_scalar_mult_g1(points_scalars: &[(Fr, G1Affine)]) -> Result<G1Affine, GrothError> {
        if points_scalars.is_empty() {
            return Ok(G1Projective::zero().into_affine());
        }
        
        let (scalars, points): (Vec<_>, Vec<_>) = points_scalars.iter().cloned().unzip();
        
        let result = G1Projective::msm(&points, &scalars)
            .map_err(|e| GrothError::MSMError(format!("G1 MSM failed: {:?}", e)))?;
        
        Ok(result.into_affine())
    }
    
    /// Optimized multi-scalar multiplication for G2
    fn multi_scalar_mult_g2(points_scalars: &[(Fr, G2Affine)]) -> Result<G2Affine, GrothError> {
        if points_scalars.is_empty() {
            return Ok(G2Projective::zero().into_affine());
        }
        
        let (scalars, points): (Vec<_>, Vec<_>) = points_scalars.iter().cloned().unzip();
        
        let result = G2Projective::msm(&points, &scalars)
            .map_err(|e| GrothError::MSMError(format!("G2 MSM failed: {:?}", e)))?;
        
        Ok(result.into_affine())
    }
}

/// Groth16 verifier
pub struct Verifier;

impl Verifier {
    /// Verify a proof against the verification key and public inputs
    pub fn verify<F>(
        vk: &VerificationKey,
        proof: &Proof,
        public_inputs: &[F],
    ) -> Result<bool, GrothError>
    where
        F: FieldLike + PrimeField,
    {
        if public_inputs.len() != vk.num_public {
            return Err(GrothError::InvalidWitness(format!(
                "Expected {} public inputs, got {}",
                vk.num_public, public_inputs.len()
            )));
        }
        
        // Convert public inputs to Fr
        let public_inputs_fr: Vec<Fr> = public_inputs.iter()
            .map(|&x| {
                let x_bigint = x.into_bigint();
                Fr::from(x_bigint.as_ref()[0])
            })
            .collect();
        
        // Compute [IC]₁ = IC₀ + Σ public_input_i * IC_i
        let mut ic_contributions: Vec<(Fr, G1Affine)> = vec![(ark_ff::One::one(), vk.ic_g1[0])];
        
        for (i, &input) in public_inputs_fr.iter().enumerate() {
            if !ark_ff::Zero::is_zero(&input) {
                ic_contributions.push((input, vk.ic_g1[i + 1]));
            }
        }
        
        let ic_g1 = Prover::multi_scalar_mult_g1(&ic_contributions)?;
        
        // Pairing check: e(π_A, π_B) = e(α, β) * e(IC, γ) * e(π_C, δ)
        // Rearranged as: e(π_A, π_B) * e(-α, β) * e(-IC, γ) * e(-π_C, δ) = 1
        
        let alpha_neg = (-G1Projective::from(vk.alpha_g1)).into_affine();
        let ic_neg = (-G1Projective::from(ic_g1)).into_affine();
        let c_neg = (-G1Projective::from(proof.c)).into_affine();
        
        let g1_inputs = [proof.a, alpha_neg, ic_neg, c_neg];
        let g2_inputs = [proof.b, vk.beta_g2, vk.gamma_g2, vk.delta_g2];
        
        let result = Bls12_381::multi_pairing(&g1_inputs, &g2_inputs);
        
        Ok(result.is_zero())
    }
}

/// Batch verification for multiple proofs
pub struct BatchVerifier;

impl BatchVerifier {
    /// Verify multiple proofs with random linear combination
    pub fn verify_batch<F, R>(
        vk: &VerificationKey,
        proofs_and_inputs: &[(Proof, Vec<F>)],
        rng: &mut R,
    ) -> Result<bool, GrothError>
    where
        F: FieldLike + PrimeField,
        R: Rng + ?Sized,
    {
        if proofs_and_inputs.is_empty() {
            return Ok(true);
        }
        
        // Generate random coefficients for batching
        let batch_coeffs: Vec<Fr> = (0..proofs_and_inputs.len())
            .map(|_| Fr::rand(rng))
            .collect();
        
        // Accumulate proofs with random coefficients
        let mut a_acc = G1Projective::zero();
        let mut b_acc = G2Projective::zero();
        let mut c_acc = G1Projective::zero();
        let mut ic_acc = G1Projective::zero();
        
        for ((proof, public_inputs), &coeff) in proofs_and_inputs.iter().zip(&batch_coeffs) {
            // Verify input length
            if public_inputs.len() != vk.num_public {
                return Err(GrothError::InvalidWitness(format!(
                    "Expected {} public inputs, got {}",
                    vk.num_public, public_inputs.len()
                )));
            }
            
            // Accumulate proof elements
            a_acc += G1Projective::from(proof.a) * coeff;
            b_acc += G2Projective::from(proof.b) * coeff;
            c_acc += G1Projective::from(proof.c) * coeff;
            
            // Compute IC for this proof
            let public_inputs_fr: Vec<Fr> = public_inputs.iter()
                .map(|&x| {
                    let x_bigint = x.into_bigint();
                    Fr::from(x_bigint.as_ref()[0])
                })
                .collect();
            
            let mut ic_contributions: Vec<(Fr, G1Affine)> = vec![(ark_ff::One::one(), vk.ic_g1[0])];
            
            for (i, &input) in public_inputs_fr.iter().enumerate() {
                if !ark_ff::Zero::is_zero(&input) {
                    ic_contributions.push((input, vk.ic_g1[i + 1]));
                }
            }
            
            let ic_g1 = Prover::multi_scalar_mult_g1(&ic_contributions)?;
            ic_acc += G1Projective::from(ic_g1) * coeff;
        }
        
        // Perform batch pairing check
        let alpha_neg = (-G1Projective::from(vk.alpha_g1)).into_affine();
        let ic_neg = (-ic_acc).into_affine();
        let c_neg = (-c_acc).into_affine();
        
        let g1_inputs = [a_acc.into_affine(), alpha_neg, ic_neg, c_neg];
        let g2_inputs = [b_acc.into_affine(), vk.beta_g2, vk.gamma_g2, vk.delta_g2];
        
        let result = Bls12_381::multi_pairing(&g1_inputs, &g2_inputs);
        
        Ok(result.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_field::F;
    use groth16_r1cs::{R1CS, LinearCombination};
    use groth16_qap::QAP;
    use groth16_setup::CRS;
    use rand::thread_rng;
    
    #[test]
    fn test_simple_proof() {
        // Create R1CS: x * y = z with x = 3, y = 4, z = 12
        let mut r1cs = R1CS::<F>::new(0);
        let x = r1cs.allocate_variable();
        let y = r1cs.allocate_variable();
        let z = r1cs.allocate_variable();
        
        r1cs.enforce_multiplication(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(y),
            LinearCombination::from_variable(z)
        );
        
        let qap = QAP::from_r1cs(&r1cs).unwrap();
        
        // Generate CRS with x as public input
        let mut rng = thread_rng();
        let crs = CRS::generate_random(&qap, 1, &mut rng).unwrap();
        
        // Create witness: [1, 3, 4, 12] with x=3 public
        let assignment = vec![
            <F as FieldLike>::one(),     // constant
            F::from(3u64), // x (public)
            F::from(4u64), // y (private)
            F::from(12u64), // z (private)
        ];
        let witness = Witness::new(assignment, 1).unwrap();
        
        // Generate proof
        let proof = Prover::prove(&crs.pk, &witness, &mut rng).unwrap();
        
        // Verify proof
        let public_inputs = vec![F::from(3u64)]; // x = 3
        let is_valid = Verifier::verify(&crs.vk, &proof, &public_inputs).unwrap();
        
        assert!(is_valid);
    }
    
    #[test]
    fn test_invalid_proof() {
        // Create simple circuit
        let mut r1cs = R1CS::<F>::new(0);
        let x = r1cs.allocate_variable();
        let y = r1cs.allocate_variable();
        let z = r1cs.allocate_variable();
        
        r1cs.enforce_multiplication(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(y),
            LinearCombination::from_variable(z)
        );
        
        let qap = QAP::from_r1cs(&r1cs).unwrap();
        let mut rng = thread_rng();
        let crs = CRS::generate_random(&qap, 1, &mut rng).unwrap();
        
        // Create valid proof
        let assignment = vec![<F as FieldLike>::one(), F::from(3u64), F::from(4u64), F::from(12u64)];
        let witness = Witness::new(assignment, 1).unwrap();
        let proof = Prover::prove(&crs.pk, &witness, &mut rng).unwrap();
        
        // Try to verify with wrong public input
        let wrong_public_inputs = vec![F::from(5u64)]; // Should be 3
        let is_valid = Verifier::verify(&crs.vk, &proof, &wrong_public_inputs).unwrap();
        
        assert!(!is_valid);
    }
    
    #[test]
    fn test_batch_verification() {
        // Create simple circuit
        let mut r1cs = R1CS::<F>::new(0);
        let x = r1cs.allocate_variable();
        let y = r1cs.allocate_variable();
        let z = r1cs.allocate_variable();
        
        r1cs.enforce_multiplication(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(y),
            LinearCombination::from_variable(z)
        );
        
        let qap = QAP::from_r1cs(&r1cs).unwrap();
        let mut rng = thread_rng();
        let crs = CRS::generate_random(&qap, 1, &mut rng).unwrap();
        
        // Generate multiple proofs
        let test_cases = vec![
            (3u64, 4u64, 12u64),
            (5u64, 6u64, 30u64),
            (2u64, 8u64, 16u64),
        ];
        
        let mut proofs_and_inputs = Vec::new();
        
        for (x_val, y_val, z_val) in test_cases {
            let assignment = vec![
                <F as FieldLike>::one(),
                F::from(x_val),
                F::from(y_val),
                F::from(z_val),
            ];
            let witness = Witness::new(assignment, 1).unwrap();
            let proof = Prover::prove(&crs.pk, &witness, &mut rng).unwrap();
            let public_inputs = vec![F::from(x_val)];
            
            proofs_and_inputs.push((proof, public_inputs));
        }
        
        // Verify batch
        let is_valid = BatchVerifier::verify_batch(&crs.vk, &proofs_and_inputs, &mut rng).unwrap();
        assert!(is_valid);
    }
}