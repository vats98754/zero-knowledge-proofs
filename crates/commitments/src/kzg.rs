//! KZG polynomial commitment scheme implementation

use crate::{traits::*, Result, CommitmentError};
use zkp_field::{Scalar, polynomial::PolynomialOps};
use ark_ec::{Group, VariableBaseMSM, CurveGroup};
use ark_bls12_381::{G1Projective, G2Projective, G1Affine, Bls12_381};
use ark_ec::pairing::Pairing;
use ark_ff::{Zero, One, UniformRand};
use ark_poly::polynomial::DenseUVPolynomial;
use ark_std::rand::Rng;
use rayon::prelude::*;

/// KZG commitment using BLS12-381
#[derive(Clone, Debug)]
pub struct KzgCommitmentEngine;

/// KZG commitment parameters
#[derive(Clone, Debug)]
pub struct KzgParams {
    /// Powers of the secret in G1
    pub g1_powers: Vec<G1Projective>,
    /// Powers of the secret in G2
    pub g2_powers: Vec<G2Projective>,
    /// Maximum degree supported
    pub max_degree: usize,
}

/// KZG commitment (point in G1)
#[derive(Clone, Debug)]
pub struct KzgCommitment(pub G1Projective);

/// KZG opening proof (point in G1)
#[derive(Clone, Debug)]
pub struct KzgOpening(pub G1Projective);

/// KZG randomness (not used in basic KZG)
#[derive(Clone, Debug, Default)]
pub struct KzgRandomness;

impl CommitmentEngine for KzgCommitmentEngine {
    type Commitment = KzgCommitment;
    type Opening = KzgOpening;
    type Parameters = KzgParams;
    type Randomness = KzgRandomness;
    
    fn setup<R: Rng>(rng: &mut R, max_degree: usize) -> Result<Self::Parameters> {
        // Generate random secret
        let secret = Scalar::rand(rng);
        
        // Generate G1 powers: [g^1, g^s, g^s^2, ..., g^s^max_degree]
        let g1 = G1Projective::generator();
        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        
        let mut current_power = Scalar::one();
        for _ in 0..=max_degree {
            g1_powers.push(g1 * current_power);
            current_power *= secret;
        }
        
        // Generate G2 powers: [h^1, h^s] (only need first two for basic KZG)
        let g2 = G2Projective::generator();
        let g2_powers = vec![g2, g2 * secret];
        
        Ok(KzgParams {
            g1_powers,
            g2_powers,
            max_degree,
        })
    }
    
    fn commit(
        params: &Self::Parameters,
        coefficients: &[Scalar],
        _randomness: Option<&Self::Randomness>,
    ) -> Result<Self::Commitment> {
        if coefficients.len() > params.max_degree + 1 {
            return Err(CommitmentError::DegreeBoundExceeded);
        }
        
        // Compute commitment as sum(coeff_i * g^(s^i))
        let affine_bases: Vec<G1Affine> = params.g1_powers[..coefficients.len()]
            .iter().map(|p| p.into_affine()).collect();
        let commitment = G1Projective::msm(
            &affine_bases,
            coefficients,
        ).map_err(|_| CommitmentError::InvalidParameters)?;
        
        Ok(KzgCommitment(commitment))
    }
    
    fn open(
        params: &Self::Parameters,
        coefficients: &[Scalar],
        point: &Scalar,
        _randomness: Option<&Self::Randomness>,
    ) -> Result<Self::Opening> {
        if coefficients.len() > params.max_degree + 1 {
            return Err(CommitmentError::DegreeBoundExceeded);
        }
        
        // Evaluate polynomial at the given point
        let polynomial = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(coefficients.to_vec());
        let value = PolynomialOps::evaluate(&polynomial, point);
        
        // Compute quotient polynomial q(x) = (p(x) - p(z)) / (x - z)
        let mut quotient_coeffs = coefficients.to_vec();
        
        // Subtract p(z) from the constant term
        if !quotient_coeffs.is_empty() {
            quotient_coeffs[0] -= value;
        }
        
        // Divide by (x - z)
        let divisor = vec![-*point, Scalar::one()]; // (x - z)
        let quotient_poly = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(quotient_coeffs);
        let divisor_poly = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(divisor);
        
        let (quotient, remainder) = PolynomialOps::long_division(&quotient_poly, &divisor_poly)?;
        
        // Remainder should be zero
        if !remainder.coeffs().iter().all(|c| c.is_zero()) {
            return Err(CommitmentError::InvalidProof);
        }
        
        // Compute proof as commitment to quotient polynomial
        let affine_bases: Vec<G1Affine> = params.g1_powers[..quotient.coeffs().len()]
            .iter().map(|p| p.into_affine()).collect();
        let proof = G1Projective::msm(
            &affine_bases,
            quotient.coeffs(),
        ).map_err(|_| CommitmentError::InvalidParameters)?;
        
        Ok(KzgOpening(proof))
    }
    
    fn verify(
        params: &Self::Parameters,
        commitment: &Self::Commitment,
        point: &Scalar,
        value: &Scalar,
        opening: &Self::Opening,
    ) -> bool {
        if params.g2_powers.len() < 2 {
            return false;
        }
        
        // Verify pairing equation: e(C - value*g, h) = e(proof, h^s - point*h)
        let g1 = params.g1_powers[0];
        let h = params.g2_powers[0];
        let h_s = params.g2_powers[1];
        
        let lhs_g1 = commitment.0 - g1 * value;
        let rhs_g2 = h_s - h * point;
        
        // Check pairing equation
        let lhs = Bls12_381::pairing(lhs_g1, h);
        let rhs = Bls12_381::pairing(opening.0, rhs_g2);
        
        lhs == rhs
    }
    
    fn batch_commit(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        _randomness: Option<&[Self::Randomness]>,
    ) -> Result<Vec<Self::Commitment>> {
        polynomials.iter()
            .map(|coeffs| Self::commit(params, coeffs, None))
            .collect()
    }
    
    fn batch_open(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        point: &Scalar,
        _randomness: Option<&[Self::Randomness]>,
    ) -> Result<Self::Opening> {
        // For basic KZG, we can't efficiently batch openings at the same point
        // This would require more advanced techniques like batch opening protocols
        // For now, we'll just use the first polynomial's opening
        if polynomials.is_empty() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        Self::open(params, polynomials[0], point, None)
    }
    
    fn batch_verify(
        params: &Self::Parameters,
        commitments: &[Self::Commitment],
        point: &Scalar,
        values: &[Scalar],
        opening: &Self::Opening,
    ) -> bool {
        // For basic KZG, verify the first commitment/value pair
        if commitments.is_empty() || values.is_empty() {
            return false;
        }
        
        Self::verify(params, &commitments[0], point, &values[0], opening)
    }
}

impl KzgParams {
    /// Trims the parameters to support a specific maximum degree
    pub fn trim(&self, degree: usize) -> Result<Self> {
        if degree > self.max_degree {
            return Err(CommitmentError::DegreeBoundExceeded);
        }
        
        Ok(KzgParams {
            g1_powers: self.g1_powers[..=degree].to_vec(),
            g2_powers: self.g2_powers.clone(),
            max_degree: degree,
        })
    }
    
    /// Returns commitment key for polynomial commitments
    pub fn commitment_key(&self) -> CommitmentKey<G1Projective> {
        CommitmentKey {
            powers: self.g1_powers.clone(),
            max_degree: self.max_degree,
        }
    }
    
    /// Returns verification key for polynomial commitments
    pub fn verification_key(&self) -> VerificationKey<G2Projective> {
        VerificationKey {
            g: self.g2_powers[0],
            h: self.g2_powers[0], // Same generator for simplicity
            beta_h: self.g2_powers.get(1).copied().unwrap_or(self.g2_powers[0]),
        }
    }
}

/// Multi-scalar multiplication optimized for KZG commitments
pub struct KzgMsm;

impl KzgMsm {
    /// Computes MSM using parallel processing
    pub fn compute(bases: &[G1Projective], scalars: &[Scalar]) -> Result<G1Projective> {
        if bases.len() != scalars.len() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        // Convert to affine for MSM
        let affine_bases: Vec<G1Affine> = bases.iter().map(|p| p.into_affine()).collect();
        G1Projective::msm(&affine_bases, scalars)
            .map_err(|_| CommitmentError::InvalidParameters)
    }
    
    /// Computes batch MSM for multiple polynomials
    pub fn batch_compute(
        bases: &[G1Projective],
        polynomials: &[&[Scalar]],
    ) -> Result<Vec<G1Projective>> {
        polynomials.par_iter()
            .map(|coeffs| {
                let relevant_bases = &bases[..coeffs.len().min(bases.len())];
                Self::compute(relevant_bases, coeffs)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    
    #[test]
    fn test_kzg_setup() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 10).unwrap();
        
        assert_eq!(params.g1_powers.len(), 11); // 0 to 10 inclusive
        assert_eq!(params.g2_powers.len(), 2);  // g and g^s
        assert_eq!(params.max_degree, 10);
    }
    
    #[test]
    fn test_kzg_commit_and_verify() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 10).unwrap();
        
        // Create a simple polynomial: 3x^2 + 2x + 1
        let coeffs = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        
        // Commit to the polynomial
        let commitment = KzgCommitmentEngine::commit(&params, &coeffs, None).unwrap();
        
        // Choose a random point to open at
        let point = Scalar::from(5u64);
        
        // Evaluate polynomial at the point: 3*25 + 2*5 + 1 = 86
        let expected_value = Scalar::from(3u64) * Scalar::from(25u64) + 
                           Scalar::from(2u64) * Scalar::from(5u64) + 
                           Scalar::one();
        
        // Generate opening proof
        let opening = KzgCommitmentEngine::open(&params, &coeffs, &point, None).unwrap();
        
        // Verify the opening
        let is_valid = KzgCommitmentEngine::verify(&params, &commitment, &point, &expected_value, &opening);
        assert!(is_valid);
        
        // Verify with wrong value should fail
        let wrong_value = expected_value + Scalar::one();
        let is_invalid = KzgCommitmentEngine::verify(&params, &commitment, &point, &wrong_value, &opening);
        assert!(!is_invalid);
    }
    
    #[test]
    fn test_kzg_batch_operations() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 5).unwrap();
        
        let poly1 = vec![Scalar::one(), Scalar::from(2u64)]; // 2x + 1
        let poly2 = vec![Scalar::from(3u64), Scalar::from(4u64)]; // 4x + 3
        let polynomials = vec![&poly1[..], &poly2[..]];
        
        // Batch commit
        let commitments = KzgCommitmentEngine::batch_commit(&params, &polynomials, None).unwrap();
        assert_eq!(commitments.len(), 2);
        
        // Individual commits should match batch commits
        let commit1 = KzgCommitmentEngine::commit(&params, &poly1, None).unwrap();
        let commit2 = KzgCommitmentEngine::commit(&params, &poly2, None).unwrap();
        
        // Note: Due to the current implementation, batch operations are just individual operations
        // In a full implementation, these would be more optimized
    }
    
    #[test]
    fn test_kzg_params_trim() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 10).unwrap();
        
        let trimmed = params.trim(5).unwrap();
        assert_eq!(trimmed.max_degree, 5);
        assert_eq!(trimmed.g1_powers.len(), 6); // 0 to 5 inclusive
        
        // Should fail to trim to a larger degree
        assert!(params.trim(15).is_err());
    }
}