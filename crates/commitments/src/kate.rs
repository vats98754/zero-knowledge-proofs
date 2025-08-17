//! Kate polynomial commitment scheme with batch opening support

use crate::{traits::*, Result, CommitmentError};
use zkp_field::{Scalar, polynomial::PolynomialOps, batch::BatchOps};
use ark_ec::{CurveGroup, Group, VariableBaseMSM};
use ark_bls12_381::{G1Projective, G2Projective, Bls12_381};
use ark_ec::pairing::Pairing;
use ark_ff::{Zero, One, UniformRand, Field};
use ark_std::rand::Rng;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rayon::prelude::*;
use std::collections::HashMap;

/// Kate commitment engine with batch opening support
#[derive(Clone, Debug)]
pub struct KateCommitmentEngine;

/// Kate commitment parameters (extends KZG with additional structure)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KateParams {
    /// Powers of the secret in G1 for commitments
    pub g1_powers: Vec<G1Projective>,
    /// Powers of the secret in G2 for verification
    pub g2_powers: Vec<G2Projective>,
    /// Maximum degree supported
    pub max_degree: usize,
    /// Precomputed Lagrange basis for common point sets
    pub lagrange_cache: HashMap<Vec<Scalar>, Vec<Vec<Scalar>>>,
}

/// Kate commitment (same as KZG)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KateCommitment(pub G1Projective);

/// Kate opening proof with batch support
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KateOpening {
    /// Main proof element
    pub proof: G1Projective,
    /// Additional proof elements for batch opening
    pub batch_proofs: Vec<G1Projective>,
}

/// Kate aggregate opening for multiple points
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KateAggregateOpening {
    /// Aggregated proof
    pub proof: G1Projective,
    /// Random challenges used in aggregation
    pub challenges: Vec<Scalar>,
}

/// Kate randomness (can include blinding factors)
#[derive(Clone, Debug)]
pub struct KateRandomness {
    /// Blinding factor for hiding commitments
    pub blinding_factor: Option<Scalar>,
}

impl Default for KateRandomness {
    fn default() -> Self {
        Self {
            blinding_factor: None,
        }
    }
}

impl CommitmentEngine for KateCommitmentEngine {
    type Commitment = KateCommitment;
    type Opening = KateOpening;
    type Parameters = KateParams;
    type Randomness = KateRandomness;
    
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
        
        // Generate more G2 powers for Kate (needed for batch verification)
        let g2 = G2Projective::generator();
        let mut g2_powers = Vec::with_capacity(max_degree + 1);
        current_power = Scalar::one();
        for _ in 0..=max_degree.min(10) { // Limit G2 powers for efficiency
            g2_powers.push(g2 * current_power);
            current_power *= secret;
        }
        
        Ok(KateParams {
            g1_powers,
            g2_powers,
            max_degree,
            lagrange_cache: HashMap::new(),
        })
    }
    
    fn commit(
        params: &Self::Parameters,
        coefficients: &[Scalar],
        randomness: Option<&Self::Randomness>,
    ) -> Result<Self::Commitment> {
        if coefficients.len() > params.max_degree + 1 {
            return Err(CommitmentError::DegreeBoundExceeded);
        }
        
        let mut commitment = G1Projective::msm(
            &params.g1_powers[..coefficients.len()],
            coefficients,
        ).map_err(|_| CommitmentError::InvalidParameters)?;
        
        // Add blinding if randomness is provided
        if let Some(rand) = randomness {
            if let Some(blinding) = rand.blinding_factor {
                // Add random element (would need additional setup for proper hiding)
                commitment += params.g1_powers[0] * blinding;
            }
        }
        
        Ok(KateCommitment(commitment))
    }
    
    fn open(
        params: &Self::Parameters,
        coefficients: &[Scalar],
        point: &Scalar,
        randomness: Option<&Self::Randomness>,
    ) -> Result<Self::Opening> {
        if coefficients.len() > params.max_degree + 1 {
            return Err(CommitmentError::DegreeBoundExceeded);
        }
        
        // Evaluate polynomial at the given point
        let polynomial = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(coefficients.to_vec());
        let value = PolynomialOps::evaluate(&polynomial, point);
        
        // Compute quotient polynomial q(x) = (p(x) - p(z)) / (x - z)
        let quotient_coeffs = Self::compute_quotient_polynomial(coefficients, point, &value)?;
        
        // Compute main proof
        let proof = G1Projective::msm(
            &params.g1_powers[..quotient_coeffs.len()],
            &quotient_coeffs,
        ).map_err(|_| CommitmentError::InvalidParameters)?;
        
        Ok(KateOpening {
            proof,
            batch_proofs: vec![], // Single opening doesn't need batch proofs
        })
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
        let rhs = Bls12_381::pairing(opening.proof, rhs_g2);
        
        lhs == rhs
    }
    
    fn batch_commit(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        randomness: Option<&[Self::Randomness]>,
    ) -> Result<Vec<Self::Commitment>> {
        polynomials.par_iter()
            .enumerate()
            .map(|(i, coeffs)| {
                let rand = randomness.and_then(|r| r.get(i));
                Self::commit(params, coeffs, rand)
            })
            .collect()
    }
    
    fn batch_open(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        point: &Scalar,
        randomness: Option<&[Self::Randomness]>,
    ) -> Result<Self::Opening> {
        if polynomials.is_empty() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        // For Kate, we can efficiently batch openings at the same point
        let mut batch_proofs = Vec::new();
        let mut combined_quotient = vec![Scalar::zero(); params.max_degree];
        
        for (i, coeffs) in polynomials.iter().enumerate() {
            // Evaluate polynomial at point
            let polynomial = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(coeffs.to_vec());
            let value = PolynomialOps::evaluate(&polynomial, point);
            
            // Compute quotient polynomial
            let quotient_coeffs = Self::compute_quotient_polynomial(coeffs, point, &value)?;
            
            // Add to combined quotient with random challenge
            let challenge = Scalar::rand(&mut ark_std::test_rng()); // In practice, use Fiat-Shamir
            for (j, &coeff) in quotient_coeffs.iter().enumerate() {
                if j < combined_quotient.len() {
                    combined_quotient[j] += challenge.pow(&[i as u64]) * coeff;
                }
            }
            
            // Individual proof for this polynomial
            let individual_proof = G1Projective::msm(
                &params.g1_powers[..quotient_coeffs.len()],
                &quotient_coeffs,
            ).map_err(|_| CommitmentError::InvalidParameters)?;
            
            batch_proofs.push(individual_proof);
        }
        
        // Compute combined proof
        let proof = G1Projective::msm(
            &params.g1_powers[..combined_quotient.len()],
            &combined_quotient,
        ).map_err(|_| CommitmentError::InvalidParameters)?;
        
        Ok(KateOpening {
            proof,
            batch_proofs,
        })
    }
    
    fn batch_verify(
        params: &Self::Parameters,
        commitments: &[Self::Commitment],
        point: &Scalar,
        values: &[Scalar],
        opening: &Self::Opening,
    ) -> bool {
        if commitments.len() != values.len() || commitments.is_empty() {
            return false;
        }
        
        // For batch verification, combine commitments with random challenges
        let mut combined_commitment = G1Projective::zero();
        let mut combined_value = Scalar::zero();
        
        for (i, (commitment, value)) in commitments.iter().zip(values.iter()).enumerate() {
            let challenge = Scalar::rand(&mut ark_std::test_rng()); // In practice, use Fiat-Shamir
            combined_commitment += commitment.0 * challenge.pow(&[i as u64]);
            combined_value += *value * challenge.pow(&[i as u64]);
        }
        
        // Verify combined commitment
        let combined_kate_commitment = KateCommitment(combined_commitment);
        Self::verify(params, &combined_kate_commitment, point, &combined_value, opening)
    }
}

impl AggregateCommitmentEngine for KateCommitmentEngine {
    type AggregateOpening = KateAggregateOpening;
    
    fn aggregate_open(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        points: &[Scalar],
        _randomness: Option<&[Self::Randomness]>,
    ) -> Result<Self::AggregateOpening> {
        if polynomials.len() != points.len() || polynomials.is_empty() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        // Generate random challenges for aggregation
        let mut rng = ark_std::test_rng(); // In practice, use Fiat-Shamir
        let challenges: Vec<Scalar> = (0..polynomials.len())
            .map(|_| Scalar::rand(&mut rng))
            .collect();
        
        // Compute aggregated quotient polynomial
        let mut aggregated_quotient = vec![Scalar::zero(); params.max_degree];
        
        for (i, (&poly_coeffs, &point)) in polynomials.iter().zip(points.iter()).enumerate() {
            // Evaluate polynomial at point
            let polynomial = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(poly_coeffs.to_vec());
            let value = PolynomialOps::evaluate(&polynomial, &point);
            
            // Compute quotient polynomial
            let quotient_coeffs = Self::compute_quotient_polynomial(poly_coeffs, &point, &value)?;
            
            // Add to aggregated quotient with challenge
            let challenge = challenges[i];
            for (j, &coeff) in quotient_coeffs.iter().enumerate() {
                if j < aggregated_quotient.len() {
                    aggregated_quotient[j] += challenge * coeff;
                }
            }
        }
        
        // Compute aggregated proof
        let proof = G1Projective::msm(
            &params.g1_powers[..aggregated_quotient.len()],
            &aggregated_quotient,
        ).map_err(|_| CommitmentError::InvalidParameters)?;
        
        Ok(KateAggregateOpening {
            proof,
            challenges,
        })
    }
    
    fn aggregate_verify(
        params: &Self::Parameters,
        commitments: &[Self::Commitment],
        points: &[Scalar],
        values: &[Scalar],
        opening: &Self::AggregateOpening,
    ) -> bool {
        if commitments.len() != points.len() || 
           points.len() != values.len() || 
           values.len() != opening.challenges.len() ||
           commitments.is_empty() {
            return false;
        }
        
        // Aggregate commitments and points using the same challenges
        let mut aggregated_commitment = G1Projective::zero();
        let mut aggregated_value = Scalar::zero();
        
        for (i, ((commitment, &point), &value)) in commitments.iter()
            .zip(points.iter())
            .zip(values.iter())
            .enumerate() {
            let challenge = opening.challenges[i];
            aggregated_commitment += commitment.0 * challenge;
            aggregated_value += value * challenge;
        }
        
        // For multi-point verification, we need a more complex pairing check
        // This is a simplified version - full implementation would handle multiple points properly
        if points.iter().all(|&p| p == points[0]) {
            // All points are the same - can use simple verification
            let kate_commitment = KateCommitment(aggregated_commitment);
            let kate_opening = KateOpening {
                proof: opening.proof,
                batch_proofs: vec![],
            };
            return Self::verify(params, &kate_commitment, &points[0], &aggregated_value, &kate_opening);
        }
        
        // For different points, use vanishing polynomial approach
        Self::verify_multipoint_opening(params, commitments, points, values, opening)
    }
}

impl KateCommitmentEngine {
    /// Computes quotient polynomial (p(x) - p(z)) / (x - z)
    fn compute_quotient_polynomial(
        coefficients: &[Scalar],
        point: &Scalar,
        value: &Scalar,
    ) -> Result<Vec<Scalar>> {
        let polynomial = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(coefficients.to_vec());
        
        // Create p(x) - p(z)
        let mut shifted_coeffs = coefficients.to_vec();
        if !shifted_coeffs.is_empty() {
            shifted_coeffs[0] -= value;
        }
        
        // Divide by (x - z)
        let divisor = vec![-*point, Scalar::one()]; // (x - z)
        let dividend = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(shifted_coeffs);
        let divisor_poly = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(divisor);
        
        let (quotient, remainder) = PolynomialOps::long_division(&dividend, &divisor_poly)?;
        
        // Remainder should be zero
        if !remainder.coeffs().iter().all(|c| c.is_zero()) {
            return Err(CommitmentError::InvalidProof);
        }
        
        Ok(quotient.coeffs().to_vec())
    }
    
    /// Verifies multi-point opening using vanishing polynomial
    fn verify_multipoint_opening(
        params: &KateParams,
        commitments: &[KateCommitment],
        points: &[Scalar],
        values: &[Scalar],
        opening: &KateAggregateOpening,
    ) -> bool {
        // This is a placeholder for the full multi-point verification
        // In practice, this would involve computing the vanishing polynomial
        // for the set of points and using it in the pairing check
        
        // For now, fall back to individual verification
        for ((commitment, &point), &value) in commitments.iter().zip(points.iter()).zip(values.iter()) {
            let individual_opening = KateOpening {
                proof: opening.proof,
                batch_proofs: vec![],
            };
            if !KateCommitmentEngine::verify(params, commitment, &point, &value, &individual_opening) {
                return false;
            }
        }
        true
    }
}

impl KateParams {
    /// Precomputes Lagrange basis for a set of points
    pub fn precompute_lagrange_basis(&mut self, points: &[Scalar]) -> Result<()> {
        if points.len() > self.max_degree + 1 {
            return Err(CommitmentError::DegreeBoundExceeded);
        }
        
        let mut lagrange_basis = Vec::new();
        
        for i in 0..points.len() {
            let mut basis_poly = vec![Scalar::one()];
            
            for (j, &point_j) in points.iter().enumerate() {
                if i != j {
                    let point_i = points[i];
                    let denominator = point_i - point_j;
                    
                    if denominator.is_zero() {
                        return Err(CommitmentError::InvalidParameters);
                    }
                    
                    // Multiply by (x - point_j) / (point_i - point_j)
                    let mut new_basis = vec![Scalar::zero(); basis_poly.len() + 1];
                    
                    // Multiply by (x - point_j)
                    for (k, &coeff) in basis_poly.iter().enumerate() {
                        new_basis[k] -= coeff * point_j;
                        new_basis[k + 1] += coeff;
                    }
                    
                    // Divide by (point_i - point_j)
                    let inv_denom = denominator.inverse().ok_or(CommitmentError::InvalidParameters)?;
                    for coeff in &mut new_basis {
                        *coeff *= inv_denom;
                    }
                    
                    basis_poly = new_basis;
                }
            }
            
            lagrange_basis.push(basis_poly);
        }
        
        self.lagrange_cache.insert(points.to_vec(), lagrange_basis);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    
    #[test]
    fn test_kate_setup() {
        let mut rng = test_rng();
        let params = KateCommitmentEngine::setup(&mut rng, 10).unwrap();
        
        assert_eq!(params.g1_powers.len(), 11);
        assert!(params.g2_powers.len() >= 2);
        assert_eq!(params.max_degree, 10);
    }
    
    #[test]
    fn test_kate_commit_and_verify() {
        let mut rng = test_rng();
        let params = KateCommitmentEngine::setup(&mut rng, 10).unwrap();
        
        // Create polynomial: 3x^2 + 2x + 1
        let coeffs = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        
        // Commit
        let commitment = KateCommitmentEngine::commit(&params, &coeffs, None).unwrap();
        
        // Open at point 5
        let point = Scalar::from(5u64);
        let expected_value = Scalar::from(3u64) * Scalar::from(25u64) + 
                           Scalar::from(2u64) * Scalar::from(5u64) + 
                           Scalar::one();
        
        let opening = KateCommitmentEngine::open(&params, &coeffs, &point, None).unwrap();
        
        // Verify
        let is_valid = KateCommitmentEngine::verify(&params, &commitment, &point, &expected_value, &opening);
        assert!(is_valid);
    }
    
    #[test]
    fn test_kate_batch_operations() {
        let mut rng = test_rng();
        let params = KateCommitmentEngine::setup(&mut rng, 10).unwrap();
        
        let poly1 = vec![Scalar::one(), Scalar::from(2u64)]; // 2x + 1
        let poly2 = vec![Scalar::from(3u64), Scalar::from(4u64)]; // 4x + 3
        let polynomials = vec![&poly1[..], &poly2[..]];
        
        // Batch commit
        let commitments = KateCommitmentEngine::batch_commit(&params, &polynomials, None).unwrap();
        assert_eq!(commitments.len(), 2);
        
        // Batch open at same point
        let point = Scalar::from(7u64);
        let batch_opening = KateCommitmentEngine::batch_open(&params, &polynomials, &point, None).unwrap();
        
        // Evaluate polynomials at the point
        let value1 = Scalar::from(2u64) * Scalar::from(7u64) + Scalar::one(); // 15
        let value2 = Scalar::from(4u64) * Scalar::from(7u64) + Scalar::from(3u64); // 31
        let values = vec![value1, value2];
        
        // Verify batch opening
        let is_valid = KateCommitmentEngine::batch_verify(&params, &commitments, &point, &values, &batch_opening);
        assert!(is_valid);
    }
    
    #[test]
    fn test_kate_aggregate_opening() {
        let mut rng = test_rng();
        let params = KateCommitmentEngine::setup(&mut rng, 10).unwrap();
        
        let poly1 = vec![Scalar::one(), Scalar::from(2u64)]; // 2x + 1
        let poly2 = vec![Scalar::from(3u64), Scalar::from(4u64)]; // 4x + 3
        let polynomials = vec![&poly1[..], &poly2[..]];
        
        let point1 = Scalar::from(5u64);
        let point2 = Scalar::from(7u64);
        let points = vec![point1, point2];
        
        // Commit to polynomials
        let commitments = KateCommitmentEngine::batch_commit(&params, &polynomials, None).unwrap();
        
        // Aggregate opening at different points
        let aggregate_opening = KateCommitmentEngine::aggregate_open(&params, &polynomials, &points, None).unwrap();
        
        // Evaluate polynomials at their respective points
        let value1 = Scalar::from(2u64) * point1 + Scalar::one();
        let value2 = Scalar::from(4u64) * point2 + Scalar::from(3u64);
        let values = vec![value1, value2];
        
        // Verify aggregate opening
        let is_valid = KateCommitmentEngine::aggregate_verify(&params, &commitments, &points, &values, &aggregate_opening);
        assert!(is_valid);
    }
}