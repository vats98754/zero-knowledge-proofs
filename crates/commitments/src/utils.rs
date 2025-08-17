//! Utility functions for polynomial commitments

use crate::{Result, CommitmentError};
use zkp_field::{Scalar, polynomial::PolynomialOps, batch::BatchOps};
use ark_ec::{CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Zero, One, Field};
use ark_std::rand::Rng;
use rayon::prelude::*;
use blake2::{Blake2s256, Digest};

/// Fiat-Shamir transcript for non-interactive challenges
pub struct FiatShamirTranscript {
    hasher: Blake2s256,
}

impl FiatShamirTranscript {
    /// Creates a new transcript
    pub fn new(label: &[u8]) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(label);
        Self { hasher }
    }
    
    /// Appends data to the transcript
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.hasher.update(label);
        self.hasher.update(&(message.len() as u64).to_le_bytes());
        self.hasher.update(message);
    }
    
    /// Appends a field element to the transcript
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        let bytes = scalar.into_bigint().to_bytes_le();
        self.append_message(label, &bytes[..32]);
    }
    
    /// Appends a curve point to the transcript
    pub fn append_point<G: CurveGroup>(&mut self, label: &[u8], point: &G) {
        let mut bytes = Vec::new();
        point.serialize_compressed(&mut bytes).unwrap();
        self.append_message(label, &bytes);
    }
    
    /// Generates a challenge from the current transcript
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        self.append_message(label, b"challenge");
        let hash = self.hasher.finalize_reset();
        
        // Convert hash to field element
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        Scalar::from_le_bytes_mod_order(&bytes)
    }
    
    /// Generates multiple challenges
    pub fn challenge_scalars(&mut self, label: &[u8], n: usize) -> Vec<Scalar> {
        (0..n).map(|i| {
            let mut extended_label = label.to_vec();
            extended_label.extend_from_slice(&i.to_le_bytes());
            self.challenge_scalar(&extended_label)
        }).collect()
    }
}

/// Multi-scalar multiplication utilities
pub struct MsmUtils;

impl MsmUtils {
    /// Performs parallel MSM computation
    pub fn parallel_msm<G: CurveGroup>(
        bases: &[G],
        scalars: &[Scalar],
        chunk_size: Option<usize>,
    ) -> Result<G> {
        if bases.len() != scalars.len() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        if bases.is_empty() {
            return Ok(G::zero());
        }
        
        let chunk_size = chunk_size.unwrap_or(1000);
        
        if bases.len() <= chunk_size {
            return G::msm(bases, scalars).map_err(|_| CommitmentError::InvalidParameters);
        }
        
        // Split into chunks and compute in parallel
        let result: Result<Vec<G>> = bases.par_chunks(chunk_size)
            .zip(scalars.par_chunks(chunk_size))
            .map(|(base_chunk, scalar_chunk)| {
                G::msm(base_chunk, scalar_chunk).map_err(|_| CommitmentError::InvalidParameters)
            })
            .collect();
        
        let chunks = result?;
        Ok(chunks.iter().fold(G::zero(), |acc, &x| acc + x))
    }
    
    /// Computes MSM with preprocessing for repeated base sets
    pub fn msm_with_precomputation<G: CurveGroup>(
        bases: &[G],
        scalars: &[Scalar],
        precomputed_tables: Option<&[G]>, // Placeholder for precomputation
    ) -> Result<G> {
        // In a full implementation, this would use precomputed tables
        // For now, fall back to regular MSM
        Self::parallel_msm(bases, scalars, None)
    }
}

/// Polynomial interpolation utilities
pub struct InterpolationUtils;

impl InterpolationUtils {
    /// Computes Lagrange coefficients for a set of points
    pub fn lagrange_coefficients(points: &[Scalar], evaluation_point: &Scalar) -> Result<Vec<Scalar>> {
        if points.is_empty() {
            return Ok(vec![]);
        }
        
        let n = points.len();
        let mut coefficients = vec![Scalar::zero(); n];
        
        for i in 0..n {
            let mut numerator = Scalar::one();
            let mut denominator = Scalar::one();
            
            for j in 0..n {
                if i != j {
                    numerator *= *evaluation_point - points[j];
                    denominator *= points[i] - points[j];
                }
            }
            
            if denominator.is_zero() {
                return Err(CommitmentError::InvalidParameters);
            }
            
            coefficients[i] = numerator * denominator.inverse().ok_or(CommitmentError::InvalidParameters)?;
        }
        
        Ok(coefficients)
    }
    
    /// Fast Lagrange interpolation for special point sets (e.g., roots of unity)
    pub fn fast_lagrange_interpolation(
        points: &[Scalar],
        values: &[Scalar],
    ) -> Result<Vec<Scalar>> {
        if points.len() != values.len() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        // For general points, use standard interpolation
        // In a full implementation, this would detect special structure (e.g., roots of unity)
        // and use FFT-based interpolation
        
        let point_value_pairs: Vec<(Scalar, Scalar)> = points.iter()
            .zip(values.iter())
            .map(|(&p, &v)| (p, v))
            .collect();
        
        let poly = PolynomialOps::interpolate(&point_value_pairs)?;
        Ok(poly.coeffs().to_vec())
    }
    
    /// Batch Lagrange coefficient computation
    pub fn batch_lagrange_coefficients(
        point_sets: &[&[Scalar]],
        evaluation_points: &[Scalar],
    ) -> Result<Vec<Vec<Scalar>>> {
        if point_sets.len() != evaluation_points.len() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        point_sets.par_iter()
            .zip(evaluation_points.par_iter())
            .map(|(points, eval_point)| Self::lagrange_coefficients(points, eval_point))
            .collect()
    }
}

/// Vanishing polynomial utilities
pub struct VanishingPolynomialUtils;

impl VanishingPolynomialUtils {
    /// Computes the vanishing polynomial for a set of points
    pub fn vanishing_polynomial(points: &[Scalar]) -> Vec<Scalar> {
        if points.is_empty() {
            return vec![Scalar::one()];
        }
        
        let mut result = vec![Scalar::one()];
        
        for &point in points {
            // Multiply by (x - point)
            let mut new_result = vec![Scalar::zero(); result.len() + 1];
            
            for (i, &coeff) in result.iter().enumerate() {
                new_result[i] -= coeff * point;
                new_result[i + 1] += coeff;
            }
            
            result = new_result;
        }
        
        result
    }
    
    /// Evaluates vanishing polynomial at a point
    pub fn evaluate_vanishing_polynomial(points: &[Scalar], evaluation_point: &Scalar) -> Scalar {
        points.iter().fold(Scalar::one(), |acc, &point| acc * (*evaluation_point - point))
    }
    
    /// Computes the vanishing polynomial's derivative
    pub fn vanishing_polynomial_derivative(points: &[Scalar]) -> Vec<Scalar> {
        let vanishing = Self::vanishing_polynomial(points);
        PolynomialOps::derivative(&zkp_field::polynomial::DensePolynomial::from_coefficients_vec(vanishing))
            .coeffs()
            .to_vec()
    }
    
    /// Fast vanishing polynomial evaluation for structured point sets
    pub fn fast_vanishing_evaluation(
        points: &[Scalar],
        evaluation_points: &[Scalar],
    ) -> Vec<Scalar> {
        evaluation_points.par_iter()
            .map(|eval_point| Self::evaluate_vanishing_polynomial(points, eval_point))
            .collect()
    }
}

/// Batch verification utilities
pub struct BatchVerificationUtils;

impl BatchVerificationUtils {
    /// Generates random challenges for batch verification
    pub fn generate_batch_challenges<R: Rng>(rng: &mut R, n: usize) -> Vec<Scalar> {
        (0..n).map(|_| Scalar::rand(rng)).collect()
    }
    
    /// Combines multiple commitments using random challenges
    pub fn combine_commitments<G: CurveGroup>(
        commitments: &[G],
        challenges: &[Scalar],
    ) -> Result<G> {
        if commitments.len() != challenges.len() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        MsmUtils::parallel_msm(commitments, challenges, None)
    }
    
    /// Combines multiple scalars using the same challenges
    pub fn combine_scalars(
        scalars: &[Scalar],
        challenges: &[Scalar],
    ) -> Result<Scalar> {
        if scalars.len() != challenges.len() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        Ok(BatchOps::inner_product(scalars, challenges)?)
    }
    
    /// Verifies multiple openings by combining them
    pub fn batch_verify_openings<G: CurveGroup>(
        commitments: &[G],
        points: &[Scalar],
        values: &[Scalar],
        proofs: &[G],
        challenges: &[Scalar],
    ) -> Result<(G, Scalar, G)> {
        if commitments.len() != points.len() || 
           points.len() != values.len() || 
           values.len() != proofs.len() ||
           proofs.len() != challenges.len() {
            return Err(CommitmentError::InvalidParameters);
        }
        
        let combined_commitment = Self::combine_commitments(commitments, challenges)?;
        let combined_value = Self::combine_scalars(values, challenges)?;
        let combined_proof = Self::combine_commitments(proofs, challenges)?;
        
        Ok((combined_commitment, combined_value, combined_proof))
    }
}

/// Degree bound utilities
pub struct DegreeBoundUtils;

impl DegreeBoundUtils {
    /// Verifies that a polynomial has degree at most d
    pub fn verify_degree_bound(
        coefficients: &[Scalar],
        degree_bound: usize,
    ) -> bool {
        if coefficients.len() > degree_bound + 1 {
            return false;
        }
        
        // Check that high-degree coefficients are zero
        for i in (degree_bound + 1)..coefficients.len() {
            if !coefficients[i].is_zero() {
                return false;
            }
        }
        
        true
    }
    
    /// Pads polynomial coefficients to a specific length
    pub fn pad_coefficients(coefficients: &[Scalar], length: usize) -> Vec<Scalar> {
        let mut padded = coefficients.to_vec();
        padded.resize(length, Scalar::zero());
        padded
    }
    
    /// Trims leading zeros from polynomial coefficients
    pub fn trim_coefficients(coefficients: &[Scalar]) -> Vec<Scalar> {
        let mut trimmed = coefficients.to_vec();
        while trimmed.len() > 1 && trimmed.last() == Some(&Scalar::zero()) {
            trimmed.pop();
        }
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_bls12_381::G1Projective;
    
    #[test]
    fn test_fiat_shamir_transcript() {
        let mut transcript1 = FiatShamirTranscript::new(b"test");
        let mut transcript2 = FiatShamirTranscript::new(b"test");
        
        let scalar = Scalar::from(42u64);
        transcript1.append_scalar(b"scalar", &scalar);
        transcript2.append_scalar(b"scalar", &scalar);
        
        let challenge1 = transcript1.challenge_scalar(b"challenge");
        let challenge2 = transcript2.challenge_scalar(b"challenge");
        
        assert_eq!(challenge1, challenge2);
    }
    
    #[test]
    fn test_lagrange_coefficients() {
        let points = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let eval_point = Scalar::from(4u64);
        
        let coeffs = InterpolationUtils::lagrange_coefficients(&points, &eval_point).unwrap();
        
        // Verify that the coefficients sum to 1 when evaluating the constant polynomial 1
        let sum: Scalar = coeffs.iter().sum();
        
        // For Lagrange interpolation, the sum should equal the evaluation of the constant polynomial 1
        // at the evaluation point, which is 1
        assert_eq!(sum, Scalar::one());
    }
    
    #[test]
    fn test_vanishing_polynomial() {
        let points = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let vanishing = VanishingPolynomialUtils::vanishing_polynomial(&points);
        
        // Verify that the vanishing polynomial evaluates to zero at all points
        for &point in &points {
            let poly = zkp_field::polynomial::DensePolynomial::from_coefficients_vec(vanishing.clone());
            let value = PolynomialOps::evaluate(&poly, &point);
            assert_eq!(value, Scalar::zero());
        }
    }
    
    #[test]
    fn test_msm_utils() {
        let mut rng = test_rng();
        let n = 100;
        
        let bases: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::rand(&mut rng)).collect();
        
        let result1 = MsmUtils::parallel_msm(&bases, &scalars, Some(10)).unwrap();
        let result2 = G1Projective::msm(&bases, &scalars).unwrap();
        
        assert_eq!(result1, result2);
    }
    
    #[test]
    fn test_batch_verification_utils() {
        let mut rng = test_rng();
        
        let commitments: Vec<G1Projective> = (0..5).map(|_| G1Projective::rand(&mut rng)).collect();
        let challenges: Vec<Scalar> = (0..5).map(|_| Scalar::rand(&mut rng)).collect();
        
        let combined = BatchVerificationUtils::combine_commitments(&commitments, &challenges).unwrap();
        
        // Verify manually
        let manual_combined = commitments.iter()
            .zip(challenges.iter())
            .fold(G1Projective::zero(), |acc, (c, r)| acc + *c * *r);
        
        assert_eq!(combined, manual_combined);
    }
    
    #[test]
    fn test_degree_bound_utils() {
        let coeffs = vec![Scalar::one(), Scalar::from(2u64), Scalar::zero(), Scalar::zero()];
        
        assert!(DegreeBoundUtils::verify_degree_bound(&coeffs, 3));
        assert!(DegreeBoundUtils::verify_degree_bound(&coeffs, 1)); // Only first two coeffs are non-zero
        assert!(!DegreeBoundUtils::verify_degree_bound(&coeffs, 0));
        
        let trimmed = DegreeBoundUtils::trim_coefficients(&coeffs);
        assert_eq!(trimmed.len(), 2);
        assert_eq!(trimmed, vec![Scalar::one(), Scalar::from(2u64)]);
    }
}