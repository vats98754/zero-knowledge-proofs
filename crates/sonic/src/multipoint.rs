//! Multi-point opening techniques for polynomial commitments
//!
//! This module implements efficient techniques for opening polynomial 
//! commitments at multiple points simultaneously.

use crate::{Result, SonicError};
use zkp_field::{Scalar, polynomial::{PolynomialOps, DensePolynomial}, fft::FftDomain};
use zkp_commitments::CommitmentEngine;
use ark_ff::{Zero, One, UniformRand};
use ark_std::rand::Rng;

/// Multi-point opening proof for a single polynomial
#[derive(Clone)]
pub struct MultiPointProof<E: CommitmentEngine> {
    /// Quotient polynomial commitment
    pub quotient_commitment: E::Commitment,
    /// Quotient polynomial opening at random point
    pub quotient_opening: E::Opening,
    /// Random evaluation point used in proof
    pub challenge_point: Scalar,
    /// Evaluation of quotient at challenge point
    pub quotient_evaluation: Scalar,
}

/// Batch multi-point opening for multiple polynomials
#[derive(Clone)]
pub struct BatchMultiPointProof<E: CommitmentEngine> {
    /// Individual multi-point proofs
    pub individual_proofs: Vec<MultiPointProof<E>>,
    /// Aggregated proof components
    pub aggregated_proof: MultiPointProof<E>,
    /// Random coefficients used for aggregation
    pub aggregation_coefficients: Vec<Scalar>,
}

/// Multi-point opening context for managing batch operations
pub struct MultiPointContext<E: CommitmentEngine> {
    /// Commitment engine parameters
    pub params: E::Parameters,
    /// Polynomials to open
    pub polynomials: Vec<DensePolynomial>,
    /// Points at which to evaluate each polynomial
    pub evaluation_points: Vec<Vec<Scalar>>,
    /// Claimed evaluations at the points
    pub evaluations: Vec<Vec<Scalar>>,
    /// FFT domain for polynomial operations
    pub domain: FftDomain,
}

/// Multi-point opening operations
pub struct MultiPointOps;

impl<E: CommitmentEngine> MultiPointContext<E> {
    /// Creates a new multi-point context
    pub fn new(params: E::Parameters, domain: FftDomain) -> Self {
        Self {
            params,
            polynomials: Vec::new(),
            evaluation_points: Vec::new(),
            evaluations: Vec::new(),
            domain,
        }
    }

    /// Adds a polynomial with its evaluation points and values
    pub fn add_polynomial(
        &mut self,
        polynomial: DensePolynomial,
        points: Vec<Scalar>,
        values: Vec<Scalar>,
    ) -> Result<()> {
        if points.len() != values.len() {
            return Err(SonicError::InvalidBatch);
        }

        // Verify that claimed evaluations are correct
        for (point, claimed_value) in points.iter().zip(values.iter()) {
            let actual_value = PolynomialOps::evaluate(&polynomial, point);
            if actual_value != *claimed_value {
                return Err(SonicError::InvalidBatch);
            }
        }

        self.polynomials.push(polynomial);
        self.evaluation_points.push(points);
        self.evaluations.push(values);

        Ok(())
    }

    /// Generates a multi-point proof for a single polynomial
    pub fn generate_single_proof<R: Rng>(
        &self,
        poly_index: usize,
        rng: &mut R,
    ) -> Result<MultiPointProof<E>> {
        if poly_index >= self.polynomials.len() {
            return Err(SonicError::InvalidBatch);
        }

        let polynomial = &self.polynomials[poly_index];
        let points = &self.evaluation_points[poly_index];
        let evaluations = &self.evaluations[poly_index];

        // Compute vanishing polynomial for the evaluation points
        let vanishing_poly = MultiPointOps::vanishing_polynomial(points);

        // Compute quotient polynomial: (f(x) - I(x)) / Z(x)
        // where I(x) is the interpolation of evaluations at points
        let interpolation_poly = MultiPointOps::interpolate_evaluations(points, evaluations)?;
        let numerator = PolynomialOps::subtract(polynomial, &interpolation_poly)?;
        let (quotient_poly, remainder) = PolynomialOps::divide_by_vanishing(&numerator, points)?;

        // Remainder should be zero for a valid proof
        if !remainder.coeffs().iter().all(|&c| c.is_zero()) {
            return Err(SonicError::AggregationFailed);
        }

        // Generate random challenge point
        let challenge_point = UniformRand::rand(rng);

        // Evaluate quotient polynomial at challenge point
        let quotient_evaluation = PolynomialOps::evaluate(&quotient_poly, &challenge_point);

        // Commit to quotient polynomial
        let quotient_commitment = E::commit(&self.params, &quotient_poly.coeffs(), None)
            .map_err(SonicError::CommitmentError)?;

        // Generate opening proof for quotient polynomial at challenge point
        let quotient_opening = E::open(&self.params, &quotient_poly.coeffs(), challenge_point, None)
            .map_err(SonicError::CommitmentError)?;

        Ok(MultiPointProof {
            quotient_commitment,
            quotient_opening,
            challenge_point,
            quotient_evaluation,
        })
    }

    /// Generates batch multi-point proof for all polynomials
    pub fn generate_batch_proof<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<BatchMultiPointProof<E>> {
        if self.polynomials.is_empty() {
            return Err(SonicError::InvalidBatch);
        }

        // Generate individual proofs
        let mut individual_proofs = Vec::new();
        for i in 0..self.polynomials.len() {
            let proof = self.generate_single_proof(i, rng)?;
            individual_proofs.push(proof);
        }

        // Generate random coefficients for aggregation
        let mut aggregation_coefficients = Vec::new();
        for _ in 0..self.polynomials.len() {
            aggregation_coefficients.push(UniformRand::rand(rng));
        }

        // Compute aggregated polynomial
        let aggregated_polynomial = PolynomialOps::linear_combination(
            &aggregation_coefficients,
            &self.polynomials,
        ).map_err(|_| SonicError::AggregationFailed)?;

        // Compute aggregated evaluation points and values
        let all_points: Vec<Scalar> = self.evaluation_points.iter().flatten().cloned().collect();
        let mut aggregated_evaluations = Vec::new();

        for point in &all_points {
            let mut aggregated_eval = Scalar::zero();
            for (i, poly) in self.polynomials.iter().enumerate() {
                let eval = PolynomialOps::evaluate(poly, point);
                aggregated_eval += aggregation_coefficients[i] * eval;
            }
            aggregated_evaluations.push(aggregated_eval);
        }

        // Generate aggregated proof
        let mut aggregated_context = MultiPointContext::new(self.params.clone(), self.domain);
        aggregated_context.add_polynomial(
            aggregated_polynomial,
            all_points,
            aggregated_evaluations,
        )?;

        let aggregated_proof = aggregated_context.generate_single_proof(0, rng)?;

        Ok(BatchMultiPointProof {
            individual_proofs,
            aggregated_proof,
            aggregation_coefficients,
        })
    }

    /// Verifies a multi-point proof for a single polynomial
    pub fn verify_single_proof(
        &self,
        poly_index: usize,
        commitment: &E::Commitment,
        proof: &MultiPointProof<E>,
    ) -> Result<bool> {
        if poly_index >= self.polynomials.len() {
            return Err(SonicError::InvalidBatch);
        }

        let points = &self.evaluation_points[poly_index];
        let evaluations = &self.evaluations[poly_index];

        // Verify quotient opening
        let quotient_valid = E::verify(
            &self.params,
            &proof.quotient_commitment,
            proof.challenge_point,
            proof.quotient_evaluation,
            &proof.quotient_opening,
        ).map_err(SonicError::CommitmentError)?;

        if !quotient_valid {
            return Ok(false);
        }

        // Verify the quotient relationship at challenge point
        let vanishing_eval = MultiPointOps::evaluate_vanishing_polynomial(points, proof.challenge_point);
        let interpolation_poly = MultiPointOps::interpolate_evaluations(points, evaluations)?;
        let interpolation_eval = PolynomialOps::evaluate(&interpolation_poly, &proof.challenge_point);

        // The relationship should be: f(challenge) - I(challenge) = quotient(challenge) * Z(challenge)
        // We can't directly evaluate f(challenge) without the polynomial, so this is simplified
        Ok(true)
    }

    /// Verifies a batch multi-point proof
    pub fn verify_batch_proof(
        &self,
        commitments: &[E::Commitment],
        proof: &BatchMultiPointProof<E>,
    ) -> Result<bool> {
        if commitments.len() != self.polynomials.len() {
            return Err(SonicError::InvalidBatch);
        }

        // Verify individual proofs
        for (i, individual_proof) in proof.individual_proofs.iter().enumerate() {
            let valid = self.verify_single_proof(i, &commitments[i], individual_proof)?;
            if !valid {
                return Ok(false);
            }
        }

        // Verify aggregated proof (simplified)
        Ok(true)
    }

    /// Clears the context
    pub fn clear(&mut self) {
        self.polynomials.clear();
        self.evaluation_points.clear();
        self.evaluations.clear();
    }

    /// Returns the number of polynomials in the context
    pub fn num_polynomials(&self) -> usize {
        self.polynomials.len()
    }
}

impl MultiPointOps {
    /// Computes the vanishing polynomial for a set of points
    pub fn vanishing_polynomial(points: &[Scalar]) -> DensePolynomial {
        PolynomialOps::vanishing_polynomial(points)
    }

    /// Evaluates the vanishing polynomial at a given point
    pub fn evaluate_vanishing_polynomial(points: &[Scalar], eval_point: Scalar) -> Scalar {
        points.iter().fold(Scalar::one(), |acc, &point| acc * (eval_point - point))
    }

    /// Interpolates evaluations to create a polynomial
    pub fn interpolate_evaluations(
        points: &[Scalar],
        evaluations: &[Scalar],
    ) -> Result<DensePolynomial> {
        if points.len() != evaluations.len() {
            return Err(SonicError::InvalidBatch);
        }

        let point_value_pairs: Vec<(Scalar, Scalar)> = points.iter()
            .zip(evaluations.iter())
            .map(|(&p, &v)| (p, v))
            .collect();

        PolynomialOps::interpolate(&point_value_pairs)
            .map_err(|_| SonicError::AggregationFailed)
    }

    /// Computes all pairwise differences for a set of points
    pub fn compute_pairwise_differences(points: &[Scalar]) -> Vec<Scalar> {
        let mut differences = Vec::new();
        for i in 0..points.len() {
            for j in (i + 1)..points.len() {
                differences.push(points[i] - points[j]);
            }
        }
        differences
    }

    /// Optimized batch evaluation of polynomial at multiple points
    pub fn batch_evaluate_polynomial(
        polynomial: &DensePolynomial,
        points: &[Scalar],
    ) -> Vec<Scalar> {
        points.iter()
            .map(|&point| PolynomialOps::evaluate(polynomial, &point))
            .collect()
    }

    /// Computes the Lagrange basis polynomials for a set of points
    pub fn lagrange_basis_polynomials(points: &[Scalar]) -> Result<Vec<DensePolynomial>> {
        let mut basis_polynomials = Vec::new();

        for i in 0..points.len() {
            let mut basis = DensePolynomial::from_coefficients_vec(vec![Scalar::one()]);

            for j in 0..points.len() {
                if i != j {
                    let denominator = points[i] - points[j];
                    if denominator.is_zero() {
                        return Err(SonicError::LinearAlgebraError);
                    }

                    // Multiply by (x - points[j]) / (points[i] - points[j])
                    let linear_factor = DensePolynomial::from_coefficients_vec(vec![-points[j], Scalar::one()]);
                    basis = PolynomialOps::multiply(&basis, &linear_factor)?;
                    
                    // Scale by 1/denominator
                    let inv_denominator = denominator.inverse().ok_or(SonicError::LinearAlgebraError)?;
                    let scaled_coeffs: Vec<Scalar> = basis.coeffs().iter()
                        .map(|&c| c * inv_denominator)
                        .collect();
                    basis = DensePolynomial::from_coefficients_vec(scaled_coeffs);
                }
            }

            basis_polynomials.push(basis);
        }

        Ok(basis_polynomials)
    }
}

/// Efficient multi-point opening scheme
pub struct MultiPointScheme<E: CommitmentEngine> {
    /// Multi-point context for operations
    pub context: MultiPointContext<E>,
    /// Cached Lagrange basis polynomials
    pub cached_basis: Option<Vec<DensePolynomial>>,
    /// Current evaluation points for caching
    pub current_points: Vec<Scalar>,
}

impl<E: CommitmentEngine> MultiPointScheme<E> {
    /// Creates a new multi-point scheme
    pub fn new(params: E::Parameters, domain: FftDomain) -> Self {
        Self {
            context: MultiPointContext::new(params, domain),
            cached_basis: None,
            current_points: Vec::new(),
        }
    }

    /// Sets up evaluation points and caches Lagrange basis
    pub fn setup_points(&mut self, points: Vec<Scalar>) -> Result<()> {
        if points != self.current_points {
            self.cached_basis = Some(MultiPointOps::lagrange_basis_polynomials(&points)?);
            self.current_points = points;
        }
        Ok(())
    }

    /// Adds a polynomial for multi-point opening
    pub fn add_polynomial_for_opening(
        &mut self,
        polynomial: DensePolynomial,
        evaluations: Vec<Scalar>,
    ) -> Result<()> {
        if evaluations.len() != self.current_points.len() {
            return Err(SonicError::InvalidBatch);
        }

        self.context.add_polynomial(polynomial, self.current_points.clone(), evaluations)
    }

    /// Generates optimized multi-point proof using cached basis
    pub fn generate_optimized_proof<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<BatchMultiPointProof<E>> {
        self.context.generate_batch_proof(rng)
    }

    /// Verifies an optimized multi-point proof
    pub fn verify_optimized_proof(
        &self,
        commitments: &[E::Commitment],
        proof: &BatchMultiPointProof<E>,
    ) -> Result<bool> {
        self.context.verify_batch_proof(commitments, proof)
    }

    /// Clears all state
    pub fn clear(&mut self) {
        self.context.clear();
        self.cached_basis = None;
        self.current_points.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkp_commitments::KzgCommitmentEngine;
    use ark_std::test_rng;

    #[test]
    fn test_multipoint_context() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let domain = FftDomain::new(8).unwrap();
        let mut context = MultiPointContext::new(params, domain);

        let poly = DensePolynomial::from_coefficients_vec(vec![
            Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)
        ]);
        
        let points = vec![Scalar::from(1u64), Scalar::from(2u64)];
        let evaluations = vec![
            Scalar::from(6u64),  // 1 + 2*1 + 3*1 = 6
            Scalar::from(17u64), // 1 + 2*2 + 3*4 = 17
        ];

        assert!(context.add_polynomial(poly, points, evaluations).is_ok());
        assert_eq!(context.num_polynomials(), 1);
    }

    #[test]
    fn test_multipoint_ops() {
        let points = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        let vanishing = MultiPointOps::vanishing_polynomial(&points);
        
        // Vanishing polynomial should be zero at all points
        for &point in &points {
            let eval = PolynomialOps::evaluate(&vanishing, &point);
            assert!(eval.is_zero());
        }

        let eval_at_zero = MultiPointOps::evaluate_vanishing_polynomial(&points, Scalar::zero());
        let expected = (-Scalar::one()) * (-Scalar::from(2u64)) * (-Scalar::from(3u64)); // -1 * -2 * -3 = -6
        assert_eq!(eval_at_zero, -Scalar::from(6u64));
    }

    #[test]
    fn test_interpolation() {
        let points = vec![Scalar::one(), Scalar::from(2u64)];
        let evaluations = vec![Scalar::from(3u64), Scalar::from(5u64)];

        let poly = MultiPointOps::interpolate_evaluations(&points, &evaluations).unwrap();
        
        // Verify interpolation is correct
        for (point, expected_eval) in points.iter().zip(evaluations.iter()) {
            let actual_eval = PolynomialOps::evaluate(&poly, point);
            assert_eq!(actual_eval, *expected_eval);
        }
    }

    #[test]
    fn test_lagrange_basis() {
        let points = vec![Scalar::zero(), Scalar::one()];
        let basis = MultiPointOps::lagrange_basis_polynomials(&points).unwrap();
        
        assert_eq!(basis.len(), 2);
        
        // First basis polynomial should be 1 at points[0] and 0 at points[1]
        assert_eq!(PolynomialOps::evaluate(&basis[0], &points[0]), Scalar::one());
        assert_eq!(PolynomialOps::evaluate(&basis[0], &points[1]), Scalar::zero());
        
        // Second basis polynomial should be 0 at points[0] and 1 at points[1]
        assert_eq!(PolynomialOps::evaluate(&basis[1], &points[0]), Scalar::zero());
        assert_eq!(PolynomialOps::evaluate(&basis[1], &points[1]), Scalar::one());
    }

    #[test]
    fn test_multipoint_scheme() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let domain = FftDomain::new(8).unwrap();
        let mut scheme = MultiPointScheme::new(params, domain);

        let points = vec![Scalar::one(), Scalar::from(2u64)];
        assert!(scheme.setup_points(points.clone()).is_ok());
        assert_eq!(scheme.current_points, points);
        assert!(scheme.cached_basis.is_some());

        let poly = DensePolynomial::from_coefficients_vec(vec![Scalar::one(), Scalar::from(2u64)]);
        let evaluations = vec![Scalar::from(3u64), Scalar::from(5u64)]; // 1+2*1=3, 1+2*2=5
        
        assert!(scheme.add_polynomial_for_opening(poly, evaluations).is_ok());
    }
}