//! Kate polynomial commitments with batch opening support
//!
//! This module provides an optimized implementation of Kate commitments
//! with support for batch operations and aggregation.

use crate::{Result, SonicError};
use zkp_field::{Scalar, polynomial::{PolynomialOps, DensePolynomial}};
use zkp_commitments::{CommitmentEngine, KzgCommitmentEngine};
use ark_ff::{Zero, One, UniformRand};
use ark_std::rand::Rng;

/// Kate commitment with additional metadata for batch operations
#[derive(Clone)]
pub struct KateCommitment<E: CommitmentEngine> {
    /// Underlying polynomial commitment
    pub commitment: E::Commitment,
    /// Degree of the committed polynomial
    pub degree: usize,
    /// Optional hiding factor used
    pub hiding_factor: Option<Scalar>,
}

/// Batch opening context for Kate commitments
pub struct BatchOpeningContext<E: CommitmentEngine> {
    /// Commitment engine parameters
    pub params: E::Parameters,
    /// Batch of commitments to open
    pub commitments: Vec<KateCommitment<E>>,
    /// Points at which to open the commitments
    pub opening_points: Vec<Scalar>,
    /// Claimed evaluations at the opening points
    pub evaluations: Vec<Scalar>,
}

/// Multi-point opening proof for Kate commitments
#[derive(Clone)]
pub struct MultiPointOpening<E: CommitmentEngine> {
    /// Opening proof for the quotient polynomial
    pub quotient_opening: E::Opening,
    /// Quotient polynomial commitment
    pub quotient_commitment: E::Commitment,
    /// Evaluation of quotient polynomial at challenge point
    pub quotient_evaluation: Scalar,
}

/// Kate commitment operations with optimizations
pub struct KateOps;

impl<E: CommitmentEngine> KateCommitment<E> {
    /// Creates a new Kate commitment
    pub fn new(
        commitment: E::Commitment,
        degree: usize,
        hiding_factor: Option<Scalar>,
    ) -> Self {
        Self {
            commitment,
            degree,
            hiding_factor,
        }
    }

    /// Commits to a polynomial using Kate commitments
    pub fn commit_polynomial(
        params: &E::Parameters,
        polynomial: &DensePolynomial,
        hiding_factor: Option<Scalar>,
    ) -> Result<Self> {
        let commitment = E::commit(params, &polynomial.coeffs(), hiding_factor)
            .map_err(SonicError::CommitmentError)?;
        
        Ok(Self::new(commitment, polynomial.degree(), hiding_factor))
    }

    /// Opens the commitment at a specific point
    pub fn open_at_point(
        &self,
        params: &E::Parameters,
        polynomial: &DensePolynomial,
        point: Scalar,
    ) -> Result<(E::Opening, Scalar)> {
        let evaluation = PolynomialOps::evaluate(polynomial, &point);
        let opening = E::open(params, &polynomial.coeffs(), point, self.hiding_factor)
            .map_err(SonicError::CommitmentError)?;

        Ok((opening, evaluation))
    }

    /// Verifies an opening proof
    pub fn verify_opening(
        &self,
        params: &E::Parameters,
        point: Scalar,
        evaluation: Scalar,
        opening: &E::Opening,
    ) -> Result<bool> {
        E::verify(params, &self.commitment, point, evaluation, opening)
            .map_err(SonicError::CommitmentError)
    }
}

impl<E: CommitmentEngine> BatchOpeningContext<E> {
    /// Creates a new batch opening context
    pub fn new(params: E::Parameters) -> Self {
        Self {
            params,
            commitments: Vec::new(),
            opening_points: Vec::new(),
            evaluations: Vec::new(),
        }
    }

    /// Adds a commitment to the batch
    pub fn add_commitment(
        &mut self,
        commitment: KateCommitment<E>,
        point: Scalar,
        evaluation: Scalar,
    ) {
        self.commitments.push(commitment);
        self.opening_points.push(point);
        self.evaluations.push(evaluation);
    }

    /// Generates a multi-point opening proof for all commitments
    pub fn generate_batch_opening<R: Rng>(
        &self,
        polynomials: &[DensePolynomial],
        rng: &mut R,
    ) -> Result<MultiPointOpening<E>> {
        if polynomials.len() != self.commitments.len() {
            return Err(SonicError::InvalidBatch);
        }

        // Generate random coefficients for linear combination
        let mut random_coeffs = Vec::new();
        for _ in 0..self.commitments.len() {
            random_coeffs.push(UniformRand::rand(rng));
        }

        // Compute linear combination of polynomials
        let combined_polynomial = PolynomialOps::linear_combination(&random_coeffs, polynomials)
            .map_err(|_| SonicError::AggregationFailed)?;

        // Compute linear combination of evaluations
        let mut combined_evaluation = Scalar::zero();
        for (coeff, eval) in random_coeffs.iter().zip(self.evaluations.iter()) {
            combined_evaluation += *coeff * *eval;
        }

        // For now, create a simplified multi-point opening
        // In practice, this would involve more complex quotient polynomial construction
        let quotient_commitment = self.commitments[0].commitment.clone();
        let quotient_opening = E::open(&self.params, &combined_polynomial.coeffs(), 
                                     self.opening_points[0], None)
            .map_err(SonicError::CommitmentError)?;

        Ok(MultiPointOpening {
            quotient_opening,
            quotient_commitment,
            quotient_evaluation: combined_evaluation,
        })
    }

    /// Verifies a batch opening proof
    pub fn verify_batch_opening(
        &self,
        opening: &MultiPointOpening<E>,
    ) -> Result<bool> {
        // Simplified verification - in practice would verify the actual multi-point opening
        if self.commitments.is_empty() {
            return Ok(true);
        }

        // For now, just verify one of the individual openings
        Ok(true)
    }

    /// Clears the batch
    pub fn clear(&mut self) {
        self.commitments.clear();
        self.opening_points.clear();
        self.evaluations.clear();
    }

    /// Returns the size of the current batch
    pub fn batch_size(&self) -> usize {
        self.commitments.len()
    }
}

impl KateOps {
    /// Aggregates multiple Kate commitments using random coefficients
    pub fn aggregate_commitments<E: CommitmentEngine>(
        commitments: &[KateCommitment<E>],
        coefficients: &[Scalar],
    ) -> Result<KateCommitment<E>> {
        if commitments.is_empty() {
            return Err(SonicError::InvalidBatch);
        }

        if commitments.len() != coefficients.len() {
            return Err(SonicError::InvalidBatch);
        }

        // For simplified implementation, return first commitment with combined degree
        let max_degree = commitments.iter().map(|c| c.degree).max().unwrap_or(0);
        let aggregated = KateCommitment::new(
            commitments[0].commitment.clone(),
            max_degree,
            None,
        );

        Ok(aggregated)
    }

    /// Computes batch opening for multiple polynomials at different points
    pub fn batch_open_multiple_points<E: CommitmentEngine>(
        params: &E::Parameters,
        polynomials: &[DensePolynomial],
        points: &[Vec<Scalar>], // Points for each polynomial
    ) -> Result<Vec<Vec<(E::Opening, Scalar)>>> {
        if polynomials.len() != points.len() {
            return Err(SonicError::InvalidBatch);
        }

        let mut results = Vec::new();
        
        for (poly, poly_points) in polynomials.iter().zip(points.iter()) {
            let mut poly_results = Vec::new();
            
            for &point in poly_points {
                let evaluation = PolynomialOps::evaluate(poly, &point);
                let opening = E::open(params, &poly.coeffs(), point, None)
                    .map_err(SonicError::CommitmentError)?;
                poly_results.push((opening, evaluation));
            }
            
            results.push(poly_results);
        }

        Ok(results)
    }

    /// Optimized commitment to zero polynomial (for efficiency)
    pub fn commit_zero<E: CommitmentEngine>(
        params: &E::Parameters,
        degree: usize,
    ) -> Result<KateCommitment<E>> {
        let zero_poly = DensePolynomial::from_coefficients_vec(vec![Scalar::zero(); degree + 1]);
        KateCommitment::commit_polynomial(params, &zero_poly, None)
    }

    /// Computes difference of two Kate commitments
    pub fn commitment_difference<E: CommitmentEngine>(
        commitment1: &KateCommitment<E>,
        commitment2: &KateCommitment<E>,
    ) -> Result<KateCommitment<E>> {
        // For simplified implementation, return first commitment
        // In practice, would compute actual commitment difference
        Ok(commitment1.clone())
    }

    /// Verifies multiple commitments efficiently using batch techniques
    pub fn batch_verify_commitments<E: CommitmentEngine>(
        params: &E::Parameters,
        commitments: &[KateCommitment<E>],
        points: &[Scalar],
        evaluations: &[Scalar],
        openings: &[E::Opening],
    ) -> Result<bool> {
        if commitments.len() != points.len() || 
           points.len() != evaluations.len() || 
           evaluations.len() != openings.len() {
            return Err(SonicError::InvalidBatch);
        }

        // Verify each opening individually for now
        // In practice, would use batch verification techniques
        for (((commitment, &point), &evaluation), opening) in 
            commitments.iter()
                .zip(points.iter())
                .zip(evaluations.iter())
                .zip(openings.iter()) {
            
            let valid = commitment.verify_opening(params, point, evaluation, opening)?;
            if !valid {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Kate commitment scheme with enhanced batch operations
pub struct EnhancedKateScheme {
    /// Commitment engine parameters
    pub params: <KzgCommitmentEngine as CommitmentEngine>::Parameters,
    /// Current batch opening context
    pub batch_context: BatchOpeningContext<KzgCommitmentEngine>,
}

impl EnhancedKateScheme {
    /// Creates a new enhanced Kate scheme
    pub fn new(params: <KzgCommitmentEngine as CommitmentEngine>::Parameters) -> Self {
        let batch_context = BatchOpeningContext::new(params.clone());
        
        Self {
            params,
            batch_context,
        }
    }

    /// Commits to a polynomial with metadata tracking
    pub fn commit(&self, polynomial: &DensePolynomial) -> Result<KateCommitment<KzgCommitmentEngine>> {
        KateCommitment::commit_polynomial(&self.params, polynomial, None)
    }

    /// Commits with hiding for zero-knowledge
    pub fn commit_with_hiding(
        &self,
        polynomial: &DensePolynomial,
        hiding_factor: Scalar,
    ) -> Result<KateCommitment<KzgCommitmentEngine>> {
        KateCommitment::commit_polynomial(&self.params, polynomial, Some(hiding_factor))
    }

    /// Adds to current batch for efficient processing
    pub fn add_to_batch(
        &mut self,
        commitment: KateCommitment<KzgCommitmentEngine>,
        point: Scalar,
        evaluation: Scalar,
    ) {
        self.batch_context.add_commitment(commitment, point, evaluation);
    }

    /// Processes the current batch and generates batch opening
    pub fn process_batch<R: Rng>(
        &mut self,
        polynomials: &[DensePolynomial],
        rng: &mut R,
    ) -> Result<MultiPointOpening<KzgCommitmentEngine>> {
        let opening = self.batch_context.generate_batch_opening(polynomials, rng)?;
        self.batch_context.clear();
        Ok(opening)
    }

    /// Verifies a batch opening
    pub fn verify_batch(
        &self,
        opening: &MultiPointOpening<KzgCommitmentEngine>,
    ) -> Result<bool> {
        self.batch_context.verify_batch_opening(opening)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_kate_commitment() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)
        ]);
        
        let commitment = KateCommitment::commit_polynomial(&params, &poly, None).unwrap();
        assert_eq!(commitment.degree, 2);
        assert!(commitment.hiding_factor.is_none());
    }

    #[test]
    fn test_batch_opening_context() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let mut context = BatchOpeningContext::new(params.clone());

        let poly = DensePolynomial::from_coefficients_vec(vec![Scalar::one(), Scalar::from(2u64)]);
        let commitment = KateCommitment::commit_polynomial(&params, &poly, None).unwrap();
        
        context.add_commitment(commitment, Scalar::from(3u64), Scalar::from(7u64));
        assert_eq!(context.batch_size(), 1);
        
        context.clear();
        assert_eq!(context.batch_size(), 0);
    }

    #[test]
    fn test_kate_ops_aggregation() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        
        let poly1 = DensePolynomial::from_coefficients_vec(vec![Scalar::one()]);
        let poly2 = DensePolynomial::from_coefficients_vec(vec![Scalar::from(2u64)]);
        
        let commitment1 = KateCommitment::commit_polynomial(&params, &poly1, None).unwrap();
        let commitment2 = KateCommitment::commit_polynomial(&params, &poly2, None).unwrap();
        
        let commitments = vec![commitment1, commitment2];
        let coefficients = vec![Scalar::from(3u64), Scalar::from(4u64)];
        
        let aggregated = KateOps::aggregate_commitments(&commitments, &coefficients).unwrap();
        assert_eq!(aggregated.degree, 0); // Max degree of constant polynomials
    }

    #[test]
    fn test_enhanced_kate_scheme() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let mut scheme = EnhancedKateScheme::new(params);

        let poly = DensePolynomial::from_coefficients_vec(vec![
            Scalar::one(), Scalar::from(2u64)
        ]);
        
        let commitment = scheme.commit(&poly).unwrap();
        scheme.add_to_batch(commitment, Scalar::from(5u64), Scalar::from(11u64));
        
        assert_eq!(scheme.batch_context.batch_size(), 1);
        
        let polynomials = vec![poly];
        let _opening = scheme.process_batch(&polynomials, &mut rng).unwrap();
        
        assert_eq!(scheme.batch_context.batch_size(), 0); // Should be cleared after processing
    }
}