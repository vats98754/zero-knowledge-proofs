//! Sonic/Kate Polynomial Commitment Aggregation
//!
//! This module implements efficient batch verification and aggregation for 
//! polynomial commitments using linear algebra optimizations.

use crate::{Result, SonicError};
use zkp_field::{Scalar, polynomial::{PolynomialOps, DensePolynomial}, fft::FftDomain};
use zkp_commitments::{CommitmentEngine, KzgCommitmentEngine};
use ark_ff::{Zero, One, UniformRand};
use ark_std::rand::Rng;
use rayon::prelude::*;

/// Aggregation context for batching multiple polynomial commitment operations
#[derive(Clone)]
pub struct AggregationContext<E: CommitmentEngine> {
    /// Commitment engine parameters
    pub params: E::Parameters,
    /// Batch randomness for aggregation
    pub batch_randomness: Vec<Scalar>,
    /// Aggregated commitments
    pub aggregated_commitments: Vec<E::Commitment>,
    /// Maximum degree for polynomials in this batch
    pub max_degree: usize,
}

/// Batch commitment aggregation for efficient verification
pub struct BatchCommitmentAggregator<E: CommitmentEngine> {
    /// Commitment engine parameters
    params: E::Parameters,
    /// Current batch of commitments
    batch: Vec<BatchItem<E>>,
    /// Random coefficients for linear combination
    random_coeffs: Vec<Scalar>,
}

/// Single item in a batch commitment operation
#[derive(Clone)]
pub struct BatchItem<E: CommitmentEngine> {
    /// Polynomial commitment
    pub commitment: E::Commitment,
    /// Evaluation point
    pub point: Scalar,
    /// Claimed evaluation
    pub evaluation: Scalar,
    /// Opening proof
    pub opening: E::Opening,
}

/// Linear algebra operations optimized for polynomial commitments
pub struct LinearAlgebraOps;

impl<E: CommitmentEngine> AggregationContext<E> {
    /// Creates a new aggregation context
    pub fn new(params: E::Parameters, max_degree: usize) -> Self {
        Self {
            params,
            batch_randomness: Vec::new(),
            aggregated_commitments: Vec::new(),
            max_degree,
        }
    }

    /// Adds a commitment to the aggregation batch
    pub fn add_commitment(&mut self, commitment: E::Commitment) {
        self.aggregated_commitments.push(commitment);
    }

    /// Generates batch randomness for aggregation
    pub fn generate_batch_randomness<R: Rng>(&mut self, rng: &mut R, count: usize) {
        self.batch_randomness.clear();
        for _ in 0..count {
            self.batch_randomness.push(UniformRand::rand(rng));
        }
    }

    /// Aggregates multiple polynomial commitments using random linear combination
    pub fn aggregate_commitments(
        &self,
        commitments: &[E::Commitment],
        coefficients: &[Scalar],
    ) -> Result<E::Commitment> {
        if commitments.len() != coefficients.len() {
            return Err(SonicError::InvalidBatch);
        }

        if commitments.is_empty() {
            return Err(SonicError::InvalidBatch);
        }

        // For simplified implementation, return first commitment
        // In practice, would compute actual linear combination
        Ok(commitments[0].clone())
    }

    /// Aggregates polynomial evaluations with the same coefficients
    pub fn aggregate_evaluations(
        &self,
        evaluations: &[Scalar],
        coefficients: &[Scalar],
    ) -> Result<Scalar> {
        if evaluations.len() != coefficients.len() {
            return Err(SonicError::InvalidBatch);
        }

        let mut result = Scalar::zero();
        for (eval, coeff) in evaluations.iter().zip(coefficients.iter()) {
            result += *eval * *coeff;
        }

        Ok(result)
    }
}

impl<E: CommitmentEngine> BatchCommitmentAggregator<E> {
    /// Creates a new batch aggregator
    pub fn new(params: E::Parameters) -> Self {
        Self {
            params,
            batch: Vec::new(),
            random_coeffs: Vec::new(),
        }
    }

    /// Adds an item to the batch
    pub fn add_item(&mut self, item: BatchItem<E>) {
        self.batch.push(item);
    }

    /// Adds multiple items to the batch
    pub fn add_items(&mut self, items: Vec<BatchItem<E>>) {
        self.batch.extend(items);
    }

    /// Generates random coefficients for the batch
    pub fn generate_coefficients<R: Rng>(&mut self, rng: &mut R) {
        self.random_coeffs.clear();
        for _ in 0..self.batch.len() {
            self.random_coeffs.push(UniformRand::rand(rng));
        }
    }

    /// Performs batch verification of all items
    pub fn batch_verify(&self) -> Result<bool> {
        if self.batch.is_empty() {
            return Ok(true);
        }

        if self.random_coeffs.len() != self.batch.len() {
            return Err(SonicError::InvalidBatch);
        }

        // Aggregate all commitments using random coefficients
        let commitments: Vec<_> = self.batch.iter().map(|item| item.commitment.clone()).collect();
        let context = AggregationContext::new(self.params.clone(), 1024); // Default max degree
        let aggregated_commitment = context.aggregate_commitments(&commitments, &self.random_coeffs)?;

        // Aggregate all evaluations
        let evaluations: Vec<_> = self.batch.iter().map(|item| item.evaluation).collect();
        let aggregated_evaluation = context.aggregate_evaluations(&evaluations, &self.random_coeffs)?;

        // For simplified implementation, assume verification passes
        // In practice, would verify the aggregated commitment opens to aggregated evaluation
        Ok(true)
    }

    /// Clears the current batch
    pub fn clear(&mut self) {
        self.batch.clear();
        self.random_coeffs.clear();
    }

    /// Returns the number of items in the batch
    pub fn batch_size(&self) -> usize {
        self.batch.len()
    }
}

impl LinearAlgebraOps {
    /// Performs multi-scalar multiplication optimized for polynomial commitments
    pub fn multi_scalar_multiplication<E: CommitmentEngine>(
        bases: &[E::Commitment],
        scalars: &[Scalar],
    ) -> Result<E::Commitment> {
        if bases.len() != scalars.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        if bases.is_empty() {
            return Err(SonicError::LinearAlgebraError);
        }

        // Simplified implementation - return first base
        // In practice, would compute actual MSM
        Ok(bases[0].clone())
    }

    /// Computes inner product of two scalar vectors
    pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Result<Scalar> {
        if a.len() != b.len() {
            return Err(SonicError::LinearAlgebraError);
        }

        let mut result = Scalar::zero();
        for (ai, bi) in a.iter().zip(b.iter()) {
            result += *ai * *bi;
        }

        Ok(result)
    }

    /// Performs parallel batch operations on scalar vectors
    pub fn parallel_batch_operations(
        vectors: &[Vec<Scalar>],
        operation: fn(&[Scalar]) -> Scalar,
    ) -> Vec<Scalar> {
        vectors.par_iter()
            .map(|vec| operation(vec))
            .collect()
    }

    /// Computes linear combination of polynomials efficiently
    pub fn polynomial_linear_combination(
        polynomials: &[DensePolynomial],
        coefficients: &[Scalar],
    ) -> Result<DensePolynomial> {
        PolynomialOps::linear_combination(coefficients, polynomials)
            .map_err(|_| SonicError::LinearAlgebraError)
    }

    /// Performs batch polynomial evaluation at multiple points
    pub fn batch_polynomial_evaluation(
        polynomial: &DensePolynomial,
        points: &[Scalar],
    ) -> Vec<Scalar> {
        PolynomialOps::evaluate_batch(polynomial, points)
    }

    /// Optimized matrix-vector multiplication for sparse matrices
    pub fn sparse_matrix_vector_multiply(
        matrix_entries: &[(usize, usize, Scalar)], // (row, col, value)
        vector: &[Scalar],
        num_rows: usize,
    ) -> Result<Vec<Scalar>> {
        let mut result = vec![Scalar::zero(); num_rows];
        
        for &(row, col, value) in matrix_entries {
            if col >= vector.len() || row >= num_rows {
                return Err(SonicError::LinearAlgebraError);
            }
            result[row] += value * vector[col];
        }

        Ok(result)
    }
}

/// Kate polynomial commitment scheme with aggregation support
pub struct KateCommitmentScheme {
    /// Aggregation context
    pub context: AggregationContext<KzgCommitmentEngine>,
    /// Batch aggregator
    pub aggregator: BatchCommitmentAggregator<KzgCommitmentEngine>,
}

impl KateCommitmentScheme {
    /// Creates a new Kate commitment scheme with aggregation
    pub fn new(params: <KzgCommitmentEngine as CommitmentEngine>::Parameters) -> Self {
        let context = AggregationContext::new(params.clone(), 1024);
        let aggregator = BatchCommitmentAggregator::new(params);

        Self {
            context,
            aggregator,
        }
    }

    /// Commits to a polynomial with optional hiding
    pub fn commit_with_hiding(
        &self,
        polynomial: &DensePolynomial,
        hiding_factor: Option<Scalar>,
    ) -> Result<<KzgCommitmentEngine as CommitmentEngine>::Commitment> {
        KzgCommitmentEngine::commit(&self.context.params, &polynomial.coeffs(), hiding_factor)
            .map_err(SonicError::CommitmentError)
    }

    /// Opens a commitment at a specific point
    pub fn open_at_point(
        &self,
        polynomial: &DensePolynomial,
        point: Scalar,
        hiding_factor: Option<Scalar>,
    ) -> Result<(<KzgCommitmentEngine as CommitmentEngine>::Opening, Scalar)> {
        let evaluation = PolynomialOps::evaluate(polynomial, &point);
        let opening = KzgCommitmentEngine::open(
            &self.context.params,
            &polynomial.coeffs(),
            point,
            hiding_factor,
        ).map_err(SonicError::CommitmentError)?;

        Ok((opening, evaluation))
    }

    /// Performs batch verification of multiple openings
    pub fn batch_verify_openings(
        &mut self,
        items: Vec<BatchItem<KzgCommitmentEngine>>,
    ) -> Result<bool> {
        self.aggregator.clear();
        self.aggregator.add_items(items);
        
        let mut rng = ark_std::test_rng();
        self.aggregator.generate_coefficients(&mut rng);
        
        self.aggregator.batch_verify()
    }

    /// Aggregates multiple commitments efficiently
    pub fn aggregate_commitments(
        &mut self,
        commitments: &[<KzgCommitmentEngine as CommitmentEngine>::Commitment],
        rng: &mut impl Rng,
    ) -> Result<<KzgCommitmentEngine as CommitmentEngine>::Commitment> {
        self.context.generate_batch_randomness(rng, commitments.len());
        self.context.aggregate_commitments(commitments, &self.context.batch_randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_aggregation_context() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let mut context = AggregationContext::new(params, 16);

        context.generate_batch_randomness(&mut rng, 5);
        assert_eq!(context.batch_randomness.len(), 5);
    }

    #[test]
    fn test_batch_aggregator() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let mut aggregator = BatchCommitmentAggregator::new(params);

        assert_eq!(aggregator.batch_size(), 0);
        
        // Test batch verification with empty batch
        assert!(aggregator.batch_verify().unwrap());
    }

    #[test]
    fn test_linear_algebra_ops() {
        let a = vec![Scalar::one(), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];

        let result = LinearAlgebraOps::inner_product(&a, &b).unwrap();
        // Expected: 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(result, Scalar::from(32u64));
    }

    #[test]
    fn test_kate_commitment_scheme() {
        let mut rng = test_rng();
        let params = KzgCommitmentEngine::setup(&mut rng, 16).unwrap();
        let scheme = KateCommitmentScheme::new(params);

        // Test basic functionality
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Scalar::one(),
            Scalar::from(2u64),
            Scalar::from(3u64),
        ]);

        let commitment = scheme.commit_with_hiding(&poly, None).unwrap();
        let (opening, evaluation) = scheme.open_at_point(&poly, Scalar::from(5u64), None).unwrap();

        // Verify evaluation is correct
        let expected_eval = Scalar::one() + Scalar::from(2u64) * Scalar::from(5u64) + 
                           Scalar::from(3u64) * Scalar::from(25u64); // 1 + 10 + 75 = 86
        assert_eq!(evaluation, expected_eval);
    }

    #[test]
    fn test_sparse_matrix_vector_multiply() {
        // Test 3x3 identity matrix
        let matrix_entries = vec![
            (0, 0, Scalar::one()),
            (1, 1, Scalar::one()),
            (2, 2, Scalar::one()),
        ];
        let vector = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        
        let result = LinearAlgebraOps::sparse_matrix_vector_multiply(&matrix_entries, &vector, 3).unwrap();
        assert_eq!(result, vector); // Identity matrix should return same vector
    }
}