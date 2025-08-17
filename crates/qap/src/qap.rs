//! QAP-specific structures and algorithms

use crate::QAPError;
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_std::vec::Vec;

/// QAP instance with polynomial representations
#[derive(Debug, Clone)]
pub struct QAPInstance<F: FftField> {
    /// Polynomials for left wire (A)
    pub a_polynomials: Vec<DensePolynomial<F>>,
    /// Polynomials for right wire (B)  
    pub b_polynomials: Vec<DensePolynomial<F>>,
    /// Polynomials for output wire (C)
    pub c_polynomials: Vec<DensePolynomial<F>>,
    /// Target polynomial (vanishing polynomial of evaluation domain)
    pub target_polynomial: DensePolynomial<F>,
    /// Number of variables
    pub num_variables: usize,
    /// Number of constraints
    pub num_constraints: usize,
}

impl<F: FftField> QAPInstance<F> {
    /// Create a new QAP instance
    pub fn new(
        a_polynomials: Vec<DensePolynomial<F>>,
        b_polynomials: Vec<DensePolynomial<F>>,
        c_polynomials: Vec<DensePolynomial<F>>,
        target_polynomial: DensePolynomial<F>,
        num_variables: usize,
        num_constraints: usize,
    ) -> Self {
        Self {
            a_polynomials,
            b_polynomials,
            c_polynomials,
            target_polynomial,
            num_variables,
            num_constraints,
        }
    }

    /// Get the degree of the QAP (degree of target polynomial)
    pub fn degree(&self) -> usize {
        self.target_polynomial.degree()
    }

    /// Evaluate polynomials at a given point
    pub fn evaluate_at(&self, witness: &[F], tau: F) -> Result<(F, F, F), QAPError> {
        if witness.len() != self.num_variables {
            return Err(QAPError::EvaluationFailed);
        }

        let mut a_eval = F::zero();
        let mut b_eval = F::zero();
        let mut c_eval = F::zero();

        for (i, &w_i) in witness.iter().enumerate() {
            a_eval += w_i * self.a_polynomials[i].evaluate(&tau);
            b_eval += w_i * self.b_polynomials[i].evaluate(&tau);
            c_eval += w_i * self.c_polynomials[i].evaluate(&tau);
        }

        Ok((a_eval, b_eval, c_eval))
    }
}