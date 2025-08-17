//! QAP (Quadratic Arithmetic Program) implementation
//! 
//! This crate converts R1CS to QAP and provides polynomial evaluation.

#![forbid(unsafe_code)]

pub mod qap;
pub mod polynomial;

pub use qap::*;
pub use polynomial::*;

use ark_ff::{FftField, Zero};
use ark_poly::{
    univariate::DensePolynomial, 
    DenseUVPolynomial,
    Polynomial,
    EvaluationDomain,
    GeneralEvaluationDomain,
};
use ark_std::vec::Vec;
use r1cs::{R1CS, LinearCombination};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QAPError {
    #[error("Invalid evaluation domain size: {0}")]
    InvalidDomainSize(usize),
    #[error("Polynomial evaluation failed")]
    EvaluationFailed,
    #[error("Invalid constraint index: {0}")]
    InvalidConstraintIndex(usize),
}

/// Quadratic Arithmetic Program representation
#[derive(Debug, Clone)]
pub struct QAP<F: FftField> {
    /// Polynomials for the A matrix
    pub a_polys: Vec<DensePolynomial<F>>,
    /// Polynomials for the B matrix
    pub b_polys: Vec<DensePolynomial<F>>,
    /// Polynomials for the C matrix
    pub c_polys: Vec<DensePolynomial<F>>,
    /// Target polynomial (vanishing polynomial)
    pub target_poly: DensePolynomial<F>,
    /// Evaluation domain
    pub domain: GeneralEvaluationDomain<F>,
}

impl<F: FftField> QAP<F> {
    /// Convert R1CS to QAP
    pub fn from_r1cs(r1cs: &R1CS<F>) -> Result<Self, QAPError> {
        let num_constraints = r1cs.num_constraints();
        let num_variables = r1cs.num_variables;

        // Create evaluation domain (must be power of 2 and >= num_constraints)
        let domain_size = num_constraints.next_power_of_two();
        let domain = GeneralEvaluationDomain::<F>::new(domain_size)
            .ok_or(QAPError::InvalidDomainSize(domain_size))?;

        // Create matrices A, B, C from R1CS
        let mut a_matrix = vec![vec![F::zero(); num_variables]; num_constraints];
        let mut b_matrix = vec![vec![F::zero(); num_variables]; num_constraints];
        let mut c_matrix = vec![vec![F::zero(); num_variables]; num_constraints];

        for (i, constraint) in r1cs.constraints.iter().enumerate() {
            Self::fill_matrix_from_lc(&constraint.a, &mut a_matrix[i]);
            Self::fill_matrix_from_lc(&constraint.b, &mut b_matrix[i]);
            Self::fill_matrix_from_lc(&constraint.c, &mut c_matrix[i]);
        }

        // Convert matrices to polynomials via interpolation
        let mut a_polys = Vec::with_capacity(num_variables);
        let mut b_polys = Vec::with_capacity(num_variables);
        let mut c_polys = Vec::with_capacity(num_variables);

        for var_idx in 0..num_variables {
            // Collect evaluations for this variable across all constraints
            let a_evals: Vec<F> = (0..domain_size).map(|i| {
                if i < num_constraints {
                    a_matrix[i][var_idx]
                } else {
                    F::zero()
                }
            }).collect();
            
            let b_evals: Vec<F> = (0..domain_size).map(|i| {
                if i < num_constraints {
                    b_matrix[i][var_idx]
                } else {
                    F::zero()
                }
            }).collect();
            
            let c_evals: Vec<F> = (0..domain_size).map(|i| {
                if i < num_constraints {
                    c_matrix[i][var_idx]
                } else {
                    F::zero()
                }
            }).collect();

            // Interpolate polynomials (ifft returns coefficients)
            a_polys.push(DensePolynomial::from_coefficients_vec(domain.ifft(&a_evals)));
            b_polys.push(DensePolynomial::from_coefficients_vec(domain.ifft(&b_evals)));
            c_polys.push(DensePolynomial::from_coefficients_vec(domain.ifft(&c_evals)));
        }

        // Create target polynomial (vanishing polynomial)
        let target_poly = domain.vanishing_polynomial().into();

        Ok(QAP {
            a_polys,
            b_polys,
            c_polys,
            target_poly,
            domain,
        })
    }

    /// Fill matrix row from linear combination
    fn fill_matrix_from_lc(lc: &LinearCombination<F>, matrix_row: &mut [F]) {
        for term in &lc.terms {
            if term.variable.index < matrix_row.len() {
                matrix_row[term.variable.index] = term.coefficient;
            }
        }
    }

    /// Evaluate QAP at a point with a witness
    pub fn evaluate_at_point(&self, witness: &[F], tau: F) -> Result<(F, F, F), QAPError> {
        if witness.len() != self.a_polys.len() {
            return Err(QAPError::EvaluationFailed);
        }

        let mut a_val = F::zero();
        let mut b_val = F::zero();
        let mut c_val = F::zero();

        for (i, &w) in witness.iter().enumerate() {
            a_val += w * self.a_polys[i].evaluate(&tau);
            b_val += w * self.b_polys[i].evaluate(&tau);
            c_val += w * self.c_polys[i].evaluate(&tau);
        }

        Ok((a_val, b_val, c_val))
    }

    /// Compute the quotient polynomial H(x) = (A(x) * B(x) - C(x)) / Z(x)
    pub fn compute_quotient_polynomial(&self, witness: &[F]) -> Result<DensePolynomial<F>, QAPError> {
        if witness.len() != self.a_polys.len() {
            return Err(QAPError::EvaluationFailed);
        }

        // Compute A(x), B(x), C(x) polynomials
        let mut a_poly = DensePolynomial::zero();
        let mut b_poly = DensePolynomial::zero();
        let mut c_poly = DensePolynomial::zero();

        for (i, &w) in witness.iter().enumerate() {
            a_poly = &a_poly + &(&self.a_polys[i] * w);
            b_poly = &b_poly + &(&self.b_polys[i] * w);
            c_poly = &c_poly + &(&self.c_polys[i] * w);
        }

        // Compute A(x) * B(x) - C(x)
        let numerator = &(&a_poly * &b_poly) - &c_poly;

        // Divide by target polynomial Z(x)
        let (quotient, remainder) = <DensePolynomial<F> as DenseUVPolynomial<F>>::divide_with_q_and_r(&numerator, &self.target_poly)
            .ok_or(QAPError::EvaluationFailed)?;

        // Check that division is exact (remainder should be zero)
        if !remainder.is_zero() {
            return Err(QAPError::EvaluationFailed);
        }

        Ok(quotient)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use r1cs::{R1CS, LinearCombination};

    #[test]
    fn test_qap_conversion() {
        let mut r1cs = R1CS::<Fr>::new();
        
        // Create a simple constraint: x * x = x^2
        let x = r1cs.alloc_variable();
        let x_squared = r1cs.alloc_variable();

        let a = LinearCombination::from_variable(x);
        let b = LinearCombination::from_variable(x);
        let c = LinearCombination::from_variable(x_squared);
        
        r1cs.add_constraint(a, b, c).unwrap();

        // Convert to QAP
        let qap = QAP::from_r1cs(&r1cs).unwrap();

        // Check basic properties
        assert_eq!(qap.a_polys.len(), r1cs.num_variables);
        assert_eq!(qap.b_polys.len(), r1cs.num_variables);
        assert_eq!(qap.c_polys.len(), r1cs.num_variables);

        // Create witness: [1, 3, 9] (constant=1, x=3, x^2=9)
        let witness = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(9u64)];

        // Compute quotient polynomial
        let quotient = qap.compute_quotient_polynomial(&witness).unwrap();
        
        // For a valid witness, quotient should be computable
        assert!(!quotient.is_zero());
    }
}