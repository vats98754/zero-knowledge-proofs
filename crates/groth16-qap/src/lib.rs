//! QAP (Quadratic Arithmetic Program) implementation for Groth16.
//! 
//! This crate handles the conversion from R1CS to QAP and polynomial operations.
//! The QAP transformation converts R1CS constraints into polynomial form suitable for
//! zero-knowledge proofs using polynomial commitments and pairings.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use groth16_field::FieldLike;
use groth16_r1cs::R1CS;
use ark_ff::FftField;
use ark_poly::{
    Polynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain,
    univariate::DensePolynomial,
};
use ark_std::{vec::Vec, Zero, One};
use rayon::prelude::*;
use rand::Rng;

pub use groth16_field;
pub use groth16_r1cs;

/// QAP (Quadratic Arithmetic Program) representation
/// 
/// Converts R1CS constraints into polynomial form where:
/// - A(x), B(x), C(x) are polynomials derived from constraint matrices
/// - The satisfiability condition becomes: A(x) * B(x) - C(x) = H(x) * Z(x)
/// - Z(x) is the vanishing polynomial over the evaluation domain
#[derive(Debug, Clone)]
pub struct QAP<F: FieldLike> {
    /// A polynomials - one for each variable
    pub a_polys: Vec<DensePolynomial<F>>,
    /// B polynomials - one for each variable  
    pub b_polys: Vec<DensePolynomial<F>>,
    /// C polynomials - one for each variable
    pub c_polys: Vec<DensePolynomial<F>>,
    /// Vanishing polynomial Z(x) = (x - ω^0)(x - ω^1)...(x - ω^{n-1})
    pub vanishing_poly: DensePolynomial<F>,
    /// Evaluation domain used for polynomial operations
    pub domain: Radix2EvaluationDomain<F>,
    /// Number of variables in the original R1CS
    pub num_variables: usize,
    /// Number of constraints in the original R1CS
    pub num_constraints: usize,
}

/// QAP evaluation at a specific point
#[derive(Debug, Clone)]
pub struct QAPEvaluation<F: FieldLike> {
    /// A(x) evaluation
    pub a_val: F,
    /// B(x) evaluation  
    pub b_val: F,
    /// C(x) evaluation
    pub c_val: F,
    /// Z(x) evaluation (vanishing polynomial)
    pub z_val: F,
    /// H(x) evaluation (quotient polynomial)
    pub h_val: Option<F>,
}

/// Errors that can occur during QAP operations
#[derive(Debug, thiserror::Error)]
pub enum QAPError {
    /// Domain size is too small for the number of constraints
    #[error("Domain size {domain_size} is too small for {num_constraints} constraints")]
    DomainTooSmall {
        /// Size of the evaluation domain
        domain_size: usize,
        /// Number of constraints
        num_constraints: usize,
    },
    
    /// Polynomial division failed (remainder should be zero)
    #[error("Polynomial division failed: non-zero remainder")]
    PolynomialDivisionFailed,
    
    /// Invalid QAP evaluation
    #[error("Invalid QAP evaluation: A(x) * B(x) - C(x) != H(x) * Z(x)")]
    InvalidQAPEvaluation,
    
    /// Field operation error
    #[error("Field error: {0}")]
    FieldError(#[from] groth16_field::FieldError),
}

impl<F: FieldLike + FftField> QAP<F> {
    /// Convert an R1CS to QAP form
    /// 
    /// This performs the transformation:
    /// 1. Set up evaluation domain of size >= num_constraints
    /// 2. Interpolate constraint matrix rows to get A_i(x), B_i(x), C_i(x) polynomials
    /// 3. Compute vanishing polynomial Z(x)
    pub fn from_r1cs(r1cs: &R1CS<F>) -> Result<Self, QAPError> {
        let num_constraints = r1cs.num_constraints();
        let num_variables = r1cs.num_variables;
        
        // Find the smallest power of 2 >= num_constraints for FFT domain
        let domain_size = num_constraints.next_power_of_two();
        let domain = Radix2EvaluationDomain::<F>::new(domain_size)
            .ok_or(QAPError::DomainTooSmall { 
                domain_size, 
                num_constraints 
            })?;
        
        // Initialize polynomial vectors
        let mut a_polys = vec![DensePolynomial::zero(); num_variables];
        let mut b_polys = vec![DensePolynomial::zero(); num_variables];
        let mut c_polys = vec![DensePolynomial::zero(); num_variables];
        
        // For each constraint, extract coefficients and build polynomial evaluations
        let _omega = domain.group_gen();
        let mut a_evals = vec![vec![<F as Zero>::zero(); num_variables]; num_constraints];
        let mut b_evals = vec![vec![<F as Zero>::zero(); num_variables]; num_constraints];
        let mut c_evals = vec![vec![<F as Zero>::zero(); num_variables]; num_constraints];
        
        // Extract constraint matrix coefficients
        for (constraint_idx, constraint) in r1cs.constraints.iter().enumerate() {
            // A matrix row
            for (&var, &coeff) in &constraint.a.terms {
                if var.index() < num_variables {
                    a_evals[constraint_idx][var.index()] = coeff;
                }
            }
            
            // B matrix row
            for (&var, &coeff) in &constraint.b.terms {
                if var.index() < num_variables {
                    b_evals[constraint_idx][var.index()] = coeff;
                }
            }
            
            // C matrix row
            for (&var, &coeff) in &constraint.c.terms {
                if var.index() < num_variables {
                    c_evals[constraint_idx][var.index()] = coeff;
                }
            }
        }
        
        // Interpolate polynomials for each variable
        for var_idx in 0..num_variables {
            // Collect evaluations for this variable across all constraints
            let a_vals: Vec<F> = (0..num_constraints)
                .map(|i| a_evals[i][var_idx])
                .collect();
            let b_vals: Vec<F> = (0..num_constraints)
                .map(|i| b_evals[i][var_idx])
                .collect();
            let c_vals: Vec<F> = (0..num_constraints)
                .map(|i| c_evals[i][var_idx])
                .collect();
            
            // Pad with zeros if domain is larger than constraints
            let mut a_vals_padded = a_vals;
            let mut b_vals_padded = b_vals;
            let mut c_vals_padded = c_vals;
            
            while a_vals_padded.len() < domain_size {
                a_vals_padded.push(<F as Zero>::zero());
                b_vals_padded.push(<F as Zero>::zero());
                c_vals_padded.push(<F as Zero>::zero());
            }
            
            // Interpolate using the evaluation domain
            a_polys[var_idx] = DensePolynomial::from_coefficients_vec(domain.ifft(&a_vals_padded));
            b_polys[var_idx] = DensePolynomial::from_coefficients_vec(domain.ifft(&b_vals_padded));
            c_polys[var_idx] = DensePolynomial::from_coefficients_vec(domain.ifft(&c_vals_padded));
        }
        
        // Compute vanishing polynomial Z(x) = x^n - 1 for domain of size n
        let mut vanishing_coeffs = vec![<F as Zero>::zero(); domain_size + 1];
        vanishing_coeffs[0] = -<F as One>::one(); // -1
        vanishing_coeffs[domain_size] = <F as One>::one(); // x^n
        let vanishing_poly = DensePolynomial::from_coefficients_vec(vanishing_coeffs);
        
        Ok(QAP {
            a_polys,
            b_polys,
            c_polys,
            vanishing_poly,
            domain,
            num_variables,
            num_constraints,
        })
    }
    
    /// Evaluate the QAP at a specific point with given variable assignment
    pub fn evaluate_at(&self, point: F, assignment: &[F]) -> Result<QAPEvaluation<F>, QAPError> {
        if assignment.len() != self.num_variables {
            return Err(QAPError::FieldError(
                groth16_field::FieldError::DimensionMismatch {
                    left: assignment.len(),
                    right: self.num_variables,
                }
            ));
        }
        
        // Compute A(point), B(point), C(point) as linear combinations
        let mut a_val = <F as Zero>::zero();
        let mut b_val = <F as Zero>::zero();
        let mut c_val = <F as Zero>::zero();
        
        for (i, &var_val) in assignment.iter().enumerate() {
            a_val += var_val * self.a_polys[i].evaluate(&point);
            b_val += var_val * self.b_polys[i].evaluate(&point);
            c_val += var_val * self.c_polys[i].evaluate(&point);
        }
        
        let z_val = self.vanishing_poly.evaluate(&point);
        
        Ok(QAPEvaluation {
            a_val,
            b_val,
            c_val,
            z_val,
            h_val: None,
        })
    }
    
    /// Compute the quotient polynomial H(x) = (A(x) * B(x) - C(x)) / Z(x)
    /// 
    /// For a valid assignment, A(x) * B(x) - C(x) should be divisible by Z(x)
    pub fn compute_quotient_polynomial(&self, assignment: &[F]) -> Result<DensePolynomial<F>, QAPError> {
        if assignment.len() != self.num_variables {
            return Err(QAPError::FieldError(
                groth16_field::FieldError::DimensionMismatch {
                    left: assignment.len(),
                    right: self.num_variables,
                }
            ));
        }
        
        // Compute A(x) = Σ assignment[i] * A_i(x)
        let mut a_poly = DensePolynomial::zero();
        for (i, &var_val) in assignment.iter().enumerate() {
            if !<F as Zero>::is_zero(&var_val) {
                a_poly = &a_poly + &(&self.a_polys[i] * var_val);
            }
        }
        
        // Compute B(x) = Σ assignment[i] * B_i(x)
        let mut b_poly = DensePolynomial::zero();
        for (i, &var_val) in assignment.iter().enumerate() {
            if !<F as Zero>::is_zero(&var_val) {
                b_poly = &b_poly + &(&self.b_polys[i] * var_val);
            }
        }
        
        // Compute C(x) = Σ assignment[i] * C_i(x)
        let mut c_poly = DensePolynomial::zero();
        for (i, &var_val) in assignment.iter().enumerate() {
            if !<F as Zero>::is_zero(&var_val) {
                c_poly = &c_poly + &(&self.c_polys[i] * var_val);
            }
        }
        
        // Compute numerator: A(x) * B(x) - C(x)
        let numerator = &(&a_poly * &b_poly) - &c_poly;
        
        // Divide by vanishing polynomial
        let (quotient, remainder) = numerator.divide_by_vanishing_poly(self.domain).unwrap();
        
        // Remainder should be zero for valid assignment
        if !remainder.is_zero() {
            return Err(QAPError::PolynomialDivisionFailed);
        }
        
        Ok(quotient)
    }
    
    /// Verify that a QAP evaluation is consistent
    pub fn verify_evaluation(&self, eval: &QAPEvaluation<F>) -> bool {
        if let Some(h_val) = eval.h_val {
            // Check: A(x) * B(x) - C(x) = H(x) * Z(x)
            eval.a_val * eval.b_val - eval.c_val == h_val * eval.z_val
        } else {
            // Just check if A(x) * B(x) - C(x) is zero (should be at domain points)
            eval.a_val * eval.b_val == eval.c_val
        }
    }
    
    /// Get the degree of the QAP (maximum degree among all polynomials)
    pub fn degree(&self) -> usize {
        let max_var_degree = self.a_polys.iter()
            .chain(self.b_polys.iter())
            .chain(self.c_polys.iter())
            .map(|p| p.degree())
            .max()
            .unwrap_or(0);
        
        std::cmp::max(max_var_degree, self.vanishing_poly.degree())
    }
}

/// Utility functions for QAP operations
pub mod utils {
    use super::*;
    
    /// Generate a random evaluation point for testing (avoiding domain points)
    pub fn random_evaluation_point<F: FieldLike + FftField, R: Rng + ?Sized>(
        domain: &Radix2EvaluationDomain<F>,
        rng: &mut R
    ) -> F {
        loop {
            let point = F::rand(rng);
            // Make sure it's not a domain point (evaluation should be non-zero)
            if !<F as Zero>::is_zero(&domain.evaluate_vanishing_polynomial(point)) {
                return point;
            }
        }
    }
    
    /// Batch evaluate multiple polynomials at the same point
    pub fn batch_evaluate<F: FieldLike>(
        polynomials: &[DensePolynomial<F>],
        point: F
    ) -> Vec<F> {
        polynomials.par_iter()
            .map(|poly| poly.evaluate(&point))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_field::F;
    use groth16_r1cs::{R1CS, LinearCombination};
    use rand::thread_rng;
    
    #[test]
    fn test_qap_basic_conversion() {
        // Create a simple R1CS: x * y = z
        let mut r1cs = R1CS::<F>::new(0);
        let x = r1cs.allocate_variable(); // variable 1
        let y = r1cs.allocate_variable(); // variable 2  
        let z = r1cs.allocate_variable(); // variable 3
        
        r1cs.enforce_multiplication(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(y),
            LinearCombination::from_variable(z)
        );
        
        // Convert to QAP
        let qap = QAP::from_r1cs(&r1cs).unwrap();
        
        assert_eq!(qap.num_variables, 4); // 1 constant + 3 variables
        assert_eq!(qap.num_constraints, 1);
        assert!(qap.domain.size() >= 1);
    }
    
    #[test]  
    fn test_qap_evaluation() {
        // Create R1CS: x * y = z
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
        
        // Test with satisfying assignment: 3 * 4 = 12
        let assignment = vec![
            <F as FieldLike>::one(), // constant
            F::from(3u64),           // x
            F::from(4u64),           // y  
            F::from(12u64),          // z
        ];
        
        // Evaluate at domain points (should satisfy constraint)
        let omega = qap.domain.group_gen();
        let eval = qap.evaluate_at(omega, &assignment).unwrap();
        assert!(qap.verify_evaluation(&eval));
    }
    
    #[test]
    fn test_quotient_polynomial() {
        // Create R1CS: x * y = z
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
        
        // Valid assignment
        let assignment = vec![
            <F as FieldLike>::one(),
            F::from(3u64),
            F::from(4u64),
            F::from(12u64),
        ];
        
        // Should be able to compute quotient polynomial
        let h_poly = qap.compute_quotient_polynomial(&assignment).unwrap();
        
        // Test evaluation at random point
        let mut rng = thread_rng();
        let point = utils::random_evaluation_point(&qap.domain, &mut rng);
        
        let mut eval = qap.evaluate_at(point, &assignment).unwrap();
        eval.h_val = Some(h_poly.evaluate(&point));
        
        assert!(qap.verify_evaluation(&eval));
    }
    
    #[test]
    fn test_invalid_assignment() {
        // Create R1CS: x * y = z
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
        
        // Invalid assignment: 3 * 4 ≠ 13
        let assignment = vec![
            <F as FieldLike>::one(),
            F::from(3u64),
            F::from(4u64),
            F::from(13u64), // Wrong!
        ];
        
        // Should fail to compute quotient polynomial
        assert!(qap.compute_quotient_polynomial(&assignment).is_err());
    }
}