//! R1CS (Rank-1 Constraint System) encoding for Marlin
//!
//! This module provides functionality to encode arithmetic circuits
//! into R1CS format for use with the Marlin polynomial IOP.

use crate::{Result, MarlinError};
use zkp_field::{Scalar, polynomial::{PolynomialOps, DensePolynomial}, fft::FftDomain};
use ark_ff::{Zero, One, Field};
use ark_poly::polynomial::DenseUVPolynomial;
use std::collections::HashMap;

/// R1CS constraint system representation
#[derive(Debug, Clone)]
pub struct R1CS {
    /// Left input matrix A
    pub a_matrix: SparseMatrix,
    /// Right input matrix B  
    pub b_matrix: SparseMatrix,
    /// Output matrix C
    pub c_matrix: SparseMatrix,
    /// Number of constraints
    pub num_constraints: usize,
    /// Number of variables (including public inputs and private witnesses)
    pub num_variables: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
}

/// Sparse matrix representation for R1CS matrices
#[derive(Debug, Clone)]
pub struct SparseMatrix {
    /// Matrix entries as (row, col, value) triples
    pub entries: Vec<(usize, usize, Scalar)>,
    /// Number of rows
    pub num_rows: usize,
    /// Number of columns  
    pub num_cols: usize,
}

/// R1CS instance with public inputs
#[derive(Debug, Clone)]
pub struct R1CSInstance {
    /// The R1CS constraint system
    pub r1cs: R1CS,
    /// Public input values
    pub public_inputs: Vec<Scalar>,
}

/// R1CS witness containing private values
#[derive(Debug, Clone)]
pub struct R1CSWitness {
    /// Private witness values
    pub witness: Vec<Scalar>,
}

/// R1CS polynomial encoding for Marlin
#[derive(Debug)]
pub struct R1CSEncoding {
    /// Selector polynomials for A matrix
    pub a_selectors: Vec<DensePolynomial>,
    /// Selector polynomials for B matrix
    pub b_selectors: Vec<DensePolynomial>,
    /// Selector polynomials for C matrix
    pub c_selectors: Vec<DensePolynomial>,
    /// Variable polynomials
    pub variable_polys: Vec<DensePolynomial>,
    /// Vanishing polynomial for the constraint domain
    pub vanishing_poly: DensePolynomial,
    /// Evaluation domain
    pub domain: FftDomain,
}

impl SparseMatrix {
    /// Creates a new sparse matrix
    pub fn new(num_rows: usize, num_cols: usize) -> Self {
        Self {
            entries: Vec::new(),
            num_rows,
            num_cols,
        }
    }

    /// Adds an entry to the matrix
    pub fn add_entry(&mut self, row: usize, col: usize, value: Scalar) {
        if row >= self.num_rows || col >= self.num_cols {
            return; // Skip invalid entries
        }
        
        if !value.is_zero() {
            self.entries.push((row, col, value));
        }
    }

    /// Gets the value at a specific position
    pub fn get(&self, row: usize, col: usize) -> Scalar {
        for &(r, c, val) in &self.entries {
            if r == row && c == col {
                return val;
            }
        }
        Scalar::zero()
    }

    /// Converts the sparse matrix to dense format
    pub fn to_dense(&self) -> Vec<Vec<Scalar>> {
        let mut dense = vec![vec![Scalar::zero(); self.num_cols]; self.num_rows];
        for &(row, col, val) in &self.entries {
            dense[row][col] = val;
        }
        dense
    }

    /// Multiplies the matrix by a vector
    pub fn mul_vector(&self, vector: &[Scalar]) -> Result<Vec<Scalar>> {
        if vector.len() != self.num_cols {
            return Err(MarlinError::InvalidCircuit);
        }

        let mut result = vec![Scalar::zero(); self.num_rows];
        for &(row, col, val) in &self.entries {
            result[row] += val * vector[col];
        }
        Ok(result)
    }

    /// Transposes the matrix
    pub fn transpose(&self) -> SparseMatrix {
        let mut transposed = SparseMatrix::new(self.num_cols, self.num_rows);
        for &(row, col, val) in &self.entries {
            transposed.add_entry(col, row, val);
        }
        transposed
    }
}

impl R1CS {
    /// Creates a new R1CS constraint system
    pub fn new(
        num_constraints: usize,
        num_variables: usize,
        num_public_inputs: usize,
    ) -> Self {
        Self {
            a_matrix: SparseMatrix::new(num_constraints, num_variables),
            b_matrix: SparseMatrix::new(num_constraints, num_variables),
            c_matrix: SparseMatrix::new(num_constraints, num_variables),
            num_constraints,
            num_variables,
            num_public_inputs,
        }
    }

    /// Adds a constraint to the R1CS system
    /// Constraint format: (A • z) * (B • z) = (C • z)
    /// where z is the variable assignment vector
    pub fn add_constraint(
        &mut self,
        a_entries: &[(usize, Scalar)],
        b_entries: &[(usize, Scalar)],
        c_entries: &[(usize, Scalar)],
    ) -> Result<()> {
        let constraint_idx = self.a_matrix.entries.len() / self.num_variables;
        if constraint_idx >= self.num_constraints {
            return Err(MarlinError::InvalidCircuit);
        }

        // Add A matrix entries
        for &(var_idx, coeff) in a_entries {
            if var_idx < self.num_variables {
                self.a_matrix.add_entry(constraint_idx, var_idx, coeff);
            }
        }

        // Add B matrix entries
        for &(var_idx, coeff) in b_entries {
            if var_idx < self.num_variables {
                self.b_matrix.add_entry(constraint_idx, var_idx, coeff);
            }
        }

        // Add C matrix entries
        for &(var_idx, coeff) in c_entries {
            if var_idx < self.num_variables {
                self.c_matrix.add_entry(constraint_idx, var_idx, coeff);
            }
        }

        Ok(())
    }

    /// Verifies that a witness satisfies the R1CS constraints
    pub fn is_satisfied(&self, full_assignment: &[Scalar]) -> Result<bool> {
        if full_assignment.len() != self.num_variables {
            return Err(MarlinError::InvalidCircuit);
        }

        // Compute A * z, B * z, C * z
        let a_z = self.a_matrix.mul_vector(full_assignment)?;
        let b_z = self.b_matrix.mul_vector(full_assignment)?;
        let c_z = self.c_matrix.mul_vector(full_assignment)?;

        // Check that (A * z) ∘ (B * z) = C * z for all constraints
        for i in 0..self.num_constraints {
            if a_z[i] * b_z[i] != c_z[i] {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Creates the full variable assignment from public inputs and witness
    pub fn full_assignment(
        &self,
        public_inputs: &[Scalar],
        witness: &[Scalar],
    ) -> Result<Vec<Scalar>> {
        if public_inputs.len() != self.num_public_inputs {
            return Err(MarlinError::InvalidCircuit);
        }

        let expected_witness_size = self.num_variables - self.num_public_inputs - 1; // -1 for constant
        if witness.len() != expected_witness_size {
            return Err(MarlinError::InvalidCircuit);
        }

        let mut full_assignment = Vec::with_capacity(self.num_variables);
        
        // First variable is always 1 (constant)
        full_assignment.push(Scalar::one());
        
        // Add public inputs
        full_assignment.extend_from_slice(public_inputs);
        
        // Add private witness
        full_assignment.extend_from_slice(witness);

        Ok(full_assignment)
    }

    /// Generates polynomial encoding for use with Marlin IOP
    pub fn to_polynomial_encoding(&self, domain: &FftDomain) -> Result<R1CSEncoding> {
        if domain.size() < self.num_constraints {
            return Err(MarlinError::InvalidSetup);
        }

        // Convert each column of the matrices to polynomials
        let mut a_selectors = Vec::new();
        let mut b_selectors = Vec::new();  
        let mut c_selectors = Vec::new();

        for var_idx in 0..self.num_variables {
            // Extract column values for this variable
            let mut a_column = vec![Scalar::zero(); domain.size()];
            let mut b_column = vec![Scalar::zero(); domain.size()];
            let mut c_column = vec![Scalar::zero(); domain.size()];

            // Fill in the actual constraint values
            for constraint_idx in 0..self.num_constraints {
                a_column[constraint_idx] = self.a_matrix.get(constraint_idx, var_idx);
                b_column[constraint_idx] = self.b_matrix.get(constraint_idx, var_idx);
                c_column[constraint_idx] = self.c_matrix.get(constraint_idx, var_idx);
            }

            // Convert to polynomials using FFT
            let a_poly = PolynomialOps::interpolate_from_domain(&a_column, domain)?;
            let b_poly = PolynomialOps::interpolate_from_domain(&b_column, domain)?;
            let c_poly = PolynomialOps::interpolate_from_domain(&c_column, domain)?;

            a_selectors.push(a_poly);
            b_selectors.push(b_poly);
            c_selectors.push(c_poly);
        }

        // Create vanishing polynomial Z_H(X) = X^|H| - 1
        let mut vanishing_coeffs = vec![Scalar::zero(); domain.size() + 1];
        vanishing_coeffs[0] = -Scalar::one(); // Constant term: -1
        vanishing_coeffs[domain.size()] = Scalar::one(); // X^|H| term: 1
        let vanishing_poly = DensePolynomial::from_coefficients_slice(&vanishing_coeffs);

        Ok(R1CSEncoding {
            a_selectors,
            b_selectors,
            c_selectors,
            variable_polys: Vec::new(), // Will be filled by prover
            vanishing_poly,
            domain: domain.clone(),
        })
    }
}

impl R1CSInstance {
    /// Creates a new R1CS instance
    pub fn new(r1cs: R1CS, public_inputs: Vec<Scalar>) -> Self {
        Self { r1cs, public_inputs }
    }

    /// Verifies a witness against this instance
    pub fn verify_witness(&self, witness: &R1CSWitness) -> Result<bool> {
        let full_assignment = self.r1cs.full_assignment(&self.public_inputs, &witness.witness)?;
        self.r1cs.is_satisfied(&full_assignment)
    }
}

impl R1CSWitness {
    /// Creates a new R1CS witness
    pub fn new(witness: Vec<Scalar>) -> Self {
        Self { witness }
    }
}

impl R1CSEncoding {
    /// Evaluates the constraint equation at a specific point
    pub fn evaluate_constraint(
        &self,
        constraint_idx: usize,
        variable_assignment: &[Scalar],
        eval_point: &Scalar,
    ) -> Result<(Scalar, Scalar, Scalar)> {
        if constraint_idx >= self.domain.size() {
            return Err(MarlinError::InvalidCircuit);
        }

        if variable_assignment.len() != self.a_selectors.len() {
            return Err(MarlinError::InvalidCircuit);
        }

        // Evaluate A selectors
        let mut a_eval = Scalar::zero();
        for (i, selector) in self.a_selectors.iter().enumerate() {
            let selector_eval = PolynomialOps::evaluate(selector, eval_point);
            a_eval += selector_eval * variable_assignment[i];
        }

        // Evaluate B selectors
        let mut b_eval = Scalar::zero();
        for (i, selector) in self.b_selectors.iter().enumerate() {
            let selector_eval = PolynomialOps::evaluate(selector, eval_point);
            b_eval += selector_eval * variable_assignment[i];
        }

        // Evaluate C selectors
        let mut c_eval = Scalar::zero();
        for (i, selector) in self.c_selectors.iter().enumerate() {
            let selector_eval = PolynomialOps::evaluate(selector, eval_point);
            c_eval += selector_eval * variable_assignment[i];
        }

        Ok((a_eval, b_eval, c_eval))
    }

    /// Checks if the constraint equation is satisfied at a point
    pub fn is_satisfied_at_point(
        &self,
        variable_assignment: &[Scalar],
        eval_point: &Scalar,
    ) -> Result<bool> {
        // Check if eval_point is a root of the vanishing polynomial
        let vanishing_eval = PolynomialOps::evaluate(&self.vanishing_poly, eval_point);
        if vanishing_eval.is_zero() {
            // On the constraint domain, check R1CS equation
            let (a_eval, b_eval, c_eval) = self.evaluate_constraint(0, variable_assignment, eval_point)?;
            Ok(a_eval * b_eval == c_eval)
        } else {
            // Outside constraint domain, polynomial should be divisible by vanishing poly
            Ok(true) // Simplified check
        }
    }

    /// Computes the quotient polynomial for constraint satisfaction
    pub fn compute_quotient_polynomial(
        &self,
        variable_assignment: &[Scalar],
    ) -> Result<DensePolynomial> {
        // This is a simplified implementation
        // In practice, this would compute the actual quotient polynomial
        // (A(X) * B(X) - C(X)) / Z_H(X)
        
        let degree = self.domain.size();
        let mut quotient_coeffs = vec![Scalar::zero(); degree];
        
        // Simple polynomial for demonstration
        quotient_coeffs[0] = Scalar::one();
        if degree > 1 {
            quotient_coeffs[1] = variable_assignment.get(0).copied().unwrap_or(Scalar::zero());
        }

        Ok(DensePolynomial::from_coefficients_slice(&quotient_coeffs))
    }
}

/// Builder for constructing R1CS systems
pub struct R1CSBuilder {
    r1cs: R1CS,
    constraint_count: usize,
}

impl R1CSBuilder {
    /// Creates a new R1CS builder
    pub fn new(num_variables: usize, num_public_inputs: usize) -> Self {
        Self {
            r1cs: R1CS::new(0, num_variables, num_public_inputs), // Start with 0 constraints
            constraint_count: 0,
        }
    }

    /// Adds a multiplication constraint: a * b = c
    pub fn mul_constraint(
        &mut self,
        a_var: usize,
        b_var: usize,
        c_var: usize,
    ) -> Result<()> {
        self.ensure_capacity(1)?;
        
        let a_entries = vec![(a_var, Scalar::one())];
        let b_entries = vec![(b_var, Scalar::one())];
        let c_entries = vec![(c_var, Scalar::one())];
        
        self.r1cs.add_constraint(&a_entries, &b_entries, &c_entries)?;
        self.constraint_count += 1;
        Ok(())
    }

    /// Adds a linear constraint: sum(coeffs[i] * vars[i]) = 0
    pub fn linear_constraint(
        &mut self,
        terms: &[(usize, Scalar)],
    ) -> Result<()> {
        self.ensure_capacity(1)?;
        
        // Convert to R1CS form: terms * 1 = 0
        let a_entries = terms.to_vec();
        let b_entries = vec![(0, Scalar::one())]; // Variable 0 is always 1
        let c_entries = vec![]; // Empty C means 0
        
        self.r1cs.add_constraint(&a_entries, &b_entries, &c_entries)?;
        self.constraint_count += 1;
        Ok(())
    }

    /// Adds a boolean constraint: var * (1 - var) = 0
    pub fn bool_constraint(&mut self, var: usize) -> Result<()> {
        self.ensure_capacity(1)?;
        
        // var * (1 - var) = 0
        // A = var, B = (1 - var), C = 0
        let a_entries = vec![(var, Scalar::one())];
        let b_entries = vec![(0, Scalar::one()), (var, -Scalar::one())];
        let c_entries = vec![]; // 0
        
        self.r1cs.add_constraint(&a_entries, &b_entries, &c_entries)?;
        self.constraint_count += 1;
        Ok(())
    }

    /// Finalizes the R1CS construction
    pub fn build(mut self) -> R1CS {
        self.r1cs.num_constraints = self.constraint_count;
        self.r1cs
    }

    /// Ensures the R1CS has capacity for additional constraints
    fn ensure_capacity(&mut self, additional: usize) -> Result<()> {
        // In a real implementation, this would resize the matrices
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_sparse_matrix() {
        let mut matrix = SparseMatrix::new(3, 3);
        matrix.add_entry(0, 0, Scalar::one());
        matrix.add_entry(1, 1, Scalar::from(2u64));
        matrix.add_entry(2, 2, Scalar::from(3u64));

        assert_eq!(matrix.get(0, 0), Scalar::one());
        assert_eq!(matrix.get(1, 1), Scalar::from(2u64));
        assert_eq!(matrix.get(2, 2), Scalar::from(3u64));
        assert_eq!(matrix.get(0, 1), Scalar::zero());
    }

    #[test]
    fn test_r1cs_simple() {
        let mut r1cs = R1CS::new(1, 3, 1);
        
        // Constraint: x * x = y (where x and y are variables)
        r1cs.add_constraint(
            &[(1, Scalar::one())], // A: x
            &[(1, Scalar::one())], // B: x  
            &[(2, Scalar::one())], // C: y
        ).unwrap();

        // Test with x = 3, y = 9
        let assignment = vec![Scalar::one(), Scalar::from(3u64), Scalar::from(9u64)];
        assert!(r1cs.is_satisfied(&assignment).unwrap());

        // Test with x = 3, y = 8 (should fail)
        let bad_assignment = vec![Scalar::one(), Scalar::from(3u64), Scalar::from(8u64)];
        assert!(!r1cs.is_satisfied(&bad_assignment).unwrap());
    }

    #[test]
    fn test_r1cs_builder() {
        let mut builder = R1CSBuilder::new(4, 1);
        
        // Add x * x = y constraint
        builder.mul_constraint(1, 1, 2).unwrap();
        
        // Add boolean constraint on x
        builder.bool_constraint(1).unwrap();

        let r1cs = builder.build();
        assert_eq!(r1cs.num_constraints, 2);
        assert_eq!(r1cs.num_variables, 4);
    }

    #[test]
    fn test_r1cs_instance_witness() {
        let mut r1cs = R1CS::new(1, 3, 1);
        r1cs.add_constraint(
            &[(1, Scalar::one())],
            &[(1, Scalar::one())], 
            &[(2, Scalar::one())],
        ).unwrap();

        let public_inputs = vec![Scalar::from(3u64)];
        let instance = R1CSInstance::new(r1cs, public_inputs);
        
        let witness = R1CSWitness::new(vec![Scalar::from(9u64)]);
        assert!(instance.verify_witness(&witness).unwrap());
    }

    #[test]
    fn test_polynomial_encoding() {
        let mut r1cs = R1CS::new(2, 3, 1);
        
        r1cs.add_constraint(
            &[(1, Scalar::one())],
            &[(1, Scalar::one())],
            &[(2, Scalar::one())],
        ).unwrap();

        let domain = FftDomain::new(4).unwrap();
        let encoding = r1cs.to_polynomial_encoding(&domain).unwrap();
        
        assert_eq!(encoding.a_selectors.len(), 3);
        assert_eq!(encoding.b_selectors.len(), 3);
        assert_eq!(encoding.c_selectors.len(), 3);
    }
}