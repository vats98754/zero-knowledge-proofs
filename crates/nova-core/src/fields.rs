//! Field operations and utilities for Nova.
//! 
//! This module provides field arithmetic operations over BLS12-381 scalar field
//! and utilities for multilinear polynomial operations.

use ark_bls12_381::Fr;
use ark_std::{vec::Vec, Zero, One};

/// The field used in Nova operations (BLS12-381 scalar field)
pub type NovaField = Fr;

/// A multilinear polynomial over the Nova field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultilinearPolynomial {
    /// Evaluations of the polynomial on the Boolean hypercube
    pub evaluations: Vec<NovaField>,
    /// Number of variables
    pub num_vars: usize,
}

impl MultilinearPolynomial {
    /// Creates a new multilinear polynomial with the given evaluations
    /// 
    /// # Arguments
    /// 
    /// * `evaluations` - Evaluations on the Boolean hypercube {0,1}^n
    /// 
    /// # Panics
    /// 
    /// Panics if the number of evaluations is not a power of 2
    pub fn new(evaluations: Vec<NovaField>) -> Self {
        let num_vars = evaluations.len().trailing_zeros() as usize;
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "Number of evaluations must be a power of 2"
        );
        
        Self {
            evaluations,
            num_vars,
        }
    }

    /// Returns the number of variables in the polynomial
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Evaluates the multilinear polynomial at a given point
    /// 
    /// Uses the multilinear extension formula:
    /// f(x) = Σ_{w ∈ {0,1}^n} f(w) * ∏_{i=1}^n ((1-x_i)(1-w_i) + x_i*w_i)
    pub fn evaluate(&self, point: &[NovaField]) -> NovaField {
        assert_eq!(
            point.len(),
            self.num_vars,
            "Point dimension must match number of variables"
        );

        let mut result = NovaField::zero();
        
        for (eval_idx, &evaluation) in self.evaluations.iter().enumerate() {
            let mut basis_eval = NovaField::one();
            
            // Compute the basis polynomial evaluation
            for (var_idx, &x_i) in point.iter().enumerate() {
                let w_i = if (eval_idx >> var_idx) & 1 == 1 {
                    NovaField::one()
                } else {
                    NovaField::zero()
                };
                
                // Basis polynomial: (1-x_i)(1-w_i) + x_i*w_i
                let term = (NovaField::one() - x_i) * (NovaField::one() - w_i) + x_i * w_i;
                basis_eval *= term;
            }
            
            result += evaluation * basis_eval;
        }
        
        result
    }

    /// Performs partial evaluation fixing the first variable to the given value
    pub fn partial_evaluation(&self, value: NovaField) -> Self {
        if self.num_vars == 0 {
            return self.clone();
        }

        let half_size = 1 << (self.num_vars - 1);
        let mut new_evaluations = Vec::with_capacity(half_size);

        // For each assignment to the remaining variables
        for i in 0..half_size {
            // Find the evaluations where first variable is 0 and 1
            // For index i in the reduced polynomial, we need to find the corresponding
            // indices in the original polynomial where only the first bit differs
            
            let idx_0 = i << 1;              // Set first bit to 0: ...i becomes 0...i  
            let idx_1 = (i << 1) | 1;       // Set first bit to 1: ...i becomes 1...i
            
            let eval_0 = self.evaluations[idx_0];  // f(0, remaining_vars) 
            let eval_1 = self.evaluations[idx_1];  // f(1, remaining_vars)
            
            // Linear interpolation: (1-value)*eval_0 + value*eval_1
            let new_eval = (NovaField::one() - value) * eval_0 + value * eval_1;
            new_evaluations.push(new_eval);
        }

        Self::new(new_evaluations)
    }
}

/// Inner product between two vectors of field elements
pub fn inner_product(a: &[NovaField], b: &[NovaField]) -> NovaField {
    assert_eq!(a.len(), b.len(), "Vectors must have the same length");
    
    a.iter()
        .zip(b.iter())
        .map(|(&a_i, &b_i)| a_i * b_i)
        .fold(NovaField::zero(), |acc, x| acc + x)
}

/// Computes the sum of squares of elements in a vector
pub fn sum_of_squares(elements: &[NovaField]) -> NovaField {
    elements.iter()
        .map(|&x| x * x)
        .fold(NovaField::zero(), |acc, x| acc + x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::{UniformRand, Field};

    #[test]
    fn test_multilinear_polynomial_creation() {
        let evaluations = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let poly = MultilinearPolynomial::new(evaluations.clone());
        
        assert_eq!(poly.num_vars(), 2);
        assert_eq!(poly.evaluations, evaluations);
    }

    #[test]
    fn test_multilinear_evaluation() {
        // Simple 2-variable polynomial: f(x,y) = 1 + 2x + 3y + 4xy
        // Evaluations: f(0,0)=1, f(1,0)=3, f(0,1)=4, f(1,1)=10
        let evaluations = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(4u64), Fr::from(10u64)];
        let poly = MultilinearPolynomial::new(evaluations);
        
        // Test evaluation at (0,0)
        let result = poly.evaluate(&[Fr::from(0u64), Fr::from(0u64)]);
        assert_eq!(result, Fr::from(1u64));
        
        // Test evaluation at (1,1)
        let result = poly.evaluate(&[Fr::from(1u64), Fr::from(1u64)]);
        assert_eq!(result, Fr::from(10u64));
        
        // Test evaluation at (0.5, 0.5)
        let half = Fr::from(2u64).inverse().unwrap();
        let result = poly.evaluate(&[half, half]);
        let expected = Fr::from(1u64) + Fr::from(3u64) + Fr::from(4u64) + Fr::from(10u64);
        assert_eq!(result * Fr::from(4u64), expected);
    }

    #[test]
    fn test_partial_evaluation() {
        let evaluations = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(4u64), Fr::from(10u64)];
        let poly = MultilinearPolynomial::new(evaluations);
        
        // Fix first variable to 0
        let partial = poly.partial_evaluation(Fr::from(0u64));
        assert_eq!(partial.num_vars(), 1);
        assert_eq!(partial.evaluations, vec![Fr::from(1u64), Fr::from(4u64)]);
        
        // Fix first variable to 1
        let partial = poly.partial_evaluation(Fr::from(1u64));
        assert_eq!(partial.num_vars(), 1);
        assert_eq!(partial.evaluations, vec![Fr::from(3u64), Fr::from(10u64)]);
    }

    #[test]
    fn test_inner_product() {
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        
        let result = inner_product(&a, &b);
        let expected = Fr::from(1*4 + 2*5 + 3*6); // 32
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sum_of_squares() {
        let elements = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let result = sum_of_squares(&elements);
        let expected = Fr::from(1*1 + 2*2 + 3*3); // 14
        assert_eq!(result, expected);
    }

    #[test]
    fn test_random_multilinear_consistency() {
        let mut rng = test_rng();
        let num_vars = 3;
        let size = 1 << num_vars;
        
        let evaluations: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPolynomial::new(evaluations.clone());
        
        // Test that evaluation at Boolean points matches the stored evaluations
        for i in 0..size {
            let mut point = Vec::new();
            for j in 0..num_vars {
                if (i >> j) & 1 == 1 {
                    point.push(Fr::one());
                } else {
                    point.push(Fr::zero());
                }
            }
            let result = poly.evaluate(&point);
            assert_eq!(result, evaluations[i]);
        }
    }
}