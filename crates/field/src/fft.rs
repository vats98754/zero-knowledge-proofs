//! Fast Fourier Transform operations for polynomial arithmetic

use crate::{Scalar, FieldError, Result};
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use rayon::prelude::*;

/// FFT domain for polynomial operations
#[derive(Debug, Clone, Copy)]
pub struct FftDomain {
    domain: GeneralEvaluationDomain<Scalar>,
}

impl FftDomain {
    /// Creates a new FFT domain of the given size
    pub fn new(size: usize) -> Result<Self> {
        if !size.is_power_of_two() {
            return Err(FieldError::InvalidFftSize);
        }
        
        let domain = GeneralEvaluationDomain::new(size)
            .ok_or(FieldError::InvalidFftSize)?;
        
        Ok(Self { domain })
    }
    
    /// Returns the size of the domain
    pub fn size(&self) -> usize {
        self.domain.size()
    }
    
    /// Returns the generator of the domain
    pub fn generator(&self) -> Scalar {
        self.domain.group_gen()
    }
    
    /// Computes the FFT of the given coefficients
    pub fn fft(&self, coeffs: &[Scalar]) -> Result<Vec<Scalar>> {
        if coeffs.len() > self.size() {
            return Err(FieldError::InvalidFftSize);
        }
        
        let mut padded_coeffs = coeffs.to_vec();
        padded_coeffs.resize(self.size(), Scalar::zero());
        
        self.domain.fft_in_place(&mut padded_coeffs);
        Ok(padded_coeffs)
    }
    
    /// Computes the inverse FFT of the given evaluations
    pub fn ifft(&self, evals: &[Scalar]) -> Result<Vec<Scalar>> {
        if evals.len() != self.size() {
            return Err(FieldError::InvalidFftSize);
        }
        
        let mut coeffs = evals.to_vec();
        self.domain.ifft_in_place(&mut coeffs);
        Ok(coeffs)
    }
    
    /// Converts polynomial coefficients to evaluations
    pub fn coeff_to_eval(&self, coeffs: &[Scalar]) -> Result<Vec<Scalar>> {
        self.fft(coeffs)
    }
    
    /// Converts polynomial evaluations to coefficients
    pub fn eval_to_coeff(&self, evals: &[Scalar]) -> Result<Vec<Scalar>> {
        self.ifft(evals)
    }
    
    /// Evaluates a polynomial represented by coefficients at domain points
    pub fn evaluate_polynomial(&self, coeffs: &[Scalar]) -> Result<Vec<Scalar>> {
        self.coeff_to_eval(coeffs)
    }
    
    /// Interpolates a polynomial from evaluations at domain points
    pub fn interpolate_polynomial(&self, evals: &[Scalar]) -> Result<Vec<Scalar>> {
        self.eval_to_coeff(evals)
    }
    
    /// Performs pointwise multiplication of two polynomials in evaluation form
    pub fn pointwise_mul(&self, a_evals: &[Scalar], b_evals: &[Scalar]) -> Result<Vec<Scalar>> {
        if a_evals.len() != self.size() || b_evals.len() != self.size() {
            return Err(FieldError::InvalidFftSize);
        }
        
        Ok(a_evals.par_iter()
            .zip(b_evals.par_iter())
            .map(|(a, b)| *a * *b)
            .collect())
    }
    
    /// Computes the coset FFT for the given coefficients
    pub fn coset_fft(&self, coeffs: &[Scalar], coset_generator: &Scalar) -> Result<Vec<Scalar>> {
        if coeffs.len() > self.size() {
            return Err(FieldError::InvalidFftSize);
        }
        
        // Multiply by powers of coset generator
        let mut coset_coeffs: Vec<Scalar> = coeffs.iter()
            .enumerate()
            .map(|(i, coeff)| *coeff * coset_generator.pow(&[i as u64]))
            .collect();
        
        coset_coeffs.resize(self.size(), Scalar::zero());
        self.domain.fft_in_place(&mut coset_coeffs);
        Ok(coset_coeffs)
    }
    
    /// Computes the inverse coset FFT
    pub fn coset_ifft(&self, evals: &[Scalar], coset_generator: &Scalar) -> Result<Vec<Scalar>> {
        if evals.len() != self.size() {
            return Err(FieldError::InvalidFftSize);
        }
        
        let mut coeffs = evals.to_vec();
        self.domain.ifft_in_place(&mut coeffs);
        
        // Divide by powers of coset generator
        let coset_inv = coset_generator.inverse().ok_or(FieldError::DivisionByZero)?;
        Ok(coeffs.iter()
            .enumerate()
            .map(|(i, coeff)| *coeff * coset_inv.pow(&[i as u64]))
            .collect())
    }
}

/// FFT-based polynomial multiplication
pub struct FftPolynomialOps;

impl FftPolynomialOps {
    /// Multiplies two polynomials using FFT
    pub fn multiply(a_coeffs: &[Scalar], b_coeffs: &[Scalar]) -> Result<Vec<Scalar>> {
        if a_coeffs.is_empty() || b_coeffs.is_empty() {
            return Ok(vec![]);
        }
        
        let result_degree = a_coeffs.len() + b_coeffs.len() - 1;
        let fft_size = result_degree.next_power_of_two();
        
        let domain = FftDomain::new(fft_size)?;
        
        // Convert to evaluation form
        let a_evals = domain.coeff_to_eval(a_coeffs)?;
        let b_evals = domain.coeff_to_eval(b_coeffs)?;
        
        // Pointwise multiplication
        let result_evals = domain.pointwise_mul(&a_evals, &b_evals)?;
        
        // Convert back to coefficient form
        let mut result_coeffs = domain.eval_to_coeff(&result_evals)?;
        result_coeffs.truncate(result_degree);
        
        Ok(result_coeffs)
    }
    
    /// Adds two polynomials (coefficient-wise)
    pub fn add(a_coeffs: &[Scalar], b_coeffs: &[Scalar]) -> Vec<Scalar> {
        let max_len = a_coeffs.len().max(b_coeffs.len());
        let mut result = vec![Scalar::zero(); max_len];
        
        for (i, coeff) in a_coeffs.iter().enumerate() {
            result[i] += coeff;
        }
        
        for (i, coeff) in b_coeffs.iter().enumerate() {
            result[i] += coeff;
        }
        
        // Remove leading zeros
        while result.len() > 1 && result.last() == Some(&Scalar::zero()) {
            result.pop();
        }
        
        result
    }
    
    /// Subtracts two polynomials (coefficient-wise)
    pub fn subtract(a_coeffs: &[Scalar], b_coeffs: &[Scalar]) -> Vec<Scalar> {
        let max_len = a_coeffs.len().max(b_coeffs.len());
        let mut result = vec![Scalar::zero(); max_len];
        
        for (i, coeff) in a_coeffs.iter().enumerate() {
            result[i] += coeff;
        }
        
        for (i, coeff) in b_coeffs.iter().enumerate() {
            result[i] -= coeff;
        }
        
        // Remove leading zeros
        while result.len() > 1 && result.last() == Some(&Scalar::zero()) {
            result.pop();
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fft_domain_creation() {
        let domain = FftDomain::new(8).unwrap();
        assert_eq!(domain.size(), 8);
        
        // Test invalid size
        assert!(FftDomain::new(7).is_err());
    }
    
    #[test]
    fn test_fft_roundtrip() {
        let domain = FftDomain::new(8).unwrap();
        
        let coeffs = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        
        let evals = domain.fft(&coeffs).unwrap();
        let recovered_coeffs = domain.ifft(&evals).unwrap();
        
        // Should recover original coefficients (up to the original length)
        for (i, coeff) in coeffs.iter().enumerate() {
            assert_eq!(recovered_coeffs[i], *coeff);
        }
    }
    
    #[test]
    fn test_pointwise_multiplication() {
        let domain = FftDomain::new(8).unwrap();
        
        let a_coeffs = vec![Scalar::from(1u64), Scalar::from(2u64)]; // 2x + 1
        let b_coeffs = vec![Scalar::from(3u64), Scalar::from(4u64)]; // 4x + 3
        
        let a_evals = domain.coeff_to_eval(&a_coeffs).unwrap();
        let b_evals = domain.coeff_to_eval(&b_coeffs).unwrap();
        
        let result_evals = domain.pointwise_mul(&a_evals, &b_evals).unwrap();
        let result_coeffs = domain.eval_to_coeff(&result_evals).unwrap();
        
        // Expected: (2x + 1)(4x + 3) = 8x^2 + 10x + 3
        assert_eq!(result_coeffs[0], Scalar::from(3u64)); // constant term
        assert_eq!(result_coeffs[1], Scalar::from(10u64)); // x term
        assert_eq!(result_coeffs[2], Scalar::from(8u64)); // x^2 term
    }
    
    #[test]
    fn test_fft_polynomial_multiplication() {
        let a_coeffs = vec![Scalar::from(1u64), Scalar::from(2u64)]; // 2x + 1
        let b_coeffs = vec![Scalar::from(3u64), Scalar::from(4u64)]; // 4x + 3
        
        let result = FftPolynomialOps::multiply(&a_coeffs, &b_coeffs).unwrap();
        
        // Expected: (2x + 1)(4x + 3) = 8x^2 + 10x + 3
        assert_eq!(result[0], Scalar::from(3u64)); // constant term
        assert_eq!(result[1], Scalar::from(10u64)); // x term
        assert_eq!(result[2], Scalar::from(8u64)); // x^2 term
    }
    
    #[test]
    fn test_coset_fft() {
        let domain = FftDomain::new(8).unwrap();
        let coset_gen = Scalar::from(7u64); // multiplicative generator
        
        let coeffs = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        
        let coset_evals = domain.coset_fft(&coeffs, &coset_gen).unwrap();
        let recovered_coeffs = domain.coset_ifft(&coset_evals, &coset_gen).unwrap();
        
        // Should recover original coefficients
        for (i, coeff) in coeffs.iter().enumerate() {
            assert_eq!(recovered_coeffs[i], *coeff);
        }
    }
    
    #[test]
    fn test_polynomial_addition_subtraction() {
        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64)];
        
        let sum = FftPolynomialOps::add(&a, &b);
        assert_eq!(sum, vec![Scalar::from(5u64), Scalar::from(7u64), Scalar::from(3u64)]);
        
        let diff = FftPolynomialOps::subtract(&a, &b);
        assert_eq!(diff, vec![-Scalar::from(3u64), -Scalar::from(3u64), Scalar::from(3u64)]);
    }
}