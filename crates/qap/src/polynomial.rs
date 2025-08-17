//! Polynomial utilities for QAP operations

use ark_ff::{Field, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::vec::Vec;

/// Polynomial utilities
pub struct PolynomialUtils;

impl PolynomialUtils {
    /// Evaluate polynomial using standard evaluation
    pub fn horner_evaluate<F: Field>(poly: &DensePolynomial<F>, x: F) -> F {
        poly.evaluate(&x)
    }

    /// Compute polynomial division with remainder using DenseUVPolynomial trait
    pub fn divide_with_remainder<F: Field>(
        dividend: &DensePolynomial<F>,
        divisor: &DensePolynomial<F>,
    ) -> Option<(DensePolynomial<F>, DensePolynomial<F>)> {
        <DensePolynomial<F> as DenseUVPolynomial<F>>::divide_with_q_and_r(dividend, divisor)
    }

    /// Check if polynomial division is exact (remainder is zero)
    pub fn divides<F: Field>(dividend: &DensePolynomial<F>, divisor: &DensePolynomial<F>) -> bool {
        if let Some((_, remainder)) = Self::divide_with_remainder(dividend, divisor) {
            remainder.is_zero()
        } else {
            false
        }
    }

    /// Compute the formal derivative of a polynomial
    pub fn derivative<F: Field>(poly: &DensePolynomial<F>) -> DensePolynomial<F> {
        let coeffs = &poly.coeffs;
        if coeffs.len() <= 1 {
            return DensePolynomial::zero();
        }

        let mut derivative_coeffs = Vec::with_capacity(coeffs.len() - 1);
        for (i, &coeff) in coeffs.iter().enumerate().skip(1) {
            derivative_coeffs.push(coeff * F::from(i as u64));
        }

        DensePolynomial::from_coefficients_vec(derivative_coeffs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn test_polynomial_division() {
        // Create polynomials x^2 - 1 and x - 1
        let dividend = DensePolynomial::from_coefficients_vec(vec![Fr::from(-1i64), Fr::zero(), Fr::from(1u64)]); // x^2 - 1
        let divisor = DensePolynomial::from_coefficients_vec(vec![Fr::from(-1i64), Fr::from(1u64)]); // x - 1

        let (quotient, remainder) = PolynomialUtils::divide_with_remainder(&dividend, &divisor).unwrap();
        
        // x^2 - 1 = (x - 1)(x + 1) + 0
        assert!(remainder.is_zero());
        assert_eq!(quotient.evaluate(&Fr::from(2u64)), Fr::from(3u64)); // 2 + 1 = 3
    }

    #[test]
    fn test_derivative() {
        // Create polynomial x^3 + 2x^2 + 3x + 4
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(4u64), Fr::from(3u64), Fr::from(2u64), Fr::from(1u64)
        ]);

        let derivative = PolynomialUtils::derivative(&poly);
        
        // Derivative should be 3x^2 + 4x + 3
        let expected = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(3u64), Fr::from(4u64), Fr::from(3u64)
        ]);

        // Check at a test point
        let x = Fr::from(2u64);
        assert_eq!(derivative.evaluate(&x), expected.evaluate(&x));
    }
}