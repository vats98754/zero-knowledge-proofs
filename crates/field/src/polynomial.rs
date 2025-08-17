//! Polynomial operations optimized for zero-knowledge proofs

use crate::{Scalar, FieldError, Result};
use ark_poly::{
    univariate::DensePolynomial as ArkDensePolynomial,
    DenseUVPolynomial, Polynomial,
};
use ark_ff::{Zero, One, UniformRand, Field};
use rayon::prelude::*;

/// Dense univariate polynomial over the scalar field
pub type DensePolynomial = ArkDensePolynomial<Scalar>;

/// Polynomial operations for zero-knowledge proofs
pub struct PolynomialOps;

impl PolynomialOps {
    /// Evaluates a polynomial at a given point
    pub fn evaluate(poly: &DensePolynomial, point: &Scalar) -> Scalar {
        poly.evaluate(point)
    }
    
    /// Evaluates a polynomial at multiple points in parallel
    pub fn evaluate_batch(poly: &DensePolynomial, points: &[Scalar]) -> Vec<Scalar> {
        points.par_iter()
            .map(|point| poly.evaluate(point))
            .collect()
    }
    
    /// Interpolates a polynomial from points using Lagrange interpolation
    pub fn interpolate(points: &[(Scalar, Scalar)]) -> Result<DensePolynomial> {
        if points.is_empty() {
            return Ok(DensePolynomial::zero());
        }
        
        let mut result = DensePolynomial::zero();
        
        for (i, (xi, yi)) in points.iter().enumerate() {
            let mut basis = DensePolynomial::from_coefficients_vec(vec![*yi]);
            
            for (j, (xj, _)) in points.iter().enumerate() {
                if i != j {
                    let denominator = *xi - *xj;
                    if denominator.is_zero() {
                        return Err(FieldError::InvalidElement);
                    }
                    
                    // Multiply by (x - xj) / (xi - xj)
                    let linear = DensePolynomial::from_coefficients_vec(vec![-*xj, Scalar::one()]);
                    basis = &basis * &linear;
                    
                    // Scale by 1 / (xi - xj)
                    let inv_denominator = denominator.inverse().ok_or(FieldError::DivisionByZero)?;
                    basis = &basis * inv_denominator;
                }
            }
            
            result = &result + &basis;
        }
        
        Ok(result)
    }
    
    /// Computes the vanishing polynomial for a given set of points
    pub fn vanishing_polynomial(points: &[Scalar]) -> DensePolynomial {
        let mut result = DensePolynomial::from_coefficients_vec(vec![Scalar::one()]);
        
        for point in points {
            // Multiply by (x - point)
            let linear = DensePolynomial::from_coefficients_vec(vec![-*point, Scalar::one()]);
            result = &result * &linear;
        }
        
        result
    }
    
    /// Divides polynomial by vanishing polynomial, returning quotient and remainder
    pub fn divide_by_vanishing(
        dividend: &DensePolynomial,
        points: &[Scalar],
    ) -> Result<(DensePolynomial, DensePolynomial)> {
        let vanishing = Self::vanishing_polynomial(points);
        
        if vanishing.is_zero() {
            return Err(FieldError::DivisionByZero);
        }
        
        let (quotient, remainder) = ark_poly::polynomial::univariate::DenseOrSparsePolynomial::divide_with_q_and_r(
            &dividend.clone().into(),
            &vanishing.into(),
        ).ok_or(FieldError::DivisionByZero)?;
        
        Ok((
            quotient.try_into().map_err(|_| FieldError::InvalidElement)?,
            remainder.try_into().map_err(|_| FieldError::InvalidElement)?,
        ))
    }
    
    /// Computes the derivative of a polynomial
    pub fn derivative(poly: &DensePolynomial) -> DensePolynomial {
        if poly.degree() == 0 {
            return DensePolynomial::zero();
        }
        
        let coeffs = poly.coeffs();
        let mut derivative_coeffs = Vec::with_capacity(coeffs.len().saturating_sub(1));
        
        for (i, coeff) in coeffs.iter().enumerate().skip(1) {
            derivative_coeffs.push(*coeff * Scalar::from(i as u64));
        }
        
        DensePolynomial::from_coefficients_vec(derivative_coeffs)
    }
    
    /// Performs polynomial long division
    pub fn long_division(
        dividend: &DensePolynomial,
        divisor: &DensePolynomial,
    ) -> Result<(DensePolynomial, DensePolynomial)> {
        if divisor.is_zero() {
            return Err(FieldError::DivisionByZero);
        }
        
        let (quotient, remainder) = ark_poly::polynomial::univariate::DenseOrSparsePolynomial::divide_with_q_and_r(
            &dividend.clone().into(),
            &divisor.clone().into(),
        ).ok_or(FieldError::DivisionByZero)?;
        
        Ok((
            quotient.try_into().map_err(|_| FieldError::InvalidElement)?,
            remainder.try_into().map_err(|_| FieldError::InvalidElement)?,
        ))
    }
    
    /// Computes the greatest common divisor of two polynomials
    pub fn gcd(a: &DensePolynomial, b: &DensePolynomial) -> DensePolynomial {
        let mut a = a.clone();
        let mut b = b.clone();
        
        while !b.is_zero() {
            let (_, remainder) = Self::long_division(&a, &b).unwrap_or((a.clone(), DensePolynomial::zero()));
            a = b;
            b = remainder;
        }
        
        a
    }
    
    /// Creates a random polynomial of given degree
    pub fn random<R: rand::Rng + ?Sized>(rng: &mut R, degree: usize) -> DensePolynomial {
        let coeffs: Vec<Scalar> = (0..=degree)
            .map(|_| Scalar::rand(rng))
            .collect();
        DensePolynomial::from_coefficients_vec(coeffs)
    }
    
    /// Computes linear combination of polynomials
    pub fn linear_combination(
        coeffs: &[Scalar],
        polys: &[DensePolynomial],
    ) -> Result<DensePolynomial> {
        if coeffs.len() != polys.len() {
            return Err(FieldError::DegreeMismatch);
        }
        
        let mut result = DensePolynomial::zero();
        
        for (coeff, poly) in coeffs.iter().zip(polys.iter()) {
            let scaled = poly * *coeff;
            result = &result + &scaled;
        }
        
        Ok(result)
    }

    /// Interpolates a polynomial from domain evaluations using FFT
    pub fn interpolate_from_domain(
        evaluations: &[Scalar],
        domain: &crate::fft::FftDomain,
    ) -> Result<DensePolynomial> {
        if evaluations.len() > domain.size() {
            return Err(FieldError::InvalidFftSize);
        }

        // Pad evaluations to domain size
        let mut padded_evals = evaluations.to_vec();
        padded_evals.resize(domain.size(), Scalar::zero());

        // Use inverse FFT to get polynomial coefficients
        let coeffs = domain.ifft(&padded_evals)?;
        Ok(DensePolynomial::from_coefficients_vec(coeffs))
    }

    /// Adds two polynomials
    pub fn add(
        poly1: &DensePolynomial,
        poly2: &DensePolynomial,
    ) -> Result<DensePolynomial> {
        Ok(poly1 + poly2)
    }

    /// Subtracts two polynomials
    pub fn subtract(
        poly1: &DensePolynomial,
        poly2: &DensePolynomial,
    ) -> Result<DensePolynomial> {
        Ok(poly1 - poly2)
    }

    /// Multiplies two polynomials
    pub fn multiply(
        poly1: &DensePolynomial,
        poly2: &DensePolynomial,
    ) -> Result<DensePolynomial> {
        Ok(poly1 * poly2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::{Zero, UniformRand};
    
    #[test]
    fn test_polynomial_evaluation() {
        // Test polynomial: 2x^2 + 3x + 1
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Scalar::one(),
            Scalar::from(3u64),
            Scalar::from(2u64),
        ]);
        
        // Evaluate at x = 2: 2*4 + 3*2 + 1 = 15
        let point = Scalar::from(2u64);
        let result = PolynomialOps::evaluate(&poly, &point);
        let expected = Scalar::from(15u64);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_interpolation() {
        let points = vec![
            (Scalar::from(1u64), Scalar::from(2u64)),
            (Scalar::from(2u64), Scalar::from(5u64)),
            (Scalar::from(3u64), Scalar::from(10u64)),
        ];
        
        let poly = PolynomialOps::interpolate(&points).unwrap();
        
        // Verify interpolation by checking all points
        for (x, y) in points {
            assert_eq!(PolynomialOps::evaluate(&poly, &x), y);
        }
    }
    
    #[test]
    fn test_vanishing_polynomial() {
        let points = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let vanishing = PolynomialOps::vanishing_polynomial(&points);
        
        // Should evaluate to zero at all points
        for point in points {
            assert_eq!(PolynomialOps::evaluate(&vanishing, &point), Scalar::zero());
        }
    }
    
    #[test]
    fn test_derivative() {
        // Test polynomial: x^3 + 2x^2 + 3x + 4
        let poly = DensePolynomial::from_coefficients_vec(vec![
            Scalar::from(4u64),
            Scalar::from(3u64),
            Scalar::from(2u64),
            Scalar::from(1u64),
        ]);
        
        // Derivative should be: 3x^2 + 4x + 3
        let derivative = PolynomialOps::derivative(&poly);
        let expected = DensePolynomial::from_coefficients_vec(vec![
            Scalar::from(3u64),
            Scalar::from(4u64),
            Scalar::from(3u64),
        ]);
        
        assert_eq!(derivative, expected);
    }
    
    #[test]
    fn test_linear_combination() {
        let mut rng = test_rng();
        
        let poly1 = PolynomialOps::random(&mut rng, 3);
        let poly2 = PolynomialOps::random(&mut rng, 3);
        let poly3 = PolynomialOps::random(&mut rng, 3);
        
        let coeffs = vec![Scalar::from(2u64), Scalar::from(3u64), Scalar::from(5u64)];
        let polys = vec![poly1.clone(), poly2.clone(), poly3.clone()];
        
        let result = PolynomialOps::linear_combination(&coeffs, &polys).unwrap();
        
        // Verify at a random point
        let point = Scalar::rand(&mut rng);
        let result_eval = PolynomialOps::evaluate(&result, &point);
        let expected_eval = coeffs[0] * PolynomialOps::evaluate(&poly1, &point)
            + coeffs[1] * PolynomialOps::evaluate(&poly2, &point)
            + coeffs[2] * PolynomialOps::evaluate(&poly3, &point);
        
        assert_eq!(result_eval, expected_eval);
    }
}