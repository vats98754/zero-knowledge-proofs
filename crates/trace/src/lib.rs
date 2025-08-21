//! Execution trace management for STARK proofs
//! 
//! This crate provides utilities for managing execution traces, including
//! low-degree extension (LDE) computation via FFT and trace validation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use stark_field::{F, GoldilocksField, get_root_of_unity, Zero, One};
use air::{ExecutionTrace, TraceRow, Air, AirError};
use ark_poly::{DenseUVPolynomial, Polynomial, EvaluationDomain};
use ark_ff::{FftField, Field as ArkField};
use rayon::prelude::*;
use std::collections::HashMap;
use thiserror::Error;
use serde::{Deserialize, Serialize};

/// Errors that can occur during trace processing
#[derive(Error, Debug)]
pub enum TraceError {
    /// Invalid trace dimensions
    #[error("Invalid trace dimensions: {message}")]
    InvalidDimensions { 
        /// Error message
        message: String 
    },
    
    /// FFT domain error
    #[error("FFT domain error: {message}")]
    FftDomainError { 
        /// Error message
        message: String 
    },
    
    /// Polynomial interpolation failed
    #[error("Polynomial interpolation failed: {message}")]
    InterpolationFailed { 
        /// Error message
        message: String 
    },
    
    /// LDE computation failed
    #[error("Low-degree extension computation failed: {message}")]
    LdeComputationFailed { 
        /// Error message
        message: String 
    },
    
    /// AIR validation failed
    #[error("AIR validation failed: {0}")]
    AirValidationFailed(#[from] AirError),
}

/// Domain for polynomial operations
#[derive(Debug, Clone)]
pub struct PolynomialDomain {
    /// Size of the trace domain (original trace length)
    pub trace_size: usize,
    /// Size of the LDE domain (extended domain for low-degree extension)  
    pub lde_size: usize,
    /// Blowup factor (lde_size / trace_size)
    pub blowup_factor: usize,
    /// Root of unity for trace domain
    pub trace_root: GoldilocksField,
    /// Root of unity for LDE domain
    pub lde_root: GoldilocksField,
    /// Trace domain elements
    pub trace_domain: Vec<GoldilocksField>,
    /// LDE domain elements
    pub lde_domain: Vec<GoldilocksField>,
}

impl PolynomialDomain {
    /// Create a new polynomial domain
    pub fn new(trace_size: usize, blowup_factor: usize) -> Result<Self, TraceError> {
        if !trace_size.is_power_of_two() {
            return Err(TraceError::InvalidDimensions {
                message: format!("Trace size must be power of 2, got {}", trace_size),
            });
        }
        
        if !blowup_factor.is_power_of_two() || blowup_factor < 2 {
            return Err(TraceError::InvalidDimensions {
                message: format!("Blowup factor must be power of 2 and >= 2, got {}", blowup_factor),
            });
        }
        
        let lde_size = trace_size * blowup_factor;
        
        let trace_root = get_root_of_unity(trace_size)
            .ok_or_else(|| TraceError::FftDomainError {
                message: format!("Cannot find root of unity for size {}", trace_size),
            })?;
            
        let lde_root = get_root_of_unity(lde_size)
            .ok_or_else(|| TraceError::FftDomainError {
                message: format!("Cannot find root of unity for size {}", lde_size),
            })?;
        
        // Generate domain elements
        let trace_domain = Self::generate_domain_elements(trace_root, trace_size);
        let lde_domain = Self::generate_domain_elements(lde_root, lde_size);
        
        Ok(Self {
            trace_size,
            lde_size,
            blowup_factor,
            trace_root,
            lde_root,
            trace_domain,
            lde_domain,
        })
    }
    
    /// Generate domain elements for a given root and size
    fn generate_domain_elements(root: GoldilocksField, size: usize) -> Vec<GoldilocksField> {
        let mut elements = Vec::with_capacity(size);
        let mut current = GoldilocksField::from(1u64);
        
        for _ in 0..size {
            elements.push(current);
            current *= root;
        }
        
        elements
    }
}

/// Represents a polynomial in coefficient form
#[derive(Debug, Clone)]
pub struct TracePolynomial {
    /// Polynomial coefficients (lowest degree first)
    pub coefficients: Vec<GoldilocksField>,
}

impl TracePolynomial {
    /// Create polynomial from coefficients
    pub fn from_coefficients(coefficients: Vec<GoldilocksField>) -> Self {
        Self { coefficients }
    }
    
    /// Evaluate polynomial at a point
    pub fn evaluate(&self, x: GoldilocksField) -> GoldilocksField {
        if self.coefficients.is_empty() {
            return GoldilocksField::zero();
        }
        
        // Horner's method
        let mut result = self.coefficients[self.coefficients.len() - 1];
        for &coeff in self.coefficients.iter().rev().skip(1) {
            result = result * x + coeff;
        }
        result
    }
    
    /// Evaluate polynomial at multiple points in parallel
    pub fn evaluate_batch(&self, points: &[GoldilocksField]) -> Vec<GoldilocksField> {
        points
            .par_iter()
            .map(|&x| self.evaluate(x))
            .collect()
    }
    
    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        if self.coefficients.is_empty() {
            return 0;
        }
        
        // Find the highest non-zero coefficient
        for (i, &coeff) in self.coefficients.iter().enumerate().rev() {
            if !coeff.is_zero() {
                return i;
            }
        }
        0
    }
}

/// Extended execution trace with polynomial representations
#[derive(Debug, Clone)]
pub struct ExtendedTrace {
    /// Original execution trace
    pub trace: ExecutionTrace,
    /// Domain for polynomial operations
    pub domain: PolynomialDomain,
    /// Interpolated polynomials for each trace column
    pub polynomials: Vec<TracePolynomial>,
    /// Low-degree extensions of each column
    pub lde_evaluations: Vec<Vec<GoldilocksField>>,
}

impl ExtendedTrace {
    /// Create an extended trace from an execution trace
    pub fn from_trace(
        trace: ExecutionTrace,
        blowup_factor: usize,
    ) -> Result<Self, TraceError> {
        if trace.is_empty() {
            return Err(TraceError::InvalidDimensions {
                message: "Cannot create extended trace from empty trace".to_string(),
            });
        }
        
        let trace_length = trace.len();
        let trace_width = trace[0].len();
        
        // Validate trace consistency
        for (i, row) in trace.iter().enumerate() {
            if row.len() != trace_width {
                return Err(TraceError::InvalidDimensions {
                    message: format!("Inconsistent trace width at row {}: expected {}, got {}", 
                                    i, trace_width, row.len()),
                });
            }
        }
        
        let domain = PolynomialDomain::new(trace_length, blowup_factor)?;
        
        // Interpolate polynomials for each column
        let polynomials = Self::interpolate_trace_columns(&trace, &domain)?;
        
        // Compute low-degree extensions
        let lde_evaluations = Self::compute_lde(&polynomials, &domain)?;
        
        Ok(Self {
            trace,
            domain,
            polynomials,
            lde_evaluations,
        })
    }
    
    /// Interpolate polynomials for each trace column
    fn interpolate_trace_columns(
        trace: &ExecutionTrace,
        domain: &PolynomialDomain,
    ) -> Result<Vec<TracePolynomial>, TraceError> {
        let trace_width = trace[0].len();
        let mut polynomials = Vec::with_capacity(trace_width);
        
        for col in 0..trace_width {
            // Extract column values
            let column_values: Vec<GoldilocksField> = trace
                .iter()
                .map(|row| row[col])
                .collect();
            
            // Interpolate using FFT
            let coefficients = Self::interpolate_fft(&column_values, domain)?;
            polynomials.push(TracePolynomial::from_coefficients(coefficients));
        }
        
        Ok(polynomials)
    }
    
    /// Interpolate a column using FFT
    fn interpolate_fft(
        values: &[GoldilocksField],
        domain: &PolynomialDomain,
    ) -> Result<Vec<GoldilocksField>, TraceError> {
        if values.len() != domain.trace_size {
            return Err(TraceError::InterpolationFailed {
                message: format!("Value count {} != domain size {}", 
                               values.len(), domain.trace_size),
            });
        }
        
        // Simple DFT-based interpolation (in practice, use optimized FFT)
        let mut coefficients = vec![GoldilocksField::zero(); domain.trace_size];
        let n = domain.trace_size as u64;
        let inv_n = GoldilocksField::from(n).inverse()
            .ok_or_else(|| TraceError::InterpolationFailed {
                message: "Cannot compute inverse of domain size".to_string(),
            })?;
        
        for i in 0..domain.trace_size {
            let mut sum = GoldilocksField::zero();
            for j in 0..domain.trace_size {
                let exponent = ((i * j) % domain.trace_size) as u64;
                let omega_power = domain.trace_root.pow(exponent);
                let inv_omega_power = omega_power.inverse()
                    .unwrap_or(GoldilocksField::zero());
                sum += values[j] * inv_omega_power;
            }
            coefficients[i] = sum * inv_n;
        }
        
        Ok(coefficients)
    }
    
    /// Compute low-degree extensions
    fn compute_lde(
        polynomials: &[TracePolynomial],
        domain: &PolynomialDomain,
    ) -> Result<Vec<Vec<GoldilocksField>>, TraceError> {
        let mut lde_evaluations = Vec::with_capacity(polynomials.len());
        
        for polynomial in polynomials {
            let evaluations = polynomial.evaluate_batch(&domain.lde_domain);
            lde_evaluations.push(evaluations);
        }
        
        Ok(lde_evaluations)
    }
    
    /// Get trace column at a specific index
    pub fn get_column(&self, column_index: usize) -> Option<Vec<GoldilocksField>> {
        if column_index >= self.trace[0].len() {
            return None;
        }
        
        Some(self.trace.iter().map(|row| row[column_index]).collect())
    }
    
    /// Get LDE evaluation for a specific column
    pub fn get_lde_column(&self, column_index: usize) -> Option<&Vec<GoldilocksField>> {
        self.lde_evaluations.get(column_index)
    }
    
    /// Validate the extended trace against an AIR
    pub fn validate_air<A: Air>(&self, air: &A) -> Result<(), TraceError> {
        air.validate_trace(&self.trace).map_err(TraceError::AirValidationFailed)
    }
    
    /// Get the number of columns in the trace
    pub fn width(&self) -> usize {
        if self.trace.is_empty() {
            0
        } else {
            self.trace[0].len()
        }
    }
    
    /// Get the length of the original trace
    pub fn length(&self) -> usize {
        self.trace.len()
    }
    
    /// Get the length of the LDE
    pub fn lde_length(&self) -> usize {
        self.domain.lde_size
    }
}

/// Trace generator utilities
pub struct TraceGenerator;

impl TraceGenerator {
    /// Generate a Fibonacci trace
    pub fn fibonacci_trace(
        initial_values: (GoldilocksField, GoldilocksField),
        length: usize,
    ) -> ExecutionTrace {
        let mut trace = Vec::with_capacity(length);
        
        if length == 0 {
            return trace;
        }
        
        // First row
        trace.push(vec![initial_values.0, initial_values.1]);
        
        // Generate subsequent rows
        for i in 1..length {
            let prev_prev = trace[i - 1][0];
            let prev = trace[i - 1][1];
            let current = prev_prev + prev;
            trace.push(vec![prev, current]);
        }
        
        trace
    }
    
    /// Generate a trace for simple arithmetic operations
    pub fn arithmetic_trace(
        operations: &[(String, GoldilocksField)],
        initial_value: GoldilocksField,
    ) -> ExecutionTrace {
        let mut trace = Vec::new();
        let mut current_value = initial_value;
        
        // Initial state
        trace.push(vec![current_value, GoldilocksField::zero()]);
        
        for (op, operand) in operations {
            let result = match op.as_str() {
                "add" => current_value + *operand,
                "sub" => current_value - *operand,
                "mul" => current_value * *operand,
                "div" => {
                    if !operand.is_zero() {
                        current_value / *operand
                    } else {
                        current_value // Division by zero -> no change
                    }
                }
                _ => current_value, // Unknown operation -> no change
            };
            
            trace.push(vec![result, *operand]);
            current_value = result;
        }
        
        trace
    }
    
    /// Pad a trace to the next power of 2 length
    pub fn pad_trace_to_power_of_two(mut trace: ExecutionTrace) -> ExecutionTrace {
        if trace.is_empty() {
            return trace;
        }
        
        let current_length = trace.len();
        let target_length = current_length.next_power_of_two();
        
        if target_length == current_length {
            return trace; // Already a power of 2
        }
        
        // Pad with copies of the last row
        let last_row = trace.last().unwrap().clone();
        trace.resize(target_length, last_row);
        
        trace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use air::{FibonacciAir, Air};
    use stark_field::F;
    
    #[test]
    fn test_polynomial_domain() {
        let domain = PolynomialDomain::new(8, 4).unwrap();
        assert_eq!(domain.trace_size, 8);
        assert_eq!(domain.lde_size, 32);
        assert_eq!(domain.blowup_factor, 4);
        assert_eq!(domain.trace_domain.len(), 8);
        assert_eq!(domain.lde_domain.len(), 32);
    }
    
    #[test]
    fn test_trace_polynomial() {
        let coeffs = vec![
            GoldilocksField::from(1u64), // constant term
            GoldilocksField::from(2u64), // x term
            GoldilocksField::from(3u64), // x^2 term
        ];
        let poly = TracePolynomial::from_coefficients(coeffs);
        
        // Test evaluation: 1 + 2x + 3x^2
        let x = GoldilocksField::from(2u64);
        let expected = GoldilocksField::from(1u64) 
            + GoldilocksField::from(2u64) * x 
            + GoldilocksField::from(3u64) * x * x;
        assert_eq!(poly.evaluate(x), expected);
        
        assert_eq!(poly.degree(), 2);
    }
    
    #[test]
    fn test_extended_trace_fibonacci() {
        let initial_values = (GoldilocksField::from(0u64), GoldilocksField::from(1u64));
        let trace = TraceGenerator::fibonacci_trace(initial_values, 8);
        
        let extended_trace = ExtendedTrace::from_trace(trace.clone(), 4).unwrap();
        
        assert_eq!(extended_trace.length(), 8);
        assert_eq!(extended_trace.lde_length(), 32);
        assert_eq!(extended_trace.width(), 2);
        
        // Validate against Fibonacci AIR
        let air = FibonacciAir::new(initial_values, 8);
        assert!(extended_trace.validate_air(&air).is_ok());
    }
    
    #[test]
    fn test_trace_generator_fibonacci() {
        let trace = TraceGenerator::fibonacci_trace(
            (GoldilocksField::from(0u64), GoldilocksField::from(1u64)),
            5,
        );
        
        assert_eq!(trace.len(), 5);
        assert_eq!(trace[0], vec![F::from(0u64), F::from(1u64)]);
        assert_eq!(trace[1], vec![F::from(1u64), F::from(1u64)]);
        assert_eq!(trace[2], vec![F::from(1u64), F::from(2u64)]);
        assert_eq!(trace[3], vec![F::from(2u64), F::from(3u64)]);
        assert_eq!(trace[4], vec![F::from(3u64), F::from(5u64)]);
    }
    
    #[test]
    fn test_trace_generator_arithmetic() {
        let operations = vec![
            ("add".to_string(), GoldilocksField::from(5u64)),
            ("mul".to_string(), GoldilocksField::from(2u64)),
            ("sub".to_string(), GoldilocksField::from(3u64)),
        ];
        
        let trace = TraceGenerator::arithmetic_trace(&operations, GoldilocksField::from(10u64));
        
        assert_eq!(trace.len(), 4); // Initial + 3 operations
        assert_eq!(trace[0][0], GoldilocksField::from(10u64)); // Initial
        assert_eq!(trace[1][0], GoldilocksField::from(15u64)); // 10 + 5
        assert_eq!(trace[2][0], GoldilocksField::from(30u64)); // 15 * 2
        assert_eq!(trace[3][0], GoldilocksField::from(27u64)); // 30 - 3
    }
    
    #[test]
    fn test_trace_padding() {
        let trace = vec![
            vec![F::from(1u64), F::from(2u64)],
            vec![F::from(3u64), F::from(4u64)],
            vec![F::from(5u64), F::from(6u64)],
        ];
        
        let padded = TraceGenerator::pad_trace_to_power_of_two(trace);
        assert_eq!(padded.len(), 4); // Next power of 2 after 3
        assert_eq!(padded[3], vec![F::from(5u64), F::from(6u64)]); // Last row repeated
    }
    
    #[test]
    fn test_invalid_trace_dimensions() {
        let trace = vec![
            vec![F::from(1u64), F::from(2u64)],
            vec![F::from(3u64)], // Wrong width
        ];
        
        let result = ExtendedTrace::from_trace(trace, 4);
        assert!(matches!(result, Err(TraceError::InvalidDimensions { .. })));
    }
}