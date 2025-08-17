//! Linear combination representation for R1CS

use crate::Variable;
use ark_ff::Field;
use ark_std::{fmt, vec::Vec};
use serde::{Deserialize, Serialize};

/// A term in a linear combination: coefficient * variable
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Term<F: Field> {
    pub coefficient: F,
    pub variable: Variable,
}

impl<F: Field> Term<F> {
    /// Create a new term
    pub fn new(coefficient: F, variable: Variable) -> Self {
        Self { coefficient, variable }
    }
}

/// A linear combination of variables: c1*v1 + c2*v2 + ... + cn*vn
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearCombination<F: Field> {
    pub terms: Vec<Term<F>>,
}

impl<F: Field> LinearCombination<F> {
    /// Create an empty linear combination
    pub fn new() -> Self {
        Self { terms: Vec::new() }
    }

    /// Create a linear combination from a single variable
    pub fn from_variable(variable: Variable) -> Self {
        Self {
            terms: vec![Term::new(F::one(), variable)],
        }
    }

    /// Create a linear combination from a constant
    pub fn from_constant(constant: F) -> Self {
        Self {
            terms: vec![Term::new(constant, Variable::new(0))], // Variable 0 is always "1"
        }
    }

    /// Add a term to the linear combination
    pub fn add_term(&mut self, coefficient: F, variable: Variable) {
        self.terms.push(Term::new(coefficient, variable));
    }

    /// Add another linear combination to this one
    pub fn add(&mut self, other: &LinearCombination<F>) {
        self.terms.extend_from_slice(&other.terms);
    }

    /// Multiply the linear combination by a scalar
    pub fn mul_scalar(&mut self, scalar: F) {
        for term in &mut self.terms {
            term.coefficient *= scalar;
        }
    }

    /// Evaluate the linear combination given a witness
    pub fn evaluate(&self, witness: &[F]) -> F {
        let mut result = F::zero();
        for term in &self.terms {
            if term.variable.index < witness.len() {
                result += term.coefficient * witness[term.variable.index];
            }
        }
        result
    }

    /// Check if the linear combination is zero
    pub fn is_zero(&self) -> bool {
        self.terms.is_empty() || self.terms.iter().all(|term| term.coefficient.is_zero())
    }

    /// Get the number of terms
    pub fn len(&self) -> usize {
        self.terms.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }
}

impl<F: Field> Default for LinearCombination<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> fmt::Display for LinearCombination<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terms.is_empty() {
            return write!(f, "0");
        }

        for (i, term) in self.terms.iter().enumerate() {
            if i > 0 {
                write!(f, " + ")?;
            }
            write!(f, "{}*{}", term.coefficient, term.variable)?;
        }
        Ok(())
    }
}

// Arithmetic operations
impl<F: Field> std::ops::Add for LinearCombination<F> {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self.terms.extend_from_slice(&other.terms);
        self
    }
}

impl<F: Field> std::ops::Add<&LinearCombination<F>> for LinearCombination<F> {
    type Output = Self;

    fn add(mut self, other: &Self) -> Self {
        self.terms.extend_from_slice(&other.terms);
        self
    }
}

impl<F: Field> std::ops::Mul<F> for LinearCombination<F> {
    type Output = Self;

    fn mul(mut self, scalar: F) -> Self {
        self.mul_scalar(scalar);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn test_linear_combination() {
        let x = Variable::new(1);
        let y = Variable::new(2);

        // Create 2*x + 3*y
        let mut lc = LinearCombination::<Fr>::new();
        lc.add_term(Fr::from(2u64), x);
        lc.add_term(Fr::from(3u64), y);

        // Evaluate with witness [1, 5, 7] (constant=1, x=5, y=7)
        let witness = vec![Fr::from(1u64), Fr::from(5u64), Fr::from(7u64)];
        let result = lc.evaluate(&witness);
        
        // 2*5 + 3*7 = 10 + 21 = 31
        assert_eq!(result, Fr::from(31u64));
    }

    #[test]
    fn test_linear_combination_operations() {
        let x = Variable::new(1);
        let y = Variable::new(2);

        let lc1 = LinearCombination::<Fr>::from_variable(x);
        let lc2 = LinearCombination::<Fr>::from_variable(y);

        // Add linear combinations
        let sum = lc1 + lc2;
        assert_eq!(sum.len(), 2);

        // Multiply by scalar
        let scaled = sum * Fr::from(5u64);
        let witness = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        
        // (x + y) * 5 = (2 + 3) * 5 = 25
        assert_eq!(scaled.evaluate(&witness), Fr::from(25u64));
    }
}