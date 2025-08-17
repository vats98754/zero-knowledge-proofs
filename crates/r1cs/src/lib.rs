//! R1CS (Rank-1 Constraint System) implementation
//! 
//! This crate provides a constraint system for expressing arithmetic circuits
//! as R1CS constraints of the form: A * B = C, where A, B, and C are linear
//! combinations of variables.

#![forbid(unsafe_code)]

pub mod constraint;
pub mod linear_combination;
pub mod variable;

pub use constraint::*;
pub use linear_combination::*;
pub use variable::*;

use ark_ff::Field;
use ark_std::vec::Vec;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum R1CSError {
    #[error("Invalid constraint: {0}")]
    InvalidConstraint(String),
    #[error("Variable out of bounds: {0}")]
    VariableOutOfBounds(usize),
    #[error("Inconsistent witness")]
    InconsistentWitness,
}

/// R1CS constraint system
#[derive(Debug, Clone)]
pub struct R1CS<F: Field> {
    /// Number of variables (including public inputs and witness)
    pub num_variables: usize,
    /// Number of public input variables
    pub num_public_inputs: usize,
    /// Constraints in the system
    pub constraints: Vec<Constraint<F>>,
}

impl<F: Field> R1CS<F> {
    /// Create a new empty R1CS instance
    pub fn new() -> Self {
        Self {
            num_variables: 1, // Start with 1 for the constant "1" variable
            num_public_inputs: 0,
            constraints: Vec::new(),
        }
    }

    /// Allocate a new variable and return its index
    pub fn alloc_variable(&mut self) -> Variable {
        let var = Variable::new(self.num_variables);
        self.num_variables += 1;
        var
    }

    /// Allocate a public input variable
    pub fn alloc_public_input(&mut self) -> Variable {
        let var = self.alloc_variable();
        self.num_public_inputs += 1;
        var
    }

    /// Add a constraint to the system
    pub fn add_constraint(&mut self, a: LinearCombination<F>, b: LinearCombination<F>, c: LinearCombination<F>) -> Result<(), R1CSError> {
        // Validate that all variables are within bounds
        for term in a.terms.iter().chain(b.terms.iter()).chain(c.terms.iter()) {
            if term.variable.index >= self.num_variables {
                return Err(R1CSError::VariableOutOfBounds(term.variable.index));
            }
        }

        self.constraints.push(Constraint { a, b, c });
        Ok(())
    }

    /// Get the number of constraints
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Verify that a witness satisfies all constraints
    pub fn verify_witness(&self, witness: &[F]) -> Result<bool, R1CSError> {
        if witness.len() != self.num_variables {
            return Err(R1CSError::InconsistentWitness);
        }

        for constraint in &self.constraints {
            let a_val = constraint.a.evaluate(witness);
            let b_val = constraint.b.evaluate(witness);
            let c_val = constraint.c.evaluate(witness);

            if a_val * b_val != c_val {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get the constant "1" variable
    pub fn one_var() -> Variable {
        Variable::new(0)
    }

    /// Create a linear combination for the constant "1"
    pub fn one() -> LinearCombination<F> {
        LinearCombination::from_variable(Self::one_var())
    }
}

impl<F: Field> Default for R1CS<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn test_r1cs_basic() {
        let mut cs = R1CS::<Fr>::new();
        
        // Allocate variables: x, y, z
        let x = cs.alloc_variable();
        let y = cs.alloc_variable();
        let z = cs.alloc_variable();

        // Add constraint: x * y = z
        let a = LinearCombination::from_variable(x);
        let b = LinearCombination::from_variable(y);
        let c = LinearCombination::from_variable(z);
        
        cs.add_constraint(a, b, c).unwrap();

        // Create witness: [1, 3, 4, 12] (constant 1, x=3, y=4, z=12)
        let witness = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(4u64), Fr::from(12u64)];
        
        assert!(cs.verify_witness(&witness).unwrap());
        
        // Invalid witness
        let invalid_witness = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(4u64), Fr::from(13u64)];
        assert!(!cs.verify_witness(&invalid_witness).unwrap());
    }
}