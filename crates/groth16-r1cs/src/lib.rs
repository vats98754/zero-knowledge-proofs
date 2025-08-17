//! R1CS (Rank-1 Constraint System) implementation for Groth16 zk-SNARK.
//!
//! This crate provides the constraint system builder API and data structures
//! for constructing R1CS constraints of the form: <a, z> * <b, z> = <c, z>
//! where z = [1 | public_inputs | witness].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use groth16_field::{FieldLike, FieldError};
use std::collections::HashMap;
use std::fmt;

pub use groth16_field;

/// Variable index in the constraint system
/// The convention is: z[0] = 1 (constant), z[1..num_public+1] = public inputs, 
/// z[num_public+1..] = witness variables
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Variable(pub usize);

impl Variable {
    /// Create a new variable with given index
    pub fn new(index: usize) -> Self {
        Variable(index)
    }
    
    /// Get the index of this variable
    pub fn index(&self) -> usize {
        self.0
    }
    
    /// The constant variable (always has value 1)
    pub const ONE: Variable = Variable(0);
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Linear combination of variables with field coefficients
/// Represents a sparse linear combination: Σ(coeff_i * var_i)
#[derive(Debug, Clone, PartialEq)]
pub struct LinearCombination<F: FieldLike> {
    /// Sparse representation: (variable_index, coefficient) pairs
    pub terms: HashMap<Variable, F>,
}

impl<F: FieldLike> LinearCombination<F> {
    /// Create a new empty linear combination
    pub fn new() -> Self {
        Self {
            terms: HashMap::new(),
        }
    }
    
    /// Create a linear combination from a single variable
    pub fn from_variable(var: Variable) -> Self {
        let mut lc = Self::new();
        lc.add_term(var, <F as FieldLike>::one());
        lc
    }
    
    /// Create a linear combination from a constant
    pub fn from_constant(constant: F) -> Self {
        let mut lc = Self::new();
        if !<F as FieldLike>::is_zero(&constant) {
            lc.add_term(Variable::ONE, constant);
        }
        lc
    }
    
    /// Add a term (variable * coefficient) to this linear combination
    pub fn add_term(&mut self, var: Variable, coeff: F) {
        if <F as FieldLike>::is_zero(&coeff) {
            return;
        }
        
        match self.terms.get_mut(&var) {
            Some(existing_coeff) => {
                *existing_coeff += coeff;
                if <F as FieldLike>::is_zero(existing_coeff) {
                    self.terms.remove(&var);
                }
            }
            None => {
                self.terms.insert(var, coeff);
            }
        }
    }
    
    /// Multiply this linear combination by a scalar
    pub fn mul_scalar(&mut self, scalar: F) {
        if <F as FieldLike>::is_zero(&scalar) {
            self.terms.clear();
            return;
        }
        
        for coeff in self.terms.values_mut() {
            *coeff *= scalar;
        }
    }
    
    /// Add another linear combination to this one
    pub fn add_lc(&mut self, other: &LinearCombination<F>) {
        for (&var, &coeff) in &other.terms {
            self.add_term(var, coeff);
        }
    }
    
    /// Subtract another linear combination from this one
    pub fn sub_lc(&mut self, other: &LinearCombination<F>) {
        for (&var, &coeff) in &other.terms {
            self.add_term(var, -coeff);
        }
    }
    
    /// Check if this linear combination is zero
    pub fn is_zero(&self) -> bool {
        self.terms.is_empty()
    }
    
    /// Evaluate this linear combination given variable assignments
    pub fn evaluate(&self, assignments: &[F]) -> Result<F, R1CSError> {
        let mut result = <F as FieldLike>::zero();
        
        for (&var, &coeff) in &self.terms {
            if var.index() >= assignments.len() {
                return Err(R1CSError::VariableOutOfBounds {
                    var_index: var.index(),
                    num_vars: assignments.len(),
                });
            }
            result += coeff * assignments[var.index()];
        }
        
        Ok(result)
    }
    
    /// Get the degree (number of non-zero terms) of this linear combination
    pub fn degree(&self) -> usize {
        self.terms.len()
    }
    
    /// Get all variables referenced in this linear combination
    pub fn variables(&self) -> Vec<Variable> {
        self.terms.keys().copied().collect()
    }
}

impl<F: FieldLike> Default for LinearCombination<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldLike> std::ops::Add for LinearCombination<F> {
    type Output = Self;
    
    fn add(mut self, other: Self) -> Self {
        self.add_lc(&other);
        self
    }
}

impl<F: FieldLike> std::ops::Sub for LinearCombination<F> {
    type Output = Self;
    
    fn sub(mut self, other: Self) -> Self {
        self.sub_lc(&other);
        self
    }
}

impl<F: FieldLike> std::ops::Mul<F> for LinearCombination<F> {
    type Output = Self;
    
    fn mul(mut self, scalar: F) -> Self {
        self.mul_scalar(scalar);
        self
    }
}

/// R1CS constraint: <A, z> * <B, z> = <C, z>
#[derive(Debug, Clone, PartialEq)]
pub struct Constraint<F: FieldLike> {
    /// Left linear combination (A)
    pub a: LinearCombination<F>,
    /// Right linear combination (B)  
    pub b: LinearCombination<F>,
    /// Output linear combination (C)
    pub c: LinearCombination<F>,
}

impl<F: FieldLike> Constraint<F> {
    /// Create a new constraint
    pub fn new(
        a: LinearCombination<F>,
        b: LinearCombination<F>, 
        c: LinearCombination<F>
    ) -> Self {
        Self { a, b, c }
    }
    
    /// Check if this constraint is satisfied by the given variable assignments
    pub fn is_satisfied(&self, assignments: &[F]) -> Result<bool, R1CSError> {
        let a_val = self.a.evaluate(assignments)?;
        let b_val = self.b.evaluate(assignments)?;
        let c_val = self.c.evaluate(assignments)?;
        
        Ok(a_val * b_val == c_val)
    }
    
    /// Get all variables referenced in this constraint
    pub fn variables(&self) -> Vec<Variable> {
        let mut vars = self.a.variables();
        vars.extend(self.b.variables());
        vars.extend(self.c.variables());
        vars.sort_by_key(|v| v.index());
        vars.dedup();
        vars
    }
}

/// R1CS (Rank-1 Constraint System) builder
#[derive(Debug, Clone)]
pub struct R1CS<F: FieldLike> {
    /// All constraints in the system
    pub constraints: Vec<Constraint<F>>,
    /// Number of public input variables (excluding the constant 1)
    pub num_public_inputs: usize,
    /// Total number of variables (including constant, public inputs, and witness)
    pub num_variables: usize,
    /// Variable allocation counter
    next_var_index: usize,
}

impl<F: FieldLike> R1CS<F> {
    /// Create a new empty R1CS with specified number of public inputs
    pub fn new(num_public_inputs: usize) -> Self {
        Self {
            constraints: Vec::new(),
            num_public_inputs,
            num_variables: 1 + num_public_inputs, // 1 for constant + public inputs
            next_var_index: 1 + num_public_inputs, // Next variable after public inputs
        }
    }
    
    /// Allocate a new witness variable and return its Variable handle
    pub fn allocate_variable(&mut self) -> Variable {
        let var = Variable::new(self.next_var_index);
        self.next_var_index += 1;
        self.num_variables += 1;
        var
    }
    
    /// Add a constraint to the system: A * B = C
    pub fn add_constraint(
        &mut self,
        a: LinearCombination<F>,
        b: LinearCombination<F>,
        c: LinearCombination<F>,
    ) {
        self.constraints.push(Constraint::new(a, b, c));
    }
    
    /// Convenience method to enforce equality: left = right
    pub fn enforce_equal(
        &mut self,
        left: LinearCombination<F>,
        right: LinearCombination<F>,
    ) {
        // (left - right) * 1 = 0
        let mut diff = left;
        diff.sub_lc(&right);
        self.add_constraint(
            diff,
            LinearCombination::from_constant(<F as FieldLike>::one()),
            LinearCombination::new(), // zero
        );
    }
    
    /// Convenience method to enforce multiplication: left * right = output
    pub fn enforce_multiplication(
        &mut self,
        left: LinearCombination<F>,
        right: LinearCombination<F>,
        output: LinearCombination<F>,
    ) {
        self.add_constraint(left, right, output);
    }
    
    /// Check if all constraints are satisfied by the given assignment
    pub fn is_satisfied(&self, assignment: &[F]) -> Result<bool, R1CSError> {
        if assignment.len() != self.num_variables {
            return Err(R1CSError::InvalidAssignmentSize {
                expected: self.num_variables,
                actual: assignment.len(),
            });
        }
        
        // Check that the first variable is always 1 (constant)
        if !<F as FieldLike>::is_one(&assignment[0]) {
            return Err(R1CSError::InvalidConstantVariable);
        }
        
        for (i, constraint) in self.constraints.iter().enumerate() {
            if !constraint.is_satisfied(assignment)? {
                return Err(R1CSError::UnsatisfiedConstraint { constraint_index: i });
            }
        }
        
        Ok(true)
    }
    
    /// Get the number of constraints
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
    
    /// Get public input variable handles
    pub fn public_input_variables(&self) -> Vec<Variable> {
        (1..=self.num_public_inputs)
            .map(Variable::new)
            .collect()
    }
    
    /// Create an assignment vector from public inputs and witness
    pub fn create_assignment(
        &self,
        public_inputs: &[F],
        witness: &[F]
    ) -> Result<Vec<F>, R1CSError> {
        if public_inputs.len() != self.num_public_inputs {
            return Err(R1CSError::InvalidPublicInputSize {
                expected: self.num_public_inputs,
                actual: public_inputs.len(),
            });
        }
        
        let expected_witness_size = self.num_variables - 1 - self.num_public_inputs;
        if witness.len() != expected_witness_size {
            return Err(R1CSError::InvalidWitnessSize {
                expected: expected_witness_size,
                actual: witness.len(),
            });
        }
        
        let mut assignment = Vec::with_capacity(self.num_variables);
        assignment.push(<F as FieldLike>::one()); // Constant variable
        assignment.extend_from_slice(public_inputs);
        assignment.extend_from_slice(witness);
        
        Ok(assignment)
    }
}

impl<F: FieldLike> Default for R1CS<F> {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Errors that can occur in R1CS operations
#[derive(Debug, thiserror::Error)]
pub enum R1CSError {
    /// Variable index out of bounds
    #[error("Variable index {var_index} out of bounds (have {num_vars} variables)")]
    VariableOutOfBounds { 
        /// Index of the variable that was out of bounds
        var_index: usize, 
        /// Total number of variables available
        num_vars: usize 
    },
    
    /// Invalid assignment size
    #[error("Invalid assignment size: expected {expected}, got {actual}")]
    InvalidAssignmentSize { 
        /// Expected number of variables
        expected: usize, 
        /// Actual number of variables provided
        actual: usize 
    },
    
    /// Invalid public input size
    #[error("Invalid public input size: expected {expected}, got {actual}")]
    InvalidPublicInputSize { 
        /// Expected number of public inputs
        expected: usize, 
        /// Actual number of public inputs provided
        actual: usize 
    },
    
    /// Invalid witness size
    #[error("Invalid witness size: expected {expected}, got {actual}")]
    InvalidWitnessSize { 
        /// Expected number of witness variables
        expected: usize, 
        /// Actual number of witness variables provided
        actual: usize 
    },
    
    /// Constraint not satisfied
    #[error("Constraint {constraint_index} not satisfied")]
    UnsatisfiedConstraint { 
        /// Index of the constraint that failed
        constraint_index: usize 
    },
    
    /// Invalid constant variable (should always be 1)
    #[error("Invalid constant variable: should always be 1")]
    InvalidConstantVariable,
    
    /// Field operation error
    #[error("Field error: {0}")]
    FieldError(#[from] FieldError),
}

/// Utility functions for building common constraints
pub mod utils {
    use super::*;
    
    /// Create a constraint enforcing that a variable is boolean (0 or 1)
    pub fn boolean_constraint<F: FieldLike>(
        r1cs: &mut R1CS<F>,
        var: Variable
    ) {
        // var * var = var  (this ensures var ∈ {0, 1})
        let var_lc = LinearCombination::from_variable(var);
        r1cs.enforce_multiplication(
            var_lc.clone(),
            var_lc.clone(),
            var_lc
        );
    }
    
    /// Create constraints for bit decomposition of a field element
    pub fn bit_decomposition<F: FieldLike>(
        r1cs: &mut R1CS<F>,
        value_var: Variable,
        num_bits: usize
    ) -> Vec<Variable> {
        let mut bit_vars = Vec::with_capacity(num_bits);
        
        // Allocate bit variables
        for _ in 0..num_bits {
            let bit_var = r1cs.allocate_variable();
            boolean_constraint(r1cs, bit_var);
            bit_vars.push(bit_var);
        }
        
        // Ensure the bits sum to the original value
        let mut sum_lc = LinearCombination::new();
        let mut power_of_two = <F as FieldLike>::one();
        
        for &bit_var in &bit_vars {
            let mut term = LinearCombination::from_variable(bit_var);
            term.mul_scalar(power_of_two);
            sum_lc.add_lc(&term);
            power_of_two = power_of_two + power_of_two; // power_of_two *= 2
        }
        
        r1cs.enforce_equal(
            LinearCombination::from_variable(value_var),
            sum_lc
        );
        
        bit_vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_field::F;
    
    #[test]
    fn test_linear_combination_basic() {
        let mut lc = LinearCombination::<F>::new();
        let var1 = Variable::new(1);
        let var2 = Variable::new(2);
        
        lc.add_term(var1, F::from(2u64));
        lc.add_term(var2, F::from(3u64));
        
        // Test evaluation: 2*5 + 3*7 = 10 + 21 = 31
        let assignment = vec![<F as FieldLike>::one(), F::from(5u64), F::from(7u64)];
        let result = lc.evaluate(&assignment).unwrap();
        assert_eq!(result, F::from(31u64));
    }
    
    #[test]
    fn test_linear_combination_operations() {
        let var1 = Variable::new(1);
        let var2 = Variable::new(2);
        
        let mut lc1 = LinearCombination::<F>::from_variable(var1);
        let lc2 = LinearCombination::<F>::from_variable(var2);
        
        lc1.add_lc(&lc2);
        
        // Should be var1 + var2
        let assignment = vec![<F as FieldLike>::one(), F::from(3u64), F::from(4u64)];
        let result = lc1.evaluate(&assignment).unwrap();
        assert_eq!(result, F::from(7u64));
    }
    
    #[test]
    fn test_constraint_satisfaction() {
        let var1 = Variable::new(1);
        let var2 = Variable::new(2);
        let var3 = Variable::new(3);
        
        // Constraint: var1 * var2 = var3
        let constraint = Constraint::new(
            LinearCombination::from_variable(var1),
            LinearCombination::from_variable(var2),
            LinearCombination::from_variable(var3),
        );
        
        // Test with satisfying assignment: 3 * 4 = 12
        let assignment = vec![<F as FieldLike>::one(), F::from(3u64), F::from(4u64), F::from(12u64)];
        assert!(constraint.is_satisfied(&assignment).unwrap());
        
        // Test with non-satisfying assignment: 3 * 4 ≠ 13
        let assignment = vec![<F as FieldLike>::one(), F::from(3u64), F::from(4u64), F::from(13u64)];
        assert!(!constraint.is_satisfied(&assignment).unwrap());
    }
    
    #[test]
    fn test_r1cs_basic() {
        let mut r1cs = R1CS::<F>::new(2); // 2 public inputs
        
        // Allocate witness variables
        let w1 = r1cs.allocate_variable();
        let w2 = r1cs.allocate_variable();
        
        // Add constraint: public_input[0] * public_input[1] = w1
        let pub1 = Variable::new(1);
        let pub2 = Variable::new(2);
        
        r1cs.enforce_multiplication(
            LinearCombination::from_variable(pub1),
            LinearCombination::from_variable(pub2),
            LinearCombination::from_variable(w1),
        );
        
        // Add constraint: w1 + public_input[0] = w2
        let mut left = LinearCombination::from_variable(w1);
        left.add_lc(&LinearCombination::from_variable(pub1));
        r1cs.enforce_equal(left, LinearCombination::from_variable(w2));
        
        // Test with satisfying assignment
        let public_inputs = vec![F::from(3u64), F::from(4u64)];
        let witness = vec![F::from(12u64), F::from(15u64)]; // 3*4=12, 12+3=15
        
        let assignment = r1cs.create_assignment(&public_inputs, &witness).unwrap();
        assert!(r1cs.is_satisfied(&assignment).unwrap());
    }
    
    #[test]
    fn test_boolean_constraint() {
        let mut r1cs = R1CS::<F>::new(0);
        let bool_var = r1cs.allocate_variable();
        
        utils::boolean_constraint(&mut r1cs, bool_var);
        
        // Test with true (1)
        let assignment1 = vec![<F as FieldLike>::one(), <F as FieldLike>::one()];
        assert!(r1cs.is_satisfied(&assignment1).unwrap());
        
        // Test with false (0)
        let assignment2 = vec![<F as FieldLike>::one(), <F as FieldLike>::zero()];
        assert!(r1cs.is_satisfied(&assignment2).unwrap());
        
        // Test with invalid value (2) - should not satisfy
        let assignment3 = vec![<F as FieldLike>::one(), F::from(2u64)];
        match r1cs.is_satisfied(&assignment3) {
            Ok(satisfied) => assert!(!satisfied, "Assignment with value 2 should not satisfy boolean constraint"),
            Err(_) => {} // Error is also acceptable - constraint fails
        }
    }
}