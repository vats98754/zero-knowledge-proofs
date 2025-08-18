//! Constraint system for Halo2 arithmetic circuits
//!
//! This module implements the constraint system that allows defining and
//! managing polynomial constraints in PLONK-style arithmetic circuits.

use crate::{Column, Gate, LookupTable, Scalar, Result, Halo2Error};
use std::collections::HashMap;
use ff::Field;

/// A polynomial constraint in the circuit
#[derive(Clone, Debug, PartialEq)]
pub struct Constraint {
    /// Name of the constraint (for debugging)
    pub name: String,
    /// The polynomial expression that should equal zero
    pub expression: Expression,
    /// Whether this constraint is enabled
    pub enabled: bool,
}

/// A polynomial expression used in constraints
#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    /// Constant value
    Constant(Scalar),
    /// Reference to a column at a specific row offset
    Column {
        column: Column,
        rotation: i32,
    },
    /// Addition of two expressions
    Sum(Box<Expression>, Box<Expression>),
    /// Multiplication of two expressions
    Product(Box<Expression>, Box<Expression>),
    /// Scaling an expression by a constant
    Scaled(Box<Expression>, Scalar),
    /// Negation of an expression
    Negated(Box<Expression>),
}

/// Constraint system managing all circuit constraints
#[derive(Clone, Debug)]
pub struct ConstraintSystem {
    /// Number of advice columns
    pub advice_columns: usize,
    /// Number of fixed columns
    pub fixed_columns: usize,
    /// Number of instance columns
    pub instance_columns: usize,
    /// All polynomial constraints
    pub constraints: Vec<Constraint>,
    /// Gates that generate constraints
    pub gates: Vec<Gate>,
    /// Lookup arguments
    pub lookups: Vec<LookupTable>,
    /// Column assignments
    pub column_mapping: HashMap<String, Column>,
    /// Degrees of all constraints
    pub constraint_degrees: Vec<usize>,
}

impl Constraint {
    /// Create a new constraint
    pub fn new(name: String, expression: Expression) -> Self {
        Self {
            name,
            expression,
            enabled: true,
        }
    }

    /// Create a constraint that enforces equality between two expressions
    pub fn equal(name: String, left: Expression, right: Expression) -> Self {
        let expression = Expression::Sum(
            Box::new(left),
            Box::new(Expression::Negated(Box::new(right)))
        );
        Self::new(name, expression)
    }

    /// Disable this constraint
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if the constraint is satisfied by given values
    pub fn evaluate(&self, column_values: &HashMap<Column, Vec<Scalar>>, row: usize) -> Result<bool> {
        if !self.enabled {
            return Ok(true);
        }
        
        let result = self.expression.evaluate(column_values, row)?;
        Ok(result == Scalar::ZERO)
    }

    /// Get the degree of this constraint
    pub fn degree(&self) -> usize {
        self.expression.degree()
    }
}

impl Expression {
    /// Create a constant expression
    pub fn constant(value: Scalar) -> Self {
        Expression::Constant(value)
    }

    /// Create a column reference
    pub fn column(column: Column, rotation: i32) -> Self {
        Expression::Column { column, rotation }
    }

    /// Add two expressions
    pub fn add(self, other: Expression) -> Self {
        Expression::Sum(Box::new(self), Box::new(other))
    }

    /// Multiply two expressions
    pub fn mul(self, other: Expression) -> Self {
        Expression::Product(Box::new(self), Box::new(other))
    }

    /// Scale expression by a constant
    pub fn scale(self, scalar: Scalar) -> Self {
        Expression::Scaled(Box::new(self), scalar)
    }

    /// Negate the expression
    pub fn neg(self) -> Self {
        Expression::Negated(Box::new(self))
    }

    /// Subtract another expression
    pub fn sub(self, other: Expression) -> Self {
        self.add(other.neg())
    }

    /// Square the expression
    pub fn square(self) -> Self {
        let copy = self.clone();
        self.mul(copy)
    }

    /// Evaluate the expression at a given row
    pub fn evaluate(&self, column_values: &HashMap<Column, Vec<Scalar>>, row: usize) -> Result<Scalar> {
        match self {
            Expression::Constant(value) => Ok(*value),
            Expression::Column { column, rotation } => {
                let values = column_values.get(column)
                    .ok_or_else(|| Halo2Error::InvalidColumn(format!("Column {:?} not found", column)))?;
                    
                let target_row = if *rotation >= 0 {
                    row + (*rotation as usize)
                } else {
                    row.checked_sub((-*rotation) as usize)
                        .ok_or_else(|| Halo2Error::InvalidRotation(format!("Row {} with rotation {}", row, rotation)))?
                };
                
                if target_row >= values.len() {
                    return Err(Halo2Error::OutOfBounds(format!("Row {} out of bounds", target_row)));
                }
                
                Ok(values[target_row])
            },
            Expression::Sum(left, right) => {
                let left_val = left.evaluate(column_values, row)?;
                let right_val = right.evaluate(column_values, row)?;
                Ok(left_val + right_val)
            },
            Expression::Product(left, right) => {
                let left_val = left.evaluate(column_values, row)?;
                let right_val = right.evaluate(column_values, row)?;
                Ok(left_val * right_val)
            },
            Expression::Scaled(expr, scalar) => {
                let val = expr.evaluate(column_values, row)?;
                Ok(val * scalar)
            },
            Expression::Negated(expr) => {
                let val = expr.evaluate(column_values, row)?;
                Ok(-val)
            },
        }
    }

    /// Get the degree of this expression
    pub fn degree(&self) -> usize {
        match self {
            Expression::Constant(_) => 0,
            Expression::Column { .. } => 1,
            Expression::Sum(left, right) => left.degree().max(right.degree()),
            Expression::Product(left, right) => left.degree() + right.degree(),
            Expression::Scaled(expr, _) => expr.degree(),
            Expression::Negated(expr) => expr.degree(),
        }
    }
}

impl ConstraintSystem {
    /// Create a new constraint system
    pub fn new(advice_columns: usize, fixed_columns: usize, instance_columns: usize) -> Self {
        Self {
            advice_columns,
            fixed_columns,
            instance_columns,
            constraints: Vec::new(),
            gates: Vec::new(),
            lookups: Vec::new(),
            column_mapping: HashMap::new(),
            constraint_degrees: Vec::new(),
        }
    }

    /// Add a constraint to the system
    pub fn add_constraint(&mut self, constraint: Constraint) -> Result<()> {
        let degree = constraint.degree();
        self.constraint_degrees.push(degree);
        self.constraints.push(constraint);
        Ok(())
    }

    /// Add a gate to the system
    pub fn add_gate(&mut self, gate: Gate) -> Result<()> {
        // Generate constraints from the gate
        let gate_constraints = gate.generate_constraints()?;
        for constraint in gate_constraints {
            self.add_constraint(constraint)?;
        }
        self.gates.push(gate);
        Ok(())
    }

    /// Add a lookup table
    pub fn add_lookup(&mut self, lookup: LookupTable) -> Result<()> {
        self.lookups.push(lookup);
        Ok(())
    }

    /// Register a named column
    pub fn register_column(&mut self, name: String, column: Column) {
        self.column_mapping.insert(name, column);
    }

    /// Get a column by name
    pub fn get_column(&self, name: &str) -> Option<&Column> {
        self.column_mapping.get(name)
    }

    /// Get total number of columns
    pub fn total_columns(&self) -> usize {
        self.advice_columns + self.fixed_columns + self.instance_columns
    }

    /// Get maximum degree of all constraints
    pub fn max_degree(&self) -> usize {
        self.constraint_degrees.iter().max().copied().unwrap_or(0)
    }

    /// Verify all constraints are satisfied
    pub fn verify_constraints(
        &self,
        column_values: &HashMap<Column, Vec<Scalar>>,
        num_rows: usize,
    ) -> Result<bool> {
        for row in 0..num_rows {
            for constraint in &self.constraints {
                if !constraint.evaluate(column_values, row)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Get constraint system statistics
    pub fn stats(&self) -> ConstraintSystemStats {
        ConstraintSystemStats {
            num_constraints: self.constraints.len(),
            num_gates: self.gates.len(),
            num_lookups: self.lookups.len(),
            max_degree: self.max_degree(),
            total_columns: self.total_columns(),
            advice_columns: self.advice_columns,
            fixed_columns: self.fixed_columns,
            instance_columns: self.instance_columns,
        }
    }
}

/// Statistics about a constraint system
#[derive(Clone, Debug, PartialEq)]
pub struct ConstraintSystemStats {
    pub num_constraints: usize,
    pub num_gates: usize,
    pub num_lookups: usize,
    pub max_degree: usize,
    pub total_columns: usize,
    pub advice_columns: usize,
    pub fixed_columns: usize,
    pub instance_columns: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdviceColumn, FixedColumn};
    use bls12_381::Scalar as BlsScalar;
    use ff::Field;

    #[test]
    fn test_constraint_creation() {
        let expr = Expression::constant(BlsScalar::from(42u64));
        let constraint = Constraint::new("test".to_string(), expr);
        assert_eq!(constraint.name, "test");
        assert!(constraint.enabled);
    }

    #[test]
    fn test_expression_evaluation() {
        let mut column_values = HashMap::new();
        let col = Column::Advice(AdviceColumn { index: 0 });
        column_values.insert(col.clone(), vec![BlsScalar::from(10u64), BlsScalar::from(20u64)]);

        let expr = Expression::column(col, 0);
        let result = expr.evaluate(&column_values, 0).unwrap();
        assert_eq!(result, BlsScalar::from(10u64));

        let expr2 = Expression::column(Column::Advice(AdviceColumn { index: 0 }), 1);
        let result2 = expr2.evaluate(&column_values, 0).unwrap();
        assert_eq!(result2, BlsScalar::from(20u64));
    }

    #[test]
    fn test_expression_arithmetic() {
        let expr1 = Expression::constant(BlsScalar::from(5u64));
        let expr2 = Expression::constant(BlsScalar::from(3u64));
        
        let sum_expr = expr1.clone().add(expr2.clone());
        let product_expr = expr1.mul(expr2);
        
        let column_values = HashMap::new();
        
        let sum_result = sum_expr.evaluate(&column_values, 0).unwrap();
        assert_eq!(sum_result, BlsScalar::from(8u64));
        
        let product_result = product_expr.evaluate(&column_values, 0).unwrap();
        assert_eq!(product_result, BlsScalar::from(15u64));
    }

    #[test]
    fn test_constraint_system() {
        let mut cs = ConstraintSystem::new(2, 1, 1);
        
        let constraint = Constraint::new(
            "test_constraint".to_string(),
            Expression::constant(BlsScalar::ZERO)
        );
        
        cs.add_constraint(constraint).unwrap();
        
        assert_eq!(cs.constraints.len(), 1);
        assert_eq!(cs.total_columns(), 4);
    }

    #[test]
    fn test_constraint_verification() {
        let mut column_values = HashMap::new();
        let col = Column::Advice(AdviceColumn { index: 0 });
        column_values.insert(col.clone(), vec![BlsScalar::ZERO]);

        // This constraint should be satisfied (column value is zero)
        let constraint = Constraint::new(
            "zero_constraint".to_string(),
            Expression::column(col, 0)
        );
        
        let result = constraint.evaluate(&column_values, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn test_expression_degrees() {
        let const_expr = Expression::constant(BlsScalar::from(5u64));
        assert_eq!(const_expr.degree(), 0);

        let col_expr = Expression::column(Column::Advice(AdviceColumn { index: 0 }), 0);
        assert_eq!(col_expr.degree(), 1);

        let product_expr = col_expr.clone().mul(col_expr.clone());
        assert_eq!(product_expr.degree(), 2);

        let sum_expr = col_expr.clone().add(const_expr);
        assert_eq!(sum_expr.degree(), 1);
    }
}
