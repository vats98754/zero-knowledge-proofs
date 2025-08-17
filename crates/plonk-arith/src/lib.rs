//! PLONK arithmetization with wire model and custom gates
//!
//! This crate provides:
//! - Wire model with configurable number of wires per row  
//! - Custom gate constraints with polynomial selectors
//! - Permutation argument implementation
//! - Circuit building API

use plonk_field::{PlonkField, Polynomial};
use plonk_pc::{PCError, Transcript};
use ark_ff::{One, Zero};
use ark_std::{vec::Vec, collections::HashMap};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for arithmetization operations
#[derive(Debug, Error)]
pub enum ArithError {
    #[error("Invalid wire index: {index} >= {max}")]
    InvalidWireIndex { index: usize, max: usize },
    #[error("Invalid gate index: {index} >= {max}")]
    InvalidGateIndex { index: usize, max: usize },
    #[error("Constraint violation at row {row}: {constraint}")]
    ConstraintViolation { row: usize, constraint: String },
    #[error("Polynomial commitment error: {0}")]
    PolynomialCommitment(#[from] PCError),
    #[error("Invalid permutation: {0}")]
    InvalidPermutation(String),
}

/// Wire identifier for the circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WireId {
    pub row: usize,
    pub column: usize,
}

impl WireId {
    pub fn new(row: usize, column: usize) -> Self {
        Self { row, column }
    }
}

/// Wire values in the circuit
#[derive(Debug, Clone)]
pub struct WireValues {
    /// Values organized as rows × columns
    /// values[row][col] = value at (row, col)
    pub values: Vec<Vec<PlonkField>>,
    pub num_rows: usize,
    pub num_columns: usize,
}

impl WireValues {
    /// Create new wire values with given dimensions
    pub fn new(num_rows: usize, num_columns: usize) -> Self {
        let values = vec![vec![PlonkField::zero(); num_columns]; num_rows];
        Self {
            values,
            num_rows,
            num_columns,
        }
    }

    /// Get value at wire
    pub fn get(&self, wire: WireId) -> Result<PlonkField, ArithError> {
        if wire.row >= self.num_rows {
            return Err(ArithError::InvalidWireIndex {
                index: wire.row,
                max: self.num_rows,
            });
        }
        if wire.column >= self.num_columns {
            return Err(ArithError::InvalidWireIndex {
                index: wire.column,
                max: self.num_columns,
            });
        }
        Ok(self.values[wire.row][wire.column])
    }

    /// Set value at wire
    pub fn set(&mut self, wire: WireId, value: PlonkField) -> Result<(), ArithError> {
        if wire.row >= self.num_rows {
            return Err(ArithError::InvalidWireIndex {
                index: wire.row,
                max: self.num_rows,
            });
        }
        if wire.column >= self.num_columns {
            return Err(ArithError::InvalidWireIndex {
                index: wire.column,
                max: self.num_columns,
            });
        }
        self.values[wire.row][wire.column] = value;
        Ok(())
    }

    /// Convert to polynomials (one per column)
    pub fn to_polynomials(&self) -> Vec<Polynomial> {
        let mut polys = Vec::with_capacity(self.num_columns);
        
        for col in 0..self.num_columns {
            let coeffs: Vec<PlonkField> = (0..self.num_rows)
                .map(|row| self.values[row][col])
                .collect();
            polys.push(Polynomial::new(coeffs));
        }
        
        polys
    }
}

/// Gate constraint definition
/// Represents: q_M * a * b + q_L * a + q_R * b + q_O * c + q_C = 0
#[derive(Debug, Clone)]
pub struct GateConstraint {
    pub q_m: PlonkField,  // Multiplicative selector  
    pub q_l: PlonkField,  // Left wire selector
    pub q_r: PlonkField,  // Right wire selector
    pub q_o: PlonkField,  // Output wire selector
    pub q_c: PlonkField,  // Constant selector
}

impl GateConstraint {
    /// Create a new gate constraint
    pub fn new(q_m: PlonkField, q_l: PlonkField, q_r: PlonkField, q_o: PlonkField, q_c: PlonkField) -> Self {
        Self { q_m, q_l, q_r, q_o, q_c }
    }

    /// Create an addition gate: a + b = c (a + b - c = 0)
    pub fn addition() -> Self {
        Self::new(
            PlonkField::zero(),  // q_m
            PlonkField::one(),   // q_l
            PlonkField::one(),   // q_r
            -PlonkField::one(),  // q_o
            PlonkField::zero(),  // q_c
        )
    }

    /// Create a multiplication gate: a * b = c (a * b - c = 0)
    pub fn multiplication() -> Self {
        Self::new(
            PlonkField::one(),   // q_m
            PlonkField::zero(),  // q_l
            PlonkField::zero(),  // q_r
            -PlonkField::one(),  // q_o
            PlonkField::zero(),  // q_c
        )
    }

    /// Create a constant gate: a = constant (a - constant = 0)
    pub fn constant(value: PlonkField) -> Self {
        Self::new(
            PlonkField::zero(),  // q_m
            PlonkField::one(),   // q_l
            PlonkField::zero(),  // q_r
            PlonkField::zero(),  // q_o
            -value,              // q_c
        )
    }

    /// Evaluate the constraint for given wire values
    pub fn evaluate(&self, a: PlonkField, b: PlonkField, c: PlonkField) -> PlonkField {
        self.q_m * a * b + self.q_l * a + self.q_r * b + self.q_o * c + self.q_c
    }
}

/// Selector polynomials for gates
#[derive(Debug, Clone)]
pub struct SelectorPolynomials {
    pub q_m: Polynomial,  // Multiplicative selectors
    pub q_l: Polynomial,  // Left wire selectors
    pub q_r: Polynomial,  // Right wire selectors
    pub q_o: Polynomial,  // Output wire selectors
    pub q_c: Polynomial,  // Constant selectors
}

impl SelectorPolynomials {
    /// Create selector polynomials from gate constraints
    pub fn from_gates(gates: &[GateConstraint]) -> Self {
        let q_m_coeffs: Vec<PlonkField> = gates.iter().map(|g| g.q_m).collect();
        let q_l_coeffs: Vec<PlonkField> = gates.iter().map(|g| g.q_l).collect();
        let q_r_coeffs: Vec<PlonkField> = gates.iter().map(|g| g.q_r).collect();
        let q_o_coeffs: Vec<PlonkField> = gates.iter().map(|g| g.q_o).collect();
        let q_c_coeffs: Vec<PlonkField> = gates.iter().map(|g| g.q_c).collect();

        Self {
            q_m: Polynomial::new(q_m_coeffs),
            q_l: Polynomial::new(q_l_coeffs),
            q_r: Polynomial::new(q_r_coeffs),
            q_o: Polynomial::new(q_o_coeffs),
            q_c: Polynomial::new(q_c_coeffs),
        }
    }
}

/// Permutation argument for copy constraints
#[derive(Debug, Clone)]
pub struct PermutationArgument {
    /// Permutation mapping: wire_id -> wire_id it should equal
    pub permutation: HashMap<WireId, WireId>,
    /// Number of rows in the circuit
    pub num_rows: usize,
    /// Number of columns in the circuit  
    pub num_columns: usize,
}

impl PermutationArgument {
    /// Create a new permutation argument
    pub fn new(num_rows: usize, num_columns: usize) -> Self {
        Self {
            permutation: HashMap::new(),
            num_rows,
            num_columns,
        }
    }

    /// Add a copy constraint: wire1 should equal wire2
    pub fn add_constraint(&mut self, wire1: WireId, wire2: WireId) -> Result<(), ArithError> {
        if wire1.row >= self.num_rows || wire1.column >= self.num_columns {
            return Err(ArithError::InvalidWireIndex {
                index: wire1.row * self.num_columns + wire1.column,
                max: self.num_rows * self.num_columns,
            });
        }
        if wire2.row >= self.num_rows || wire2.column >= self.num_columns {
            return Err(ArithError::InvalidWireIndex {
                index: wire2.row * self.num_columns + wire2.column,
                max: self.num_rows * self.num_columns,
            });
        }

        self.permutation.insert(wire1, wire2);
        self.permutation.insert(wire2, wire1);
        Ok(())
    }

    /// Check if permutation constraints are satisfied
    pub fn check_constraints(&self, wires: &WireValues) -> Result<(), ArithError> {
        for (&wire1, &wire2) in &self.permutation {
            let val1 = wires.get(wire1)?;
            let val2 = wires.get(wire2)?;
            if val1 != val2 {
                return Err(ArithError::ConstraintViolation {
                    row: wire1.row,
                    constraint: format!("Copy constraint: {:?} != {:?}", wire1, wire2),
                });
            }
        }
        Ok(())
    }

    /// Compute permutation polynomial Z(x) using grand product argument
    pub fn compute_permutation_polynomial(
        &self,
        wires: &WireValues,
        _domain: &[PlonkField],
        beta: PlonkField,
        gamma: PlonkField,
    ) -> Result<Polynomial, ArithError> {
        let n = self.num_rows;
        let m = self.num_columns;
        
        // Initialize Z polynomial coefficients
        let mut z_values = vec![PlonkField::one(); n + 1];
        
        // Compute grand product: Z(ω^{i+1}) = Z(ω^i) * numerator(i) / denominator(i)
        for i in 0..n {
            let mut numerator = PlonkField::one();
            let mut denominator = PlonkField::one();
            
            for j in 0..m {
                let wire = WireId::new(i, j);
                let value = wires.get(wire)?;
                
                // Numerator: (value + β * σ(wire) + γ)
                let sigma_wire = self.get_permutation_value(wire);
                numerator *= value + beta * sigma_wire + gamma;
                
                // Denominator: (value + β * wire_index + γ)  
                let wire_index = PlonkField::from_u64((i * m + j) as u64);
                denominator *= value + beta * wire_index + gamma;
            }
            
            // Z(ω^{i+1}) = Z(ω^i) * numerator / denominator
            let inv_denominator = denominator.inverse()
                .ok_or_else(|| ArithError::InvalidPermutation("Zero denominator in permutation".to_string()))?;
            z_values[i + 1] = z_values[i] * numerator * inv_denominator;
        }
        
        // Check that Z(ω^n) = 1 (constraint that the permutation is valid)
        if !z_values[n].is_one() {
            return Err(ArithError::InvalidPermutation(
                "Permutation polynomial does not satisfy Z(ω^n) = 1".to_string()
            ));
        }
        
        // Interpolate Z polynomial from its evaluations on the domain
        // For simplicity, we'll return the evaluation vector as polynomial coefficients
        // In practice, you'd use polynomial interpolation
        Ok(Polynomial::new(z_values[..n].to_vec()))
    }
    
    /// Get the permutation value for a wire (used in grand product)
    fn get_permutation_value(&self, wire: WireId) -> PlonkField {
        if let Some(&target) = self.permutation.get(&wire) {
            PlonkField::from_u64((target.row * self.num_columns + target.column) as u64)
        } else {
            PlonkField::from_u64((wire.row * self.num_columns + wire.column) as u64)
        }
    }
}

/// PLONK circuit builder
#[derive(Debug)]
pub struct PlonkCircuit {
    /// Wire values
    pub wires: WireValues,
    /// Gate constraints (one per row)
    pub gates: Vec<GateConstraint>,
    /// Permutation argument
    pub permutation: PermutationArgument,
    /// Current row index for building
    current_row: usize,
}

impl PlonkCircuit {
    /// Create a new PLONK circuit with 3 wires per row (default)
    pub fn new(num_rows: usize) -> Self {
        Self::with_wires(num_rows, 3)
    }

    /// Create a new PLONK circuit with custom number of wires per row
    pub fn with_wires(num_rows: usize, num_wires: usize) -> Self {
        Self {
            wires: WireValues::new(num_rows, num_wires),
            gates: vec![GateConstraint::new(
                PlonkField::zero(),
                PlonkField::zero(),
                PlonkField::zero(),
                PlonkField::zero(),
                PlonkField::zero(),
            ); num_rows],
            permutation: PermutationArgument::new(num_rows, num_wires),
            current_row: 0,
        }
    }

    /// Add an addition gate: a + b = c
    pub fn add_addition_gate(
        &mut self,
        a: PlonkField,
        b: PlonkField,
        c: PlonkField,
    ) -> Result<(WireId, WireId, WireId), ArithError> {
        if self.current_row >= self.wires.num_rows {
            return Err(ArithError::InvalidGateIndex {
                index: self.current_row,
                max: self.wires.num_rows,
            });
        }

        let wire_a = WireId::new(self.current_row, 0);
        let wire_b = WireId::new(self.current_row, 1);
        let wire_c = WireId::new(self.current_row, 2);

        self.wires.set(wire_a, a)?;
        self.wires.set(wire_b, b)?;
        self.wires.set(wire_c, c)?;

        self.gates[self.current_row] = GateConstraint::addition();
        self.current_row += 1;

        Ok((wire_a, wire_b, wire_c))
    }

    /// Add a multiplication gate: a * b = c
    pub fn add_multiplication_gate(
        &mut self,
        a: PlonkField,
        b: PlonkField,
        c: PlonkField,
    ) -> Result<(WireId, WireId, WireId), ArithError> {
        if self.current_row >= self.wires.num_rows {
            return Err(ArithError::InvalidGateIndex {
                index: self.current_row,
                max: self.wires.num_rows,
            });
        }

        let wire_a = WireId::new(self.current_row, 0);
        let wire_b = WireId::new(self.current_row, 1);
        let wire_c = WireId::new(self.current_row, 2);

        self.wires.set(wire_a, a)?;
        self.wires.set(wire_b, b)?;
        self.wires.set(wire_c, c)?;

        self.gates[self.current_row] = GateConstraint::multiplication();
        self.current_row += 1;

        Ok((wire_a, wire_b, wire_c))
    }

    /// Add a copy constraint between two wires
    pub fn add_copy_constraint(&mut self, wire1: WireId, wire2: WireId) -> Result<(), ArithError> {
        self.permutation.add_constraint(wire1, wire2)
    }

    /// Check if all constraints are satisfied
    pub fn check_constraints(&self) -> Result<(), ArithError> {
        // Check gate constraints
        for (i, gate) in self.gates.iter().enumerate() {
            if i >= self.wires.num_rows {
                break;
            }
            
            let a = self.wires.get(WireId::new(i, 0))?;
            let b = self.wires.get(WireId::new(i, 1))?;
            let c = self.wires.get(WireId::new(i, 2))?;
            
            let result = gate.evaluate(a, b, c);
            if !result.is_zero() {
                return Err(ArithError::ConstraintViolation {
                    row: i,
                    constraint: format!("Gate constraint failed: {:?}", result),
                });
            }
        }

        // Check permutation constraints
        self.permutation.check_constraints(&self.wires)?;

        Ok(())
    }

    /// Get selector polynomials
    pub fn selector_polynomials(&self) -> SelectorPolynomials {
        SelectorPolynomials::from_gates(&self.gates)
    }

    /// Get wire polynomials
    pub fn wire_polynomials(&self) -> Vec<Polynomial> {
        self.wires.to_polynomials()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_constraints() {
        let add_gate = GateConstraint::addition();
        let mul_gate = GateConstraint::multiplication();

        // Test addition: 2 + 3 = 5
        let a = PlonkField::from_u64(2);
        let b = PlonkField::from_u64(3);
        let c = PlonkField::from_u64(5);
        assert!(add_gate.evaluate(a, b, c).is_zero());

        // Test multiplication: 2 * 3 = 6
        let a = PlonkField::from_u64(2);
        let b = PlonkField::from_u64(3);
        let c = PlonkField::from_u64(6);
        assert!(mul_gate.evaluate(a, b, c).is_zero());
    }

    #[test]
    fn test_plonk_circuit() {
        let mut circuit = PlonkCircuit::new(10);

        // Add some gates
        let a = PlonkField::from_u64(2);
        let b = PlonkField::from_u64(3);
        let c = a + b;
        let (wire_a, _wire_b, _wire_c) = circuit.add_addition_gate(a, b, c).unwrap();

        let d = PlonkField::from_u64(4);
        let e = a * d;
        let (wire_d, _, _wire_e) = circuit.add_multiplication_gate(a, d, e).unwrap();

        // Add copy constraint: wire_a should equal the first wire in multiplication
        circuit.add_copy_constraint(wire_a, wire_d).unwrap();

        // Check constraints
        circuit.check_constraints().unwrap();
    }

    #[test]
    fn test_permutation_argument() {
        let mut perm = PermutationArgument::new(3, 3);
        let wire1 = WireId::new(0, 0);
        let wire2 = WireId::new(1, 1);

        perm.add_constraint(wire1, wire2).unwrap();

        let mut wires = WireValues::new(3, 3);
        let value = PlonkField::from_u64(42);
        wires.set(wire1, value).unwrap();
        wires.set(wire2, value).unwrap();

        // Should pass with equal values
        perm.check_constraints(&wires).unwrap();

        // Should fail with different values
        wires.set(wire2, PlonkField::from_u64(43)).unwrap();
        assert!(perm.check_constraints(&wires).is_err());
    }

    #[test]
    fn test_wire_values_to_polynomials() {
        let mut wires = WireValues::new(3, 2);
        
        // Set some values
        wires.set(WireId::new(0, 0), PlonkField::from_u64(1)).unwrap();
        wires.set(WireId::new(1, 0), PlonkField::from_u64(2)).unwrap();
        wires.set(WireId::new(2, 0), PlonkField::from_u64(3)).unwrap();
        
        wires.set(WireId::new(0, 1), PlonkField::from_u64(4)).unwrap();
        wires.set(WireId::new(1, 1), PlonkField::from_u64(5)).unwrap();
        wires.set(WireId::new(2, 1), PlonkField::from_u64(6)).unwrap();

        let polys = wires.to_polynomials();
        assert_eq!(polys.len(), 2);
        
        // Check first column polynomial
        assert_eq!(polys[0].evaluate(PlonkField::zero()), PlonkField::from_u64(1));
        
        // Check second column polynomial  
        assert_eq!(polys[1].evaluate(PlonkField::zero()), PlonkField::from_u64(4));
    }
}