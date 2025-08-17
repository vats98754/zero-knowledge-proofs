//! Halo2 circuit implementation
//!
//! This module provides the main circuit building functionality for creating
//! PLONK-style arithmetic circuits with configurable gates and lookup tables.

use crate::{
    ConstraintSystem, Gate, Column, LookupTable, ColumnManager, 
    Scalar, Result, Halo2Error, AdviceColumn, FixedColumn, InstanceColumn
};
use std::collections::HashMap;

/// A complete Halo2 arithmetic circuit
#[derive(Clone, Debug)]
pub struct Halo2Circuit {
    /// The constraint system for this circuit
    pub constraint_system: ConstraintSystem,
    /// Column manager for organizing columns
    pub column_manager: ColumnManager,
    /// Circuit configuration parameters
    pub config: CircuitConfig,
    /// Whether the circuit has been finalized
    pub finalized: bool,
}

/// Configuration parameters for a Halo2 circuit
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    /// Number of advice columns to allocate
    pub num_advice: usize,
    /// Number of fixed columns to allocate
    pub num_fixed: usize,
    /// Number of instance columns to allocate
    pub num_instance: usize,
    /// Circuit size (number of rows)
    pub circuit_size: usize,
    /// Security parameter
    pub security_bits: usize,
}

/// Circuit builder for constructing Halo2 circuits step by step
#[derive(Clone, Debug)]
pub struct CircuitBuilder {
    /// The circuit being built
    circuit: Halo2Circuit,
    /// Gates added to the circuit
    gates: Vec<Gate>,
    /// Lookup tables added to the circuit
    lookups: Vec<LookupTable>,
}

/// Circuit synthesis context
#[derive(Clone, Debug)]
pub struct SynthesisContext {
    /// Current row being synthesized
    pub current_row: usize,
    /// Column assignments
    pub assignments: HashMap<Column, Vec<Scalar>>,
    /// Instance values
    pub instances: HashMap<InstanceColumn, Vec<Scalar>>,
    /// Fixed values
    pub fixed: HashMap<FixedColumn, Vec<Scalar>>,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            num_advice: 3,
            num_fixed: 1,
            num_instance: 1,
            circuit_size: 1024,
            security_bits: 128,
        }
    }
}

impl CircuitConfig {
    /// Create a new circuit configuration
    pub fn new(num_advice: usize, num_fixed: usize, num_instance: usize) -> Self {
        Self {
            num_advice,
            num_fixed,
            num_instance,
            circuit_size: 1024,
            security_bits: 128,
        }
    }

    /// Set the circuit size
    pub fn with_circuit_size(mut self, size: usize) -> Self {
        self.circuit_size = size;
        self
    }

    /// Set the security parameter
    pub fn with_security_bits(mut self, bits: usize) -> Self {
        self.security_bits = bits;
        self
    }
}

impl Halo2Circuit {
    /// Create a new Halo2 circuit with the given configuration
    pub fn new(config: CircuitConfig) -> Self {
        let constraint_system = ConstraintSystem::new(
            config.num_advice,
            config.num_fixed,
            config.num_instance,
        );
        let column_manager = ColumnManager::new();

        Self {
            constraint_system,
            column_manager,
            config,
            finalized: false,
        }
    }

    /// Create a circuit with default configuration
    pub fn default() -> Self {
        Self::new(CircuitConfig::default())
    }

    /// Add a gate to the circuit
    pub fn add_gate(&mut self, gate: Gate) -> Result<()> {
        if self.finalized {
            return Err(Halo2Error::InvalidCircuit("Cannot modify finalized circuit".to_string()));
        }
        self.constraint_system.add_gate(gate)
    }

    /// Add a lookup table to the circuit
    pub fn add_lookup(&mut self, lookup: LookupTable) -> Result<()> {
        if self.finalized {
            return Err(Halo2Error::InvalidCircuit("Cannot modify finalized circuit".to_string()));
        }
        self.constraint_system.add_lookup(lookup)
    }

    /// Add an advice column to the circuit
    pub fn add_advice_column(&mut self) -> Result<AdviceColumn> {
        if self.finalized {
            return Err(Halo2Error::InvalidCircuit("Cannot modify finalized circuit".to_string()));
        }
        Ok(self.column_manager.add_advice_column())
    }

    /// Add a fixed column to the circuit
    pub fn add_fixed_column(&mut self) -> Result<FixedColumn> {
        if self.finalized {
            return Err(Halo2Error::InvalidCircuit("Cannot modify finalized circuit".to_string()));
        }
        Ok(self.column_manager.add_fixed_column())
    }

    /// Add an instance column to the circuit
    pub fn add_instance_column(&mut self) -> Result<InstanceColumn> {
        if self.finalized {
            return Err(Halo2Error::InvalidCircuit("Cannot modify finalized circuit".to_string()));
        }
        Ok(self.column_manager.add_instance_column())
    }

    /// Assign a value to a cell in the circuit
    pub fn assign(&mut self, column: Column, row: usize, value: Scalar) -> Result<()> {
        if self.finalized {
            return Err(Halo2Error::InvalidCircuit("Cannot modify finalized circuit".to_string()));
        }

        if row >= self.config.circuit_size {
            return Err(Halo2Error::OutOfBounds(format!("Row {} exceeds circuit size {}", row, self.config.circuit_size)));
        }

        // Get or create column data
        if self.column_manager.get_column_data(&column).is_none() {
            let mut data = vec![Scalar::zero(); self.config.circuit_size];
            data[row] = value;
            self.column_manager.set_column_data(column, data)?;
        } else {
            let data = self.column_manager.get_column_data_mut(&column).unwrap();
            if row < data.len() {
                data[row] = value;
            } else {
                return Err(Halo2Error::OutOfBounds(format!("Row {} out of bounds", row)));
            }
        }

        Ok(())
    }

    /// Get a value from a cell in the circuit
    pub fn get(&self, column: &Column, row: usize) -> Result<Scalar> {
        let data = self.column_manager.get_column_data(column)
            .ok_or_else(|| Halo2Error::InvalidColumn(format!("Column {:?} not found", column)))?;
        
        if row >= data.len() {
            return Err(Halo2Error::OutOfBounds(format!("Row {} out of bounds", row)));
        }

        Ok(data[row])
    }

    /// Finalize the circuit (no more modifications allowed)
    pub fn finalize(&mut self) -> Result<()> {
        self.finalized = true;
        
        // Validate circuit consistency
        self.column_manager.validate_row_consistency()?;
        
        // Ensure all columns have the correct size
        for column in self.column_manager.all_columns() {
            if let Some(data) = self.column_manager.get_column_data(&column) {
                if data.len() != self.config.circuit_size {
                    return Err(Halo2Error::InconsistentRowCount {
                        column: format!("{}", column),
                        expected: self.config.circuit_size,
                        actual: data.len(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Check if the circuit is finalized
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Verify all constraints are satisfied
    pub fn verify_constraints(&self) -> Result<bool> {
        if !self.finalized {
            return Err(Halo2Error::InvalidCircuit("Circuit must be finalized before verification".to_string()));
        }

        let column_values: HashMap<Column, Vec<Scalar>> = self.column_manager.all_columns()
            .into_iter()
            .filter_map(|col| {
                self.column_manager.get_column_data(&col)
                    .map(|data| (col, data.clone()))
            })
            .collect();

        self.constraint_system.verify_constraints(&column_values, self.config.circuit_size)
    }

    /// Get circuit statistics
    pub fn stats(&self) -> CircuitStats {
        let cs_stats = self.constraint_system.stats();
        let col_stats = self.column_manager.stats();

        CircuitStats {
            constraint_system: cs_stats,
            columns: col_stats,
            circuit_size: self.config.circuit_size,
            finalized: self.finalized,
        }
    }
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub fn new(config: CircuitConfig) -> Self {
        Self {
            circuit: Halo2Circuit::new(config),
            gates: Vec::new(),
            lookups: Vec::new(),
        }
    }

    /// Create a builder with default configuration
    pub fn default() -> Self {
        Self::new(CircuitConfig::default())
    }

    /// Add a gate to the builder
    pub fn gate(mut self, gate: Gate) -> Self {
        self.gates.push(gate);
        self
    }

    /// Add a lookup table to the builder
    pub fn lookup(mut self, lookup: LookupTable) -> Self {
        self.lookups.push(lookup);
        self
    }

    /// Build the circuit
    pub fn build(mut self) -> Result<Halo2Circuit> {
        // Add all gates
        for gate in self.gates {
            self.circuit.add_gate(gate)?;
        }

        // Add all lookup tables
        for lookup in self.lookups {
            self.circuit.add_lookup(lookup)?;
        }

        Ok(self.circuit)
    }
}

impl SynthesisContext {
    /// Create a new synthesis context
    pub fn new(circuit_size: usize) -> Self {
        Self {
            current_row: 0,
            assignments: HashMap::new(),
            instances: HashMap::new(),
            fixed: HashMap::new(),
        }
    }

    /// Assign a value to an advice column
    pub fn assign_advice(&mut self, column: AdviceColumn, value: Scalar) -> Result<()> {
        let col = Column::Advice(column);
        let data = self.assignments.entry(col).or_insert_with(Vec::new);
        
        // Extend vector if needed
        while data.len() <= self.current_row {
            data.push(Scalar::zero());
        }
        
        data[self.current_row] = value;
        Ok(())
    }

    /// Set an instance value
    pub fn set_instance(&mut self, column: InstanceColumn, row: usize, value: Scalar) -> Result<()> {
        let data = self.instances.entry(column).or_insert_with(Vec::new);
        
        while data.len() <= row {
            data.push(Scalar::zero());
        }
        
        data[row] = value;
        Ok(())
    }

    /// Set a fixed value
    pub fn set_fixed(&mut self, column: FixedColumn, row: usize, value: Scalar) -> Result<()> {
        let data = self.fixed.entry(column).or_insert_with(Vec::new);
        
        while data.len() <= row {
            data.push(Scalar::zero());
        }
        
        data[row] = value;
        Ok(())
    }

    /// Move to the next row
    pub fn next_row(&mut self) {
        self.current_row += 1;
    }

    /// Reset to row 0
    pub fn reset(&mut self) {
        self.current_row = 0;
    }
}

/// Statistics about a circuit
#[derive(Clone, Debug)]
pub struct CircuitStats {
    pub constraint_system: crate::constraints::ConstraintSystemStats,
    pub columns: crate::columns::ColumnStats,
    pub circuit_size: usize,
    pub finalized: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::Scalar as BlsScalar;
    use ff::Field;

    #[test]
    fn test_circuit_creation() {
        let config = CircuitConfig::new(2, 1, 1);
        let circuit = Halo2Circuit::new(config);
        
        assert_eq!(circuit.config.num_advice, 2);
        assert_eq!(circuit.config.num_fixed, 1);
        assert_eq!(circuit.config.num_instance, 1);
        assert!(!circuit.finalized);
    }

    #[test]
    fn test_circuit_builder() {
        let circuit = CircuitBuilder::default()
            .build()
            .unwrap();
        
        assert_eq!(circuit.constraint_system.advice_columns, 3);
        assert_eq!(circuit.constraint_system.fixed_columns, 1);
        assert_eq!(circuit.constraint_system.instance_columns, 1);
    }

    #[test]
    fn test_circuit_assignment() {
        let mut circuit = Halo2Circuit::default();
        let advice_col = circuit.add_advice_column().unwrap();
        
        let column = Column::Advice(advice_col);
        circuit.assign(column.clone(), 0, BlsScalar::from(42u64)).unwrap();
        
        let value = circuit.get(&column, 0).unwrap();
        assert_eq!(value, BlsScalar::from(42u64));
    }

    #[test]
    fn test_circuit_finalization() {
        let mut circuit = Halo2Circuit::default();
        let advice_col = circuit.add_advice_column().unwrap();
        
        // Assign some values
        for i in 0..circuit.config.circuit_size {
            circuit.assign(Column::Advice(advice_col.clone()), i, BlsScalar::from(i as u64)).unwrap();
        }
        
        circuit.finalize().unwrap();
        assert!(circuit.is_finalized());
        
        // Should not be able to modify after finalization
        let result = circuit.add_advice_column();
        assert!(result.is_err());
    }

    #[test]
    fn test_synthesis_context() {
        let mut ctx = SynthesisContext::new(10);
        let advice_col = AdviceColumn::new(0);
        
        ctx.assign_advice(advice_col, BlsScalar::from(100u64)).unwrap();
        assert_eq!(ctx.current_row, 0);
        
        ctx.next_row();
        assert_eq!(ctx.current_row, 1);
        
        ctx.assign_advice(advice_col, BlsScalar::from(200u64)).unwrap();
        
        let data = &ctx.assignments[&Column::Advice(advice_col)];
        assert_eq!(data[0], BlsScalar::from(100u64));
        assert_eq!(data[1], BlsScalar::from(200u64));
    }
}
