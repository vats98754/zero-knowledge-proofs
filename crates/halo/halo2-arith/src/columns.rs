//! Column types for Halo2 arithmetic circuits
//!
//! This module defines the different types of columns used in PLONK-style
//! arithmetic circuits: advice (private), fixed (constants), and instance (public).

use crate::{Scalar, Result, Halo2Error};
use std::fmt;

/// A column in the circuit constraint matrix
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Column {
    /// Advice column (private witness data)
    Advice(AdviceColumn),
    /// Fixed column (circuit constants)
    Fixed(FixedColumn),
    /// Instance column (public inputs/outputs)
    Instance(InstanceColumn),
}

/// Advice column containing private witness data
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdviceColumn {
    /// Index of this advice column
    pub index: usize,
}

/// Fixed column containing circuit constants
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedColumn {
    /// Index of this fixed column
    pub index: usize,
}

/// Instance column containing public inputs/outputs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InstanceColumn {
    /// Index of this instance column
    pub index: usize,
}

/// Manager for all columns in a circuit
#[derive(Clone, Debug)]
pub struct ColumnManager {
    /// All advice columns
    pub advice_columns: Vec<AdviceColumn>,
    /// All fixed columns
    pub fixed_columns: Vec<FixedColumn>,
    /// All instance columns
    pub instance_columns: Vec<InstanceColumn>,
    /// Column data storage
    pub column_data: std::collections::HashMap<Column, Vec<Scalar>>,
}

impl Column {
    /// Get the index of this column within its type
    pub fn index(&self) -> usize {
        match self {
            Column::Advice(col) => col.index,
            Column::Fixed(col) => col.index,
            Column::Instance(col) => col.index,
        }
    }

    /// Get the type name of this column
    pub fn type_name(&self) -> &'static str {
        match self {
            Column::Advice(_) => "advice",
            Column::Fixed(_) => "fixed",
            Column::Instance(_) => "instance",
        }
    }

    /// Check if this is an advice column
    pub fn is_advice(&self) -> bool {
        matches!(self, Column::Advice(_))
    }

    /// Check if this is a fixed column
    pub fn is_fixed(&self) -> bool {
        matches!(self, Column::Fixed(_))
    }

    /// Check if this is an instance column
    pub fn is_instance(&self) -> bool {
        matches!(self, Column::Instance(_))
    }

    /// Convert to advice column if possible
    pub fn as_advice(&self) -> Option<&AdviceColumn> {
        match self {
            Column::Advice(col) => Some(col),
            _ => None,
        }
    }

    /// Convert to fixed column if possible
    pub fn as_fixed(&self) -> Option<&FixedColumn> {
        match self {
            Column::Fixed(col) => Some(col),
            _ => None,
        }
    }

    /// Convert to instance column if possible
    pub fn as_instance(&self) -> Option<&InstanceColumn> {
        match self {
            Column::Instance(col) => Some(col),
            _ => None,
        }
    }
}

impl AdviceColumn {
    /// Create a new advice column
    pub fn new(index: usize) -> Self {
        Self { index }
    }

    /// Convert to generic column
    pub fn into_column(self) -> Column {
        Column::Advice(self)
    }
}

impl FixedColumn {
    /// Create a new fixed column
    pub fn new(index: usize) -> Self {
        Self { index }
    }

    /// Convert to generic column
    pub fn into_column(self) -> Column {
        Column::Fixed(self)
    }
}

impl InstanceColumn {
    /// Create a new instance column
    pub fn new(index: usize) -> Self {
        Self { index }
    }

    /// Convert to generic column
    pub fn into_column(self) -> Column {
        Column::Instance(self)
    }
}

impl ColumnManager {
    /// Create a new column manager
    pub fn new() -> Self {
        Self {
            advice_columns: Vec::new(),
            fixed_columns: Vec::new(),
            instance_columns: Vec::new(),
            column_data: std::collections::HashMap::new(),
        }
    }

    /// Add an advice column
    pub fn add_advice_column(&mut self) -> AdviceColumn {
        let index = self.advice_columns.len();
        let column = AdviceColumn::new(index);
        self.advice_columns.push(column.clone());
        column
    }

    /// Add a fixed column
    pub fn add_fixed_column(&mut self) -> FixedColumn {
        let index = self.fixed_columns.len();
        let column = FixedColumn::new(index);
        self.fixed_columns.push(column.clone());
        column
    }

    /// Add an instance column
    pub fn add_instance_column(&mut self) -> InstanceColumn {
        let index = self.instance_columns.len();
        let column = InstanceColumn::new(index);
        self.instance_columns.push(column.clone());
        column
    }

    /// Set data for a column
    pub fn set_column_data(&mut self, column: Column, data: Vec<Scalar>) -> Result<()> {
        self.column_data.insert(column, data);
        Ok(())
    }

    /// Get data for a column
    pub fn get_column_data(&self, column: &Column) -> Option<&Vec<Scalar>> {
        self.column_data.get(column)
    }

    /// Get mutable data for a column
    pub fn get_column_data_mut(&mut self, column: &Column) -> Option<&mut Vec<Scalar>> {
        self.column_data.get_mut(column)
    }

    /// Get the total number of columns
    pub fn total_columns(&self) -> usize {
        self.advice_columns.len() + self.fixed_columns.len() + self.instance_columns.len()
    }

    /// Get all columns as a vector
    pub fn all_columns(&self) -> Vec<Column> {
        let mut columns = Vec::new();
        
        for col in &self.advice_columns {
            columns.push(Column::Advice(col.clone()));
        }
        
        for col in &self.fixed_columns {
            columns.push(Column::Fixed(col.clone()));
        }
        
        for col in &self.instance_columns {
            columns.push(Column::Instance(col.clone()));
        }
        
        columns
    }

    /// Validate that all columns have the same number of rows
    pub fn validate_row_consistency(&self) -> Result<usize> {
        let mut expected_rows: Option<usize> = None;
        
        for (column, data) in &self.column_data {
            match expected_rows {
                None => expected_rows = Some(data.len()),
                Some(rows) => {
                    if data.len() != rows {
                        return Err(Halo2Error::InconsistentRowCount {
                            column: format!("{:?}", column),
                            expected: rows,
                            actual: data.len(),
                        });
                    }
                }
            }
        }
        
        Ok(expected_rows.unwrap_or(0))
    }

    /// Clear all column data
    pub fn clear_data(&mut self) {
        self.column_data.clear();
    }

    /// Get column statistics
    pub fn stats(&self) -> ColumnStats {
        let num_rows = self.validate_row_consistency().unwrap_or(0);
        ColumnStats {
            num_advice: self.advice_columns.len(),
            num_fixed: self.fixed_columns.len(),
            num_instance: self.instance_columns.len(),
            total_columns: self.total_columns(),
            num_rows,
        }
    }
}

/// Statistics about columns in a circuit
#[derive(Clone, Debug, PartialEq)]
pub struct ColumnStats {
    pub num_advice: usize,
    pub num_fixed: usize,
    pub num_instance: usize,
    pub total_columns: usize,
    pub num_rows: usize,
}

impl Default for ColumnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Column {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Column::Advice(col) => write!(f, "advice_{}", col.index),
            Column::Fixed(col) => write!(f, "fixed_{}", col.index),
            Column::Instance(col) => write!(f, "instance_{}", col.index),
        }
    }
}

impl fmt::Display for AdviceColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "advice_{}", self.index)
    }
}

impl fmt::Display for FixedColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixed_{}", self.index)
    }
}

impl fmt::Display for InstanceColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "instance_{}", self.index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::Scalar as BlsScalar;
    use ff::Field;

    #[test]
    fn test_column_creation() {
        let advice = AdviceColumn::new(0);
        let fixed = FixedColumn::new(1);
        let instance = InstanceColumn::new(2);

        assert_eq!(advice.index, 0);
        assert_eq!(fixed.index, 1);
        assert_eq!(instance.index, 2);
    }

    #[test]
    fn test_column_type_checks() {
        let advice_col = Column::Advice(AdviceColumn::new(0));
        let fixed_col = Column::Fixed(FixedColumn::new(0));
        let instance_col = Column::Instance(InstanceColumn::new(0));

        assert!(advice_col.is_advice());
        assert!(!advice_col.is_fixed());
        assert!(!advice_col.is_instance());

        assert!(!fixed_col.is_advice());
        assert!(fixed_col.is_fixed());
        assert!(!fixed_col.is_instance());

        assert!(!instance_col.is_advice());
        assert!(!instance_col.is_fixed());
        assert!(instance_col.is_instance());
    }

    #[test]
    fn test_column_manager() {
        let mut manager = ColumnManager::new();

        let advice1 = manager.add_advice_column();
        let advice2 = manager.add_advice_column();
        let fixed1 = manager.add_fixed_column();
        let instance1 = manager.add_instance_column();

        assert_eq!(advice1.index, 0);
        assert_eq!(advice2.index, 1);
        assert_eq!(fixed1.index, 0);
        assert_eq!(instance1.index, 0);

        assert_eq!(manager.total_columns(), 4);
    }

    #[test]
    fn test_column_data() {
        let mut manager = ColumnManager::new();
        let advice = manager.add_advice_column();
        
        let data = vec![BlsScalar::from(1u64), BlsScalar::from(2u64), BlsScalar::from(3u64)];
        manager.set_column_data(advice.clone().into_column(), data.clone()).unwrap();
        
        let retrieved = manager.get_column_data(&Column::Advice(advice)).unwrap();
        assert_eq!(*retrieved, data);
    }

    #[test]
    fn test_row_consistency_validation() {
        let mut manager = ColumnManager::new();
        let advice1 = manager.add_advice_column();
        let advice2 = manager.add_advice_column();
        
        let data1 = vec![BlsScalar::from(1u64), BlsScalar::from(2u64)];
        let data2 = vec![BlsScalar::from(3u64), BlsScalar::from(4u64)];
        
        manager.set_column_data(advice1.clone().into_column(), data1).unwrap();
        manager.set_column_data(advice2.clone().into_column(), data2).unwrap();
        
        let rows = manager.validate_row_consistency().unwrap();
        assert_eq!(rows, 2);
    }

    #[test]
    fn test_column_display() {
        let advice = Column::Advice(AdviceColumn::new(5));
        let fixed = Column::Fixed(FixedColumn::new(3));
        let instance = Column::Instance(InstanceColumn::new(1));

        assert_eq!(format!("{}", advice), "advice_5");
        assert_eq!(format!("{}", fixed), "fixed_3");
        assert_eq!(format!("{}", instance), "instance_1");
    }

    #[test]
    fn test_column_stats() {
        let mut manager = ColumnManager::new();
        manager.add_advice_column();
        manager.add_advice_column();
        manager.add_fixed_column();
        manager.add_instance_column();

        let stats = manager.stats();
        assert_eq!(stats.num_advice, 2);
        assert_eq!(stats.num_fixed, 1);
        assert_eq!(stats.num_instance, 1);
        assert_eq!(stats.total_columns, 4);
        assert_eq!(stats.num_rows, 0);
    }
}
