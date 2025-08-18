//! Error types for Halo2 arithmetic circuits

use thiserror::Error;

/// Result type for Halo2 operations
pub type Result<T> = std::result::Result<T, Halo2Error>;

/// Errors that can occur in Halo2 arithmetic circuits
#[derive(Error, Debug, Clone, PartialEq)]
pub enum Halo2Error {
    /// Commitment error
    #[error("Commitment error: {0}")]
    Commitment(String),
    
    /// Invalid circuit
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
    
    /// Invalid column reference
    #[error("Invalid column: {0}")]
    InvalidColumn(String),
    
    /// Invalid rotation
    #[error("Invalid rotation: {0}")]
    InvalidRotation(String),
    
    /// Array index out of bounds
    #[error("Out of bounds: {0}")]
    OutOfBounds(String),
    
    /// Inconsistent row count
    #[error("Inconsistent row count for {column}: expected {expected}, got {actual}")]
    InconsistentRowCount {
        column: String,
        expected: usize,
        actual: usize,
    },
    
    /// Constraint system error
    #[error("Constraint system error: {0}")]
    ConstraintSystem(String),
    
    /// Gate error
    #[error("Gate error: {0}")]
    Gate(String),
    
    /// Lookup table error
    #[error("Lookup error: {0}")]
    Lookup(String),
}
