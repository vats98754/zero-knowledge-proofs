//! errors module

use thiserror::Error;

/// Result type for Halo2 operations
pub type Result<T> = std::result::Result<T, Halo2Error>;

/// Errors that can occur in Halo2
#[derive(Error, Debug, Clone, PartialEq)]
pub enum Halo2Error {
    /// Commitment error
    #[error("Commitment error: {0}")]
    Commitment(String),
    
    /// Invalid circuit
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
}
