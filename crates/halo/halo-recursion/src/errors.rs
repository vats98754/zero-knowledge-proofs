//! Error types for recursion

use thiserror::Error;

/// Result type for recursion operations
pub type Result<T> = std::result::Result<T, RecursionError>;

/// Errors that can occur in recursion
#[derive(Error, Debug, Clone, PartialEq)]
pub enum RecursionError {
    /// Core Halo error
    #[error("Halo error: {0}")]
    Halo(#[from] halo_core::HaloError),
    
    /// Invalid accumulator
    #[error("Invalid accumulator: {0}")]
    InvalidAccumulator(String),
    
    /// Folding failed
    #[error("Folding failed: {0}")]
    FoldingFailed(String),
}