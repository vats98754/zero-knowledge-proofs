//! # Zero-Knowledge Proof Examples
//!
//! This crate provides examples and integration tests for the zero-knowledge
//! proof systems implemented in this workspace.

pub mod circuits;
pub mod integration;
pub mod benchmarks;

use zkp_field::Scalar;
use zkp_marlin::MarlinError;
use zkp_sonic::SonicError;
use thiserror::Error;

/// Error types for examples
#[derive(Debug, Error)]
pub enum ExampleError {
    #[error("Circuit construction failed")]
    CircuitError,
    #[error("Example execution failed")]
    ExecutionFailed,
    #[error("Marlin error: {0}")]
    MarlinError(#[from] MarlinError),
    #[error("Sonic error: {0}")]
    SonicError(#[from] SonicError),
}

pub type Result<T> = std::result::Result<T, ExampleError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_example_basic() {
        // Basic smoke test
        assert!(true);
    }
}