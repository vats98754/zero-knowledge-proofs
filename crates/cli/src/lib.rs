//! # CLI Tools for Zero-Knowledge Proofs
//!
//! This crate provides command-line tools for working with Marlin and Sonic
//! zero-knowledge proof systems.

pub mod common;
pub mod setup;
pub mod prove;
pub mod verify;

use zkp_marlin::MarlinError;
use zkp_sonic::SonicError;
use thiserror::Error;

/// Error types for CLI operations
#[derive(Debug, Error)]
pub enum CliError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Marlin error: {0}")]
    MarlinError(#[from] MarlinError),
    #[error("Sonic error: {0}")]
    SonicError(#[from] SonicError),
    #[error("Invalid command arguments")]
    InvalidArguments,
}

pub type Result<T> = std::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cli_basic() {
        // Basic smoke test
        assert!(true);
    }
}