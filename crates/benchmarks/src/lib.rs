//! # Zero-Knowledge Proof Benchmarks
//!
//! This crate provides comprehensive benchmarks for the zero-knowledge
//! proof systems implemented in this workspace.

pub mod integration;
pub mod comparison;

use zkp_examples::ExampleError;
use thiserror::Error;

/// Error types for benchmarks
#[derive(Debug, Error)]
pub enum BenchmarkError {
    #[error("Benchmark setup failed")]
    SetupFailed,
    #[error("Benchmark execution failed")]
    ExecutionFailed,
    #[error("Example error: {0}")]
    ExampleError(#[from] ExampleError),
}

pub type Result<T> = std::result::Result<T, BenchmarkError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_benchmark_basic() {
        // Basic smoke test
        assert!(true);
    }
}