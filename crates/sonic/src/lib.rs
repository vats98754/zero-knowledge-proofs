//! # Sonic/Kate Polynomial Commitment Aggregation
//!
//! This crate implements Sonic/Kate polynomial commitment schemes with
//! aggregation optimizations for batch verification.

pub mod aggregation;
pub mod kate_commitments;
pub mod linear_algebra;
pub mod multipoint;

pub use aggregation::*;
pub use kate_commitments::*;

use zkp_field::Scalar;
use zkp_commitments::CommitmentError;
use thiserror::Error;

/// Error types for Sonic operations
#[derive(Debug, Error)]
pub enum SonicError {
    #[error("Aggregation failed")]
    AggregationFailed,
    #[error("Invalid batch")]
    InvalidBatch,
    #[error("Linear algebra error")]
    LinearAlgebraError,
    #[error("Commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),
    #[error("Field error: {0}")]
    FieldError(#[from] zkp_field::FieldError),
}

pub type Result<T> = std::result::Result<T, SonicError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sonic_error_conversion() {
        let commit_err = CommitmentError::InvalidParameters;
        let sonic_err = SonicError::from(commit_err);
        
        match sonic_err {
            SonicError::CommitmentError(_) => {},
            _ => panic!("Expected CommitmentError variant"),
        }
    }
}