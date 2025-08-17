//! # Zero-Knowledge Proof Commitment Schemes
//!
//! This crate provides polynomial commitment schemes optimized for zero-knowledge proofs,
//! including KZG commitments and Kate polynomial commitments with batching support.

pub mod traits;
pub mod kzg;
pub mod kate;
pub mod utils;

pub use traits::*;
pub use kzg::*;
pub use kate::*;

use thiserror::Error;

/// Error types for commitment operations
#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("Invalid commitment parameters")]
    InvalidParameters,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Degree bound exceeded")]
    DegreeBoundExceeded,
    #[error("Field operation error: {0}")]
    FieldError(#[from] zkp_field::FieldError),
}

pub type Result<T> = std::result::Result<T, CommitmentError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_commitment_error_conversion() {
        let field_err = zkp_field::FieldError::InvalidElement;
        let commit_err = CommitmentError::from(field_err);
        
        match commit_err {
            CommitmentError::FieldError(_) => {},
            _ => panic!("Expected FieldError variant"),
        }
    }
}