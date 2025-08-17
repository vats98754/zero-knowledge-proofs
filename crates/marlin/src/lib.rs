//! # Marlin Polynomial IOP Implementation
//!
//! This crate implements the Marlin polynomial Interactive Oracle Proof system,
//! a universal SNARK construction.

pub mod iop;
pub mod prover;
pub mod verifier;
pub mod setup;
pub mod transcript;
pub mod r1cs;

pub use iop::*;
pub use prover::*;
pub use verifier::*;
pub use setup::*;

use zkp_field::Scalar;
use zkp_commitments::CommitmentError;
use thiserror::Error;

/// Error types for Marlin operations
#[derive(Debug, Error)]
pub enum MarlinError {
    #[error("Invalid circuit")]
    InvalidCircuit,
    #[error("Proof generation failed")]
    ProofFailed,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid setup parameters")]
    InvalidSetup,
    #[error("Commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),
    #[error("Field error: {0}")]
    FieldError(#[from] zkp_field::FieldError),
}

pub type Result<T> = std::result::Result<T, MarlinError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_marlin_error_conversion() {
        let commit_err = CommitmentError::InvalidParameters;
        let marlin_err = MarlinError::from(commit_err);
        
        match marlin_err {
            MarlinError::CommitmentError(_) => {},
            _ => panic!("Expected CommitmentError variant"),
        }
    }
}