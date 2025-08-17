//! Error types for Halo core

use thiserror::Error;

/// Result type for Halo operations
pub type Result<T> = std::result::Result<T, HaloError>;

/// Errors that can occur in Halo
#[derive(Error, Debug, Clone, PartialEq)]
pub enum HaloError {
    /// Commitment error
    #[error("Commitment error: {0}")]
    Commitment(#[from] commitments::CommitmentError),
    
    /// Invalid circuit
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
    
    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed,
}