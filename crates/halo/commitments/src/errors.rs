//! Error types for commitment schemes

use thiserror::Error;

/// Result type for commitment operations
pub type Result<T> = std::result::Result<T, CommitmentError>;

/// Errors that can occur in commitment schemes
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CommitmentError {
    /// Invalid commitment parameters
    #[error("Invalid commitment parameters: {0}")]
    InvalidParameters(String),
    
    /// Invalid proof or opening
    #[error("Invalid proof or opening: {0}")]
    InvalidProof(String),
    
    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed,
    
    /// Transcript error during Fiat-Shamir
    #[error("Transcript error: {0}")]
    TranscriptError(String),
    
    /// Insufficient randomness
    #[error("Insufficient randomness")]
    InsufficientRandomness,
    
    /// Invalid polynomial degree
    #[error("Invalid polynomial degree: expected {expected}, got {actual}")]
    InvalidDegree { expected: usize, actual: usize },
    
    /// Inner product argument error
    #[error("Inner product argument error: {0}")]
    IpaError(String),
    
    /// Multi-scalar multiplication error
    #[error("Multi-scalar multiplication error: {0}")]
    MsmError(String),
}