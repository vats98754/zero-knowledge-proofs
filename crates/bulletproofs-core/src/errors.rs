//! Error types for Bulletproofs operations

use thiserror::Error;

/// Main error type for Bulletproofs operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BulletproofsError {
    /// Verification failed
    #[error("Proof verification failed")]
    VerificationFailed,

    /// Invalid proof format or structure
    #[error("Invalid proof format: {0}")]
    InvalidProof(String),

    /// Invalid parameters provided
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Vector length mismatch
    #[error("Vector length mismatch: expected {expected}, got {actual}")]
    VectorLengthMismatch { expected: usize, actual: usize },

    /// Insufficient generators
    #[error("Insufficient generators: need {needed}, have {available}")]
    InsufficientGenerators { needed: usize, available: usize },

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Range constraint violation
    #[error("Value {value} is not in range [0, 2^{bits})")]
    RangeConstraintViolation { value: u64, bits: usize },
}

/// Result type for Bulletproofs operations
pub type BulletproofsResult<T> = Result<T, BulletproofsError>;