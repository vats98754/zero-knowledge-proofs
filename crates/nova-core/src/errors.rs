//! Error types for Nova incremental verifiable computation.

use thiserror::Error;

/// Errors that can occur in Nova operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NovaError {
    /// Invalid instance error
    #[error("Invalid instance: {0}")]
    InvalidInstance(String),

    /// Invalid witness error
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// Invalid relation error
    #[error("Invalid relation: {0}")]
    InvalidRelation(String),

    /// Folding operation error
    #[error("Folding error: {0}")]
    FoldingError(String),

    /// Proof generation error
    #[error("Proof generation error: {0}")]
    ProofError(String),

    /// Verification error
    #[error("Verification error: {0}")]
    VerificationError(String),

    /// Commitment scheme error
    #[error("Commitment error: {0}")]
    CommitmentError(String),

    /// Transcript error
    #[error("Transcript error: {0}")]
    TranscriptError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    /// Parameter error
    #[error("Parameter error: {0}")]
    ParameterError(String),

    /// Incompatible instances
    #[error("Incompatible instances: {0}")]
    IncompatibleInstances(String),

    /// Resource exhaustion
    #[error("Resource exhaustion: {0}")]
    ResourceExhaustion(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl NovaError {
    /// Creates an invalid instance error
    pub fn invalid_instance(msg: impl Into<String>) -> Self {
        Self::InvalidInstance(msg.into())
    }

    /// Creates an invalid witness error
    pub fn invalid_witness(msg: impl Into<String>) -> Self {
        Self::InvalidWitness(msg.into())
    }

    /// Creates an invalid relation error
    pub fn invalid_relation(msg: impl Into<String>) -> Self {
        Self::InvalidRelation(msg.into())
    }

    /// Creates a folding error
    pub fn folding_error(msg: impl Into<String>) -> Self {
        Self::FoldingError(msg.into())
    }

    /// Creates a proof error
    pub fn proof_error(msg: impl Into<String>) -> Self {
        Self::ProofError(msg.into())
    }

    /// Creates a verification error
    pub fn verification_error(msg: impl Into<String>) -> Self {
        Self::VerificationError(msg.into())
    }

    /// Creates a commitment error
    pub fn commitment_error(msg: impl Into<String>) -> Self {
        Self::CommitmentError(msg.into())
    }

    /// Creates a transcript error
    pub fn transcript_error(msg: impl Into<String>) -> Self {
        Self::TranscriptError(msg.into())
    }

    /// Creates a serialization error
    pub fn serialization_error(msg: impl Into<String>) -> Self {
        Self::SerializationError(msg.into())
    }

    /// Creates a cryptographic error
    pub fn cryptographic_error(msg: impl Into<String>) -> Self {
        Self::CryptographicError(msg.into())
    }

    /// Creates a parameter error
    pub fn parameter_error(msg: impl Into<String>) -> Self {
        Self::ParameterError(msg.into())
    }

    /// Creates an incompatible instances error
    pub fn incompatible_instances(msg: impl Into<String>) -> Self {
        Self::IncompatibleInstances(msg.into())
    }

    /// Creates a resource exhaustion error
    pub fn resource_exhaustion(msg: impl Into<String>) -> Self {
        Self::ResourceExhaustion(msg.into())
    }

    /// Creates an internal error
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::InternalError(msg.into())
    }
}

/// Result type alias for Nova operations
pub type NovaResult<T> = Result<T, NovaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = NovaError::invalid_instance("test message");
        assert_eq!(
            error.to_string(),
            "Invalid instance: test message"
        );

        let error = NovaError::folding_error("folding failed");
        assert_eq!(
            error.to_string(),
            "Folding error: folding failed"
        );
    }

    #[test]
    fn test_error_equality() {
        let error1 = NovaError::invalid_witness("same message");
        let error2 = NovaError::invalid_witness("same message");
        let error3 = NovaError::invalid_witness("different message");

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_result_type() {
        let success: NovaResult<u32> = Ok(42);
        let failure: NovaResult<u32> = Err(NovaError::internal_error("test"));

        assert!(success.is_ok());
        assert!(failure.is_err());
    }
}