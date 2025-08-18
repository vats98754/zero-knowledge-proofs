//! Error types for recursion

use thiserror::Error;

/// Result type for recursion operations
pub type Result<T> = std::result::Result<T, RecursionError>;

/// Errors that can occur in recursion
#[derive(Error, Debug, Clone, PartialEq)]
pub enum RecursionError {
    /// Core Halo error
    #[error("Halo error: {0}")]
    Halo(#[from] halo_core::HaloError),
    
    /// Commitment engine error
    #[error("Commitment error: {0}")]
    Commitment(#[from] commitments::CommitmentError),
    
    /// Invalid accumulator
    #[error("Invalid accumulator: {0}")]
    InvalidAccumulator(String),
    
    /// Folding failed
    #[error("Folding failed: {0}")]
    FoldingFailed(String),
    
    /// Invalid folding proof
    #[error("Invalid folding proof: {0}")]
    InvalidFoldingProof(String),
    
    /// Maximum recursion depth exceeded
    #[error("Maximum recursion depth exceeded")]
    MaxRecursionDepthExceeded,
    
    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    /// Invalid proof structure
    #[error("Invalid proof structure: {0}")]
    InvalidProofStructure(String),
    
    /// Challenge generation failed
    #[error("Challenge generation failed: {0}")]
    ChallengeGenerationFailed(String),
    
    /// Transcript error
    #[error("Transcript error: {0}")]
    TranscriptError(String),
}