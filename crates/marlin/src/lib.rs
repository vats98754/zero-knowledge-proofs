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
pub use transcript::*;
pub use r1cs::*;

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

    #[test]
    fn test_marlin_integration() {
        // Basic integration test to ensure all modules work together
        use ark_std::test_rng;
        use zkp_commitments::kzg::KzgCommitmentEngine;
        
        let mut rng = test_rng();
        
        // Create a simple R1CS
        let mut r1cs = R1CS::new(1, 3, 1);
        r1cs.add_constraint(
            &[(1, zkp_field::Scalar::one())], // A: x
            &[(1, zkp_field::Scalar::one())], // B: x
            &[(2, zkp_field::Scalar::one())], // C: y
        ).unwrap();
        
        // Test setup
        let setup = MarlinSetup::<KzgCommitmentEngine>::new(128, 1000);
        let setup_params = SetupParams {
            security_bits: 128,
            max_degree: 16,
            max_constraints: 10,
            max_variables: 5,
        };
        
        let srs_result = setup.universal_setup(&mut rng, &setup_params);
        assert!(srs_result.is_ok());
        
        // Test transcript
        let mut transcript = MarlinTranscript::new();
        transcript.prover_round1(b"w", b"za", b"zb", b"zc");
        let (_alpha, _beta) = transcript.verifier_round1();
        
        // Verify basic functionality works
        assert_eq!(transcript.current_round(), 1);
    }
}