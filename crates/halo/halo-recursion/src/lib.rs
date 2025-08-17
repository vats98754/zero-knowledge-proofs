//! # Halo Recursion
//!
//! Implementation of proof folding and recursive aggregation for the Halo system.
//! This crate provides APIs for accumulating proofs and enabling recursive
//! verification with logarithmic verification time.

pub mod accumulator;
pub mod folding;
pub mod recursive_verifier;
pub mod errors;

// Re-export key types
pub use accumulator::{Accumulator, AccumulatorInstance};
pub use folding::{fold_proof, FoldingProof};
pub use recursive_verifier::{verify_recursive, RecursiveVerifier};
pub use errors::{RecursionError, Result};

/// Re-export core types
pub use halo_core::{Scalar, GroupElement, Proof, Circuit};

/// Main recursion API
pub trait RecursionEngine {
    type Proof;
    type Instance;
    type Accumulator;
    
    /// Fold a proof into an accumulator
    fn fold_proof(
        prev_proof: Option<Self::Proof>,
        instance: Self::Instance,
    ) -> Result<Self::Proof>;
    
    /// Verify a recursive proof
    fn verify_recursive(
        proof: &Self::Proof,
        instance: &Self::Instance,
    ) -> Result<bool>;
}