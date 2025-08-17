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
pub use folding::{
    fold_proof, fold_proof_with_config, verify_folding_proof,
    FoldingProof, FoldingResult, FoldingConfig
};
pub use recursive_verifier::{
    verify_recursive, verify_base_proof,
    RecursiveVerifier, RecursiveVerifierConfig, VerificationContext
};
pub use errors::{RecursionError, Result};

/// Re-export core types
pub use halo_core::{Scalar, GroupElement, Proof, Circuit};

/// Main recursion API
pub trait RecursionEngine {
    type Proof;
    type Instance;
    type Accumulator;
    type FoldingProof;
    
    /// Fold a proof into an accumulator
    fn fold_proof(
        prev_accumulator: Option<Self::Accumulator>,
        new_proof: Self::Proof,
        instance: Self::Instance,
    ) -> Result<(Self::Accumulator, Self::FoldingProof)>;
    
    /// Verify a recursive proof
    fn verify_recursive(
        folding_proof: &Self::FoldingProof,
        expected_instance: &Self::Instance,
    ) -> Result<bool>;
}

/// Default Halo recursion engine implementation
pub struct HaloRecursionEngine;

impl RecursionEngine for HaloRecursionEngine {
    type Proof = halo_core::Proof;
    type Instance = AccumulatorInstance;
    type Accumulator = Accumulator;
    type FoldingProof = FoldingProof;
    
    fn fold_proof(
        prev_accumulator: Option<Self::Accumulator>,
        new_proof: Self::Proof,
        instance: Self::Instance,
    ) -> Result<(Self::Accumulator, Self::FoldingProof)> {
        let result = fold_proof(prev_accumulator, new_proof, instance.public_inputs)?;
        Ok((result.accumulator, result.folding_proof))
    }
    
    fn verify_recursive(
        folding_proof: &Self::FoldingProof,
        expected_instance: &Self::Instance,
    ) -> Result<bool> {
        verify_recursive(folding_proof, expected_instance)
    }
}