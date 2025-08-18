//! # Commitment Schemes for Halo
//!
//! This crate provides commitment schemes used in the Halo family of proof systems,
//! particularly focusing on Inner Product Arguments (IPA) and supporting infrastructure
//! for recursion-friendly polynomial commitments.
//!
//! ## Components
//!
//! - [`CommitmentEngine`]: Core trait for polynomial commitment schemes
//! - [`ipa`]: Inner Product Argument implementation
//! - [`transcript`]: Fiat-Shamir transcript utilities
//! - [`msm`]: Multi-scalar multiplication optimizations

pub mod commitment_engine;
pub mod ipa;
pub mod transcript;
pub mod msm;
pub mod errors;

// Re-export key types
pub use commitment_engine::{CommitmentEngine, Commitment, Opening};
pub use ipa::{IpaCommitmentEngine, IpaCommitment, IpaOpening};
pub use transcript::{Transcript, TranscriptWrite, TranscriptRead};
pub use errors::{CommitmentError, Result};

/// BLS12-381 scalar field used throughout Halo
pub type Scalar = bls12_381::Scalar;

/// BLS12-381 group element used for commitments
pub type GroupElement = bls12_381::G1Affine;

/// BLS12-381 projective group element
pub type GroupProjective = bls12_381::G1Projective;