//! # Halo Core
//!
//! Core implementation of the Halo proof system with recursive SNARK capabilities.
//! This crate provides the fundamental proving and verification infrastructure
//! for building recursive zero-knowledge proofs without trusted setup.

pub mod circuit;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod errors;

// Re-export key types
pub use circuit::{Circuit, CircuitConfig};
pub use proof::{Proof, ProofSystem};
pub use prover::Prover;
pub use verifier::Verifier;
pub use errors::{HaloError, Result};

/// Re-export commitments for convenience
pub use commitments;

/// BLS12-381 scalar field
pub type Scalar = bls12_381::Scalar;

/// BLS12-381 group element
pub type GroupElement = bls12_381::G1Affine;