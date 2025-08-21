//! STARK prover implementation
//! 
//! This crate implements the prover side of the STARK protocol.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Transcript management for Fiat-Shamir transformation
pub mod transcript;
/// Constraint system evaluation
pub mod constraints;
/// Main STARK prover implementation
pub mod stark_prover;

pub use stark_prover::*;