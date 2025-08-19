//! # Bulletproofs Core
//!
//! This crate provides the foundational types, traits, and utilities for
//! implementing Bulletproofs zero-knowledge proofs. It includes:
//!
//! - Basic cryptographic primitives and group operations
//! - Transcript management for Fiat-Shamir transforms
//! - Vector commitment and generator management
//! - Error types and utilities
//!
//! ## Mathematical Background
//!
//! Bulletproofs operate over an elliptic curve group of prime order with generators:
//! - `G`: primary generator for commitments
//! - `H`: secondary generator for blinding
//! - `{g_i}`: vector of generators for left commitments
//! - `{h_i}`: vector of generators for right commitments
//! - `u`: generator for inner product
//!
//! The core mathematical relationship is proving knowledge of vectors `a, b` such that:
//! ```text
//! P = g^a * h^b * u^<a,b>
//! ```
//! where `<a,b>` denotes the inner product of vectors `a` and `b`.

pub mod errors;
pub mod generators;
pub mod group;
pub mod transcript;
pub mod utils;

pub use errors::*;
pub use generators::*;
pub use group::*;
pub use transcript::*;

/// Re-export commonly used types from curve25519-dalek
pub use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};

/// Re-export merlin transcript
pub use merlin::Transcript;