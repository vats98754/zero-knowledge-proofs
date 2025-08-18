//! # Bulletproofs Range Proofs
//!
//! This crate implements range proofs using the inner product argument.
//! Range proofs allow proving that a committed value lies within a specified range
//! without revealing the actual value.
//!
//! ## Mathematical Background
//!
//! A range proof for value `v` in range `[0, 2^n)` works by:
//!
//! 1. **Bit Decomposition**: Express `v = Σ(b_i * 2^i)` where `b_i ∈ {0,1}`
//! 2. **Vector Commitment**: Commit to bit vector using generators
//! 3. **Constraint System**: Use inner product argument to prove constraints:
//!    - Each `b_i` is binary: `b_i * (b_i - 1) = 0`
//!    - Bits sum to value: `Σ(b_i * 2^i) = v`
//!
//! ## Usage
//!
//! ```rust,no_run
//! use range::{RangeProver, RangeVerifier};
//! use bulletproofs_core::*;
//! use curve25519_dalek::scalar::Scalar;
//! 
//! // Prove that value 42 is in range [0, 2^8)
//! let value = Scalar::from(42u64);
//! let bit_length = 8;
//! 
//! let prover = RangeProver::new();
//! let proof = prover.prove_range(value, bit_length).unwrap();
//! 
//! let verifier = RangeVerifier::new();
//! assert!(verifier.verify_range(&proof, bit_length).is_ok());
//! ```

pub mod proof;
pub mod prover;
pub mod verifier;
pub mod constraints;

#[cfg(test)]
pub mod property_tests;

pub use proof::*;
pub use prover::*;
pub use verifier::*;
pub use constraints::*;