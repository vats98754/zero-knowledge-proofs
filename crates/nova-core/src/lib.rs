//! # Nova Core: Incremental Verifiable Computation
//! 
//! This crate provides the foundational components for Nova, an incremental verifiable
//! computation scheme that supports recursive succinct proofs via efficient folding.
//! 
//! ## Mathematical Foundation
//! 
//! Nova operates over a field `F` (BLS12-381 Fr by default) and performs folding over
//! multilinear polynomial encodings using inner products and evaluation protocols.
//! 
//! The core model defines computational instances as algebraic relations `R` over vector
//! spaces, with a `Step` folding operator that compresses relations and witnesses into
//! smaller instances.
//! 
//! ## Key Components
//! 
//! - **Fields**: BLS12-381 scalar field operations
//! - **Instances**: Computational instance representation as algebraic relations
//! - **Witnesses**: Witness data for satisfying computational relations
//! - **Folding**: Core folding operations and compression algorithms
//! - **Transcripts**: Fiat-Shamir transcript handling for non-interactive proofs
//! 
//! ## Correctness Theorem
//! 
//! The folding operation `compress(instance, witness, randomness)` produces 
//! `(new_instance, folded_witness)` such that verifying `new_instance` suffices to
//! verify the original instance given the randomness.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod fields;
pub mod instances;
pub mod witnesses;
pub mod folding;
pub mod transcripts;
pub mod errors;

pub use fields::*;
pub use instances::*;
pub use witnesses::*;
pub use folding::*;
pub use transcripts::*;
pub use errors::*;