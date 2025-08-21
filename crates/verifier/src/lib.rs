//! STARK verifier implementation
//! 
//! This crate implements the verifier side of the STARK protocol.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Main STARK verifier implementation
pub mod stark_verifier;

pub use stark_verifier::*;