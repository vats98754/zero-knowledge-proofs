//! Examples and CLI tools for Bulletproofs
//! 
//! This crate provides command-line tools for generating and verifying range proofs:
//! 
//! - `prove-range`: Generate a range proof for a value
//! - `verify-range`: Verify a range proof
//! 
//! ## Usage
//! 
//! Generate a proof that value 42 is in range [0, 256):
//! ```bash
//! cargo run --bin prove-range -- --value 42 --bits 8
//! ```
//! 
//! Verify a proof:
//! ```bash
//! echo "proof_hex_string" | cargo run --bin verify-range -- --bits 8
//! ```

pub use range::*;
pub use bulletproofs_core::*;