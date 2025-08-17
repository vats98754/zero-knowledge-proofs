//! Benchmarks for Bulletproofs implementation
//!
//! This crate contains performance benchmarks for:
//! - Range proof generation and verification
//! - Inner product argument (IPA) operations
//! - Generator operations and multi-scalar multiplication
//!
//! Run benchmarks with:
//! ```bash
//! cargo bench -p benches
//! ```
//!
//! Or run specific benchmarks:
//! ```bash
//! cargo bench -p benches --bench range_proof
//! cargo bench -p benches --bench ipa
//! ```

pub use bulletproofs_core::*;
pub use ipa::*;
pub use range::*;