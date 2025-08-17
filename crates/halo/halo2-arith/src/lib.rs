//! # Halo2 Arithmetic
//!
//! PLONK-style arithmetic circuits with configurable gates and lookup tables
//! for the Halo2 proving system. This crate provides the circuit description
//! language and constraint system for building complex arithmetic circuits.

pub mod circuit;
pub mod gates;
pub mod lookup;
pub mod columns;
pub mod constraints;
pub mod errors;

// Re-export key types
pub use circuit::{Halo2Circuit, CircuitBuilder};
pub use gates::{Gate, StandardGate, CustomGate};
pub use lookup::{LookupTable, LookupArgument};
pub use columns::{Column, AdviceColumn, FixedColumn, InstanceColumn};
pub use constraints::{ConstraintSystem, Constraint};
pub use errors::{Halo2Error, Result};

/// Re-export commitments for convenience
pub use commitments;

/// BLS12-381 scalar field
pub type Scalar = bls12_381::Scalar;