//! Accumulator for recursive proofs

use crate::{Scalar, Result};

/// Accumulator instance
#[derive(Clone, Debug)]
pub struct AccumulatorInstance {
    /// Public inputs
    pub public_inputs: Vec<Scalar>,
}

/// Accumulator for folding proofs
#[derive(Clone, Debug)]
pub struct Accumulator {
    /// Instance data
    pub instance: AccumulatorInstance,
}

impl Accumulator {
    /// Create a new accumulator
    pub fn new(instance: AccumulatorInstance) -> Self {
        Self { instance }
    }
}