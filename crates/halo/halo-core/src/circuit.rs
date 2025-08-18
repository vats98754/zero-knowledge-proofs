//! Circuit definitions for Halo

use crate::HaloError;

/// Configuration for a circuit
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    /// Number of advice columns
    pub advice_columns: usize,
    /// Number of fixed columns  
    pub fixed_columns: usize,
    /// Number of instance columns
    pub instance_columns: usize,
}

/// Trait for defining circuits
pub trait Circuit {
    /// Configure the circuit with the given config
    fn configure(config: &CircuitConfig) -> Result<Self, HaloError>
    where
        Self: Sized;
    
    /// Synthesize the circuit
    fn synthesize(&self) -> Result<(), HaloError>;
}