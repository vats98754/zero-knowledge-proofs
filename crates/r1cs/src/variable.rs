//! Variable representation in R1CS

use ark_std::fmt;
use serde::{Deserialize, Serialize};

/// A variable in the R1CS constraint system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Variable {
    pub index: usize,
}

impl Variable {
    /// Create a new variable with the given index
    pub fn new(index: usize) -> Self {
        Self { index }
    }

    /// Get the variable index
    pub fn index(&self) -> usize {
        self.index
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.index)
    }
}