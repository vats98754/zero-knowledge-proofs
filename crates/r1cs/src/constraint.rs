//! R1CS constraint representation

use crate::LinearCombination;
use ark_ff::Field;
use ark_std::fmt;
use serde::{Deserialize, Serialize};

/// An R1CS constraint: A * B = C
/// where A, B, and C are linear combinations of variables
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint<F: Field> {
    pub a: LinearCombination<F>,
    pub b: LinearCombination<F>,
    pub c: LinearCombination<F>,
}

impl<F: Field> Constraint<F> {
    /// Create a new constraint
    pub fn new(a: LinearCombination<F>, b: LinearCombination<F>, c: LinearCombination<F>) -> Self {
        Self { a, b, c }
    }

    /// Check if the constraint is satisfied by the given witness
    pub fn is_satisfied(&self, witness: &[F]) -> bool {
        let a_val = self.a.evaluate(witness);
        let b_val = self.b.evaluate(witness);
        let c_val = self.c.evaluate(witness);
        
        a_val * b_val == c_val
    }
}

impl<F: Field> fmt::Display for Constraint<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}) * ({}) = ({})", self.a, self.b, self.c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Variable, LinearCombination};
    use ark_bls12_381::Fr;

    #[test]
    fn test_constraint_satisfaction() {
        let x = Variable::new(1);
        let y = Variable::new(2);
        let z = Variable::new(3);

        // Constraint: x * y = z
        let a = LinearCombination::<Fr>::from_variable(x);
        let b = LinearCombination::<Fr>::from_variable(y);
        let c = LinearCombination::<Fr>::from_variable(z);

        let constraint = Constraint::new(a, b, c);

        // Satisfying witness: [1, 3, 4, 12] (x=3, y=4, z=12)
        let witness = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(4u64), Fr::from(12u64)];
        assert!(constraint.is_satisfied(&witness));

        // Non-satisfying witness: [1, 3, 4, 13] (x=3, y=4, z=13)
        let bad_witness = vec![Fr::from(1u64), Fr::from(3u64), Fr::from(4u64), Fr::from(13u64)];
        assert!(!constraint.is_satisfied(&bad_witness));
    }
}