//! Computational instances and algebraic relations for Nova.
//!
//! This module defines the representation of computational instances as algebraic
//! relations over vector spaces, which form the basis of the Nova folding scheme.

use crate::fields::{NovaField, MultilinearPolynomial};
use ark_std::{vec::Vec, Zero};
use crate::errors::NovaError;

/// Represents a computational instance as an algebraic relation over a vector space.
/// 
/// In Nova, computational instances are represented as satisfiability problems
/// for algebraic relations. Each instance consists of:
/// - Public inputs that define the computation
/// - Parameters that characterize the relation structure
/// - Metadata about the computation size and complexity
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Public inputs to the computation
    pub public_inputs: Vec<NovaField>,
    /// Committed values (e.g., polynomial commitments)
    pub commitments: Vec<NovaField>,
    /// Instance size parameters
    pub size: InstanceSize,
}

/// Size parameters for a computational instance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSize {
    /// Number of variables in the relation
    pub num_vars: usize,
    /// Number of constraints in the relation
    pub num_constraints: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
}

impl Instance {
    /// Creates a new computational instance
    pub fn new(
        public_inputs: Vec<NovaField>,
        commitments: Vec<NovaField>,
        num_vars: usize,
        num_constraints: usize,
    ) -> Self {
        let size = InstanceSize {
            num_vars,
            num_constraints,
            num_public_inputs: public_inputs.len(),
        };

        Self {
            public_inputs,
            commitments,
            size,
        }
    }

    /// Returns the size of this instance
    pub fn size(&self) -> &InstanceSize {
        &self.size
    }

    /// Checks if this instance is compatible with another for folding
    pub fn is_compatible_for_folding(&self, other: &Instance) -> bool {
        self.size.num_vars == other.size.num_vars
            && self.size.num_constraints == other.size.num_constraints
            && self.size.num_public_inputs == other.size.num_public_inputs
    }

    /// Validates the instance structure
    pub fn validate(&self) -> Result<(), NovaError> {
        if self.public_inputs.len() != self.size.num_public_inputs {
            return Err(NovaError::InvalidInstance(
                "Public inputs length mismatch".to_string()
            ));
        }

        if self.size.num_vars == 0 {
            return Err(NovaError::InvalidInstance(
                "Number of variables must be positive".to_string()
            ));
        }

        if self.size.num_constraints == 0 {
            return Err(NovaError::InvalidInstance(
                "Number of constraints must be positive".to_string()
            ));
        }

        Ok(())
    }
}

/// Represents an algebraic relation that defines the computation.
/// 
/// The relation `R` is defined over a vector space and specifies the constraints
/// that must be satisfied by a valid computation. This is typically represented
/// as a system of multilinear polynomial equations.
#[derive(Debug, Clone)]
pub struct Relation {
    /// Constraint polynomials that define the relation
    pub constraints: Vec<MultilinearPolynomial>,
    /// Number of variables in the relation
    pub num_vars: usize,
    /// Public input positions
    pub public_input_indices: Vec<usize>,
}

impl Relation {
    /// Creates a new algebraic relation
    pub fn new(
        constraints: Vec<MultilinearPolynomial>,
        public_input_indices: Vec<usize>,
    ) -> Result<Self, NovaError> {
        if constraints.is_empty() {
            return Err(NovaError::InvalidRelation(
                "Relation must have at least one constraint".to_string()
            ));
        }

        let num_vars = constraints[0].num_vars();
        
        // Ensure all constraints have the same number of variables
        for constraint in &constraints {
            if constraint.num_vars() != num_vars {
                return Err(NovaError::InvalidRelation(
                    "All constraints must have the same number of variables".to_string()
                ));
            }
        }

        // Validate public input indices
        for &idx in &public_input_indices {
            if idx >= num_vars {
                return Err(NovaError::InvalidRelation(
                    "Public input index out of range".to_string()
                ));
            }
        }

        Ok(Self {
            constraints,
            num_vars,
            public_input_indices,
        })
    }

    /// Returns the number of constraints in this relation
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Returns the number of variables in this relation
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Evaluates all constraints at a given assignment
    pub fn evaluate_constraints(&self, assignment: &[NovaField]) -> Vec<NovaField> {
        if assignment.len() != self.num_vars {
            panic!("Assignment length must match number of variables");
        }

        self.constraints
            .iter()
            .map(|constraint| constraint.evaluate(assignment))
            .collect()
    }

    /// Checks if an assignment satisfies the relation (all constraints evaluate to zero)
    pub fn is_satisfied(&self, assignment: &[NovaField]) -> bool {
        let evaluations = self.evaluate_constraints(assignment);
        evaluations.iter().all(|&eval| eval == NovaField::zero())
    }

    /// Creates an instance from this relation and a witness assignment
    pub fn create_instance(&self, witness: &[NovaField]) -> Result<Instance, NovaError> {
        if witness.len() != self.num_vars {
            return Err(NovaError::InvalidWitness(
                "Witness length must match relation variables".to_string()
            ));
        }

        // Extract public inputs
        let public_inputs: Vec<NovaField> = self.public_input_indices
            .iter()
            .map(|&idx| witness[idx])
            .collect();

        // For now, we'll use constraint evaluations as commitments
        // In a full implementation, these would be actual polynomial commitments
        let commitments = self.evaluate_constraints(witness);

        Ok(Instance::new(
            public_inputs,
            commitments,
            self.num_vars,
            self.num_constraints(),
        ))
    }
}

/// A step function that transforms one computational instance into another.
/// 
/// This represents one step of incremental computation in Nova. The step function
/// takes an instance and produces a new instance that represents the next step
/// in the computation.
#[derive(Debug, Clone)]
pub struct StepFunction {
    /// The relation that defines this step
    pub relation: Relation,
    /// Additional parameters for the step function
    pub parameters: StepParameters,
}

/// Parameters for a step function
#[derive(Debug, Clone)]
pub struct StepParameters {
    /// Step identifier
    pub step_id: u64,
    /// Maximum number of iterations
    pub max_iterations: usize,
}

impl StepFunction {
    /// Creates a new step function
    pub fn new(relation: Relation, step_id: u64, max_iterations: usize) -> Self {
        let parameters = StepParameters {
            step_id,
            max_iterations,
        };

        Self {
            relation,
            parameters,
        }
    }

    /// Applies the step function to transform an instance
    pub fn apply(&self, _input: &Instance, witness: &[NovaField]) -> Result<Instance, NovaError> {
        // Validate that the witness satisfies the relation
        if !self.relation.is_satisfied(witness) {
            return Err(NovaError::InvalidWitness(
                "Witness does not satisfy the step relation".to_string()
            ));
        }

        // Create the output instance
        self.relation.create_instance(witness)
    }

    /// Returns the size characteristics of instances this step function operates on
    pub fn instance_size(&self) -> InstanceSize {
        InstanceSize {
            num_vars: self.relation.num_vars(),
            num_constraints: self.relation.num_constraints(),
            num_public_inputs: self.relation.public_input_indices.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::NovaField;
    use ark_std::{vec, Zero, One};

    fn create_simple_relation() -> Relation {
        // Create a simple linear relation: x + y = z (one constraint)
        // Variables: [x, y, z], Public inputs: [z] (index 2)
        
        // Constraint polynomial: x + y - z = 0
        // This is a 3-variable multilinear polynomial
        // Evaluations at (0,0,0), (1,0,0), (0,1,0), (1,1,0), (0,0,1), (1,0,1), (0,1,1), (1,1,1)
        // f(x,y,z) = x + y - z
        // f(0,0,0) = 0, f(1,0,0) = 1, f(0,1,0) = 1, f(1,1,0) = 2
        // f(0,0,1) = -1, f(1,0,1) = 0, f(0,1,1) = 0, f(1,1,1) = 1
        let evaluations = vec![
            NovaField::zero(),          // (0,0,0): 0 + 0 - 0 = 0
            NovaField::one(),           // (1,0,0): 1 + 0 - 0 = 1
            NovaField::one(),           // (0,1,0): 0 + 1 - 0 = 1
            NovaField::from(2u64),      // (1,1,0): 1 + 1 - 0 = 2
            -NovaField::one(),          // (0,0,1): 0 + 0 - 1 = -1
            NovaField::zero(),          // (1,0,1): 1 + 0 - 1 = 0
            NovaField::zero(),          // (0,1,1): 0 + 1 - 1 = 0
            NovaField::one(),           // (1,1,1): 1 + 1 - 1 = 1
        ];
        
        let constraint = MultilinearPolynomial::new(evaluations);
        Relation::new(vec![constraint], vec![2]).unwrap()
    }

    #[test]
    fn test_instance_creation() {
        let public_inputs = vec![NovaField::from(6u64)];
        let commitments = vec![NovaField::zero()];
        let instance = Instance::new(public_inputs.clone(), commitments.clone(), 3, 1);

        assert_eq!(instance.public_inputs, public_inputs);
        assert_eq!(instance.commitments, commitments);
        assert_eq!(instance.size.num_vars, 3);
        assert_eq!(instance.size.num_constraints, 1);
        assert_eq!(instance.size.num_public_inputs, 1);
    }

    #[test]
    fn test_instance_validation() {
        let instance = Instance::new(
            vec![NovaField::from(6u64)],
            vec![NovaField::zero()],
            3,
            1,
        );
        assert!(instance.validate().is_ok());

        // Invalid instance with mismatched public inputs length
        let mut invalid_instance = instance.clone();
        invalid_instance.size.num_public_inputs = 2;
        assert!(invalid_instance.validate().is_err());
    }

    #[test]
    fn test_relation_creation() {
        let relation = create_simple_relation();
        assert_eq!(relation.num_vars(), 3);
        assert_eq!(relation.num_constraints(), 1);
        assert_eq!(relation.public_input_indices, vec![2]);
    }

    #[test]
    fn test_relation_satisfaction() {
        let relation = create_simple_relation();
        
        // Valid assignment: x=2, y=3, z=5
        let valid_assignment = vec![
            NovaField::from(2u64),
            NovaField::from(3u64),
            NovaField::from(5u64),
        ];
        assert!(relation.is_satisfied(&valid_assignment));

        // Invalid assignment: x=2, y=3, z=4
        let invalid_assignment = vec![
            NovaField::from(2u64),
            NovaField::from(3u64),
            NovaField::from(4u64),
        ];
        assert!(!relation.is_satisfied(&invalid_assignment));
    }

    #[test]
    fn test_instance_creation_from_relation() {
        let relation = create_simple_relation();
        let witness = vec![
            NovaField::from(2u64),
            NovaField::from(3u64),
            NovaField::from(5u64),
        ];

        let instance = relation.create_instance(&witness).unwrap();
        assert_eq!(instance.public_inputs, vec![NovaField::from(5u64)]);
        assert_eq!(instance.size.num_vars, 3);
        assert_eq!(instance.size.num_public_inputs, 1);
    }

    #[test]
    fn test_step_function() {
        let relation = create_simple_relation();
        let step_function = StepFunction::new(relation, 1, 100);

        let input_instance = Instance::new(
            vec![NovaField::from(5u64)],
            vec![NovaField::zero()],
            3,
            1,
        );

        let witness = vec![
            NovaField::from(2u64),
            NovaField::from(3u64),
            NovaField::from(5u64),
        ];

        let output_instance = step_function.apply(&input_instance, &witness).unwrap();
        assert_eq!(output_instance.public_inputs, vec![NovaField::from(5u64)]);
    }

    #[test]
    fn test_instance_compatibility() {
        let instance1 = Instance::new(
            vec![NovaField::from(1u64)],
            vec![NovaField::zero()],
            3,
            1,
        );

        let instance2 = Instance::new(
            vec![NovaField::from(2u64)],
            vec![NovaField::zero()],
            3,
            1,
        );

        let incompatible_instance = Instance::new(
            vec![NovaField::from(1u64)],
            vec![NovaField::zero()],
            4,  // Different number of variables
            1,
        );

        assert!(instance1.is_compatible_for_folding(&instance2));
        assert!(!instance1.is_compatible_for_folding(&incompatible_instance));
    }
}