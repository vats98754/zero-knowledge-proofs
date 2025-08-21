//! Algebraic Intermediate Representation (AIR) for STARK proofs
//! 
//! This crate defines the AIR trait and common implementations for expressing
//! computational integrity constraints in STARK proof systems.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use stark_field::{GoldilocksField, Zero, One};
use thiserror::Error;
use num_traits::{Zero as NumZero, One as NumOne};

/// Errors that can occur when working with AIR constraints
#[derive(Error, Debug)]
pub enum AirError {
    /// Invalid trace dimensions
    #[error("Invalid trace dimensions: expected {expected}, got {actual}")]
    InvalidTraceDimensions { 
        /// Expected dimension
        expected: usize, 
        /// Actual dimension
        actual: usize 
    },
    
    /// Constraint evaluation failed
    #[error("Constraint evaluation failed: {message}")]
    ConstraintEvaluationFailed { 
        /// Error message
        message: String 
    },
    
    /// Invalid boundary constraint
    #[error("Invalid boundary constraint at step {step}, column {column}")]
    InvalidBoundaryConstraint { 
        /// Step number
        step: usize, 
        /// Column number
        column: usize 
    },
}

/// Represents a single row in the execution trace
pub type TraceRow = Vec<GoldilocksField>;

/// Represents the complete execution trace
pub type ExecutionTrace = Vec<TraceRow>;

/// Context for evaluating AIR constraints
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// Current trace row
    pub current_row: TraceRow,
    /// Next trace row (if available)
    pub next_row: Option<TraceRow>,
    /// Current step number
    pub step: usize,
    /// Total number of steps
    pub num_steps: usize,
}

/// Boundary constraint specification
#[derive(Debug, Clone)]
pub struct BoundaryConstraint {
    /// Column index in the trace
    pub column: usize,
    /// Step number (0 for initial, num_steps-1 for final)
    pub step: usize,
    /// Required value at this position
    pub value: GoldilocksField,
}

/// Algebraic Intermediate Representation trait
/// 
/// This trait defines the interface for expressing computational integrity
/// constraints that will be verified by the STARK prover and verifier.
pub trait Air {
    /// Number of columns in the execution trace
    fn trace_width(&self) -> usize;
    
    /// Minimum number of steps required for this computation
    fn min_trace_length(&self) -> usize;
    
    /// Number of transition constraints
    fn num_transition_constraints(&self) -> usize;
    
    /// Number of boundary constraints  
    fn num_boundary_constraints(&self) -> usize;
    
    /// Degree of transition constraints (maximum degree of polynomials)
    fn constraint_degree(&self) -> usize;
    
    /// Evaluate transition constraints at the given context
    /// 
    /// Returns a vector where each element represents the evaluation of
    /// one transition constraint. These should be zero for valid transitions.
    fn evaluate_transition_constraints(
        &self,
        context: &EvaluationContext,
    ) -> Result<Vec<GoldilocksField>, AirError>;
    
    /// Get all boundary constraints for this AIR
    fn boundary_constraints(&self) -> Vec<BoundaryConstraint>;
    
    /// Validate that a trace satisfies this AIR's constraints
    fn validate_trace(&self, trace: &ExecutionTrace) -> Result<(), AirError> {
        // Check trace dimensions
        if trace.is_empty() {
            return Err(AirError::InvalidTraceDimensions {
                expected: self.min_trace_length(),
                actual: 0,
            });
        }
        
        let trace_length = trace.len();
        if trace_length < self.min_trace_length() {
            return Err(AirError::InvalidTraceDimensions {
                expected: self.min_trace_length(),
                actual: trace_length,
            });
        }
        
        // Check that all rows have correct width
        for (step, row) in trace.iter().enumerate() {
            if row.len() != self.trace_width() {
                return Err(AirError::InvalidTraceDimensions {
                    expected: self.trace_width(),
                    actual: row.len(),
                });
            }
        }
        
        // Check boundary constraints
        for constraint in self.boundary_constraints() {
            if constraint.step >= trace_length {
                return Err(AirError::InvalidBoundaryConstraint {
                    step: constraint.step,
                    column: constraint.column,
                });
            }
            
            if constraint.column >= self.trace_width() {
                return Err(AirError::InvalidBoundaryConstraint {
                    step: constraint.step,
                    column: constraint.column,
                });
            }
            
            let actual_value = trace[constraint.step][constraint.column];
            if actual_value != constraint.value {
                return Err(AirError::ConstraintEvaluationFailed {
                    message: format!(
                        "Boundary constraint failed at step {}, column {}: expected {}, got {}",
                        constraint.step, constraint.column, constraint.value, actual_value
                    ),
                });
            }
        }
        
        // Check transition constraints
        for step in 0..trace_length - 1 {
            let context = EvaluationContext {
                current_row: trace[step].clone(),
                next_row: Some(trace[step + 1].clone()),
                step,
                num_steps: trace_length,
            };
            
            let constraint_evaluations = self.evaluate_transition_constraints(&context)?;
            
            for (i, &evaluation) in constraint_evaluations.iter().enumerate() {
                if !evaluation.is_zero() {
                    return Err(AirError::ConstraintEvaluationFailed {
                        message: format!(
                            "Transition constraint {} failed at step {}: evaluation = {}",
                            i, step, evaluation
                        ),
                    });
                }
            }
        }
        
        Ok(())
    }
}

/// Example AIR implementation for Fibonacci sequence
/// 
/// This demonstrates a simple AIR with two columns:
/// - Column 0: F(n-1) 
/// - Column 1: F(n)
/// 
/// Transition constraint: F(n+1) = F(n) + F(n-1)
#[derive(Debug, Clone)]
pub struct FibonacciAir {
    /// Starting values for the sequence
    pub initial_values: (GoldilocksField, GoldilocksField),
    /// Target length for the computation
    pub target_length: usize,
}

impl FibonacciAir {
    /// Create a new Fibonacci AIR with given initial values
    pub fn new(
        initial_values: (GoldilocksField, GoldilocksField),
        target_length: usize,
    ) -> Self {
        Self {
            initial_values,
            target_length,
        }
    }
    
    /// Generate a valid execution trace for this Fibonacci computation
    pub fn generate_trace(&self) -> ExecutionTrace {
        let mut trace = Vec::with_capacity(self.target_length);
        
        // Initial step
        trace.push(vec![self.initial_values.0, self.initial_values.1]);
        
        // Generate subsequent steps
        for i in 1..self.target_length {
            let prev_prev = trace[i - 1][0];
            let prev = trace[i - 1][1];
            let current = prev_prev + prev;
            
            trace.push(vec![prev, current]);
        }
        
        trace
    }
}

impl Air for FibonacciAir {
    fn trace_width(&self) -> usize {
        2
    }
    
    fn min_trace_length(&self) -> usize {
        self.target_length
    }
    
    fn num_transition_constraints(&self) -> usize {
        1
    }
    
    fn num_boundary_constraints(&self) -> usize {
        2 // Initial values for both columns
    }
    
    fn constraint_degree(&self) -> usize {
        1 // Linear constraints only
    }
    
    fn evaluate_transition_constraints(
        &self,
        context: &EvaluationContext,
    ) -> Result<Vec<GoldilocksField>, AirError> {
        let next_row = context.next_row.as_ref().ok_or_else(|| {
            AirError::ConstraintEvaluationFailed {
                message: "Next row required for transition constraint".to_string(),
            }
        })?;
        
        if context.current_row.len() != 2 || next_row.len() != 2 {
            return Err(AirError::ConstraintEvaluationFailed {
                message: "Invalid row dimensions for Fibonacci AIR".to_string(),
            });
        }
        
        // Constraint: next_row[1] = current_row[0] + current_row[1]
        // And: next_row[0] = current_row[1]
        let constraint1 = next_row[0] - context.current_row[1];
        let constraint2 = next_row[1] - (context.current_row[0] + context.current_row[1]);
        
        Ok(vec![constraint1, constraint2])
    }
    
    fn boundary_constraints(&self) -> Vec<BoundaryConstraint> {
        vec![
            BoundaryConstraint {
                column: 0,
                step: 0,
                value: self.initial_values.0,
            },
            BoundaryConstraint {
                column: 1,
                step: 0,
                value: self.initial_values.1,
            },
        ]
    }
}

/// Simple CPU AIR for demonstrating more complex constraints
/// 
/// This represents a minimal CPU with:
/// - Program counter (PC)
/// - Accumulator (ACC) 
/// - Memory interface
/// 
/// Instructions:
/// - ADD: ACC = ACC + memory[PC+1]
/// - SUB: ACC = ACC - memory[PC+1]  
/// - JMP: PC = memory[PC+1]
/// - HALT: Stop execution
#[derive(Debug, Clone)]
pub struct SimpleCpuAir {
    /// The program to execute
    pub program: Vec<GoldilocksField>,
    /// Initial accumulator value
    pub initial_acc: GoldilocksField,
}

/// CPU instruction opcodes
#[repr(u64)]
pub enum Opcode {
    /// Add immediate to accumulator
    Add = 1,
    /// Subtract immediate from accumulator  
    Sub = 2,
    /// Jump to address
    Jmp = 3,
    /// Halt execution
    Halt = 0,
}

impl SimpleCpuAir {
    /// Create a new simple CPU AIR
    pub fn new(program: Vec<GoldilocksField>, initial_acc: GoldilocksField) -> Self {
        Self {
            program,
            initial_acc,
        }
    }
    
    /// Generate execution trace for the CPU
    pub fn generate_trace(&self) -> ExecutionTrace {
        let mut trace = Vec::new();
        let mut pc = 0usize;
        let mut acc = self.initial_acc;
        
        loop {
            if pc >= self.program.len() {
                break;
            }
            
            let instruction = self.program[pc];
            let opcode = instruction.value();
            
            // Record current state: [PC, ACC, OPCODE, OPERAND]
            let operand = if pc + 1 < self.program.len() {
                self.program[pc + 1]
            } else {
                GoldilocksField::zero()
            };
            
            trace.push(vec![
                GoldilocksField::from(pc as u64),
                acc,
                instruction,
                operand,
            ]);
            
            match opcode {
                0 => break, // HALT
                1 => {
                    // ADD
                    acc = acc + operand;
                    pc += 2;
                }
                2 => {
                    // SUB
                    acc = acc - operand;
                    pc += 2;
                }
                3 => {
                    // JMP
                    pc = operand.value() as usize;
                }
                _ => {
                    // Invalid opcode, halt
                    break;
                }
            }
        }
        
        trace
    }
}

impl Air for SimpleCpuAir {
    fn trace_width(&self) -> usize {
        4 // PC, ACC, OPCODE, OPERAND
    }
    
    fn min_trace_length(&self) -> usize {
        1
    }
    
    fn num_transition_constraints(&self) -> usize {
        4 // Different constraints for different opcodes
    }
    
    fn num_boundary_constraints(&self) -> usize {
        2 // Initial PC = 0, initial ACC = initial_acc
    }
    
    fn constraint_degree(&self) -> usize {
        2 // May have quadratic constraints for opcode checking
    }
    
    fn evaluate_transition_constraints(
        &self,
        context: &EvaluationContext,
    ) -> Result<Vec<GoldilocksField>, AirError> {
        let next_row = context.next_row.as_ref().ok_or_else(|| {
            AirError::ConstraintEvaluationFailed {
                message: "Next row required for transition constraint".to_string(),
            }
        })?;
        
        if context.current_row.len() != 4 || next_row.len() != 4 {
            return Err(AirError::ConstraintEvaluationFailed {
                message: "Invalid row dimensions for CPU AIR".to_string(),
            });
        }
        
        let pc = context.current_row[0];
        let acc = context.current_row[1];
        let opcode = context.current_row[2];
        let operand = context.current_row[3];
        
        let next_pc = next_row[0];
        let next_acc = next_row[1];
        
        // Simplified constraints - in practice these would be more sophisticated
        let mut constraints = Vec::new();
        
        // For this simple example, we'll just enforce basic consistency
        // Real CPU AIRs would have much more complex constraint systems
        
        // Constraint 1: PC updates correctly for most instructions
        let pc_constraint = if opcode.value() == 3 {
            // JMP: next_pc should equal operand
            next_pc - operand
        } else if opcode.value() == 0 {
            // HALT: PC doesn't change
            next_pc - pc
        } else {
            // ADD/SUB: PC increases by 2
            next_pc - (pc + GoldilocksField::from(2u64))
        };
        constraints.push(pc_constraint);
        
        // Constraint 2: ACC updates correctly
        let acc_constraint = if opcode.value() == 1 {
            // ADD
            next_acc - (acc + operand)
        } else if opcode.value() == 2 {
            // SUB
            next_acc - (acc - operand)
        } else {
            // JMP/HALT: ACC doesn't change
            next_acc - acc
        };
        constraints.push(acc_constraint);
        
        // Add padding constraints
        constraints.push(GoldilocksField::zero());
        constraints.push(GoldilocksField::zero());
        
        Ok(constraints)
    }
    
    fn boundary_constraints(&self) -> Vec<BoundaryConstraint> {
        vec![
            BoundaryConstraint {
                column: 0, // PC
                step: 0,
                value: GoldilocksField::zero(),
            },
            BoundaryConstraint {
                column: 1, // ACC
                step: 0,
                value: self.initial_acc,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stark_field::F;
    
    #[test]
    fn test_fibonacci_air() {
        let air = FibonacciAir::new(
            (GoldilocksField::from(0u64), GoldilocksField::from(1u64)),
            5,
        );
        
        let trace = air.generate_trace();
        assert_eq!(trace.len(), 5);
        assert_eq!(trace[0], vec![F::from(0u64), F::from(1u64)]);
        assert_eq!(trace[1], vec![F::from(1u64), F::from(1u64)]);
        assert_eq!(trace[2], vec![F::from(1u64), F::from(2u64)]);
        assert_eq!(trace[3], vec![F::from(2u64), F::from(3u64)]);
        assert_eq!(trace[4], vec![F::from(3u64), F::from(5u64)]);
        
        // Validate the trace
        assert!(air.validate_trace(&trace).is_ok());
    }
    
    #[test]
    fn test_fibonacci_air_invalid_trace() {
        let air = FibonacciAir::new(
            (GoldilocksField::from(0u64), GoldilocksField::from(1u64)),
            3,
        );
        
        // Create an invalid trace
        let invalid_trace = vec![
            vec![F::from(0u64), F::from(1u64)],
            vec![F::from(1u64), F::from(2u64)], // Should be [1, 1]
            vec![F::from(2u64), F::from(3u64)],
        ];
        
        assert!(air.validate_trace(&invalid_trace).is_err());
    }
    
    #[test]
    fn test_simple_cpu_air() {
        let program = vec![
            GoldilocksField::from(1u64), // ADD
            GoldilocksField::from(5u64), // operand: 5
            GoldilocksField::from(2u64), // SUB  
            GoldilocksField::from(2u64), // operand: 2
            GoldilocksField::from(0u64), // HALT
        ];
        
        let air = SimpleCpuAir::new(program, GoldilocksField::from(10u64));
        let trace = air.generate_trace();
        
        // Check that trace was generated
        assert!(!trace.is_empty());
        
        // Check initial state
        assert_eq!(trace[0][0], GoldilocksField::from(0u64)); // PC = 0
        assert_eq!(trace[0][1], GoldilocksField::from(10u64)); // ACC = 10
        
        // Validate boundary constraints
        let boundary_constraints = air.boundary_constraints();
        assert_eq!(boundary_constraints.len(), 2);
    }
}