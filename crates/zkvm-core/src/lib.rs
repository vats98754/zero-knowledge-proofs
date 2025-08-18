use std::collections::HashMap;
use thiserror::Error;

pub mod instruction;
pub mod state;
pub mod trace;
pub mod constraints;

pub use instruction::{Instruction, Opcode};
pub use state::{VmState, Register};
pub use trace::{ExecutionTrace, TraceRow};
pub use constraints::{ConstraintGenerator, ConstraintSystem, Constraint, ConstraintType};

#[derive(Error, Debug)]
pub enum VmError {
    #[error("Invalid instruction: {0}")]
    InvalidInstruction(String),
    #[error("Memory access out of bounds: {0}")]
    MemoryOutOfBounds(u64),
    #[error("Stack overflow")]
    StackOverflow,
    #[error("Stack underflow")]
    StackUnderflow,
    #[error("Division by zero")]
    DivisionByZero,
    #[error("Invalid register: {0}")]
    InvalidRegister(u8),
}

pub type Result<T> = std::result::Result<T, VmError>;

/// Core zkVM that executes instructions and generates execution traces
#[derive(Debug, Clone)]
pub struct ZkVm {
    state: VmState,
    trace: ExecutionTrace,
    memory: HashMap<u64, u64>,
    program: Vec<Instruction>,
}

impl ZkVm {
    pub fn new(trace_width: usize) -> Self {
        Self {
            state: VmState::new(),
            trace: ExecutionTrace::new(trace_width),
            memory: HashMap::new(),
            program: Vec::new(),
        }
    }

    pub fn load_program(&mut self, program: Vec<Instruction>) {
        self.program = program;
        self.state.reset();
    }

    /// Execute the loaded program and generate execution trace
    pub fn execute(&mut self) -> Result<()> {
        while (self.state.pc as usize) < self.program.len() {
            let instruction = &self.program[self.state.pc as usize].clone();
            
            // Record current state in trace before execution
            self.record_trace_step(instruction)?;
            
            // Execute the instruction
            self.execute_instruction(instruction)?;
        }
        Ok(())
    }

    fn execute_instruction(&mut self, instruction: &Instruction) -> Result<()> {
        match instruction.opcode {
            Opcode::Add => {
                let a = self.state.get_register(instruction.src1)?;
                let b = self.state.get_register(instruction.src2)?;
                self.state.set_register(instruction.dst, a.wrapping_add(b))?;
                self.state.pc += 1;
            }
            Opcode::Sub => {
                let a = self.state.get_register(instruction.src1)?;
                let b = self.state.get_register(instruction.src2)?;
                self.state.set_register(instruction.dst, a.wrapping_sub(b))?;
                self.state.pc += 1;
            }
            Opcode::Mul => {
                let a = self.state.get_register(instruction.src1)?;
                let b = self.state.get_register(instruction.src2)?;
                self.state.set_register(instruction.dst, a.wrapping_mul(b))?;
                self.state.pc += 1;
            }
            Opcode::Div => {
                let a = self.state.get_register(instruction.src1)?;
                let b = self.state.get_register(instruction.src2)?;
                if b == 0 {
                    return Err(VmError::DivisionByZero);
                }
                self.state.set_register(instruction.dst, a / b)?;
                self.state.pc += 1;
            }
            Opcode::Load => {
                let addr = self.state.get_register(instruction.src1)?;
                let value = self.memory.get(&addr).copied().unwrap_or(0);
                self.state.set_register(instruction.dst, value)?;
                self.state.pc += 1;
            }
            Opcode::Store => {
                let addr = self.state.get_register(instruction.src1)?;
                let value = self.state.get_register(instruction.src2)?;
                self.memory.insert(addr, value);
                self.state.pc += 1;
            }
            Opcode::Jump => {
                self.state.pc = instruction.immediate as u64;
            }
            Opcode::JumpIfZero => {
                let value = self.state.get_register(instruction.src1)?;
                if value == 0 {
                    self.state.pc = instruction.immediate as u64;
                } else {
                    self.state.pc += 1;
                }
            }
            Opcode::Syscall => {
                // Stub for syscall - could be extended for I/O operations
                self.state.pc += 1;
            }
            Opcode::Halt => {
                // Set PC beyond program to stop execution
                self.state.pc = self.program.len() as u64;
            }
        }
        Ok(())
    }

    fn record_trace_step(&mut self, instruction: &Instruction) -> Result<()> {
        let mut row = vec![0u64; self.trace.width()];
        
        // Standard trace encoding:
        // [0]: program counter
        // [1-8]: register values (R0-R7)
        // [9]: instruction opcode
        // [10]: src1 register
        // [11]: src2 register  
        // [12]: dst register
        // [13]: immediate value
        // [14-end]: memory access addresses and values
        
        row[0] = self.state.pc;
        for i in 0..8 {
            row[i + 1] = self.state.get_register(i as u8).unwrap_or(0);
        }
        row[9] = instruction.opcode as u64;
        row[10] = instruction.src1 as u64;
        row[11] = instruction.src2 as u64;
        row[12] = instruction.dst as u64;
        row[13] = instruction.immediate as u64;

        self.trace.add_row(TraceRow::new(row));
        Ok(())
    }

    pub fn get_trace(&self) -> &ExecutionTrace {
        &self.trace
    }

    pub fn get_state(&self) -> &VmState {
        &self.state
    }
}