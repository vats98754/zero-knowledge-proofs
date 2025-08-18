use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Opcode {
    Add = 0,
    Sub = 1,
    Mul = 2,
    Div = 3,
    Load = 4,
    Store = 5,
    Jump = 6,
    JumpIfZero = 7,
    Syscall = 8,
    Halt = 9,
}

impl TryFrom<u8> for Opcode {
    type Error = crate::VmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Opcode::Add),
            1 => Ok(Opcode::Sub),
            2 => Ok(Opcode::Mul),
            3 => Ok(Opcode::Div),
            4 => Ok(Opcode::Load),
            5 => Ok(Opcode::Store),
            6 => Ok(Opcode::Jump),
            7 => Ok(Opcode::JumpIfZero),
            8 => Ok(Opcode::Syscall),
            9 => Ok(Opcode::Halt),
            _ => Err(crate::VmError::InvalidInstruction(format!("Unknown opcode: {}", value))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: Opcode,
    pub dst: u8,      // destination register
    pub src1: u8,     // source register 1  
    pub src2: u8,     // source register 2
    pub immediate: i32, // immediate value for jumps, constants
}

impl Instruction {
    pub fn new(opcode: Opcode, dst: u8, src1: u8, src2: u8, immediate: i32) -> Self {
        Self {
            opcode,
            dst,
            src1,
            src2,
            immediate,
        }
    }

    // Convenience constructors for common instruction patterns
    pub fn add(dst: u8, src1: u8, src2: u8) -> Self {
        Self::new(Opcode::Add, dst, src1, src2, 0)
    }

    pub fn sub(dst: u8, src1: u8, src2: u8) -> Self {
        Self::new(Opcode::Sub, dst, src1, src2, 0)
    }

    pub fn mul(dst: u8, src1: u8, src2: u8) -> Self {
        Self::new(Opcode::Mul, dst, src1, src2, 0)
    }

    pub fn div(dst: u8, src1: u8, src2: u8) -> Self {
        Self::new(Opcode::Div, dst, src1, src2, 0)
    }

    pub fn load(dst: u8, addr_reg: u8) -> Self {
        Self::new(Opcode::Load, dst, addr_reg, 0, 0)
    }

    pub fn store(addr_reg: u8, value_reg: u8) -> Self {
        Self::new(Opcode::Store, 0, addr_reg, value_reg, 0)
    }

    pub fn jump(target: i32) -> Self {
        Self::new(Opcode::Jump, 0, 0, 0, target)
    }

    pub fn jump_if_zero(reg: u8, target: i32) -> Self {
        Self::new(Opcode::JumpIfZero, 0, reg, 0, target)
    }

    pub fn syscall() -> Self {
        Self::new(Opcode::Syscall, 0, 0, 0, 0)
    }

    pub fn halt() -> Self {
        Self::new(Opcode::Halt, 0, 0, 0, 0)
    }
}