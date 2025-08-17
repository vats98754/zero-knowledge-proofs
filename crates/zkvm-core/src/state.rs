use crate::{VmError, Result};
use serde::{Deserialize, Serialize};

pub type Register = u8;

/// VM state containing registers and program counter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    pub registers: [u64; 8], // R0-R7 general purpose registers
    pub pc: u64,             // program counter
}

impl VmState {
    pub fn new() -> Self {
        Self {
            registers: [0; 8],
            pc: 0,
        }
    }

    pub fn reset(&mut self) {
        self.registers = [0; 8];
        self.pc = 0;
    }

    pub fn get_register(&self, reg: Register) -> Result<u64> {
        if reg >= 8 {
            return Err(VmError::InvalidRegister(reg));
        }
        Ok(self.registers[reg as usize])
    }

    pub fn set_register(&mut self, reg: Register, value: u64) -> Result<()> {
        if reg >= 8 {
            return Err(VmError::InvalidRegister(reg));
        }
        self.registers[reg as usize] = value;
        Ok(())
    }

    pub fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }
}

impl Default for VmState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_state_creation() {
        let state = VmState::new();
        assert_eq!(state.pc, 0);
        assert_eq!(state.registers, [0; 8]);
    }

    #[test]
    fn test_register_operations() {
        let mut state = VmState::new();
        
        assert!(state.set_register(0, 42).is_ok());
        assert_eq!(state.get_register(0).unwrap(), 42);
        
        assert!(state.set_register(7, 100).is_ok());
        assert_eq!(state.get_register(7).unwrap(), 100);
        
        // Test invalid register
        assert!(state.set_register(8, 50).is_err());
        assert!(state.get_register(8).is_err());
    }

    #[test]
    fn test_state_reset() {
        let mut state = VmState::new();
        state.set_register(0, 42).unwrap();
        state.set_pc(10);
        
        state.reset();
        assert_eq!(state.pc, 0);
        assert_eq!(state.get_register(0).unwrap(), 0);
    }
}