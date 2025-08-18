use zkvm_core::Instruction;
use crate::{CompilerError, Result};
use serde::{Deserialize, Serialize};

/// Bytecode representation of a compiled program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bytecode {
    instructions: Vec<Instruction>,
    metadata: BytecodeMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeMetadata {
    pub version: String,
    pub source_hash: Option<String>,
    pub compile_time: Option<String>,
    pub optimization_level: u8,
}

impl Bytecode {
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self {
            instructions,
            metadata: BytecodeMetadata {
                version: "0.1.0".to_string(),
                source_hash: None,
                compile_time: None,
                optimization_level: 0,
            },
        }
    }

    pub fn with_metadata(mut self, metadata: BytecodeMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn to_instructions(&self) -> Result<Vec<Instruction>> {
        Ok(self.instructions.clone())
    }

    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    pub fn metadata(&self) -> &BytecodeMetadata {
        &self.metadata
    }

    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Serialize bytecode to binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CompilerError::ParseError(format!("Serialization failed: {}", e)))
    }

    /// Deserialize bytecode from binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| CompilerError::ParseError(format!("Deserialization failed: {}", e)))
    }

    /// Apply basic optimizations to the bytecode
    pub fn optimize(&mut self) -> Result<()> {
        // Remove consecutive no-ops
        self.remove_nops();
        
        // Optimize jump chains
        self.optimize_jumps()?;
        
        // Mark as optimized
        self.metadata.optimization_level = 1;
        
        Ok(())
    }

    fn remove_nops(&mut self) {
        // In this simple VM, we don't have explicit NOPs, but we could
        // remove redundant operations like "ADD R0, R0, #0"
        // For now, this is a placeholder
    }

    fn optimize_jumps(&mut self) -> Result<()> {
        // Optimize jump chains: if instruction A jumps to B, and B jumps to C,
        // then A can jump directly to C
        // This is a placeholder for a more sophisticated optimization
        Ok(())
    }

    /// Get statistics about the bytecode
    pub fn stats(&self) -> BytecodeStats {
        let mut opcode_counts = std::collections::HashMap::new();
        let mut register_usage = [0u32; 8];

        for instruction in &self.instructions {
            *opcode_counts.entry(instruction.opcode).or_insert(0) += 1;
            
            // Track register usage
            if instruction.dst < 8 {
                register_usage[instruction.dst as usize] += 1;
            }
            if instruction.src1 < 8 {
                register_usage[instruction.src1 as usize] += 1;
            }
            if instruction.src2 < 8 {
                register_usage[instruction.src2 as usize] += 1;
            }
        }

        BytecodeStats {
            instruction_count: self.instructions.len(),
            opcode_distribution: opcode_counts,
            register_usage,
            estimated_cycles: self.estimate_cycles(),
        }
    }

    fn estimate_cycles(&self) -> u64 {
        // Simple cycle estimation based on instruction types
        self.instructions.iter().map(|inst| {
            match inst.opcode {
                zkvm_core::Opcode::Add | zkvm_core::Opcode::Sub => 1,
                zkvm_core::Opcode::Mul => 2,
                zkvm_core::Opcode::Div => 4,
                zkvm_core::Opcode::Load | zkvm_core::Opcode::Store => 2,
                zkvm_core::Opcode::Jump | zkvm_core::Opcode::JumpIfZero => 1,
                zkvm_core::Opcode::Syscall => 10, // Assuming syscalls are expensive
                zkvm_core::Opcode::Halt => 1,
            }
        }).sum()
    }
}

#[derive(Debug, Clone)]
pub struct BytecodeStats {
    pub instruction_count: usize,
    pub opcode_distribution: std::collections::HashMap<zkvm_core::Opcode, u32>,
    pub register_usage: [u32; 8],
    pub estimated_cycles: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkvm_core::Instruction;

    #[test]
    fn test_bytecode_creation() {
        let instructions = vec![
            Instruction::add(0, 1, 2),
            Instruction::halt(),
        ];

        let bytecode = Bytecode::new(instructions);
        assert_eq!(bytecode.len(), 2);
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_bytecode_serialization() {
        let instructions = vec![
            Instruction::add(0, 1, 2),
            Instruction::halt(),
        ];

        let bytecode = Bytecode::new(instructions);
        let bytes = bytecode.to_bytes().unwrap();
        let restored = Bytecode::from_bytes(&bytes).unwrap();

        assert_eq!(bytecode.len(), restored.len());
    }

    #[test]
    fn test_bytecode_stats() {
        let instructions = vec![
            Instruction::add(0, 1, 2),
            Instruction::sub(1, 0, 2),
            Instruction::mul(2, 0, 1),
            Instruction::halt(),
        ];

        let bytecode = Bytecode::new(instructions);
        let stats = bytecode.stats();

        assert_eq!(stats.instruction_count, 4);
        assert!(stats.estimated_cycles > 0);
        
        // R0, R1, R2 should be used
        assert!(stats.register_usage[0] > 0);
        assert!(stats.register_usage[1] > 0);
        assert!(stats.register_usage[2] > 0);
    }

    #[test]
    fn test_optimization() {
        let instructions = vec![
            Instruction::add(0, 1, 2),
            Instruction::halt(),
        ];

        let mut bytecode = Bytecode::new(instructions);
        assert_eq!(bytecode.metadata().optimization_level, 0);

        bytecode.optimize().unwrap();
        assert_eq!(bytecode.metadata().optimization_level, 1);
    }
}