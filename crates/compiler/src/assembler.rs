use crate::{CompilerError, Result, Bytecode};
use zkvm_core::{Instruction, Opcode};
use std::collections::HashMap;

/// Assembly language parser and assembler
pub struct Assembler {
    labels: HashMap<String, usize>,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            labels: HashMap::new(),
        }
    }

    /// Assemble assembly code into bytecode
    pub fn assemble(&mut self, assembly: &str) -> Result<Bytecode> {
        let lines = self.preprocess(assembly);
        let instructions = self.parse_instructions(&lines)?;
        Ok(Bytecode::new(instructions))
    }

    fn preprocess(&mut self, assembly: &str) -> Vec<String> {
        let mut lines = Vec::new();
        let mut address = 0;

        for line in assembly.lines() {
            let line = line.trim();
            
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Handle labels
            if line.ends_with(':') {
                let label = line.trim_end_matches(':').to_string();
                self.labels.insert(label, address);
                continue;
            }

            lines.push(line.to_string());
            address += 1;
        }

        lines
    }

    fn parse_instructions(&self, lines: &[String]) -> Result<Vec<Instruction>> {
        let mut instructions = Vec::new();

        for line in lines {
            let instruction = self.parse_instruction(line)?;
            instructions.push(instruction);
        }

        Ok(instructions)
    }

    fn parse_instruction(&self, line: &str) -> Result<Instruction> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Err(CompilerError::ParseError("Empty instruction".to_string()));
        }

        let opcode_str = parts[0].to_uppercase();
        let opcode = self.parse_opcode(&opcode_str)?;

        match opcode {
            Opcode::Add | Opcode::Sub | Opcode::Mul | Opcode::Div => {
                // Format: ADD R0, R1, R2
                if parts.len() != 4 {
                    return Err(CompilerError::ParseError(format!("Invalid {} instruction format", opcode_str)));
                }
                let dst = self.parse_register(parts[1].trim_end_matches(','))?;
                let src1 = self.parse_register(parts[2].trim_end_matches(','))?;
                let src2 = self.parse_register(parts[3])?;
                Ok(Instruction::new(opcode, dst, src1, src2, 0))
            }
            Opcode::Load => {
                // Format: LOAD R0, R1 (load from address in R1 to R0)
                if parts.len() != 3 {
                    return Err(CompilerError::ParseError("Invalid LOAD instruction format".to_string()));
                }
                let dst = self.parse_register(parts[1].trim_end_matches(','))?;
                let addr_reg = self.parse_register(parts[2])?;
                Ok(Instruction::load(dst, addr_reg))
            }
            Opcode::Store => {
                // Format: STORE R0, R1 (store R1 to address in R0)
                if parts.len() != 3 {
                    return Err(CompilerError::ParseError("Invalid STORE instruction format".to_string()));
                }
                let addr_reg = self.parse_register(parts[1].trim_end_matches(','))?;
                let value_reg = self.parse_register(parts[2])?;
                Ok(Instruction::store(addr_reg, value_reg))
            }
            Opcode::Jump => {
                // Format: JUMP label or JUMP #immediate
                if parts.len() != 2 {
                    return Err(CompilerError::ParseError("Invalid JUMP instruction format".to_string()));
                }
                let target = self.parse_target(parts[1])?;
                Ok(Instruction::jump(target))
            }
            Opcode::JumpIfZero => {
                // Format: JZ R0, label
                if parts.len() != 3 {
                    return Err(CompilerError::ParseError("Invalid JZ instruction format".to_string()));
                }
                let reg = self.parse_register(parts[1].trim_end_matches(','))?;
                let target = self.parse_target(parts[2])?;
                Ok(Instruction::jump_if_zero(reg, target))
            }
            Opcode::Syscall => {
                Ok(Instruction::syscall())
            }
            Opcode::Halt => {
                Ok(Instruction::halt())
            }
        }
    }

    fn parse_opcode(&self, opcode_str: &str) -> Result<Opcode> {
        match opcode_str {
            "ADD" => Ok(Opcode::Add),
            "SUB" => Ok(Opcode::Sub),
            "MUL" => Ok(Opcode::Mul),
            "DIV" => Ok(Opcode::Div),
            "LOAD" => Ok(Opcode::Load),
            "STORE" => Ok(Opcode::Store),
            "JUMP" | "JMP" => Ok(Opcode::Jump),
            "JZ" | "JUMPIFZERO" => Ok(Opcode::JumpIfZero),
            "SYSCALL" => Ok(Opcode::Syscall),
            "HALT" => Ok(Opcode::Halt),
            _ => Err(CompilerError::UnknownInstruction(opcode_str.to_string())),
        }
    }

    fn parse_register(&self, reg_str: &str) -> Result<u8> {
        if !reg_str.starts_with('R') {
            return Err(CompilerError::InvalidRegister(reg_str.to_string()));
        }

        let num_str = &reg_str[1..];
        let reg_num: u8 = num_str.parse()
            .map_err(|_| CompilerError::InvalidRegister(reg_str.to_string()))?;

        if reg_num >= 8 {
            return Err(CompilerError::InvalidRegister(reg_str.to_string()));
        }

        Ok(reg_num)
    }

    fn parse_target(&self, target_str: &str) -> Result<i32> {
        if target_str.starts_with('#') {
            // Immediate value
            let num_str = &target_str[1..];
            num_str.parse()
                .map_err(|_| CompilerError::InvalidImmediate(target_str.to_string()))
        } else {
            // Label reference
            let address = self.labels.get(target_str)
                .ok_or_else(|| CompilerError::UndefinedLabel(target_str.to_string()))?;
            Ok(*address as i32)
        }
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_assembly() {
        let mut assembler = Assembler::new();
        let assembly = r#"
            ADD R0, R1, R2
            SUB R3, R0, R1
            HALT
        "#;

        let result = assembler.assemble(assembly);
        assert!(result.is_ok());

        let bytecode = result.unwrap();
        let instructions = bytecode.to_instructions().unwrap();
        assert_eq!(instructions.len(), 3);
    }

    #[test]
    fn test_labels_and_jumps() {
        let mut assembler = Assembler::new();
        let assembly = r#"
            ADD R0, R1, R2
        loop:
            SUB R0, R0, R1
            JZ R0, end
            JUMP loop
        end:
            HALT
        "#;

        let result = assembler.assemble(assembly);
        assert!(result.is_ok());
    }

    #[test]
    fn test_memory_operations() {
        let mut assembler = Assembler::new();
        let assembly = r#"
            LOAD R0, R1
            STORE R2, R3
            HALT
        "#;

        let result = assembler.assemble(assembly);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_register() {
        let mut assembler = Assembler::new();
        let assembly = "ADD R8, R1, R2"; // R8 is invalid (only R0-R7)

        let result = assembler.assemble(assembly);
        assert!(result.is_err());
    }
}