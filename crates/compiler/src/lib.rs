use zkvm_core::{ExecutionTrace, ZkVm, ConstraintSystem, ConstraintGenerator};
use thiserror::Error;

pub mod assembler;
pub mod bytecode;

pub use assembler::Assembler;
pub use bytecode::Bytecode;

#[derive(Error, Debug)]
pub enum CompilerError {
    #[error("Assembly parse error: {0}")]
    ParseError(String),
    #[error("Unknown instruction: {0}")]
    UnknownInstruction(String),
    #[error("Invalid register: {0}")]
    InvalidRegister(String),
    #[error("Invalid immediate value: {0}")]
    InvalidImmediate(String),
    #[error("Undefined label: {0}")]
    UndefinedLabel(String),
    #[error("VM execution error: {0}")]
    VmError(#[from] zkvm_core::VmError),
}

pub type Result<T> = std::result::Result<T, CompilerError>;

/// Compile assembly code to bytecode and generate execution trace
pub fn compile_to_trace(assembly: &str) -> Result<ExecutionTrace> {
    let mut assembler = Assembler::new();
    let bytecode = assembler.assemble(assembly)?;
    let program = bytecode.to_instructions()?;
    
    let mut vm = ZkVm::new(16); // 16-column trace width
    vm.load_program(program);
    vm.execute()?;
    
    Ok(vm.get_trace().clone())
}

/// Compile assembly code to bytecode
pub fn compile(assembly: &str) -> Result<Bytecode> {
    let mut assembler = Assembler::new();
    assembler.assemble(assembly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_compilation() {
        let assembly = r#"
            ADD R0, R1, R2
            HALT
        "#;
        
        let result = compile(assembly);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_to_trace() {
        let assembly = r#"
            ADD R0, R1, R2
            HALT
        "#;
        
        let result = compile_to_trace(assembly);
        assert!(result.is_ok());
        
        let trace = result.unwrap();
        assert!(trace.length() > 0);
        assert_eq!(trace.width(), 16);
    }
}