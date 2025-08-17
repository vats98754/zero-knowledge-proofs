use compiler::compile_to_trace;

pub mod token_contract;

pub use token_contract::TokenContract;

/// Simple arithmetic example
pub fn arithmetic_example() -> anyhow::Result<()> {
    let assembly = r#"
        # Simple arithmetic: compute 10 + 20 * 5
        # R0 = 10, R1 = 20, R2 = 5
        ADD R3, R0, R1
        MUL R4, R1, R2
        ADD R5, R3, R4
        HALT
    "#;

    let trace = compile_to_trace(assembly)?;
    println!("Generated execution trace with {} steps", trace.length());
    println!("Trace width: {}", trace.width());
    
    Ok(())
}

/// Fibonacci sequence example
pub fn fibonacci_example() -> anyhow::Result<()> {
    let assembly = r#"
        # Compute 10th Fibonacci number
        # R0 = n (counter), R1 = a, R2 = b, R3 = temp
        
        # Initialize: a=0, b=1, n=10
        # (Assume registers are pre-loaded with initial values)
        
    loop:
        JZ R0, done
        ADD R3, R1, R2
        ADD R1, R2, R4
        ADD R2, R3, R4
        SUB R0, R0, R7
        JUMP loop
        
    done:
        HALT
    "#;

    let trace = compile_to_trace(assembly)?;
    println!("Fibonacci trace generated with {} steps", trace.length());
    
    Ok(())
}

/// Memory operations example
pub fn memory_example() -> anyhow::Result<()> {
    let assembly = r#"
        # Test memory load/store operations
        # Store value 42 at address 100
        # Then load it back
        
        STORE R0, R1    # Store R1 to address in R0
        LOAD R2, R0     # Load from address in R0 to R2
        HALT
    "#;

    let trace = compile_to_trace(assembly)?;
    println!("Memory operations trace generated with {} steps", trace.length());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arithmetic_example() {
        match arithmetic_example() {
            Ok(_) => (),
            Err(e) => {
                println!("Error: {:?}", e);
                panic!("arithmetic_example failed: {}", e);
            }
        }
    }

    #[test]
    fn test_fibonacci_example() {
        assert!(fibonacci_example().is_ok());
    }

    #[test]
    fn test_memory_example() {
        match memory_example() {
            Ok(_) => (),
            Err(e) => {
                println!("Error: {:?}", e);
                panic!("memory_example failed: {}", e);
            }
        }
    }
}