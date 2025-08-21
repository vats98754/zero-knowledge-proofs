//! Arithmetic circuit example.

use groth16_examples::run_all_examples;
use anyhow::Result;

fn main() -> Result<()> {
    println!("🚀 Groth16 Arithmetic Circuit Examples");
    println!("======================================\n");
    
    run_all_examples()?;
    
    Ok(())
}