//! CLI tool for proving that a value is in a specified range

use clap::Parser;
use range::{RangeProver, RangeProof};
use bulletproofs_core::{GeneratorSet, Scalar};
use rand::thread_rng;
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "prove-range")]
#[command(about = "Generate a range proof for a value")]
struct Args {
    /// The value to prove is in range
    #[arg(long)]
    value: u64,
    
    /// Number of bits for the range [0, 2^bits)
    #[arg(short, long)]
    bits: usize,
    
    /// Output file for the proof (default: stdout)
    #[arg(short, long)]
    output: Option<String>,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.verbose {
        eprintln!("Generating range proof for value {} with {} bits", args.value, args.bits);
    }
    
    // Validate inputs
    if args.bits == 0 || args.bits > 64 {
        eprintln!("Error: bit length must be between 1 and 64");
        std::process::exit(1);
    }
    
    let max_value = (1u64 << args.bits) - 1;
    if args.value > max_value {
        eprintln!("Error: value {} exceeds maximum {} for {} bits", args.value, max_value, args.bits);
        std::process::exit(1);
    }
    
    let mut rng = thread_rng();
    
    // Create prover  
    let prover = RangeProver::new(&mut rng, args.bits * 2); // Support enough generators
    
    if args.verbose {
        eprintln!("Generating proof...");
    }
    
    // Generate proof
    let proof = prover.prove_range(args.value, args.bits, None, &mut rng)
        .map_err(|e| format!("Failed to generate proof: {}", e))?;
    
    if args.verbose {
        eprintln!("Proof generated successfully");
        eprintln!("Proof size: {} bytes", proof.to_bytes().len());
    }
    
    // Serialize proof
    let proof_bytes = proof.to_bytes();
    let proof_hex = hex::encode(proof_bytes);
    
    // Output proof
    match args.output {
        Some(filename) => {
            std::fs::write(&filename, proof_hex)?;
            if args.verbose {
                eprintln!("Proof written to {}", filename);
            }
        }
        None => {
            println!("{}", proof_hex);
        }
    }
    
    Ok(())
}