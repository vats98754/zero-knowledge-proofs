//! CLI tool for verifying range proofs

use clap::Parser;
use range::{RangeVerifier, RangeProof};
use bulletproofs_core::GeneratorSet;
use rand::thread_rng;
use std::io::{self, Read};

#[derive(Parser)]
#[command(name = "verify-range")]
#[command(about = "Verify a range proof")]
struct Args {
    /// Number of bits for the range [0, 2^bits)
    #[arg(short, long)]
    bits: usize,
    
    /// Input file containing the proof (default: stdin)
    #[arg(short, long)]
    input: Option<String>,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if args.verbose {
        eprintln!("Verifying range proof for {} bits", args.bits);
    }
    
    // Validate inputs
    if args.bits == 0 || args.bits > 64 {
        eprintln!("Error: bit length must be between 1 and 64");
        std::process::exit(1);
    }
    
    // Read proof
    let proof_hex = match args.input {
        Some(filename) => {
            if args.verbose {
                eprintln!("Reading proof from {}", filename);
            }
            std::fs::read_to_string(&filename)?
        }
        None => {
            if args.verbose {
                eprintln!("Reading proof from stdin");
            }
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            input
        }
    };
    
    // Parse proof
    let proof_hex = proof_hex.trim();
    let proof_bytes = hex::decode(proof_hex)
        .map_err(|e| format!("Failed to decode hex proof: {}", e))?;
    
    let proof = RangeProof::from_bytes(&proof_bytes)
        .map_err(|e| format!("Failed to parse proof: {}", e))?;
    
    if args.verbose {
        eprintln!("Proof parsed successfully");
        eprintln!("Proof size: {} bytes", proof_bytes.len());
    }
    
    // Create verifier (note: in production, generators should be deterministic/shared)
    let mut rng = thread_rng();
    let verifier = RangeVerifier::new(&mut rng, args.bits * 2); // Support enough generators
    
    if args.verbose {
        eprintln!("Verifying proof...");
    }
    
    // Verify proof
    match verifier.verify_range(&proof, args.bits) {
        Ok(()) => {
            if args.verbose {
                eprintln!("✓ Proof verification successful");
            } else {
                println!("VALID");
            }
        }
        Err(e) => {
            if args.verbose {
                eprintln!("✗ Proof verification failed: {}", e);
            } else {
                println!("INVALID");
            }
            std::process::exit(1);
        }
    }
    
    Ok(())
}