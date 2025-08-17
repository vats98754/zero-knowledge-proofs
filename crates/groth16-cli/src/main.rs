//! CLI main entry point for Groth16 operations.

use clap::{Parser, Subcommand};
use groth16_cli::{generate_crs, generate_proof, verify_proof};

#[derive(Parser)]
#[command(name = "groth16-cli")]
#[command(about = "A CLI for Groth16 zk-SNARK operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a trusted setup / CRS
    GenerateCrs {
        /// Number of constraints in the circuit
        #[arg(short, long)]
        num_constraints: usize,
        
        /// Output file prefix for the CRS
        #[arg(short, long)]
        output: String,
    },
    /// Generate a proof
    Prove {
        /// CRS file prefix (will look for {crs}_pk.json)
        #[arg(short, long)]
        crs: String,
        
        /// Circuit file
        #[arg(short = 'i', long)]
        circuit: String,
        
        /// Witness file
        #[arg(short, long)]
        witness: String,
        
        /// Output proof file
        #[arg(short, long)]
        output: String,
    },
    /// Verify a proof
    Verify {
        /// Verification key file
        #[arg(short, long)]
        vk: String,
        
        /// Public inputs file
        #[arg(short, long)]
        public_inputs: String,
        
        /// Proof file
        #[arg(short, long)]
        proof: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::GenerateCrs { num_constraints, output } => {
            generate_crs(num_constraints, &output)?;
        }
        Commands::Prove { crs, circuit, witness, output } => {
            generate_proof(&crs, &circuit, &witness, &output)?;
        }
        Commands::Verify { vk, public_inputs, proof } => {
            verify_proof(&vk, &public_inputs, &proof)?;
        }
    }
    
    Ok(())
}