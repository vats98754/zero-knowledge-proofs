//! Marlin Prove CLI Tool
//!
//! Command-line interface for generating zero-knowledge proofs.

use clap::Parser;
use zkp_cli::{prove::*, CliError, Result};

#[derive(Parser)]
#[command(name = "marlin-prove")]
#[command(about = "Marlin zero-knowledge proof generation tool")]
#[command(version)]
struct Cli {
    #[command(flatten)]
    prove_args: ProveArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if let Err(e) = handle_prove_command(cli.prove_args) {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}