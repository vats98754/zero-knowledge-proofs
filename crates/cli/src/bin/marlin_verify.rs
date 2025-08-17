//! Marlin Verify CLI Tool
//!
//! Command-line interface for verifying zero-knowledge proofs.

use clap::Parser;
use zkp_cli::{verify::*, CliError, Result};

#[derive(Parser)]
#[command(name = "marlin-verify")]
#[command(about = "Marlin zero-knowledge proof verification tool")]
#[command(version)]
struct Cli {
    #[command(flatten)]
    verify_args: VerifyArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if let Err(e) = handle_verify_command(cli.verify_args) {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}