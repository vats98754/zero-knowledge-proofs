//! Marlin Setup CLI Tool
//!
//! Command-line interface for generating universal SRS and preprocessing keys.

use clap::Parser;
use zkp_cli::{setup::*, CliError, Result};

#[derive(Parser)]
#[command(name = "marlin-setup")]
#[command(about = "Marlin zero-knowledge proof setup tool")]
#[command(version)]
struct Cli {
    #[command(flatten)]
    setup_args: SetupArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if let Err(e) = handle_setup_command(cli.setup_args) {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}