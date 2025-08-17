//! Marlin setup CLI tool
//!
//! This module implements the `marlin-setup` command for generating
//! universal trusted setup and circuit-specific preprocessing keys.

use crate::{Result, CliError, common::*};
use zkp_commitments::KzgCommitmentEngine;
use zkp_marlin::{MarlinSetup, MarlinSRS, MarlinPreprocessingKey, R1CS};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use ark_std::test_rng;

/// Setup command configuration
#[derive(Debug, Args)]
pub struct SetupArgs {
    #[command(subcommand)]
    pub command: SetupCommand,
}

/// Setup subcommands
#[derive(Debug, Subcommand)]
pub enum SetupCommand {
    /// Generate universal SRS for Marlin
    UniversalSrs {
        /// Path to save the SRS file
        #[arg(short, long, default_value = "marlin.srs")]
        output: PathBuf,
        
        /// Maximum degree supported by the SRS
        #[arg(short, long, default_value = "1024")]
        max_degree: usize,
        
        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,
        
        /// Force overwrite existing files
        #[arg(short, long)]
        force: bool,
    },
    
    /// Generate circuit-specific preprocessing key
    Preprocess {
        /// Path to the SRS file
        #[arg(short, long, default_value = "marlin.srs")]
        srs: PathBuf,
        
        /// Path to the R1CS circuit file
        #[arg(short, long)]
        circuit: Option<PathBuf>,
        
        /// Path to save the preprocessing key
        #[arg(short, long, default_value = "marlin.pk")]
        output: PathBuf,
        
        /// Use built-in example circuit
        #[arg(long)]
        example: bool,
        
        /// Configuration file path
        #[arg(short = 'f', long)]
        config: Option<PathBuf>,
        
        /// Force overwrite existing files
        #[arg(long)]
        force: bool,
    },
    
    /// Verify SRS integrity
    Verify {
        /// Path to the SRS file to verify
        #[arg(short, long, default_value = "marlin.srs")]
        srs: PathBuf,
    },
    
    /// Show SRS information
    Info {
        /// Path to the SRS file
        #[arg(short, long, default_value = "marlin.srs")]
        srs: PathBuf,
    },
}

/// Universal SRS generation
pub fn generate_universal_srs(
    output: &PathBuf,
    max_degree: usize,
    config_path: Option<&PathBuf>,
    force: bool,
) -> Result<()> {
    // Check if output file exists and force flag
    if FileOps::file_exists(output) && !force {
        return Err(CliError::IoError(
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("SRS file already exists: {}. Use --force to overwrite.", output.display())
            )
        ));
    }

    // Load configuration
    let config = ConfigUtils::load_or_default(config_path.map(|p| p.as_path()))?;
    ConfigUtils::validate_config(&config)?;

    println!("Generating universal SRS...");
    println!("  Max degree: {}", max_degree);
    println!("  Security: {} bits", config.security_bits);

    // Estimate required SRS size
    let estimated_size = CommitmentUtils::estimate_srs_size(&config);
    let srs_size = std::cmp::max(max_degree, estimated_size);

    println!("  SRS size: {}", srs_size);

    // Generate SRS with progress tracking
    let mut progress = ProgressIndicator::new("Generating commitment parameters", 3);
    
    progress.update(1);
    let mut rng = test_rng();
    
    progress.update(2);
    let commitment_params = KzgCommitmentEngine::setup(&mut rng, srs_size)
        .map_err(CliError::MarlinError)?;

    // Validate parameters
    CommitmentUtils::validate_parameters(&commitment_params)?;

    // Create SRS
    let srs = MarlinSRS::new(commitment_params, srs_size, config.security_bits);

    progress.update(3);
    progress.finish();

    // Export SRS
    println!("Saving SRS to: {}", output.display());
    let srs_data = srs.export()?;
    FileOps::write_binary(&srs_data, output)?;

    // Save configuration alongside SRS
    let config_path = output.with_extension("config.json");
    ConfigUtils::save_config(&config, &config_path)?;

    println!("✓ Universal SRS generation complete!");
    println!("  SRS file: {}", output.display());
    println!("  Config file: {}", config_path.display());
    println!("  Size: {} bytes", srs_data.len());

    Ok(())
}

/// Circuit preprocessing
pub fn preprocess_circuit(
    srs_path: &PathBuf,
    circuit_path: Option<&PathBuf>,
    output: &PathBuf,
    use_example: bool,
    config_path: Option<&PathBuf>,
    force: bool,
) -> Result<()> {
    // Check if output file exists
    if FileOps::file_exists(output) && !force {
        return Err(CliError::IoError(
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Preprocessing key already exists: {}. Use --force to overwrite.", output.display())
            )
        ));
    }

    // Validate required files
    ArgUtils::validate_input_files(&[srs_path.as_path()])?;

    // Load SRS
    println!("Loading SRS from: {}", srs_path.display());
    let srs_data = FileOps::read_binary(srs_path)?;
    let srs = MarlinSRS::<KzgCommitmentEngine>::import(&srs_data)?;

    // Load or create R1CS circuit
    let r1cs = if use_example {
        println!("Using built-in example circuit (x² = y)");
        R1CSUtils::create_example_r1cs()
    } else if let Some(circuit_path) = circuit_path {
        println!("Loading circuit from: {}", circuit_path.display());
        ArgUtils::validate_input_files(&[circuit_path.as_path()])?;
        FileOps::read_json(circuit_path)?
    } else {
        return Err(CliError::InvalidArguments);
    };

    // Load configuration
    let config = ConfigUtils::load_or_default(config_path.map(|p| p.as_path()))?;
    ConfigUtils::validate_config(&config)?;

    // Validate circuit against configuration
    if r1cs.num_constraints > config.max_constraints {
        return Err(CliError::InvalidArguments);
    }

    if r1cs.num_public_inputs > config.num_public_inputs {
        return Err(CliError::InvalidArguments);
    }

    println!("Circuit information:");
    println!("  Constraints: {}", r1cs.num_constraints);
    println!("  Public inputs: {}", r1cs.num_public_inputs);
    println!("  Witness variables: {}", r1cs.num_witness_variables);

    // Generate preprocessing key
    let mut progress = ProgressIndicator::new("Generating preprocessing key", 3);

    progress.update(1);
    let mut rng = test_rng();
    let setup = MarlinSetup::new();

    progress.update(2);
    let preprocessing_key = setup.preprocess(&srs, &r1cs, &mut rng)?;

    progress.update(3);
    progress.finish();

    // Export preprocessing key
    println!("Saving preprocessing key to: {}", output.display());
    let pk_data = preprocessing_key.export()?;
    FileOps::write_binary(&pk_data, output)?;

    // Save circuit alongside preprocessing key
    let circuit_output = output.with_extension("circuit.json");
    FileOps::write_json(&r1cs, &circuit_output)?;

    println!("✓ Circuit preprocessing complete!");
    println!("  Preprocessing key: {}", output.display());
    println!("  Circuit file: {}", circuit_output.display());
    println!("  Key size: {} bytes", pk_data.len());

    Ok(())
}

/// Verify SRS integrity
pub fn verify_srs(srs_path: &PathBuf) -> Result<()> {
    ArgUtils::validate_input_files(&[srs_path.as_path()])?;

    println!("Verifying SRS: {}", srs_path.display());

    // Load SRS
    let srs_data = FileOps::read_binary(srs_path)?;
    let srs = MarlinSRS::<KzgCommitmentEngine>::import(&srs_data)?;

    // Perform basic validation
    let mut progress = ProgressIndicator::new("Verifying SRS integrity", 3);

    progress.update(1);
    // Basic structure validation
    if srs.max_degree == 0 {
        return Err(CliError::InvalidArguments);
    }

    progress.update(2);
    // Validate commitment parameters
    CommitmentUtils::validate_parameters(&srs.commitment_params)?;

    progress.update(3);
    progress.finish();

    println!("✓ SRS verification complete!");
    println!("  Max degree: {}", srs.max_degree);
    println!("  Security bits: {}", srs.security_bits);

    Ok(())
}

/// Show SRS information
pub fn show_srs_info(srs_path: &PathBuf) -> Result<()> {
    ArgUtils::validate_input_files(&[srs_path.as_path()])?;

    println!("SRS Information");
    println!("===============");

    // Load SRS
    let srs_data = FileOps::read_binary(srs_path)?;
    let srs = MarlinSRS::<KzgCommitmentEngine>::import(&srs_data)?;

    // Display information
    println!("File: {}", srs_path.display());
    println!("Size: {} bytes", srs_data.len());
    println!("Max degree: {}", srs.max_degree);
    println!("Security bits: {}", srs.security_bits);

    // Load config if available
    let config_path = srs_path.with_extension("config.json");
    if FileOps::file_exists(&config_path) {
        println!("\nConfiguration:");
        let config: MarlinConfig = FileOps::read_json(&config_path)?;
        println!("  Max constraints: {}", config.max_constraints);
        println!("  Max degree: {}", config.max_degree);
        println!("  Public inputs: {}", config.num_public_inputs);
    }

    Ok(())
}

/// Main setup command handler
pub fn handle_setup_command(args: SetupArgs) -> Result<()> {
    match args.command {
        SetupCommand::UniversalSrs { output, max_degree, config, force } => {
            generate_universal_srs(&output, max_degree, config.as_ref(), force)
        }
        
        SetupCommand::Preprocess { srs, circuit, output, example, config, force } => {
            preprocess_circuit(&srs, circuit.as_ref(), &output, example, config.as_ref(), force)
        }
        
        SetupCommand::Verify { srs } => {
            verify_srs(&srs)
        }
        
        SetupCommand::Info { srs } => {
            show_srs_info(&srs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_universal_srs() {
        let dir = tempdir().unwrap();
        let srs_path = dir.path().join("test.srs");
        
        // Test with small parameters
        let result = generate_universal_srs(&srs_path, 16, None, false);
        assert!(result.is_ok());
        assert!(FileOps::file_exists(&srs_path));
        
        // Test that it doesn't overwrite without force
        let result2 = generate_universal_srs(&srs_path, 16, None, false);
        assert!(result2.is_err());
        
        // Test with force
        let result3 = generate_universal_srs(&srs_path, 16, None, true);
        assert!(result3.is_ok());
    }

    #[test]
    fn test_preprocess_example_circuit() {
        let dir = tempdir().unwrap();
        let srs_path = dir.path().join("test.srs");
        let pk_path = dir.path().join("test.pk");
        
        // First generate SRS
        generate_universal_srs(&srs_path, 16, None, false).unwrap();
        
        // Then preprocess example circuit
        let result = preprocess_circuit(&srs_path, None, &pk_path, true, None, false);
        assert!(result.is_ok());
        assert!(FileOps::file_exists(&pk_path));
    }

    #[test]
    fn test_verify_and_info() {
        let dir = tempdir().unwrap();
        let srs_path = dir.path().join("test.srs");
        
        // Generate SRS first
        generate_universal_srs(&srs_path, 16, None, false).unwrap();
        
        // Test verification
        let verify_result = verify_srs(&srs_path);
        assert!(verify_result.is_ok());
        
        // Test info display
        let info_result = show_srs_info(&srs_path);
        assert!(info_result.is_ok());
    }
}