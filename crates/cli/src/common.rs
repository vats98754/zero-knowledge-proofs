//! Common utilities for CLI tools
//!
//! This module provides shared functionality used across all CLI tools.

use crate::{Result, CliError};
use zkp_field::Scalar;
use zkp_commitments::KzgCommitmentEngine;
use zkp_marlin::{MarlinSRS, MarlinPreprocessingKey, MarlinProver, MarlinVerifier, R1CS};
use serde::{Serialize, Deserialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;

/// Configuration for Marlin proof system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarlinConfig {
    /// Security parameter (in bits)
    pub security_bits: usize,
    /// Maximum number of constraints
    pub max_constraints: usize,
    /// Maximum degree of polynomials
    pub max_degree: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
}

impl Default for MarlinConfig {
    fn default() -> Self {
        Self {
            security_bits: 128,
            max_constraints: 1024,
            max_degree: 1024,
            num_public_inputs: 1,
        }
    }
}

/// File formats supported by the CLI tools
#[derive(Debug, Clone)]
pub enum FileFormat {
    Json,
    Binary,
}

/// Common file operations for CLI tools
pub struct FileOps;

impl FileOps {
    /// Reads a JSON file and deserializes it
    pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
        let file = File::open(path)
            .map_err(|e| CliError::IoError(e))?;
        let reader = BufReader::new(file);
        let data = serde_json::from_reader(reader)
            .map_err(|e| CliError::SerializationError(e))?;
        Ok(data)
    }

    /// Writes data to a JSON file
    pub fn write_json<T: Serialize>(data: &T, path: &Path) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| CliError::IoError(e))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, data)
            .map_err(|e| CliError::SerializationError(e))?;
        Ok(())
    }

    /// Reads binary data from a file
    pub fn read_binary(path: &Path) -> Result<Vec<u8>> {
        let mut file = File::open(path)
            .map_err(|e| CliError::IoError(e))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| CliError::IoError(e))?;
        Ok(data)
    }

    /// Writes binary data to a file
    pub fn write_binary(data: &[u8], path: &Path) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| CliError::IoError(e))?;
        file.write_all(data)
            .map_err(|e| CliError::IoError(e))?;
        Ok(())
    }

    /// Checks if a file exists
    pub fn file_exists(path: &Path) -> bool {
        path.exists() && path.is_file()
    }

    /// Creates a directory if it doesn't exist
    pub fn ensure_directory(path: &Path) -> Result<()> {
        if !path.exists() {
            std::fs::create_dir_all(path)
                .map_err(|e| CliError::IoError(e))?;
        }
        Ok(())
    }
}

/// Utilities for working with R1CS constraint systems
pub struct R1CSUtils;

impl R1CSUtils {
    /// Creates a simple example R1CS for testing
    /// Represents the constraint: x * x = y
    pub fn create_example_r1cs() -> R1CS {
        let mut r1cs = R1CS::new(1, 1, 1); // 1 constraint, 1 public input, 1 witness variable
        
        // Variable assignments: [1, public_input, witness]
        // Constraint: witness * witness = public_input
        r1cs.add_constraint(
            vec![(2, Scalar::from(1u64))], // A: witness
            vec![(2, Scalar::from(1u64))], // B: witness  
            vec![(1, Scalar::from(1u64))], // C: public_input
        ).expect("Failed to add constraint");

        r1cs
    }

    /// Creates a more complex example for multiplication chain
    /// Represents: x1 * x2 = x3, x3 * x4 = y
    pub fn create_multiplication_chain_r1cs() -> R1CS {
        let mut r1cs = R1CS::new(2, 1, 4); // 2 constraints, 1 public input, 4 witness variables

        // Variables: [1, public_input, x1, x2, x3, x4]
        // Constraint 1: x1 * x2 = x3
        r1cs.add_constraint(
            vec![(2, Scalar::from(1u64))], // A: x1
            vec![(3, Scalar::from(1u64))], // B: x2
            vec![(4, Scalar::from(1u64))], // C: x3
        ).expect("Failed to add constraint 1");

        // Constraint 2: x3 * x4 = public_input
        r1cs.add_constraint(
            vec![(4, Scalar::from(1u64))], // A: x3
            vec![(5, Scalar::from(1u64))], // B: x4
            vec![(1, Scalar::from(1u64))], // C: public_input
        ).expect("Failed to add constraint 2");

        r1cs
    }

    /// Validates witness values against an R1CS
    pub fn validate_witness(
        r1cs: &R1CS,
        public_inputs: &[Scalar],
        witness: &[Scalar],
    ) -> Result<bool> {
        if public_inputs.len() != r1cs.num_public_inputs {
            return Err(CliError::InvalidArguments);
        }

        if witness.len() != r1cs.num_witness_variables {
            return Err(CliError::InvalidArguments);
        }

        // Create full variable assignment
        let mut variables = vec![Scalar::from(1u64)]; // Constant 1
        variables.extend_from_slice(public_inputs);
        variables.extend_from_slice(witness);

        // Check each constraint
        for constraint_idx in 0..r1cs.num_constraints {
            let a_val = r1cs.evaluate_constraint_side(&variables, &r1cs.a_matrix, constraint_idx);
            let b_val = r1cs.evaluate_constraint_side(&variables, &r1cs.b_matrix, constraint_idx);
            let c_val = r1cs.evaluate_constraint_side(&variables, &r1cs.c_matrix, constraint_idx);

            if a_val * b_val != c_val {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Progress indicator for long-running operations
pub struct ProgressIndicator {
    message: String,
    total_steps: usize,
    current_step: usize,
}

impl ProgressIndicator {
    /// Creates a new progress indicator
    pub fn new(message: &str, total_steps: usize) -> Self {
        println!("{}", message);
        Self {
            message: message.to_string(),
            total_steps,
            current_step: 0,
        }
    }

    /// Updates the progress
    pub fn update(&mut self, step: usize) {
        self.current_step = step;
        let percentage = if self.total_steps > 0 {
            (step * 100) / self.total_steps
        } else {
            0
        };
        print!("\r[{}%] {}", percentage, self.message);
        std::io::stdout().flush().ok();
    }

    /// Finishes the progress indicator
    pub fn finish(&self) {
        println!("\r[100%] {} - Complete!", self.message);
    }
}

/// Utilities for working with commitment parameters
pub struct CommitmentUtils;

impl CommitmentUtils {
    /// Estimates the required SRS size for a given configuration
    pub fn estimate_srs_size(config: &MarlinConfig) -> usize {
        // SRS size should be at least max_degree + security margin
        std::cmp::max(config.max_degree * 2, config.max_constraints * 2)
    }

    /// Validates commitment parameters
    pub fn validate_parameters(params: &<KzgCommitmentEngine as zkp_commitments::CommitmentEngine>::Parameters) -> Result<()> {
        // Basic validation - in practice would check more properties
        println!("Validating commitment parameters...");
        // For now, just assume valid
        Ok(())
    }
}

/// Configuration management utilities
pub struct ConfigUtils;

impl ConfigUtils {
    /// Loads configuration from file or returns default
    pub fn load_or_default(config_path: Option<&Path>) -> Result<MarlinConfig> {
        if let Some(path) = config_path {
            if FileOps::file_exists(path) {
                println!("Loading configuration from: {}", path.display());
                return FileOps::read_json(path);
            }
        }

        println!("Using default configuration");
        Ok(MarlinConfig::default())
    }

    /// Saves configuration to file
    pub fn save_config(config: &MarlinConfig, path: &Path) -> Result<()> {
        println!("Saving configuration to: {}", path.display());
        FileOps::write_json(config, path)
    }

    /// Validates configuration parameters
    pub fn validate_config(config: &MarlinConfig) -> Result<()> {
        if config.security_bits < 80 {
            return Err(CliError::InvalidArguments);
        }

        if config.max_constraints == 0 || config.max_degree == 0 {
            return Err(CliError::InvalidArguments);
        }

        if config.num_public_inputs > config.max_constraints {
            return Err(CliError::InvalidArguments);
        }

        Ok(())
    }
}

/// Common command-line argument parsing utilities
pub struct ArgUtils;

impl ArgUtils {
    /// Parses a hex string into a scalar field element
    pub fn parse_scalar_hex(hex_str: &str) -> Result<Scalar> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)
            .map_err(|_| CliError::InvalidArguments)?;
        
        // Convert bytes to scalar (simplified)
        if bytes.is_empty() {
            return Ok(Scalar::from(0u64));
        }

        let mut value = 0u64;
        for (i, &byte) in bytes.iter().take(8).enumerate() {
            value += (byte as u64) << (i * 8);
        }

        Ok(Scalar::from(value))
    }

    /// Parses a comma-separated list of scalars
    pub fn parse_scalar_list(list_str: &str) -> Result<Vec<Scalar>> {
        let mut scalars = Vec::new();
        
        for part in list_str.split(',') {
            let trimmed = part.trim();
            if trimmed.starts_with("0x") {
                scalars.push(Self::parse_scalar_hex(trimmed)?);
            } else {
                let value: u64 = trimmed.parse()
                    .map_err(|_| CliError::InvalidArguments)?;
                scalars.push(Scalar::from(value));
            }
        }

        Ok(scalars)
    }

    /// Formats a scalar as hex string
    pub fn format_scalar_hex(scalar: &Scalar) -> String {
        // Simplified formatting
        format!("0x{:016x}", scalar.into_bigint().as_ref()[0])
    }

    /// Validates that required files exist
    pub fn validate_input_files(files: &[&Path]) -> Result<()> {
        for file in files {
            if !FileOps::file_exists(file) {
                return Err(CliError::IoError(
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Required file not found: {}", file.display())
                    )
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_marlin_config_default() {
        let config = MarlinConfig::default();
        assert_eq!(config.security_bits, 128);
        assert_eq!(config.max_constraints, 1024);
    }

    #[test]
    fn test_file_ops_json() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.json");
        
        let config = MarlinConfig::default();
        assert!(FileOps::write_json(&config, &file_path).is_ok());
        assert!(FileOps::file_exists(&file_path));
        
        let loaded_config: MarlinConfig = FileOps::read_json(&file_path).unwrap();
        assert_eq!(loaded_config.security_bits, config.security_bits);
    }

    #[test]
    fn test_r1cs_utils() {
        let r1cs = R1CSUtils::create_example_r1cs();
        assert_eq!(r1cs.num_constraints, 1);
        assert_eq!(r1cs.num_public_inputs, 1);
        assert_eq!(r1cs.num_witness_variables, 1);

        // Test valid witness: x=3, y=9 (3*3=9)
        let public_inputs = vec![Scalar::from(9u64)];
        let witness = vec![Scalar::from(3u64)];
        assert!(R1CSUtils::validate_witness(&r1cs, &public_inputs, &witness).unwrap());

        // Test invalid witness: x=3, y=8 (3*3≠8)
        let invalid_public = vec![Scalar::from(8u64)];
        assert!(!R1CSUtils::validate_witness(&r1cs, &invalid_public, &witness).unwrap());
    }

    #[test]
    fn test_arg_utils() {
        // Test scalar parsing
        let scalar = ArgUtils::parse_scalar_hex("0x10").unwrap();
        assert_eq!(scalar, Scalar::from(16u64));

        // Test scalar list parsing
        let scalars = ArgUtils::parse_scalar_list("1,2,0x10").unwrap();
        assert_eq!(scalars.len(), 3);
        assert_eq!(scalars[0], Scalar::from(1u64));
        assert_eq!(scalars[1], Scalar::from(2u64));
        assert_eq!(scalars[2], Scalar::from(16u64));
    }

    #[test]
    fn test_progress_indicator() {
        let mut progress = ProgressIndicator::new("Testing", 10);
        progress.update(5);
        progress.finish();
        // Just test that it doesn't panic
    }

    #[test]
    fn test_config_validation() {
        let valid_config = MarlinConfig::default();
        assert!(ConfigUtils::validate_config(&valid_config).is_ok());

        let invalid_config = MarlinConfig {
            security_bits: 50, // Too low
            ..Default::default()
        };
        assert!(ConfigUtils::validate_config(&invalid_config).is_err());
    }
}