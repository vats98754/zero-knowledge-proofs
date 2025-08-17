//! Marlin prove CLI tool
//!
//! This module implements the `marlin-prove` command for generating
//! zero-knowledge proofs using the Marlin protocol.

use crate::{Result, CliError, common::*};
use zkp_commitments::KzgCommitmentEngine;
use zkp_marlin::{MarlinProver, MarlinProof, MarlinPreprocessingKey, R1CS};
use zkp_field::Scalar;
use clap::{Args, Subcommand};
use std::path::PathBuf;
use ark_std::test_rng;

/// Prove command configuration
#[derive(Debug, Args)]
pub struct ProveArgs {
    #[command(subcommand)]
    pub command: ProveCommand,
}

/// Prove subcommands
#[derive(Debug, Subcommand)]
pub enum ProveCommand {
    /// Generate a single proof
    Single {
        /// Path to the preprocessing key
        #[arg(short, long, default_value = "marlin.pk")]
        key: PathBuf,
        
        /// Public inputs (comma-separated)
        #[arg(short, long)]
        public_inputs: String,
        
        /// Witness values (comma-separated)
        #[arg(short, long)]
        witness: String,
        
        /// Path to save the proof
        #[arg(short, long, default_value = "proof.json")]
        output: PathBuf,
        
        /// Use built-in example witness
        #[arg(long)]
        example: bool,
        
        /// Force overwrite existing proof
        #[arg(short, long)]
        force: bool,
    },
    
    /// Generate multiple proofs in batch
    Batch {
        /// Path to the preprocessing key
        #[arg(short, long, default_value = "marlin.pk")]
        key: PathBuf,
        
        /// Path to JSON file with batch inputs
        #[arg(short, long)]
        inputs: PathBuf,
        
        /// Output directory for proofs
        #[arg(short, long, default_value = "proofs/")]
        output_dir: PathBuf,
        
        /// Force overwrite existing proofs
        #[arg(short, long)]
        force: bool,
    },
    
    /// Verify a witness before proving
    Verify {
        /// Path to the circuit file
        #[arg(short, long)]
        circuit: PathBuf,
        
        /// Public inputs (comma-separated)
        #[arg(short, long)]
        public_inputs: String,
        
        /// Witness values (comma-separated)
        #[arg(short, long)]
        witness: String,
        
        /// Use built-in example
        #[arg(long)]
        example: bool,
    },
}

/// Batch input specification
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchInput {
    /// Public inputs for this proof
    pub public_inputs: Vec<String>,
    /// Witness values for this proof
    pub witness: Vec<String>,
    /// Optional identifier for this proof
    pub id: Option<String>,
}

/// Batch specification
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BatchSpec {
    /// List of inputs for batch proving
    pub inputs: Vec<BatchInput>,
}

/// Generate a single proof
pub fn generate_single_proof(
    key_path: &PathBuf,
    public_inputs_str: &str,
    witness_str: &str,
    output: &PathBuf,
    use_example: bool,
    force: bool,
) -> Result<()> {
    // Check if output exists
    if FileOps::file_exists(output) && !force {
        return Err(CliError::IoError(
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Proof file already exists: {}. Use --force to overwrite.", output.display())
            )
        ));
    }

    // Validate and load preprocessing key
    ArgUtils::validate_input_files(&[key_path.as_path()])?;
    
    println!("Loading preprocessing key from: {}", key_path.display());
    let pk_data = FileOps::read_binary(key_path)?;
    let preprocessing_key = MarlinPreprocessingKey::<KzgCommitmentEngine>::import(&pk_data)?;

    // Load circuit
    let circuit_path = key_path.with_extension("circuit.json");
    let r1cs: R1CS = if FileOps::file_exists(&circuit_path) {
        FileOps::read_json(&circuit_path)?
    } else {
        // Fallback to example circuit
        println!("Warning: Circuit file not found, using example circuit");
        R1CSUtils::create_example_r1cs()
    };

    // Parse inputs and witness
    let (public_inputs, witness) = if use_example {
        println!("Using built-in example (x=3, y=9 where x²=y)");
        (vec![Scalar::from(9u64)], vec![Scalar::from(3u64)])
    } else {
        let public_inputs = ArgUtils::parse_scalar_list(public_inputs_str)?;
        let witness = ArgUtils::parse_scalar_list(witness_str)?;
        (public_inputs, witness)
    };

    // Validate inputs
    if public_inputs.len() != r1cs.num_public_inputs {
        return Err(CliError::InvalidArguments);
    }

    if witness.len() != r1cs.num_witness_variables {
        return Err(CliError::InvalidArguments);
    }

    // Verify witness satisfies constraints
    println!("Validating witness...");
    let witness_valid = R1CSUtils::validate_witness(&r1cs, &public_inputs, &witness)?;
    if !witness_valid {
        return Err(CliError::InvalidArguments);
    }
    println!("✓ Witness validation passed");

    // Create prover
    let prover = MarlinProver::new(
        preprocessing_key.srs.commitment_params.clone(),
        r1cs,
        preprocessing_key.proving_key.clone(),
    );

    // Generate proof with progress tracking
    let mut progress = ProgressIndicator::new("Generating zero-knowledge proof", 4);
    
    progress.update(1);
    let mut rng = test_rng();
    
    progress.update(2);
    println!("Executing Marlin protocol...");
    let proof = prover.prove(&witness, &mut rng)?;
    
    progress.update(3);
    
    // Format proof for output
    let proof_data = ProofData {
        public_inputs: public_inputs.iter().map(ArgUtils::format_scalar_hex).collect(),
        proof: proof,
        metadata: ProofMetadata {
            circuit_constraints: r1cs.num_constraints,
            circuit_public_inputs: r1cs.num_public_inputs,
            circuit_witness_vars: r1cs.num_witness_variables,
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    };

    // Save proof
    FileOps::write_json(&proof_data, output)?;
    
    progress.update(4);
    progress.finish();

    println!("✓ Proof generation complete!");
    println!("  Proof file: {}", output.display());
    println!("  Public inputs: {:?}", proof_data.public_inputs);
    println!("  Constraints: {}", proof_data.metadata.circuit_constraints);

    Ok(())
}

/// Generate batch proofs
pub fn generate_batch_proofs(
    key_path: &PathBuf,
    inputs_path: &PathBuf,
    output_dir: &PathBuf,
    force: bool,
) -> Result<()> {
    // Validate inputs
    ArgUtils::validate_input_files(&[key_path.as_path(), inputs_path.as_path()])?;
    
    // Create output directory
    FileOps::ensure_directory(output_dir)?;

    // Load preprocessing key
    println!("Loading preprocessing key from: {}", key_path.display());
    let pk_data = FileOps::read_binary(key_path)?;
    let preprocessing_key = MarlinPreprocessingKey::<KzgCommitmentEngine>::import(&pk_data)?;

    // Load circuit
    let circuit_path = key_path.with_extension("circuit.json");
    let r1cs: R1CS = if FileOps::file_exists(&circuit_path) {
        FileOps::read_json(&circuit_path)?
    } else {
        return Err(CliError::InvalidArguments);
    };

    // Load batch specification
    println!("Loading batch inputs from: {}", inputs_path.display());
    let batch_spec: BatchSpec = FileOps::read_json(inputs_path)?;

    if batch_spec.inputs.is_empty() {
        return Err(CliError::InvalidArguments);
    }

    println!("Processing {} proofs in batch", batch_spec.inputs.len());

    // Create prover
    let prover = MarlinProver::new(
        preprocessing_key.srs.commitment_params.clone(),
        r1cs.clone(),
        preprocessing_key.proving_key.clone(),
    );

    let mut rng = test_rng();
    let mut successful_proofs = 0;
    let mut failed_proofs = 0;

    // Process each input
    for (index, input) in batch_spec.inputs.iter().enumerate() {
        let proof_id = input.id.as_ref()
            .map(|id| format!("proof_{}", id))
            .unwrap_or_else(|| format!("proof_{:04}", index));
        
        let output_path = output_dir.join(format!("{}.json", proof_id));
        
        // Check if proof already exists
        if FileOps::file_exists(&output_path) && !force {
            println!("Skipping existing proof: {}", proof_id);
            continue;
        }

        println!("Generating proof {}/{}: {}", index + 1, batch_spec.inputs.len(), proof_id);

        // Parse inputs
        let public_inputs_result = input.public_inputs.iter()
            .map(|s| ArgUtils::parse_scalar_hex(s))
            .collect::<Result<Vec<_>>>();
        
        let witness_result = input.witness.iter()
            .map(|s| ArgUtils::parse_scalar_hex(s))
            .collect::<Result<Vec<_>>>();

        match (public_inputs_result, witness_result) {
            (Ok(public_inputs), Ok(witness)) => {
                // Validate witness
                if let Ok(true) = R1CSUtils::validate_witness(&r1cs, &public_inputs, &witness) {
                    // Generate proof
                    match prover.prove(&witness, &mut rng) {
                        Ok(proof) => {
                            let proof_data = ProofData {
                                public_inputs: public_inputs.iter().map(ArgUtils::format_scalar_hex).collect(),
                                proof,
                                metadata: ProofMetadata {
                                    circuit_constraints: r1cs.num_constraints,
                                    circuit_public_inputs: r1cs.num_public_inputs,
                                    circuit_witness_vars: r1cs.num_witness_variables,
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                },
                            };

                            if FileOps::write_json(&proof_data, &output_path).is_ok() {
                                successful_proofs += 1;
                                println!("  ✓ Saved: {}", output_path.display());
                            } else {
                                failed_proofs += 1;
                                println!("  ✗ Failed to save: {}", output_path.display());
                            }
                        }
                        Err(e) => {
                            failed_proofs += 1;
                            println!("  ✗ Proof generation failed: {:?}", e);
                        }
                    }
                } else {
                    failed_proofs += 1;
                    println!("  ✗ Invalid witness for proof: {}", proof_id);
                }
            }
            _ => {
                failed_proofs += 1;
                println!("  ✗ Failed to parse inputs for proof: {}", proof_id);
            }
        }
    }

    println!("\n✓ Batch proving complete!");
    println!("  Successful: {}", successful_proofs);
    println!("  Failed: {}", failed_proofs);
    println!("  Total: {}", batch_spec.inputs.len());

    Ok(())
}

/// Verify witness without generating proof
pub fn verify_witness_only(
    circuit_path: &PathBuf,
    public_inputs_str: &str,
    witness_str: &str,
    use_example: bool,
) -> Result<()> {
    // Load circuit
    let r1cs: R1CS = if use_example {
        println!("Using built-in example circuit");
        R1CSUtils::create_example_r1cs()
    } else {
        ArgUtils::validate_input_files(&[circuit_path.as_path()])?;
        FileOps::read_json(circuit_path)?
    };

    // Parse inputs
    let (public_inputs, witness) = if use_example {
        println!("Using example: x=3, y=9 (where x²=y)");
        (vec![Scalar::from(9u64)], vec![Scalar::from(3u64)])
    } else {
        let public_inputs = ArgUtils::parse_scalar_list(public_inputs_str)?;
        let witness = ArgUtils::parse_scalar_list(witness_str)?;
        (public_inputs, witness)
    };

    println!("Circuit information:");
    println!("  Constraints: {}", r1cs.num_constraints);
    println!("  Public inputs: {} (provided: {})", r1cs.num_public_inputs, public_inputs.len());
    println!("  Witness variables: {} (provided: {})", r1cs.num_witness_variables, witness.len());

    // Validate dimensions
    if public_inputs.len() != r1cs.num_public_inputs {
        return Err(CliError::InvalidArguments);
    }

    if witness.len() != r1cs.num_witness_variables {
        return Err(CliError::InvalidArguments);
    }

    // Verify witness
    println!("\nValidating witness against constraints...");
    let witness_valid = R1CSUtils::validate_witness(&r1cs, &public_inputs, &witness)?;

    if witness_valid {
        println!("✓ Witness validation PASSED");
        println!("  Public inputs: {:?}", public_inputs.iter().map(ArgUtils::format_scalar_hex).collect::<Vec<_>>());
        println!("  Witness values: {:?}", witness.iter().map(ArgUtils::format_scalar_hex).collect::<Vec<_>>());
    } else {
        println!("✗ Witness validation FAILED");
        return Err(CliError::InvalidArguments);
    }

    Ok(())
}

/// Proof data structure for serialization
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofData {
    pub public_inputs: Vec<String>,
    pub proof: MarlinProof<KzgCommitmentEngine>,
    pub metadata: ProofMetadata,
}

/// Proof metadata
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofMetadata {
    pub circuit_constraints: usize,
    pub circuit_public_inputs: usize,
    pub circuit_witness_vars: usize,
    pub timestamp: String,
}

/// Main prove command handler
pub fn handle_prove_command(args: ProveArgs) -> Result<()> {
    match args.command {
        ProveCommand::Single { key, public_inputs, witness, output, example, force } => {
            generate_single_proof(&key, &public_inputs, &witness, &output, example, force)
        }
        
        ProveCommand::Batch { key, inputs, output_dir, force } => {
            generate_batch_proofs(&key, &inputs, &output_dir, force)
        }
        
        ProveCommand::Verify { circuit, public_inputs, witness, example } => {
            verify_witness_only(&circuit, &public_inputs, &witness, example)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::setup::generate_universal_srs;

    #[test]
    fn test_verify_witness_example() {
        let dir = tempdir().unwrap();
        let circuit_path = dir.path().join("test.circuit");
        
        // Create example circuit
        let r1cs = R1CSUtils::create_example_r1cs();
        FileOps::write_json(&r1cs, &circuit_path).unwrap();
        
        // Test with valid witness
        let result = verify_witness_only(&circuit_path, "9", "3", false);
        assert!(result.is_ok());
        
        // Test with invalid witness
        let result2 = verify_witness_only(&circuit_path, "8", "3", false);
        assert!(result2.is_err());
    }

    #[test]
    fn test_batch_spec_serialization() {
        let batch_spec = BatchSpec {
            inputs: vec![
                BatchInput {
                    public_inputs: vec!["9".to_string()],
                    witness: vec!["3".to_string()],
                    id: Some("test1".to_string()),
                },
                BatchInput {
                    public_inputs: vec!["16".to_string()],
                    witness: vec!["4".to_string()],
                    id: Some("test2".to_string()),
                },
            ],
        };

        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("batch.json");
        
        assert!(FileOps::write_json(&batch_spec, &spec_path).is_ok());
        
        let loaded_spec: BatchSpec = FileOps::read_json(&spec_path).unwrap();
        assert_eq!(loaded_spec.inputs.len(), 2);
        assert_eq!(loaded_spec.inputs[0].id, Some("test1".to_string()));
    }

    #[test]
    fn test_proof_data_serialization() {
        use zkp_marlin::{MarlinProof, Round1Prover, Round2Prover, Round3Prover, ProofMetadata as MarlinProofMetadata};
        
        // Create a minimal proof for testing
        let proof_metadata = MarlinProofMetadata {
            num_public_inputs: 1,
            num_constraints: 1,
            security_bits: 128,
        };

        // Note: Creating a real proof would require full setup, so this is simplified
        let dir = tempdir().unwrap();
        let proof_path = dir.path().join("test_proof.json");

        let metadata = ProofMetadata {
            circuit_constraints: 1,
            circuit_public_inputs: 1,
            circuit_witness_vars: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        // Just test metadata serialization
        assert!(FileOps::write_json(&metadata, &proof_path).is_ok());
        let loaded_metadata: ProofMetadata = FileOps::read_json(&proof_path).unwrap();
        assert_eq!(loaded_metadata.circuit_constraints, 1);
    }
}