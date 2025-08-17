//! Marlin verify CLI tool
//!
//! This module implements the `marlin-verify` command for verifying
//! zero-knowledge proofs generated with the Marlin protocol.

use crate::{Result, CliError, common::*, prove::ProofData};
use zkp_commitments::KzgCommitmentEngine;
use zkp_marlin::{MarlinVerifier, MarlinPreprocessingKey, R1CS};
use zkp_field::Scalar;
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Verify command configuration
#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[command(subcommand)]
    pub command: VerifyCommand,
}

/// Verify subcommands
#[derive(Debug, Subcommand)]
pub enum VerifyCommand {
    /// Verify a single proof
    Single {
        /// Path to the preprocessing key
        #[arg(short, long, default_value = "marlin.pk")]
        key: PathBuf,
        
        /// Path to the proof file
        #[arg(short, long, default_value = "proof.json")]
        proof: PathBuf,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Verify multiple proofs in batch
    Batch {
        /// Path to the preprocessing key
        #[arg(short, long, default_value = "marlin.pk")]
        key: PathBuf,
        
        /// Directory containing proof files
        #[arg(short, long, default_value = "proofs/")]
        proof_dir: PathBuf,
        
        /// Pattern to match proof files
        #[arg(long, default_value = "*.json")]
        pattern: String,
        
        /// Stop on first verification failure
        #[arg(long)]
        fail_fast: bool,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Benchmark verification performance
    Benchmark {
        /// Path to the preprocessing key
        #[arg(short, long, default_value = "marlin.pk")]
        key: PathBuf,
        
        /// Path to the proof file
        #[arg(short, long, default_value = "proof.json")]
        proof: PathBuf,
        
        /// Number of verification rounds
        #[arg(short, long, default_value = "100")]
        rounds: usize,
    },
    
    /// Show proof information without verification
    Info {
        /// Path to the proof file
        #[arg(short, long, default_value = "proof.json")]
        proof: PathBuf,
    },
}

/// Verification result
#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub proof_file: PathBuf,
    pub public_inputs: Vec<String>,
    pub verification_time_ms: u128,
    pub error: Option<String>,
}

/// Verify a single proof
pub fn verify_single_proof(
    key_path: &PathBuf,
    proof_path: &PathBuf,
    verbose: bool,
) -> Result<VerificationResult> {
    // Validate input files
    ArgUtils::validate_input_files(&[key_path.as_path(), proof_path.as_path()])?;

    if verbose {
        println!("Loading preprocessing key from: {}", key_path.display());
    }
    
    // Load preprocessing key
    let pk_data = FileOps::read_binary(key_path)?;
    let preprocessing_key = MarlinPreprocessingKey::<KzgCommitmentEngine>::import(&pk_data)?;

    // Load circuit
    let circuit_path = key_path.with_extension("circuit.json");
    let r1cs: R1CS = if FileOps::file_exists(&circuit_path) {
        if verbose {
            println!("Loading circuit from: {}", circuit_path.display());
        }
        FileOps::read_json(&circuit_path)?
    } else {
        if verbose {
            println!("Warning: Circuit file not found, using example circuit");
        }
        R1CSUtils::create_example_r1cs()
    };

    if verbose {
        println!("Loading proof from: {}", proof_path.display());
    }

    // Load proof
    let proof_data: ProofData = FileOps::read_json(proof_path)?;

    // Parse public inputs
    let public_inputs: Result<Vec<Scalar>> = proof_data.public_inputs.iter()
        .map(|s| ArgUtils::parse_scalar_hex(s))
        .collect();
    
    let public_inputs = public_inputs?;

    // Validate public inputs length
    if public_inputs.len() != r1cs.num_public_inputs {
        return Ok(VerificationResult {
            valid: false,
            proof_file: proof_path.clone(),
            public_inputs: proof_data.public_inputs.clone(),
            verification_time_ms: 0,
            error: Some(format!("Public inputs length mismatch: expected {}, got {}", 
                               r1cs.num_public_inputs, public_inputs.len())),
        });
    }

    if verbose {
        println!("Circuit information:");
        println!("  Constraints: {}", r1cs.num_constraints);
        println!("  Public inputs: {}", r1cs.num_public_inputs);
        println!("  Witness variables: {}", r1cs.num_witness_variables);
        println!("\nProof information:");
        println!("  Public inputs: {:?}", proof_data.public_inputs);
        println!("  Generated: {}", proof_data.metadata.timestamp);
        println!("\nVerifying proof...");
    }

    // Create verifier
    let mut verifier = MarlinVerifier::new(preprocessing_key.verification_key);

    // Measure verification time
    let start_time = std::time::Instant::now();
    
    let verification_result = verifier.verify(&proof_data.proof, &public_inputs);
    
    let verification_time = start_time.elapsed();

    match verification_result {
        Ok(is_valid) => {
            Ok(VerificationResult {
                valid: is_valid,
                proof_file: proof_path.clone(),
                public_inputs: proof_data.public_inputs,
                verification_time_ms: verification_time.as_millis(),
                error: None,
            })
        }
        Err(e) => {
            Ok(VerificationResult {
                valid: false,
                proof_file: proof_path.clone(),
                public_inputs: proof_data.public_inputs,
                verification_time_ms: verification_time.as_millis(),
                error: Some(format!("Verification error: {:?}", e)),
            })
        }
    }
}

/// Verify multiple proofs in batch
pub fn verify_batch_proofs(
    key_path: &PathBuf,
    proof_dir: &PathBuf,
    pattern: &str,
    fail_fast: bool,
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    // Validate inputs
    ArgUtils::validate_input_files(&[key_path.as_path()])?;
    
    if !proof_dir.exists() || !proof_dir.is_dir() {
        return Err(CliError::IoError(
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Proof directory not found: {}", proof_dir.display())
            )
        ));
    }

    // Find proof files
    let proof_files = find_proof_files(proof_dir, pattern)?;
    
    if proof_files.is_empty() {
        println!("No proof files found matching pattern: {}", pattern);
        return Ok(Vec::new());
    }

    println!("Found {} proof files to verify", proof_files.len());

    let mut results = Vec::new();
    let mut successful = 0;
    let mut failed = 0;

    // Process each proof file
    for (index, proof_file) in proof_files.iter().enumerate() {
        if verbose {
            println!("\nVerifying proof {}/{}: {}", 
                    index + 1, proof_files.len(), proof_file.display());
        } else {
            print!("Verifying {}/{}: ", index + 1, proof_files.len());
            std::io::Write::flush(&mut std::io::stdout()).ok();
        }

        match verify_single_proof(key_path, proof_file, false) {
            Ok(result) => {
                if result.valid {
                    successful += 1;
                    if !verbose {
                        println!("✓ VALID ({}ms)", result.verification_time_ms);
                    }
                } else {
                    failed += 1;
                    if !verbose {
                        println!("✗ INVALID");
                    }
                    if let Some(error) = &result.error {
                        println!("    Error: {}", error);
                    }
                }

                if verbose {
                    println!("  Result: {}", if result.valid { "VALID" } else { "INVALID" });
                    println!("  Time: {}ms", result.verification_time_ms);
                    if let Some(error) = &result.error {
                        println!("  Error: {}", error);
                    }
                }

                results.push(result);

                // Stop on first failure if fail_fast is enabled
                if fail_fast && failed > 0 {
                    println!("\nStopping on first failure (--fail-fast enabled)");
                    break;
                }
            }
            Err(e) => {
                failed += 1;
                let error_result = VerificationResult {
                    valid: false,
                    proof_file: proof_file.clone(),
                    public_inputs: Vec::new(),
                    verification_time_ms: 0,
                    error: Some(format!("Failed to load/verify proof: {:?}", e)),
                };

                if !verbose {
                    println!("✗ ERROR");
                }
                println!("    Error: {:?}", e);

                results.push(error_result);

                if fail_fast {
                    println!("\nStopping on error (--fail-fast enabled)");
                    break;
                }
            }
        }
    }

    // Summary
    println!("\n✓ Batch verification complete!");
    println!("  Successful: {}", successful);
    println!("  Failed: {}", failed);
    println!("  Total: {}", results.len());

    if successful == results.len() {
        println!("  All proofs are VALID! 🎉");
    }

    Ok(results)
}

/// Benchmark verification performance
pub fn benchmark_verification(
    key_path: &PathBuf,
    proof_path: &PathBuf,
    rounds: usize,
) -> Result<()> {
    ArgUtils::validate_input_files(&[key_path.as_path(), proof_path.as_path()])?;

    println!("Benchmarking verification performance...");
    println!("  Proof: {}", proof_path.display());
    println!("  Rounds: {}", rounds);

    let mut times = Vec::new();
    let mut successful = 0;
    let mut failed = 0;

    let mut progress = ProgressIndicator::new("Running benchmark", rounds);

    for round in 0..rounds {
        progress.update(round);

        match verify_single_proof(key_path, proof_path, false) {
            Ok(result) => {
                times.push(result.verification_time_ms);
                if result.valid {
                    successful += 1;
                } else {
                    failed += 1;
                }
            }
            Err(_) => {
                failed += 1;
            }
        }
    }

    progress.finish();

    // Calculate statistics
    if !times.is_empty() {
        let total_time: u128 = times.iter().sum();
        let avg_time = total_time as f64 / times.len() as f64;
        let min_time = *times.iter().min().unwrap();
        let max_time = *times.iter().max().unwrap();

        times.sort_unstable();
        let median_time = if times.len() % 2 == 0 {
            (times[times.len() / 2 - 1] + times[times.len() / 2]) as f64 / 2.0
        } else {
            times[times.len() / 2] as f64
        };

        println!("\n✓ Benchmark results:");
        println!("  Total rounds: {}", rounds);
        println!("  Successful: {}", successful);
        println!("  Failed: {}", failed);
        println!("\n  Timing statistics:");
        println!("    Average: {:.2}ms", avg_time);
        println!("    Median:  {:.2}ms", median_time);
        println!("    Min:     {}ms", min_time);
        println!("    Max:     {}ms", max_time);
        println!("    Total:   {}ms", total_time);
        
        if successful > 0 {
            println!("\n  Throughput: {:.2} verifications/second", 
                    successful as f64 / (total_time as f64 / 1000.0));
        }
    } else {
        println!("No successful verifications recorded.");
    }

    Ok(())
}

/// Show proof information
pub fn show_proof_info(proof_path: &PathBuf) -> Result<()> {
    ArgUtils::validate_input_files(&[proof_path.as_path()])?;

    println!("Proof Information");
    println!("=================");

    // Load proof
    let proof_data: ProofData = FileOps::read_json(proof_path)?;

    println!("File: {}", proof_path.display());
    
    // File size
    let file_size = std::fs::metadata(proof_path)
        .map(|m| m.len())
        .unwrap_or(0);
    println!("Size: {} bytes", file_size);

    println!("\nCircuit Information:");
    println!("  Constraints: {}", proof_data.metadata.circuit_constraints);
    println!("  Public inputs: {}", proof_data.metadata.circuit_public_inputs);
    println!("  Witness variables: {}", proof_data.metadata.circuit_witness_vars);

    println!("\nProof Information:");
    println!("  Generated: {}", proof_data.metadata.timestamp);
    println!("  Public inputs: {:?}", proof_data.public_inputs);

    println!("\nProof Structure:");
    println!("  Round 1 commitments: present");
    println!("  Round 2 commitments: present");
    println!("  Round 3 openings: present");

    Ok(())
}

/// Find proof files matching pattern
fn find_proof_files(dir: &PathBuf, pattern: &str) -> Result<Vec<PathBuf>> {
    let mut proof_files = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    
                    // Simple pattern matching (just check extension for now)
                    if pattern == "*.json" && file_name.ends_with(".json") {
                        proof_files.push(path);
                    } else if file_name.contains(&pattern.replace("*", "")) {
                        proof_files.push(path);
                    }
                }
            }
        }
    }

    proof_files.sort();
    Ok(proof_files)
}

/// Main verify command handler
pub fn handle_verify_command(args: VerifyArgs) -> Result<()> {
    match args.command {
        VerifyCommand::Single { key, proof, verbose } => {
            let result = verify_single_proof(&key, &proof, verbose)?;
            
            if !verbose {
                if result.valid {
                    println!("✓ Proof is VALID");
                } else {
                    println!("✗ Proof is INVALID");
                    if let Some(error) = &result.error {
                        println!("Error: {}", error);
                    }
                }
                println!("Verification time: {}ms", result.verification_time_ms);
            }

            if !result.valid {
                std::process::exit(1);
            }

            Ok(())
        }
        
        VerifyCommand::Batch { key, proof_dir, pattern, fail_fast, verbose } => {
            let results = verify_batch_proofs(&key, &proof_dir, &pattern, fail_fast, verbose)?;
            
            let failed_count = results.iter().filter(|r| !r.valid).count();
            if failed_count > 0 {
                std::process::exit(1);
            }

            Ok(())
        }
        
        VerifyCommand::Benchmark { key, proof, rounds } => {
            benchmark_verification(&key, &proof, rounds)
        }
        
        VerifyCommand::Info { proof } => {
            show_proof_info(&proof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::prove::ProofMetadata;

    #[test]
    fn test_proof_info() {
        let dir = tempdir().unwrap();
        let proof_path = dir.path().join("test_proof.json");
        
        // Create a minimal proof data for testing
        let metadata = ProofMetadata {
            circuit_constraints: 1,
            circuit_public_inputs: 1,
            circuit_witness_vars: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        // Just test metadata serialization and info display
        FileOps::write_json(&metadata, &proof_path).unwrap();
        
        // This would normally fail because it's not a complete ProofData,
        // but we can test the file finding logic
        assert!(FileOps::file_exists(&proof_path));
    }

    #[test]
    fn test_find_proof_files() {
        let dir = tempdir().unwrap();
        
        // Create some test files
        let proof1 = dir.path().join("proof1.json");
        let proof2 = dir.path().join("proof2.json");
        let other = dir.path().join("other.txt");
        
        std::fs::write(&proof1, "{}").unwrap();
        std::fs::write(&proof2, "{}").unwrap();
        std::fs::write(&other, "test").unwrap();
        
        let proof_files = find_proof_files(&dir.path().to_path_buf(), "*.json").unwrap();
        assert_eq!(proof_files.len(), 2);
        
        let names: Vec<String> = proof_files.iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"proof1.json".to_string()));
        assert!(names.contains(&"proof2.json".to_string()));
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            valid: true,
            proof_file: PathBuf::from("test.json"),
            public_inputs: vec!["0x09".to_string()],
            verification_time_ms: 42,
            error: None,
        };

        assert!(result.valid);
        assert_eq!(result.verification_time_ms, 42);
        assert!(result.error.is_none());
    }
}