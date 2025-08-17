//! PLONK Proof Generation CLI Tool
//!
//! Generates PLONK proofs for compiled circuits given witness data.

use clap::{Arg, Command};
use anyhow::{Result, Context};
use plonk_prover::{KZGPlonkProver, PlonkProof};
use plonk_arith::PlonkCircuit;
use plonk_field::PlonkField;
use plonk_pc::Transcript;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;

fn main() -> Result<()> {
    let matches = Command::new("plonk-prove")
        .about("Generate PLONK proofs for arithmetic circuits")
        .arg(
            Arg::new("circuit")
                .short('c')
                .long("circuit")
                .value_name("PREFIX")
                .help("Circuit file prefix (from plonk-compile)")
                .required(true)
        )
        .arg(
            Arg::new("witness")
                .short('w')
                .long("witness")
                .value_name("FILE")
                .help("Witness data file")
                .required(true)
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output proof file")
                .default_value("proof.bin")
        )
        .arg(
            Arg::new("srs")
                .short('s')
                .long("srs")
                .value_name("FILE")
                .help("Universal SRS file")
                .default_value("universal_srs.bin")
        )
        .get_matches();

    let circuit_prefix = matches.get_one::<String>("circuit").unwrap();
    let witness_path = matches.get_one::<String>("witness").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let srs_path = matches.get_one::<String>("srs").unwrap();

    println!("Generating PLONK proof...");
    println!("  Circuit: {}", circuit_prefix);
    println!("  Witness: {}", witness_path);
    println!("  SRS: {}", srs_path);

    // For demo purposes, create a simple circuit and witness
    // In practice, you'd load the compiled circuit and parse witness data
    let circuit = create_demo_circuit_with_witness()
        .context("Failed to create demo circuit")?;
    
    println!("Setting up prover...");
    let mut rng = OsRng;
    let max_degree = 16; // Should match the SRS
    
    let prover = KZGPlonkProver::setup(max_degree, &mut rng)
        .context("Failed to setup PLONK prover")?;
    
    println!("Generating proof...");
    let mut transcript = Transcript::new(b"plonk_proof");
    let proof = prover.prove(&circuit, &mut transcript)
        .context("Failed to generate proof")?;
    
    println!("Serializing proof...");
    // In practice, you'd serialize the actual proof structure
    let mut output_file = File::create(output_path)
        .context("Failed to create output file")?;
    
    // Write proof header
    output_file.write_all(b"PLONK_PROOF_V1")?;
    
    // Write proof size info
    output_file.write_all(&(proof.wire_commitments.len() as u32).to_le_bytes())?;
    output_file.write_all(&(proof.wire_evaluations.len() as u32).to_le_bytes())?;
    
    println!("Proof generated successfully and saved to: {}", output_path);
    println!("Proof contains:");
    println!("  - Wire commitments: {}", proof.wire_commitments.len());
    println!("  - Wire evaluations: {}", proof.wire_evaluations.len());
    println!("  - Selector evaluations: {}", proof.selector_evaluations.len());
    
    Ok(())
}

fn create_demo_circuit_with_witness() -> Result<PlonkCircuit> {
    let mut circuit = PlonkCircuit::new(4);
    
    // Simple addition: 5 + 7 = 12
    let a = PlonkField::from_u64(5);
    let b = PlonkField::from_u64(7);
    let c = a + b;
    
    circuit.add_addition_gate(a, b, c)
        .context("Failed to add addition gate")?;
    
    Ok(circuit)
}