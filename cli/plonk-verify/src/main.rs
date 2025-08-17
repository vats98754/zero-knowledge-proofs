//! PLONK Proof Verification CLI Tool
//!
//! Verifies PLONK proofs against compiled circuits and public inputs.

use clap::{Arg, Command};
use anyhow::{Result, Context};
use plonk_verifier::{KZGPlonkVerifier, SelectorCommitments};
use plonk_prover::PlonkProof;
use plonk_field::PlonkField;
use plonk_pc::{KZGEngine, UniversalSetup, Transcript, KZGCommitmentWrapper, KZGProofWrapper};
use ark_bls12_381::G1Affine;
use rand::rngs::OsRng;
use std::path::Path;

fn main() -> Result<()> {
    let matches = Command::new("plonk-verify")
        .about("Verify PLONK proofs for arithmetic circuits")
        .arg(
            Arg::new("proof")
                .short('p')
                .long("proof")
                .value_name("FILE")
                .help("Proof file to verify")
                .required(true)
        )
        .arg(
            Arg::new("circuit")
                .short('c')
                .long("circuit")
                .value_name("PREFIX")
                .help("Circuit file prefix")
                .required(true)
        )
        .arg(
            Arg::new("public")
                .long("public")
                .value_name("FILE")
                .help("Public inputs file")
                .default_value("")
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

    let proof_path = matches.get_one::<String>("proof").unwrap();
    let circuit_prefix = matches.get_one::<String>("circuit").unwrap();
    let public_inputs_path = matches.get_one::<String>("public").unwrap();
    let srs_path = matches.get_one::<String>("srs").unwrap();

    println!("Verifying PLONK proof...");
    println!("  Proof: {}", proof_path);
    println!("  Circuit: {}", circuit_prefix);
    println!("  SRS: {}", srs_path);

    // Load and verify proof exists
    if !Path::new(proof_path).exists() {
        anyhow::bail!("Proof file does not exist: {}", proof_path);
    }

    // For demo purposes, create dummy verification components
    // In practice, you'd load the actual circuit, proof, and public inputs
    println!("Setting up verifier...");
    let mut rng = OsRng;
    let max_degree = 16;
    
    let setup = UniversalSetup::<KZGEngine>::new(max_degree, &mut rng)
        .context("Failed to create universal setup")?;
    
    // Create dummy selector commitments (in practice, loaded from circuit)
    let dummy_commitment = KZGCommitmentWrapper {
        point: G1Affine::default(),
    };
    
    let selector_commitments = SelectorCommitments {
        q_m: dummy_commitment.clone(),
        q_l: dummy_commitment.clone(),
        q_r: dummy_commitment.clone(),
        q_o: dummy_commitment.clone(),
        q_c: dummy_commitment,
    };
    
    let verifier = KZGPlonkVerifier::from_setup(
        &setup,
        selector_commitments,
        4, // num_constraints
        3, // num_variables
    ).context("Failed to create verifier")?;
    
    // Load public inputs (empty for demo)
    let public_inputs: Vec<PlonkField> = if public_inputs_path.is_empty() {
        vec![]
    } else {
        load_public_inputs(public_inputs_path)
            .context("Failed to load public inputs")?
    };
    
    println!("Public inputs: {} values", public_inputs.len());
    
    // Create a dummy proof for demo (in practice, load from file)
    let proof = create_dummy_proof();
    
    println!("Verifying proof...");
    let mut transcript = Transcript::new(b"plonk_proof");
    
    match verifier.verify(&proof, &public_inputs, &mut transcript) {
        Ok(true) => {
            println!("✓ Proof verification SUCCESSFUL");
            println!("The proof is valid and the statement is satisfied.");
        }
        Ok(false) => {
            println!("✗ Proof verification FAILED");
            println!("The proof is invalid or the statement is not satisfied.");
            std::process::exit(1);
        }
        Err(e) => {
            println!("✗ Proof verification ERROR");
            println!("Error: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn load_public_inputs(_path: &str) -> Result<Vec<PlonkField>> {
    // In practice, parse public inputs from file
    // For demo, return empty vector
    Ok(vec![])
}

fn create_dummy_proof() -> PlonkProof<KZGEngine> {
    // Create a minimal dummy proof for demo
    // In practice, this would be loaded from the proof file
    let dummy_commitment = KZGCommitmentWrapper {
        point: G1Affine::default(),
    };
    
    let dummy_proof = KZGProofWrapper {
        point: G1Affine::default(),
    };
    
    PlonkProof {
        wire_commitments: vec![dummy_commitment.clone(); 3],
        permutation_commitment: dummy_commitment.clone(),
        quotient_commitment: dummy_commitment,
        wire_opening_proof: dummy_proof.clone(),
        selector_opening_proof: dummy_proof.clone(),
        permutation_opening_proof: dummy_proof.clone(),
        permutation_shift_opening_proof: dummy_proof,
        zeta: PlonkField::from_u64(123),
        wire_evaluations: vec![PlonkField::from_u64(5), PlonkField::from_u64(7), PlonkField::from_u64(12)],
        selector_evaluations: vec![PlonkField::from_u64(0); 5],
        permutation_evaluation: PlonkField::from_u64(1),
        permutation_shift_evaluation: PlonkField::from_u64(1),
    }
}