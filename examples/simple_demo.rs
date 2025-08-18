//! Simple Demo of Halo/Halo2 Capabilities
//!
//! This example demonstrates the core functionality of the Halo/Halo2 implementation:
//! - Circuit building with arithmetic gates
//! - Proof folding and recursive verification
//! - IPA polynomial commitments

use halo2_arith::{CircuitBuilder, ColumnManager, StandardGate, circuit::CircuitConfig};
use halo_recursion::fold_proof;
use halo_core::Proof;
use bls12_381::{G1Projective, Scalar as BlsScalar};
use ff::Field;
use group::{Curve, Group};
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Halo/Halo2 Simple Demo");
    println!("========================");
    
    // Demonstrate circuit building
    demo_circuit_building()?;
    
    // Demonstrate proof folding
    demo_proof_folding()?;
    
    println!("\n✅ Demo completed successfully!");
    Ok(())
}

fn demo_circuit_building() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🏗️  Circuit Building Demo");
    println!("-----------------------");
    
    // Create column manager and add columns
    let mut column_manager = ColumnManager::new();
    let advice_col = column_manager.add_advice_column();
    let fixed_col = column_manager.add_fixed_column();
    let _instance_col = column_manager.add_instance_column();
    
    // Create circuit config and builder
    let circuit_config = CircuitConfig::default();
    let mut builder = CircuitBuilder::new(circuit_config);
    
    // Create a simple arithmetic circuit with 3 gates
    for i in 0..3 {
        println!("   Adding gate {}", i + 1);
        
        // Create a standard gate (supports addition and multiplication)
        let a_col = advice_col.clone().into_column();
        let b_col = advice_col.clone().into_column();  
        let c_col = advice_col.clone().into_column();
        let q_add_col = fixed_col.clone().into_column();
        let q_mul_col = fixed_col.clone().into_column();
        let q_const_col = fixed_col.clone().into_column();
        
        let gate = StandardGate::new(a_col, b_col, c_col, q_add_col, q_mul_col, q_const_col);
        builder = builder.gate(gate.into_gate()?);
    }
    
    // Build the circuit
    let circuit = builder.build()?;
    let stats = circuit.stats();
    
    println!("   ✅ Circuit built successfully!");
    println!("   📊 Circuit size: {}", stats.circuit_size);
    println!("   📈 Total columns: {}", stats.columns.total_columns);
    
    Ok(())
}

fn demo_proof_folding() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔄 Proof Folding Demo");
    println!("--------------------");
    
    let mut rng = thread_rng();
    
    // Create mock proofs
    let proof1 = create_mock_proof(&mut rng);
    let proof2 = create_mock_proof(&mut rng);
    
    // Create public inputs
    let public_inputs1: Vec<BlsScalar> = (0..4)
        .map(|_| BlsScalar::random(&mut rng))
        .collect();
    let public_inputs2: Vec<BlsScalar> = (0..4)
        .map(|_| BlsScalar::random(&mut rng))
        .collect();
    
    println!("   📝 Created 2 mock proofs with public inputs");
    
    // Fold the first proof (creates initial accumulator)
    println!("   🔄 Folding first proof...");
    let folding_result1 = fold_proof(None, proof1, public_inputs1)?;
    println!("   ✅ First proof folded successfully!");
    
    // Fold the second proof with the accumulator
    println!("   🔄 Folding second proof...");
    let folding_result2 = fold_proof(Some(folding_result1.accumulator), proof2, public_inputs2)?;
    println!("   ✅ Second proof folded successfully!");
    
    // Show accumulator statistics
    let final_accumulator = &folding_result2.accumulator;
    println!("   📊 Final accumulator stats:");
    println!("      - Public inputs: {}", final_accumulator.instance.public_inputs.len());
    println!("      - Commitments: {}", final_accumulator.instance.commitments.len());
    println!("      - Challenges: {}", final_accumulator.instance.challenges.len());
    println!("      - Proof count: {}", final_accumulator.instance.proof_count);
    println!("      - Error terms: {}", final_accumulator.error_terms.len());
    
    Ok(())
}

fn create_mock_proof(rng: &mut impl rand::RngCore) -> Proof {
    Proof {
        commitments: vec![G1Projective::random(&mut *rng).to_affine(); 3],
        evaluations: vec![BlsScalar::random(&mut *rng); 5],
        openings: vec![0u8; 96], // Mock opening proof as bytes
    }
}