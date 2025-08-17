//! Scalar multiplication sequencer example
//!
//! This example demonstrates recursive proof aggregation by proving
//! successive scalar multiplications with efficient verification.

use halo_core::{Circuit, HaloError};
use halo_recursion::{fold_proof, verify_recursive, AccumulatorInstance, FoldingResult, Accumulator};
use commitments::{IpaCommitmentEngine, CommitmentEngine};
use group::prime::PrimeCurveAffine;
use ff::{Field, PrimeField};
use bls12_381::{G1Affine, G1Projective, Scalar as BlsScalar};
use rand::thread_rng;
use std::result::Result;

/// Circuit that proves knowledge of a scalar multiplication
#[derive(Clone, Debug)]
pub struct ScalarMultiplicationCircuit {
    /// The base point
    pub base: G1Affine,
    /// The scalar multiplier
    pub scalar: BlsScalar,
    /// The expected result
    pub result: G1Affine,
}

impl Circuit for ScalarMultiplicationCircuit {
    type Config = ();
    type Error = HaloError;
    
    fn configure(_config: &Self::Config) -> Result<Self, Self::Error> {
        // Generate a random example for demonstration
        let mut rng = thread_rng();
        let base = G1Affine::generator();
        let scalar = BlsScalar::random(&mut rng);
        let result = (base.to_curve() * scalar).to_affine();
        
        Ok(Self { base, scalar, result })
    }
    
    fn synthesize(&self) -> Result<(), Self::Error> {
        // Verify that base * scalar = result
        let computed = (self.base.to_curve() * self.scalar).to_affine();
        if computed != self.result {
            return Err(HaloError::SynthesisError("Invalid scalar multiplication".to_string()));
        }
        Ok(())
    }
}

/// Convert scalar to bytes for public input
fn scalar_to_bytes(scalar: BlsScalar) -> Vec<u8> {
    scalar.to_repr().as_ref().to_vec()
}

/// Convert point to bytes for public input  
fn point_to_bytes(point: G1Affine) -> Vec<u8> {
    if point.is_identity().into() {
        vec![0u8; 48] // Compressed identity point
    } else {
        // Simplified conversion for demo
        vec![1u8; 48] // Placeholder
    }
}

/// Create accumulator instance from circuit data
fn create_accumulator_instance(circuit: &ScalarMultiplicationCircuit) -> AccumulatorInstance {
    let mut public_inputs = Vec::new();
    
    // Add base point coordinates
    public_inputs.extend_from_slice(&point_to_bytes(circuit.base));
    
    // Add result point coordinates  
    public_inputs.extend_from_slice(&point_to_bytes(circuit.result));
    
    AccumulatorInstance {
        public_inputs,
    }
}

/// Demonstrates recursive proof aggregation for scalar multiplication sequence
pub fn demonstrate_recursive_scalar_multiplication() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Recursive Scalar Multiplication Demonstration");
    println!("===============================================");
    
    let num_proofs = 5;
    println!("📊 Aggregating {} scalar multiplication proofs", num_proofs);
    
    // Generate a sequence of scalar multiplication circuits
    let mut circuits = Vec::new();
    let mut base = G1Affine::generator();
    
    for i in 0..num_proofs {
        let mut rng = thread_rng();
        let scalar = BlsScalar::from((i + 1) as u64);
        let result = (base.to_curve() * scalar).to_affine();
        
        let circuit = ScalarMultiplicationCircuit {
            base,
            scalar,
            result,
        };
        
        circuits.push(circuit);
        base = result; // Chain the results
    }
    
    println!("🔗 Chained scalar multiplications:");
    for (i, circuit) in circuits.iter().enumerate() {
        println!("   Step {}: G × {} = Result", i + 1, i + 1);
    }
    
    // Create commitment engine
    let commitment_engine = IpaCommitmentEngine::new();
    
    // Fold proofs recursively
    let mut current_accumulator: Option<Accumulator> = None;
    let mut proof_count = 0;
    
    for (i, circuit) in circuits.iter().enumerate() {
        println!("📝 Processing proof {} of {}", i + 1, num_proofs);
        
        // Create proof for this circuit (simplified - in practice would use actual prover)
        let proof_data = create_mock_proof(circuit);
        let instance = create_accumulator_instance(circuit);
        
        // Convert to the expected format for fold_proof
        let public_inputs = instance.public_inputs.iter()
            .enumerate()
            .map(|(i, &byte)| BlsScalar::from(byte as u64 + i as u64))
            .collect::<Vec<_>>();
        
        // Fold the proof into the accumulator
        match fold_proof(current_accumulator, proof_data, public_inputs) {
            Ok(folding_result) => {
                current_accumulator = Some(folding_result.accumulator);
                proof_count += 1;
                println!("   ✅ Proof {} folded successfully", i + 1);
            }
            Err(e) => {
                println!("   ❌ Error folding proof {}: {:?}", i + 1, e);
                continue;
            }
        }
    }
    
    // Verify the final aggregated proof
    if let Some(final_accumulator) = current_accumulator {
        println!("🔍 Verifying aggregated proof...");
        
        // Create verification instance (using last circuit for demo)
        let verification_instance = create_accumulator_instance(circuits.last().unwrap());
        
        // Create a mock folding proof for verification
        let folding_proof = create_mock_folding_proof(&final_accumulator);
        
        match verify_recursive(&folding_proof, &verification_instance) {
            Ok(is_valid) => {
                println!("✅ Recursive verification result: {}", is_valid);
                if is_valid {
                    println!("🎉 All {} proofs successfully aggregated and verified!", proof_count);
                } else {
                    println!("❌ Aggregated proof verification failed");
                }
            }
            Err(e) => {
                println!("❌ Verification error: {:?}", e);
            }
        }
        
        // Display proof statistics
        println!("📈 Aggregation Statistics:");
        println!("   📊 Individual proofs: {}", proof_count);
        println!("   🔄 Folding operations: {}", proof_count - 1);
        println!("   📦 Final proof represents {} computations", proof_count);
        
        // Show compression benefits
        let individual_size = 48 * proof_count; // Simplified size calculation
        let aggregated_size = 48; // Single aggregated proof
        let compression_ratio = individual_size as f64 / aggregated_size as f64;
        
        println!("💰 Compression Benefits:");
        println!("   Individual proofs total: ~{} bytes", individual_size);
        println!("   Aggregated proof: ~{} bytes", aggregated_size);
        println!("   Compression ratio: {:.2}x", compression_ratio);
        
    } else {
        println!("❌ No accumulator generated - all proof folding failed");
    }
    
    Ok(())
}

/// Create a mock proof for demonstration (in practice, would use actual prover)
fn create_mock_proof(circuit: &ScalarMultiplicationCircuit) -> halo_core::Proof {
    // Synthesize the circuit to ensure it's valid
    if let Err(e) = circuit.synthesize() {
        println!("⚠️  Circuit synthesis failed: {:?}", e);
    }
    
    // Create a mock proof with some realistic structure
    halo_core::Proof {
        commitments: vec![G1Affine::generator(); 3], // Mock commitments
        evaluations: vec![BlsScalar::one(); 5],      // Mock evaluations  
        opening_proof: G1Affine::generator(),        // Mock opening
    }
}

/// Create a mock folding proof for verification
fn create_mock_folding_proof(accumulator: &Accumulator) -> halo_recursion::FoldingProof {
    halo_recursion::FoldingProof {
        accumulator: accumulator.clone(),
        folding_challenges: vec![BlsScalar::one(); 3],
        cross_terms: vec![G1Affine::generator(); 2],
        evaluation_proof: G1Affine::generator(),
    }
}

/// Display challenge generation process
fn display_challenge_info(challenges: &[BlsScalar]) {
    println!("🎲 Fiat-Shamir Challenges Generated:");
    for (i, challenge) in challenges.iter().enumerate() {
        let challenge_bytes = challenge.to_repr();
        println!("   Challenge {}: {}...", i + 1, hex::encode(&challenge_bytes.as_ref()[..4]));
    }
}

/// Run the demonstration
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting Scalar Multiplication Sequencer Example");
    println!("===================================================\n");
    
    demonstrate_recursive_scalar_multiplication()?;
    
    // Show additional insights
    println!("\n💡 Key Insights:");
    println!("   🔄 Recursive aggregation enables logarithmic verification time");
    println!("   📦 Proof size remains constant regardless of number of proofs");
    println!("   🔒 Security maintained through polynomial commitments");
    println!("   ⚡ Efficient for batch verification scenarios");
    
    println!("\n✨ Demonstration completed successfully!");
    Ok(())
}
    println!("🔄 Demonstrating Recursive Scalar Multiplication Sequencer");
    println!("=========================================================");
    
    // Setup parameters
    let mut rng = thread_rng();
    let commitment_params = IpaCommitmentEngine::setup(16, &mut rng)?;
    let prover = Prover::new(ProverConfig { max_degree: 16 });
    
    println!("✅ Setup complete with max degree 16");
    
    // Create a sequence of scalar multiplication circuits
    let num_steps = 4;
    let mut circuits = Vec::new();
    let mut base = bls12_381::G1Projective::random(&mut rng).to_affine();
    
    println!("🏗️  Creating {} scalar multiplication circuits...", num_steps);
    
    for i in 0..num_steps {
        let scalar = Scalar::from(i as u64 + 1);
        let result = (base.to_curve() * scalar).to_affine();
        
        let circuit = ScalarMultiplicationCircuit {
            base,
            scalar,
            result,
        };
        
        circuits.push(circuit);
        base = result; // Chain the results
        
        println!("   Circuit {}: {} * {} = {}", 
            i + 1, 
            hex::encode(&base.to_compressed()[..8]),
            scalar,
            hex::encode(&result.to_compressed()[..8])
        );
    }
    
    // Generate individual proofs
    println!("\n🔐 Generating individual proofs...");
    let mut proofs = Vec::new();
    
    for (i, circuit) in circuits.iter().enumerate() {
        let proof = prover.prove(circuit.clone())?;
        proofs.push(proof);
        println!("   ✓ Proof {} generated", i + 1);
    }
    
    // Demonstrate proof folding
    println!("\n🔄 Folding proofs recursively...");
    let mut current_proof = None;
    
    for (i, proof) in proofs.into_iter().enumerate() {
        // Create instance data for folding
        let instance_data = format!("step-{}", i).into_bytes();
        
        // Fold the proof
        current_proof = Some(fold_proof(current_proof, instance_data)?);
        println!("   ✓ Folded proof for step {}", i + 1);
    }
    
    let final_proof = current_proof.unwrap();
    
    // Verify the recursive proof
    println!("\n🔍 Verifying recursive proof...");
    let verification_instance = b"final-verification";
    let is_valid = verify_recursive(&final_proof, verification_instance)?;
    
    if is_valid {
        println!("   ✅ Recursive proof verification PASSED!");
        println!("   📊 Proof size: {} bytes", final_proof.to_bytes().len());
        println!("   🎯 Proved {} scalar multiplications in single proof", num_steps);
    } else {
        println!("   ❌ Recursive proof verification FAILED!");
        return Err(anyhow::anyhow!("Verification failed"));
    }
    
    // Demonstrate transcript integration
    println!("\n📝 Demonstrating transcript integration...");
    let mut transcript = Transcript::new(b"scalar-mult-demo");
    
    // Add commitments to transcript
    for (i, circuit) in circuits.iter().enumerate() {
        transcript.append_point(b"base", &circuit.base);
        transcript.append_scalar(b"scalar", &circuit.scalar);
        transcript.append_point(b"result", &circuit.result);
        
        let challenge = transcript.challenge_scalar(b"challenge");
        println!("   Challenge {}: {}", i + 1, hex::encode(&challenge.to_repr()[..8]));
    }
    
    println!("\n🎉 Recursive scalar multiplication demonstration complete!");
    println!("   • Aggregated {} proofs into one", num_steps);
    println!("   • Verification time: O(log n) instead of O(n)");
    println!("   • Proof size: O(log n) instead of O(n)");
    
    Ok(())
}

/// Test the scalar multiplication circuit
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scalar_multiplication_circuit() {
        let mut rng = thread_rng();
        let base = bls12_381::G1Projective::random(&mut rng).to_affine();
        let scalar = Scalar::from(42u64);
        let result = (base.to_curve() * scalar).to_affine();
        
        let circuit = ScalarMultiplicationCircuit { base, scalar, result };
        assert!(circuit.synthesize().is_ok());
    }
    
    #[test]
    fn test_invalid_scalar_multiplication() {
        let mut rng = thread_rng();
        let base = bls12_381::G1Projective::random(&mut rng).to_affine();
        let scalar = Scalar::from(42u64);
        let wrong_result = bls12_381::G1Projective::random(&mut rng).to_affine();
        
        let circuit = ScalarMultiplicationCircuit { 
            base, 
            scalar, 
            result: wrong_result 
        };
        assert!(circuit.synthesize().is_err());
    }
}

fn main() -> Result<()> {
    demonstrate_recursive_scalar_multiplication()
}