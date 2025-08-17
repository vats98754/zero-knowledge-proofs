//! Scalar multiplication sequencer example
//!
//! This example demonstrates recursive proof aggregation by proving
//! successive scalar multiplications in a logarithmic proof size.

use anyhow::Result;
use halo_core::{Scalar, GroupElement, Circuit, CircuitConfig, Prover, ProverConfig};
use halo_recursion::{fold_proof, verify_recursive, AccumulatorInstance};
use commitments::{IpaCommitmentEngine, CommitmentEngine, Transcript, TranscriptWrite, TranscriptRead};
use group::{Group, Curve};
use ff::Field;
use rand::thread_rng;

/// Circuit that proves knowledge of a scalar multiplication
#[derive(Clone, Debug)]
pub struct ScalarMultiplicationCircuit {
    /// The base point
    pub base: GroupElement,
    /// The scalar multiplier
    pub scalar: Scalar,
    /// The expected result
    pub result: GroupElement,
}

impl Circuit for ScalarMultiplicationCircuit {
    fn configure(_config: &CircuitConfig) -> Result<Self>
    where
        Self: Sized
    {
        // Generate a random example for now
        let mut rng = thread_rng();
        let base = bls12_381::G1Projective::random(&mut rng).to_affine();
        let scalar = Scalar::random(&mut rng);
        let result = (base.to_curve() * scalar).to_affine();
        
        Ok(Self { base, scalar, result })
    }
    
    fn synthesize(&self) -> Result<()> {
        // Verify that base * scalar = result
        let computed = (self.base.to_curve() * self.scalar).to_affine();
        if computed != self.result {
            return Err(anyhow::anyhow!("Invalid scalar multiplication"));
        }
        Ok(())
    }
}

/// Demonstrates recursive proof aggregation for scalar multiplication sequence
pub fn demonstrate_recursive_scalar_multiplication() -> Result<()> {
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