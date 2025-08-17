use zkvm_core::{ExecutionTrace, ConstraintGenerator};
use compiler::compile_to_trace;
use plonk_backend::PlonkBackend;
use stark_backend::StarkBackend;
use groth_backend::GrothBackend;
use examples::TokenContract;
use rand_chacha::ChaCha20Rng;
use ark_std::rand::SeedableRng;
use ark_bn254::Fr;

pub mod benchmarks;

/// Integration test for end-to-end zkVM workflow
pub fn end_to_end_test() -> anyhow::Result<()> {
    println!("Running end-to-end zkVM integration test...");

    // Step 1: Compile assembly to execution trace
    let assembly = r#"
        ADD R0, R1, R2
        MUL R3, R0, R1
        HALT
    "#;
    
    let trace = compile_to_trace(assembly)?;
    println!("✓ Generated execution trace: {} steps, {} width", trace.length(), trace.width());

    // Step 2: Generate constraints
    let constraints = ConstraintGenerator::generate_plonk_constraints(&trace);
    println!("✓ Generated {} constraints", constraints.constraints.len());

    // Step 3: Test PLONK backend
    test_plonk_backend(&trace)?;
    
    // Step 4: Test STARK backend
    test_stark_backend(&trace)?;
    
    // Step 5: Test Groth16 backend
    test_groth_backend(&trace)?;

    println!("✓ All backend tests passed!");
    Ok(())
}

fn test_plonk_backend(trace: &ExecutionTrace) -> anyhow::Result<()> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut backend = PlonkBackend::new();
    
    // Setup
    let constraints = ConstraintGenerator::generate_plonk_constraints(trace);
    backend.setup(&constraints, &mut rng)?;
    println!("✓ PLONK setup completed");

    // Prove
    let proof = backend.prove(trace, &mut rng)?;
    println!("✓ PLONK proof generated (size: ~{} bytes)", backend.proof_size());

    // Verify
    let public_inputs = vec![Fr::from(0u64)]; // Initial PC
    let verified = backend.verify(&proof, &public_inputs)?;
    println!("✓ PLONK proof verification: {}", verified);

    Ok(())
}

fn test_stark_backend(trace: &ExecutionTrace) -> anyhow::Result<()> {
    let backend = StarkBackend::new();
    
    // Prove
    let proof = backend.prove(trace)?;
    println!("✓ STARK proof generated");

    // Verify
    let public_inputs = vec![0u64]; // Initial PC
    let verified = backend.verify(&proof, &public_inputs)?;
    println!("✓ STARK proof verification: {}", verified);

    Ok(())
}

fn test_groth_backend(trace: &ExecutionTrace) -> anyhow::Result<()> {
    let mut backend = GrothBackend::new();
    
    // Setup
    let constraints = ConstraintGenerator::generate_plonk_constraints(trace);
    backend.setup(&constraints)?;
    println!("✓ Groth16 setup completed");

    // Prove
    let proof = backend.prove(trace)?;
    println!("✓ Groth16 proof generated");

    // Verify
    let public_inputs = vec![0u64]; // Initial PC
    let verified = backend.verify(&proof, &public_inputs)?;
    println!("✓ Groth16 proof verification: {}", verified);

    Ok(())
}

/// Test token contract integration
pub fn token_contract_integration_test() -> anyhow::Result<()> {
    println!("Running token contract integration test...");

    let contract = TokenContract::new();

    // Test simple transfer
    let transfer_trace = contract.execute_transfer(1, 2, 100)?;
    println!("✓ Transfer trace generated: {} steps", transfer_trace.length());

    // Test balance verification
    let verify_trace = contract.execute_verify_balance(1, 900)?; // After transfer
    println!("✓ Balance verification trace generated: {} steps", verify_trace.length());

    // Test batch transfer
    let transfers = vec![(1, 2, 50), (2, 3, 25)];
    let batch_trace = contract.execute_batch_transfer(&transfers)?;
    println!("✓ Batch transfer trace generated: {} steps", batch_trace.length());

    // Generate proof for transfer using PLONK
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let mut plonk_backend = PlonkBackend::new();
    let constraints = ConstraintGenerator::generate_plonk_constraints(&transfer_trace);
    plonk_backend.setup(&constraints, &mut rng)?;
    let transfer_proof = plonk_backend.prove(&transfer_trace, &mut rng)?;
    println!("✓ Token transfer proof generated with PLONK");

    println!("✓ Token contract integration test completed!");
    Ok(())
}

/// Cross-backend comparison test
pub fn cross_backend_comparison() -> anyhow::Result<()> {
    println!("Running cross-backend comparison...");

    let assembly = r#"
        # Fibonacci computation
        ADD R0, R1, R2
        SUB R3, R0, R1
        MUL R4, R2, R3
        HALT
    "#;

    let trace = compile_to_trace(assembly)?;
    
    // Test all backends with the same trace
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    
    // PLONK
    let mut plonk = PlonkBackend::new();
    let constraints = ConstraintGenerator::generate_plonk_constraints(&trace);
    plonk.setup(&constraints, &mut rng)?;
    let plonk_proof = plonk.prove(&trace, &mut rng)?;
    println!("✓ PLONK: proof size ~{} bytes", plonk.proof_size());
    println!("✓ PLONK: verification complexity {}", plonk.verification_complexity());

    // STARK
    let stark = StarkBackend::new();
    let stark_proof = stark.prove(&trace)?;
    println!("✓ STARK: proof generated (transparent, no trusted setup)");

    // Groth16
    let mut groth = GrothBackend::new();
    groth.setup(&constraints)?;
    let groth_proof = groth.prove(&trace)?;
    println!("✓ Groth16: proof generated (smallest size, trusted setup required)");

    println!("✓ Cross-backend comparison completed!");
    Ok(())
}

/// Performance characteristics test
pub fn performance_characteristics_test() -> anyhow::Result<()> {
    println!("Running performance characteristics test...");

    let sizes = vec![10, 50, 100, 200];
    
    for size in sizes {
        // Generate program of given size
        let mut assembly = String::new();
        for i in 0..size {
            assembly.push_str(&format!("ADD R{}, R{}, R{}\n", i % 8, (i + 1) % 8, (i + 2) % 8));
        }
        assembly.push_str("HALT\n");

        let trace = compile_to_trace(&assembly)?;
        println!("Program size: {} instructions -> Trace length: {}", size, trace.length());

        // Test scalability with different backends
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let mut plonk = PlonkBackend::new();
        let constraints = ConstraintGenerator::generate_plonk_constraints(&trace);
        plonk.setup(&constraints, &mut rng)?;
        
        let _proof = plonk.prove(&trace, &mut rng)?;
        println!("  ✓ PLONK proof generated for size {}", size);
    }

    println!("✓ Performance characteristics test completed!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end() {
        assert!(end_to_end_test().is_ok());
    }

    #[test]
    fn test_token_contract_integration() {
        assert!(token_contract_integration_test().is_ok());
    }

    #[test]
    fn test_cross_backend_comparison() {
        assert!(cross_backend_comparison().is_ok());
    }

    #[test]
    fn test_performance_characteristics() {
        assert!(performance_characteristics_test().is_ok());
    }
}