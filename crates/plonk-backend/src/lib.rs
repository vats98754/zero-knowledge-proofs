use zkvm_core::{ExecutionTrace, ConstraintSystem, ConstraintGenerator};
use thiserror::Error;
use serde::{Deserialize, Serialize};
use ark_ff::{Field, UniformRand};
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::Group;
use ark_std::rand::RngCore;

pub mod prover;
pub mod verifier;
pub mod setup;

pub use prover::PlonkProver;
pub use verifier::PlonkVerifier;
pub use setup::PlonkSetup;

#[derive(Error, Debug)]
pub enum PlonkError {
    #[error("Setup error: {0}")]
    SetupError(String),
    #[error("Prove error: {0}")]
    ProveError(String),
    #[error("Verify error: {0}")]
    VerifyError(String),
    #[error("Invalid proof format")]
    InvalidProofFormat,
    #[error("Invalid public inputs")]
    InvalidPublicInputs,
}

pub type Result<T> = std::result::Result<T, PlonkError>;

/// PLONK proof
#[derive(Debug, Clone)]
pub struct PlonkProof {
    pub a: G1Projective,
    pub b: G1Projective,
    pub c: G1Projective,
    pub z: G1Projective,
    pub t_lo: G1Projective,
    pub t_mid: G1Projective, 
    pub t_hi: G1Projective,
    pub w_omega: Fr,
    pub w_omega2: Fr,
    pub a_eval: Fr,
    pub b_eval: Fr,
    pub c_eval: Fr,
    pub s1_eval: Fr,
    pub s2_eval: Fr,
    pub z_omega_eval: Fr,
}

/// PLONK verification key
#[derive(Debug, Clone)]
pub struct PlonkVerifyingKey {
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub alpha_g1: G1Projective,
    pub beta_g1: G1Projective,
    pub beta_g2: G2Projective,
    pub gamma_g2: G2Projective,
    pub delta_g1: G1Projective,
    pub delta_g2: G2Projective,
    pub ql: Vec<G1Projective>,
    pub qr: Vec<G1Projective>,
    pub qo: Vec<G1Projective>,
    pub qm: Vec<G1Projective>,
    pub qc: Vec<G1Projective>,
    pub s1: Vec<G1Projective>,
    pub s2: Vec<G1Projective>,
    pub s3: Vec<G1Projective>,
}

/// PLONK proving key
#[derive(Debug, Clone)]
pub struct PlonkProvingKey {
    pub vk: PlonkVerifyingKey,
    pub alpha: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub delta: Fr,
    pub h: Vec<G1Projective>,
}

/// PLONK backend adapter for zkVM
pub struct PlonkBackend {
    setup: Option<PlonkSetup>,
}

impl PlonkBackend {
    pub fn new() -> Self {
        Self { setup: None }
    }

    /// Generate setup parameters for a given constraint system
    pub fn setup<R: RngCore>(&mut self, constraints: &ConstraintSystem, rng: &mut R) -> Result<()> {
        let setup = PlonkSetup::new(constraints, rng)?;
        self.setup = Some(setup);
        Ok(())
    }

    /// Generate a proof for an execution trace
    pub fn prove<R: RngCore>(
        &self,
        trace: &ExecutionTrace,
        rng: &mut R,
    ) -> Result<PlonkProof> {
        let setup = self.setup.as_ref()
            .ok_or_else(|| PlonkError::SetupError("Setup not initialized".to_string()))?;

        let constraints = ConstraintGenerator::generate_plonk_constraints(trace);
        let prover = PlonkProver::new(&setup.proving_key);
        prover.prove(trace, &constraints, rng)
    }

    /// Verify a proof
    pub fn verify(
        &self,
        proof: &PlonkProof,
        public_inputs: &[Fr],
    ) -> Result<bool> {
        let setup = self.setup.as_ref()
            .ok_or_else(|| PlonkError::SetupError("Setup not initialized".to_string()))?;

        let verifier = PlonkVerifier::new(&setup.verifying_key);
        verifier.verify(proof, public_inputs)
    }

    /// Get the verifying key for on-chain verification
    pub fn verifying_key(&self) -> Option<&PlonkVerifyingKey> {
        self.setup.as_ref().map(|s| &s.verifying_key)
    }

    /// Estimate proof size
    pub fn proof_size(&self) -> usize {
        // PLONK proof size is roughly:
        // - 7 G1 elements (a, b, c, z, t_lo, t_mid, t_hi) = 7 * 32 = 224 bytes
        // - 6 Fr elements (evaluations) = 6 * 32 = 192 bytes
        // Total ≈ 416 bytes
        416
    }

    /// Estimate verification time complexity
    pub fn verification_complexity(&self) -> String {
        "O(1) - constant time verification independent of trace size".to_string()
    }
}

impl Default for PlonkBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkvm_core::{TraceRow, ConstraintGenerator};
    use rand_chacha::ChaCha20Rng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_plonk_backend_creation() {
        let backend = PlonkBackend::new();
        assert!(backend.setup.is_none());
    }

    #[test]
    fn test_proof_size_estimation() {
        let backend = PlonkBackend::new();
        assert_eq!(backend.proof_size(), 416);
    }

    #[test]
    fn test_setup_and_prove() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut backend = PlonkBackend::new();

        // Create a simple trace
        let mut trace = ExecutionTrace::new(16);
        let row = TraceRow::new(vec![0u64; 16]);
        trace.add_row(row);

        // Generate constraints and setup
        let constraints = ConstraintGenerator::generate_plonk_constraints(&trace);
        backend.setup(&constraints, &mut rng).unwrap();

        // Generate proof
        let proof = backend.prove(&trace, &mut rng);
        assert!(proof.is_ok());
    }
}