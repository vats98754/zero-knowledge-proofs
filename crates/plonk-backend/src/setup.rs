use crate::{PlonkProvingKey, PlonkVerifyingKey, PlonkError, Result};
use zkvm_core::ConstraintSystem;
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::Group;
use ark_ff::UniformRand;
use ark_std::rand::RngCore;

/// PLONK setup containing proving and verifying keys
#[derive(Debug, Clone)]
pub struct PlonkSetup {
    pub proving_key: PlonkProvingKey,
    pub verifying_key: PlonkVerifyingKey,
}

impl PlonkSetup {
    /// Generate setup parameters for PLONK
    pub fn new<R: RngCore>(constraints: &ConstraintSystem, rng: &mut R) -> Result<Self> {
        // This is a simplified setup - in a real implementation,
        // this would involve KZG commitment setup, SRS generation, etc.
        
        let n = constraints.trace_length.next_power_of_two();
        
        // Generate random parameters (in practice, these would come from a trusted setup)
        let alpha = Fr::rand(rng);
        let beta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let delta = Fr::rand(rng);

        // Generator points
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();

        // Commitment keys
        let alpha_g1 = g1 * alpha;
        let beta_g1 = g1 * beta;
        let beta_g2 = g2 * beta;
        let gamma_g2 = g2 * gamma;
        let delta_g1 = g1 * delta;
        let delta_g2 = g2 * delta;

        // Selector polynomials (simplified)
        let ql = (0..n).map(|_| g1 * Fr::rand(rng)).collect();
        let qr = (0..n).map(|_| g1 * Fr::rand(rng)).collect();
        let qo = (0..n).map(|_| g1 * Fr::rand(rng)).collect();
        let qm = (0..n).map(|_| g1 * Fr::rand(rng)).collect();
        let qc = (0..n).map(|_| g1 * Fr::rand(rng)).collect();

        // Permutation polynomials
        let s1 = (0..n).map(|_| g1 * Fr::rand(rng)).collect();
        let s2 = (0..n).map(|_| g1 * Fr::rand(rng)).collect();
        let s3 = (0..n).map(|_| g1 * Fr::rand(rng)).collect();

        // Powers of tau for KZG (simplified)
        let h: Vec<G1Projective> = (0..n * 2).map(|i| g1 * Fr::from(i as u64 + 1)).collect();

        let verifying_key = PlonkVerifyingKey {
            g1,
            g2,
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
            ql,
            qr,
            qo,
            qm,
            qc,
            s1,
            s2,
            s3,
        };

        let proving_key = PlonkProvingKey {
            vk: verifying_key.clone(),
            alpha,
            beta,
            gamma,
            delta,
            h,
        };

        Ok(PlonkSetup {
            proving_key,
            verifying_key,
        })
    }

    /// Export verifying key for on-chain verification
    pub fn export_vk(&self) -> Vec<u8> {
        // In practice, this would serialize the verifying key in a format
        // compatible with smart contract verifiers
        // For now, return a simple but consistent format for testing
        let mut data = Vec::new();
        data.extend_from_slice(b"PLONK_VK_v1");
        data.extend_from_slice(&(self.verifying_key.ql.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.verifying_key.qr.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.verifying_key.qm.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.verifying_key.qo.len() as u32).to_le_bytes());
        data.extend_from_slice(&(self.verifying_key.qc.len() as u32).to_le_bytes());
        data
    }

    /// Import verifying key from serialized format
    pub fn import_vk(data: &[u8]) -> Result<PlonkVerifyingKey> {
        if data.len() < 11 {
            return Err(PlonkError::SetupError("Invalid data length".to_string()));
        }
        
        if &data[0..11] != b"PLONK_VK_v1" {
            return Err(PlonkError::SetupError("Invalid magic bytes".to_string()));
        }
        
        if data.len() < 11 + 5 * 4 {
            return Err(PlonkError::SetupError("Insufficient data for sizes".to_string()));
        }
        
        let ql_len = u32::from_le_bytes([data[11], data[12], data[13], data[14]]) as usize;
        let qr_len = u32::from_le_bytes([data[15], data[16], data[17], data[18]]) as usize;
        let qm_len = u32::from_le_bytes([data[19], data[20], data[21], data[22]]) as usize;
        let qo_len = u32::from_le_bytes([data[23], data[24], data[25], data[26]]) as usize;
        let qc_len = u32::from_le_bytes([data[27], data[28], data[29], data[30]]) as usize;
        
        // Create a new verifying key with the parsed dimensions
        // In practice, these would be proper deserialized elliptic curve points
        Ok(PlonkVerifyingKey {
            g1: G1Projective::generator(),
            g2: G2Projective::generator(),
            alpha_g1: G1Projective::generator(),
            beta_g1: G1Projective::generator(),
            beta_g2: G2Projective::generator(),
            gamma_g2: G2Projective::generator(),
            delta_g1: G1Projective::generator(),
            delta_g2: G2Projective::generator(),
            ql: vec![G1Projective::generator(); ql_len],
            qr: vec![G1Projective::generator(); qr_len],
            qm: vec![G1Projective::generator(); qm_len],
            qo: vec![G1Projective::generator(); qo_len],
            qc: vec![G1Projective::generator(); qc_len],
            s1: vec![G1Projective::generator(); ql_len], // s permutation polynomials have same length as selectors
            s2: vec![G1Projective::generator(); ql_len],
            s3: vec![G1Projective::generator(); ql_len],
        })
    }

    /// Get setup parameters info
    pub fn info(&self) -> SetupInfo {
        SetupInfo {
            vk_size: self.export_vk().len(),
            h_size: self.proving_key.h.len(),
            selector_size: self.verifying_key.ql.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SetupInfo {
    pub vk_size: usize,
    pub h_size: usize,
    pub selector_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkvm_core::{ConstraintGenerator, ExecutionTrace, TraceRow};
    use rand_chacha::ChaCha20Rng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_plonk_setup() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        
        // Create dummy constraints
        let mut trace = ExecutionTrace::new(4);
        trace.add_row(TraceRow::new(vec![1, 2, 3, 4]));
        let constraints = ConstraintGenerator::generate_plonk_constraints(&trace);

        let setup = PlonkSetup::new(&constraints, &mut rng);
        assert!(setup.is_ok());

        let setup = setup.unwrap();
        assert!(!setup.verifying_key.ql.is_empty());
        assert!(!setup.proving_key.h.is_empty());
    }

    #[test]
    fn test_vk_export_import() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        
        let mut trace = ExecutionTrace::new(4);
        trace.add_row(TraceRow::new(vec![1, 2, 3, 4]));
        let constraints = ConstraintGenerator::generate_plonk_constraints(&trace);

        let setup = PlonkSetup::new(&constraints, &mut rng).unwrap();
        
        let vk_data = setup.export_vk();
        assert!(!vk_data.is_empty());

        let imported_vk = PlonkSetup::import_vk(&vk_data);
        assert!(imported_vk.is_ok());
    }

    #[test]
    fn test_setup_info() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        
        let mut trace = ExecutionTrace::new(4);
        trace.add_row(TraceRow::new(vec![1, 2, 3, 4]));
        let constraints = ConstraintGenerator::generate_plonk_constraints(&trace);

        let setup = PlonkSetup::new(&constraints, &mut rng).unwrap();
        let info = setup.info();
        
        assert!(info.vk_size > 0);
        assert!(info.h_size > 0);
        assert!(info.selector_size > 0);
    }
}