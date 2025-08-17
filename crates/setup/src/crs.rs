//! Common Reference String (CRS) structures and utilities

use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

/// Proving key containing structured reference string for proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvingKeyData {
    /// Alpha in G1
    pub alpha_g1: Vec<u8>,
    /// Beta in G1 and G2
    pub beta_g1: Vec<u8>,
    pub beta_g2: Vec<u8>,
    /// Delta in G1 and G2
    pub delta_g1: Vec<u8>,
    pub delta_g2: Vec<u8>,
    /// Query vectors (serialized)
    pub a_query: Vec<Vec<u8>>,
    pub b_g1_query: Vec<Vec<u8>>,
    pub b_g2_query: Vec<Vec<u8>>,
    pub h_query: Vec<Vec<u8>>,
    pub l_query: Vec<Vec<u8>>,
}

/// Verification key for public verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKeyData {
    /// Alpha in G1
    pub alpha_g1: Vec<u8>,
    /// Beta in G2
    pub beta_g2: Vec<u8>,
    /// Gamma in G2
    pub gamma_g2: Vec<u8>,
    /// Delta in G2
    pub delta_g2: Vec<u8>,
    /// IC query for public inputs
    pub gamma_abc_g1: Vec<Vec<u8>>,
}

/// Serializable CRS structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CRSData {
    pub proving_key: ProvingKeyData,
    pub verification_key: VerificationKeyData,
}