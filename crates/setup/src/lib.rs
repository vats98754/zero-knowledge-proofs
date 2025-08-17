//! Trusted setup implementation for Groth16
//! 
//! This crate provides trusted setup and SRS generation.

#![forbid(unsafe_code)]

pub mod crs;
pub mod powers_of_tau;
pub mod toxic_waste;

pub use crs::*;
pub use powers_of_tau::*;
pub use toxic_waste::*;

use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{Group};
use ark_ff::{Zero, UniformRand};
use ark_poly::Polynomial;
use ark_std::{vec::Vec, rand::Rng};
use qap::QAP;
use r1cs::R1CS;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SetupError {
    #[error("Invalid circuit")]
    InvalidCircuit,
    #[error("Setup failed: {0}")]
    SetupFailed(String),
    #[error("Verification key generation failed")]
    VerificationKeyGenFailed,
}

/// Common Reference String (CRS) for Groth16
#[derive(Debug, Clone)]
pub struct CRS {
    /// Parameters for proving
    pub proving_key: ProvingKey,
    /// Parameters for verification
    pub verification_key: VerificationKey,
}

/// Proving key containing the structured reference string
#[derive(Debug, Clone)]
pub struct ProvingKey {
    /// Alpha parameter in G1
    pub alpha_g1: G1Projective,
    /// Beta parameters in G1 and G2
    pub beta_g1: G1Projective,
    pub beta_g2: G2Projective,
    /// Delta parameters in G1 and G2
    pub delta_g1: G1Projective,
    pub delta_g2: G2Projective,
    /// A polynomials evaluated at powers of tau in G1
    pub a_query: Vec<G1Projective>,
    /// B polynomials in G1 and G2
    pub b_g1_query: Vec<G1Projective>,
    pub b_g2_query: Vec<G2Projective>,
    /// H polynomial powers for quotient computation
    pub h_query: Vec<G1Projective>,
    /// L polynomials for witness component
    pub l_query: Vec<G1Projective>,
}

/// Verification key for public verification
#[derive(Debug, Clone)]
pub struct VerificationKey {
    /// Alpha parameter in G1
    pub alpha_g1: G1Projective,
    /// Beta parameter in G2
    pub beta_g2: G2Projective,
    /// Gamma parameter in G2
    pub gamma_g2: G2Projective,
    /// Delta parameter in G2
    pub delta_g2: G2Projective,
    /// IC query for public inputs
    pub gamma_abc_g1: Vec<G1Projective>,
}

/// Toxic waste that must be securely destroyed after setup
#[derive(Debug, Clone)]
pub struct ToxicWaste {
    pub tau: Fr,
    pub alpha: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub delta: Fr,
}

impl ToxicWaste {
    /// Generate random toxic waste
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        Self {
            tau: Fr::rand(rng),
            alpha: Fr::rand(rng),
            beta: Fr::rand(rng),
            gamma: Fr::rand(rng),
            delta: Fr::rand(rng),
        }
    }

    /// Securely zero out the toxic waste (best effort)
    pub fn destroy(&mut self) {
        self.tau = Fr::zero();
        self.alpha = Fr::zero();
        self.beta = Fr::zero();
        self.gamma = Fr::zero();
        self.delta = Fr::zero();
    }
}

/// Generate trusted setup for a given R1CS circuit
pub fn generate_setup<R: Rng>(r1cs: &R1CS<Fr>, rng: &mut R) -> Result<CRS, SetupError> {
    // Convert R1CS to QAP
    let qap = QAP::from_r1cs(r1cs).map_err(|_| SetupError::InvalidCircuit)?;
    
    // Generate toxic waste
    let mut toxic_waste = ToxicWaste::new(rng);
    
    // Perform the setup
    let crs = generate_crs(&qap, &toxic_waste)?;
    
    // Destroy toxic waste
    toxic_waste.destroy();
    
    Ok(crs)
}

/// Generate CRS from QAP and toxic waste
pub fn generate_crs(qap: &QAP<Fr>, toxic: &ToxicWaste) -> Result<CRS, SetupError> {
    let num_vars = qap.num_variables();
    let degree = qap.degree();
    
    // Generate powers of tau
    let tau_powers = generate_powers_of_tau(toxic.tau, degree + 1);
    
    // Generators
    let g1_gen = G1Projective::generator();
    let g2_gen = G2Projective::generator();
    
    // Alpha, beta, gamma, delta in groups
    let alpha_g1 = g1_gen * toxic.alpha;
    let beta_g1 = g1_gen * toxic.beta;
    let beta_g2 = g2_gen * toxic.beta;
    let gamma_g2 = g2_gen * toxic.gamma;
    let delta_g1 = g1_gen * toxic.delta;
    let delta_g2 = g2_gen * toxic.delta;
    
    // A query: [A_i(tau) + alpha] for i in 0..num_vars
    let mut a_query = Vec::with_capacity(num_vars);
    for i in 0..num_vars {
        let a_at_tau = qap.a_polys[i].evaluate(&toxic.tau);
        a_query.push(g1_gen * (a_at_tau + toxic.alpha));
    }
    
    // B query in G1 and G2: [B_i(tau) + beta] for i in 0..num_vars
    let mut b_g1_query = Vec::with_capacity(num_vars);
    let mut b_g2_query = Vec::with_capacity(num_vars);
    for i in 0..num_vars {
        let b_at_tau = qap.b_polys[i].evaluate(&toxic.tau);
        b_g1_query.push(g1_gen * (b_at_tau + toxic.beta));
        b_g2_query.push(g2_gen * (b_at_tau + toxic.beta));
    }
    
    // H query: powers of tau up to degree-1 divided by delta
    let mut h_query = Vec::with_capacity(degree);
    for i in 0..degree {
        h_query.push(g1_gen * (tau_powers[i] / toxic.delta));
    }
    
    // L query: [beta * A_i(tau) + alpha * B_i(tau) + C_i(tau)] / gamma for private inputs
    let num_public = 0; // For now, assume no public inputs for simplicity
    let mut l_query = Vec::with_capacity(num_vars.saturating_sub(num_public + 1));
    for i in (num_public + 1)..num_vars {
        let a_at_tau = qap.a_polys[i].evaluate(&toxic.tau);
        let b_at_tau = qap.b_polys[i].evaluate(&toxic.tau);
        let c_at_tau = qap.c_polys[i].evaluate(&toxic.tau);
        let l_val = (toxic.beta * a_at_tau + toxic.alpha * b_at_tau + c_at_tau) / toxic.gamma;
        l_query.push(g1_gen * l_val);
    }
    
    // Gamma ABC query for public inputs: [beta * A_i(tau) + alpha * B_i(tau) + C_i(tau)] / gamma
    let mut gamma_abc_g1 = Vec::with_capacity(num_public + 1);
    for i in 0..=num_public {
        let a_at_tau = qap.a_polys[i].evaluate(&toxic.tau);
        let b_at_tau = qap.b_polys[i].evaluate(&toxic.tau);
        let c_at_tau = qap.c_polys[i].evaluate(&toxic.tau);
        let abc_val = (toxic.beta * a_at_tau + toxic.alpha * b_at_tau + c_at_tau) / toxic.gamma;
        gamma_abc_g1.push(g1_gen * abc_val);
    }
    
    let proving_key = ProvingKey {
        alpha_g1,
        beta_g1,
        beta_g2,
        delta_g1,
        delta_g2,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    };
    
    let verification_key = VerificationKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };
    
    Ok(CRS {
        proving_key,
        verification_key,
    })
}

/// Generate powers of tau: [1, tau, tau^2, ..., tau^(degree-1)]
fn generate_powers_of_tau(tau: Fr, degree: usize) -> Vec<Fr> {
    let mut powers = Vec::with_capacity(degree);
    let mut current = Fr::from(1u64);
    
    for _ in 0..degree {
        powers.push(current);
        current *= tau;
    }
    
    powers
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use r1cs::{R1CS, LinearCombination};

    #[test]
    fn test_toxic_waste_generation() {
        let mut rng = test_rng();
        let mut toxic = ToxicWaste::new(&mut rng);
        
        // Check that values are non-zero
        assert!(!toxic.tau.is_zero());
        assert!(!toxic.alpha.is_zero());
        assert!(!toxic.beta.is_zero());
        assert!(!toxic.gamma.is_zero());
        assert!(!toxic.delta.is_zero());
        
        // Destroy and check they're zeroed
        toxic.destroy();
        assert!(toxic.tau.is_zero());
        assert!(toxic.alpha.is_zero());
        assert!(toxic.beta.is_zero());
        assert!(toxic.gamma.is_zero());
        assert!(toxic.delta.is_zero());
    }

    #[test]
    fn test_powers_of_tau() {
        let tau = Fr::from(5u64);
        let powers = generate_powers_of_tau(tau, 4);
        
        assert_eq!(powers.len(), 4);
        assert_eq!(powers[0], Fr::from(1u64));   // tau^0 = 1
        assert_eq!(powers[1], Fr::from(5u64));   // tau^1 = 5
        assert_eq!(powers[2], Fr::from(25u64));  // tau^2 = 25
        assert_eq!(powers[3], Fr::from(125u64)); // tau^3 = 125
    }

    #[test]
    fn test_setup_generation() {
        let mut rng = test_rng();
        let mut r1cs = R1CS::<Fr>::new();
        
        // Create a simple constraint: x * x = x^2
        let x = r1cs.alloc_variable();
        let x_squared = r1cs.alloc_variable();

        let a = LinearCombination::from_variable(x);
        let b = LinearCombination::from_variable(x);
        let c = LinearCombination::from_variable(x_squared);
        
        r1cs.add_constraint(a, b, c).unwrap();

        // Generate setup
        let crs = generate_setup(&r1cs, &mut rng).unwrap();
        let num_public = 0; // We used no public inputs in the test
        
        // Check that keys have expected sizes
        assert_eq!(crs.proving_key.a_query.len(), r1cs.num_variables);
        assert_eq!(crs.proving_key.b_g1_query.len(), r1cs.num_variables);
        assert_eq!(crs.proving_key.b_g2_query.len(), r1cs.num_variables);
        assert_eq!(crs.verification_key.gamma_abc_g1.len(), num_public + 1);
    }
}