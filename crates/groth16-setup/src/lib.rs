//! Trusted setup and CRS generation for Groth16.
//! 
//! This crate implements the trusted setup ceremony and CRS generation.
//! The setup generates a Common Reference String (CRS) that includes both
//! proving and verification keys for the Groth16 protocol.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use groth16_field::FieldLike;
use groth16_qap::QAP;
use ark_ff::PrimeField;
use ark_ec::{CurveGroup, Group};
use ark_poly::Polynomial;
use ark_bls12_381::{G1Projective, G2Projective, G1Affine, G2Affine, Fr};
use ark_std::{vec::Vec, One, UniformRand};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rand::Rng;
use rayon::prelude::*;

pub use groth16_field;
pub use groth16_r1cs;
pub use groth16_qap;

/// Proving key for Groth16
#[derive(Debug, Clone)]
pub struct ProvingKey<F: FieldLike> {
    /// α in G1
    pub alpha_g1: G1Affine,
    /// β in G1  
    pub beta_g1: G1Affine,
    /// β in G2
    pub beta_g2: G2Affine,
    /// δ in G1
    pub delta_g1: G1Affine,
    /// δ in G2
    pub delta_g2: G2Affine,
    /// [A_i(s)]₁ for i ∈ {0..num_variables}
    pub a_g1: Vec<G1Affine>,
    /// [B_i(s)]₁ for i ∈ {0..num_variables}
    pub b_g1: Vec<G1Affine>,
    /// [B_i(s)]₂ for i ∈ {0..num_variables}
    pub b_g2: Vec<G2Affine>,
    /// [(β·A_i(s) + α·B_i(s) + C_i(s))/δ]₁ for i ∈ {num_public+1..num_variables}
    pub ic_g1: Vec<G1Affine>,
    /// [s^i/δ]₁ for i ∈ {0..degree-1}
    pub h_g1: Vec<G1Affine>,
    /// Number of public inputs (excluding constant)
    pub num_public: usize,
    /// QAP data for reference
    pub qap: QAP<F>,
}

/// Verification key for Groth16
#[derive(Debug, Clone)]
pub struct VerificationKey {
    /// α in G1
    pub alpha_g1: G1Affine,
    /// β in G2
    pub beta_g2: G2Affine,
    /// γ in G2
    pub gamma_g2: G2Affine,
    /// δ in G2
    pub delta_g2: G2Affine,
    /// [(β·A_i(s) + α·B_i(s) + C_i(s))/γ]₁ for i ∈ {0..num_public}
    pub ic_g1: Vec<G1Affine>,
    /// Number of public inputs (excluding constant)
    pub num_public: usize,
}

/// Common Reference String containing both proving and verification keys
#[derive(Debug, Clone)]
pub struct CRS<F: FieldLike> {
    /// Proving key
    pub pk: ProvingKey<F>,
    /// Verification key
    pub vk: VerificationKey,
}

/// Setup parameters for the trusted setup
#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Random α parameter
    pub alpha: Fr,
    /// Random β parameter  
    pub beta: Fr,
    /// Random γ parameter
    pub gamma: Fr,
    /// Random δ parameter
    pub delta: Fr,
    /// Random s parameter (evaluation point)
    pub s: Fr,
}

/// Errors that can occur during setup
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// QAP error
    #[error("QAP error: {0}")]
    QAPError(#[from] groth16_qap::QAPError),
    
    /// Field operation error
    #[error("Field error: {0}")]
    FieldError(#[from] groth16_field::FieldError),
    
    /// Invalid setup parameters
    #[error("Invalid setup parameters: {0}")]
    InvalidParams(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

impl SetupParams {
    /// Generate random setup parameters
    pub fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            alpha: Fr::rand(rng),
            beta: Fr::rand(rng), 
            gamma: Fr::rand(rng),
            delta: Fr::rand(rng),
            s: Fr::rand(rng),
        }
    }
    
    /// Validate that parameters are non-zero
    pub fn validate(&self) -> Result<(), SetupError> {
        if ark_ff::Zero::is_zero(&self.alpha) || ark_ff::Zero::is_zero(&self.beta) || 
           ark_ff::Zero::is_zero(&self.gamma) || ark_ff::Zero::is_zero(&self.delta) {
            return Err(SetupError::InvalidParams(
                "Setup parameters must be non-zero".to_string()
            ));
        }
        Ok(())
    }
}

impl<F: FieldLike + PrimeField> CRS<F> {
    /// Generate a CRS from a QAP and setup parameters
    pub fn generate_from_qap(
        qap: &QAP<F>, 
        params: &SetupParams,
        num_public: usize
    ) -> Result<Self, SetupError> {
        params.validate()?;
        
        if num_public >= qap.num_variables {
            return Err(SetupError::InvalidParams(
                "Number of public inputs must be less than total variables".to_string()
            ));
        }
        
        // Convert setup parameters to the field type F  
        let alpha = F::from(params.alpha.into_bigint().as_ref()[0]);
        let beta = F::from(params.beta.into_bigint().as_ref()[0]);
        let gamma = F::from(params.gamma.into_bigint().as_ref()[0]);
        let delta = F::from(params.delta.into_bigint().as_ref()[0]);
        let s = F::from(params.s.into_bigint().as_ref()[0]);
        
        // Generators
        let g1_gen = G1Projective::generator();
        let g2_gen = G2Projective::generator();
        
        // Compute basic elements
        let alpha_g1 = (g1_gen * params.alpha).into_affine();
        let beta_g1 = (g1_gen * params.beta).into_affine();
        let beta_g2 = (g2_gen * params.beta).into_affine();
        let gamma_g2 = (g2_gen * params.gamma).into_affine();
        let delta_g1 = (g1_gen * params.delta).into_affine();
        let delta_g2 = (g2_gen * params.delta).into_affine();
        
        // Evaluate polynomials at s
        let a_vals: Vec<F> = qap.a_polys.par_iter()
            .map(|poly| Polynomial::evaluate(poly, &s))
            .collect();
        let b_vals: Vec<F> = qap.b_polys.par_iter()
            .map(|poly| Polynomial::evaluate(poly, &s))
            .collect();
        let c_vals: Vec<F> = qap.c_polys.par_iter()
            .map(|poly| Polynomial::evaluate(poly, &s))
            .collect();
        
        // Compute [A_i(s)]₁
        let a_g1: Vec<G1Affine> = a_vals.par_iter()
            .map(|&a_val| {
                let a_bigint = a_val.into_bigint();
                let a_fr = Fr::from(a_bigint.as_ref()[0]);
                (g1_gen * a_fr).into_affine()
            })
            .collect();
        
        // Compute [B_i(s)]₁ and [B_i(s)]₂
        let b_g1: Vec<G1Affine> = b_vals.par_iter()
            .map(|&b_val| {
                let b_bigint = b_val.into_bigint();
                let b_fr = Fr::from(b_bigint.as_ref()[0]);
                (g1_gen * b_fr).into_affine()
            })
            .collect();
        let b_g2: Vec<G2Affine> = b_vals.par_iter()
            .map(|&b_val| {
                let b_bigint = b_val.into_bigint();
                let b_fr = Fr::from(b_bigint.as_ref()[0]);
                (g2_gen * b_fr).into_affine()
            })
            .collect();
        
        // Compute IC elements for proving key (private variables)
        let pk_ic_g1: Vec<G1Affine> = (num_public + 1..qap.num_variables).into_par_iter()
            .map(|i| {
                let term = beta * a_vals[i] + alpha * b_vals[i] + c_vals[i];
                let scaled = term * ark_ff::Field::inverse(&delta).unwrap();
                let scaled_bigint = scaled.into_bigint();
                let fr_val = Fr::from(scaled_bigint.as_ref()[0]);
                (g1_gen * fr_val).into_affine()
            })
            .collect();
        
        // Compute IC elements for verification key (public variables)
        let vk_ic_g1: Vec<G1Affine> = (0..=num_public).into_par_iter()
            .map(|i| {
                let term = beta * a_vals[i] + alpha * b_vals[i] + c_vals[i];
                let scaled = term * ark_ff::Field::inverse(&gamma).unwrap();
                let scaled_bigint = scaled.into_bigint();
                let fr_val = Fr::from(scaled_bigint.as_ref()[0]);
                (g1_gen * fr_val).into_affine()
            })
            .collect();
        
        // Compute H elements [s^i/δ]₁
        let max_degree = qap.degree();
        let h_g1: Vec<G1Affine> = (0..max_degree).into_par_iter()
            .map(|i| {
                let s_pow = ark_ff::Field::pow(&s, &[i as u64]);
                let scaled = s_pow * ark_ff::Field::inverse(&delta).unwrap();
                let scaled_bigint = scaled.into_bigint();
                let fr_val = Fr::from(scaled_bigint.as_ref()[0]);
                (g1_gen * fr_val).into_affine()
            })
            .collect();
        
        let pk = ProvingKey {
            alpha_g1,
            beta_g1,
            beta_g2,
            delta_g1,
            delta_g2,
            a_g1,
            b_g1,
            b_g2,
            ic_g1: pk_ic_g1,
            h_g1,
            num_public,
            qap: qap.clone(),
        };
        
        let vk = VerificationKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic_g1: vk_ic_g1,
            num_public,
        };
        
        Ok(CRS { pk, vk })
    }
    
    /// Generate a random CRS for testing purposes
    pub fn generate_random<R: Rng + ?Sized>(
        qap: &QAP<F>,
        num_public: usize,
        rng: &mut R
    ) -> Result<Self, SetupError> {
        let params = SetupParams::random(rng);
        Self::generate_from_qap(qap, &params, num_public)
    }
}

/// Multi-party ceremony simulation for testing
pub mod ceremony {
    use super::*;
    
    /// Participant in the ceremony
    #[derive(Debug)]
    pub struct Participant {
        /// Participant ID
        pub id: String,
        /// Secret randomness
        pub randomness: Fr,
    }
    
    /// Ceremony state
    #[derive(Debug)]
    pub struct Ceremony {
        /// List of participants
        pub participants: Vec<Participant>,
        /// Accumulated parameters
        pub params: SetupParams,
    }
    
    impl Ceremony {
        /// Initialize a new ceremony
        pub fn new() -> Self {
            Self {
                participants: Vec::new(),
                params: SetupParams {
                    alpha: ark_ff::One::one(),
                    beta: ark_ff::One::one(),
                    gamma: ark_ff::One::one(),
                    delta: ark_ff::One::one(),
                    s: ark_ff::One::one(),
                },
            }
        }
        
        /// Add a participant with random contribution
        pub fn add_participant<R: Rng + ?Sized>(&mut self, id: String, rng: &mut R) {
            let randomness = Fr::rand(rng);
            
            // Update parameters multiplicatively
            self.params.alpha *= randomness;
            self.params.beta *= randomness;
            self.params.gamma *= randomness;
            self.params.delta *= randomness;
            self.params.s *= randomness;
            
            self.participants.push(Participant { id, randomness });
        }
        
        /// Finalize ceremony and return setup parameters
        pub fn finalize(self) -> SetupParams {
            self.params
        }
        
        /// Verify ceremony integrity (all participants contributed)
        pub fn verify(&self) -> bool {
            !self.participants.is_empty() && 
            !ark_ff::Zero::is_zero(&self.params.alpha) &&
            !ark_ff::Zero::is_zero(&self.params.beta) &&
            !ark_ff::Zero::is_zero(&self.params.gamma) &&
            !ark_ff::Zero::is_zero(&self.params.delta)
        }
    }
    
    impl Default for Ceremony {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_field::F;
    use groth16_r1cs::{R1CS, LinearCombination};
    use groth16_qap::QAP;
    use rand::thread_rng;
    
    #[test]
    fn test_setup_params_generation() {
        let mut rng = thread_rng();
        let params = SetupParams::random(&mut rng);
        
        assert!(params.validate().is_ok());
        assert!(!params.alpha.is_zero());
        assert!(!params.beta.is_zero());
        assert!(!params.gamma.is_zero());
        assert!(!params.delta.is_zero());
        assert!(!params.s.is_zero());
    }
    
    #[test]
    fn test_crs_generation() {
        // Create simple R1CS: x * y = z
        let mut r1cs = R1CS::<F>::new(0);
        let x = r1cs.allocate_variable();
        let y = r1cs.allocate_variable();
        let z = r1cs.allocate_variable();
        
        r1cs.enforce_multiplication(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(y),
            LinearCombination::from_variable(z)
        );
        
        let qap = QAP::from_r1cs(&r1cs).unwrap();
        
        // Generate CRS with 1 public input (x)
        let mut rng = thread_rng();
        let crs = CRS::generate_random(&qap, 1, &mut rng).unwrap();
        
        assert_eq!(crs.pk.num_public, 1);
        assert_eq!(crs.vk.num_public, 1);
        assert_eq!(crs.pk.a_g1.len(), qap.num_variables);
        assert_eq!(crs.pk.b_g1.len(), qap.num_variables);
        assert_eq!(crs.pk.b_g2.len(), qap.num_variables);
        assert_eq!(crs.vk.ic_g1.len(), 2); // constant + 1 public input
    }
    
    #[test]
    fn test_ceremony_simulation() {
        let mut ceremony = ceremony::Ceremony::new();
        let mut rng = thread_rng();
        
        // Add multiple participants
        ceremony.add_participant("Alice".to_string(), &mut rng);
        ceremony.add_participant("Bob".to_string(), &mut rng);
        ceremony.add_participant("Charlie".to_string(), &mut rng);
        
        assert!(ceremony.verify());
        assert_eq!(ceremony.participants.len(), 3);
        
        let params = ceremony.finalize();
        assert!(params.validate().is_ok());
    }
}