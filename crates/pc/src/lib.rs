//! Simplified polynomial commitment schemes for PLONK
//!
//! This crate provides polynomial commitment functionality with support for:
//! - KZG commitments over BLS12-381 (default)
//! - Universal setup generation
//! - Basic opening proofs

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::{Rng, SeedableRng, rngs::StdRng}, vec::Vec, marker::PhantomData};
use plonk_field::{PlonkField, Polynomial as PlonkPolynomial};
use sha3::{Digest, Keccak256};

/// Error types for polynomial commitment operations
#[derive(Debug, thiserror::Error)]
pub enum PCError {
    #[error("Setup generation failed: {0}")]
    SetupFailed(String),
    #[error("Commitment failed: {0}")]
    CommitmentFailed(String),
    #[error("Proof generation failed: {0}")]
    ProofFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid polynomial degree: expected <= {max}, got {actual}")]
    InvalidDegree { max: usize, actual: usize },
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Trait for polynomial commitment engines
pub trait CommitmentEngine {
    type Params: Clone + CanonicalSerialize + CanonicalDeserialize;
    type CommitterKey: Clone + CanonicalSerialize + CanonicalDeserialize;
    type VerifierKey: Clone + CanonicalSerialize + CanonicalDeserialize;
    type Commitment: Clone + CanonicalSerialize + CanonicalDeserialize;
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// Generate universal parameters for a maximum degree
    fn setup<R: Rng>(max_degree: usize, rng: &mut R) -> Result<Self::Params, PCError>;

    /// Extract committer and verifier keys from universal parameters
    fn extract_keys(
        params: &Self::Params,
        max_degree: usize,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), PCError>;

    /// Commit to a polynomial
    fn commit(
        ck: &Self::CommitterKey,
        poly: &PlonkPolynomial,
    ) -> Result<Self::Commitment, PCError>;

    /// Generate an opening proof for a polynomial at a given point
    fn open(
        ck: &Self::CommitterKey,
        poly: &PlonkPolynomial,
        point: PlonkField,
    ) -> Result<Self::Proof, PCError>;

    /// Verify an opening proof
    fn verify(
        vk: &Self::VerifierKey,
        commitment: &Self::Commitment,
        point: PlonkField,
        value: PlonkField,
        proof: &Self::Proof,
    ) -> Result<bool, PCError>;
}

/// KZG polynomial commitment scheme over BLS12-381
#[derive(Debug, Clone)]
pub struct KZGEngine;

/// KZG commitment parameters (simplified)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGUniversalParams {
    /// Powers of tau in G1: [g, g^tau, g^tau^2, ..., g^tau^max_degree]
    pub powers_of_g: Vec<G1Affine>,
    /// Powers of tau in G2: [h, h^tau]  
    pub powers_of_h: Vec<G2Affine>,
    pub max_degree: usize,
}

/// KZG committer key (simplified)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGCommitterKey {
    pub powers_of_g: Vec<G1Affine>,
}

/// KZG verifier key (simplified)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGVerifierKey {
    pub g: G1Affine,
    pub h: G2Affine,
    pub tau_h: G2Affine,
}

/// KZG commitment (G1 element)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct KZGCommitmentWrapper {
    pub point: G1Affine,
}

/// KZG proof (G1 element)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGProofWrapper {
    pub point: G1Affine,
}

impl CommitmentEngine for KZGEngine {
    type Params = KZGUniversalParams;
    type CommitterKey = KZGCommitterKey;
    type VerifierKey = KZGVerifierKey;
    type Commitment = KZGCommitmentWrapper;
    type Proof = KZGProofWrapper;

    fn setup<R: Rng>(max_degree: usize, rng: &mut R) -> Result<Self::Params, PCError> {
        use ark_ec::Group;

        // Generate random tau (toxic waste)
        let tau = Fr::rand(rng);
        
        // Generate G1 generator
        let g = ark_bls12_381::G1Projective::generator();
        
        // Generate G2 generator  
        let h = ark_bls12_381::G2Projective::generator();

        // Compute powers of tau in G1: [g, g^tau, g^tau^2, ..., g^tau^max_degree]
        let mut powers_of_g = Vec::with_capacity(max_degree + 1);
        let mut current_power = Fr::one();
        for _ in 0..=max_degree {
            powers_of_g.push((g * current_power).into_affine());
            current_power *= tau;
        }

        // Compute powers of tau in G2: [h, h^tau]
        let powers_of_h = vec![
            h.into_affine(),
            (h * tau).into_affine(),
        ];

        Ok(KZGUniversalParams {
            powers_of_g,
            powers_of_h,
            max_degree,
        })
    }

    fn extract_keys(
        params: &Self::Params,
        max_degree: usize,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), PCError> {
        if max_degree > params.max_degree {
            return Err(PCError::InvalidDegree {
                max: params.max_degree,
                actual: max_degree,
            });
        }

        let ck = KZGCommitterKey {
            powers_of_g: params.powers_of_g[..=max_degree].to_vec(),
        };

        let vk = KZGVerifierKey {
            g: params.powers_of_g[0],
            h: params.powers_of_h[0],
            tau_h: params.powers_of_h[1],
        };

        Ok((ck, vk))
    }

    fn commit(
        ck: &Self::CommitterKey,
        poly: &PlonkPolynomial,
    ) -> Result<Self::Commitment, PCError> {
        use ark_ec::VariableBaseMSM;

        if poly.coeffs.len() > ck.powers_of_g.len() {
            return Err(PCError::CommitmentFailed(
                "Polynomial degree exceeds committer key".to_string()
            ));
        }

        // Compute commitment: sum(coeff_i * g^(tau^i))
        let scalars: Vec<Fr> = poly.coeffs.iter().map(|c| c.inner()).collect();
        let bases: Vec<G1Affine> = ck.powers_of_g[..poly.coeffs.len()].to_vec();
        
        let commitment = ark_bls12_381::G1Projective::msm(&bases, &scalars)
            .map_err(|e| PCError::CommitmentFailed(format!("{:?}", e)))?;

        Ok(KZGCommitmentWrapper {
            point: commitment.into_affine(),
        })
    }

    fn open(
        ck: &Self::CommitterKey,
        poly: &PlonkPolynomial,
        point: PlonkField,
    ) -> Result<Self::Proof, PCError> {
        use ark_ec::VariableBaseMSM;

        // Compute quotient polynomial q(x) = (p(x) - p(z)) / (x - z)
        let eval = poly.evaluate(point);
        
        // Build quotient polynomial coefficients
        let mut quotient_coeffs = Vec::new();
        
        // For simplification, we'll compute this directly
        // In practice, you'd use polynomial long division
        let z = point.inner();
        
        for i in 1..poly.coeffs.len() {
            let mut coeff = Fr::zero();
            for j in i..poly.coeffs.len() {
                let mut term = poly.coeffs[j].inner();
                // Multiply by binomial coefficient and power of z
                for _k in 0..(j - i) {
                    term *= z;
                }
                coeff += term;
            }
            quotient_coeffs.push(coeff);
        }

        if quotient_coeffs.is_empty() {
            quotient_coeffs.push(Fr::zero());
        }

        // Commit to quotient polynomial
        let bases: Vec<G1Affine> = ck.powers_of_g[..quotient_coeffs.len()].to_vec();
        let proof = ark_bls12_381::G1Projective::msm(&bases, &quotient_coeffs)
            .map_err(|e| PCError::ProofFailed(format!("{:?}", e)))?;

        Ok(KZGProofWrapper {
            point: proof.into_affine(),
        })
    }

    fn verify(
        vk: &Self::VerifierKey,
        commitment: &Self::Commitment,
        point: PlonkField,
        value: PlonkField,
        proof: &Self::Proof,
    ) -> Result<bool, PCError> {
        use ark_ec::pairing::Pairing;

        // Verify: e(C - v*g, h) = e(pi, tau*h - z*h)
        // This is equivalent to: e(C - v*g, h) = e(pi, (tau - z)*h)
        
        let g = vk.g.into_group();
        let h = vk.h.into_group();
        let tau_h = vk.tau_h.into_group();
        
        let v_g = g * value.inner();
        let lhs_g1 = commitment.point.into_group() - v_g;
        
        let z_h = h * point.inner();
        let rhs_g2 = tau_h - z_h;
        
        let lhs = Bls12_381::pairing(lhs_g1, h);
        let rhs = Bls12_381::pairing(proof.point, rhs_g2);
        
        Ok(lhs == rhs)
    }
}

/// Universal setup manager for polynomial commitments
#[derive(Debug)]
pub struct UniversalSetup<E: CommitmentEngine> {
    pub params: E::Params,
    pub max_degree: usize,
    _engine: PhantomData<E>,
}

impl<E: CommitmentEngine> UniversalSetup<E> {
    /// Generate a new universal setup
    pub fn new<R: Rng>(max_degree: usize, rng: &mut R) -> Result<Self, PCError> {
        let params = E::setup(max_degree, rng)?;
        Ok(Self {
            params,
            max_degree,
            _engine: PhantomData,
        })
    }

    /// Extract keys for a specific degree bound
    pub fn extract_keys(&self, degree: usize) -> Result<(E::CommitterKey, E::VerifierKey), PCError> {
        if degree > self.max_degree {
            return Err(PCError::InvalidDegree {
                max: self.max_degree,
                actual: degree,
            });
        }
        E::extract_keys(&self.params, degree)
    }

    /// Serialize the setup to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, PCError> {
        let mut bytes = Vec::new();
        self.params
            .serialize_compressed(&mut bytes)
            .map_err(|e| PCError::SerializationError(format!("{:?}", e)))?;
        Ok(bytes)
    }

    /// Deserialize setup from bytes
    pub fn from_bytes(bytes: &[u8], max_degree: usize) -> Result<Self, PCError> {
        let params = E::Params::deserialize_compressed(&mut &bytes[..])
            .map_err(|e| PCError::SerializationError(format!("{:?}", e)))?;
        Ok(Self {
            params,
            max_degree,
            _engine: PhantomData,
        })
    }
}

/// Fiat-Shamir transcript for generating random challenges
#[derive(Debug, Clone)]
pub struct Transcript {
    hasher: Keccak256,
}

impl Transcript {
    /// Create a new transcript
    pub fn new(label: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(label);
        Self { hasher }
    }

    /// Add data to the transcript
    pub fn append_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.hasher.update(label);
        self.hasher.update(data);
    }

    /// Add a field element to the transcript
    pub fn append_field(&mut self, label: &[u8], field: PlonkField) {
        let bytes = field.to_bytes();
        self.append_bytes(label, &bytes);
    }

    /// Generate a challenge field element
    pub fn challenge_field(&mut self, label: &[u8]) -> PlonkField {
        self.hasher.update(label);
        let hash = self.hasher.finalize_reset();
        
        // Convert hash to field element (simplified)
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        
        // Use rejection sampling to get a valid field element
        let mut rng = StdRng::seed_from_u64(
            u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
        );
        PlonkField::random(&mut rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_kzg_commitment_scheme() {
        let mut rng = test_rng();
        
        // Setup
        let max_degree = 10;
        let setup = UniversalSetup::<KZGEngine>::new(max_degree, &mut rng).unwrap();
        let (ck, vk) = setup.extract_keys(max_degree).unwrap();

        // Create a test polynomial: 2x^2 + 3x + 1
        let poly = PlonkPolynomial::new(vec![
            PlonkField::one(),
            PlonkField::from_u64(3),
            PlonkField::from_u64(2),
        ]);

        // Commit
        let commitment = KZGEngine::commit(&ck, &poly).unwrap();

        // Open at a random point
        let point = PlonkField::from_u64(5);
        let value = poly.evaluate(point);
        let proof = KZGEngine::open(&ck, &poly, point).unwrap();

        // Verify
        let is_valid = KZGEngine::verify(&vk, &commitment, point, value, &proof).unwrap();
        assert!(is_valid);

        // Test with wrong value
        let wrong_value = value + PlonkField::one();
        let is_valid = KZGEngine::verify(&vk, &commitment, point, wrong_value, &proof).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_transcript() {
        let mut transcript = Transcript::new(b"test");
        
        let field = PlonkField::from_u64(42);
        transcript.append_field(b"field", field);
        
        let challenge = transcript.challenge_field(b"challenge");
        
        // Challenges should be deterministic
        let mut transcript2 = Transcript::new(b"test");
        transcript2.append_field(b"field", field);
        let challenge2 = transcript2.challenge_field(b"challenge");
        
        assert_eq!(challenge, challenge2);
    }

    #[test]
    fn test_setup_serialization() {
        let mut rng = test_rng();
        let max_degree = 8;
        
        let setup = UniversalSetup::<KZGEngine>::new(max_degree, &mut rng).unwrap();
        let bytes = setup.to_bytes().unwrap();
        let recovered = UniversalSetup::<KZGEngine>::from_bytes(&bytes, max_degree).unwrap();
        
        // Test that we can extract keys from both setups
        let (ck1, _vk1) = setup.extract_keys(max_degree).unwrap();
        let (ck2, _vk2) = recovered.extract_keys(max_degree).unwrap();
        
        // Keys should be equivalent (test by using them)
        let poly = PlonkPolynomial::new(vec![PlonkField::one(), PlonkField::from_u64(2)]);
        let comm1 = KZGEngine::commit(&ck1, &poly).unwrap();
        let comm2 = KZGEngine::commit(&ck2, &poly).unwrap();
        
        assert_eq!(comm1, comm2);
    }
}