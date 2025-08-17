//! Commitment schemes (KZG, IPA) for Nova with recursion support.
//!
//! This crate provides polynomial commitment schemes that are essential for Nova's
//! recursive proving system. This implementation focuses on KZG commitments first.

pub use nova_core::*;

use ark_std::rand::Rng;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{
    kzg10::KZG10,
    PolynomialCommitment
};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use thiserror::Error;

/// Errors that can occur in commitment operations
#[derive(Debug, Error)]
pub enum CommitmentError {
    /// Setup failed
    #[error("Commitment setup failed: {0}")]
    SetupFailed(String),
    /// Commitment failed
    #[error("Commitment failed: {0}")]
    CommitmentFailed(String),
    /// Opening failed
    #[error("Opening failed: {0}")]
    OpeningFailed(String),
    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed,
    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}

/// Result type for commitment operations
pub type CommitmentResult<T> = Result<T, CommitmentError>;

/// Trait for polynomial commitment schemes compatible with Nova
pub trait NovaCommitmentScheme<F: PrimeField> {
    type SetupParams;
    type CommitterKey;
    type VerifierKey;
    type Commitment;
    type Proof;
    type Polynomial;

    /// Setup the commitment scheme
    fn setup<R: Rng>(
        max_degree: usize,
        rng: &mut R,
    ) -> CommitmentResult<Self::SetupParams>;

    /// Trim setup parameters to get committer and verifier keys
    fn trim(
        params: &Self::SetupParams,
        supported_degree: usize,
    ) -> CommitmentResult<(Self::CommitterKey, Self::VerifierKey)>;

    /// Commit to a polynomial
    fn commit(
        ck: &Self::CommitterKey,
        poly: &Self::Polynomial,
    ) -> CommitmentResult<Self::Commitment>;

    /// Open a commitment at a point
    fn open(
        ck: &Self::CommitterKey,
        poly: &Self::Polynomial,
        commitment: &Self::Commitment,
        point: F,
    ) -> CommitmentResult<Self::Proof>;

    /// Verify an opening proof
    fn verify(
        vk: &Self::VerifierKey,
        commitment: &Self::Commitment,
        point: F,
        value: F,
        proof: &Self::Proof,
    ) -> CommitmentResult<bool>;
}

/// KZG commitment scheme for Nova using arkworks
type KZGScheme = KZG10<Bls12_381, DensePolynomial<BlsFr>>;

/// KZG commitment scheme for Nova
pub struct NovaKZG;

impl NovaCommitmentScheme<BlsFr> for NovaKZG {
    type SetupParams = ark_poly_commit::kzg10::UniversalParams<Bls12_381>;
    type CommitterKey = ark_poly_commit::kzg10::Powers<Bls12_381>;
    type VerifierKey = ark_poly_commit::kzg10::VerifierKey<Bls12_381>;
    type Commitment = ark_poly_commit::kzg10::Commitment<Bls12_381>;
    type Proof = ark_poly_commit::kzg10::Proof<Bls12_381>;
    type Polynomial = DensePolynomial<BlsFr>;

    fn setup<R: Rng>(
        max_degree: usize,
        rng: &mut R,
    ) -> CommitmentResult<Self::SetupParams> {
        KZGScheme::setup(max_degree, false, rng)
            .map_err(|e| CommitmentError::SetupFailed(format!("{:?}", e)))
    }

    fn trim(
        params: &Self::SetupParams,
        supported_degree: usize,
    ) -> CommitmentResult<(Self::CommitterKey, Self::VerifierKey)> {
        KZGScheme::trim(params, supported_degree)
            .map_err(|e| CommitmentError::InvalidParameters(format!("{:?}", e)))
    }

    fn commit(
        ck: &Self::CommitterKey,
        poly: &Self::Polynomial,
    ) -> CommitmentResult<Self::Commitment> {
        KZGScheme::commit(ck, poly, None, None)
            .map(|(commitment, _)| commitment)
            .map_err(|e| CommitmentError::CommitmentFailed(format!("{:?}", e)))
    }

    fn open(
        ck: &Self::CommitterKey,
        poly: &Self::Polynomial,
        _commitment: &Self::Commitment,
        point: BlsFr,
    ) -> CommitmentResult<Self::Proof> {
        KZGScheme::open(ck, poly, point, &None)
            .map_err(|e| CommitmentError::OpeningFailed(format!("{:?}", e)))
    }

    fn verify(
        vk: &Self::VerifierKey,
        commitment: &Self::Commitment,
        point: BlsFr,
        value: BlsFr,
        proof: &Self::Proof,
    ) -> CommitmentResult<bool> {
        KZGScheme::check(vk, commitment, point, value, proof)
            .map_err(|_| CommitmentError::VerificationFailed)
    }
}

/// Commitment backend selector for Nova
pub enum CommitmentBackend {
    /// KZG commitment scheme (requires trusted setup)
    KZG,
}

/// Nova commitment manager that abstracts over different backends
pub struct NovaCommitment {
    backend: CommitmentBackend,
}

impl NovaCommitment {
    /// Create a new Nova commitment with the specified backend
    pub fn new(backend: CommitmentBackend) -> Self {
        Self { backend }
    }

    /// Get the backend type
    pub fn backend(&self) -> &CommitmentBackend {
        &self.backend
    }

    /// Setup commitment scheme with maximum degree
    pub fn setup_with_kzg<R: Rng>(max_degree: usize, rng: &mut R) -> CommitmentResult<
        <NovaKZG as NovaCommitmentScheme<BlsFr>>::SetupParams
    > {
        NovaKZG::setup(max_degree, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{test_rng, UniformRand};
    use ark_poly::{Polynomial, DenseUVPolynomial};

    #[test]
    fn test_kzg_commitment_scheme() {
        let mut rng = test_rng();
        let max_degree = 16;
        
        // Setup
        let params = NovaKZG::setup(max_degree, &mut rng).unwrap();
        let (ck, vk) = NovaKZG::trim(&params, max_degree).unwrap();
        
        // Create a random polynomial
        let poly = DensePolynomial::from_coefficients_vec(
            (0..=max_degree).map(|_| BlsFr::rand(&mut rng)).collect()
        );
        
        // Commit
        let commitment = NovaKZG::commit(&ck, &poly).unwrap();
        
        // Open at a random point
        let point = BlsFr::rand(&mut rng);
        let value = poly.evaluate(&point);
        let proof = NovaKZG::open(&ck, &poly, &commitment, point).unwrap();
        
        // Verify
        let verified = NovaKZG::verify(&vk, &commitment, point, value, &proof).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_nova_commitment_manager() {
        let mut rng = test_rng();
        let max_degree = 8;
        
        // Test KZG backend
        let kzg_commitment = NovaCommitment::new(CommitmentBackend::KZG);
        assert!(matches!(kzg_commitment.backend(), CommitmentBackend::KZG));
        
        let kzg_params = NovaCommitment::setup_with_kzg(max_degree, &mut rng).unwrap();
        assert!(kzg_params.powers_of_g.len() > max_degree);
    }

    #[test]
    fn test_commitment_errors() {
        let mut rng = test_rng();
        
        // Test invalid degree
        let result = NovaKZG::setup(0, &mut rng);
        assert!(result.is_err());
        
        // Test trim with degree larger than setup
        let params = NovaKZG::setup(8, &mut rng).unwrap();
        let result = NovaKZG::trim(&params, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_batch_operations() {
        let mut rng = test_rng();
        let max_degree = 8;
        let num_polys = 5;
        
        // Setup
        let params = NovaKZG::setup(max_degree, &mut rng).unwrap();
        let (ck, vk) = NovaKZG::trim(&params, max_degree).unwrap();
        
        // Create multiple polynomials
        let polys: Vec<DensePolynomial<BlsFr>> = (0..num_polys)
            .map(|_| {
                DensePolynomial::from_coefficients_vec(
                    (0..=max_degree).map(|_| BlsFr::rand(&mut rng)).collect()
                )
            })
            .collect();
        
        // Batch commit
        let commitments: Vec<_> = polys
            .iter()
            .map(|poly| NovaKZG::commit(&ck, poly).unwrap())
            .collect();
        
        // Batch open at the same point
        let point = BlsFr::rand(&mut rng);
        let proofs_and_values: Vec<_> = polys
            .iter()
            .zip(commitments.iter())
            .map(|(poly, commitment)| {
                let value = poly.evaluate(&point);
                let proof = NovaKZG::open(&ck, poly, commitment, point).unwrap();
                (proof, value)
            })
            .collect();
        
        // Batch verify
        for (i, ((proof, value), commitment)) in proofs_and_values.iter().zip(commitments.iter()).enumerate() {
            let verified = NovaKZG::verify(&vk, commitment, point, *value, proof).unwrap();
            assert!(verified, "Verification failed for polynomial {}", i);
        }
    }
}