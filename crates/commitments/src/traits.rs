//! Commitment scheme traits and interfaces

use crate::CommitmentError;
use zkp_field::Scalar;
use ark_ec::CurveGroup;
use ark_std::rand::Rng;

type Result<T> = std::result::Result<T, CommitmentError>;

/// Trait for polynomial commitment schemes
pub trait CommitmentEngine: Clone + Send + Sync {
    /// Type representing a commitment to a polynomial
    type Commitment: Clone;
    
    /// Type representing a commitment opening proof
    type Opening: Clone;
    
    /// Type representing commitment parameters (e.g., SRS)
    type Parameters: Clone;
    
    /// Type representing a randomness value used in commitments
    type Randomness: Clone + Default;
    
    /// Generates parameters for the commitment scheme
    fn setup<R: Rng>(rng: &mut R, max_degree: usize) -> Result<Self::Parameters>;
    
    /// Commits to a polynomial with optional randomness
    fn commit(
        params: &Self::Parameters,
        coefficients: &[Scalar],
        randomness: Option<&Self::Randomness>,
    ) -> Result<Self::Commitment>;
    
    /// Opens a commitment at a given point
    fn open(
        params: &Self::Parameters,
        coefficients: &[Scalar],
        point: &Scalar,
        randomness: Option<&Self::Randomness>,
    ) -> Result<Self::Opening>;
    
    /// Verifies a commitment opening
    fn verify(
        params: &Self::Parameters,
        commitment: &Self::Commitment,
        point: &Scalar,
        value: &Scalar,
        opening: &Self::Opening,
    ) -> bool;
    
    /// Commits to multiple polynomials and returns commitments
    fn batch_commit(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        randomness: Option<&[Self::Randomness]>,
    ) -> Result<Vec<Self::Commitment>>;
    
    /// Opens multiple commitments at the same point
    fn batch_open(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        point: &Scalar,
        randomness: Option<&[Self::Randomness]>,
    ) -> Result<Self::Opening>;
    
    /// Verifies multiple commitment openings at the same point
    fn batch_verify(
        params: &Self::Parameters,
        commitments: &[Self::Commitment],
        point: &Scalar,
        values: &[Scalar],
        opening: &Self::Opening,
    ) -> bool;
}

/// Trait for commitment schemes that support degree bounds
pub trait BoundedCommitmentEngine: CommitmentEngine {
    /// Commits to a polynomial with an explicit degree bound
    fn commit_with_degree_bound(
        params: &Self::Parameters,
        coefficients: &[Scalar],
        degree_bound: usize,
        randomness: Option<&Self::Randomness>,
    ) -> Result<Self::Commitment>;
    
    /// Verifies a degree-bounded commitment opening
    fn verify_with_degree_bound(
        params: &Self::Parameters,
        commitment: &Self::Commitment,
        degree_bound: usize,
        point: &Scalar,
        value: &Scalar,
        opening: &Self::Opening,
    ) -> bool;
}

/// Trait for commitment schemes with aggregation support
pub trait AggregateCommitmentEngine: CommitmentEngine {
    /// Type representing an aggregated opening proof
    type AggregateOpening: Clone;
    
    /// Creates an aggregated opening for multiple polynomials at multiple points
    fn aggregate_open(
        params: &Self::Parameters,
        polynomials: &[&[Scalar]],
        points: &[Scalar],
        randomness: Option<&[Self::Randomness]>,
    ) -> Result<Self::AggregateOpening>;
    
    /// Verifies an aggregated opening
    fn aggregate_verify(
        params: &Self::Parameters,
        commitments: &[Self::Commitment],
        points: &[Scalar],
        values: &[Scalar],
        opening: &Self::AggregateOpening,
    ) -> bool;
}

/// Universal setup parameters for commitment schemes
#[derive(Clone, Debug)]
pub struct UniversalParams<G: CurveGroup> {
    /// Powers of the secret in the first group
    pub g_powers: Vec<G>,
    /// Powers of the secret in the second group (for pairings)
    pub h_powers: Vec<G>,
    /// Maximum degree supported
    pub max_degree: usize,
}

impl<G: CurveGroup> UniversalParams<G> {
    /// Creates new universal parameters
    pub fn new(g_powers: Vec<G>, h_powers: Vec<G>, max_degree: usize) -> Self {
        Self {
            g_powers,
            h_powers,
            max_degree,
        }
    }
    
    /// Returns the maximum supported degree
    pub fn max_degree(&self) -> usize {
        self.max_degree
    }
    
    /// Trims parameters for a specific degree
    pub fn trim(&self, degree: usize) -> Result<Self> {
        if degree > self.max_degree {
            return Err(CommitmentError::DegreeBoundExceeded);
        }
        
        Ok(Self {
            g_powers: self.g_powers[..=degree].to_vec(),
            h_powers: self.h_powers[..=degree].to_vec(),
            max_degree: degree,
        })
    }
}

/// Commitment key for polynomial commitments
#[derive(Clone, Debug)]
pub struct CommitmentKey<G: CurveGroup> {
    /// Powers of the secret for commitments
    pub powers: Vec<G>,
    /// Maximum degree
    pub max_degree: usize,
}

/// Verification key for polynomial commitments
#[derive(Clone, Debug)]
pub struct VerificationKey<G: CurveGroup> {
    /// Generator in the first group
    pub g: G,
    /// Generator in the second group
    pub h: G,
    /// Secret times generator in the second group
    pub beta_h: G,
}

#[cfg(test)]
mod tests {
    
    #[test]
    fn test_universal_params_trim() {
        // This is a placeholder test - would need actual curve group implementation
        // to test properly
    }
}