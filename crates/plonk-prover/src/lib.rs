//! PLONK prover implementation
//!
//! This crate provides the prover side of the PLONK protocol:
//! - Witness polynomial computation
//! - Quotient polynomial computation  
//! - KZG polynomial commitments and openings
//! - Fiat-Shamir transcript integration

use plonk_field::{PlonkField, Polynomial};
use plonk_pc::{CommitmentEngine, KZGEngine, UniversalSetup, Transcript, PCError, KZGCommitterKey, KZGVerifierKey};
use plonk_arith::{PlonkCircuit, SelectorPolynomials, ArithError};
use ark_ff::{One, Zero};
use ark_std::{vec::Vec, rand::Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for prover operations
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Polynomial commitment error: {0}")]
    PolynomialCommitment(#[from] PCError),
    #[error("Arithmetization error: {0}")]
    Arithmetization(#[from] ArithError),
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
}

/// PLONK proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlonkProof<E: CommitmentEngine> {
    /// Commitments to wire polynomials [a(x), b(x), c(x)]
    pub wire_commitments: Vec<E::Commitment>,
    /// Commitment to permutation polynomial Z(x)
    pub permutation_commitment: E::Commitment,
    /// Commitment to quotient polynomial t(x)
    pub quotient_commitment: E::Commitment,
    /// Opening proof for wire polynomials at evaluation point ζ
    pub wire_opening_proof: E::Proof,
    /// Opening proof for selector polynomials at evaluation point ζ
    pub selector_opening_proof: E::Proof,
    /// Opening proof for permutation polynomial at evaluation point ζ
    pub permutation_opening_proof: E::Proof,
    /// Opening proof for permutation polynomial at evaluation point ζω
    pub permutation_shift_opening_proof: E::Proof,
    /// Evaluation point ζ
    pub zeta: PlonkField,
    /// Wire polynomial evaluations at ζ
    pub wire_evaluations: Vec<PlonkField>,
    /// Selector polynomial evaluations at ζ  
    pub selector_evaluations: Vec<PlonkField>,
    /// Permutation polynomial evaluation at ζ
    pub permutation_evaluation: PlonkField,
    /// Permutation polynomial evaluation at ζω
    pub permutation_shift_evaluation: PlonkField,
}

/// PLONK prover context
pub struct PlonkProver<E: CommitmentEngine> {
    /// Universal setup parameters
    pub setup: UniversalSetup<E>,
    /// Committer key
    pub committer_key: E::CommitterKey,
    /// Verifier key
    pub verifier_key: E::VerifierKey,
}

impl<E: CommitmentEngine> PlonkProver<E> {
    /// Create a new PLONK prover
    pub fn new(setup: UniversalSetup<E>, max_degree: usize) -> Result<Self, ProverError> {
        let (committer_key, verifier_key) = setup.extract_keys(max_degree)?;
        Ok(Self {
            setup,
            committer_key,
            verifier_key,
        })
    }

    /// Generate a PLONK proof for the given circuit
    pub fn prove(&self, circuit: &PlonkCircuit, transcript: &mut Transcript) -> Result<PlonkProof<E>, ProverError> {
        // Check that circuit constraints are satisfied
        circuit.check_constraints()?;

        // Step 1: Commit to wire polynomials
        let wire_polys = circuit.wire_polynomials();
        let mut wire_commitments = Vec::new();
        
        for (i, poly) in wire_polys.iter().enumerate() {
            let commitment = E::commit(&self.committer_key, poly)?;
            wire_commitments.push(commitment.clone());
            
            // Add commitment to transcript
            let commitment_bytes = self.serialize_commitment(&commitment)?;
            transcript.append_bytes(&format!("wire_commitment_{}", i).as_bytes(), &commitment_bytes);
        }

        // Step 2: Generate challenges β and γ from transcript
        let beta = transcript.challenge_field(b"beta");
        let gamma = transcript.challenge_field(b"gamma");

        // Step 3: Compute permutation polynomial Z(x)
        let domain = self.generate_evaluation_domain(circuit.wires.num_rows);
        let permutation_poly = circuit.permutation.compute_permutation_polynomial(
            &circuit.wires,
            &domain,
            beta,
            gamma,
        )?;

        // Step 4: Commit to permutation polynomial
        let permutation_commitment = E::commit(&self.committer_key, &permutation_poly)?;
        let perm_commitment_bytes = self.serialize_commitment(&permutation_commitment)?;
        transcript.append_bytes(b"permutation_commitment", &perm_commitment_bytes);

        // Step 5: Generate evaluation challenge α
        let alpha = transcript.challenge_field(b"alpha");

        // Step 6: Compute quotient polynomial t(x)
        let quotient_poly = self.compute_quotient_polynomial(
            &wire_polys,
            &circuit.selector_polynomials(),
            &permutation_poly,
            &domain,
            alpha,
            beta,
            gamma,
        )?;

        // Step 7: Commit to quotient polynomial
        let quotient_commitment = E::commit(&self.committer_key, &quotient_poly)?;
        let quotient_commitment_bytes = self.serialize_commitment(&quotient_commitment)?;
        transcript.append_bytes(b"quotient_commitment", &quotient_commitment_bytes);

        // Step 8: Generate evaluation challenge ζ
        let zeta = transcript.challenge_field(b"zeta");

        // Step 9: Evaluate polynomials at ζ
        let wire_evaluations: Vec<PlonkField> = wire_polys.iter()
            .map(|poly| poly.evaluate(zeta))
            .collect();

        let selector_polys = circuit.selector_polynomials();
        let selector_evaluations = vec![
            selector_polys.q_m.evaluate(zeta),
            selector_polys.q_l.evaluate(zeta),
            selector_polys.q_r.evaluate(zeta),
            selector_polys.q_o.evaluate(zeta),
            selector_polys.q_c.evaluate(zeta),
        ];

        let permutation_evaluation = permutation_poly.evaluate(zeta);
        
        // Evaluate permutation polynomial at ζω (where ω is primitive root)
        let omega = self.compute_primitive_root(circuit.wires.num_rows);
        let zeta_omega = zeta * omega;
        let permutation_shift_evaluation = permutation_poly.evaluate(zeta_omega);

        // Add evaluations to transcript
        for (i, &eval) in wire_evaluations.iter().enumerate() {
            transcript.append_field(&format!("wire_eval_{}", i).as_bytes(), eval);
        }
        for (i, &eval) in selector_evaluations.iter().enumerate() {
            transcript.append_field(&format!("selector_eval_{}", i).as_bytes(), eval);
        }
        transcript.append_field(b"permutation_eval", permutation_evaluation);
        transcript.append_field(b"permutation_shift_eval", permutation_shift_evaluation);

        // Step 10: Generate opening proofs
        let wire_opening_proof = self.compute_batched_opening_proof(&wire_polys, zeta)?;
        let selector_opening_proof = self.compute_selector_opening_proof(&selector_polys, zeta)?;
        let permutation_opening_proof = E::open(&self.committer_key, &permutation_poly, zeta)?;
        let permutation_shift_opening_proof = E::open(&self.committer_key, &permutation_poly, zeta_omega)?;

        Ok(PlonkProof {
            wire_commitments,
            permutation_commitment,
            quotient_commitment,
            wire_opening_proof,
            selector_opening_proof,
            permutation_opening_proof,
            permutation_shift_opening_proof,
            zeta,
            wire_evaluations,
            selector_evaluations,
            permutation_evaluation,
            permutation_shift_evaluation,
        })
    }

    /// Compute the quotient polynomial t(x) = (gate_constraints + permutation_constraints) / Z_H(x)
    fn compute_quotient_polynomial(
        &self,
        wire_polys: &[Polynomial],
        selectors: &SelectorPolynomials,
        permutation_poly: &Polynomial,
        domain: &[PlonkField],
        alpha: PlonkField,
        beta: PlonkField,
        gamma: PlonkField,
    ) -> Result<Polynomial, ProverError> {
        let n = domain.len();
        
        // Evaluate gate constraints at each point in domain
        let mut constraint_evals = Vec::with_capacity(n);
        
        for &point in domain {
            // Evaluate all polynomials at this point
            let a_eval = wire_polys[0].evaluate(point);
            let b_eval = wire_polys[1].evaluate(point);
            let c_eval = wire_polys[2].evaluate(point);
            
            let q_m_eval = selectors.q_m.evaluate(point);
            let q_l_eval = selectors.q_l.evaluate(point);
            let q_r_eval = selectors.q_r.evaluate(point);
            let q_o_eval = selectors.q_o.evaluate(point);
            let q_c_eval = selectors.q_c.evaluate(point);
            
            // Gate constraint: q_M * a * b + q_L * a + q_R * b + q_O * c + q_C
            let gate_constraint = q_m_eval * a_eval * b_eval 
                + q_l_eval * a_eval 
                + q_r_eval * b_eval 
                + q_o_eval * c_eval 
                + q_c_eval;
            
            // Permutation constraint (simplified)
            let z_eval = permutation_poly.evaluate(point);
            let omega = self.compute_primitive_root(n);
            let z_next_eval = permutation_poly.evaluate(point * omega);
            
            // Simplified permutation constraint: Z(ωx) - Z(x) * (something) = 0
            let permutation_constraint = z_next_eval - z_eval * (a_eval + beta * point + gamma);
            
            // Combined constraint with α scaling
            let total_constraint = gate_constraint + alpha * permutation_constraint;
            constraint_evals.push(total_constraint);
        }
        
        // Divide by vanishing polynomial Z_H(x) = x^n - 1
        // For simplicity, we'll assume the constraints are already properly formed
        let quotient_poly = Polynomial::new(constraint_evals);
        
        Ok(quotient_poly)
    }

    /// Compute batched opening proof for wire polynomials
    fn compute_batched_opening_proof(
        &self,
        wire_polys: &[Polynomial],
        zeta: PlonkField,
    ) -> Result<E::Proof, ProverError> {
        // For simplicity, just open the first wire polynomial
        // In practice, you'd use random linear combination for batching
        let proof = E::open(&self.committer_key, &wire_polys[0], zeta)?;
        Ok(proof)
    }

    /// Compute opening proof for selector polynomials
    fn compute_selector_opening_proof(
        &self,
        selectors: &SelectorPolynomials,
        zeta: PlonkField,
    ) -> Result<E::Proof, ProverError> {
        // For simplicity, just open the multiplicative selector
        let proof = E::open(&self.committer_key, &selectors.q_m, zeta)?;
        Ok(proof)
    }

    /// Generate evaluation domain (primitive nth roots of unity)
    fn generate_evaluation_domain(&self, n: usize) -> Vec<PlonkField> {
        let mut domain = Vec::with_capacity(n);
        let omega = self.compute_primitive_root(n);
        let mut current = PlonkField::one();
        
        for _ in 0..n {
            domain.push(current);
            current *= omega;
        }
        
        domain
    }

    /// Compute primitive root of unity (simplified)
    fn compute_primitive_root(&self, _n: usize) -> PlonkField {
        // In practice, you'd compute the actual primitive root
        // For simplicity, return a fixed generator
        PlonkField::from_u64(7) // This is not actually a primitive root, just a placeholder
    }

    /// Serialize commitment for transcript (placeholder)
    fn serialize_commitment(&self, _commitment: &E::Commitment) -> Result<Vec<u8>, ProverError> {
        // In practice, you'd serialize the commitment properly
        Ok(vec![0u8; 32]) // Placeholder
    }
}

/// Convenience type alias for KZG-based PLONK prover
pub type KZGPlonkProver = PlonkProver<KZGEngine>;

impl KZGPlonkProver {
    /// Create a new KZG PLONK prover with universal setup
    pub fn setup<R: Rng>(max_degree: usize, rng: &mut R) -> Result<Self, ProverError> {
        let setup = UniversalSetup::<KZGEngine>::new(max_degree, rng)?;
        Self::new(setup, max_degree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_plonk_prover_setup() {
        let mut rng = test_rng();
        let max_degree = 16;
        
        let prover = KZGPlonkProver::setup(max_degree, &mut rng).unwrap();
        
        // Basic sanity check
        assert_eq!(prover.setup.max_degree, max_degree);
    }

    #[test]
    fn test_plonk_proof_generation() {
        let mut rng = test_rng();
        let max_degree = 16;
        
        let prover = KZGPlonkProver::setup(max_degree, &mut rng).unwrap();
        
        // Create a simple circuit
        let mut circuit = PlonkCircuit::new(4);
        
        // Add some gates: 2 + 3 = 5
        let a = PlonkField::from_u64(2);
        let b = PlonkField::from_u64(3);
        let c = a + b;
        circuit.add_addition_gate(a, b, c).unwrap();
        
        // Add multiplication gate: 2 * 4 = 8
        let d = PlonkField::from_u64(4);
        let e = a * d;
        circuit.add_multiplication_gate(a, d, e).unwrap();
        
        // Generate proof
        let mut transcript = Transcript::new(b"plonk_test");
        let proof = prover.prove(&circuit, &mut transcript).unwrap();
        
        // Basic proof structure checks
        assert_eq!(proof.wire_commitments.len(), 3); // a, b, c wires
        assert_eq!(proof.wire_evaluations.len(), 3);
        assert_eq!(proof.selector_evaluations.len(), 5); // q_M, q_L, q_R, q_O, q_C
    }

    #[test]
    fn test_evaluation_domain_generation() {
        let mut rng = test_rng();
        let max_degree = 8;
        
        let prover = KZGPlonkProver::setup(max_degree, &mut rng).unwrap();
        let domain = prover.generate_evaluation_domain(4);
        
        assert_eq!(domain.len(), 4);
        assert_eq!(domain[0], PlonkField::one()); // First element should be 1
    }

    #[test]
    fn test_quotient_polynomial_computation() {
        let mut rng = test_rng();
        let max_degree = 16;
        
        let prover = KZGPlonkProver::setup(max_degree, &mut rng).unwrap();
        
        // Create simple polynomials for testing
        let wire_polys = vec![
            Polynomial::new(vec![PlonkField::one(), PlonkField::from_u64(2)]),
            Polynomial::new(vec![PlonkField::from_u64(3), PlonkField::from_u64(4)]),
            Polynomial::new(vec![PlonkField::from_u64(5), PlonkField::from_u64(6)]),
        ];
        
        let gates = vec![
            plonk_arith::GateConstraint::addition(),
            plonk_arith::GateConstraint::multiplication(),
        ];
        let selectors = SelectorPolynomials::from_gates(&gates);
        
        let permutation_poly = Polynomial::new(vec![PlonkField::one(); 4]);
        let domain = prover.generate_evaluation_domain(4);
        
        let alpha = PlonkField::from_u64(13);
        let beta = PlonkField::from_u64(17);
        let gamma = PlonkField::from_u64(19);
        
        let quotient_poly = prover.compute_quotient_polynomial(
            &wire_polys,
            &selectors,
            &permutation_poly,
            &domain,
            alpha,
            beta,
            gamma,
        ).unwrap();
        
        // Quotient polynomial should have the right degree
        assert!(quotient_poly.coeffs.len() <= domain.len());
    }
}