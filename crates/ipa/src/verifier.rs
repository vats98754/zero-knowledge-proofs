//! Inner Product Argument verifier implementation

use crate::InnerProductProof;
use bulletproofs_core::{
    BulletproofsResult, BulletproofsError, GeneratorSet, GroupElement, TranscriptProtocol,
    utils::*,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// Inner Product Argument verifier
#[derive(Debug)]
pub struct InnerProductVerifier {
    generators: GeneratorSet,
}

impl InnerProductVerifier {
    /// Create a new IPA verifier with the given generators
    pub fn new(generators: GeneratorSet) -> Self {
        Self { generators }
    }

    /// Verify an inner product proof
    ///
    /// Verifies that the proof corresponds to the commitment `P` with the claimed inner product.
    pub fn verify<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        transcript: &mut Transcript,
        proof: &InnerProductProof,
        p: &GroupElement,
        n: usize,
    ) -> BulletproofsResult<bool> {
        // Validate proof structure
        proof.validate_structure()?;

        if n == 0 {
            return Err(BulletproofsError::InvalidParameters(
                "Vector length cannot be zero".to_string(),
            ));
        }

        // Pad to next power of 2 if needed
        let padded_n = if is_power_of_two(n) { n } else { next_power_of_two(n) };
        
        // Check that proof has correct number of rounds
        let expected_rounds = if padded_n == 1 { 0 } else { (padded_n as f64).log2() as usize };
        if proof.num_rounds() != expected_rounds {
            return Err(BulletproofsError::InvalidProof(format!(
                "Expected {} rounds for vector length {}, got {}",
                expected_rounds, n, proof.num_rounds()
            )));
        }

        // Ensure we have enough generators
        self.generators.ensure_capacity(&mut rng, padded_n)?;

        // Add P to transcript
        transcript.append_point(b"P", p);

        // Handle base case (no folding)
        if proof.num_rounds() == 0 {
            // For vectors of length 1, just verify: P = g^a * h^b * u^{a*b}
            let inner_product = proof.a * proof.b;
            let expected = GroupElement::multiscalar_mul(
                [proof.a, proof.b, inner_product],
                [self.generators.g_vec[0], self.generators.h_vec[0], self.generators.u],
            );
            return Ok(*p == expected);
        }

        // Decompress proof elements
        let l_vec = proof.decompress_l_vec()?;
        let r_vec = proof.decompress_r_vec()?;

        // Add L and R values to transcript and compute challenges
        let mut challenges = Vec::with_capacity(proof.num_rounds());
        for (l, r) in l_vec.iter().zip(r_vec.iter()) {
            transcript.append_point(b"L", l);
            transcript.append_point(b"R", r);
            challenges.push(transcript.challenge_scalar(b"x"));
        }

        // Compute challenge products for efficient verification
        let mut challenges_inv = Vec::with_capacity(challenges.len());
        for x in &challenges {
            challenges_inv.push(x.invert());
        }

        // Compute s scalars for generator combination
        let s_scalars = self.compute_s_scalars(&challenges, &challenges_inv, padded_n)?;

        // Verify the final equation
        self.verify_final_equation(p, &l_vec, &r_vec, &challenges, &challenges_inv, &s_scalars, proof)
    }

    /// Compute the s scalars for combining generators efficiently  
    fn compute_s_scalars(
        &self,
        challenges: &[Scalar],
        challenges_inv: &[Scalar],
        n: usize,
    ) -> BulletproofsResult<(Vec<Scalar>, Vec<Scalar>)> {
        let mut s_l = vec![Scalar::ONE; n];
        let mut s_r = vec![Scalar::ONE; n];

        // For each challenge (from most significant to least significant)
        for (round, (x, x_inv)) in challenges.iter().zip(challenges_inv.iter()).enumerate() {
            let bit_position = challenges.len() - 1 - round; // MSB first
            
            for i in 0..n {
                // Check if bit at position bit_position is set (counting from LSB)
                if (i >> bit_position) & 1 == 1 {
                    s_l[i] *= x;
                    s_r[i] *= x_inv;
                } else {
                    s_l[i] *= x_inv;
                    s_r[i] *= x;
                }
            }
        }

        Ok((s_l, s_r))
    }

    /// Verify the final equation of the IPA
    fn verify_final_equation(
        &self,
        p: &GroupElement,
        l_vec: &[GroupElement],
        r_vec: &[GroupElement],
        challenges: &[Scalar],
        challenges_inv: &[Scalar],
        s_scalars: &(Vec<Scalar>, Vec<Scalar>),
        proof: &InnerProductProof,
    ) -> BulletproofsResult<bool> {
        let (s_l, s_r) = s_scalars;
        let n = s_l.len();

        // Compute the left side: P + sum(x_i^2 * L_i) + sum(x_i^{-2} * R_i)
        let mut left_side = *p;

        for (i, (l, r)) in l_vec.iter().zip(r_vec.iter()).enumerate() {
            let x = challenges[i];
            let x_inv = challenges_inv[i];
            let x_sq = x * x;
            let x_inv_sq = x_inv * x_inv;

            left_side = left_side + (*l * x_sq) + (*r * x_inv_sq);
        }

        // Compute the right side: g'^a * h'^b * u^{a*b}
        // where g' and h' are the folded generators
        let inner_product = proof.a * proof.b;

        // The folded generators are linear combinations of the original generators
        // g' = sum(s_l[i] * g[i]) and h' = sum(s_r[i] * h[i])
        let folded_g = GroupElement::multiscalar_mul(
            s_l.iter().cloned(),
            self.generators.g_vec[..n].iter().cloned(),
        );
        
        let folded_h = GroupElement::multiscalar_mul(
            s_r.iter().cloned(),
            self.generators.h_vec[..n].iter().cloned(),
        );

        let right_side = folded_g * proof.a + folded_h * proof.b + GroupElement::from(self.generators.u) * inner_product;

        Ok(left_side == right_side)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InnerProductProver;
    use rand::rngs::OsRng;
    use bulletproofs_core::bulletproofs_transcript;

    fn test_ipa_round_trip(vector_length: usize) {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, next_power_of_two(vector_length));
        
        // Create prover and verifier
        let mut prover = InnerProductProver::new(generators.clone());
        let mut verifier = InnerProductVerifier::new(generators.clone());

        // Generate random vectors
        let a: Vec<Scalar> = (0..vector_length).map(|i| Scalar::from((i + 1) as u64)).collect();
        let b: Vec<Scalar> = (0..vector_length).map(|i| Scalar::from((i + 10) as u64)).collect();

        // Compute commitment
        let commitment = generators.inner_product_commit(&a, &b).unwrap();

        // Generate proof
        let mut prove_transcript = bulletproofs_transcript(b"ipa_test");
        let proof = prover.prove(&mut rng, &mut prove_transcript, &a, &b).unwrap();

        // Verify proof
        let mut verify_transcript = bulletproofs_transcript(b"ipa_test");
        let result = verifier.verify(&mut rng, &mut verify_transcript, &proof, &commitment, vector_length).unwrap();

        assert!(result, "Proof verification failed for vector length {}", vector_length);
    }

    #[test]
    fn test_ipa_verification_length_1() {
        test_ipa_round_trip(1);
    }

    #[test]
    fn test_ipa_verification_length_2() {
        test_ipa_round_trip(2);
    }

    #[test]
    fn test_ipa_verification_length_4() {
        test_ipa_round_trip(4);
    }

    #[test]
    fn test_ipa_verification_length_8() {
        test_ipa_round_trip(8);
    }

    #[test]
    fn test_ipa_verification_non_power_of_two() {
        test_ipa_round_trip(3);
        test_ipa_round_trip(5);
        test_ipa_round_trip(7);
    }

    #[test]
    fn test_ipa_verification_larger_vectors() {
        test_ipa_round_trip(16);
        test_ipa_round_trip(32);
    }

    #[test]
    fn test_invalid_proof_wrong_rounds() {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, 8);
        let mut verifier = InnerProductVerifier::new(generators);

        // Create a proof with wrong number of rounds
        let l_vec = vec![GroupElement::identity(); 2]; // Should be 3 for n=8
        let r_vec = vec![GroupElement::identity(); 2];
        let proof = InnerProductProof::new(l_vec, r_vec, Scalar::from(1u64), Scalar::from(2u64));

        let commitment = GroupElement::identity();
        let mut transcript = bulletproofs_transcript(b"ipa_test");
        
        let result = verifier.verify(&mut rng, &mut transcript, &proof, &commitment, 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_forge_proof_detection() {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, 4);
        let mut verifier = InnerProductVerifier::new(generators.clone());

        // Create a valid commitment for vectors [1,2,3,4] and [5,6,7,8]
        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
        let b = vec![Scalar::from(5u64), Scalar::from(6u64), Scalar::from(7u64), Scalar::from(8u64)];
        let commitment = generators.inner_product_commit(&a, &b).unwrap();

        // Try to forge a proof with different final values
        let l_vec = vec![GroupElement::identity(); 2];
        let r_vec = vec![GroupElement::identity(); 2];
        let forged_proof = InnerProductProof::new(
            l_vec, 
            r_vec, 
            Scalar::from(99u64), // Wrong value
            Scalar::from(99u64)  // Wrong value
        );

        let mut transcript = bulletproofs_transcript(b"ipa_test");
        let result = verifier.verify(&mut rng, &mut transcript, &forged_proof, &commitment, 4).unwrap();
        
        assert!(!result, "Forged proof should not verify");
    }
}