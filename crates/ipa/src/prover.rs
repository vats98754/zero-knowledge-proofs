//! Inner Product Argument prover implementation

use crate::InnerProductProof;
use bulletproofs_core::{
    BulletproofsResult, BulletproofsError, GeneratorSet, GroupElement, TranscriptProtocol,
    utils::*,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// Inner Product Argument prover
#[derive(Debug)]
pub struct InnerProductProver {
    generators: GeneratorSet,
}

impl InnerProductProver {
    /// Create a new IPA prover with the given generators
    pub fn new(generators: GeneratorSet) -> Self {
        Self { generators }
    }

    /// Create an inner product proof
    ///
    /// Proves knowledge of vectors `a` and `b` such that:
    /// `P = g^a * h^b * u^<a,b>`
    pub fn prove<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        transcript: &mut Transcript,
        a: &[Scalar],
        b: &[Scalar],
    ) -> BulletproofsResult<InnerProductProof> {
        if a.len() != b.len() {
            return Err(BulletproofsError::VectorLengthMismatch {
                expected: a.len(),
                actual: b.len(),
            });
        }

        let n = a.len();
        if n == 0 {
            return Err(BulletproofsError::InvalidParameters(
                "Vectors cannot be empty".to_string(),
            ));
        }

        // Ensure we have enough generators
        self.generators.ensure_capacity(&mut rng, n)?;

        // Pad vectors to next power of 2 if needed
        let mut a_vec = a.to_vec();
        let mut b_vec = b.to_vec();
        
        if !is_power_of_two(n) {
            a_vec = pad_to_power_of_two(a_vec);
            b_vec = pad_to_power_of_two(b_vec);
            self.generators.ensure_capacity(&mut rng, a_vec.len())?;
        }

        let padded_n = a_vec.len();

        // Initialize generator vectors for the proof
        let g_vec = self.generators.g_vec[..padded_n].to_vec();
        let h_vec = self.generators.h_vec[..padded_n].to_vec();

        // Compute initial commitment
        let p = self.generators.inner_product_commit(&a_vec, &b_vec)?;
        transcript.append_point(b"P", &p);

        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();

        // Recursive folding
        let mut current_a = a_vec;
        let mut current_b = b_vec;
        let mut current_g = g_vec;
        let mut current_h = h_vec;

        // Base case: if vector length is 1, no folding needed
        if current_a.len() == 1 {
            return Ok(InnerProductProof::new(vec![], vec![], current_a[0], current_b[0]));
        }

        while current_a.len() > 1 {
            let m = current_a.len() / 2;

            // Split vectors
            let (a_l, a_r) = current_a.split_at(m);
            let (b_l, b_r) = current_b.split_at(m);
            let (g_l, g_r) = current_g.split_at(m);
            let (h_l, h_r) = current_h.split_at(m);

            // Compute cross terms
            let c_l = inner_product(a_l, b_r)?;
            let c_r = inner_product(a_r, b_l)?;

            // L = g_R^{a_L} * h_L^{b_R} * u^{<a_L, b_R>}
            let l = GroupElement::multiscalar_mul(
                a_l.iter().cloned().chain(b_r.iter().cloned()).chain(std::iter::once(c_l)),
                g_r.iter().cloned().chain(h_l.iter().cloned()).chain(std::iter::once(self.generators.u)),
            );

            // R = g_L^{a_R} * h_R^{b_L} * u^{<a_R, b_L>}
            let r = GroupElement::multiscalar_mul(
                a_r.iter().cloned().chain(b_l.iter().cloned()).chain(std::iter::once(c_r)),
                g_l.iter().cloned().chain(h_r.iter().cloned()).chain(std::iter::once(self.generators.u)),
            );

            transcript.append_point(b"L", &l);
            transcript.append_point(b"R", &r);

            l_vec.push(l);
            r_vec.push(r);

            // Get challenge
            let x = transcript.challenge_scalar(b"x");
            let x_inv = x.invert();

            // Fold vectors
            let mut folded_a = Vec::with_capacity(m);
            let mut folded_b = Vec::with_capacity(m);
            let mut folded_g = Vec::with_capacity(m);
            let mut folded_h = Vec::with_capacity(m);

            for i in 0..m {
                // a' = a_L * x + a_R * x^{-1}
                folded_a.push(a_l[i] * x + a_r[i] * x_inv);
                // b' = b_L * x^{-1} + b_R * x
                folded_b.push(b_l[i] * x_inv + b_r[i] * x);
                // g' = g_L^{x^{-1}} * g_R^x
                folded_g.push(g_l[i] * x_inv + g_r[i] * x);
                // h' = h_L^x * h_R^{x^{-1}}
                folded_h.push(h_l[i] * x + h_r[i] * x_inv);
            }

            current_a = folded_a;
            current_b = folded_b;
            current_g = folded_g;
            current_h = folded_h;
        }

        // Base case: vectors of length 1
        let final_a = current_a[0];
        let final_b = current_b[0];

        Ok(InnerProductProof::new(l_vec, r_vec, final_a, final_b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use bulletproofs_core::bulletproofs_transcript;

    #[test]
    fn test_ipa_prove_simple() {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, 4);
        let mut prover = InnerProductProver::new(generators);

        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
        let b = vec![Scalar::from(5u64), Scalar::from(6u64), Scalar::from(7u64), Scalar::from(8u64)];

        let mut transcript = bulletproofs_transcript(b"ipa_test");
        let proof = prover.prove(&mut rng, &mut transcript, &a, &b).unwrap();

        // For vector of length 4, we should have log_2(4) = 2 folding rounds
        assert_eq!(proof.num_rounds(), 2);
        assert!(proof.validate_structure().is_ok());
    }

    #[test]
    fn test_ipa_prove_power_of_two() {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, 8);
        let mut prover = InnerProductProver::new(generators);

        let a = vec![Scalar::from(1u64); 8];
        let b = vec![Scalar::from(2u64); 8];

        let mut transcript = bulletproofs_transcript(b"ipa_test");
        let proof = prover.prove(&mut rng, &mut transcript, &a, &b).unwrap();

        // For vector of length 8, we should have log_2(8) = 3 folding rounds
        assert_eq!(proof.num_rounds(), 3);
    }

    #[test]
    fn test_ipa_prove_non_power_of_two() {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, 8);
        let mut prover = InnerProductProver::new(generators);

        let a = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let b = vec![Scalar::from(4u64), Scalar::from(5u64), Scalar::from(6u64)];

        let mut transcript = bulletproofs_transcript(b"ipa_test");
        let proof = prover.prove(&mut rng, &mut transcript, &a, &b).unwrap();

        // Vector is padded from 3 to 4, so log_2(4) = 2 folding rounds
        assert_eq!(proof.num_rounds(), 2);
    }

    #[test]
    fn test_ipa_prove_empty_vectors() {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, 4);
        let mut prover = InnerProductProver::new(generators);

        let a = vec![];
        let b = vec![];

        let mut transcript = bulletproofs_transcript(b"ipa_test");
        let result = prover.prove(&mut rng, &mut transcript, &a, &b);

        assert!(result.is_err());
    }

    #[test]
    fn test_ipa_prove_mismatched_lengths() {
        let mut rng = OsRng;
        let generators = GeneratorSet::new(&mut rng, 4);
        let mut prover = InnerProductProver::new(generators);

        let a = vec![Scalar::from(1u64), Scalar::from(2u64)];
        let b = vec![Scalar::from(3u64)];

        let mut transcript = bulletproofs_transcript(b"ipa_test");
        let result = prover.prove(&mut rng, &mut transcript, &a, &b);

        assert!(result.is_err());
    }
}