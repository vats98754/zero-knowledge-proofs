//! Powers of tau ceremony utilities

use ark_ff::{Field, UniformRand};
use ark_std::{vec::Vec, rand::Rng};

/// Powers of tau contribution for multi-party setup
#[derive(Debug, Clone)]
pub struct PowersOfTauContribution {
    /// Tau powers in G1: [g1, g1^tau, g1^tau^2, ...]
    pub tau_powers_g1: Vec<Vec<u8>>,
    /// Tau powers in G2: [g2, g2^tau, g2^tau^2, ...]
    pub tau_powers_g2: Vec<Vec<u8>>,
    /// Alpha tau powers: [g1^alpha, g1^(alpha*tau), ...]
    pub alpha_tau_powers_g1: Vec<Vec<u8>>,
    /// Beta tau powers: [g1^beta, g1^(beta*tau), ...]
    pub beta_tau_powers_g1: Vec<Vec<u8>>,
    /// Beta in G2
    pub beta_g2: Vec<u8>,
}

/// Simulate a powers of tau ceremony for testing
pub fn simulate_powers_of_tau_ceremony<F: Field, R: Rng>(
    num_powers: usize,
    num_participants: usize,
    rng: &mut R,
) -> Vec<F> {
    let mut current_tau = F::from(1u64);
    
    // Simulate multiple participants each contributing randomness
    for _ in 0..num_participants {
        let participant_tau = F::rand(rng);
        current_tau *= participant_tau;
    }
    
    // Generate powers
    let mut powers = Vec::with_capacity(num_powers);
    let mut power = F::from(1u64);
    
    for _ in 0..num_powers {
        powers.push(power);
        power *= current_tau;
    }
    
    powers
}

/// Verify powers of tau contribution
pub fn verify_powers_of_tau<F: Field>(powers: &[F]) -> bool {
    if powers.is_empty() {
        return false;
    }
    
    // Check first power is 1
    if powers[0] != F::from(1u64) {
        return false;
    }
    
    // Check that powers form a geometric sequence
    for i in 1..powers.len() {
        if i + 1 < powers.len() {
            // Check: powers[i+1] / powers[i] == powers[1] / powers[0]
            // This ensures consistent tau across all powers
            let ratio1 = powers[i + 1] / powers[i];
            let ratio2 = powers[1] / powers[0];
            if ratio1 != ratio2 {
                return false;
            }
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;

    #[test]
    fn test_powers_of_tau_ceremony() {
        let mut rng = test_rng();
        let powers = simulate_powers_of_tau_ceremony::<Fr, _>(10, 3, &mut rng);
        
        assert_eq!(powers.len(), 10);
        assert!(verify_powers_of_tau(&powers));
    }

    #[test]
    fn test_powers_verification() {
        // Valid powers sequence
        let tau = Fr::from(7u64);
        let valid_powers = vec![
            Fr::from(1u64),   // tau^0
            tau,              // tau^1
            tau * tau,        // tau^2
            tau * tau * tau,  // tau^3
        ];
        assert!(verify_powers_of_tau(&valid_powers));
        
        // Invalid powers sequence
        let invalid_powers = vec![
            Fr::from(1u64),
            Fr::from(7u64),
            Fr::from(50u64), // Should be 49
            Fr::from(343u64),
        ];
        assert!(!verify_powers_of_tau(&invalid_powers));
    }
}