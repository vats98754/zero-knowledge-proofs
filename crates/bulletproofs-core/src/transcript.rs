//! Transcript management for Fiat-Shamir heuristic

use crate::GroupElement;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// Extension trait for Transcript to add Bulletproofs-specific methods
pub trait TranscriptProtocol {
    /// Append a group element to the transcript
    fn append_point(&mut self, label: &'static [u8], point: &GroupElement);
    
    /// Append a scalar to the transcript
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    
    /// Append a vector of scalars to the transcript
    fn append_scalar_vector(&mut self, label: &'static [u8], scalars: &[Scalar]);
    
    /// Challenge scalar from transcript
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    
    /// Challenge vector of scalars from transcript
    fn challenge_scalar_vector(&mut self, label: &'static [u8], length: usize) -> Vec<Scalar>;
}

impl TranscriptProtocol for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &GroupElement) {
        self.append_message(label, point.compress().as_bytes());
    }
    
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }
    
    fn append_scalar_vector(&mut self, label: &'static [u8], scalars: &[Scalar]) {
        self.append_message(b"vector_length", &(scalars.len() as u64).to_le_bytes());
        self.append_message(label, b"vector_start");
        for scalar in scalars.iter() {
            self.append_message(b"element", scalar.as_bytes());
        }
        self.append_message(label, b"vector_end");
    }
    
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
    
    fn challenge_scalar_vector(&mut self, label: &'static [u8], length: usize) -> Vec<Scalar> {
        let mut result = Vec::with_capacity(length);
        self.append_message(label, b"challenge_vector_start");
        self.append_message(b"vector_length", &(length as u64).to_le_bytes());
        for _ in 0..length {
            let mut buf = [0u8; 64];
            self.challenge_bytes(b"element", &mut buf);
            result.push(Scalar::from_bytes_mod_order_wide(&buf));
        }
        self.append_message(label, b"challenge_vector_end");
        result
    }
}

/// Create a new transcript for Bulletproofs with domain separation
pub fn bulletproofs_transcript(domain_label: &'static [u8]) -> Transcript {
    let mut transcript = Transcript::new(b"Bulletproofs");
    transcript.append_message(b"domain", domain_label);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;

    #[test]
    fn test_transcript_point_append() {
        let mut transcript = bulletproofs_transcript(b"test");
        let point = GroupElement::from(RistrettoPoint::identity());
        
        transcript.append_point(b"test_point", &point);
        
        // Should be able to generate challenges after appending
        let challenge = transcript.challenge_scalar(b"challenge");
        assert_ne!(challenge, Scalar::ZERO);
    }

    #[test]
    fn test_transcript_deterministic() {
        let point = GroupElement::from(RistrettoPoint::identity());
        let scalar = Scalar::from(42u64);
        
        // Create two identical transcripts
        let mut transcript1 = bulletproofs_transcript(b"test");
        let mut transcript2 = bulletproofs_transcript(b"test");
        
        // Append same data to both
        transcript1.append_point(b"point", &point);
        transcript1.append_scalar(b"scalar", &scalar);
        
        transcript2.append_point(b"point", &point);
        transcript2.append_scalar(b"scalar", &scalar);
        
        // Should generate same challenges
        let challenge1 = transcript1.challenge_scalar(b"challenge");
        let challenge2 = transcript2.challenge_scalar(b"challenge");
        
        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_scalar_vector_append() {
        let mut transcript = bulletproofs_transcript(b"test");
        let scalars = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        
        transcript.append_scalar_vector(b"scalars", &scalars);
        
        let challenge = transcript.challenge_scalar(b"challenge");
        assert_ne!(challenge, Scalar::ZERO);
    }

    #[test]
    fn test_challenge_vector() {
        let mut transcript = bulletproofs_transcript(b"test");
        
        let challenges = transcript.challenge_scalar_vector(b"challenges", 3);
        
        assert_eq!(challenges.len(), 3);
        // All challenges should be different (with very high probability)
        assert_ne!(challenges[0], challenges[1]);
        assert_ne!(challenges[1], challenges[2]);
        assert_ne!(challenges[0], challenges[2]);
    }
}