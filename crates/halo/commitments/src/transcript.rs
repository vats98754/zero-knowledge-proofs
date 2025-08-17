//! Transcript utilities for Fiat-Shamir transformation
//!
//! This module provides a wrapper around the Merlin transcript library
//! for use in Halo's non-interactive proof generation.

use crate::{Scalar, GroupElement};
use ff::PrimeField;
use group::prime::PrimeCurveAffine;
use merlin::Transcript as MerlinTranscript;

/// Trait for writing to a transcript
pub trait TranscriptWrite {
    /// Append a label and message to the transcript
    fn append_message(&mut self, label: &'static [u8], message: &[u8]);
    
    /// Append a scalar field element to the transcript
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, &scalar.to_repr());
    }
    
    /// Append a group element to the transcript
    fn append_point(&mut self, label: &'static [u8], point: &GroupElement) {
        self.append_message(label, &point.to_compressed());
    }
    
    /// Append multiple scalars to the transcript
    fn append_scalars(&mut self, label: &'static [u8], scalars: &[Scalar]) {
        // Add count first
        self.append_message(label, &(scalars.len() as u32).to_le_bytes());
        // Add each scalar
        for scalar in scalars {
            self.append_scalar(b"scalar-item", scalar);
        }
    }
    
    /// Append multiple points to the transcript
    fn append_points(&mut self, label: &'static [u8], points: &[GroupElement]) {
        // Add count first
        self.append_message(label, &(points.len() as u32).to_le_bytes());
        // Add each point
        for point in points {
            self.append_point(b"point-item", point);
        }
    }
}

/// Trait for reading from a transcript
pub trait TranscriptRead: TranscriptWrite {
    /// Challenge a scalar from the transcript
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    
    /// Challenge multiple scalars from the transcript
    fn challenge_scalars(&mut self, label: &'static [u8], count: usize) -> Vec<Scalar> {
        let mut scalars = Vec::with_capacity(count);
        for i in 0..count {
            // Use a fixed label with index embedded in transcript state
            self.append_message(b"challenge-index", &(i as u32).to_le_bytes());
            scalars.push(self.challenge_scalar(label));
        }
        scalars
    }
}

/// Halo transcript wrapper around Merlin
#[derive(Clone)]
pub struct Transcript {
    transcript: MerlinTranscript,
}

impl Transcript {
    /// Create a new transcript with the given label
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            transcript: MerlinTranscript::new(label),
        }
    }
    
    /// Fork the transcript for parallel operations
    pub fn fork(&self, label: &'static [u8]) -> Self {
        let mut new_transcript = self.clone();
        new_transcript.transcript.append_message(b"fork", label);
        new_transcript
    }
}

impl TranscriptWrite for Transcript {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.transcript.append_message(label, message);
    }
}

impl TranscriptRead for Transcript {
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label, &mut buf);
        
        // Reduce the 64-byte challenge modulo the scalar field order
        Scalar::from_bytes_wide(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::thread_rng;
    
    #[test]
    fn test_transcript_deterministic() {
        let mut transcript1 = Transcript::new(b"test");
        let mut transcript2 = Transcript::new(b"test");
        
        let scalar = Scalar::random(&mut thread_rng());
        
        transcript1.append_scalar(b"scalar", &scalar);
        transcript2.append_scalar(b"scalar", &scalar);
        
        let challenge1 = transcript1.challenge_scalar(b"challenge");
        let challenge2 = transcript2.challenge_scalar(b"challenge");
        
        assert_eq!(challenge1, challenge2);
    }
    
    #[test]
    fn test_transcript_different_inputs() {
        let mut transcript1 = Transcript::new(b"test");
        let mut transcript2 = Transcript::new(b"test");
        
        let scalar1 = Scalar::random(&mut thread_rng());
        let scalar2 = Scalar::random(&mut thread_rng());
        
        transcript1.append_scalar(b"scalar", &scalar1);
        transcript2.append_scalar(b"scalar", &scalar2);
        
        let challenge1 = transcript1.challenge_scalar(b"challenge");
        let challenge2 = transcript2.challenge_scalar(b"challenge");
        
        // Should be different with very high probability
        assert_ne!(challenge1, challenge2);
    }
    
    #[test]
    fn test_transcript_fork() {
        let mut base_transcript = Transcript::new(b"test");
        base_transcript.append_scalar(b"base", &Scalar::one());
        
        let mut fork1 = base_transcript.fork(b"fork1");
        let mut fork2 = base_transcript.fork(b"fork2");
        
        let challenge1 = fork1.challenge_scalar(b"challenge");
        let challenge2 = fork2.challenge_scalar(b"challenge");
        
        // Forks should produce different challenges
        assert_ne!(challenge1, challenge2);
    }
}