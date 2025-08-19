//! Transcript operations for Nova's Fiat-Shamir transformation.
//!
//! This module provides transcript functionality for converting interactive
//! protocols into non-interactive ones using the Fiat-Shamir heuristic.

use crate::fields::NovaField;
use crate::errors::{NovaError, NovaResult};
use ark_ff::{PrimeField, BigInteger};
use ark_std::{vec::Vec, format};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// A transcript for the Fiat-Shamir transformation.
/// 
/// The transcript maintains a running hash of all protocol messages
/// and can be used to generate pseudo-random challenges.
#[derive(Debug, Clone)]
pub struct Transcript {
    /// Internal state of the transcript
    state: Vec<u8>,
    /// Label for the current protocol
    protocol_label: String,
}

impl Transcript {
    /// Creates a new transcript with a protocol label
    pub fn new(protocol_label: impl Into<String>) -> Self {
        let protocol_label = protocol_label.into();
        let mut transcript = Self {
            state: Vec::new(),
            protocol_label: protocol_label.clone(),
        };
        
        // Initialize with protocol label
        transcript.append_bytes(b"nova-protocol");
        transcript.append_bytes(protocol_label.as_bytes());
        
        transcript
    }

    /// Appends a label to the transcript
    pub fn append_label(&mut self, label: &str) {
        self.append_bytes(label.as_bytes());
    }

    /// Appends a field element to the transcript
    pub fn append_field_element(&mut self, element: &NovaField) {
        let bytes = field_to_bytes(element);
        self.append_bytes(&bytes);
    }

    /// Appends multiple field elements to the transcript
    pub fn append_field_elements(&mut self, elements: &[NovaField]) {
        for element in elements {
            self.append_field_element(element);
        }
    }

    /// Appends a u64 value to the transcript
    pub fn append_u64(&mut self, value: u64) {
        self.append_bytes(&value.to_le_bytes());
    }

    /// Appends arbitrary bytes to the transcript
    pub fn append_bytes(&mut self, bytes: &[u8]) {
        self.state.extend_from_slice(bytes);
    }

    /// Generates a challenge field element from the current transcript state
    pub fn challenge_field_element(&mut self, label: &str) -> NovaField {
        self.append_label(label);
        
        // Use a simple hash-based approach to generate randomness
        // In a production system, this should use a cryptographically secure
        // hash function like SHA-3 or BLAKE2
        let mut hasher = DefaultHasher::new();
        self.state.hash(&mut hasher);
        let hash_value = hasher.finish();
        
        // Convert hash to field element
        // This is a simplified approach; production code should use proper
        // hash-to-field algorithms
        NovaField::from(hash_value)
    }

    /// Generates multiple challenge field elements
    pub fn challenge_field_elements(&mut self, label: &str, count: usize) -> Vec<NovaField> {
        let mut challenges = Vec::with_capacity(count);
        for i in 0..count {
            let indexed_label = format!("{}-{}", label, i);
            challenges.push(self.challenge_field_element(&indexed_label));
        }
        challenges
    }

    /// Generates a challenge scalar (for use in linear combinations)
    pub fn challenge_scalar(&mut self, label: &str) -> NovaField {
        self.challenge_field_element(label)
    }

    /// Generates a batch of challenge scalars
    pub fn challenge_scalars(&mut self, label: &str, count: usize) -> Vec<NovaField> {
        self.challenge_field_elements(label, count)
    }

    /// Resets the transcript to its initial state
    pub fn reset(&mut self) {
        let protocol_label = self.protocol_label.clone();
        *self = Self::new(protocol_label);
    }

    /// Returns the current state size (for debugging)
    pub fn state_size(&self) -> usize {
        self.state.len()
    }

    /// Clones the transcript for branching protocols
    pub fn fork(&self, new_label: &str) -> Self {
        let mut forked = self.clone();
        forked.append_label(new_label);
        forked
    }
}

/// Converts a field element to bytes for transcript operations
fn field_to_bytes(element: &NovaField) -> Vec<u8> {
    // Convert field element to its canonical byte representation
    // This is a simplified version; production code should use
    // the field's canonical serialization
    let value = element.into_bigint();
    value.to_bytes_le()
}

/// Transcript builder for constructing transcripts with specific messages
#[derive(Debug, Clone)]
pub struct TranscriptBuilder {
    transcript: Transcript,
}

impl TranscriptBuilder {
    /// Creates a new transcript builder
    pub fn new(protocol_label: impl Into<String>) -> Self {
        Self {
            transcript: Transcript::new(protocol_label),
        }
    }

    /// Adds a message to the transcript
    pub fn message(mut self, label: &str, data: &[NovaField]) -> Self {
        self.transcript.append_label(label);
        self.transcript.append_field_elements(data);
        self
    }

    /// Adds a commitment to the transcript
    pub fn commitment(mut self, label: &str, commitment: &NovaField) -> Self {
        self.transcript.append_label(label);
        self.transcript.append_field_element(commitment);
        self
    }

    /// Adds instance data to the transcript
    pub fn instance(mut self, public_inputs: &[NovaField], commitments: &[NovaField]) -> Self {
        self.transcript.append_label("instance");
        self.transcript.append_field_elements(public_inputs);
        self.transcript.append_field_elements(commitments);
        self
    }

    /// Finalizes the transcript
    pub fn finalize(self) -> Transcript {
        self.transcript
    }
}

/// Verifier transcript that mirrors the prover's operations
#[derive(Debug, Clone)]
pub struct VerifierTranscript {
    inner: Transcript,
}

impl VerifierTranscript {
    /// Creates a new verifier transcript
    pub fn new(protocol_label: impl Into<String>) -> Self {
        Self {
            inner: Transcript::new(protocol_label),
        }
    }

    /// Appends a public message (should match prover's message)
    pub fn append_message(&mut self, label: &str, data: &[NovaField]) {
        self.inner.append_label(label);
        self.inner.append_field_elements(data);
    }

    /// Generates a challenge (should match prover's challenge)
    pub fn challenge(&mut self, label: &str) -> NovaField {
        self.inner.challenge_field_element(label)
    }

    /// Generates multiple challenges
    pub fn challenges(&mut self, label: &str, count: usize) -> Vec<NovaField> {
        self.inner.challenge_field_elements(label, count)
    }

    /// Verifies that the transcript state matches expected values
    pub fn verify_state(&self, expected_size: usize) -> NovaResult<()> {
        if self.inner.state_size() < expected_size {
            return Err(NovaError::transcript_error(
                "Transcript state is smaller than expected"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{vec, Zero};

    #[test]
    fn test_transcript_creation() {
        let transcript = Transcript::new("test-protocol");
        assert_eq!(transcript.protocol_label, "test-protocol");
        assert!(transcript.state_size() > 0); // Should contain protocol initialization
    }

    #[test]
    fn test_append_field_element() {
        let mut transcript = Transcript::new("test");
        let initial_size = transcript.state_size();
        
        transcript.append_field_element(&NovaField::from(42u64));
        assert!(transcript.state_size() > initial_size);
    }

    #[test]
    fn test_append_field_elements() {
        let mut transcript = Transcript::new("test");
        let initial_size = transcript.state_size();
        
        let elements = vec![
            NovaField::from(1u64),
            NovaField::from(2u64),
            NovaField::from(3u64),
        ];
        transcript.append_field_elements(&elements);
        assert!(transcript.state_size() > initial_size);
    }

    #[test]
    fn test_challenge_generation() {
        let mut transcript = Transcript::new("test");
        
        transcript.append_field_element(&NovaField::from(42u64));
        let challenge1 = transcript.challenge_field_element("challenge1");
        let challenge2 = transcript.challenge_field_element("challenge2");
        
        // Challenges should be different for different labels
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_challenge_determinism() {
        let mut transcript1 = Transcript::new("test");
        let mut transcript2 = Transcript::new("test");
        
        // Add the same data to both transcripts
        let data = vec![NovaField::from(1u64), NovaField::from(2u64)];
        transcript1.append_field_elements(&data);
        transcript2.append_field_elements(&data);
        
        // Challenges should be identical
        let challenge1 = transcript1.challenge_field_element("test-challenge");
        let challenge2 = transcript2.challenge_field_element("test-challenge");
        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_multiple_challenges() {
        let mut transcript = Transcript::new("test");
        transcript.append_field_element(&NovaField::from(42u64));
        
        let challenges = transcript.challenge_field_elements("batch", 5);
        assert_eq!(challenges.len(), 5);
        
        // All challenges should be different
        for i in 0..challenges.len() {
            for j in i+1..challenges.len() {
                assert_ne!(challenges[i], challenges[j]);
            }
        }
    }

    #[test]
    fn test_transcript_fork() {
        let mut transcript = Transcript::new("test");
        transcript.append_field_element(&NovaField::from(42u64));
        
        let forked = transcript.fork("branch");
        assert!(forked.state_size() >= transcript.state_size());
    }

    #[test]
    fn test_transcript_builder() {
        let public_inputs = vec![NovaField::from(1u64), NovaField::from(2u64)];
        let commitments = vec![NovaField::from(10u64), NovaField::from(20u64)];
        
        let transcript = TranscriptBuilder::new("test-protocol")
            .message("msg1", &[NovaField::from(42u64)])
            .commitment("comm1", &NovaField::from(99u64))
            .instance(&public_inputs, &commitments)
            .finalize();
        
        assert!(transcript.state_size() > 0);
    }

    #[test]
    fn test_verifier_transcript() {
        let mut verifier_transcript = VerifierTranscript::new("test");
        
        let data = vec![NovaField::from(1u64), NovaField::from(2u64)];
        verifier_transcript.append_message("test-message", &data);
        
        let challenge = verifier_transcript.challenge("test-challenge");
        assert_ne!(challenge, NovaField::zero());
        
        let challenges = verifier_transcript.challenges("batch", 3);
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_prover_verifier_consistency() {
        // Prover side
        let mut prover_transcript = Transcript::new("consistency-test");
        let data = vec![NovaField::from(123u64), NovaField::from(456u64)];
        prover_transcript.append_field_elements(&data);
        let prover_challenge = prover_transcript.challenge_field_element("challenge");
        
        // Verifier side
        let mut verifier_transcript = VerifierTranscript::new("consistency-test");
        verifier_transcript.append_message("", &data);
        let verifier_challenge = verifier_transcript.challenge("challenge");
        
        // Challenges should match
        assert_eq!(prover_challenge, verifier_challenge);
    }

    #[test]
    fn test_transcript_reset() {
        let mut transcript = Transcript::new("test");
        transcript.append_field_element(&NovaField::from(42u64));
        let size_before = transcript.state_size();
        
        transcript.reset();
        let size_after = transcript.state_size();
        
        // Size should be back to initial state (just protocol label)
        assert!(size_after < size_before);
    }
}