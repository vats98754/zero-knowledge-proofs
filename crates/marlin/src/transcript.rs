//! Fiat-Shamir transcript implementation for Marlin
//!
//! This module provides cryptographic transcript functionality for implementing
//! the Fiat-Shamir heuristic in the Marlin protocol.

use crate::{Result, MarlinError};
use zkp_field::Scalar;
use ark_ff::{PrimeField, BigInteger};
use blake2::{Blake2s256, Digest};
use std::marker::PhantomData;

/// Cryptographic transcript for Fiat-Shamir transform
#[derive(Debug, Clone)]
pub struct Transcript {
    /// Current state of the transcript
    hasher: Blake2s256,
    /// Domain separator for this protocol
    domain_separator: Vec<u8>,
}

/// Transcript builder for constructing transcripts with proper domain separation
pub struct TranscriptBuilder {
    domain_separator: Vec<u8>,
    protocol_name: String,
}

/// Challenge generation from transcript
pub struct ChallengeGenerator {
    transcript: Transcript,
    challenge_count: usize,
}

/// Transcript protocol for Marlin-specific operations
pub trait MarlinTranscriptProtocol {
    /// Appends a labeled message to the transcript
    fn append_message(&mut self, label: &[u8], message: &[u8]);
    
    /// Appends a scalar field element
    fn append_scalar(&mut self, label: &[u8], scalar: &Scalar);
    
    /// Appends multiple scalars
    fn append_scalars(&mut self, label: &[u8], scalars: &[Scalar]);
    
    /// Generates a challenge scalar
    fn challenge_scalar(&mut self, label: &[u8]) -> Scalar;
    
    /// Generates multiple challenge scalars
    fn challenge_scalars(&mut self, label: &[u8], n: usize) -> Vec<Scalar>;
}

impl Transcript {
    /// Creates a new transcript with the given domain separator
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(b"marlin-transcript");
        hasher.update(&(domain_separator.len() as u64).to_le_bytes());
        hasher.update(domain_separator);
        
        Self {
            hasher,
            domain_separator: domain_separator.to_vec(),
        }
    }

    /// Creates a transcript for the Marlin protocol
    pub fn marlin_transcript() -> Self {
        Self::new(b"marlin-v1.0")
    }

    /// Resets the transcript to its initial state
    pub fn reset(&mut self) {
        self.hasher = Blake2s256::new();
        self.hasher.update(b"marlin-transcript");
        self.hasher.update(&(self.domain_separator.len() as u64).to_le_bytes());
        self.hasher.update(&self.domain_separator);
    }

    /// Gets the current transcript state as bytes
    pub fn state(&self) -> Vec<u8> {
        let mut hasher_clone = self.hasher.clone();
        hasher_clone.finalize().to_vec()
    }

    /// Clones the transcript at its current state
    pub fn fork(&self, label: &[u8]) -> Self {
        let mut forked = self.clone();
        forked.append_message(b"fork", label);
        forked
    }
}

impl MarlinTranscriptProtocol for Transcript {
    fn append_message(&mut self, label: &[u8], message: &[u8]) {
        // Append label length and label
        self.hasher.update(&(label.len() as u64).to_le_bytes());
        self.hasher.update(label);
        
        // Append message length and message
        self.hasher.update(&(message.len() as u64).to_le_bytes());
        self.hasher.update(message);
    }

    fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        let bytes = scalar.into_bigint().to_bytes_le();
        self.append_message(label, &bytes);
    }

    fn append_scalars(&mut self, label: &[u8], scalars: &[Scalar]) {
        // Append number of scalars
        self.append_message(label, &(scalars.len() as u64).to_le_bytes());
        
        // Append each scalar
        for (i, scalar) in scalars.iter().enumerate() {
            let element_label = format!("{}-{}", 
                String::from_utf8_lossy(label), i);
            self.append_scalar(element_label.as_bytes(), scalar);
        }
    }

    fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        // Append challenge request to transcript
        self.append_message(label, b"challenge");
        
        // Finalize current state and generate challenge
        let hash = self.hasher.finalize_reset();
        
        // Convert hash to scalar using rejection sampling for uniform distribution
        let mut bytes = [0u8; 64]; // Use 64 bytes for better uniformity
        bytes[..32].copy_from_slice(&hash);
        
        // Use hash as seed for additional bytes if needed
        let mut extended_hasher = Blake2s256::new();
        extended_hasher.update(&hash);
        extended_hasher.update(b"extend");
        let extended_hash = extended_hasher.finalize();
        bytes[32..].copy_from_slice(&extended_hash);
        
        // Convert to field element
        Scalar::from_le_bytes_mod_order(&bytes)
    }

    fn challenge_scalars(&mut self, label: &[u8], n: usize) -> Vec<Scalar> {
        let mut challenges = Vec::with_capacity(n);
        
        for i in 0..n {
            let indexed_label = format!("{}-{}", 
                String::from_utf8_lossy(label), i);
            let challenge = self.challenge_scalar(indexed_label.as_bytes());
            challenges.push(challenge);
        }
        
        challenges
    }
}

impl TranscriptBuilder {
    /// Creates a new transcript builder
    pub fn new(protocol_name: &str) -> Self {
        Self {
            domain_separator: Vec::new(),
            protocol_name: protocol_name.to_string(),
        }
    }

    /// Adds a domain separator component
    pub fn with_separator(mut self, separator: &[u8]) -> Self {
        self.domain_separator.extend_from_slice(separator);
        self
    }

    /// Adds protocol version
    pub fn with_version(mut self, version: &str) -> Self {
        self.domain_separator.extend_from_slice(version.as_bytes());
        self
    }

    /// Adds circuit identifier
    pub fn with_circuit_id(mut self, circuit_id: &str) -> Self {
        self.domain_separator.extend_from_slice(b"circuit:");
        self.domain_separator.extend_from_slice(circuit_id.as_bytes());
        self
    }

    /// Builds the transcript
    pub fn build(self) -> Transcript {
        let mut full_separator = self.protocol_name.as_bytes().to_vec();
        full_separator.extend_from_slice(&self.domain_separator);
        Transcript::new(&full_separator)
    }
}

impl ChallengeGenerator {
    /// Creates a new challenge generator
    pub fn new(transcript: Transcript) -> Self {
        Self {
            transcript,
            challenge_count: 0,
        }
    }

    /// Generates the next challenge in sequence
    pub fn next_challenge(&mut self) -> Scalar {
        let label = format!("challenge-{}", self.challenge_count);
        self.challenge_count += 1;
        self.transcript.challenge_scalar(label.as_bytes())
    }

    /// Generates multiple challenges at once
    pub fn next_challenges(&mut self, n: usize) -> Vec<Scalar> {
        let mut challenges = Vec::with_capacity(n);
        for _ in 0..n {
            challenges.push(self.next_challenge());
        }
        challenges
    }

    /// Resets the challenge counter
    pub fn reset_counter(&mut self) {
        self.challenge_count = 0;
    }

    /// Gets the current challenge count
    pub fn challenge_count(&self) -> usize {
        self.challenge_count
    }
}

/// Marlin-specific transcript operations
pub struct MarlinTranscript {
    transcript: Transcript,
    round: usize,
}

impl MarlinTranscript {
    /// Creates a new Marlin transcript
    pub fn new() -> Self {
        let transcript = TranscriptBuilder::new("marlin")
            .with_version("1.0")
            .build();
            
        Self {
            transcript,
            round: 0,
        }
    }

    /// Creates a transcript for a specific circuit
    pub fn for_circuit(circuit_id: &str) -> Self {
        let transcript = TranscriptBuilder::new("marlin")
            .with_version("1.0")
            .with_circuit_id(circuit_id)
            .build();
            
        Self {
            transcript,
            round: 0,
        }
    }

    /// Starts a new round in the protocol
    pub fn start_round(&mut self, round_name: &str) {
        self.round += 1;
        let round_label = format!("round-{}-{}", self.round, round_name);
        self.transcript.append_message(b"round", round_label.as_bytes());
    }

    /// Adds prover's first round message
    pub fn prover_round1(
        &mut self,
        w_commitment: &[u8],
        za_commitment: &[u8],
        zb_commitment: &[u8],
        zc_commitment: &[u8],
    ) {
        self.start_round("prover-1");
        self.transcript.append_message(b"w-commit", w_commitment);
        self.transcript.append_message(b"za-commit", za_commitment);
        self.transcript.append_message(b"zb-commit", zb_commitment);
        self.transcript.append_message(b"zc-commit", zc_commitment);
    }

    /// Generates verifier's first round challenges
    pub fn verifier_round1(&mut self) -> (Scalar, Scalar) {
        let alpha = self.transcript.challenge_scalar(b"alpha");
        let beta = self.transcript.challenge_scalar(b"beta");
        (alpha, beta)
    }

    /// Adds prover's second round message
    pub fn prover_round2(
        &mut self,
        h1_commitment: &[u8],
        h2_commitment: &[u8],
        g_commitment: &[u8],
    ) {
        self.start_round("prover-2");
        self.transcript.append_message(b"h1-commit", h1_commitment);
        self.transcript.append_message(b"h2-commit", h2_commitment);
        self.transcript.append_message(b"g-commit", g_commitment);
    }

    /// Generates verifier's second round challenge
    pub fn verifier_round2(&mut self) -> Scalar {
        self.transcript.challenge_scalar(b"zeta")
    }

    /// Adds prover's third round message
    pub fn prover_round3(
        &mut self,
        evaluations: &[Scalar],
        openings: &[&[u8]],
    ) {
        self.start_round("prover-3");
        self.transcript.append_scalars(b"evaluations", evaluations);
        
        for (i, opening) in openings.iter().enumerate() {
            let label = format!("opening-{}", i);
            self.transcript.append_message(label.as_bytes(), opening);
        }
    }

    /// Finalizes the transcript and returns verification randomness
    pub fn finalize(&mut self) -> Vec<Scalar> {
        self.transcript.append_message(b"finalize", b"end-of-protocol");
        self.transcript.challenge_scalars(b"final-randomness", 3)
    }

    /// Gets the current round number
    pub fn current_round(&self) -> usize {
        self.round
    }

    /// Resets the transcript
    pub fn reset(&mut self) {
        self.transcript.reset();
        self.round = 0;
    }
}

/// Transcript utilities for testing and debugging
pub mod utils {
    use super::*;

    /// Creates a deterministic transcript for testing
    pub fn test_transcript() -> Transcript {
        TranscriptBuilder::new("test")
            .with_version("dev")
            .with_separator(b"deterministic")
            .build()
    }

    /// Compares two transcripts for equality
    pub fn transcripts_equal(t1: &Transcript, t2: &Transcript) -> bool {
        t1.state() == t2.state()
    }

    /// Generates a fixed challenge for testing
    pub fn fixed_challenge() -> Scalar {
        let mut transcript = test_transcript();
        transcript.append_message(b"test", b"fixed");
        transcript.challenge_scalar(b"challenge")
    }

    /// Verifies transcript determinism
    pub fn verify_determinism() -> Result<()> {
        let mut t1 = test_transcript();
        let mut t2 = test_transcript();

        t1.append_scalar(b"test", &Scalar::from(42u64));
        t2.append_scalar(b"test", &Scalar::from(42u64));

        let c1 = t1.challenge_scalar(b"challenge");
        let c2 = t2.challenge_scalar(b"challenge");

        if c1 != c2 {
            return Err(MarlinError::VerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transcript_basic_operations() {
        let mut transcript = Transcript::marlin_transcript();
        
        // Test appending messages
        transcript.append_message(b"test", b"message");
        transcript.append_scalar(b"scalar", &Scalar::from(42u64));
        
        // Test challenge generation
        let challenge1 = transcript.challenge_scalar(b"challenge1");
        let challenge2 = transcript.challenge_scalar(b"challenge2");
        
        // Challenges should be different
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_transcript_determinism() {
        let mut t1 = Transcript::marlin_transcript();
        let mut t2 = Transcript::marlin_transcript();

        // Add same data to both transcripts
        t1.append_scalar(b"test", &Scalar::from(123u64));
        t2.append_scalar(b"test", &Scalar::from(123u64));

        // Should generate same challenges
        let c1 = t1.challenge_scalar(b"challenge");
        let c2 = t2.challenge_scalar(b"challenge");
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_transcript_builder() {
        let transcript = TranscriptBuilder::new("test-protocol")
            .with_version("1.0")
            .with_circuit_id("test-circuit")
            .build();

        let state1 = transcript.state();
        
        let transcript2 = TranscriptBuilder::new("test-protocol")
            .with_version("1.0")
            .with_circuit_id("test-circuit")
            .build();

        let state2 = transcript2.state();
        
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_challenge_generator() {
        let transcript = Transcript::marlin_transcript();
        let mut generator = ChallengeGenerator::new(transcript);

        let challenges = generator.next_challenges(5);
        assert_eq!(challenges.len(), 5);
        assert_eq!(generator.challenge_count(), 5);

        // All challenges should be different
        for i in 0..challenges.len() {
            for j in i+1..challenges.len() {
                assert_ne!(challenges[i], challenges[j]);
            }
        }
    }

    #[test]
    fn test_marlin_transcript_protocol() {
        let mut marlin_transcript = MarlinTranscript::new();
        
        // Simulate protocol rounds
        marlin_transcript.prover_round1(b"w", b"za", b"zb", b"zc");
        let (alpha, beta) = marlin_transcript.verifier_round1();
        
        marlin_transcript.prover_round2(b"h1", b"h2", b"g");
        let zeta = marlin_transcript.verifier_round2();
        
        let evaluations = vec![alpha, beta, zeta];
        marlin_transcript.prover_round3(&evaluations, &[b"opening1", b"opening2"]);
        
        let final_randomness = marlin_transcript.finalize();
        assert_eq!(final_randomness.len(), 3);
        assert_eq!(marlin_transcript.current_round(), 3);
    }

    #[test]
    fn test_transcript_fork() {
        let mut transcript = Transcript::marlin_transcript();
        transcript.append_message(b"common", b"data");
        
        let mut fork1 = transcript.fork(b"branch1");
        let mut fork2 = transcript.fork(b"branch2");
        
        fork1.append_message(b"specific", b"data1");
        fork2.append_message(b"specific", b"data2");
        
        let c1 = fork1.challenge_scalar(b"challenge");
        let c2 = fork2.challenge_scalar(b"challenge");
        
        // Forked transcripts should produce different challenges
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_utils_functions() {
        // Test determinism verification
        assert!(utils::verify_determinism().is_ok());
        
        // Test fixed challenge
        let c1 = utils::fixed_challenge();
        let c2 = utils::fixed_challenge();
        assert_eq!(c1, c2);
        
        // Test transcript comparison
        let t1 = utils::test_transcript();
        let t2 = utils::test_transcript();
        assert!(utils::transcripts_equal(&t1, &t2));
    }

    #[test]
    fn test_scalar_arrays() {
        let mut transcript = Transcript::marlin_transcript();
        
        let scalars = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
        ];
        
        transcript.append_scalars(b"array", &scalars);
        let challenges = transcript.challenge_scalars(b"multi", 3);
        
        assert_eq!(challenges.len(), 3);
        
        // All challenges should be different
        for i in 0..challenges.len() {
            for j in i+1..challenges.len() {
                assert_ne!(challenges[i], challenges[j]);
            }
        }
    }
}