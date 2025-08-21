//! Merkle tree commitments for STARK proofs
//! 
//! This crate provides efficient Merkle tree implementations for committing to
//! polynomial evaluations in STARK proof systems.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use stark_field::{F, GoldilocksField};
use std::collections::HashMap;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

#[cfg(feature = "blake2")]
use blake2::{Blake2s256, Digest as Blake2Digest};

#[cfg(feature = "sha3")]
use sha3::{Keccak256, Digest as Sha3Digest};

/// Hash digest type - 32 bytes
pub type Hash = [u8; 32];

/// Errors that can occur when working with Merkle trees
#[derive(Error, Debug)]
pub enum MerkleError {
    /// Invalid leaf index
    #[error("Invalid leaf index: {index} >= {tree_size}")]
    InvalidLeafIndex { 
        /// The invalid index
        index: usize, 
        /// The tree size
        tree_size: usize 
    },
    
    /// Invalid proof length
    #[error("Invalid proof length: expected {expected}, got {actual}")]
    InvalidProofLength { 
        /// Expected proof length
        expected: usize, 
        /// Actual proof length
        actual: usize 
    },
    
    /// Proof verification failed
    #[error("Merkle proof verification failed")]
    ProofVerificationFailed,
    
    /// Tree construction failed
    #[error("Tree construction failed: {message}")]
    TreeConstructionFailed { 
        /// Error message
        message: String 
    },
    
    /// Unsupported tree size
    #[error("Unsupported tree size: {size}. Must be a power of 2")]
    UnsupportedTreeSize { 
        /// The unsupported size
        size: usize 
    },
}

/// Hasher trait for different hash functions
pub trait Hasher: Send + Sync {
    /// Hash a single field element
    fn hash_field_element(&self, element: &GoldilocksField) -> Hash;
    
    /// Hash a slice of field elements
    fn hash_field_elements(&self, elements: &[GoldilocksField]) -> Hash;
    
    /// Hash two hash values together
    fn hash_pair(&self, left: &Hash, right: &Hash) -> Hash;
    
    /// Hash a batch of field elements in parallel
    fn hash_field_elements_batch(&self, elements: &[GoldilocksField]) -> Vec<Hash> {
        elements
            .par_iter()
            .map(|elem| self.hash_field_element(elem))
            .collect()
    }
}

/// Blake2s hasher implementation
#[cfg(feature = "blake2")]
#[derive(Debug, Clone)]
pub struct Blake2sHasher;

#[cfg(feature = "blake2")]
impl Hasher for Blake2sHasher {
    fn hash_field_element(&self, element: &GoldilocksField) -> Hash {
        let mut hasher = Blake2s256::new();
        hasher.update(&element.value().to_le_bytes());
        hasher.finalize().into()
    }
    
    fn hash_field_elements(&self, elements: &[GoldilocksField]) -> Hash {
        let mut hasher = Blake2s256::new();
        for element in elements {
            hasher.update(&element.value().to_le_bytes());
        }
        hasher.finalize().into()
    }
    
    fn hash_pair(&self, left: &Hash, right: &Hash) -> Hash {
        let mut hasher = Blake2s256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

/// Keccak256 hasher implementation
#[cfg(feature = "sha3")]
#[derive(Debug, Clone)]
pub struct Keccak256Hasher;

#[cfg(feature = "sha3")]
impl Hasher for Keccak256Hasher {
    fn hash_field_element(&self, element: &GoldilocksField) -> Hash {
        let mut hasher = Keccak256::new();
        hasher.update(&element.value().to_le_bytes());
        hasher.finalize().into()
    }
    
    fn hash_field_elements(&self, elements: &[GoldilocksField]) -> Hash {
        let mut hasher = Keccak256::new();
        for element in elements {
            hasher.update(&element.value().to_le_bytes());
        }
        hasher.finalize().into()
    }
    
    fn hash_pair(&self, left: &Hash, right: &Hash) -> Hash {
        let mut hasher = Keccak256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

/// Default hasher type
#[cfg(feature = "blake2")]
pub type DefaultHasher = Blake2sHasher;

#[cfg(all(feature = "sha3", not(feature = "blake2")))]
pub type DefaultHasher = Keccak256Hasher;

/// Merkle proof for a single leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Path from leaf to root
    pub path: Vec<Hash>,
    /// Bit vector indicating left/right direction for each step
    pub directions: Vec<bool>, // false = left, true = right
    /// Index of the leaf
    pub leaf_index: usize,
}

impl MerkleProof {
    /// Verify this proof against a root hash and leaf value
    pub fn verify<H: Hasher>(
        &self,
        hasher: &H,
        root: &Hash,
        leaf_value: &GoldilocksField,
    ) -> bool {
        if self.path.len() != self.directions.len() {
            return false;
        }
        
        let mut current_hash = hasher.hash_field_element(leaf_value);
        
        for (sibling_hash, &is_right) in self.path.iter().zip(self.directions.iter()) {
            current_hash = if is_right {
                hasher.hash_pair(sibling_hash, &current_hash)
            } else {
                hasher.hash_pair(&current_hash, sibling_hash)
            };
        }
        
        current_hash == *root
    }
    
    /// Get the depth of this proof
    pub fn depth(&self) -> usize {
        self.path.len()
    }
}

/// Batch Merkle proof for multiple leaves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMerkleProof {
    /// Individual proofs for each leaf
    pub proofs: Vec<MerkleProof>,
    /// Indices of the queried leaves
    pub indices: Vec<usize>,
}

impl BatchMerkleProof {
    /// Verify all proofs in this batch
    pub fn verify<H: Hasher>(
        &self,
        hasher: &H,
        root: &Hash,
        leaf_values: &[GoldilocksField],
    ) -> bool {
        if self.proofs.len() != leaf_values.len() || self.indices.len() != leaf_values.len() {
            return false;
        }
        
        for (proof, &leaf_value) in self.proofs.iter().zip(leaf_values.iter()) {
            if !proof.verify(hasher, root, &leaf_value) {
                return false;
            }
        }
        
        true
    }
}

/// Merkle tree for committing to field element arrays
#[derive(Debug, Clone)]
pub struct MerkleTree<H: Hasher> {
    /// All nodes in the tree (level-order, bottom-up)
    nodes: Vec<Hash>,
    /// Number of leaves
    num_leaves: usize,
    /// Height of the tree
    height: usize,
    /// Hasher instance
    hasher: H,
}

impl<H: Hasher> MerkleTree<H> {
    /// Build a Merkle tree from field elements
    pub fn build(hasher: H, leaves: &[GoldilocksField]) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::TreeConstructionFailed {
                message: "Cannot build tree from empty leaves".to_string(),
            });
        }
        
        if !leaves.len().is_power_of_two() {
            return Err(MerkleError::UnsupportedTreeSize {
                size: leaves.len(),
            });
        }
        
        let num_leaves = leaves.len();
        let height = num_leaves.trailing_zeros() as usize;
        let total_nodes = 2 * num_leaves - 1;
        
        let mut nodes = vec![[0u8; 32]; total_nodes];
        
        // Hash leaves in parallel
        let leaf_hashes: Vec<Hash> = leaves
            .par_iter()
            .map(|leaf| hasher.hash_field_element(leaf))
            .collect();
        
        // Place leaf hashes at the bottom level
        let leaf_start = total_nodes - num_leaves;
        nodes[leaf_start..].copy_from_slice(&leaf_hashes);
        
        // Build internal nodes bottom-up
        for level in (0..height).rev() {
            let level_start = (1 << level) - 1;
            let level_size = 1 << level;
            let child_level_start = (1 << (level + 1)) - 1;
            
            for i in 0..level_size {
                let left_child = nodes[child_level_start + 2 * i];
                let right_child = nodes[child_level_start + 2 * i + 1];
                nodes[level_start + i] = hasher.hash_pair(&left_child, &right_child);
            }
        }
        
        Ok(Self {
            nodes,
            num_leaves,
            height,
            hasher,
        })
    }
    
    /// Get the root hash of the tree
    pub fn root(&self) -> Hash {
        self.nodes[0]
    }
    
    /// Generate a proof for a single leaf
    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof, MerkleError> {
        if leaf_index >= self.num_leaves {
            return Err(MerkleError::InvalidLeafIndex {
                index: leaf_index,
                tree_size: self.num_leaves,
            });
        }
        
        let mut path = Vec::with_capacity(self.height);
        let mut directions = Vec::with_capacity(self.height);
        let mut current_index = leaf_index;
        
        for level in (0..self.height).rev() {
            let level_start = (1 << level) - 1;
            let sibling_index = current_index ^ 1; // Flip the last bit
            let sibling_hash = if level == self.height - 1 {
                // Leaf level
                let leaf_start = self.nodes.len() - self.num_leaves;
                self.nodes[leaf_start + sibling_index]
            } else {
                // Internal level
                let child_level_start = (1 << (level + 1)) - 1;
                self.nodes[child_level_start + sibling_index]
            };
            
            path.push(sibling_hash);
            directions.push(current_index % 2 == 0); // true if current is left child
            current_index /= 2;
        }
        
        Ok(MerkleProof {
            path,
            directions,
            leaf_index,
        })
    }
    
    /// Generate proofs for multiple leaves efficiently
    pub fn prove_batch(&self, indices: &[usize]) -> Result<BatchMerkleProof, MerkleError> {
        let mut proofs = Vec::with_capacity(indices.len());
        
        for &index in indices {
            proofs.push(self.prove(index)?);
        }
        
        Ok(BatchMerkleProof {
            proofs,
            indices: indices.to_vec(),
        })
    }
    
    /// Get the number of leaves in the tree
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }
    
    /// Get the height of the tree
    pub fn height(&self) -> usize {
        self.height
    }
    
    /// Verify a proof against this tree's root
    pub fn verify_proof(
        &self,
        proof: &MerkleProof,
        leaf_value: &GoldilocksField,
    ) -> bool {
        proof.verify(&self.hasher, &self.root(), leaf_value)
    }
}

/// Optimized Merkle tree builder for STARK polynomial commitments
pub struct StarkMerkleTreeBuilder<H: Hasher> {
    hasher: H,
    parallel_threshold: usize,
}

impl<H: Hasher> StarkMerkleTreeBuilder<H> {
    /// Create a new builder with the given hasher
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            parallel_threshold: 1024, // Use parallel processing for trees with >1024 leaves
        }
    }
    
    /// Set the threshold for parallel processing
    pub fn with_parallel_threshold(mut self, threshold: usize) -> Self {
        self.parallel_threshold = threshold;
        self
    }
    
    /// Build a Merkle tree optimized for STARK commitments
    pub fn build_stark_tree(
        &self,
        evaluations: &[GoldilocksField],
    ) -> Result<MerkleTree<H>, MerkleError>
    where
        H: Clone,
    {
        if evaluations.len() >= self.parallel_threshold {
            self.build_parallel(evaluations)
        } else {
            MerkleTree::build(self.hasher.clone(), evaluations)
        }
    }
    
    /// Build tree using parallel processing
    fn build_parallel(
        &self,
        evaluations: &[GoldilocksField],
    ) -> Result<MerkleTree<H>, MerkleError>
    where
        H: Clone,
    {
        if !evaluations.len().is_power_of_two() {
            return Err(MerkleError::UnsupportedTreeSize {
                size: evaluations.len(),
            });
        }
        
        let num_leaves = evaluations.len();
        let height = num_leaves.trailing_zeros() as usize;
        
        // Use chunked parallel processing for very large trees
        let chunk_size = (num_leaves / rayon::current_num_threads()).max(1024);
        
        let leaf_hashes: Vec<Hash> = evaluations
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .map(|elem| self.hasher.hash_field_element(elem))
                    .collect::<Vec<_>>()
            })
            .collect();
        
        let mut nodes = vec![[0u8; 32]; 2 * num_leaves - 1];
        let leaf_start = nodes.len() - num_leaves;
        nodes[leaf_start..].copy_from_slice(&leaf_hashes);
        
        // Build internal nodes with parallel processing where beneficial
        for level in (0..height).rev() {
            let level_start = (1 << level) - 1;
            let level_size = 1 << level;
            let child_level_start = (1 << (level + 1)) - 1;
            
            if level_size >= 32 {
                // Use parallel processing for larger levels
                let level_nodes: Vec<Hash> = (0..level_size)
                    .into_par_iter()
                    .map(|i| {
                        let left_child = nodes[child_level_start + 2 * i];
                        let right_child = nodes[child_level_start + 2 * i + 1];
                        self.hasher.hash_pair(&left_child, &right_child)
                    })
                    .collect();
                
                nodes[level_start..level_start + level_size].copy_from_slice(&level_nodes);
            } else {
                // Use sequential processing for smaller levels
                for i in 0..level_size {
                    let left_child = nodes[child_level_start + 2 * i];
                    let right_child = nodes[child_level_start + 2 * i + 1];
                    nodes[level_start + i] = self.hasher.hash_pair(&left_child, &right_child);
                }
            }
        }
        
        Ok(MerkleTree {
            nodes,
            num_leaves,
            height,
            hasher: self.hasher.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(feature = "blake2")]
    #[test]
    fn test_merkle_tree_build_and_prove() {
        let hasher = Blake2sHasher;
        let leaves = vec![
            GoldilocksField::from(1u64),
            GoldilocksField::from(2u64),
            GoldilocksField::from(3u64),
            GoldilocksField::from(4u64),
        ];
        
        let tree = MerkleTree::build(hasher, &leaves).unwrap();
        assert_eq!(tree.num_leaves(), 4);
        assert_eq!(tree.height(), 2);
        
        // Test single proof
        let proof = tree.prove(0).unwrap();
        assert!(tree.verify_proof(&proof, &leaves[0]));
        
        // Test with wrong leaf value
        assert!(!tree.verify_proof(&proof, &leaves[1]));
        
        // Test all leaves
        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            assert!(tree.verify_proof(&proof, &leaves[i]));
        }
    }
    
    #[cfg(feature = "blake2")]
    #[test]
    fn test_batch_proof() {
        let hasher = Blake2sHasher;
        let leaves: Vec<GoldilocksField> = (0..8)
            .map(|i| GoldilocksField::from(i as u64))
            .collect();
        
        let tree = MerkleTree::build(hasher, &leaves).unwrap();
        
        let indices = vec![0, 2, 5, 7];
        let batch_proof = tree.prove_batch(&indices).unwrap();
        
        let queried_leaves: Vec<GoldilocksField> = indices
            .iter()
            .map(|&i| leaves[i])
            .collect();
        
        assert!(batch_proof.verify(&tree.hasher, &tree.root(), &queried_leaves));
    }
    
    #[cfg(feature = "blake2")]
    #[test]
    fn test_stark_tree_builder() {
        let hasher = Blake2sHasher;
        let builder = StarkMerkleTreeBuilder::new(hasher);
        
        let evaluations: Vec<GoldilocksField> = (0..1024)
            .map(|i| GoldilocksField::from(i as u64))
            .collect();
        
        let tree = builder.build_stark_tree(&evaluations).unwrap();
        assert_eq!(tree.num_leaves(), 1024);
        
        // Verify a few random proofs
        for &index in &[0, 100, 500, 1023] {
            let proof = tree.prove(index).unwrap();
            assert!(tree.verify_proof(&proof, &evaluations[index]));
        }
    }
    
    #[test]
    fn test_invalid_tree_size() {
        let hasher = Blake2sHasher;
        let leaves = vec![
            GoldilocksField::from(1u64),
            GoldilocksField::from(2u64),
            GoldilocksField::from(3u64), // 3 is not a power of 2
        ];
        
        let result = MerkleTree::build(hasher, &leaves);
        assert!(matches!(result, Err(MerkleError::UnsupportedTreeSize { .. })));
    }
    
    #[test]
    fn test_invalid_leaf_index() {
        let hasher = Blake2sHasher;
        let leaves = vec![
            GoldilocksField::from(1u64),
            GoldilocksField::from(2u64),
        ];
        
        let tree = MerkleTree::build(hasher, &leaves).unwrap();
        let result = tree.prove(5);
        assert!(matches!(result, Err(MerkleError::InvalidLeafIndex { .. })));
    }
}