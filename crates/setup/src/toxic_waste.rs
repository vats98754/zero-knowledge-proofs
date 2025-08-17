//! Toxic waste management and security utilities

use ark_ff::{Zero};
use ark_std::vec::Vec;

/// Secure handling of toxic waste
pub trait SecureDestroy {
    /// Securely destroy sensitive data
    fn secure_destroy(&mut self);
    
    /// Check if data has been destroyed
    fn is_destroyed(&self) -> bool;
}

/// Secure array that zeros itself on drop
#[derive(Debug)]
pub struct SecureArray<T: Zero + Clone> {
    data: Vec<T>,
    destroyed: bool,
}

impl<T: Zero + Clone> SecureArray<T> {
    /// Create a new secure array
    pub fn new(data: Vec<T>) -> Self {
        Self {
            data,
            destroyed: false,
        }
    }
    
    /// Get the data (if not destroyed)
    pub fn data(&self) -> Option<&[T]> {
        if self.destroyed {
            None
        } else {
            Some(&self.data)
        }
    }
    
    /// Get mutable data (if not destroyed)
    pub fn data_mut(&mut self) -> Option<&mut [T]> {
        if self.destroyed {
            None
        } else {
            Some(&mut self.data)
        }
    }
}

impl<T: Zero + Clone> SecureDestroy for SecureArray<T> {
    fn secure_destroy(&mut self) {
        // Zero out the data
        for item in &mut self.data {
            *item = T::zero();
        }
        self.destroyed = true;
    }
    
    fn is_destroyed(&self) -> bool {
        self.destroyed
    }
}

impl<T: Zero + Clone> Drop for SecureArray<T> {
    fn drop(&mut self) {
        self.secure_destroy();
    }
}

/// Utility for secure random number generation with extra entropy
pub struct SecureRng<R> {
    inner: R,
}

impl<R> SecureRng<R> {
    pub fn new(rng: R) -> Self {
        Self { inner: rng }
    }
    
    pub fn inner(&mut self) -> &mut R {
        &mut self.inner
    }
}

/// Audit trail for setup ceremony
#[derive(Debug, Clone)]
pub struct SetupAudit {
    pub participants: Vec<String>,
    pub phase: String,
    pub timestamp: u64,
    pub commitment_hash: Vec<u8>,
}

impl SetupAudit {
    pub fn new(phase: String) -> Self {
        Self {
            participants: Vec::new(),
            phase,
            timestamp: 0, // In real implementation, use actual timestamp
            commitment_hash: Vec::new(),
        }
    }
    
    pub fn add_participant(&mut self, participant: String) {
        self.participants.push(participant);
    }
    
    pub fn set_commitment(&mut self, hash: Vec<u8>) {
        self.commitment_hash = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn test_secure_array() {
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let mut secure = SecureArray::new(data.clone());
        
        // Initially not destroyed
        assert!(!secure.is_destroyed());
        assert_eq!(secure.data().unwrap(), &data);
        
        // Destroy and check
        secure.secure_destroy();
        assert!(secure.is_destroyed());
        assert!(secure.data().is_none());
    }

    #[test]
    fn test_setup_audit() {
        let mut audit = SetupAudit::new("phase1".to_string());
        audit.add_participant("Alice".to_string());
        audit.add_participant("Bob".to_string());
        audit.set_commitment(vec![1, 2, 3, 4]);
        
        assert_eq!(audit.participants.len(), 2);
        assert_eq!(audit.phase, "phase1");
        assert_eq!(audit.commitment_hash, vec![1, 2, 3, 4]);
    }
}