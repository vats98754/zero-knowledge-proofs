//! Group operations and point utilities

use crate::{BulletproofsError, BulletproofsResult};
use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use serde::{Deserialize, Serialize};

/// A point on the Ristretto group with additional utility methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupElement(pub RistrettoPoint);

impl GroupElement {
    /// Identity element
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }

    /// Create from compressed point
    pub fn from_compressed(compressed: &CompressedRistretto) -> BulletproofsResult<Self> {
        compressed
            .decompress()
            .map(Self)
            .ok_or_else(|| BulletproofsError::InvalidProof("Invalid compressed point".to_string()))
    }

    /// Compress this point
    pub fn compress(&self) -> CompressedRistretto {
        self.0.compress()
    }

    /// Perform multi-scalar multiplication
    pub fn multiscalar_mul<I, J>(scalars: I, points: J) -> Self
    where
        I: IntoIterator<Item = Scalar>,
        J: IntoIterator<Item = RistrettoPoint>,
    {
        Self(RistrettoPoint::vartime_multiscalar_mul(scalars, points))
    }
}

impl std::ops::Add for GroupElement {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for GroupElement {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl std::ops::Mul<Scalar> for GroupElement {
    type Output = Self;
    
    fn mul(self, scalar: Scalar) -> Self {
        Self(self.0 * scalar)
    }
}

impl std::ops::Neg for GroupElement {
    type Output = Self;
    
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl From<RistrettoPoint> for GroupElement {
    fn from(point: RistrettoPoint) -> Self {
        Self(point)
    }
}

impl From<GroupElement> for RistrettoPoint {
    fn from(element: GroupElement) -> Self {
        element.0
    }
}