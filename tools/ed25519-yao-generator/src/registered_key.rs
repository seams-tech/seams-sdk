//! Canonical registered Ed25519 public-key boundary shared by host references.

use core::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;

/// Validation error for a registered Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredEd25519PublicKeyErrorV1 {
    /// The compressed Edwards encoding did not decompress.
    InvalidEncoding,
    /// Recompression did not reproduce the supplied bytes.
    NonCanonicalEncoding,
    /// The point was the Edwards identity.
    Identity,
    /// The point was outside the prime-order subgroup.
    NonPrimeSubgroup,
}

impl fmt::Display for RegisteredEd25519PublicKeyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("registered public key is invalid"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("registered public key encoding is noncanonical")
            }
            Self::Identity => formatter.write_str("registered public key is the identity"),
            Self::NonPrimeSubgroup => {
                formatter.write_str("registered public key is outside the prime subgroup")
            }
        }
    }
}

impl std::error::Error for RegisteredEd25519PublicKeyErrorV1 {}

/// Canonical registered Ed25519 identity used by ceremony, provenance, and export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisteredEd25519PublicKey32V1([u8; 32]);

impl RegisteredEd25519PublicKey32V1 {
    /// Validates canonical compression, non-identity, and prime-subgroup membership.
    pub fn parse(bytes: [u8; 32]) -> Result<Self, RegisteredEd25519PublicKeyErrorV1> {
        let point = CompressedEdwardsY(bytes)
            .decompress()
            .ok_or(RegisteredEd25519PublicKeyErrorV1::InvalidEncoding)?;
        if point.compress().to_bytes() != bytes {
            return Err(RegisteredEd25519PublicKeyErrorV1::NonCanonicalEncoding);
        }
        if point.is_identity() {
            return Err(RegisteredEd25519PublicKeyErrorV1::Identity);
        }
        if !point.is_torsion_free() {
            return Err(RegisteredEd25519PublicKeyErrorV1::NonPrimeSubgroup);
        }
        Ok(Self(bytes))
    }

    /// Returns the canonical compressed point bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
