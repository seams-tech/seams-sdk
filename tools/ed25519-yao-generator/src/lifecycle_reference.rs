//! Host-only synthetic lifecycle-continuity reference arithmetic.
//!
//! This module models only a correlated zero-sum adjustment over public fixture
//! contributions. It does not model production delta generation, credentials,
//! packages, persistence, transport, or active security.

use core::fmt;

use curve25519_dalek::scalar::Scalar;

use crate::{
    wrapping_add_le_256, DeriverAContribution, DeriverBContribution, RawDeriverAContribution,
    RawDeriverBContribution,
};

/// Validation failures for synthetic correlated lifecycle deltas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticContinuityDeltaErrorV1 {
    /// The seed-domain delta was the additive identity in `Z_(2^256)`.
    ZeroDeltaY,
    /// The scalar-domain delta was not a canonical little-endian scalar.
    NonCanonicalDeltaTau,
    /// The scalar-domain delta was the additive identity in `Z_l`.
    ZeroDeltaTau,
}

impl fmt::Display for SyntheticContinuityDeltaErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDeltaY => formatter.write_str("synthetic delta_y must be nonzero"),
            Self::NonCanonicalDeltaTau => {
                formatter.write_str("synthetic delta_tau must be a canonical Ed25519 scalar")
            }
            Self::ZeroDeltaTau => formatter.write_str("synthetic delta_tau must be nonzero"),
        }
    }
}

impl std::error::Error for SyntheticContinuityDeltaErrorV1 {}

/// Nonzero synthetic seed-domain delta in `Z_(2^256)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SyntheticNonZeroDeltaYV1([u8; 32]);

impl SyntheticNonZeroDeltaYV1 {
    /// Validates a little-endian fixture value as nonzero.
    pub fn from_fixture_bytes(bytes: [u8; 32]) -> Result<Self, SyntheticContinuityDeltaErrorV1> {
        if bytes == [0u8; 32] {
            return Err(SyntheticContinuityDeltaErrorV1::ZeroDeltaY);
        }
        Ok(Self(bytes))
    }

    /// Exposes the public synthetic fixture bytes.
    pub const fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Nonzero synthetic canonical scalar delta in `Z_l`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SyntheticNonZeroDeltaTauV1(Scalar);

impl SyntheticNonZeroDeltaTauV1 {
    /// Validates canonical little-endian fixture bytes as a nonzero scalar.
    pub fn from_canonical_fixture_bytes(
        bytes: [u8; 32],
    ) -> Result<Self, SyntheticContinuityDeltaErrorV1> {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or(SyntheticContinuityDeltaErrorV1::NonCanonicalDeltaTau)?;
        if scalar == Scalar::ZERO {
            return Err(SyntheticContinuityDeltaErrorV1::ZeroDeltaTau);
        }
        Ok(Self(scalar))
    }

    /// Exposes the canonical public synthetic fixture bytes.
    pub fn expose_fixture_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Typed zero-sum adjustment applied to the two synthetic server contributions.
pub struct SyntheticCorrelatedServerDeltaV1 {
    delta_y: SyntheticNonZeroDeltaYV1,
    delta_tau: SyntheticNonZeroDeltaTauV1,
}

impl SyntheticCorrelatedServerDeltaV1 {
    /// Constructs a correlated delta from individually validated domain values.
    pub const fn new(
        delta_y: SyntheticNonZeroDeltaYV1,
        delta_tau: SyntheticNonZeroDeltaTauV1,
    ) -> Self {
        Self { delta_y, delta_tau }
    }
}

/// Validated role contributions after one synthetic zero-sum adjustment.
pub struct SyntheticContinuityTransitionV1 {
    deriver_a: DeriverAContribution,
    deriver_b: DeriverBContribution,
}

impl SyntheticContinuityTransitionV1 {
    /// Returns the refreshed Deriver A contribution.
    pub const fn deriver_a(&self) -> &DeriverAContribution {
        &self.deriver_a
    }

    /// Returns the refreshed Deriver B contribution.
    pub const fn deriver_b(&self) -> &DeriverBContribution {
        &self.deriver_b
    }
}

/// Applies `+delta` to A's synthetic server contribution and `-delta` to B's.
///
/// Client contributions are copied byte-for-byte. The returned role values pass
/// the same canonical scalar validation as every other oracle input.
pub fn apply_synthetic_correlated_server_delta_v1(
    deriver_a: &DeriverAContribution,
    deriver_b: &DeriverBContribution,
    delta: &SyntheticCorrelatedServerDeltaV1,
) -> SyntheticContinuityTransitionV1 {
    let delta_y = delta.delta_y.expose_fixture_bytes();
    let delta_tau = delta.delta_tau.0;
    let deriver_a_server_tau = canonical_scalar(deriver_a.tau_server().expose_bytes());
    let deriver_b_server_tau = canonical_scalar(deriver_b.tau_server().expose_bytes());

    let refreshed_a = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: deriver_a.y_client().expose_bytes(),
        y_server: wrapping_add_le_256(deriver_a.y_server().expose_bytes(), delta_y),
        tau_client: deriver_a.tau_client().expose_bytes(),
        tau_server: (deriver_a_server_tau + delta_tau).to_bytes(),
    })
    .expect("canonical scalar arithmetic keeps the synthetic A contribution valid");
    let refreshed_b = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: deriver_b.y_client().expose_bytes(),
        y_server: wrapping_sub_le_256(deriver_b.y_server().expose_bytes(), delta_y),
        tau_client: deriver_b.tau_client().expose_bytes(),
        tau_server: (deriver_b_server_tau - delta_tau).to_bytes(),
    })
    .expect("canonical scalar arithmetic keeps the synthetic B contribution valid");

    SyntheticContinuityTransitionV1 {
        deriver_a: refreshed_a,
        deriver_b: refreshed_b,
    }
}

fn canonical_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("validated oracle contribution contains a canonical scalar")
}

fn wrapping_sub_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut borrow = false;
    for index in 0..32 {
        let (without_right, right_borrow) = left[index].overflowing_sub(right[index]);
        let (difference, prior_borrow) = without_right.overflowing_sub(u8::from(borrow));
        output[index] = difference;
        borrow = right_borrow || prior_borrow;
    }
    output
}
