//! Shared activation-continuity checks over public synthetic host inputs.
//!
//! These variable-time comparisons belong only to the clear fixture generator.
//! Production protocol code and protected values cannot depend on this crate.

use core::fmt;

use crate::{
    wrapping_add_le_256, ActivationOracleOutput, DeriverAContribution, DeriverBContribution,
};

/// Activation field checked for exact equality across a host-only transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyActivationContinuityFieldV1 {
    /// Reconstructed seed-domain value before SHA-512.
    JoinedSeed,
    /// Complete SHA-512 digest.
    Sha512Digest,
    /// RFC 8032-clamped digest prefix.
    ClampedScalar,
    /// Canonical reduced Ed25519 signing scalar.
    SigningScalar,
    /// Joined contribution adjustment scalar.
    Tau,
    /// Client-labelled scalar base.
    ClientScalarBase,
    /// SigningWorker-labelled scalar base.
    SigningWorkerScalarBase,
    /// Client-labelled public point.
    ClientPoint,
    /// SigningWorker-labelled public point.
    SigningWorkerPoint,
    /// Registered RFC 8032 public key.
    PublicKey,
}

impl fmt::Display for HostOnlyActivationContinuityFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JoinedSeed => formatter.write_str("joined seed"),
            Self::Sha512Digest => formatter.write_str("SHA-512 digest"),
            Self::ClampedScalar => formatter.write_str("clamped scalar bytes"),
            Self::SigningScalar => formatter.write_str("signing scalar"),
            Self::Tau => formatter.write_str("joined tau"),
            Self::ClientScalarBase => formatter.write_str("client scalar base"),
            Self::SigningWorkerScalarBase => formatter.write_str("SigningWorker scalar base"),
            Self::ClientPoint => formatter.write_str("client point"),
            Self::SigningWorkerPoint => formatter.write_str("SigningWorker point"),
            Self::PublicKey => formatter.write_str("public key"),
        }
    }
}

pub(crate) fn validate_host_only_activation_continuity_v1(
    current_deriver_a: &DeriverAContribution,
    current_deriver_b: &DeriverBContribution,
    next_deriver_a: &DeriverAContribution,
    next_deriver_b: &DeriverBContribution,
    current: &ActivationOracleOutput,
    next: &ActivationOracleOutput,
) -> Result<(), HostOnlyActivationContinuityFieldV1> {
    require_equal_v1(
        joined_seed_v1(current_deriver_a, current_deriver_b),
        joined_seed_v1(next_deriver_a, next_deriver_b),
        HostOnlyActivationContinuityFieldV1::JoinedSeed,
    )?;
    require_equal_v1(
        current.material().sha512_digest().expose_bytes(),
        next.material().sha512_digest().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::Sha512Digest,
    )?;
    require_equal_v1(
        current.material().clamped_scalar_bytes().expose_bytes(),
        next.material().clamped_scalar_bytes().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::ClampedScalar,
    )?;
    require_equal_v1(
        current.material().signing_scalar().expose_bytes(),
        next.material().signing_scalar().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::SigningScalar,
    )?;
    require_equal_v1(
        current.material().tau().expose_bytes(),
        next.material().tau().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::Tau,
    )?;
    require_equal_v1(
        current.material().x_client_base().expose_bytes(),
        next.material().x_client_base().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::ClientScalarBase,
    )?;
    require_equal_v1(
        current.material().x_server_base().expose_bytes(),
        next.material().x_server_base().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::SigningWorkerScalarBase,
    )?;
    require_equal_v1(
        current.material().x_client().expose_bytes(),
        next.material().x_client().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::ClientPoint,
    )?;
    require_equal_v1(
        current.material().x_server().expose_bytes(),
        next.material().x_server().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::SigningWorkerPoint,
    )?;
    require_equal_v1(
        current.material().public_key().expose_bytes(),
        next.material().public_key().expose_bytes(),
        HostOnlyActivationContinuityFieldV1::PublicKey,
    )
}

fn joined_seed_v1(deriver_a: &DeriverAContribution, deriver_b: &DeriverBContribution) -> [u8; 32] {
    let deriver_a_y = wrapping_add_le_256(
        deriver_a.y_client().expose_bytes(),
        deriver_a.y_server().expose_bytes(),
    );
    let deriver_b_y = wrapping_add_le_256(
        deriver_b.y_client().expose_bytes(),
        deriver_b.y_server().expose_bytes(),
    );
    wrapping_add_le_256(deriver_a_y, deriver_b_y)
}

fn require_equal_v1<const LENGTH: usize>(
    current: [u8; LENGTH],
    next: [u8; LENGTH],
    field: HostOnlyActivationContinuityFieldV1,
) -> Result<(), HostOnlyActivationContinuityFieldV1> {
    if current == next {
        Ok(())
    } else {
        Err(field)
    }
}
