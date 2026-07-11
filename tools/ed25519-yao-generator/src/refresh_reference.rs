//! Host-only refresh continuity over public synthetic reference inputs.
//!
//! Variable-time arithmetic is permitted because this module belongs only to
//! the clear fixture generator. Production protocol code and secret material
//! cannot depend on this crate.

use core::fmt;

use curve25519_dalek::scalar::Scalar;

use crate::joint_refresh_delta::{
    derive_host_only_joint_refresh_delta_v1, HostOnlyJointRefreshDeltaV1,
};
use crate::lifecycle_reference::apply_host_only_joint_refresh_delta_v1;
use crate::{
    evaluate_activation, share_host_only_activation_outputs_v1, wrapping_add_le_256,
    ActivationOracleOutput, DeriverAContribution, DeriverBContribution,
    HostOnlyActivationContinuityFieldV1, HostOnlyActivationOutputSharesV1,
    HostOnlyJointRefreshDeltaCoinsV1, HostOnlyJointRefreshDeltaErrorV1,
    HostOnlyRefreshIdealCoinsV1,
};

/// Refresh field checked while constructing a host-only continuity witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyRefreshContinuityFieldV1 {
    /// Deriver A's client seed contribution.
    DeriverAClientY,
    /// Deriver A's client scalar contribution.
    DeriverAClientTau,
    /// Deriver B's client seed contribution.
    DeriverBClientY,
    /// Deriver B's client scalar contribution.
    DeriverBClientTau,
    /// Deriver A's server seed contribution after applying `+delta_y`.
    DeriverAServerY,
    /// Deriver A's server scalar contribution after applying `+delta_tau`.
    DeriverAServerTau,
    /// Deriver B's server seed contribution after applying `-delta_y`.
    DeriverBServerY,
    /// Deriver B's server scalar contribution after applying `-delta_tau`.
    DeriverBServerTau,
    /// Exact joined and downstream activation continuity.
    Activation(HostOnlyActivationContinuityFieldV1),
}

impl fmt::Display for HostOnlyRefreshContinuityFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeriverAClientY => formatter.write_str("Deriver A client y"),
            Self::DeriverAClientTau => formatter.write_str("Deriver A client tau"),
            Self::DeriverBClientY => formatter.write_str("Deriver B client y"),
            Self::DeriverBClientTau => formatter.write_str("Deriver B client tau"),
            Self::DeriverAServerY => formatter.write_str("Deriver A server y"),
            Self::DeriverAServerTau => formatter.write_str("Deriver A server tau"),
            Self::DeriverBServerY => formatter.write_str("Deriver B server y"),
            Self::DeriverBServerTau => formatter.write_str("Deriver B server tau"),
            Self::Activation(field) => write!(formatter, "activation {field}"),
        }
    }
}

/// Defensive failure while checking the typed synthetic refresh transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyRefreshReferenceErrorV1 {
    /// The two role-local ideal contributions did not produce a valid delta.
    InvalidJointDelta(HostOnlyJointRefreshDeltaErrorV1),
    /// One exact transition or activation-continuity relation failed.
    ContinuityMismatch {
        /// Exact field that differed.
        field: HostOnlyRefreshContinuityFieldV1,
    },
}

impl fmt::Display for HostOnlyRefreshReferenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJointDelta(error) => {
                write!(formatter, "invalid joint refresh delta: {error}")
            }
            Self::ContinuityMismatch { field } => {
                write!(
                    formatter,
                    "refresh changed or miscomputed host-only {field}"
                )
            }
        }
    }
}

impl std::error::Error for HostOnlyRefreshReferenceErrorV1 {}

/// Borrowed current inputs plus move-owned role-local ideal delta coins.
pub struct HostOnlyRefreshReferenceInputsV1<'a> {
    current_deriver_a: &'a DeriverAContribution,
    current_deriver_b: &'a DeriverBContribution,
    delta_coins: HostOnlyJointRefreshDeltaCoinsV1,
}

impl<'a> HostOnlyRefreshReferenceInputsV1<'a> {
    /// Binds current role inputs to the two host-only role contributions.
    pub const fn new(
        current_deriver_a: &'a DeriverAContribution,
        current_deriver_b: &'a DeriverBContribution,
        delta_coins: HostOnlyJointRefreshDeltaCoinsV1,
    ) -> Self {
        Self {
            current_deriver_a,
            current_deriver_b,
            delta_coins,
        }
    }
}

/// Marker produced after every checked host-only refresh arithmetic field matches.
pub struct HostOnlyRefreshContinuityWitnessV1 {
    _private: (),
}

/// Validated refresh state ready for deterministic host-only output sharing.
pub struct HostOnlyPreparedRefreshReferenceV1 {
    refreshed_deriver_a: DeriverAContribution,
    refreshed_deriver_b: DeriverBContribution,
    current_activation: ActivationOracleOutput,
    refreshed_activation: ActivationOracleOutput,
    continuity_witness: HostOnlyRefreshContinuityWitnessV1,
}

impl HostOnlyPreparedRefreshReferenceV1 {
    /// Returns Deriver A's exact `+delta` refreshed input.
    pub const fn refreshed_deriver_a(&self) -> &DeriverAContribution {
        &self.refreshed_deriver_a
    }

    /// Returns Deriver B's exact `-delta` refreshed input.
    pub const fn refreshed_deriver_b(&self) -> &DeriverBContribution {
        &self.refreshed_deriver_b
    }

    /// Returns the activation output evaluated from current inputs.
    pub const fn current_activation(&self) -> &ActivationOracleOutput {
        &self.current_activation
    }

    /// Returns the equal activation output evaluated from refreshed inputs.
    pub const fn refreshed_activation(&self) -> &ActivationOracleOutput {
        &self.refreshed_activation
    }

    /// Returns evidence that every checked host-only arithmetic field matched.
    pub const fn continuity_witness(&self) -> &HostOnlyRefreshContinuityWitnessV1 {
        &self.continuity_witness
    }
}

/// Host-only refresh output after applying typed activation output sharing.
pub struct HostOnlyRefreshReferenceSuccessV1 {
    prepared: HostOnlyPreparedRefreshReferenceV1,
    output_shares: HostOnlyActivationOutputSharesV1,
}

impl HostOnlyRefreshReferenceSuccessV1 {
    /// Returns the validated refresh preparation and continuity evidence.
    pub const fn prepared(&self) -> &HostOnlyPreparedRefreshReferenceV1 {
        &self.prepared
    }

    /// Returns the typed client and SigningWorker scalar output shares.
    pub const fn output_shares(&self) -> &HostOnlyActivationOutputSharesV1 {
        &self.output_shares
    }

    pub(crate) fn into_output_shares(self) -> HostOnlyActivationOutputSharesV1 {
        self.output_shares
    }
}

/// Derives one ideal joint delta and defensively checks refresh continuity.
pub fn prepare_host_only_refresh_reference_v1(
    inputs: HostOnlyRefreshReferenceInputsV1<'_>,
) -> Result<HostOnlyPreparedRefreshReferenceV1, HostOnlyRefreshReferenceErrorV1> {
    let HostOnlyRefreshReferenceInputsV1 {
        current_deriver_a,
        current_deriver_b,
        delta_coins,
    } = inputs;
    let delta = derive_host_only_joint_refresh_delta_v1(delta_coins)
        .map_err(HostOnlyRefreshReferenceErrorV1::InvalidJointDelta)?;
    let transitioned =
        apply_host_only_joint_refresh_delta_v1(current_deriver_a, current_deriver_b, &delta);
    let (refreshed_deriver_a, refreshed_deriver_b) = transitioned.into_parts();
    validate_exact_refresh_transition_v1(
        current_deriver_a,
        current_deriver_b,
        &refreshed_deriver_a,
        &refreshed_deriver_b,
        &delta,
    )?;

    let current_activation = evaluate_activation(current_deriver_a, current_deriver_b);
    let refreshed_activation = evaluate_activation(&refreshed_deriver_a, &refreshed_deriver_b);
    crate::continuity_reference::validate_host_only_activation_continuity_v1(
        current_deriver_a,
        current_deriver_b,
        &refreshed_deriver_a,
        &refreshed_deriver_b,
        &current_activation,
        &refreshed_activation,
    )
    .map_err(
        |field| HostOnlyRefreshReferenceErrorV1::ContinuityMismatch {
            field: HostOnlyRefreshContinuityFieldV1::Activation(field),
        },
    )?;

    Ok(HostOnlyPreparedRefreshReferenceV1 {
        refreshed_deriver_a,
        refreshed_deriver_b,
        current_activation,
        refreshed_activation,
        continuity_witness: HostOnlyRefreshContinuityWitnessV1 { _private: () },
    })
}

/// Applies explicit fixture coins to a previously validated refresh output.
pub fn evaluate_host_only_refresh_output_sharing_v1(
    prepared: HostOnlyPreparedRefreshReferenceV1,
    coins: HostOnlyRefreshIdealCoinsV1,
) -> HostOnlyRefreshReferenceSuccessV1 {
    let output_shares = share_host_only_activation_outputs_v1(
        prepared.refreshed_activation(),
        coins.into_activation_output_coins(),
    );
    HostOnlyRefreshReferenceSuccessV1 {
        prepared,
        output_shares,
    }
}

fn validate_exact_refresh_transition_v1(
    current_deriver_a: &DeriverAContribution,
    current_deriver_b: &DeriverBContribution,
    refreshed_deriver_a: &DeriverAContribution,
    refreshed_deriver_b: &DeriverBContribution,
    delta: &HostOnlyJointRefreshDeltaV1,
) -> Result<(), HostOnlyRefreshReferenceErrorV1> {
    require_equal_v1(
        current_deriver_a.y_client().expose_bytes(),
        refreshed_deriver_a.y_client().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverAClientY,
    )?;
    require_equal_v1(
        current_deriver_a.tau_client().expose_bytes(),
        refreshed_deriver_a.tau_client().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverAClientTau,
    )?;
    require_equal_v1(
        current_deriver_b.y_client().expose_bytes(),
        refreshed_deriver_b.y_client().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverBClientY,
    )?;
    require_equal_v1(
        current_deriver_b.tau_client().expose_bytes(),
        refreshed_deriver_b.tau_client().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverBClientTau,
    )?;

    let delta_y = delta.delta_y();
    let delta_tau = delta.delta_tau();
    require_equal_v1(
        wrapping_add_le_256(current_deriver_a.y_server().expose_bytes(), delta_y),
        refreshed_deriver_a.y_server().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverAServerY,
    )?;
    require_equal_v1(
        (canonical_scalar_v1(current_deriver_a.tau_server().expose_bytes()) + delta_tau).to_bytes(),
        refreshed_deriver_a.tau_server().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverAServerTau,
    )?;
    require_equal_v1(
        crate::lifecycle_reference::wrapping_sub_le_256(
            current_deriver_b.y_server().expose_bytes(),
            delta_y,
        ),
        refreshed_deriver_b.y_server().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverBServerY,
    )?;
    require_equal_v1(
        (canonical_scalar_v1(current_deriver_b.tau_server().expose_bytes()) - delta_tau).to_bytes(),
        refreshed_deriver_b.tau_server().expose_bytes(),
        HostOnlyRefreshContinuityFieldV1::DeriverBServerTau,
    )
}

fn canonical_scalar_v1(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("validated host-only scalar remains canonical")
}

fn require_equal_v1(
    expected: [u8; 32],
    actual: [u8; 32],
    field: HostOnlyRefreshContinuityFieldV1,
) -> Result<(), HostOnlyRefreshReferenceErrorV1> {
    if expected == actual {
        Ok(())
    } else {
        Err(HostOnlyRefreshReferenceErrorV1::ContinuityMismatch { field })
    }
}
