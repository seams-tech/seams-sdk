//! Host-only recovery continuity over public synthetic reference inputs.
//!
//! Variable-time arithmetic is permitted because this module belongs only to
//! the clear fixture generator. Production protocol code and secret material
//! cannot depend on this crate.

use core::fmt;

use crate::{
    derive_synthetic_client_contributions_v1, evaluate_activation,
    share_host_only_activation_outputs_v1, ActivationOracleOutput, DeriverAContribution,
    DeriverBContribution, HostOnlyActivationContinuityFieldV1, HostOnlyActivationOutputSharesV1,
    HostOnlyRecoveryIdealCoinsV1, RawDeriverAContribution, RawDeriverBContribution,
    StableKeyDerivationContext, SyntheticClientContributionsV1, SyntheticClientDerivationRootV1,
};

/// Validation failure for the narrow host-only recovery reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyRecoveryReferenceErrorV1 {
    /// The recovered root differs from the current logical client root.
    RecoveredClientRootMismatch,
    /// Deriver A's current client seed contribution does not match the KDF.
    DeriverAClientYContributionMismatch,
    /// Deriver A's current client scalar contribution does not match the KDF.
    DeriverAClientTauContributionMismatch,
    /// Deriver B's current client seed contribution does not match the KDF.
    DeriverBClientYContributionMismatch,
    /// Deriver B's current client scalar contribution does not match the KDF.
    DeriverBClientTauContributionMismatch,
    /// A before/after activation field failed the exact continuity check.
    ActivationContinuityMismatch {
        /// Exact field that differed.
        field: HostOnlyActivationContinuityFieldV1,
    },
}

impl fmt::Display for HostOnlyRecoveryReferenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecoveredClientRootMismatch => {
                formatter.write_str("recovered client root must equal current client root")
            }
            Self::DeriverAClientYContributionMismatch => {
                formatter.write_str("Deriver A client y contribution does not match the KDF")
            }
            Self::DeriverAClientTauContributionMismatch => {
                formatter.write_str("Deriver A client tau contribution does not match the KDF")
            }
            Self::DeriverBClientYContributionMismatch => {
                formatter.write_str("Deriver B client y contribution does not match the KDF")
            }
            Self::DeriverBClientTauContributionMismatch => {
                formatter.write_str("Deriver B client tau contribution does not match the KDF")
            }
            Self::ActivationContinuityMismatch { field } => {
                write!(
                    formatter,
                    "recovery changed the host-only activation {field}"
                )
            }
        }
    }
}

impl std::error::Error for HostOnlyRecoveryReferenceErrorV1 {}

/// Borrowed aggregate inputs for synthetic same-root recovery preparation.
pub struct HostOnlyRecoveryReferenceInputsV1<'a> {
    current_client_root: &'a SyntheticClientDerivationRootV1,
    recovered_client_root: &'a SyntheticClientDerivationRootV1,
    stable_context: &'a StableKeyDerivationContext,
    current_deriver_a: &'a DeriverAContribution,
    current_deriver_b: &'a DeriverBContribution,
}

impl<'a> HostOnlyRecoveryReferenceInputsV1<'a> {
    /// Binds every required host-only recovery input without taking custody.
    pub const fn new(
        current_client_root: &'a SyntheticClientDerivationRootV1,
        recovered_client_root: &'a SyntheticClientDerivationRootV1,
        stable_context: &'a StableKeyDerivationContext,
        current_deriver_a: &'a DeriverAContribution,
        current_deriver_b: &'a DeriverBContribution,
    ) -> Self {
        Self {
            current_client_root,
            recovered_client_root,
            stable_context,
            current_deriver_a,
            current_deriver_b,
        }
    }

    pub(crate) const fn stable_context(&self) -> &StableKeyDerivationContext {
        self.stable_context
    }
}

/// Marker produced after every checked host-only recovery arithmetic field matches.
pub struct HostOnlyRecoveryContinuityWitnessV1 {
    _private: (),
}

/// Validated arithmetic state ready for deterministic host-only output sharing.
pub struct HostOnlyPreparedRecoveryReferenceV1 {
    rederived_client: SyntheticClientContributionsV1,
    recovered_deriver_a: DeriverAContribution,
    recovered_deriver_b: DeriverBContribution,
    current_activation: ActivationOracleOutput,
    recovered_activation: ActivationOracleOutput,
    continuity_witness: HostOnlyRecoveryContinuityWitnessV1,
}

impl HostOnlyPreparedRecoveryReferenceV1 {
    /// Returns the role-separated client contributions derived during recovery.
    pub const fn rederived_client(&self) -> &SyntheticClientContributionsV1 {
        &self.rederived_client
    }

    /// Returns Deriver A's recovered input with its server fields preserved.
    pub const fn recovered_deriver_a(&self) -> &DeriverAContribution {
        &self.recovered_deriver_a
    }

    /// Returns Deriver B's recovered input with its server fields preserved.
    pub const fn recovered_deriver_b(&self) -> &DeriverBContribution {
        &self.recovered_deriver_b
    }

    /// Returns the activation output evaluated from current inputs.
    pub const fn current_activation(&self) -> &ActivationOracleOutput {
        &self.current_activation
    }

    /// Returns the equal activation output evaluated from recovered inputs.
    pub const fn recovered_activation(&self) -> &ActivationOracleOutput {
        &self.recovered_activation
    }

    /// Returns evidence that every checked host-only arithmetic field matched.
    pub const fn continuity_witness(&self) -> &HostOnlyRecoveryContinuityWitnessV1 {
        &self.continuity_witness
    }
}

/// Host-only recovery output after applying typed activation output sharing.
pub struct HostOnlyRecoveryReferenceSuccessV1 {
    prepared: HostOnlyPreparedRecoveryReferenceV1,
    output_shares: HostOnlyActivationOutputSharesV1,
}

impl HostOnlyRecoveryReferenceSuccessV1 {
    /// Returns the validated recovery preparation and continuity evidence.
    pub const fn prepared(&self) -> &HostOnlyPreparedRecoveryReferenceV1 {
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

/// Validates same-root recovery and prepares equal before/after activation outputs.
pub fn prepare_host_only_recovery_reference_v1(
    inputs: HostOnlyRecoveryReferenceInputsV1<'_>,
) -> Result<HostOnlyPreparedRecoveryReferenceV1, HostOnlyRecoveryReferenceErrorV1> {
    if inputs.current_client_root != inputs.recovered_client_root {
        return Err(HostOnlyRecoveryReferenceErrorV1::RecoveredClientRootMismatch);
    }

    let current_client =
        derive_synthetic_client_contributions_v1(inputs.current_client_root, inputs.stable_context);
    validate_current_client_contributions_v1(
        &current_client,
        inputs.current_deriver_a,
        inputs.current_deriver_b,
    )?;

    let rederived_client = derive_synthetic_client_contributions_v1(
        inputs.recovered_client_root,
        inputs.stable_context,
    );
    let recovered_deriver_a = recovered_deriver_a_v1(&rederived_client, inputs.current_deriver_a);
    let recovered_deriver_b = recovered_deriver_b_v1(&rederived_client, inputs.current_deriver_b);
    let current_activation =
        evaluate_activation(inputs.current_deriver_a, inputs.current_deriver_b);
    let recovered_activation = evaluate_activation(&recovered_deriver_a, &recovered_deriver_b);
    crate::continuity_reference::validate_host_only_activation_continuity_v1(
        inputs.current_deriver_a,
        inputs.current_deriver_b,
        &recovered_deriver_a,
        &recovered_deriver_b,
        &current_activation,
        &recovered_activation,
    )
    .map_err(|field| HostOnlyRecoveryReferenceErrorV1::ActivationContinuityMismatch { field })?;

    Ok(HostOnlyPreparedRecoveryReferenceV1 {
        rederived_client,
        recovered_deriver_a,
        recovered_deriver_b,
        current_activation,
        recovered_activation,
        continuity_witness: HostOnlyRecoveryContinuityWitnessV1 { _private: () },
    })
}

/// Applies explicit fixture coins to a previously validated recovery output.
pub fn evaluate_host_only_recovery_output_sharing_v1(
    prepared: HostOnlyPreparedRecoveryReferenceV1,
    coins: HostOnlyRecoveryIdealCoinsV1,
) -> HostOnlyRecoveryReferenceSuccessV1 {
    let output_shares = share_host_only_activation_outputs_v1(
        prepared.recovered_activation(),
        coins.into_activation_output_coins(),
    );
    HostOnlyRecoveryReferenceSuccessV1 {
        prepared,
        output_shares,
    }
}

fn validate_current_client_contributions_v1(
    expected: &SyntheticClientContributionsV1,
    current_deriver_a: &DeriverAContribution,
    current_deriver_b: &DeriverBContribution,
) -> Result<(), HostOnlyRecoveryReferenceErrorV1> {
    if expected.deriver_a().y().expose_fixture_bytes()
        != current_deriver_a.y_client().expose_bytes()
    {
        return Err(HostOnlyRecoveryReferenceErrorV1::DeriverAClientYContributionMismatch);
    }
    if expected.deriver_a().tau().expose_fixture_bytes()
        != current_deriver_a.tau_client().expose_bytes()
    {
        return Err(HostOnlyRecoveryReferenceErrorV1::DeriverAClientTauContributionMismatch);
    }
    if expected.deriver_b().y().expose_fixture_bytes()
        != current_deriver_b.y_client().expose_bytes()
    {
        return Err(HostOnlyRecoveryReferenceErrorV1::DeriverBClientYContributionMismatch);
    }
    if expected.deriver_b().tau().expose_fixture_bytes()
        != current_deriver_b.tau_client().expose_bytes()
    {
        return Err(HostOnlyRecoveryReferenceErrorV1::DeriverBClientTauContributionMismatch);
    }
    Ok(())
}

fn recovered_deriver_a_v1(
    rederived_client: &SyntheticClientContributionsV1,
    current: &DeriverAContribution,
) -> DeriverAContribution {
    DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: rederived_client.deriver_a().y().expose_fixture_bytes(),
        y_server: current.y_server().expose_bytes(),
        tau_client: rederived_client.deriver_a().tau().expose_fixture_bytes(),
        tau_server: current.tau_server().expose_bytes(),
    })
    .expect("KDF scalar output and preserved validated server scalar remain canonical")
}

fn recovered_deriver_b_v1(
    rederived_client: &SyntheticClientContributionsV1,
    current: &DeriverBContribution,
) -> DeriverBContribution {
    DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: rederived_client.deriver_b().y().expose_fixture_bytes(),
        y_server: current.y_server().expose_bytes(),
        tau_client: rederived_client.deriver_b().tau().expose_fixture_bytes(),
        tau_server: current.tau_server().expose_bytes(),
    })
    .expect("KDF scalar output and preserved validated server scalar remain canonical")
}
