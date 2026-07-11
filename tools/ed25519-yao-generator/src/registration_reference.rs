//! Host-only registration arithmetic over public synthetic reference inputs.
//!
//! Variable-time arithmetic is permitted because this module belongs only to
//! the clear fixture generator. Production protocol code and secret material
//! cannot depend on this crate.

use crate::{
    derive_synthetic_client_contributions_v1, derive_synthetic_deriver_a_server_contribution_v1,
    derive_synthetic_deriver_b_server_contribution_v1, evaluate_activation,
    share_host_only_activation_outputs_v1, ActivationOracleOutput, DeriverAContribution,
    DeriverBContribution, HostOnlyActivationOutputSharesV1, HostOnlyRegistrationIdealCoinsV1,
    RawDeriverAContribution, RawDeriverBContribution, StableKeyDerivationContext,
    SyntheticClientDerivationRootV1, SyntheticDeriverADerivationRootV1,
    SyntheticDeriverBDerivationRootV1,
};

/// Borrowed synthetic roots and stable context for one host-only registration evaluation.
///
/// The role-specific root types make an A/B root swap fail at compile time.
///
/// ```compile_fail
/// use ed25519_yao_generator::{
///     HostOnlyRegistrationReferenceInputsV1, StableKeyDerivationContext,
///     SyntheticClientDerivationRootV1, SyntheticDeriverADerivationRootV1,
///     SyntheticDeriverBDerivationRootV1,
/// };
///
/// fn swapped_roles<'a>(
///     client: &'a SyntheticClientDerivationRootV1,
///     deriver_a: &'a SyntheticDeriverADerivationRootV1,
///     deriver_b: &'a SyntheticDeriverBDerivationRootV1,
///     context: &'a StableKeyDerivationContext,
/// ) {
///     let _ = HostOnlyRegistrationReferenceInputsV1::new(
///         client, deriver_b, deriver_a, context,
///     );
/// }
/// ```
pub struct HostOnlyRegistrationReferenceInputsV1<'a> {
    client_root: &'a SyntheticClientDerivationRootV1,
    deriver_a_root: &'a SyntheticDeriverADerivationRootV1,
    deriver_b_root: &'a SyntheticDeriverBDerivationRootV1,
    stable_context: &'a StableKeyDerivationContext,
}

impl<'a> HostOnlyRegistrationReferenceInputsV1<'a> {
    /// Binds the three purpose-typed synthetic roots to one frozen stable context.
    pub const fn new(
        client_root: &'a SyntheticClientDerivationRootV1,
        deriver_a_root: &'a SyntheticDeriverADerivationRootV1,
        deriver_b_root: &'a SyntheticDeriverBDerivationRootV1,
        stable_context: &'a StableKeyDerivationContext,
    ) -> Self {
        Self {
            client_root,
            deriver_a_root,
            deriver_b_root,
            stable_context,
        }
    }

    pub(crate) const fn stable_context(&self) -> &StableKeyDerivationContext {
        self.stable_context
    }
}

/// KDF-derived registration inputs and their seed-free activation evaluation.
pub struct HostOnlyPreparedRegistrationReferenceV1 {
    deriver_a: DeriverAContribution,
    deriver_b: DeriverBContribution,
    activation: ActivationOracleOutput,
}

impl HostOnlyPreparedRegistrationReferenceV1 {
    /// Returns the internally derived Deriver A contribution tuple.
    pub const fn deriver_a(&self) -> &DeriverAContribution {
        &self.deriver_a
    }

    /// Returns the internally derived Deriver B contribution tuple.
    pub const fn deriver_b(&self) -> &DeriverBContribution {
        &self.deriver_b
    }

    /// Returns the seed-free activation-family evaluation.
    pub const fn activation(&self) -> &ActivationOracleOutput {
        &self.activation
    }
}

/// Host-only registration result after deterministic fixture output sharing.
///
/// ```compile_fail
/// use ed25519_yao_generator::HostOnlyRegistrationReferenceSuccessV1;
///
/// fn expose_seed(success: HostOnlyRegistrationReferenceSuccessV1) {
///     let _ = success.seed();
/// }
/// ```
pub struct HostOnlyRegistrationReferenceSuccessV1 {
    prepared: HostOnlyPreparedRegistrationReferenceV1,
    output_shares: HostOnlyActivationOutputSharesV1,
}

impl HostOnlyRegistrationReferenceSuccessV1 {
    /// Returns the KDF-derived registration preparation.
    pub const fn prepared(&self) -> &HostOnlyPreparedRegistrationReferenceV1 {
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

/// Derives every synthetic role input and evaluates the activation-family arithmetic.
pub fn prepare_host_only_registration_reference_v1(
    inputs: HostOnlyRegistrationReferenceInputsV1<'_>,
) -> HostOnlyPreparedRegistrationReferenceV1 {
    let client =
        derive_synthetic_client_contributions_v1(inputs.client_root, inputs.stable_context);
    let server_a = derive_synthetic_deriver_a_server_contribution_v1(
        inputs.deriver_a_root,
        inputs.stable_context,
    );
    let server_b = derive_synthetic_deriver_b_server_contribution_v1(
        inputs.deriver_b_root,
        inputs.stable_context,
    );
    let deriver_a = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: client.deriver_a().y().expose_fixture_bytes(),
        y_server: server_a.y().expose_fixture_bytes(),
        tau_client: client.deriver_a().tau().expose_fixture_bytes(),
        tau_server: server_a.tau().expose_fixture_bytes(),
    })
    .expect("synthetic KDF scalar outputs are canonical");
    let deriver_b = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: client.deriver_b().y().expose_fixture_bytes(),
        y_server: server_b.y().expose_fixture_bytes(),
        tau_client: client.deriver_b().tau().expose_fixture_bytes(),
        tau_server: server_b.tau().expose_fixture_bytes(),
    })
    .expect("synthetic KDF scalar outputs are canonical");
    let activation = evaluate_activation(&deriver_a, &deriver_b);

    HostOnlyPreparedRegistrationReferenceV1 {
        deriver_a,
        deriver_b,
        activation,
    }
}

/// Applies explicit fixture coins to one prepared synthetic registration output.
pub fn evaluate_host_only_registration_output_sharing_v1(
    prepared: HostOnlyPreparedRegistrationReferenceV1,
    coins: HostOnlyRegistrationIdealCoinsV1,
) -> HostOnlyRegistrationReferenceSuccessV1 {
    let output_shares = share_host_only_activation_outputs_v1(
        prepared.activation(),
        coins.into_activation_output_coins(),
    );
    HostOnlyRegistrationReferenceSuccessV1 {
        prepared,
        output_shares,
    }
}
