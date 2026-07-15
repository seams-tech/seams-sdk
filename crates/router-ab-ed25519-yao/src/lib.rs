#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Local-first composition boundary between Router A/B contracts and the fixed
//! Ed25519 Yao role engines.
//!
//! The crate owns no transport, persistence, Router policy, or joined Deriver
//! state. Each builder consumes exactly one role's contribution and returns one
//! move-only role engine.

use core::fmt;

use ed25519_yao::local_protocol::{
    Activation128KiBDeriverA, Activation128KiBDeriverB,
    ActivationDeriverAInputs as YaoActivationDeriverAInputs,
    ActivationDeriverBInputs as YaoActivationDeriverBInputs, BenchmarkRoleError,
    Export128KiBDeriverA, Export128KiBDeriverB, ExportDeriverAInputs as YaoExportDeriverAInputs,
    ExportDeriverBInputs as YaoExportDeriverBInputs,
};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoCircuitFamilyV1, Ed25519YaoOperationV1,
    Ed25519YaoRefreshBindingV1, Ed25519YaoSessionIdV1, RouterAbEd25519YaoApplicationBindingFactsV1,
};
use serde::{Deserialize, Serialize};
use signer_core::ed25519_yao_derivation::{
    Ed25519YaoApplicationBindingFactsV1, Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverBServerContributionV1, Ed25519YaoStableKeyDerivationContextV1,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HPKE info for Client-to-Deriver role-input encryption.
pub const ED25519_YAO_INPUT_HPKE_INFO_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/deriver-input/hpke/v1";
/// HPKE info for Deriver-to-recipient package encryption.
pub const ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recipient-package/hpke/v1";

/// Builds the canonical associated data for one opaque Deriver input.
pub fn ed25519_yao_input_aad_v1(
    kind: router_ab_core::Ed25519YaoInputKindV1,
    deriver: router_ab_core::Ed25519YaoDeriverRoleV1,
    operation: Ed25519YaoOperationV1,
    session: [u8; 32],
    stable_context_binding: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(100);
    aad.extend_from_slice(b"seams/router-ab/ed25519-yao/deriver-input/aad/v1");
    aad.push(kind.wire_tag());
    aad.push(deriver.wire_tag());
    aad.push(match operation {
        Ed25519YaoOperationV1::Registration => 1,
        Ed25519YaoOperationV1::Recovery => 2,
        Ed25519YaoOperationV1::Refresh => 3,
        Ed25519YaoOperationV1::Export => 4,
    });
    aad.extend_from_slice(&session);
    aad.extend_from_slice(&stable_context_binding);
    aad
}

/// Builds the canonical associated data for one recipient-encrypted package.
pub fn ed25519_yao_recipient_package_aad_v1(
    kind: router_ab_core::Ed25519YaoPackageKindV1,
    deriver: router_ab_core::Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1.len() + 66);
    aad.extend_from_slice(ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1);
    aad.push(kind.wire_tag());
    aad.push(deriver.wire_tag());
    aad.extend_from_slice(&session);
    aad.extend_from_slice(&transcript);
    aad
}

/// Fixed activation Deriver A engine used by local composition.
pub type ActivationDeriverA = Activation128KiBDeriverA;
/// Fixed activation Deriver B engine used by local composition.
pub type ActivationDeriverB = Activation128KiBDeriverB;
/// Fixed export Deriver A engine used by local composition.
pub type ExportDeriverA = Export128KiBDeriverA;
/// Fixed export Deriver B engine used by local composition.
pub type ExportDeriverB = Export128KiBDeriverB;

/// Relay and exact-EOF types consumed by local transport adapters.
pub mod relay {
    pub use ed25519_yao::local_protocol::{
        derive_registration_receipt, verify_activation_continuity, ActivationDeriverAClientPackage,
        ActivationDeriverACompletion, ActivationDeriverASigningWorkerPackage,
        ActivationDeriverBClientPackage, ActivationDeriverBCompletion,
        ActivationDeriverBSigningWorkerPackage, ActivationPublicCommitments,
        ActivationPublicReceipt, BenchmarkRoleError, DirectionalEofEvidence,
        DirectionalWireDecoder, DirectionalWireEncoder, ExportDeriverAClientPackage,
        ExportDeriverACompletion, ExportDeriverBClientPackage, ExportDeriverBCompletion,
        RelayEvent, RelayInstruction, RelayStep, StreamMetrics, WireByteLedger, WireDirection,
        WireMessage, WireMessageKind,
    };
}

/// Recipient-only package opening APIs. Transport and Router code should never
/// import this module.
pub mod recipient {
    /// Client-only activation and explicit-export package combination.
    pub mod client {
        pub use ed25519_yao::local_protocol::{
            combine_client_activation_packages, combine_export_packages, ClientBaseScalar,
            ExportedSeed32,
        };
    }

    /// SigningWorker-only activation package combination.
    pub mod signing_worker {
        pub use ed25519_yao::local_protocol::{
            combine_signing_worker_activation_packages, SigningWorkerBaseScalar,
        };
    }
}

/// One zeroizing Client contribution sent inside exactly one Deriver envelope.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoClientContributionV1 {
    /// Client `y` contribution for this Deriver role.
    pub y: [u8; 32],
    /// Client `tau` contribution for this Deriver role.
    pub tau: [u8; 32],
}

impl fmt::Debug for LocalEd25519YaoClientContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalEd25519YaoClientContributionV1([REDACTED])")
    }
}

/// Recipient public keys bound into an activation-family role input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoActivationRecipientsV1 {
    /// Client recipient public key.
    pub client_public_key: [u8; 32],
    /// SigningWorker recipient public key.
    pub signing_worker_public_key: [u8; 32],
}

/// Client recipient public key bound into an export role input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoExportRecipientV1 {
    /// Client recipient public key.
    pub client_public_key: [u8; 32],
}

macro_rules! define_role_request {
    ($name:ident, $recipients:ty) => {
        #[doc = "One binding-specific role input opened only by its Deriver."]
        #[derive(Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            /// Router-admitted ceremony binding.
            pub binding: Ed25519YaoCeremonyBindingV1,
            /// Canonical application-binding facts.
            pub application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
            /// Canonical ascending participant identifiers.
            pub participant_ids: [u16; 2],
            /// Client contribution for this Deriver role.
            pub client_contribution: LocalEd25519YaoClientContributionV1,
            /// Recipient public keys for this fixed circuit family.
            pub recipients: $recipients,
        }
    };
}

define_role_request!(
    LocalEd25519YaoActivationDeriverARequestV1,
    LocalEd25519YaoActivationRecipientsV1
);
define_role_request!(
    LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1
);
define_role_request!(
    LocalEd25519YaoExportDeriverARequestV1,
    LocalEd25519YaoExportRecipientV1
);
define_role_request!(
    LocalEd25519YaoExportDeriverBRequestV1,
    LocalEd25519YaoExportRecipientV1
);

macro_rules! define_refresh_role_request {
    ($name:ident) => {
        #[doc = "One refresh-bound role input opened only by its Deriver."]
        #[derive(Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            /// Router-admitted refresh binding.
            pub binding: Ed25519YaoRefreshBindingV1,
            /// Canonical application-binding facts.
            pub application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
            /// Canonical ascending participant identifiers.
            pub participant_ids: [u16; 2],
            /// Client contribution for this Deriver role.
            pub client_contribution: LocalEd25519YaoClientContributionV1,
            /// Recipient public keys for the activation circuit.
            pub recipients: LocalEd25519YaoActivationRecipientsV1,
        }
    };
}

define_refresh_role_request!(LocalEd25519YaoRefreshDeriverARequestV1);
define_refresh_role_request!(LocalEd25519YaoRefreshDeriverBRequestV1);

/// Uniform local composition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    /// Canonical application or participant facts could not form a stable context.
    InvalidDerivationContext,
    /// The admitted operation selected the other fixed circuit family.
    CircuitFamilyMismatch,
    /// A role input or role-engine initialization failed.
    RoleProtocol,
    /// The contribution shape does not match registration/recovery or refresh.
    LifecycleContributionMismatch,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDerivationContext => {
                formatter.write_str("Ed25519 Yao stable derivation context is invalid")
            }
            Self::CircuitFamilyMismatch => {
                formatter.write_str("Ed25519 Yao circuit family does not match the role builder")
            }
            Self::RoleProtocol => formatter.write_str("Ed25519 Yao role initialization failed"),
            Self::LifecycleContributionMismatch => formatter
                .write_str("Ed25519 Yao contribution does not match the lifecycle operation"),
        }
    }
}

/// Builds the canonical stable key-derivation context shared by Client and Derivers.
pub fn stable_key_derivation_context_v1(
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> Result<Ed25519YaoStableKeyDerivationContextV1, AdapterError> {
    let facts = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse(application.wallet_id())
            .map_err(|_| AdapterError::InvalidDerivationContext)?,
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse(
            application.near_ed25519_signing_key_id(),
        )
        .map_err(|_| AdapterError::InvalidDerivationContext)?,
        Ed25519YaoApplicationBindingSigningRootIdV1::parse(application.signing_root_id())
            .map_err(|_| AdapterError::InvalidDerivationContext)?,
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(
            application.key_creation_signer_slot(),
        )
        .map_err(|_| AdapterError::InvalidDerivationContext)?,
    );
    Ed25519YaoStableKeyDerivationContextV1::new(
        facts.digest(),
        participant_ids[0],
        participant_ids[1],
    )
    .map_err(|_| AdapterError::InvalidDerivationContext)
}

impl std::error::Error for AdapterError {}

impl From<BenchmarkRoleError> for AdapterError {
    fn from(_: BenchmarkRoleError) -> Self {
        Self::RoleProtocol
    }
}

macro_rules! define_activation_contribution {
    ($name:ident, $client:ty, $server:ty) => {
        #[doc = "One Deriver's zeroizing role-local activation contribution."]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            client_contribution: [u8; 32],
            server_contribution: [u8; 32],
            client_tau: [u8; 32],
            server_tau: [u8; 32],
            stable_key_context_binding: [u8; 32],
            #[zeroize(skip)]
            lifecycle: ActivationContributionLifecycleV1,
        }

        impl $name {
            /// Creates registration or recovery inputs from canonical KDF outputs.
            pub fn base(
                context: &Ed25519YaoStableKeyDerivationContextV1,
                client: $client,
                server: $server,
            ) -> Self {
                let (client_y, client_tau) = client.into_parts();
                let (server_y, server_tau) = server.into_parts();
                Self {
                    client_contribution: client_y.into_bytes(),
                    server_contribution: server_y.into_bytes(),
                    client_tau: client_tau.into_bytes(),
                    server_tau: server_tau.into_bytes(),
                    stable_key_context_binding: context.binding_digest(),
                    lifecycle: ActivationContributionLifecycleV1::Base,
                }
            }

            /// Creates refresh inputs from unchanged Client contributions and
            /// the role's already transitioned effective server contribution.
            pub fn refresh(
                context: &Ed25519YaoStableKeyDerivationContextV1,
                client: $client,
                server: $server,
            ) -> Self {
                let (client_y, client_tau) = client.into_parts();
                let (server_y, server_tau) = server.into_parts();
                Self {
                    client_contribution: client_y.into_bytes(),
                    server_contribution: server_y.into_bytes(),
                    client_tau: client_tau.into_bytes(),
                    server_tau: server_tau.into_bytes(),
                    stable_key_context_binding: context.binding_digest(),
                    lifecycle: ActivationContributionLifecycleV1::Refresh,
                }
            }

            fn matches_context(&self, binding: &Ed25519YaoCeremonyBindingV1) -> bool {
                self.stable_key_context_binding == binding.stable_key_context_binding.into_bytes()
            }

            fn matches_operation(&self, operation: Ed25519YaoOperationV1) -> bool {
                matches!(
                    (self.lifecycle, operation),
                    (
                        ActivationContributionLifecycleV1::Base,
                        Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery
                    ) | (
                        ActivationContributionLifecycleV1::Refresh,
                        Ed25519YaoOperationV1::Refresh
                    )
                )
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationContributionLifecycleV1 {
    Base,
    Refresh,
}

macro_rules! define_export_contribution {
    ($name:ident, $client:ty, $server:ty) => {
        #[doc = "One Deriver's zeroizing role-local export contribution."]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            client_contribution: [u8; 32],
            server_contribution: [u8; 32],
            stable_key_context_binding: [u8; 32],
        }

        impl $name {
            /// Creates one role-local export contribution from canonical KDF outputs.
            pub fn from_derived(
                context: &Ed25519YaoStableKeyDerivationContextV1,
                client: $client,
                server: $server,
            ) -> Self {
                let (client_y, _client_tau) = client.into_parts();
                let (server_y, _server_tau) = server.into_parts();
                Self {
                    client_contribution: client_y.into_bytes(),
                    server_contribution: server_y.into_bytes(),
                    stable_key_context_binding: context.binding_digest(),
                }
            }

            fn matches_context(&self, binding: &Ed25519YaoCeremonyBindingV1) -> bool {
                self.stable_key_context_binding == binding.stable_key_context_binding.into_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_activation_contribution!(
    ActivationDeriverAContribution,
    Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverAServerContributionV1
);
define_activation_contribution!(
    ActivationDeriverBContribution,
    Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverBServerContributionV1
);
define_export_contribution!(
    ExportDeriverAContribution,
    Ed25519YaoDeriverAClientContributionV1,
    Ed25519YaoDeriverAServerContributionV1
);
define_export_contribution!(
    ExportDeriverBContribution,
    Ed25519YaoDeriverBClientContributionV1,
    Ed25519YaoDeriverBServerContributionV1
);

fn activation_session(
    binding: &Ed25519YaoCeremonyBindingV1,
) -> Result<Ed25519YaoSessionIdV1, AdapterError> {
    if binding.circuit_family() != Ed25519YaoCircuitFamilyV1::Activation {
        return Err(AdapterError::CircuitFamilyMismatch);
    }
    Ok(binding.session_id)
}

fn export_session(
    binding: &Ed25519YaoCeremonyBindingV1,
) -> Result<Ed25519YaoSessionIdV1, AdapterError> {
    if binding.circuit_family() != Ed25519YaoCircuitFamilyV1::Export {
        return Err(AdapterError::CircuitFamilyMismatch);
    }
    Ok(binding.session_id)
}

/// Builds only Deriver A's fixed activation role from A-owned inputs.
pub fn build_activation_deriver_a(
    binding: &Ed25519YaoCeremonyBindingV1,
    contribution: ActivationDeriverAContribution,
) -> Result<ActivationDeriverA, AdapterError> {
    let session = activation_session(binding)?.into_bytes();
    if !contribution.matches_operation(binding.operation) || !contribution.matches_context(binding)
    {
        return Err(AdapterError::LifecycleContributionMismatch);
    }
    let inputs = YaoActivationDeriverAInputs::new(
        contribution.client_contribution,
        contribution.server_contribution,
        contribution.client_tau,
        contribution.server_tau,
    )?;
    Ok(ActivationDeriverA::with_inputs(session, inputs)?)
}

/// Builds only Deriver B's fixed activation role from B-owned inputs.
pub fn build_activation_deriver_b(
    binding: &Ed25519YaoCeremonyBindingV1,
    contribution: ActivationDeriverBContribution,
) -> Result<ActivationDeriverB, AdapterError> {
    let session = activation_session(binding)?.into_bytes();
    if !contribution.matches_operation(binding.operation) || !contribution.matches_context(binding)
    {
        return Err(AdapterError::LifecycleContributionMismatch);
    }
    let inputs = YaoActivationDeriverBInputs::new(
        contribution.client_contribution,
        contribution.server_contribution,
        contribution.client_tau,
        contribution.server_tau,
    )?;
    Ok(ActivationDeriverB::with_inputs(session, inputs)?)
}

/// Builds only Deriver A's fixed export role from A-owned inputs.
pub fn build_export_deriver_a(
    binding: &Ed25519YaoCeremonyBindingV1,
    contribution: ExportDeriverAContribution,
) -> Result<ExportDeriverA, AdapterError> {
    let session = export_session(binding)?.into_bytes();
    if !contribution.matches_context(binding) {
        return Err(AdapterError::LifecycleContributionMismatch);
    }
    let inputs = YaoExportDeriverAInputs::new(
        contribution.client_contribution,
        contribution.server_contribution,
    )?;
    Ok(ExportDeriverA::with_inputs(session, inputs)?)
}

/// Builds only Deriver B's fixed export role from B-owned inputs.
pub fn build_export_deriver_b(
    binding: &Ed25519YaoCeremonyBindingV1,
    contribution: ExportDeriverBContribution,
) -> Result<ExportDeriverB, AdapterError> {
    let session = export_session(binding)?.into_bytes();
    if !contribution.matches_context(binding) {
        return Err(AdapterError::LifecycleContributionMismatch);
    }
    let inputs = YaoExportDeriverBInputs::new(
        contribution.client_contribution,
        contribution.server_contribution,
    )?;
    Ok(ExportDeriverB::with_inputs(session, inputs)?)
}
