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
    Ed25519YaoSessionIdV1,
};
pub use router_ab_ed25519_yao_protocol::{
    ed25519_yao_input_aad_v1, ed25519_yao_recipient_package_aad_v1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoClientContributionV1,
    LocalEd25519YaoExportDeriverARequestV1, LocalEd25519YaoExportDeriverBRequestV1,
    LocalEd25519YaoExportRecipientV1, LocalEd25519YaoRefreshDeriverARequestV1,
    LocalEd25519YaoRefreshDeriverBRequestV1, ED25519_YAO_INPUT_HPKE_INFO_V1,
    ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
};
use signer_core::ed25519_yao_derivation::{
    Ed25519YaoDeriverAClientContributionV1, Ed25519YaoDeriverAServerContributionV1,
    Ed25519YaoDeriverBClientContributionV1, Ed25519YaoDeriverBServerContributionV1,
    Ed25519YaoStableKeyDerivationContextV1,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod activation;
mod crypto;
pub mod duplex;
mod execution;
mod product;
pub use activation::*;
pub use crypto::*;
pub use execution::*;
pub use product::*;

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
    /// A role-local derivation root could not produce its server contribution.
    ServerContributionDerivation,
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
            Self::ServerContributionDerivation => {
                formatter.write_str("Ed25519 Yao server contribution derivation failed")
            }
        }
    }
}

/// Builds the stable key context used by the local Deriver engines.
pub fn stable_key_derivation_context_v1(
    application: &router_ab_core::RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> Result<Ed25519YaoStableKeyDerivationContextV1, AdapterError> {
    router_ab_ed25519_yao_protocol::stable_key_derivation_context_v1(application, participant_ids)
        .map_err(AdapterError::from)
}

impl std::error::Error for AdapterError {}

impl From<router_ab_ed25519_yao_protocol::StableKeyDerivationContextError> for AdapterError {
    fn from(_: router_ab_ed25519_yao_protocol::StableKeyDerivationContextError) -> Self {
        Self::InvalidDerivationContext
    }
}

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
