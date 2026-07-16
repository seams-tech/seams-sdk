#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Client-safe Router A/B Ed25519 Yao wire types and recipient output decoding.
//!
//! This crate deliberately contains no circuit, garbling, evaluator, or
//! oblivious-transfer implementation. Browser clients can prepare encrypted
//! role inputs and combine recipient outputs without linking either Deriver.

mod recipient;

use core::fmt;

use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoInputKindV1,
    Ed25519YaoOperationV1, Ed25519YaoPackageKindV1, Ed25519YaoRefreshBindingV1,
    RouterAbEd25519YaoApplicationBindingFactsV1,
};
use serde::{Deserialize, Serialize};
use signer_core::ed25519_yao_derivation::{
    Ed25519YaoApplicationBindingFactsV1, Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoStableKeyDerivationContextV1,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use recipient::{
    combine_client_activation_packages, combine_export_packages, ActivationDeriverAClientPackage,
    ActivationDeriverBClientPackage, ClientBaseScalar, ExportDeriverAClientPackage,
    ExportDeriverBClientPackage, ExportedSeed32, RecipientPackageError,
};

/// HPKE info for Client-to-Deriver role-input encryption.
pub const ED25519_YAO_INPUT_HPKE_INFO_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/deriver-input/hpke/v1";
/// HPKE info for Deriver-to-recipient package encryption.
pub const ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recipient-package/hpke/v1";

/// Builds the canonical associated data for one opaque Deriver input.
pub fn ed25519_yao_input_aad_v1(
    kind: Ed25519YaoInputKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
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
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
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

/// Stable application-binding construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StableKeyDerivationContextError;

impl fmt::Display for StableKeyDerivationContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519 Yao stable derivation context is invalid")
    }
}

impl std::error::Error for StableKeyDerivationContextError {}

/// Builds the canonical stable key-derivation context shared by Client and Derivers.
pub fn stable_key_derivation_context_v1(
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
) -> Result<Ed25519YaoStableKeyDerivationContextV1, StableKeyDerivationContextError> {
    let facts = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse(application.wallet_id())
            .map_err(|_| StableKeyDerivationContextError)?,
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse(
            application.near_ed25519_signing_key_id(),
        )
        .map_err(|_| StableKeyDerivationContextError)?,
        Ed25519YaoApplicationBindingSigningRootIdV1::parse(application.signing_root_id())
            .map_err(|_| StableKeyDerivationContextError)?,
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(
            application.key_creation_signer_slot(),
        )
        .map_err(|_| StableKeyDerivationContextError)?,
    );
    Ed25519YaoStableKeyDerivationContextV1::new(
        facts.digest(),
        participant_ids[0],
        participant_ids[1],
    )
    .map_err(|_| StableKeyDerivationContextError)
}
