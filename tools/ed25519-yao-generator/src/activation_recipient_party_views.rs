//! Host-only recipient custody views after activation output release.

use core::fmt;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use crate::activation_delivery::{
    HostOnlyActivationClientReleasedV1, HostOnlyActivationRecipientsReleasedV1,
    HostOnlySigningWorkerActivationReleaseAuthorityV1,
};
use crate::ceremony_context::{CeremonyActivationEpochV1, CeremonySigningWorkerBindingV1};
use crate::lifecycle_domain::{ActivationPackageOriginV1, ZeroReevaluationWitnessV1};
use crate::semantic_artifacts::{
    OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
    OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
};
use crate::signing_worker_activation::{
    SigningWorkerActivationReceiptDigest32V1, SigningWorkerActivationReceiptSignature64V1,
    SigningWorkerActivationSuccessV1, SigningWorkerOutputStorageReceiptDigest32V1,
    SigningWorkerReceiptKeyEpochV1,
};
use crate::RegisteredEd25519PublicKey32V1;

/// Closed host-only activation recipient-view stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyActivationRecipientPartyViewStageV1 {
    /// Atomic Client and SigningWorker capabilities have been released.
    RecipientsReleased,
    /// The SigningWorker owns one receipt-verified activated state.
    SigningWorkerActivated,
}

/// Authorization is already consumed at every stage in this companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyActivationRecipientAuthorizationStateV1 {
    /// Activation metadata/control authority was consumed before release.
    Consumed,
}

/// Equal public view at the atomic recipient-release stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlyActivationRecipientsReleasedCommonV1 {
    origin: ActivationPackageOriginV1,
    package_set_digest: [u8; 32],
    output_committed_receipt_digest: [u8; 32],
    activation_transcript_digest: [u8; 32],
    authorization_state: HostOnlyActivationRecipientAuthorizationStateV1,
    zero_private_work: ZeroReevaluationWitnessV1,
}

impl HostOnlyActivationRecipientsReleasedCommonV1 {
    /// Returns the exact lifecycle origin.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        self.origin
    }

    /// Returns the committed activation package-set identity.
    pub const fn package_set_digest(&self) -> &[u8; 32] {
        &self.package_set_digest
    }

    /// Returns the preceding output-committed receipt identity.
    pub const fn output_committed_receipt_digest(&self) -> &[u8; 32] {
        &self.output_committed_receipt_digest
    }

    /// Returns the activation-control transcript that consumed authorization.
    pub const fn activation_transcript_digest(&self) -> &[u8; 32] {
        &self.activation_transcript_digest
    }

    /// Returns the consumed authorization state.
    pub const fn authorization_state(&self) -> HostOnlyActivationRecipientAuthorizationStateV1 {
        self.authorization_state
    }

    /// Returns the exact zero-private-work witness for recipient release.
    pub const fn zero_private_work(&self) -> ZeroReevaluationWitnessV1 {
        self.zero_private_work
    }
}

/// Equal public view after strict SigningWorker receipt verification.
pub struct HostOnlySigningWorkerActivatedCommonV1 {
    origin: ActivationPackageOriginV1,
    package_set_digest: [u8; 32],
    output_committed_receipt_digest: [u8; 32],
    activation_epoch: CeremonyActivationEpochV1,
    worker: CeremonySigningWorkerBindingV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    x_server: [u8; 32],
    storage_receipt_digest: SigningWorkerOutputStorageReceiptDigest32V1,
    activation_receipt_encoding: Vec<u8>,
    activation_receipt_digest: SigningWorkerActivationReceiptDigest32V1,
    activation_receipt_signature: SigningWorkerActivationReceiptSignature64V1,
    receipt_key_epoch: SigningWorkerReceiptKeyEpochV1,
    receipt_key_digest: [u8; 32],
    receipt_verifying_key: [u8; 32],
    authorization_state: HostOnlyActivationRecipientAuthorizationStateV1,
}

impl HostOnlySigningWorkerActivatedCommonV1 {
    /// Returns the exact lifecycle origin.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        self.origin
    }

    /// Returns the committed activation package-set identity.
    pub const fn package_set_digest(&self) -> &[u8; 32] {
        &self.package_set_digest
    }

    /// Returns the preceding output-committed receipt identity.
    pub const fn output_committed_receipt_digest(&self) -> &[u8; 32] {
        &self.output_committed_receipt_digest
    }

    /// Returns the active activation epoch.
    pub const fn activation_epoch(&self) -> CeremonyActivationEpochV1 {
        self.activation_epoch
    }

    /// Returns the exact SigningWorker identity and recipient-key epoch.
    pub const fn worker(&self) -> &CeremonySigningWorkerBindingV1 {
        &self.worker
    }

    /// Returns the registered Ed25519 public key preserved by activation.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the public SigningWorker point.
    pub const fn x_server(&self) -> &[u8; 32] {
        &self.x_server
    }

    /// Returns the opaque worker-output storage evidence digest.
    pub const fn storage_receipt_digest(&self) -> SigningWorkerOutputStorageReceiptDigest32V1 {
        self.storage_receipt_digest
    }

    /// Returns the exact signed activation-receipt body encoding.
    pub fn activation_receipt_encoding(&self) -> &[u8] {
        &self.activation_receipt_encoding
    }

    /// Returns the verified activation-receipt digest.
    pub const fn activation_receipt_digest(&self) -> SigningWorkerActivationReceiptDigest32V1 {
        self.activation_receipt_digest
    }

    /// Returns the verified activation-receipt signature.
    pub const fn activation_receipt_signature(
        &self,
    ) -> SigningWorkerActivationReceiptSignature64V1 {
        self.activation_receipt_signature
    }

    /// Returns the trusted receipt-signing-key epoch used during verification.
    pub const fn receipt_key_epoch(&self) -> SigningWorkerReceiptKeyEpochV1 {
        self.receipt_key_epoch
    }

    /// Returns the trusted receipt-authority key digest.
    pub const fn receipt_key_digest(&self) -> &[u8; 32] {
        &self.receipt_key_digest
    }

    /// Returns the trusted Ed25519 receipt-verifying key bytes.
    pub const fn receipt_verifying_key(&self) -> &[u8; 32] {
        &self.receipt_verifying_key
    }

    /// Returns the consumed activation-authorization state.
    pub const fn authorization_state(&self) -> HostOnlyActivationRecipientAuthorizationStateV1 {
        self.authorization_state
    }
}

/// Validation failure while composing post-release recipient views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlyActivationRecipientPartyViewErrorV1 {
    /// The released Client and SigningWorker capabilities name different outputs.
    ReleasedPackageSetMismatch,
    /// The released Client and SigningWorker capabilities name different origins.
    ReleasedOriginMismatch,
    /// The released Client and SigningWorker capabilities name different output receipts.
    ReleasedOutputCommittedReceiptMismatch,
    /// The released Client and SigningWorker capabilities name different activation transcripts.
    ReleasedActivationTranscriptMismatch,
    /// The released Client scalar does not match the committed Client point.
    ReleasedClientPointMismatch,
    /// Recipient release reported private evaluation work.
    ReleasedPrivateWorkMismatch,
    /// The retained Client capability and activated worker name different outputs.
    ActivatedPackageSetMismatch,
    /// The retained Client capability and activated worker name different origins.
    ActivatedOriginMismatch,
    /// The retained Client capability and activated worker name different output receipts.
    ActivatedOutputCommittedReceiptMismatch,
    /// The retained Client capability and activated worker name different activation transcripts.
    ActivatedActivationTranscriptMismatch,
    /// The retained Client scalar and activated worker do not preserve the registered key.
    ActivatedRegisteredKeyRelationMismatch,
    /// The verified receipt body no longer reproduces its recorded digest.
    ActivatedReceiptDigestMismatch,
}

impl fmt::Display for HostOnlyActivationRecipientPartyViewErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReleasedPackageSetMismatch => {
                "released Client and SigningWorker capabilities name different package sets"
            }
            Self::ReleasedOriginMismatch => {
                "released Client and SigningWorker capabilities name different lifecycle origins"
            }
            Self::ReleasedOutputCommittedReceiptMismatch => {
                "released Client and SigningWorker capabilities name different output receipts"
            }
            Self::ReleasedActivationTranscriptMismatch => {
                "released Client and SigningWorker capabilities name different activation transcripts"
            }
            Self::ReleasedClientPointMismatch => {
                "released Client scalar does not match the committed Client point"
            }
            Self::ReleasedPrivateWorkMismatch => {
                "activation recipient release must perform zero private evaluation work"
            }
            Self::ActivatedPackageSetMismatch => {
                "retained Client capability and activated worker name different package sets"
            }
            Self::ActivatedOriginMismatch => {
                "retained Client capability and activated worker name different lifecycle origins"
            }
            Self::ActivatedOutputCommittedReceiptMismatch => {
                "retained Client capability and activated worker name different output receipts"
            }
            Self::ActivatedActivationTranscriptMismatch => {
                "retained Client capability and activated worker name different activation transcripts"
            }
            Self::ActivatedRegisteredKeyRelationMismatch => {
                "activated Client and SigningWorker outputs do not preserve the registered key"
            }
            Self::ActivatedReceiptDigestMismatch => {
                "verified SigningWorker receipt body does not reproduce its digest"
            }
        })
    }
}

impl std::error::Error for HostOnlyActivationRecipientPartyViewErrorV1 {}

/// Rejected release-stage view construction retaining both recipient capabilities.
pub struct RejectedHostOnlyActivationRecipientsReleasedPartyViewsV1 {
    reason: HostOnlyActivationRecipientPartyViewErrorV1,
    client: Box<HostOnlyActivationClientReleasedV1>,
    signing_worker: Box<HostOnlySigningWorkerActivationReleaseAuthorityV1>,
}

impl RejectedHostOnlyActivationRecipientsReleasedPartyViewsV1 {
    /// Returns the public rejection reason.
    pub const fn reason(&self) -> HostOnlyActivationRecipientPartyViewErrorV1 {
        self.reason
    }

    /// Recovers both exact released capabilities.
    pub fn into_capabilities(
        self,
    ) -> (
        HostOnlyActivationClientReleasedV1,
        HostOnlySigningWorkerActivationReleaseAuthorityV1,
    ) {
        (*self.client, *self.signing_worker)
    }
}

impl fmt::Debug for RejectedHostOnlyActivationRecipientsReleasedPartyViewsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedHostOnlyActivationRecipientsReleasedPartyViewsV1")
            .field("reason", &self.reason)
            .field("client", &"retained")
            .field("signing_worker", &"retained")
            .finish()
    }
}

/// Rejected activated-stage view construction retaining both recipient states.
pub struct RejectedHostOnlySigningWorkerActivatedPartyViewsV1 {
    reason: HostOnlyActivationRecipientPartyViewErrorV1,
    client: Box<HostOnlyActivationClientReleasedV1>,
    signing_worker: Box<SigningWorkerActivationSuccessV1>,
}

impl RejectedHostOnlySigningWorkerActivatedPartyViewsV1 {
    /// Returns the public rejection reason.
    pub const fn reason(&self) -> HostOnlyActivationRecipientPartyViewErrorV1 {
        self.reason
    }

    /// Recovers the exact retained Client capability and worker activation.
    pub fn into_parts(
        self,
    ) -> (
        HostOnlyActivationClientReleasedV1,
        SigningWorkerActivationSuccessV1,
    ) {
        (*self.client, *self.signing_worker)
    }
}

impl fmt::Debug for RejectedHostOnlySigningWorkerActivatedPartyViewsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedHostOnlySigningWorkerActivatedPartyViewsV1")
            .field("reason", &self.reason)
            .field("client", &"retained")
            .field("signing_worker", &"retained")
            .finish()
    }
}

/// Client's released activation scalar view.
pub struct HostOnlyClientActivationRecipientsReleasedPartyViewV1 {
    common: HostOnlyActivationRecipientsReleasedCommonV1,
    capability: HostOnlyActivationClientReleasedV1,
}

impl HostOnlyClientActivationRecipientsReleasedPartyViewV1 {
    /// Returns the equal common public view.
    pub const fn common(&self) -> &HostOnlyActivationRecipientsReleasedCommonV1 {
        &self.common
    }

    /// Returns only the Client release capability.
    pub const fn capability(&self) -> &HostOnlyActivationClientReleasedV1 {
        &self.capability
    }

    /// Consumes this view into the Client release capability.
    pub fn into_capability(self) -> HostOnlyActivationClientReleasedV1 {
        self.capability
    }
}

/// SigningWorker's opaque activation release-authority view.
pub struct HostOnlySigningWorkerActivationRecipientsReleasedPartyViewV1 {
    common: HostOnlyActivationRecipientsReleasedCommonV1,
    authority: HostOnlySigningWorkerActivationReleaseAuthorityV1,
}

impl HostOnlySigningWorkerActivationRecipientsReleasedPartyViewV1 {
    /// Returns the equal common public view.
    pub const fn common(&self) -> &HostOnlyActivationRecipientsReleasedCommonV1 {
        &self.common
    }

    /// Returns the opaque worker-delivery evidence without exposing retained shares.
    pub const fn delivery_evidence(
        &self,
    ) -> OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1 {
        self.authority.delivery_evidence()
    }

    /// Consumes this view into the exact SigningWorker activation authority.
    pub fn into_authority(self) -> HostOnlySigningWorkerActivationReleaseAuthorityV1 {
        self.authority
    }
}

macro_rules! define_empty_released_view {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        pub struct $name {
            common: HostOnlyActivationRecipientsReleasedCommonV1,
        }

        impl $name {
            /// Returns the equal common public view; this role has no private extension.
            pub const fn common(&self) -> &HostOnlyActivationRecipientsReleasedCommonV1 {
                &self.common
            }
        }
    };
}

define_empty_released_view!(
    HostOnlyDeriverAActivationRecipientsReleasedPartyViewV1,
    "Deriver A's recipient-release view with no copied recipient output."
);
define_empty_released_view!(
    HostOnlyDeriverBActivationRecipientsReleasedPartyViewV1,
    "Deriver B's recipient-release view with no copied recipient output."
);
define_empty_released_view!(
    HostOnlyRouterActivationRecipientsReleasedPartyViewV1,
    "Router's public-only recipient-release view."
);
define_empty_released_view!(
    HostOnlyObserverActivationRecipientsReleasedPartyViewV1,
    "Observer's public-only recipient-release view."
);
define_empty_released_view!(
    HostOnlyDiagnosticsActivationRecipientsReleasedPartyViewV1,
    "Diagnostics' public-only recipient-release view."
);

/// Private aggregate owning both atomic recipient-release capabilities.
pub struct HostOnlyActivationRecipientsReleasedPartyViewSetV1 {
    common: HostOnlyActivationRecipientsReleasedCommonV1,
    client: HostOnlyActivationClientReleasedV1,
    signing_worker: HostOnlySigningWorkerActivationReleaseAuthorityV1,
}

impl HostOnlyActivationRecipientsReleasedPartyViewSetV1 {
    /// Consumes the set into Deriver A's public-only view.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverAActivationRecipientsReleasedPartyViewV1 {
        HostOnlyDeriverAActivationRecipientsReleasedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into Deriver B's public-only view.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBActivationRecipientsReleasedPartyViewV1 {
        HostOnlyDeriverBActivationRecipientsReleasedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the Client scalar-capability view.
    pub fn observe_client_v1(self) -> HostOnlyClientActivationRecipientsReleasedPartyViewV1 {
        HostOnlyClientActivationRecipientsReleasedPartyViewV1 {
            common: self.common,
            capability: self.client,
        }
    }

    /// Consumes the set into the SigningWorker authority view.
    pub fn observe_signing_worker_v1(
        self,
    ) -> HostOnlySigningWorkerActivationRecipientsReleasedPartyViewV1 {
        HostOnlySigningWorkerActivationRecipientsReleasedPartyViewV1 {
            common: self.common,
            authority: self.signing_worker,
        }
    }

    /// Consumes the set into the Router's public-only view.
    pub fn observe_router_v1(self) -> HostOnlyRouterActivationRecipientsReleasedPartyViewV1 {
        HostOnlyRouterActivationRecipientsReleasedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the observer's public-only view.
    pub fn observe_observer_v1(self) -> HostOnlyObserverActivationRecipientsReleasedPartyViewV1 {
        HostOnlyObserverActivationRecipientsReleasedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into diagnostics' public-only view.
    pub fn observe_diagnostics_v1(
        self,
    ) -> HostOnlyDiagnosticsActivationRecipientsReleasedPartyViewV1 {
        HostOnlyDiagnosticsActivationRecipientsReleasedPartyViewV1 {
            common: self.common,
        }
    }
}

/// Client view retained after SigningWorker activation.
pub struct HostOnlyClientSigningWorkerActivatedPartyViewV1 {
    common: HostOnlySigningWorkerActivatedCommonV1,
    capability: HostOnlyActivationClientReleasedV1,
}

impl HostOnlyClientSigningWorkerActivatedPartyViewV1 {
    /// Returns the equal common public view.
    pub const fn common(&self) -> &HostOnlySigningWorkerActivatedCommonV1 {
        &self.common
    }

    /// Returns the exact retained Client release capability.
    pub const fn capability(&self) -> &HostOnlyActivationClientReleasedV1 {
        &self.capability
    }

    /// Consumes this view into the retained Client release capability.
    pub fn into_capability(self) -> HostOnlyActivationClientReleasedV1 {
        self.capability
    }
}

/// SigningWorker view owning one receipt-verified activated state.
pub struct HostOnlySigningWorkerActivatedPartyViewV1 {
    common: HostOnlySigningWorkerActivatedCommonV1,
    activation: SigningWorkerActivationSuccessV1,
}

impl HostOnlySigningWorkerActivatedPartyViewV1 {
    /// Returns the equal common public view.
    pub const fn common(&self) -> &HostOnlySigningWorkerActivatedCommonV1 {
        &self.common
    }

    /// Returns the public activated worker state without a secret-scalar accessor.
    pub const fn activation(&self) -> &SigningWorkerActivationSuccessV1 {
        &self.activation
    }

    /// Consumes this view into the receipt-verified worker activation.
    pub fn into_activation(self) -> SigningWorkerActivationSuccessV1 {
        self.activation
    }
}

macro_rules! define_empty_activated_view {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        pub struct $name {
            common: HostOnlySigningWorkerActivatedCommonV1,
        }

        impl $name {
            /// Returns the equal common public view; this role has no private extension.
            pub const fn common(&self) -> &HostOnlySigningWorkerActivatedCommonV1 {
                &self.common
            }
        }
    };
}

define_empty_activated_view!(
    HostOnlyDeriverASigningWorkerActivatedPartyViewV1,
    "Deriver A's worker-activated view with no copied recipient output."
);
define_empty_activated_view!(
    HostOnlyDeriverBSigningWorkerActivatedPartyViewV1,
    "Deriver B's worker-activated view with no copied recipient output."
);
define_empty_activated_view!(
    HostOnlyRouterSigningWorkerActivatedPartyViewV1,
    "Router's public-only worker-activated view."
);
define_empty_activated_view!(
    HostOnlyObserverSigningWorkerActivatedPartyViewV1,
    "Observer's public-only worker-activated view."
);
define_empty_activated_view!(
    HostOnlyDiagnosticsSigningWorkerActivatedPartyViewV1,
    "Diagnostics' public-only worker-activated view."
);

/// Private aggregate owning the retained Client capability and worker activation.
pub struct HostOnlySigningWorkerActivatedPartyViewSetV1 {
    common: HostOnlySigningWorkerActivatedCommonV1,
    client: HostOnlyActivationClientReleasedV1,
    signing_worker: SigningWorkerActivationSuccessV1,
}

impl HostOnlySigningWorkerActivatedPartyViewSetV1 {
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn semantic_trace_identity_v1(
        &self,
    ) -> (ActivationPackageOriginV1, [u8; 32], [u8; 32]) {
        (
            self.common.origin(),
            *self.common.package_set_digest(),
            *self.common.output_committed_receipt_digest(),
        )
    }

    /// Consumes the set into Deriver A's public-only view.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverASigningWorkerActivatedPartyViewV1 {
        HostOnlyDeriverASigningWorkerActivatedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into Deriver B's public-only view.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBSigningWorkerActivatedPartyViewV1 {
        HostOnlyDeriverBSigningWorkerActivatedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the retained Client capability view.
    pub fn observe_client_v1(self) -> HostOnlyClientSigningWorkerActivatedPartyViewV1 {
        HostOnlyClientSigningWorkerActivatedPartyViewV1 {
            common: self.common,
            capability: self.client,
        }
    }

    /// Consumes the set into the sealed worker-activation view.
    pub fn observe_signing_worker_v1(self) -> HostOnlySigningWorkerActivatedPartyViewV1 {
        HostOnlySigningWorkerActivatedPartyViewV1 {
            common: self.common,
            activation: self.signing_worker,
        }
    }

    /// Consumes the set into the Router's public-only view.
    pub fn observe_router_v1(self) -> HostOnlyRouterSigningWorkerActivatedPartyViewV1 {
        HostOnlyRouterSigningWorkerActivatedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into the observer's public-only view.
    pub fn observe_observer_v1(self) -> HostOnlyObserverSigningWorkerActivatedPartyViewV1 {
        HostOnlyObserverSigningWorkerActivatedPartyViewV1 {
            common: self.common,
        }
    }

    /// Consumes the set into diagnostics' public-only view.
    pub fn observe_diagnostics_v1(self) -> HostOnlyDiagnosticsSigningWorkerActivatedPartyViewV1 {
        HostOnlyDiagnosticsSigningWorkerActivatedPartyViewV1 {
            common: self.common,
        }
    }
}

/// Builds the seven recipient-release views from one atomic release.
pub(crate) fn build_host_only_activation_recipients_released_party_view_set_v1(
    released: HostOnlyActivationRecipientsReleasedV1,
) -> Result<
    HostOnlyActivationRecipientsReleasedPartyViewSetV1,
    RejectedHostOnlyActivationRecipientsReleasedPartyViewsV1,
> {
    let zero_private_work = released.zero_private_evaluation_work();
    let (client, signing_worker) = released.into_capabilities();
    let metadata = signing_worker.metadata();
    let output = metadata.post_state().committed_output();
    let receipt = output.artifacts().receipt();
    let client_identity = client.release_identity();
    let worker_identity = signing_worker.release_identity();
    let reason = if client_identity.origin() != worker_identity.origin() {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ReleasedOriginMismatch)
    } else if client_identity.package_set_digest() != worker_identity.package_set_digest() {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ReleasedPackageSetMismatch)
    } else if client_identity.output_committed_receipt_digest()
        != worker_identity.output_committed_receipt_digest()
    {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ReleasedOutputCommittedReceiptMismatch)
    } else if client_identity.activation_transcript_digest()
        != worker_identity.activation_transcript_digest()
    {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ReleasedActivationTranscriptMismatch)
    } else if scalar_point(client.x_client_base().expose_bytes()) != *receipt.x_client() {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ReleasedClientPointMismatch)
    } else if has_private_work(zero_private_work) {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ReleasedPrivateWorkMismatch)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(RejectedHostOnlyActivationRecipientsReleasedPartyViewsV1 {
            reason,
            client: Box::new(client),
            signing_worker: Box::new(signing_worker),
        });
    }
    let common = HostOnlyActivationRecipientsReleasedCommonV1 {
        origin: worker_identity.origin(),
        package_set_digest: *worker_identity.package_set_digest().as_bytes(),
        output_committed_receipt_digest: *worker_identity
            .output_committed_receipt_digest()
            .as_bytes(),
        activation_transcript_digest: *worker_identity.activation_transcript_digest().as_bytes(),
        authorization_state: HostOnlyActivationRecipientAuthorizationStateV1::Consumed,
        zero_private_work,
    };
    Ok(HostOnlyActivationRecipientsReleasedPartyViewSetV1 {
        common,
        client,
        signing_worker,
    })
}

/// Builds the seven worker-activated views from exact retained recipient states.
pub(crate) fn build_host_only_signing_worker_activated_party_view_set_v1(
    client: HostOnlyActivationClientReleasedV1,
    signing_worker: SigningWorkerActivationSuccessV1,
) -> Result<
    HostOnlySigningWorkerActivatedPartyViewSetV1,
    RejectedHostOnlySigningWorkerActivatedPartyViewsV1,
> {
    let state = signing_worker.state();
    let receipt = signing_worker.receipt();
    let receipt_authority = signing_worker.receipt_authority();
    let receipt_encoding = receipt
        .body()
        .encode()
        .expect("verified host-only activation receipt remains encodable");
    let receipt_digest = receipt
        .body()
        .digest()
        .expect("verified host-only activation receipt remains digestible");
    let client_identity = client.release_identity();
    let worker_identity = state.release_identity();
    let reason = if client_identity.origin() != worker_identity.origin() {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ActivatedOriginMismatch)
    } else if client_identity.package_set_digest() != worker_identity.package_set_digest() {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ActivatedPackageSetMismatch)
    } else if client_identity.output_committed_receipt_digest()
        != worker_identity.output_committed_receipt_digest()
    {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ActivatedOutputCommittedReceiptMismatch)
    } else if client_identity.activation_transcript_digest()
        != worker_identity.activation_transcript_digest()
    {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ActivatedActivationTranscriptMismatch)
    } else if !registered_key_relation_holds(
        client.x_client_base().expose_bytes(),
        state.x_server(),
        state.registered_public_key(),
    ) {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ActivatedRegisteredKeyRelationMismatch)
    } else if receipt_digest != receipt.digest() {
        Some(HostOnlyActivationRecipientPartyViewErrorV1::ActivatedReceiptDigestMismatch)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(RejectedHostOnlySigningWorkerActivatedPartyViewsV1 {
            reason,
            client: Box::new(client),
            signing_worker: Box::new(signing_worker),
        });
    }
    let common = HostOnlySigningWorkerActivatedCommonV1 {
        origin: worker_identity.origin(),
        package_set_digest: *worker_identity.package_set_digest().as_bytes(),
        output_committed_receipt_digest: *worker_identity
            .output_committed_receipt_digest()
            .as_bytes(),
        activation_epoch: state.activation_epoch(),
        worker: state.worker().clone(),
        registered_public_key: state.registered_public_key(),
        x_server: *state.x_server(),
        storage_receipt_digest: state.storage_receipt_digest(),
        activation_receipt_encoding: receipt_encoding,
        activation_receipt_digest: receipt.digest(),
        activation_receipt_signature: receipt.signature(),
        receipt_key_epoch: receipt_authority.key_epoch(),
        receipt_key_digest: receipt_authority.key_digest(),
        receipt_verifying_key: receipt_authority.verifying_key_bytes(),
        authorization_state: HostOnlyActivationRecipientAuthorizationStateV1::Consumed,
    };
    Ok(HostOnlySigningWorkerActivatedPartyViewSetV1 {
        common,
        client,
        signing_worker,
    })
}

fn scalar_point(bytes: [u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * canonical_scalar(bytes))
        .compress()
        .to_bytes()
}

fn registered_key_relation_holds(
    client_scalar: [u8; 32],
    x_server: &[u8; 32],
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> bool {
    let Some(server_point) = CompressedEdwardsY(*x_server).decompress() else {
        return false;
    };
    let client_point = ED25519_BASEPOINT_POINT * canonical_scalar(client_scalar);
    (client_point + client_point - server_point)
        .compress()
        .to_bytes()
        == *registered_public_key.as_bytes()
}

fn canonical_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("typed host-only scalar remains canonical")
}

fn has_private_work(witness: ZeroReevaluationWitnessV1) -> bool {
    witness.yao_evaluations() != 0
        || witness.deriver_a_invocations() != 0
        || witness.deriver_b_invocations() != 0
        || witness.contribution_derivations() != 0
        || witness.output_share_samples() != 0
}

/// Client delivery evidence is intentionally distinct from worker authority evidence.
pub const fn activation_client_delivery_evidence_v1(
    client: &HostOnlyActivationClientReleasedV1,
) -> OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1 {
    client.delivery_evidence()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation_recipient_party_view_fixtures::{
        canonical_activated_recipient_fixture_v1, canonical_activation_recipients_released_v1,
    };

    const ORIGINS: [ActivationPackageOriginV1; 3] = [
        ActivationPackageOriginV1::Registration,
        ActivationPackageOriginV1::Recovery,
        ActivationPackageOriginV1::Refresh,
    ];

    #[test]
    fn release_views_are_disjoint_and_other_roles_are_empty() {
        for origin in ORIGINS {
            let client = build_host_only_activation_recipients_released_party_view_set_v1(
                canonical_activation_recipients_released_v1(origin),
            )
            .expect("release view set")
            .observe_client_v1();
            assert_eq!(client.common().origin(), origin);
            assert_eq!(
                scalar_point(client.capability().x_client_base().expose_bytes()),
                *canonical_activation_recipients_released_v1(origin)
                    .into_capabilities()
                    .1
                    .metadata()
                    .post_state()
                    .artifacts()
                    .receipt()
                    .x_client()
            );

            let worker = build_host_only_activation_recipients_released_party_view_set_v1(
                canonical_activation_recipients_released_v1(origin),
            )
            .expect("release view set")
            .observe_signing_worker_v1();
            assert_eq!(worker.common().origin(), origin);
            assert!(worker
                .delivery_evidence()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0));

            let deriver_a = build_host_only_activation_recipients_released_party_view_set_v1(
                canonical_activation_recipients_released_v1(origin),
            )
            .expect("release view set")
            .observe_deriver_a_v1();
            let router = build_host_only_activation_recipients_released_party_view_set_v1(
                canonical_activation_recipients_released_v1(origin),
            )
            .expect("release view set")
            .observe_router_v1();
            assert_eq!(deriver_a.common(), router.common());
        }
    }

    #[test]
    fn activated_views_retain_client_capability_and_seal_worker_activation() {
        for origin in ORIGINS {
            let fixture = canonical_activated_recipient_fixture_v1(origin);
            let expected_client = fixture.client().x_client_base().expose_bytes();
            let expected_x_server = *fixture.signing_worker().state().x_server();
            let expected_worker_scalar = fixture.x_server_base().expose_bytes();
            assert_eq!(scalar_point(expected_worker_scalar), expected_x_server);
            let (client, signing_worker) = fixture.into_recipient_states();
            let client_view =
                build_host_only_signing_worker_activated_party_view_set_v1(client, signing_worker)
                    .expect("activated view set")
                    .observe_client_v1();
            assert_eq!(client_view.common().origin(), origin);
            assert_eq!(
                client_view.capability().x_client_base().expose_bytes(),
                expected_client
            );

            let fixture = canonical_activated_recipient_fixture_v1(origin);
            let (client, signing_worker) = fixture.into_recipient_states();
            let worker_view =
                build_host_only_signing_worker_activated_party_view_set_v1(client, signing_worker)
                    .expect("activated view set")
                    .observe_signing_worker_v1();
            assert_eq!(worker_view.common().x_server(), &expected_x_server);
            assert_eq!(
                worker_view.activation().state().x_server(),
                &expected_x_server
            );
        }
    }

    #[test]
    fn activated_view_rejects_cross_output_splicing_and_retains_retry_states() {
        let registration =
            canonical_activated_recipient_fixture_v1(ActivationPackageOriginV1::Registration);
        let refresh = canonical_activated_recipient_fixture_v1(ActivationPackageOriginV1::Refresh);
        let (client, _) = registration.into_recipient_states();
        let (_, signing_worker) = refresh.into_recipient_states();
        let rejection =
            build_host_only_signing_worker_activated_party_view_set_v1(client, signing_worker)
                .err()
                .expect("cross-output splice must fail");
        assert_eq!(
            rejection.reason(),
            HostOnlyActivationRecipientPartyViewErrorV1::ActivatedOriginMismatch
        );
        let (client, signing_worker) = rejection.into_parts();
        assert_ne!(
            client.package_set_digest(),
            signing_worker.state().package_set_digest()
        );
    }

    #[test]
    fn activated_common_view_binds_verified_receipt_and_public_identity() {
        for origin in ORIGINS {
            let fixture = canonical_activated_recipient_fixture_v1(origin);
            let expected_key = *fixture
                .signing_worker()
                .state()
                .registered_public_key()
                .as_bytes();
            let expected_authority = fixture.signing_worker().receipt_authority().key_digest();
            let expected_authority_key = fixture
                .signing_worker()
                .receipt_authority()
                .verifying_key_bytes();
            let expected_authority_epoch = fixture.signing_worker().receipt_authority().key_epoch();
            let (client, signing_worker) = fixture.into_recipient_states();
            let common =
                build_host_only_signing_worker_activated_party_view_set_v1(client, signing_worker)
                    .expect("activated view set")
                    .observe_observer_v1();
            assert_eq!(common.common().origin(), origin);
            assert_eq!(
                common.common().registered_public_key().as_bytes(),
                &expected_key
            );
            assert!(common
                .common()
                .activation_receipt_encoding()
                .windows(expected_authority.len())
                .any(|window| window == expected_authority));
            assert_eq!(
                common.common().receipt_key_epoch(),
                expected_authority_epoch
            );
            assert_eq!(common.common().receipt_key_digest(), &expected_authority);
            assert_eq!(
                common.common().receipt_verifying_key(),
                &expected_authority_key
            );
            assert_eq!(
                common.common().authorization_state(),
                HostOnlyActivationRecipientAuthorizationStateV1::Consumed
            );
            assert!(common
                .common()
                .activation_receipt_signature()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0));
        }
    }
}
