//! Profile-neutral semantic delivery states and cumulative role observations.
//!
//! The layer projects public labels from existing host lifecycle evidence. It
//! does not own any companion state transition or secret value.

#![cfg_attr(not(test), allow(dead_code))]
#![cfg_attr(test, allow(dead_code))]

use crate::activation_delivery::{
    HostOnlyActivationRecipientsReleasedV1, HostOnlyActivationRedeliveryPendingV1,
    HostOnlyActivationRedeliveryV1,
};
use crate::activation_recipient_party_views::HostOnlySigningWorkerActivatedPartyViewSetV1;
use crate::ceremony_context::{CeremonyRequestKindV1, CeremonyValidatedDagV1};
use crate::evaluation_input_views::{
    HostOnlyExportEvaluationInputViewSetV1, HostOnlyRecoveryEvaluationInputViewSetV1,
    HostOnlyRefreshEvaluationInputViewSetV1, HostOnlyRegistrationEvaluationInputViewSetV1,
};
use crate::export_delivery::{
    HostOnlyExportRedeliveryPendingV1, HostOnlyExportRedeliveryV1, HostOnlyExportReleasedV1,
};
use crate::lifecycle_domain::ActivationPackageOriginV1;
use crate::lifecycle_domain::HostOnlyExportOutputCommittedV1;
use crate::lifecycle_persistence::EvaluationAbortedPersistenceProjectionV1;
use crate::output_party_views::{
    HostOnlyActivationMetadataConsumedPartyViewSetV1,
    HostOnlyActivationPackagePreparedPartyViewSetV1,
};
use crate::semantic_frame_classes::HostOnlySemanticFrameClassV1;

/// Closed semantic delivery state labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlySemanticDeliveryStateV1 {
    /// Router admitted one ceremony.
    CeremonyAdmitted,
    /// Both Derivers accepted their disjoint input custody.
    EvaluationInputsAccepted,
    /// The opaque selected protocol is exchanging peer observations.
    PeerProtocolInProgress,
    /// Router committed the complete output artifact identity.
    OutputCommitted,
    /// Evaluation terminated with the uniform abort observation.
    EvaluatorAborted,
    /// Router consumed activation metadata without evaluator work.
    ActivationMetadataConsumed,
    /// Recipient delivery has an uncertain result and retains exact identity.
    RecipientDeliveryUncertain,
    /// Client and SigningWorker activation capabilities were released atomically.
    ActivationRecipientsReleased,
    /// The authorized Client export was released.
    ExportReleased,
    /// SigningWorker activated receipt-verified server state.
    SigningWorkerActivated,
    /// The exact prior recipient delivery was repeated.
    ExactRedelivery,
}

impl HostOnlySemanticDeliveryStateV1 {
    /// Returns the frozen source label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CeremonyAdmitted => "ceremony_admitted",
            Self::EvaluationInputsAccepted => "evaluation_inputs_accepted",
            Self::PeerProtocolInProgress => "peer_protocol_in_progress",
            Self::OutputCommitted => "output_committed",
            Self::EvaluatorAborted => "evaluator_aborted",
            Self::ActivationMetadataConsumed => "activation_metadata_consumed",
            Self::RecipientDeliveryUncertain => "recipient_delivery_uncertain",
            Self::ActivationRecipientsReleased => "activation_recipients_released",
            Self::ExportReleased => "export_released",
            Self::SigningWorkerActivated => "signing_worker_activated",
            Self::ExactRedelivery => "exact_redelivery",
        }
    }
}

/// Frozen state order consumed by the strict semantic corpus.
pub const HOST_ONLY_SEMANTIC_DELIVERY_STATES_V1: [HostOnlySemanticDeliveryStateV1; 11] = [
    HostOnlySemanticDeliveryStateV1::CeremonyAdmitted,
    HostOnlySemanticDeliveryStateV1::EvaluationInputsAccepted,
    HostOnlySemanticDeliveryStateV1::PeerProtocolInProgress,
    HostOnlySemanticDeliveryStateV1::OutputCommitted,
    HostOnlySemanticDeliveryStateV1::EvaluatorAborted,
    HostOnlySemanticDeliveryStateV1::ActivationMetadataConsumed,
    HostOnlySemanticDeliveryStateV1::RecipientDeliveryUncertain,
    HostOnlySemanticDeliveryStateV1::ActivationRecipientsReleased,
    HostOnlySemanticDeliveryStateV1::ExportReleased,
    HostOnlySemanticDeliveryStateV1::SigningWorkerActivated,
    HostOnlySemanticDeliveryStateV1::ExactRedelivery,
];

/// Closed role labels. They label corpus rows and are never accepted by a projection method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlySemanticRoleV1 {
    /// Deriver A.
    DeriverA,
    /// Deriver B.
    DeriverB,
    /// Requesting Client.
    Client,
    /// Isolated signing worker.
    SigningWorker,
    /// Strict Router.
    Router,
    /// Public observer.
    Observer,
    /// Redacted diagnostics.
    Diagnostics,
}

impl HostOnlySemanticRoleV1 {
    /// Returns the frozen source label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeriverA => "deriver_a",
            Self::DeriverB => "deriver_b",
            Self::Client => "client",
            Self::SigningWorker => "signing_worker",
            Self::Router => "router",
            Self::Observer => "observer",
            Self::Diagnostics => "diagnostics",
        }
    }
}

/// Frozen role order consumed by every seven-row value-learning table.
pub const HOST_ONLY_SEMANTIC_ROLES_V1: [HostOnlySemanticRoleV1; 7] = [
    HostOnlySemanticRoleV1::DeriverA,
    HostOnlySemanticRoleV1::DeriverB,
    HostOnlySemanticRoleV1::Client,
    HostOnlySemanticRoleV1::SigningWorker,
    HostOnlySemanticRoleV1::Router,
    HostOnlySemanticRoleV1::Observer,
    HostOnlySemanticRoleV1::Diagnostics,
];

/// Public semantic events retained cumulatively by every role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlySemanticPublicEventV1 {
    /// Public ceremony identity and branch.
    CeremonyPublic,
    /// Public acceptance of both evaluator inputs.
    EvaluationInputsAcceptedPublic,
    /// Public peer-protocol progress.
    PeerProgressPublic,
    /// Public output commitment.
    OutputCommitmentPublic,
    /// Public uniform evaluator abort.
    UniformAbortPublic,
    /// Public activation metadata consumption.
    ActivationMetadataPublic,
    /// Public recipient-delivery uncertainty.
    RecipientDeliveryUncertaintyPublic,
    /// Public atomic activation-recipient release.
    ActivationRecipientReleasePublic,
    /// Public authorized export release.
    ExportReleasePublic,
    /// Public exact-redelivery identity.
    ExactRedeliveryIdentityPublic,
    /// Public receipt-verified worker activation.
    SigningWorkerActivationReceiptPublic,
}

impl HostOnlySemanticPublicEventV1 {
    /// Returns the frozen source label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CeremonyPublic => "ceremony_public",
            Self::EvaluationInputsAcceptedPublic => "evaluation_inputs_accepted_public",
            Self::PeerProgressPublic => "peer_progress_public",
            Self::OutputCommitmentPublic => "output_commitment_public",
            Self::UniformAbortPublic => "uniform_abort_public",
            Self::ActivationMetadataPublic => "activation_metadata_public",
            Self::RecipientDeliveryUncertaintyPublic => "recipient_delivery_uncertainty_public",
            Self::ActivationRecipientReleasePublic => "activation_recipient_release_public",
            Self::ExportReleasePublic => "export_release_public",
            Self::ExactRedeliveryIdentityPublic => "exact_redelivery_identity_public",
            Self::SigningWorkerActivationReceiptPublic => {
                "signing_worker_activation_receipt_public"
            }
        }
    }
}

/// Frozen public-event order consumed by strict corpus guards.
pub const HOST_ONLY_SEMANTIC_PUBLIC_EVENTS_V1: [HostOnlySemanticPublicEventV1; 11] = [
    HostOnlySemanticPublicEventV1::CeremonyPublic,
    HostOnlySemanticPublicEventV1::EvaluationInputsAcceptedPublic,
    HostOnlySemanticPublicEventV1::PeerProgressPublic,
    HostOnlySemanticPublicEventV1::OutputCommitmentPublic,
    HostOnlySemanticPublicEventV1::UniformAbortPublic,
    HostOnlySemanticPublicEventV1::ActivationMetadataPublic,
    HostOnlySemanticPublicEventV1::RecipientDeliveryUncertaintyPublic,
    HostOnlySemanticPublicEventV1::ActivationRecipientReleasePublic,
    HostOnlySemanticPublicEventV1::ExportReleasePublic,
    HostOnlySemanticPublicEventV1::ExactRedeliveryIdentityPublic,
    HostOnlySemanticPublicEventV1::SigningWorkerActivationReceiptPublic,
];

/// Semantic labels for values retained cumulatively by one role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlySemanticPrivateValueClassV1 {
    /// Client-owned role-scoped inputs.
    ClientRoleScopedInputs,
    /// Deriver A's activation-family inputs.
    DeriverAActivationInputs,
    /// Deriver B's activation-family inputs.
    DeriverBActivationInputs,
    /// Deriver A's export-family inputs.
    DeriverAExportInputs,
    /// Deriver B's export-family inputs.
    DeriverBExportInputs,
    /// Deriver A's peer-local protocol state.
    DeriverAPeerLocalState,
    /// Deriver B's peer-local protocol state.
    DeriverBPeerLocalState,
    /// Deriver A's selected-protocol randomness.
    DeriverAProtocolRandomness,
    /// Deriver B's selected-protocol randomness.
    DeriverBProtocolRandomness,
    /// Deriver A's activation output shares.
    DeriverAActivationOutputShares,
    /// Deriver B's activation output shares.
    DeriverBActivationOutputShares,
    /// Deriver A's export seed share.
    DeriverAExportSeedShare,
    /// Deriver B's export seed share.
    DeriverBExportSeedShare,
    /// Client activation scalar after recipient release.
    ClientActivationScalar,
    /// SigningWorker activation authority after recipient release.
    SigningWorkerActivationAuthority,
    /// Client seed after authorized export release.
    ClientExportSeed,
    /// SigningWorker activated scalar after receipt verification.
    SigningWorkerActivatedScalar,
    /// Router-owned opaque role-envelope identities.
    RouterOpaqueRoleEnvelopeIdentities,
    /// Router-owned opaque output-package identities.
    RouterOpaqueOutputPackageIdentities,
    /// Router-owned opaque recipient-delivery identities.
    RouterOpaqueRecipientDeliveryIdentities,
    /// Router lifecycle-control knowledge.
    RouterLifecycleControlKnowledge,
    /// Router receipt-control knowledge.
    RouterReceiptControlKnowledge,
}

impl HostOnlySemanticPrivateValueClassV1 {
    /// Returns the frozen source label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientRoleScopedInputs => "client_role_scoped_inputs",
            Self::DeriverAActivationInputs => "deriver_a_activation_inputs",
            Self::DeriverBActivationInputs => "deriver_b_activation_inputs",
            Self::DeriverAExportInputs => "deriver_a_export_inputs",
            Self::DeriverBExportInputs => "deriver_b_export_inputs",
            Self::DeriverAPeerLocalState => "deriver_a_peer_local_state",
            Self::DeriverBPeerLocalState => "deriver_b_peer_local_state",
            Self::DeriverAProtocolRandomness => "deriver_a_protocol_randomness",
            Self::DeriverBProtocolRandomness => "deriver_b_protocol_randomness",
            Self::DeriverAActivationOutputShares => "deriver_a_activation_output_shares",
            Self::DeriverBActivationOutputShares => "deriver_b_activation_output_shares",
            Self::DeriverAExportSeedShare => "deriver_a_export_seed_share",
            Self::DeriverBExportSeedShare => "deriver_b_export_seed_share",
            Self::ClientActivationScalar => "client_activation_scalar",
            Self::SigningWorkerActivationAuthority => "signing_worker_activation_authority",
            Self::ClientExportSeed => "client_export_seed",
            Self::SigningWorkerActivatedScalar => "signing_worker_activated_scalar",
            Self::RouterOpaqueRoleEnvelopeIdentities => "router_opaque_role_envelope_identities",
            Self::RouterOpaqueOutputPackageIdentities => "router_opaque_output_package_identities",
            Self::RouterOpaqueRecipientDeliveryIdentities => {
                "router_opaque_recipient_delivery_identities"
            }
            Self::RouterLifecycleControlKnowledge => "router_lifecycle_control_knowledge",
            Self::RouterReceiptControlKnowledge => "router_receipt_control_knowledge",
        }
    }
}

/// Frozen value-label order consumed by strict corpus guards.
pub const HOST_ONLY_SEMANTIC_PRIVATE_VALUE_CLASSES_V1: [HostOnlySemanticPrivateValueClassV1; 22] = [
    HostOnlySemanticPrivateValueClassV1::ClientRoleScopedInputs,
    HostOnlySemanticPrivateValueClassV1::DeriverAActivationInputs,
    HostOnlySemanticPrivateValueClassV1::DeriverBActivationInputs,
    HostOnlySemanticPrivateValueClassV1::DeriverAExportInputs,
    HostOnlySemanticPrivateValueClassV1::DeriverBExportInputs,
    HostOnlySemanticPrivateValueClassV1::DeriverAPeerLocalState,
    HostOnlySemanticPrivateValueClassV1::DeriverBPeerLocalState,
    HostOnlySemanticPrivateValueClassV1::DeriverAProtocolRandomness,
    HostOnlySemanticPrivateValueClassV1::DeriverBProtocolRandomness,
    HostOnlySemanticPrivateValueClassV1::DeriverAActivationOutputShares,
    HostOnlySemanticPrivateValueClassV1::DeriverBActivationOutputShares,
    HostOnlySemanticPrivateValueClassV1::DeriverAExportSeedShare,
    HostOnlySemanticPrivateValueClassV1::DeriverBExportSeedShare,
    HostOnlySemanticPrivateValueClassV1::ClientActivationScalar,
    HostOnlySemanticPrivateValueClassV1::SigningWorkerActivationAuthority,
    HostOnlySemanticPrivateValueClassV1::ClientExportSeed,
    HostOnlySemanticPrivateValueClassV1::SigningWorkerActivatedScalar,
    HostOnlySemanticPrivateValueClassV1::RouterOpaqueRoleEnvelopeIdentities,
    HostOnlySemanticPrivateValueClassV1::RouterOpaqueOutputPackageIdentities,
    HostOnlySemanticPrivateValueClassV1::RouterOpaqueRecipientDeliveryIdentities,
    HostOnlySemanticPrivateValueClassV1::RouterLifecycleControlKnowledge,
    HostOnlySemanticPrivateValueClassV1::RouterReceiptControlKnowledge,
];

/// Exact public-or-private label used when a corpus concatenates one role's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlySemanticValueClassV1 {
    /// One cumulative public-prefix label.
    Public(HostOnlySemanticPublicEventV1),
    /// One role-private or role-local label.
    Private(HostOnlySemanticPrivateValueClassV1),
}

impl HostOnlySemanticValueClassV1 {
    /// Returns the exact authoritative label without a translation table.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public(value) => value.as_str(),
            Self::Private(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvaluationFamilyV1 {
    Activation,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecipientFamilyV1 {
    Activation,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticStageV1 {
    CeremonyAdmitted(EvaluationFamilyV1),
    EvaluationInputsAccepted(EvaluationFamilyV1),
    PeerProtocolInProgress(EvaluationFamilyV1),
    OutputCommitted(EvaluationFamilyV1),
    EvaluatorAborted(EvaluationFamilyV1),
    ActivationMetadataConsumed,
    RecipientDeliveryUncertain(RecipientFamilyV1),
    ActivationRecipientsReleased,
    ExportReleased,
    SigningWorkerActivated,
    ExactRedelivery(RecipientFamilyV1),
}

impl SemanticStageV1 {
    const fn state(self) -> HostOnlySemanticDeliveryStateV1 {
        match self {
            Self::CeremonyAdmitted(_) => HostOnlySemanticDeliveryStateV1::CeremonyAdmitted,
            Self::EvaluationInputsAccepted(_) => {
                HostOnlySemanticDeliveryStateV1::EvaluationInputsAccepted
            }
            Self::PeerProtocolInProgress(_) => {
                HostOnlySemanticDeliveryStateV1::PeerProtocolInProgress
            }
            Self::OutputCommitted(_) => HostOnlySemanticDeliveryStateV1::OutputCommitted,
            Self::EvaluatorAborted(_) => HostOnlySemanticDeliveryStateV1::EvaluatorAborted,
            Self::ActivationMetadataConsumed => {
                HostOnlySemanticDeliveryStateV1::ActivationMetadataConsumed
            }
            Self::RecipientDeliveryUncertain(_) => {
                HostOnlySemanticDeliveryStateV1::RecipientDeliveryUncertain
            }
            Self::ActivationRecipientsReleased => {
                HostOnlySemanticDeliveryStateV1::ActivationRecipientsReleased
            }
            Self::ExportReleased => HostOnlySemanticDeliveryStateV1::ExportReleased,
            Self::SigningWorkerActivated => HostOnlySemanticDeliveryStateV1::SigningWorkerActivated,
            Self::ExactRedelivery(_) => HostOnlySemanticDeliveryStateV1::ExactRedelivery,
        }
    }

    const fn evaluation_family(self) -> EvaluationFamilyV1 {
        match self {
            Self::CeremonyAdmitted(family)
            | Self::EvaluationInputsAccepted(family)
            | Self::PeerProtocolInProgress(family)
            | Self::OutputCommitted(family)
            | Self::EvaluatorAborted(family) => family,
            Self::ActivationMetadataConsumed
            | Self::ActivationRecipientsReleased
            | Self::SigningWorkerActivated
            | Self::RecipientDeliveryUncertain(RecipientFamilyV1::Activation)
            | Self::ExactRedelivery(RecipientFamilyV1::Activation) => {
                EvaluationFamilyV1::Activation
            }
            Self::ExportReleased
            | Self::RecipientDeliveryUncertain(RecipientFamilyV1::Export)
            | Self::ExactRedelivery(RecipientFamilyV1::Export) => EvaluationFamilyV1::Export,
        }
    }
}

/// One validated trace step with emitted classes separated from cumulative observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlySemanticTraceStepV1 {
    stage: SemanticStageV1,
    emitted_frame_classes: &'static [HostOnlySemanticFrameClassV1],
}

impl HostOnlySemanticTraceStepV1 {
    /// Returns the exact closed semantic state.
    pub const fn state(self) -> HostOnlySemanticDeliveryStateV1 {
        self.stage.state()
    }

    /// Returns classes emitted by this step, preserving protocol order.
    pub const fn emitted_frame_classes(self) -> &'static [HostOnlySemanticFrameClassV1] {
        self.emitted_frame_classes
    }

    pub(crate) const fn view_set(self) -> HostOnlySemanticDeliveryViewSetV1 {
        HostOnlySemanticDeliveryViewSetV1 { stage: self.stage }
    }
}

const ACTIVATION_SUCCESS_TRACE_STEPS: [HostOnlySemanticTraceStepV1; 9] = [
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::CeremonyAdmitted(EvaluationFamilyV1::Activation),
        emitted_frame_classes: &[HostOnlySemanticFrameClassV1::ClientToRouterEvaluationRequest],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::EvaluationInputsAccepted(EvaluationFamilyV1::Activation),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::RouterToDeriverAInputDelivery,
            HostOnlySemanticFrameClassV1::RouterToDeriverBInputDelivery,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::PeerProtocolInProgress(EvaluationFamilyV1::Activation),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::DeriverAToDeriverBPeerProtocol,
            HostOnlySemanticFrameClassV1::DeriverBToDeriverAPeerProtocol,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::OutputCommitted(EvaluationFamilyV1::Activation),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::DeriverAToRouterOutputPackages,
            HostOnlySemanticFrameClassV1::DeriverBToRouterOutputPackages,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::ActivationMetadataConsumed,
        emitted_frame_classes: &[HostOnlySemanticFrameClassV1::RouterLocalActivationControl],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Activation),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::RouterToClientRecipientDelivery,
            HostOnlySemanticFrameClassV1::RouterToSigningWorkerRecipientDelivery,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::ActivationRecipientsReleased,
        emitted_frame_classes: &[],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Activation),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::RouterToClientRecipientDelivery,
            HostOnlySemanticFrameClassV1::RouterToSigningWorkerRecipientDelivery,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::SigningWorkerActivated,
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::SigningWorkerToRouterActivationReceipt,
        ],
    },
];

const EXPORT_SUCCESS_TRACE_STEPS: [HostOnlySemanticTraceStepV1; 7] = [
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::CeremonyAdmitted(EvaluationFamilyV1::Export),
        emitted_frame_classes: &[HostOnlySemanticFrameClassV1::ClientToRouterEvaluationRequest],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::EvaluationInputsAccepted(EvaluationFamilyV1::Export),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::RouterToDeriverAInputDelivery,
            HostOnlySemanticFrameClassV1::RouterToDeriverBInputDelivery,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::PeerProtocolInProgress(EvaluationFamilyV1::Export),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::DeriverAToDeriverBPeerProtocol,
            HostOnlySemanticFrameClassV1::DeriverBToDeriverAPeerProtocol,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::OutputCommitted(EvaluationFamilyV1::Export),
        emitted_frame_classes: &[
            HostOnlySemanticFrameClassV1::DeriverAToRouterOutputPackages,
            HostOnlySemanticFrameClassV1::DeriverBToRouterOutputPackages,
        ],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Export),
        emitted_frame_classes: &[HostOnlySemanticFrameClassV1::RouterToClientRecipientDelivery],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::ExportReleased,
        emitted_frame_classes: &[],
    },
    HostOnlySemanticTraceStepV1 {
        stage: SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Export),
        emitted_frame_classes: &[HostOnlySemanticFrameClassV1::RouterToClientRecipientDelivery],
    },
];

const fn abort_trace_steps(family: EvaluationFamilyV1) -> [HostOnlySemanticTraceStepV1; 4] {
    [
        HostOnlySemanticTraceStepV1 {
            stage: SemanticStageV1::CeremonyAdmitted(family),
            emitted_frame_classes: &[HostOnlySemanticFrameClassV1::ClientToRouterEvaluationRequest],
        },
        HostOnlySemanticTraceStepV1 {
            stage: SemanticStageV1::EvaluationInputsAccepted(family),
            emitted_frame_classes: &[
                HostOnlySemanticFrameClassV1::RouterToDeriverAInputDelivery,
                HostOnlySemanticFrameClassV1::RouterToDeriverBInputDelivery,
            ],
        },
        HostOnlySemanticTraceStepV1 {
            stage: SemanticStageV1::PeerProtocolInProgress(family),
            emitted_frame_classes: &[
                HostOnlySemanticFrameClassV1::DeriverAToDeriverBPeerProtocol,
                HostOnlySemanticFrameClassV1::DeriverBToDeriverAPeerProtocol,
            ],
        },
        HostOnlySemanticTraceStepV1 {
            stage: SemanticStageV1::EvaluatorAborted(family),
            emitted_frame_classes: &[],
        },
    ]
}

const ACTIVATION_ABORT_TRACE_STEPS: [HostOnlySemanticTraceStepV1; 4] =
    abort_trace_steps(EvaluationFamilyV1::Activation);
const EXPORT_ABORT_TRACE_STEPS: [HostOnlySemanticTraceStepV1; 4] =
    abort_trace_steps(EvaluationFamilyV1::Export);

pub(crate) const fn activation_success_trace_steps_v1() -> &'static [HostOnlySemanticTraceStepV1; 9]
{
    &ACTIVATION_SUCCESS_TRACE_STEPS
}

pub(crate) const fn export_success_trace_steps_v1() -> &'static [HostOnlySemanticTraceStepV1; 7] {
    &EXPORT_SUCCESS_TRACE_STEPS
}

pub(crate) const fn evaluator_abort_trace_steps_v1(
    request_kind: CeremonyRequestKindV1,
) -> Option<&'static [HostOnlySemanticTraceStepV1; 4]> {
    match request_kind {
        CeremonyRequestKindV1::Registration
        | CeremonyRequestKindV1::Recovery
        | CeremonyRequestKindV1::Refresh => Some(&ACTIVATION_ABORT_TRACE_STEPS),
        CeremonyRequestKindV1::Export => Some(&EXPORT_ABORT_TRACE_STEPS),
        CeremonyRequestKindV1::Activation => None,
    }
}

/// Validated registration, recovery, or refresh trace through worker activation.
pub struct HostOnlyActivationSuccessSemanticTraceV1 {
    origin: ActivationPackageOriginV1,
}

impl HostOnlyActivationSuccessSemanticTraceV1 {
    /// Returns the exact activation-package origin.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        self.origin
    }

    /// Returns the fixed nine-step sequence, including redelivery before activation.
    pub const fn steps(&self) -> &'static [HostOnlySemanticTraceStepV1; 9] {
        activation_success_trace_steps_v1()
    }

    fn for_origin(origin: ActivationPackageOriginV1) -> Self {
        Self { origin }
    }
}

/// Validated export trace through release and subsequent exact redelivery.
pub struct HostOnlyExportSuccessSemanticTraceV1;

impl HostOnlyExportSuccessSemanticTraceV1 {
    /// Returns the fixed seven-step sequence.
    pub const fn steps(&self) -> &'static [HostOnlySemanticTraceStepV1; 7] {
        export_success_trace_steps_v1()
    }
}

/// Validated branch-typed evaluator-abort trace.
pub struct HostOnlyEvaluatorAbortSemanticTraceV1 {
    request_kind: CeremonyRequestKindV1,
    steps: [HostOnlySemanticTraceStepV1; 4],
}

impl HostOnlyEvaluatorAbortSemanticTraceV1 {
    /// Returns the request kind derived from retained abort evidence.
    pub const fn request_kind(&self) -> CeremonyRequestKindV1 {
        self.request_kind
    }

    /// Returns the fixed terminal-abort sequence.
    pub const fn steps(&self) -> &[HostOnlySemanticTraceStepV1; 4] {
        &self.steps
    }
}

/// Source-authority bundle for activation success trace construction.
pub(crate) struct HostOnlyActivationSuccessTraceSourcesV1<'a> {
    pub(crate) ceremony: &'a CeremonyValidatedDagV1,
    pub(crate) output: &'a HostOnlyActivationPackagePreparedPartyViewSetV1,
    pub(crate) metadata: &'a HostOnlyActivationMetadataConsumedPartyViewSetV1,
    pub(crate) uncertain: &'a HostOnlyActivationRedeliveryPendingV1,
    pub(crate) released: &'a HostOnlyActivationRecipientsReleasedV1,
    pub(crate) redelivery: &'a HostOnlyActivationRedeliveryV1,
    pub(crate) activated: &'a HostOnlySigningWorkerActivatedPartyViewSetV1,
}

pub(crate) fn build_registration_success_semantic_trace_v1(
    sources: HostOnlyActivationSuccessTraceSourcesV1<'_>,
    _: &HostOnlyRegistrationEvaluationInputViewSetV1,
) -> Option<HostOnlyActivationSuccessSemanticTraceV1> {
    build_activation_success_trace(sources, ActivationPackageOriginV1::Registration)
}

pub(crate) fn build_recovery_success_semantic_trace_v1(
    sources: HostOnlyActivationSuccessTraceSourcesV1<'_>,
    _: &HostOnlyRecoveryEvaluationInputViewSetV1,
) -> Option<HostOnlyActivationSuccessSemanticTraceV1> {
    build_activation_success_trace(sources, ActivationPackageOriginV1::Recovery)
}

pub(crate) fn build_refresh_success_semantic_trace_v1(
    sources: HostOnlyActivationSuccessTraceSourcesV1<'_>,
    _: &HostOnlyRefreshEvaluationInputViewSetV1,
) -> Option<HostOnlyActivationSuccessSemanticTraceV1> {
    build_activation_success_trace(sources, ActivationPackageOriginV1::Refresh)
}

fn build_activation_success_trace(
    sources: HostOnlyActivationSuccessTraceSourcesV1<'_>,
    origin: ActivationPackageOriginV1,
) -> Option<HostOnlyActivationSuccessSemanticTraceV1> {
    let HostOnlyActivationSuccessTraceSourcesV1 {
        ceremony,
        output,
        metadata,
        uncertain,
        released,
        redelivery,
        activated,
    } = sources;
    let expected = output.semantic_trace_identity_v1();
    let identities_match = activation_trace_identities_match(
        origin,
        expected,
        [
            metadata.semantic_trace_identity_v1(),
            uncertain.semantic_trace_identity_v1(),
            released.semantic_trace_identity_v1(),
            redelivery.semantic_trace_identity_v1(),
            activated.semantic_trace_identity_v1(),
        ],
    );
    if ceremony.request_kind() == origin.request_kind() && identities_match {
        Some(HostOnlyActivationSuccessSemanticTraceV1::for_origin(origin))
    } else {
        None
    }
}

pub(crate) fn build_export_success_semantic_trace_v1(
    ceremony: &CeremonyValidatedDagV1,
    _: &HostOnlyExportEvaluationInputViewSetV1,
    output: &HostOnlyExportOutputCommittedV1,
    uncertain: &HostOnlyExportRedeliveryPendingV1,
    released: &HostOnlyExportReleasedV1,
    redelivery: &HostOnlyExportRedeliveryV1,
) -> Option<HostOnlyExportSuccessSemanticTraceV1> {
    let expected = output.semantic_trace_identity_v1();
    let identities_match = export_trace_identities_match(
        expected,
        [
            uncertain.semantic_trace_identity_v1(),
            released.semantic_trace_identity_v1(),
            redelivery.semantic_trace_identity_v1(),
        ],
    );
    if ceremony.request_kind() == CeremonyRequestKindV1::Export && identities_match {
        Some(HostOnlyExportSuccessSemanticTraceV1)
    } else {
        None
    }
}

pub(crate) fn build_evaluator_abort_semantic_trace_v1(
    projection: &EvaluationAbortedPersistenceProjectionV1,
) -> HostOnlyEvaluatorAbortSemanticTraceV1 {
    let request_kind = projection.abort().request_kind();
    let steps = evaluator_abort_trace_steps_v1(request_kind)
        .copied()
        .expect("activation performs zero evaluation");
    HostOnlyEvaluatorAbortSemanticTraceV1 {
        request_kind,
        steps,
    }
}

type ActivationTraceIdentityV1 = (ActivationPackageOriginV1, [u8; 32], [u8; 32]);
type ExportTraceIdentityV1 = ([u8; 32], [u8; 32]);

fn activation_trace_identities_match(
    origin: ActivationPackageOriginV1,
    expected: ActivationTraceIdentityV1,
    continuations: [ActivationTraceIdentityV1; 5],
) -> bool {
    expected.0 == origin && continuations == [expected; 5]
}

fn export_trace_identities_match(
    expected: ExportTraceIdentityV1,
    continuations: [ExportTraceIdentityV1; 3],
) -> bool {
    continuations == [expected; 3]
}

/// Move-only validated semantic state from which exactly one static role view is projected.
pub struct HostOnlySemanticDeliveryViewSetV1 {
    stage: SemanticStageV1,
}

impl HostOnlySemanticDeliveryViewSetV1 {
    /// Consumes the validated state into Deriver A's static view.
    pub fn observe_deriver_a_v1(self) -> HostOnlyDeriverASemanticDeliveryViewV1 {
        HostOnlyDeriverASemanticDeliveryViewV1 { stage: self.stage }
    }

    /// Consumes the validated state into Deriver B's static view.
    pub fn observe_deriver_b_v1(self) -> HostOnlyDeriverBSemanticDeliveryViewV1 {
        HostOnlyDeriverBSemanticDeliveryViewV1 { stage: self.stage }
    }

    /// Consumes the validated state into Client's static view.
    pub fn observe_client_v1(self) -> HostOnlyClientSemanticDeliveryViewV1 {
        HostOnlyClientSemanticDeliveryViewV1 { stage: self.stage }
    }

    /// Consumes the validated state into SigningWorker's static view.
    pub fn observe_signing_worker_v1(self) -> HostOnlySigningWorkerSemanticDeliveryViewV1 {
        HostOnlySigningWorkerSemanticDeliveryViewV1 { stage: self.stage }
    }

    /// Consumes the validated state into Router's static view.
    pub fn observe_router_v1(self) -> HostOnlyRouterSemanticDeliveryViewV1 {
        HostOnlyRouterSemanticDeliveryViewV1 { stage: self.stage }
    }

    /// Consumes the validated state into the public observer's static view.
    pub fn observe_observer_v1(self) -> HostOnlyObserverSemanticDeliveryViewV1 {
        HostOnlyObserverSemanticDeliveryViewV1 { stage: self.stage }
    }

    /// Consumes the validated state into redacted diagnostics' static view.
    pub fn observe_diagnostics_v1(self) -> HostOnlyDiagnosticsSemanticDeliveryViewV1 {
        HostOnlyDiagnosticsSemanticDeliveryViewV1 { stage: self.stage }
    }
}

macro_rules! define_semantic_role_view {
    ($name:ident, $documentation:literal, $frames:ident, $values:ident) => {
        #[doc = $documentation]
        pub struct $name {
            stage: SemanticStageV1,
        }

        impl $name {
            /// Returns the exact public semantic state.
            pub const fn state(&self) -> HostOnlySemanticDeliveryStateV1 {
                self.stage.state()
            }

            /// Returns the ordered directed classes directly observed by this role at this state.
            pub const fn observed_frame_classes(&self) -> &'static [HostOnlySemanticFrameClassV1] {
                $frames(self.stage)
            }

            /// Returns the ordered public events retained through this state.
            pub const fn known_public_events(&self) -> &'static [HostOnlySemanticPublicEventV1] {
                public_events(self.stage)
            }

            /// Returns cumulative value labels; values learned at earlier states remain present.
            pub const fn known_private_values(
                &self,
            ) -> &'static [HostOnlySemanticPrivateValueClassV1] {
                $values(self.stage)
            }
        }
    };
}

define_semantic_role_view!(
    HostOnlyDeriverASemanticDeliveryViewV1,
    "Deriver A's static semantic state and cumulative value-learning view.",
    deriver_a_frames,
    deriver_a_values
);
define_semantic_role_view!(
    HostOnlyDeriverBSemanticDeliveryViewV1,
    "Deriver B's static semantic state and cumulative value-learning view.",
    deriver_b_frames,
    deriver_b_values
);
define_semantic_role_view!(
    HostOnlyClientSemanticDeliveryViewV1,
    "Client's static semantic state and cumulative value-learning view.",
    client_frames,
    client_values
);
define_semantic_role_view!(
    HostOnlySigningWorkerSemanticDeliveryViewV1,
    "SigningWorker's static semantic state and cumulative value-learning view.",
    signing_worker_frames,
    signing_worker_values
);
define_semantic_role_view!(
    HostOnlyRouterSemanticDeliveryViewV1,
    "Router's static semantic state and cumulative opaque value-learning view.",
    router_frames,
    router_values
);
define_semantic_role_view!(
    HostOnlyObserverSemanticDeliveryViewV1,
    "Observer's common-public semantic state view.",
    observer_frames,
    observer_values
);
define_semantic_role_view!(
    HostOnlyDiagnosticsSemanticDeliveryViewV1,
    "Diagnostics' redacted semantic class and transition view.",
    diagnostics_frames,
    diagnostics_values
);

use HostOnlySemanticFrameClassV1 as Frame;
use HostOnlySemanticPrivateValueClassV1 as Value;

use HostOnlySemanticPublicEventV1 as Event;

const EVENTS_ADMITTED: &[Event] = &[Event::CeremonyPublic];
const EVENTS_INPUTS: &[Event] = &[Event::CeremonyPublic, Event::EvaluationInputsAcceptedPublic];
const EVENTS_PEER: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
];
const EVENTS_OUTPUT: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
];
const EVENTS_ABORT: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::UniformAbortPublic,
];
const EVENTS_ACTIVATION_METADATA: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::ActivationMetadataPublic,
];
const EVENTS_ACTIVATION_UNCERTAIN: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::ActivationMetadataPublic,
    Event::RecipientDeliveryUncertaintyPublic,
];
const EVENTS_ACTIVATION_RELEASED: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::ActivationMetadataPublic,
    Event::RecipientDeliveryUncertaintyPublic,
    Event::ActivationRecipientReleasePublic,
];
const EVENTS_ACTIVATION_REDELIVERED: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::ActivationMetadataPublic,
    Event::RecipientDeliveryUncertaintyPublic,
    Event::ActivationRecipientReleasePublic,
    Event::ExactRedeliveryIdentityPublic,
];
const EVENTS_ACTIVATED: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::ActivationMetadataPublic,
    Event::RecipientDeliveryUncertaintyPublic,
    Event::ActivationRecipientReleasePublic,
    Event::ExactRedeliveryIdentityPublic,
    Event::SigningWorkerActivationReceiptPublic,
];
const EVENTS_EXPORT_UNCERTAIN: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::RecipientDeliveryUncertaintyPublic,
];
const EVENTS_EXPORT_RELEASED: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::RecipientDeliveryUncertaintyPublic,
    Event::ExportReleasePublic,
];
const EVENTS_EXPORT_REDELIVERED: &[Event] = &[
    Event::CeremonyPublic,
    Event::EvaluationInputsAcceptedPublic,
    Event::PeerProgressPublic,
    Event::OutputCommitmentPublic,
    Event::RecipientDeliveryUncertaintyPublic,
    Event::ExportReleasePublic,
    Event::ExactRedeliveryIdentityPublic,
];

const fn public_events(stage: SemanticStageV1) -> &'static [Event] {
    match stage {
        SemanticStageV1::CeremonyAdmitted(_) => EVENTS_ADMITTED,
        SemanticStageV1::EvaluationInputsAccepted(_) => EVENTS_INPUTS,
        SemanticStageV1::PeerProtocolInProgress(_) => EVENTS_PEER,
        SemanticStageV1::OutputCommitted(_) => EVENTS_OUTPUT,
        SemanticStageV1::EvaluatorAborted(_) => EVENTS_ABORT,
        SemanticStageV1::ActivationMetadataConsumed => EVENTS_ACTIVATION_METADATA,
        SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Activation) => {
            EVENTS_ACTIVATION_UNCERTAIN
        }
        SemanticStageV1::ActivationRecipientsReleased => EVENTS_ACTIVATION_RELEASED,
        SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Activation) => {
            EVENTS_ACTIVATION_REDELIVERED
        }
        SemanticStageV1::SigningWorkerActivated => EVENTS_ACTIVATED,
        SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Export) => {
            EVENTS_EXPORT_UNCERTAIN
        }
        SemanticStageV1::ExportReleased => EVENTS_EXPORT_RELEASED,
        SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Export) => EVENTS_EXPORT_REDELIVERED,
    }
}

const NO_FRAMES: &[Frame] = &[];
const CLIENT_REQUEST: &[Frame] = &[Frame::ClientToRouterEvaluationRequest];
const DERIVER_A_INPUT: &[Frame] = &[Frame::RouterToDeriverAInputDelivery];
const DERIVER_B_INPUT: &[Frame] = &[Frame::RouterToDeriverBInputDelivery];
const WORKER_DELIVERY: &[Frame] = &[Frame::RouterToSigningWorkerRecipientDelivery];
const DERIVER_A_PEER_CUMULATIVE: &[Frame] = &[
    Frame::RouterToDeriverAInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
];
const DERIVER_A_OUTPUT_CUMULATIVE: &[Frame] = &[
    Frame::RouterToDeriverAInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
    Frame::DeriverAToRouterOutputPackages,
];
const DERIVER_B_PEER_CUMULATIVE: &[Frame] = &[
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
];
const DERIVER_B_OUTPUT_CUMULATIVE: &[Frame] = &[
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
    Frame::DeriverBToRouterOutputPackages,
];
const CLIENT_DELIVERY_CUMULATIVE: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToClientRecipientDelivery,
];
const WORKER_ACTIVATED_CUMULATIVE: &[Frame] = &[
    Frame::RouterToSigningWorkerRecipientDelivery,
    Frame::SigningWorkerToRouterActivationReceipt,
];
const ROUTER_INPUTS_CUMULATIVE: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
];
const ROUTER_OUTPUTS_CUMULATIVE: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
];
const ROUTER_ACTIVATION_CONTROL_CUMULATIVE: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterLocalActivationControl,
];
const ROUTER_ACTIVATION_DELIVERY_CUMULATIVE: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterLocalActivationControl,
    Frame::RouterToClientRecipientDelivery,
    Frame::RouterToSigningWorkerRecipientDelivery,
];
const ROUTER_EXPORT_DELIVERY_CUMULATIVE: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterToClientRecipientDelivery,
];
const ROUTER_ACTIVATED_CUMULATIVE: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterLocalActivationControl,
    Frame::RouterToClientRecipientDelivery,
    Frame::RouterToSigningWorkerRecipientDelivery,
    Frame::SigningWorkerToRouterActivationReceipt,
];
const DIAGNOSTICS_ADMITTED: &[Frame] = &[Frame::ClientToRouterEvaluationRequest];
const DIAGNOSTICS_INPUTS: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
];
const DIAGNOSTICS_PEER: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
];
const DIAGNOSTICS_OUTPUT: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
];
const DIAGNOSTICS_ACTIVATION_CONTROL: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterLocalActivationControl,
];
const DIAGNOSTICS_ACTIVATION_DELIVERY: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterLocalActivationControl,
    Frame::RouterToClientRecipientDelivery,
    Frame::RouterToSigningWorkerRecipientDelivery,
];
const DIAGNOSTICS_ACTIVATED: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterLocalActivationControl,
    Frame::RouterToClientRecipientDelivery,
    Frame::RouterToSigningWorkerRecipientDelivery,
    Frame::SigningWorkerToRouterActivationReceipt,
];
const DIAGNOSTICS_EXPORT_DELIVERY: &[Frame] = &[
    Frame::ClientToRouterEvaluationRequest,
    Frame::RouterToDeriverAInputDelivery,
    Frame::RouterToDeriverBInputDelivery,
    Frame::DeriverAToDeriverBPeerProtocol,
    Frame::DeriverBToDeriverAPeerProtocol,
    Frame::DeriverAToRouterOutputPackages,
    Frame::DeriverBToRouterOutputPackages,
    Frame::RouterToClientRecipientDelivery,
];

const fn deriver_a_frames(stage: SemanticStageV1) -> &'static [Frame] {
    match stage {
        SemanticStageV1::EvaluationInputsAccepted(_) => DERIVER_A_INPUT,
        SemanticStageV1::PeerProtocolInProgress(_) | SemanticStageV1::EvaluatorAborted(_) => {
            DERIVER_A_PEER_CUMULATIVE
        }
        SemanticStageV1::OutputCommitted(_)
        | SemanticStageV1::ActivationMetadataConsumed
        | SemanticStageV1::RecipientDeliveryUncertain(_)
        | SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExportReleased
        | SemanticStageV1::SigningWorkerActivated
        | SemanticStageV1::ExactRedelivery(_) => DERIVER_A_OUTPUT_CUMULATIVE,
        SemanticStageV1::CeremonyAdmitted(_) => NO_FRAMES,
    }
}

const fn deriver_b_frames(stage: SemanticStageV1) -> &'static [Frame] {
    match stage {
        SemanticStageV1::EvaluationInputsAccepted(_) => DERIVER_B_INPUT,
        SemanticStageV1::PeerProtocolInProgress(_) | SemanticStageV1::EvaluatorAborted(_) => {
            DERIVER_B_PEER_CUMULATIVE
        }
        SemanticStageV1::OutputCommitted(_)
        | SemanticStageV1::ActivationMetadataConsumed
        | SemanticStageV1::RecipientDeliveryUncertain(_)
        | SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExportReleased
        | SemanticStageV1::SigningWorkerActivated
        | SemanticStageV1::ExactRedelivery(_) => DERIVER_B_OUTPUT_CUMULATIVE,
        SemanticStageV1::CeremonyAdmitted(_) => NO_FRAMES,
    }
}

const fn client_frames(stage: SemanticStageV1) -> &'static [Frame] {
    match stage {
        SemanticStageV1::CeremonyAdmitted(_)
        | SemanticStageV1::EvaluationInputsAccepted(_)
        | SemanticStageV1::PeerProtocolInProgress(_)
        | SemanticStageV1::OutputCommitted(_)
        | SemanticStageV1::EvaluatorAborted(_)
        | SemanticStageV1::ActivationMetadataConsumed => CLIENT_REQUEST,
        SemanticStageV1::RecipientDeliveryUncertain(_)
        | SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExportReleased
        | SemanticStageV1::SigningWorkerActivated
        | SemanticStageV1::ExactRedelivery(_) => CLIENT_DELIVERY_CUMULATIVE,
    }
}

const fn signing_worker_frames(stage: SemanticStageV1) -> &'static [Frame] {
    match stage {
        SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Activation)
        | SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Activation) => WORKER_DELIVERY,
        SemanticStageV1::SigningWorkerActivated => WORKER_ACTIVATED_CUMULATIVE,
        _ => NO_FRAMES,
    }
}

const fn router_frames(stage: SemanticStageV1) -> &'static [Frame] {
    match stage {
        SemanticStageV1::CeremonyAdmitted(_) => CLIENT_REQUEST,
        SemanticStageV1::EvaluationInputsAccepted(_)
        | SemanticStageV1::PeerProtocolInProgress(_)
        | SemanticStageV1::EvaluatorAborted(_) => ROUTER_INPUTS_CUMULATIVE,
        SemanticStageV1::OutputCommitted(_) => ROUTER_OUTPUTS_CUMULATIVE,
        SemanticStageV1::ActivationMetadataConsumed => ROUTER_ACTIVATION_CONTROL_CUMULATIVE,
        SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Activation)
        | SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Activation) => {
            ROUTER_ACTIVATION_DELIVERY_CUMULATIVE
        }
        SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Export)
        | SemanticStageV1::ExportReleased
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Export) => {
            ROUTER_EXPORT_DELIVERY_CUMULATIVE
        }
        SemanticStageV1::SigningWorkerActivated => ROUTER_ACTIVATED_CUMULATIVE,
    }
}

const fn observer_frames(_: SemanticStageV1) -> &'static [Frame] {
    NO_FRAMES
}

const fn diagnostics_frames(stage: SemanticStageV1) -> &'static [Frame] {
    match stage {
        SemanticStageV1::CeremonyAdmitted(_) => DIAGNOSTICS_ADMITTED,
        SemanticStageV1::EvaluationInputsAccepted(_) => DIAGNOSTICS_INPUTS,
        SemanticStageV1::PeerProtocolInProgress(_) | SemanticStageV1::EvaluatorAborted(_) => {
            DIAGNOSTICS_PEER
        }
        SemanticStageV1::OutputCommitted(_) => DIAGNOSTICS_OUTPUT,
        SemanticStageV1::ActivationMetadataConsumed => DIAGNOSTICS_ACTIVATION_CONTROL,
        SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Activation)
        | SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Activation) => {
            DIAGNOSTICS_ACTIVATION_DELIVERY
        }
        SemanticStageV1::SigningWorkerActivated => DIAGNOSTICS_ACTIVATED,
        SemanticStageV1::RecipientDeliveryUncertain(RecipientFamilyV1::Export)
        | SemanticStageV1::ExportReleased
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Export) => {
            DIAGNOSTICS_EXPORT_DELIVERY
        }
    }
}

const EMPTY_VALUES: &[Value] = &[];
const DERIVER_A_ACTIVATION_INPUT_VALUES: &[Value] = &[Value::DeriverAActivationInputs];
const DERIVER_A_EXPORT_INPUT_VALUES: &[Value] = &[Value::DeriverAExportInputs];
const DERIVER_A_ACTIVATION_PEER_VALUES: &[Value] = &[
    Value::DeriverAActivationInputs,
    Value::DeriverAPeerLocalState,
    Value::DeriverAProtocolRandomness,
];
const DERIVER_A_EXPORT_PEER_VALUES: &[Value] = &[
    Value::DeriverAExportInputs,
    Value::DeriverAPeerLocalState,
    Value::DeriverAProtocolRandomness,
];
const DERIVER_A_ACTIVATION_OUTPUT_VALUES: &[Value] = &[
    Value::DeriverAActivationInputs,
    Value::DeriverAPeerLocalState,
    Value::DeriverAProtocolRandomness,
    Value::DeriverAActivationOutputShares,
];
const DERIVER_A_EXPORT_OUTPUT_VALUES: &[Value] = &[
    Value::DeriverAExportInputs,
    Value::DeriverAPeerLocalState,
    Value::DeriverAProtocolRandomness,
    Value::DeriverAExportSeedShare,
];
const DERIVER_B_ACTIVATION_INPUT_VALUES: &[Value] = &[Value::DeriverBActivationInputs];
const DERIVER_B_EXPORT_INPUT_VALUES: &[Value] = &[Value::DeriverBExportInputs];
const DERIVER_B_ACTIVATION_PEER_VALUES: &[Value] = &[
    Value::DeriverBActivationInputs,
    Value::DeriverBPeerLocalState,
    Value::DeriverBProtocolRandomness,
];
const DERIVER_B_EXPORT_PEER_VALUES: &[Value] = &[
    Value::DeriverBExportInputs,
    Value::DeriverBPeerLocalState,
    Value::DeriverBProtocolRandomness,
];
const DERIVER_B_ACTIVATION_OUTPUT_VALUES: &[Value] = &[
    Value::DeriverBActivationInputs,
    Value::DeriverBPeerLocalState,
    Value::DeriverBProtocolRandomness,
    Value::DeriverBActivationOutputShares,
];
const DERIVER_B_EXPORT_OUTPUT_VALUES: &[Value] = &[
    Value::DeriverBExportInputs,
    Value::DeriverBPeerLocalState,
    Value::DeriverBProtocolRandomness,
    Value::DeriverBExportSeedShare,
];

const fn evaluation_progress(stage: SemanticStageV1) -> u8 {
    match stage {
        SemanticStageV1::CeremonyAdmitted(_) => 0,
        SemanticStageV1::EvaluationInputsAccepted(_) => 1,
        SemanticStageV1::PeerProtocolInProgress(_) => 2,
        SemanticStageV1::EvaluatorAborted(_) => 3,
        _ => 4,
    }
}

const fn deriver_a_values(stage: SemanticStageV1) -> &'static [Value] {
    match (evaluation_progress(stage), stage.evaluation_family()) {
        (0, _) => EMPTY_VALUES,
        (1, EvaluationFamilyV1::Activation) => DERIVER_A_ACTIVATION_INPUT_VALUES,
        (1, EvaluationFamilyV1::Export) => DERIVER_A_EXPORT_INPUT_VALUES,
        (2 | 3, EvaluationFamilyV1::Activation) => DERIVER_A_ACTIVATION_PEER_VALUES,
        (2 | 3, EvaluationFamilyV1::Export) => DERIVER_A_EXPORT_PEER_VALUES,
        (_, EvaluationFamilyV1::Activation) => DERIVER_A_ACTIVATION_OUTPUT_VALUES,
        (_, EvaluationFamilyV1::Export) => DERIVER_A_EXPORT_OUTPUT_VALUES,
    }
}

const fn deriver_b_values(stage: SemanticStageV1) -> &'static [Value] {
    match (evaluation_progress(stage), stage.evaluation_family()) {
        (0, _) => EMPTY_VALUES,
        (1, EvaluationFamilyV1::Activation) => DERIVER_B_ACTIVATION_INPUT_VALUES,
        (1, EvaluationFamilyV1::Export) => DERIVER_B_EXPORT_INPUT_VALUES,
        (2 | 3, EvaluationFamilyV1::Activation) => DERIVER_B_ACTIVATION_PEER_VALUES,
        (2 | 3, EvaluationFamilyV1::Export) => DERIVER_B_EXPORT_PEER_VALUES,
        (_, EvaluationFamilyV1::Activation) => DERIVER_B_ACTIVATION_OUTPUT_VALUES,
        (_, EvaluationFamilyV1::Export) => DERIVER_B_EXPORT_OUTPUT_VALUES,
    }
}

const CLIENT_BASE: &[Value] = &[Value::ClientRoleScopedInputs];
const CLIENT_ACTIVATION_RELEASED: &[Value] =
    &[Value::ClientRoleScopedInputs, Value::ClientActivationScalar];
const CLIENT_EXPORT_RELEASED: &[Value] = &[Value::ClientRoleScopedInputs, Value::ClientExportSeed];

const fn client_values(stage: SemanticStageV1) -> &'static [Value] {
    match stage {
        SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::SigningWorkerActivated
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Activation) => {
            CLIENT_ACTIVATION_RELEASED
        }
        SemanticStageV1::ExportReleased
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Export) => CLIENT_EXPORT_RELEASED,
        _ => CLIENT_BASE,
    }
}

const WORKER_RELEASED: &[Value] = &[Value::SigningWorkerActivationAuthority];
const WORKER_ACTIVATED: &[Value] = &[
    Value::SigningWorkerActivationAuthority,
    Value::SigningWorkerActivatedScalar,
];

const fn signing_worker_values(stage: SemanticStageV1) -> &'static [Value] {
    match stage {
        SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Activation) => WORKER_RELEASED,
        SemanticStageV1::SigningWorkerActivated => WORKER_ACTIVATED,
        _ => EMPTY_VALUES,
    }
}

const ROUTER_BASE: &[Value] = &[Value::RouterLifecycleControlKnowledge];
const ROUTER_INPUT: &[Value] = &[
    Value::RouterLifecycleControlKnowledge,
    Value::RouterOpaqueRoleEnvelopeIdentities,
];
const ROUTER_OUTPUT: &[Value] = &[
    Value::RouterLifecycleControlKnowledge,
    Value::RouterOpaqueRoleEnvelopeIdentities,
    Value::RouterOpaqueOutputPackageIdentities,
    Value::RouterReceiptControlKnowledge,
];
const ROUTER_DELIVERY: &[Value] = &[
    Value::RouterLifecycleControlKnowledge,
    Value::RouterOpaqueRoleEnvelopeIdentities,
    Value::RouterOpaqueOutputPackageIdentities,
    Value::RouterReceiptControlKnowledge,
    Value::RouterOpaqueRecipientDeliveryIdentities,
];

const fn router_values(stage: SemanticStageV1) -> &'static [Value] {
    match stage {
        SemanticStageV1::EvaluationInputsAccepted(_)
        | SemanticStageV1::PeerProtocolInProgress(_)
        | SemanticStageV1::EvaluatorAborted(_) => ROUTER_INPUT,
        SemanticStageV1::OutputCommitted(_) | SemanticStageV1::ActivationMetadataConsumed => {
            ROUTER_OUTPUT
        }
        SemanticStageV1::RecipientDeliveryUncertain(_)
        | SemanticStageV1::ActivationRecipientsReleased
        | SemanticStageV1::ExportReleased
        | SemanticStageV1::ExactRedelivery(_) => ROUTER_DELIVERY,
        SemanticStageV1::SigningWorkerActivated => ROUTER_DELIVERY,
        _ => ROUTER_BASE,
    }
}

const fn observer_values(_: SemanticStageV1) -> &'static [Value] {
    EMPTY_VALUES
}

const fn diagnostics_values(_: SemanticStageV1) -> &'static [Value] {
    EMPTY_VALUES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(stage: SemanticStageV1) -> HostOnlySemanticDeliveryViewSetV1 {
        HostOnlySemanticDeliveryViewSetV1 { stage }
    }

    #[test]
    fn frozen_orders_have_exact_counts_and_unique_labels() {
        assert_eq!(HOST_ONLY_SEMANTIC_DELIVERY_STATES_V1.len(), 11);
        assert_eq!(HOST_ONLY_SEMANTIC_ROLES_V1.len(), 7);
        assert_eq!(HOST_ONLY_SEMANTIC_PRIVATE_VALUE_CLASSES_V1.len(), 22);
        for (index, value) in HOST_ONLY_SEMANTIC_PRIVATE_VALUE_CLASSES_V1
            .iter()
            .enumerate()
        {
            assert!(!value.as_str().is_empty());
            assert!(!HOST_ONLY_SEMANTIC_PRIVATE_VALUE_CLASSES_V1[..index].contains(value));
        }
    }

    #[test]
    fn activation_control_and_export_never_emit_deriver_or_worker_frames() {
        let activation = stage(SemanticStageV1::ActivationMetadataConsumed);
        assert!(!activation
            .observe_deriver_a_v1()
            .observed_frame_classes()
            .contains(&Frame::RouterLocalActivationControl));
        let export = stage(SemanticStageV1::ExportReleased);
        assert!(export
            .observe_signing_worker_v1()
            .observed_frame_classes()
            .is_empty());
    }

    #[test]
    fn router_cannot_observe_peer_protocol_classes() {
        let router = stage(SemanticStageV1::PeerProtocolInProgress(
            EvaluationFamilyV1::Activation,
        ))
        .observe_router_v1();
        assert!(!router
            .observed_frame_classes()
            .contains(&Frame::DeriverAToDeriverBPeerProtocol));
        assert!(!router
            .observed_frame_classes()
            .contains(&Frame::DeriverBToDeriverAPeerProtocol));
    }

    #[test]
    fn cumulative_views_retain_prior_learning_through_delivery() {
        let a_output = stage(SemanticStageV1::OutputCommitted(
            EvaluationFamilyV1::Activation,
        ))
        .observe_deriver_a_v1();
        let a_redelivery = stage(SemanticStageV1::ExactRedelivery(
            RecipientFamilyV1::Activation,
        ))
        .observe_deriver_a_v1();
        for value in a_output.known_private_values() {
            assert!(a_redelivery.known_private_values().contains(value));
        }

        let client_release = stage(SemanticStageV1::ExportReleased).observe_client_v1();
        let client_redelivery =
            stage(SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Export)).observe_client_v1();
        assert_eq!(
            client_release.known_private_values(),
            client_redelivery.known_private_values()
        );
    }

    #[test]
    fn redelivery_ordering_preserves_activation_and_export_recipient_sets() {
        let activation = stage(SemanticStageV1::ExactRedelivery(
            RecipientFamilyV1::Activation,
        ));
        assert_eq!(
            activation
                .observe_signing_worker_v1()
                .observed_frame_classes(),
            WORKER_DELIVERY
        );
        let export = stage(SemanticStageV1::ExactRedelivery(RecipientFamilyV1::Export));
        assert!(export
            .observe_signing_worker_v1()
            .observed_frame_classes()
            .is_empty());
    }

    #[test]
    fn opposite_deriver_values_never_cross_role_views() {
        let a = stage(SemanticStageV1::OutputCommitted(
            EvaluationFamilyV1::Activation,
        ))
        .observe_deriver_a_v1();
        assert!(!a
            .known_private_values()
            .contains(&Value::DeriverBActivationInputs));
        assert!(!a
            .known_private_values()
            .contains(&Value::DeriverBActivationOutputShares));
    }

    #[test]
    fn canonical_trace_plans_fix_release_redelivery_and_abort_order() {
        let activation = activation_success_trace_steps_v1();
        assert_eq!(activation.len(), 9);
        assert_eq!(
            activation[6].state(),
            HostOnlySemanticDeliveryStateV1::ActivationRecipientsReleased
        );
        assert!(activation[6].emitted_frame_classes().is_empty());
        assert_eq!(
            activation[7].state(),
            HostOnlySemanticDeliveryStateV1::ExactRedelivery
        );
        assert_eq!(
            activation[8].state(),
            HostOnlySemanticDeliveryStateV1::SigningWorkerActivated
        );
        assert!(activation[7]
            .view_set()
            .observe_diagnostics_v1()
            .known_public_events()
            .contains(&Event::ExactRedeliveryIdentityPublic));

        let export = export_success_trace_steps_v1();
        assert_eq!(
            export[5].state(),
            HostOnlySemanticDeliveryStateV1::ExportReleased
        );
        assert!(export[5].emitted_frame_classes().is_empty());
        assert_eq!(
            export[6].state(),
            HostOnlySemanticDeliveryStateV1::ExactRedelivery
        );

        assert!(evaluator_abort_trace_steps_v1(CeremonyRequestKindV1::Activation).is_none());
        let abort = evaluator_abort_trace_steps_v1(CeremonyRequestKindV1::Recovery)
            .expect("recovery evaluates");
        assert_eq!(
            abort[3].state(),
            HostOnlySemanticDeliveryStateV1::EvaluatorAborted
        );
        assert!(abort[3].emitted_frame_classes().is_empty());
    }

    #[test]
    fn identity_continuity_rejects_cross_trace_splices() {
        let expected = (ActivationPackageOriginV1::Registration, [7; 32], [9; 32]);
        assert!(activation_trace_identities_match(
            ActivationPackageOriginV1::Registration,
            expected,
            [expected; 5]
        ));
        let mut spliced = [expected; 5];
        spliced[3].1 = [8; 32];
        assert!(!activation_trace_identities_match(
            ActivationPackageOriginV1::Registration,
            expected,
            spliced
        ));
        assert!(!activation_trace_identities_match(
            ActivationPackageOriginV1::Recovery,
            expected,
            [expected; 5]
        ));

        let export = ([3; 32], [4; 32]);
        assert!(export_trace_identities_match(export, [export; 3]));
        let mut export_splice = [export; 3];
        export_splice[1].1 = [5; 32];
        assert!(!export_trace_identities_match(export, export_splice));
    }
}
