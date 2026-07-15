//! Construction-independent activation persistence projections.
//!
//! These nonserializable host-only values retain public digests and epochs only.
//! They model the lean output-committed, rejected-attempt self-loop, and
//! metadata-consumed control transitions shared by all selectable P0-P3
//! profiles. Durable storage records, signatures, replay databases, redelivery
//! ciphertexts, worker activation, and preprocessing state remain profile- and
//! platform-specific work.

use crate::authenticated_store::AuthenticatedRegisteredStoreResolutionV1;
use crate::ceremony_context::{
    CeremonyActivationEpochV1, CeremonyAuthorizationDigest32V1, CeremonyPackageSetDigest32V1,
    CeremonyPublicRequestContextDigest32V1, CeremonyRequestKindV1, CeremonyTranscriptDigest32V1,
};
use crate::lifecycle_domain::{
    ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1, ArtifactEvaluationFailureV1,
    BurnedArtifactAttemptV1, FailedExportArtifactAttemptV1, FailedRecoveryArtifactAttemptV1,
    FailedRefreshArtifactAttemptV1, FailedRegistrationArtifactAttemptV1,
    PendingActivationPreStateV1, RegisteredLifecyclePreStateV1,
    RejectedActivationControlProposalV1, UniformLifecycleAbortV1,
};
use crate::semantic_artifacts::{
    ActivationArtifactBindingV1, ActivationOutputCommittedReceiptDigest32V1, OneUseExecutionId32V1,
};
use crate::RegisteredEd25519PublicKey32V1;

/// Digest-only identity of one exact output-committed activation artifact set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCommittedArtifactIdentityV1 {
    origin: ActivationPackageOriginV1,
    origin_request_kind: CeremonyRequestKindV1,
    origin_request_context_digest: CeremonyPublicRequestContextDigest32V1,
    origin_authorization_digest: CeremonyAuthorizationDigest32V1,
    origin_transcript_digest: CeremonyTranscriptDigest32V1,
    one_use_execution_id: OneUseExecutionId32V1,
    package_set_digest: CeremonyPackageSetDigest32V1,
    receipt_digest: ActivationOutputCommittedReceiptDigest32V1,
    activation_epoch: CeremonyActivationEpochV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
}

impl OutputCommittedArtifactIdentityV1 {
    pub(crate) fn from_binding(
        binding: ActivationArtifactBindingV1,
        receipt_digest: ActivationOutputCommittedReceiptDigest32V1,
    ) -> Self {
        Self {
            origin: binding.origin(),
            origin_request_kind: binding.origin_request_kind(),
            origin_request_context_digest: binding.origin_request_context_digest(),
            origin_authorization_digest: binding.origin_authorization_digest(),
            origin_transcript_digest: binding.origin_transcript_digest(),
            one_use_execution_id: binding.one_use_execution_id(),
            package_set_digest: binding.package_set_digest(),
            receipt_digest,
            activation_epoch: binding.activation_epoch(),
            registered_public_key: binding.registered_public_key(),
        }
    }

    /// Returns the evaluation branch that produced the committed artifacts.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        self.origin
    }

    /// Returns the canonical origin request kind.
    pub const fn origin_request_kind(&self) -> CeremonyRequestKindV1 {
        self.origin_request_kind
    }

    /// Returns the origin request-context digest.
    pub const fn origin_request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1 {
        self.origin_request_context_digest
    }

    /// Returns the origin authorization digest.
    pub const fn origin_authorization_digest(&self) -> CeremonyAuthorizationDigest32V1 {
        self.origin_authorization_digest
    }

    /// Returns the origin transcript digest.
    pub const fn origin_transcript_digest(&self) -> CeremonyTranscriptDigest32V1 {
        self.origin_transcript_digest
    }

    /// Returns the one-use execution identifier.
    pub const fn one_use_execution_id(&self) -> OneUseExecutionId32V1 {
        self.one_use_execution_id
    }

    /// Returns the committed package-set digest.
    pub const fn package_set_digest(&self) -> CeremonyPackageSetDigest32V1 {
        self.package_set_digest
    }

    /// Returns the exact output-committed receipt digest.
    pub const fn receipt_digest(&self) -> ActivationOutputCommittedReceiptDigest32V1 {
        self.receipt_digest
    }

    /// Returns the selected activation epoch.
    pub const fn activation_epoch(&self) -> CeremonyActivationEpochV1 {
        self.activation_epoch
    }

    /// Returns the established or preserved registered key.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }
}

fn identity_from_pending(
    pending: &PendingActivationPreStateV1,
) -> OutputCommittedArtifactIdentityV1 {
    OutputCommittedArtifactIdentityV1::from_binding(
        pending.artifact_binding(),
        pending.artifacts().receipt().digest(),
    )
}

/// Abstract output-committed state retained before activation succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCommittedActivationProjectionV1 {
    identity: OutputCommittedArtifactIdentityV1,
}

impl OutputCommittedActivationProjectionV1 {
    /// Projects one move-owned pending state into public digest-only persistence.
    pub fn from_pending(pending: &PendingActivationPreStateV1) -> Self {
        Self {
            identity: identity_from_pending(pending),
        }
    }

    /// Returns the exact committed artifact identity.
    pub const fn identity(&self) -> OutputCommittedArtifactIdentityV1 {
        self.identity
    }
}

/// Rejected activation attempt whose durable artifact state is an exact self-loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptRejectedActivationProjectionV1 {
    retained: OutputCommittedActivationProjectionV1,
    abort: UniformLifecycleAbortV1,
}

impl AttemptRejectedActivationProjectionV1 {
    /// Projects one retry-preserving rejection without consuming pending artifacts.
    pub fn from_rejection(rejection: &RejectedActivationControlProposalV1) -> Self {
        Self {
            retained: OutputCommittedActivationProjectionV1::from_pending(rejection.pending()),
            abort: rejection.abort(),
        }
    }

    /// Returns the output-committed state before the rejected attempt.
    pub const fn before(&self) -> OutputCommittedActivationProjectionV1 {
        self.retained
    }

    /// Returns the identical output-committed state after the rejected attempt.
    pub const fn after(&self) -> OutputCommittedActivationProjectionV1 {
        self.retained
    }

    /// Returns the public-only rejection envelope.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        self.abort
    }
}

/// Digest-only metadata-consumed state without a worker-activation claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataConsumedActivationProjectionV1 {
    committed: OutputCommittedActivationProjectionV1,
    activation_request_context_digest: CeremonyPublicRequestContextDigest32V1,
    activation_authorization_digest: CeremonyAuthorizationDigest32V1,
    activation_transcript_digest: CeremonyTranscriptDigest32V1,
}

impl MetadataConsumedActivationProjectionV1 {
    /// Projects one metadata/control consumption into its public durable identity.
    pub fn from_success(success: &ActivationMetadataConsumptionSuccessV1) -> Self {
        let state = success.post_state();
        let identity = OutputCommittedArtifactIdentityV1::from_binding(
            state.artifact_binding(),
            state.artifacts().receipt().digest(),
        );
        let activation = state.activation_dag();
        Self {
            committed: OutputCommittedActivationProjectionV1 { identity },
            activation_request_context_digest: activation.request_context_digest(),
            activation_authorization_digest: activation.authorization_digest(),
            activation_transcript_digest: activation.transcript_digest(),
        }
    }

    /// Returns the exact artifact identity whose metadata authority was consumed.
    pub const fn committed(&self) -> OutputCommittedActivationProjectionV1 {
        self.committed
    }

    /// Returns the activation request-context digest.
    pub const fn activation_request_context_digest(
        &self,
    ) -> CeremonyPublicRequestContextDigest32V1 {
        self.activation_request_context_digest
    }

    /// Returns the activation authorization digest.
    pub const fn activation_authorization_digest(&self) -> CeremonyAuthorizationDigest32V1 {
        self.activation_authorization_digest
    }

    /// Returns the activation transcript digest.
    pub const fn activation_transcript_digest(&self) -> CeremonyTranscriptDigest32V1 {
        self.activation_transcript_digest
    }
}

/// Lean construction-independent activation persistence family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationPersistenceProjectionV1 {
    /// Output artifacts are committed and await activation.
    OutputCommitted(OutputCommittedActivationProjectionV1),
    /// One attempt was rejected while the committed state remained unchanged.
    AttemptRejected(AttemptRejectedActivationProjectionV1),
    /// Control metadata was consumed; worker activation remains unproven.
    MetadataConsumed(MetadataConsumedActivationProjectionV1),
}

/// Construction-independent pre-state class retained by an admitted evaluator abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationAbortPreStateClassV1 {
    /// Registration remains unregistered.
    Unregistered,
    /// Recovery retains its authenticated credential suspension.
    RecoveryCredentialSuspended,
    /// Refresh and export retain the exact registered pre-state.
    Registered,
}

/// Closed registration state effect after an admitted evaluation abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationEvaluationAbortStateV1 {
    /// No registered state was created.
    Unregistered,
}

/// Registration abort after the request and one-use attempt were burned.
pub struct RegistrationEvaluationAbortedProjectionV1 {
    abort: UniformLifecycleAbortV1,
    retained: FailedRegistrationArtifactAttemptV1,
}

impl RegistrationEvaluationAbortedProjectionV1 {
    #[allow(dead_code)]
    fn from_failure(
        failure: ArtifactEvaluationFailureV1<FailedRegistrationArtifactAttemptV1>,
    ) -> Self {
        let abort = failure.abort();
        Self {
            abort,
            retained: failure.into_retained(),
        }
    }

    /// Returns the unregistered state before evaluation.
    pub const fn before(&self) -> RegistrationEvaluationAbortStateV1 {
        RegistrationEvaluationAbortStateV1::Unregistered
    }

    /// Returns the identical unregistered state after evaluation aborts.
    pub const fn after(&self) -> RegistrationEvaluationAbortStateV1 {
        RegistrationEvaluationAbortStateV1::Unregistered
    }

    /// Returns the burned request and one-use attempt identity.
    pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
        self.retained.burned()
    }

    /// Returns the exact terminal selection retained outside public abort views.
    pub const fn terminal_selection(
        &self,
    ) -> &crate::registration_evaluation_admission::TerminalRegistrationSelectionV1 {
        self.retained.terminal_selection()
    }

    /// Returns the uniform public abort.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        self.abort
    }
}

macro_rules! define_registered_evaluation_abort_projection {
    ($name:ident, $retained:ident, $documentation:literal) => {
        #[doc = $documentation]
        pub struct $name {
            abort: UniformLifecycleAbortV1,
            retained: $retained,
        }

        impl $name {
            #[allow(dead_code)]
            fn from_failure(failure: ArtifactEvaluationFailureV1<$retained>) -> Self {
                let abort = failure.abort();
                Self {
                    abort,
                    retained: failure.into_retained(),
                }
            }

            /// Returns the exact registered state before evaluation.
            pub const fn before(&self) -> &RegisteredLifecyclePreStateV1 {
                self.retained.state()
            }

            /// Returns the identical registered state after evaluation aborts.
            pub const fn after(&self) -> &RegisteredLifecyclePreStateV1 {
                self.retained.state()
            }

            /// Returns the burned request and one-use attempt identity.
            pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
                self.retained.burned()
            }

            /// Returns the uniform public abort.
            pub const fn abort(&self) -> UniformLifecycleAbortV1 {
                self.abort
            }

            /// Recovers the unchanged authenticated registered state.
            pub fn into_state(self) -> AuthenticatedRegisteredStoreResolutionV1 {
                self.retained.into_state()
            }
        }
    };
}

define_registered_evaluation_abort_projection!(
    ExportEvaluationAbortedProjectionV1,
    FailedExportArtifactAttemptV1,
    "Export abort retaining the exact registered pre-state without releasing a seed."
);

/// Refresh abort retaining current state plus terminal transition audit identity.
pub struct RefreshEvaluationAbortedProjectionV1 {
    abort: UniformLifecycleAbortV1,
    retained: FailedRefreshArtifactAttemptV1,
}

impl RefreshEvaluationAbortedProjectionV1 {
    #[allow(dead_code)]
    fn from_failure(failure: ArtifactEvaluationFailureV1<FailedRefreshArtifactAttemptV1>) -> Self {
        let abort = failure.abort();
        Self {
            abort,
            retained: failure.into_retained(),
        }
    }

    /// Returns the exact registered state before evaluation.
    pub const fn before(&self) -> &RegisteredLifecyclePreStateV1 {
        self.retained.terminal().state().state()
    }

    /// Returns the identical active registered state after evaluation aborts.
    pub const fn after(&self) -> &RegisteredLifecyclePreStateV1 {
        self.retained.terminal().state().state()
    }

    /// Returns the burned request and one-use attempt identity.
    pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
        self.retained.burned()
    }

    /// Returns the uniform public abort.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        self.abort
    }

    /// Returns the retained terminal admission for audit identity.
    pub const fn terminal(
        &self,
    ) -> &crate::refresh_evaluation_admission::TerminalRefreshEvaluationV1 {
        self.retained.terminal()
    }

    /// Recovers terminal audit authority without creating a retry path.
    pub fn into_terminal(self) -> crate::refresh_evaluation_admission::TerminalRefreshEvaluationV1 {
        self.retained.into_terminal()
    }
}

/// Recovery abort retaining the exact authenticated credential suspension.
pub struct RecoveryEvaluationAbortedProjectionV1 {
    abort: UniformLifecycleAbortV1,
    retained: FailedRecoveryArtifactAttemptV1,
}

impl RecoveryEvaluationAbortedProjectionV1 {
    #[allow(dead_code)]
    fn from_failure(failure: ArtifactEvaluationFailureV1<FailedRecoveryArtifactAttemptV1>) -> Self {
        let abort = failure.abort();
        Self {
            abort,
            retained: failure.into_retained(),
        }
    }

    /// Returns the credential suspension before evaluator failure.
    pub const fn before(
        &self,
    ) -> &crate::recovery_credential_transition::AuthenticatedRecoveryCredentialSuspensionV1 {
        self.retained.suspension()
    }

    /// Returns the identical credential suspension after evaluator failure.
    pub const fn after(
        &self,
    ) -> &crate::recovery_credential_transition::AuthenticatedRecoveryCredentialSuspensionV1 {
        self.retained.suspension()
    }

    /// Returns the exact terminal evaluator admission retained by the abort.
    pub const fn terminal(
        &self,
    ) -> &crate::recovery_evaluation_admission::TerminalRecoveryEvaluationV1 {
        self.retained.terminal()
    }

    /// Returns the burned request and one-use attempt identity.
    pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
        self.retained.burned()
    }

    /// Returns the uniform public abort.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        self.abort
    }

    /// Recovers the terminal admission; the admitted request remains burned.
    pub fn into_terminal(
        self,
    ) -> crate::recovery_evaluation_admission::TerminalRecoveryEvaluationV1 {
        self.retained.into_terminal()
    }
}

/// Closed construction-independent admitted evaluator-abort persistence family.
pub enum EvaluationAbortedPersistenceProjectionV1 {
    /// Registration remains unregistered.
    Registration(RegistrationEvaluationAbortedProjectionV1),
    /// Recovery retains the authenticated credential suspension.
    Recovery(Box<RecoveryEvaluationAbortedProjectionV1>),
    /// Refresh discards its proposal and retains the registered state.
    Refresh(RefreshEvaluationAbortedProjectionV1),
    /// Export retains the registered state and releases no seed.
    Export(ExportEvaluationAbortedProjectionV1),
}

impl EvaluationAbortedPersistenceProjectionV1 {
    /// Consumes one admitted registration failure into its persistence projection.
    #[allow(dead_code)]
    pub(crate) fn from_registration_failure(
        failure: ArtifactEvaluationFailureV1<FailedRegistrationArtifactAttemptV1>,
    ) -> Self {
        Self::Registration(RegistrationEvaluationAbortedProjectionV1::from_failure(
            failure,
        ))
    }

    /// Consumes one admitted recovery failure into its persistence projection.
    #[allow(dead_code)]
    pub(crate) fn from_recovery_failure(
        failure: ArtifactEvaluationFailureV1<FailedRecoveryArtifactAttemptV1>,
    ) -> Self {
        Self::Recovery(Box::new(
            RecoveryEvaluationAbortedProjectionV1::from_failure(failure),
        ))
    }

    /// Consumes one admitted refresh failure into its persistence projection.
    #[allow(dead_code)]
    pub(crate) fn from_refresh_failure(
        failure: ArtifactEvaluationFailureV1<FailedRefreshArtifactAttemptV1>,
    ) -> Self {
        Self::Refresh(RefreshEvaluationAbortedProjectionV1::from_failure(failure))
    }

    /// Consumes one admitted export failure into its persistence projection.
    #[allow(dead_code)]
    pub(crate) fn from_export_failure(
        failure: ArtifactEvaluationFailureV1<FailedExportArtifactAttemptV1>,
    ) -> Self {
        Self::Export(ExportEvaluationAbortedProjectionV1::from_failure(failure))
    }

    /// Returns the request's retained pre-state class.
    pub const fn pre_state_class(&self) -> EvaluationAbortPreStateClassV1 {
        match self {
            Self::Registration(_) => EvaluationAbortPreStateClassV1::Unregistered,
            Self::Recovery(_) => EvaluationAbortPreStateClassV1::RecoveryCredentialSuspended,
            Self::Refresh(_) | Self::Export(_) => EvaluationAbortPreStateClassV1::Registered,
        }
    }

    /// Returns the burned request and one-use attempt identity.
    pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
        match self {
            Self::Registration(projection) => projection.burned(),
            Self::Recovery(projection) => projection.burned(),
            Self::Refresh(projection) => projection.burned(),
            Self::Export(projection) => projection.burned(),
        }
    }

    /// Returns the only public abort projection.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        match self {
            Self::Registration(projection) => projection.abort(),
            Self::Recovery(projection) => projection.abort(),
            Self::Refresh(projection) => projection.abort(),
            Self::Export(projection) => projection.abort(),
        }
    }
}
