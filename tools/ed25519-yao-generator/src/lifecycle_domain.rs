//! Canonical host-only lifecycle ownership for Ed25519 Yao artifacts.
//!
//! Evaluation requests own one canonical ceremony DAG and can be consumed into
//! exactly one host-reference semantic artifact session. Registered branches
//! additionally compare store-projected metadata before evaluation. Activation in this
//! slice consumes only metadata/control authority with zero reevaluation. A real
//! activated state remains blocked on sealed SigningWorker package verification,
//! recipient and epoch checks, share combination, the public-key relation, and a
//! signed idempotent worker-activation receipt.

use core::fmt;

use crate::authenticated_store::{
    ActiveStoreStateVersionV1, AuthenticatedRegisteredStoreResolutionV1,
};

use crate::ceremony_context::{
    CeremonyActivationAuthorizationV1, CeremonyActivationEpochV1, CeremonyArtifactSuiteDigest32V1,
    CeremonyAuthorizationRecordDigest32V1, CeremonyAuthorizationV1, CeremonyContextErrorV1,
    CeremonyExportAuthorizationV1, CeremonyPublicRequestContextV1, CeremonyRecoveryAuthorizationV1,
    CeremonyRefreshAuthorizationV1, CeremonyRegistrationAuthorizationV1,
    CeremonyReplacementCredentialBindingDigest32V1, CeremonyReplayNonce32V1,
    CeremonyRequestExpiryV1, CeremonyRequestIdV1, CeremonyRequestKindV1,
    CeremonyTranscriptNonce32V1, CeremonyTranscriptV1, CeremonyTransportBindingDigest32V1,
    CeremonyValidatedDagV1,
};
use crate::export_evaluation_acceptance::{
    ExportAuthorizationAcceptanceAuthoritiesV1, VerifiedExportAuthorizationAcceptancePairV1,
};
use crate::provenance::{
    DeriverAProvenanceRoleV1, DeriverBProvenanceRoleV1, ProvenanceRoleStateBindingV1,
    RecoveryContinuityArtifactDigest32V1, RegisteredStateProvenanceBindingV1,
    RegisteredStateProvenanceErrorV1,
    RoleInputProvenancePairV1, RoleInputStateEpochV1, RoleInputStateRecordDigest32V1,
    RoleRootEpochV1, RoleRootRecordDigest32V1, RootBindingArtifactDigest32V1, StableKdfScopeV1,
};
use crate::recovery_credential_transition::AuthenticatedRecoveryCredentialSuspensionV1;
use crate::recovery_evaluation_admission::{
    AcceptedRecoveryAdmissionV1, TerminalRecoveryEvaluationV1,
};
use crate::refresh_evaluation_admission::{
    AcceptedRefreshAdmissionV1, TerminalRefreshEvaluationV1,
};
use crate::registration_evaluation_admission::{
    AcceptedRegistrationAdmissionV1, RegistrationCandidateStateV1, TerminalRegistrationSelectionV1,
};
use crate::semantic_artifacts::{
    ActivationArtifactBindingV1, CommittedActivationArtifactsV1, ExportSemanticArtifactContextV1,
    HostOnlyPackagedActivationV1, OneUseExecutionId32V1,
    OpaqueHostReferenceActivationPackageBindingsV1,
    OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    OpaqueHostReferenceExportPackageBindingsV1,
    OutputCommittedExportArtifactsV1, RecoveryActivationSemanticArtifactContextV1,
    RefreshActivationSemanticArtifactContextV1, RegistrationActivationSemanticArtifactContextV1,
    SemanticArtifactErrorV1,
};
use crate::{
    HostOnlyActivationOutputSharesV1, HostOnlyExportIdealCoinV1, HostOnlyExportReferenceInputsV1,
    HostOnlyRecoveryIdealCoinsV1, HostOnlyRecoveryReferenceInputsV1, HostOnlyRefreshIdealCoinsV1,
    HostOnlyRefreshReferenceInputsV1, HostOnlyRegistrationIdealCoinsV1,
    HostOnlyRegistrationReferenceInputsV1, HostOnlySeedExportSharesV1,
    RegisteredEd25519PublicKey32V1,
};

/// Evaluation branch that produced an activation package set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationPackageOriginV1 {
    /// Registration-created artifacts.
    Registration,
    /// Same-root recovery-created artifacts.
    Recovery,
    /// Opposite-delta refresh-created artifacts.
    Refresh,
}

impl ActivationPackageOriginV1 {
    /// Returns the canonical request kind for this origin.
    pub const fn request_kind(self) -> CeremonyRequestKindV1 {
        match self {
            Self::Registration => CeremonyRequestKindV1::Registration,
            Self::Recovery => CeremonyRequestKindV1::Recovery,
            Self::Refresh => CeremonyRequestKindV1::Refresh,
        }
    }
}

macro_rules! define_evaluation_request {
    ($(#[$meta:meta])* $name:ident, $authorization:ty, $kind:ident) => {
        $(#[$meta])*
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name {
            request_context: CeremonyPublicRequestContextV1,
            authorization: $authorization,
            transcript: CeremonyTranscriptV1,
            validated_dag: CeremonyValidatedDagV1,
        }

        impl $name {
            /// Validates and takes ownership of one complete canonical ceremony DAG.
            pub fn new(
                request_context: CeremonyPublicRequestContextV1,
                authorization: $authorization,
                transcript: CeremonyTranscriptV1,
            ) -> Result<Self, CeremonyContextErrorV1> {
                let authorization_union = CeremonyAuthorizationV1::from(authorization);
                let validated_dag = CeremonyValidatedDagV1::from_components(
                    &request_context,
                    &authorization_union,
                    &transcript,
                )?;
                Ok(Self {
                    request_context,
                    authorization,
                    transcript,
                    validated_dag,
                })
            }

            /// Returns the canonical public request context.
            pub const fn request_context(&self) -> &CeremonyPublicRequestContextV1 {
                &self.request_context
            }

            /// Returns the branch-typed authorization.
            pub const fn authorization(&self) -> &$authorization {
                &self.authorization
            }

            /// Returns the canonical ceremony transcript.
            pub const fn transcript(&self) -> &CeremonyTranscriptV1 {
                &self.transcript
            }

            /// Returns the sealed coherent ceremony DAG.
            pub const fn validated_dag(&self) -> CeremonyValidatedDagV1 {
                self.validated_dag
            }

            /// Returns the request kind fixed by this branch type.
            pub const fn request_kind(&self) -> CeremonyRequestKindV1 {
                CeremonyRequestKindV1::$kind
            }
        }
    };
}

define_evaluation_request!(
    /// Canonical registration ceremony.
    RegistrationRequestV1,
    CeremonyRegistrationAuthorizationV1,
    Registration
);

/// Nonzero digest identifying the credential binding active in registered state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActiveCredentialBindingDigest32V1([u8; 32]);

impl ActiveCredentialBindingDigest32V1 {
    /// Validates one nonzero active credential binding digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, ActiveCredentialBindingErrorV1> {
        let mut index = 0;
        let mut nonzero = 0u8;
        while index < bytes.len() {
            nonzero |= bytes[index];
            index += 1;
        }
        if nonzero == 0 {
            return Err(ActiveCredentialBindingErrorV1::Zero);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact active credential binding digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Invalid active credential binding digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveCredentialBindingErrorV1 {
    /// Credential binding digests must not be all zero.
    Zero,
}

impl fmt::Display for ActiveCredentialBindingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("active credential binding digest must be nonzero")
    }
}

impl std::error::Error for ActiveCredentialBindingErrorV1 {}
define_evaluation_request!(
    /// Canonical same-root recovery ceremony.
    RecoveryRequestV1,
    CeremonyRecoveryAuthorizationV1,
    Recovery
);
define_evaluation_request!(
    /// Canonical opposite-delta refresh ceremony.
    RefreshRequestV1,
    CeremonyRefreshAuthorizationV1,
    Refresh
);
define_evaluation_request!(
    /// Canonical authorized export ceremony.
    ExportRequestV1,
    CeremonyExportAuthorizationV1,
    Export
);

/// Non-Clone host-reference projection of registered lifecycle metadata.
///
/// State-record digests are typed opaque bindings in Phase 1. Authentication of
/// those records and store reads remains mandatory Phase 6B work.
#[derive(Debug, PartialEq, Eq)]
pub struct RegisteredLifecyclePreStateV1 {
    pub(crate) registered_public_key: RegisteredEd25519PublicKey32V1,
    pub(crate) active_credential_binding_digest: ActiveCredentialBindingDigest32V1,
    pub(crate) stable_scope: StableKdfScopeV1,
    pub(crate) active_activation_epoch: CeremonyActivationEpochV1,
    pub(crate) deriver_a_root_record: RoleRootRecordDigest32V1<DeriverAProvenanceRoleV1>,
    pub(crate) deriver_a_root_binding: RootBindingArtifactDigest32V1<DeriverAProvenanceRoleV1>,
    pub(crate) deriver_a_root_epoch: RoleRootEpochV1<DeriverAProvenanceRoleV1>,
    pub(crate) deriver_a_state_record: RoleInputStateRecordDigest32V1<DeriverAProvenanceRoleV1>,
    pub(crate) deriver_a_input_state_epoch: RoleInputStateEpochV1<DeriverAProvenanceRoleV1>,
    pub(crate) deriver_b_root_record: RoleRootRecordDigest32V1<DeriverBProvenanceRoleV1>,
    pub(crate) deriver_b_root_binding: RootBindingArtifactDigest32V1<DeriverBProvenanceRoleV1>,
    pub(crate) deriver_b_root_epoch: RoleRootEpochV1<DeriverBProvenanceRoleV1>,
    pub(crate) deriver_b_state_record: RoleInputStateRecordDigest32V1<DeriverBProvenanceRoleV1>,
    pub(crate) deriver_b_input_state_epoch: RoleInputStateEpochV1<DeriverBProvenanceRoleV1>,
}

impl RegisteredLifecyclePreStateV1 {
    /// Creates a synthetic host-reference projection for lifecycle relation tests.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn from_host_reference_store_projection(
        registered_public_key: RegisteredEd25519PublicKey32V1,
        active_credential_binding_digest: ActiveCredentialBindingDigest32V1,
        stable_scope: StableKdfScopeV1,
        active_activation_epoch: CeremonyActivationEpochV1,
        deriver_a_root_record: RoleRootRecordDigest32V1<DeriverAProvenanceRoleV1>,
        deriver_a_root_binding: RootBindingArtifactDigest32V1<DeriverAProvenanceRoleV1>,
        deriver_a_root_epoch: RoleRootEpochV1<DeriverAProvenanceRoleV1>,
        deriver_a_state_record: RoleInputStateRecordDigest32V1<DeriverAProvenanceRoleV1>,
        deriver_a_input_state_epoch: RoleInputStateEpochV1<DeriverAProvenanceRoleV1>,
        deriver_b_root_record: RoleRootRecordDigest32V1<DeriverBProvenanceRoleV1>,
        deriver_b_root_binding: RootBindingArtifactDigest32V1<DeriverBProvenanceRoleV1>,
        deriver_b_root_epoch: RoleRootEpochV1<DeriverBProvenanceRoleV1>,
        deriver_b_state_record: RoleInputStateRecordDigest32V1<DeriverBProvenanceRoleV1>,
        deriver_b_input_state_epoch: RoleInputStateEpochV1<DeriverBProvenanceRoleV1>,
    ) -> Self {
        Self {
            registered_public_key,
            active_credential_binding_digest,
            stable_scope,
            active_activation_epoch,
            deriver_a_root_record,
            deriver_a_root_binding,
            deriver_a_root_epoch,
            deriver_a_state_record,
            deriver_a_input_state_epoch,
            deriver_b_root_record,
            deriver_b_root_binding,
            deriver_b_root_epoch,
            deriver_b_state_record,
            deriver_b_input_state_epoch,
        }
    }

    /// Returns the store-resolved registered key.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the credential binding currently admitted for this identity.
    pub const fn active_credential_binding_digest(&self) -> ActiveCredentialBindingDigest32V1 {
        self.active_credential_binding_digest
    }

    /// Returns the stable KDF scope.
    pub const fn stable_scope(&self) -> StableKdfScopeV1 {
        self.stable_scope
    }

    /// Returns the currently active activation epoch.
    pub const fn active_activation_epoch(&self) -> CeremonyActivationEpochV1 {
        self.active_activation_epoch
    }

    /// Returns Deriver A's current input-state epoch.
    pub const fn deriver_a_input_state_epoch(
        &self,
    ) -> RoleInputStateEpochV1<DeriverAProvenanceRoleV1> {
        self.deriver_a_input_state_epoch
    }

    /// Returns Deriver B's current input-state epoch.
    pub const fn deriver_b_input_state_epoch(
        &self,
    ) -> RoleInputStateEpochV1<DeriverBProvenanceRoleV1> {
        self.deriver_b_input_state_epoch
    }
}

/// Exact field that failed store-state to provenance validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredStateBindingFieldV1 {
    /// Registered Ed25519 public key.
    RegisteredPublicKey,
    /// Stable KDF scope.
    StableScope,
    /// Deriver A state-record digest.
    DeriverARootRecord,
    /// Deriver A root-binding artifact digest.
    DeriverARootBinding,
    /// Deriver A role-root epoch.
    DeriverARootEpoch,
    /// Deriver A state-record digest.
    DeriverAStateRecord,
    /// Deriver A input-state epoch.
    DeriverAInputStateEpoch,
    /// Deriver B state-record digest.
    DeriverBRootRecord,
    /// Deriver B root-binding artifact digest.
    DeriverBRootBinding,
    /// Deriver B role-root epoch.
    DeriverBRootEpoch,
    /// Deriver B state-record digest.
    DeriverBStateRecord,
    /// Deriver B input-state epoch.
    DeriverBInputStateEpoch,
    /// Refresh next Deriver A epoch.
    NextDeriverAInputStateEpoch,
    /// Refresh next Deriver B epoch.
    NextDeriverBInputStateEpoch,
    /// Refresh authorization current Deriver A epoch.
    AuthorizationCurrentDeriverAInputStateEpoch,
    /// Refresh authorization next Deriver A epoch.
    AuthorizationNextDeriverAInputStateEpoch,
    /// Refresh authorization current Deriver B epoch.
    AuthorizationCurrentDeriverBInputStateEpoch,
    /// Refresh authorization next Deriver B epoch.
    AuthorizationNextDeriverBInputStateEpoch,
}

/// Failure while establishing a consuming lifecycle-to-semantic session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSessionErrorV1 {
    /// The provenance pair represented another lifecycle branch.
    ProvenanceRequestKindMismatch,
    /// Store state differed from the branch provenance or authorization.
    RegisteredStateMismatch(RegisteredStateBindingFieldV1),
    /// Authenticated store authority did not bind this request and provenance pair.
    AuthenticatedStoreAuthorityRejected,
    /// The construction-independent registration admission was absent or incoherent.
    RegistrationAdmissionRejected,
    /// The construction-independent recovery admission was incoherent.
    RecoveryAdmissionRejected,
    /// The construction-independent refresh admission was incoherent.
    RefreshAdmissionRejected,
    /// Independent A/B export-authorization acceptance was absent or incoherent.
    ExportAuthorizationAcceptanceRejected,
    /// Recovery did not establish a coherent old-to-replacement credential transition.
    RecoveryCredentialContinuity(RecoveryCredentialContinuityErrorV1),
    /// The canonical semantic context rejected its bound inputs.
    Semantic(SemanticArtifactErrorV1),
}

impl fmt::Display for ArtifactSessionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProvenanceRequestKindMismatch => {
                formatter.write_str("provenance request kind does not match the lifecycle session")
            }
            Self::RegisteredStateMismatch(field) => {
                write!(
                    formatter,
                    "registered lifecycle state mismatch at {field:?}"
                )
            }
            Self::AuthenticatedStoreAuthorityRejected => {
                formatter.write_str("authenticated store authority rejected the lifecycle session")
            }
            Self::RegistrationAdmissionRejected => {
                formatter.write_str("construction-independent registration admission rejected")
            }
            Self::RecoveryAdmissionRejected => {
                formatter.write_str("construction-independent recovery admission rejected")
            }
            Self::RefreshAdmissionRejected => {
                formatter.write_str("construction-independent refresh admission rejected")
            }
            Self::ExportAuthorizationAcceptanceRejected => {
                formatter.write_str("independent A/B export authorization acceptance rejected")
            }
            Self::RecoveryCredentialContinuity(error) => error.fmt(formatter),
            Self::Semantic(error) => error.fmt(formatter),
        }
    }
}

/// Failure while sealing authenticated recovery credential-continuity evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCredentialContinuityErrorV1 {
    /// The authorized replacement credential was already the active credential.
    ReplacementCredentialDidNotChange,
    /// The provenance pair did not contain recovery same-root evidence.
    ProvenanceRequestKindMismatch,
    /// The suspension paired records from different active state versions.
    ActiveStateVersionMismatch,
    /// The suspension paired different old credential bindings.
    ActiveCredentialBindingMismatch,
    /// The suspension paired different registered Ed25519 identities.
    RegisteredPublicKeyMismatch,
    /// The suspension paired different stable KDF scopes.
    StableScopeMismatch,
}

impl fmt::Display for RecoveryCredentialContinuityErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReplacementCredentialDidNotChange => formatter
                .write_str("recovery replacement credential equals the active credential binding"),
            Self::ProvenanceRequestKindMismatch => {
                formatter.write_str("recovery credential evidence requires recovery provenance")
            }
            Self::ActiveStateVersionMismatch => {
                formatter.write_str("recovery suspension active state version mismatch")
            }
            Self::ActiveCredentialBindingMismatch => {
                formatter.write_str("recovery suspension active credential mismatch")
            }
            Self::RegisteredPublicKeyMismatch => {
                formatter.write_str("recovery suspension registered public key mismatch")
            }
            Self::StableScopeMismatch => {
                formatter.write_str("recovery suspension stable KDF scope mismatch")
            }
        }
    }
}

impl std::error::Error for RecoveryCredentialContinuityErrorV1 {}

/// Store-authenticated binding from the active credential to one replacement.
///
/// The store resolution authenticates the active state version and old
/// credential. The request authorization fixes the replacement credential, and
/// the signed provenance-pair digest fixes the same-root evidence artifact.
/// The artifact remains proof-system-specific and must be verified at the
/// production custody boundary before the store authority signs the resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedRecoveryCredentialContinuityEvidenceV1 {
    active_state_version: ActiveStoreStateVersionV1,
    active_credential_binding_digest: ActiveCredentialBindingDigest32V1,
    replacement_credential_binding_digest: CeremonyReplacementCredentialBindingDigest32V1,
    same_root_evidence_artifact_digest: RecoveryContinuityArtifactDigest32V1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    stable_scope: StableKdfScopeV1,
}

impl AuthenticatedRecoveryCredentialContinuityEvidenceV1 {
    pub(crate) fn from_authenticated_bindings(
        state: &AuthenticatedRegisteredStoreResolutionV1,
        authorization: &CeremonyRecoveryAuthorizationV1,
        provenance: &RoleInputProvenancePairV1,
    ) -> Result<Self, RecoveryCredentialContinuityErrorV1> {
        let active = state.state().active_credential_binding_digest();
        let replacement = authorization.replacement_credential_binding_digest();
        if active.as_bytes() == replacement.as_bytes() {
            return Err(RecoveryCredentialContinuityErrorV1::ReplacementCredentialDidNotChange);
        }
        let same_root_evidence_artifact_digest = provenance
            .recovery_same_root_evidence_artifact_digest()
            .map_err(|_| RecoveryCredentialContinuityErrorV1::ProvenanceRequestKindMismatch)?;
        Ok(Self {
            active_state_version: state.active_state_version(),
            active_credential_binding_digest: active,
            replacement_credential_binding_digest: replacement,
            same_root_evidence_artifact_digest,
            registered_public_key: state.state().registered_public_key(),
            stable_scope: state.state().stable_scope(),
        })
    }

    /// Returns the authenticated store version containing the active credential.
    pub const fn active_state_version(&self) -> ActiveStoreStateVersionV1 {
        self.active_state_version
    }

    /// Returns the credential binding that was active before recovery.
    pub const fn active_credential_binding_digest(&self) -> ActiveCredentialBindingDigest32V1 {
        self.active_credential_binding_digest
    }

    /// Returns the distinct replacement credential fixed by authorization.
    pub const fn replacement_credential_binding_digest(
        &self,
    ) -> CeremonyReplacementCredentialBindingDigest32V1 {
        self.replacement_credential_binding_digest
    }

    /// Returns the same-root artifact fixed by the authenticated provenance pair.
    pub const fn same_root_evidence_artifact_digest(&self) -> RecoveryContinuityArtifactDigest32V1 {
        self.same_root_evidence_artifact_digest
    }

    /// Returns the registered identity that recovery must preserve.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the stable KDF scope that recovery must preserve.
    pub const fn stable_scope(&self) -> StableKdfScopeV1 {
        self.stable_scope
    }
}

impl std::error::Error for ArtifactSessionErrorV1 {}

impl From<SemanticArtifactErrorV1> for ArtifactSessionErrorV1 {
    fn from(error: SemanticArtifactErrorV1) -> Self {
        Self::Semantic(error)
    }
}

impl From<RegisteredStateProvenanceErrorV1> for ArtifactSessionErrorV1 {
    fn from(_: RegisteredStateProvenanceErrorV1) -> Self {
        Self::ProvenanceRequestKindMismatch
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_registered_state(
    state: &RegisteredLifecyclePreStateV1,
    provenance: RegisteredStateProvenanceBindingV1,
) -> Result<(), ArtifactSessionErrorV1> {
    validate_registered_state_fields(state, provenance)
        .map_err(ArtifactSessionErrorV1::RegisteredStateMismatch)
}

pub(crate) fn validate_registered_state_fields(
    state: &RegisteredLifecyclePreStateV1,
    provenance: RegisteredStateProvenanceBindingV1,
) -> Result<(), RegisteredStateBindingFieldV1> {
    macro_rules! require_equal {
        ($actual:expr, $expected:expr, $field:ident) => {
            if $actual != $expected {
                return Err(RegisteredStateBindingFieldV1::$field);
            }
        };
    }

    require_equal!(
        state.registered_public_key,
        provenance.registered_public_key(),
        RegisteredPublicKey
    );
    require_equal!(state.stable_scope, provenance.stable_scope(), StableScope);
    let a = provenance.deriver_a();
    require_equal!(
        state.deriver_a_root_record,
        a.role_root_record_digest(),
        DeriverARootRecord
    );
    require_equal!(
        state.deriver_a_root_binding,
        a.root_binding_artifact_digest(),
        DeriverARootBinding
    );
    require_equal!(
        state.deriver_a_root_epoch,
        a.role_root_epoch(),
        DeriverARootEpoch
    );
    require_equal!(
        state.deriver_a_state_record,
        a.record_digest(),
        DeriverAStateRecord
    );
    require_equal!(
        state.deriver_a_input_state_epoch,
        a.epoch(),
        DeriverAInputStateEpoch
    );
    let b = provenance.deriver_b();
    require_equal!(
        state.deriver_b_root_record,
        b.role_root_record_digest(),
        DeriverBRootRecord
    );
    require_equal!(
        state.deriver_b_root_binding,
        b.root_binding_artifact_digest(),
        DeriverBRootBinding
    );
    require_equal!(
        state.deriver_b_root_epoch,
        b.role_root_epoch(),
        DeriverBRootEpoch
    );
    require_equal!(
        state.deriver_b_state_record,
        b.record_digest(),
        DeriverBStateRecord
    );
    require_equal!(
        state.deriver_b_input_state_epoch,
        b.epoch(),
        DeriverBInputStateEpoch
    );
    Ok(())
}

/// Host-reference first activation epoch and one-use identity for registration.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RegistrationArtifactIssuanceV1 {
    activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
    admission: AcceptedRegistrationAdmissionV1,
}

#[cfg_attr(not(test), allow(dead_code))]
impl RegistrationArtifactIssuanceV1 {
    /// Establishes the first activation epoch for one unregistered request.
    pub(crate) const fn new(
        activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
        admission: AcceptedRegistrationAdmissionV1,
    ) -> Self {
        Self {
            activation_epoch,
            one_use_execution_id,
            admission,
        }
    }
}

/// Export one-use issuance consuming the store-resolved registered state.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ExportArtifactIssuanceV1 {
    state: AuthenticatedRegisteredStoreResolutionV1,
    one_use_execution_id: OneUseExecutionId32V1,
    acceptance_authorities: ExportAuthorizationAcceptanceAuthoritiesV1,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExportArtifactIssuanceV1 {
    /// Binds one registered state resolution to one export execution.
    pub(crate) const fn new(
        state: AuthenticatedRegisteredStoreResolutionV1,
        one_use_execution_id: OneUseExecutionId32V1,
        acceptance_authorities: ExportAuthorizationAcceptanceAuthoritiesV1,
    ) -> Self {
        Self {
            state,
            one_use_execution_id,
            acceptance_authorities,
        }
    }
}

/// Rejected consuming session construction retaining request and issuance inputs.
pub struct RejectedArtifactSessionV1<Request, Issuance> {
    reason: ArtifactSessionErrorV1,
    request: Box<Request>,
    issuance: Box<Issuance>,
}

impl<Request, Issuance> RejectedArtifactSessionV1<Request, Issuance> {
    /// Returns the exact session-binding failure.
    pub const fn reason(&self) -> ArtifactSessionErrorV1 {
        self.reason
    }

    /// Recovers both move-owned inputs.
    pub fn into_parts(self) -> (Request, Issuance) {
        (*self.request, *self.issuance)
    }
}

impl<Request, Issuance> fmt::Debug for RejectedArtifactSessionV1<Request, Issuance> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedArtifactSessionV1")
            .field("reason", &self.reason)
            .field("request", &"retained")
            .field("issuance", &"retained")
            .finish()
    }
}

/// Separate A/B evidence required to commit activation artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationReceiptEvidenceV1 {
    deriver_a: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    deriver_b: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
}

impl ActivationReceiptEvidenceV1 {
    /// Creates complete role-separated activation receipt evidence.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn new(
        deriver_a: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        deriver_b: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_b,
        }
    }
}

/// Separate A/B evidence required to commit export outputs before client release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOutputCommitmentEvidenceV1 {
    deriver_a: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    deriver_b: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
}

impl ExportOutputCommitmentEvidenceV1 {
    /// Creates complete role-separated export output-commitment evidence.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn new(
        deriver_a: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        deriver_b: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_b,
        }
    }
}

/// Non-callable audit identity for a burned artifact attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnedArtifactAttemptV1 {
    request_kind: CeremonyRequestKindV1,
    request_context_digest: crate::ceremony_context::CeremonyPublicRequestContextDigest32V1,
    authorization_digest: crate::ceremony_context::CeremonyAuthorizationDigest32V1,
    transcript_digest: crate::ceremony_context::CeremonyTranscriptDigest32V1,
    one_use_execution_id: OneUseExecutionId32V1,
}

impl BurnedArtifactAttemptV1 {
    #[cfg_attr(not(test), allow(dead_code))]
    fn from_dag(dag: CeremonyValidatedDagV1, one_use_execution_id: OneUseExecutionId32V1) -> Self {
        Self {
            request_kind: dag.request_kind(),
            request_context_digest: dag.request_context_digest(),
            authorization_digest: dag.authorization_digest(),
            transcript_digest: dag.transcript_digest(),
            one_use_execution_id,
        }
    }

    /// Returns the burned request kind.
    pub const fn request_kind(&self) -> CeremonyRequestKindV1 {
        self.request_kind
    }

    /// Returns the burned request-context digest.
    pub const fn request_context_digest(
        &self,
    ) -> crate::ceremony_context::CeremonyPublicRequestContextDigest32V1 {
        self.request_context_digest
    }

    /// Returns the burned authorization digest.
    pub const fn authorization_digest(
        &self,
    ) -> crate::ceremony_context::CeremonyAuthorizationDigest32V1 {
        self.authorization_digest
    }

    /// Returns the burned transcript digest.
    pub const fn transcript_digest(&self) -> crate::ceremony_context::CeremonyTranscriptDigest32V1 {
        self.transcript_digest
    }

    /// Returns the burned one-use execution identifier.
    pub const fn one_use_execution_id(&self) -> OneUseExecutionId32V1 {
        self.one_use_execution_id
    }
}

/// Registration failure state after the admitted request and attempt are burned.
pub struct FailedRegistrationArtifactAttemptV1 {
    burned: BurnedArtifactAttemptV1,
    terminal_selection: TerminalRegistrationSelectionV1,
}

impl FailedRegistrationArtifactAttemptV1 {
    fn new(
        burned: BurnedArtifactAttemptV1,
        terminal_selection: TerminalRegistrationSelectionV1,
    ) -> Self {
        Self {
            burned,
            terminal_selection,
        }
    }

    /// Returns the burned registration attempt identity.
    pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
        self.burned
    }

    /// Returns the terminal selection retained after evaluator admission.
    pub const fn terminal_selection(&self) -> &TerminalRegistrationSelectionV1 {
        &self.terminal_selection
    }
}

struct RegisteredArtifactAttemptFailureCoreV1 {
    state: AuthenticatedRegisteredStoreResolutionV1,
    burned: BurnedArtifactAttemptV1,
}

macro_rules! define_failed_registered_artifact_attempt {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        pub struct $name {
            inner: RegisteredArtifactAttemptFailureCoreV1,
        }

        impl $name {
            fn new(
                state: AuthenticatedRegisteredStoreResolutionV1,
                burned: BurnedArtifactAttemptV1,
            ) -> Self {
                Self {
                    inner: RegisteredArtifactAttemptFailureCoreV1 { state, burned },
                }
            }

            /// Returns the burned request and one-use attempt identity.
            pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
                self.inner.burned
            }

            /// Returns the exact unchanged registered state.
            pub const fn state(&self) -> &RegisteredLifecyclePreStateV1 {
                self.inner.state.state()
            }

            /// Recovers the authenticated unchanged state; the admitted request remains burned.
            pub fn into_state(self) -> AuthenticatedRegisteredStoreResolutionV1 {
                self.inner.state
            }
        }
    };
}

define_failed_registered_artifact_attempt!(
    FailedExportArtifactAttemptV1,
    "Unchanged registered metadata after one admitted export attempt is burned."
);

/// Suspended recovery state after one admitted recovery attempt is burned.
pub struct FailedRecoveryArtifactAttemptV1 {
    terminal: TerminalRecoveryEvaluationV1,
    burned: BurnedArtifactAttemptV1,
}

impl FailedRecoveryArtifactAttemptV1 {
    fn new(
        terminal: TerminalRecoveryEvaluationV1,
        burned: BurnedArtifactAttemptV1,
    ) -> Self {
        Self { terminal, burned }
    }

    /// Returns the burned request and one-use attempt identity.
    pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
        self.burned
    }

    /// Returns the exact credential-suspended recovery state.
    pub const fn suspension(&self) -> &AuthenticatedRecoveryCredentialSuspensionV1 {
        self.terminal.suspension()
    }

    /// Returns the exact terminal admission retained after evaluator failure.
    pub const fn terminal(&self) -> &TerminalRecoveryEvaluationV1 {
        &self.terminal
    }

    /// Recovers the terminal admission; the admitted request remains burned.
    pub fn into_terminal(self) -> TerminalRecoveryEvaluationV1 {
        self.terminal
    }
}

/// Terminal refresh admission after one evaluator attempt is burned.
pub struct FailedRefreshArtifactAttemptV1 {
    terminal: TerminalRefreshEvaluationV1,
    burned: BurnedArtifactAttemptV1,
}

impl FailedRefreshArtifactAttemptV1 {
    fn new(terminal: TerminalRefreshEvaluationV1, burned: BurnedArtifactAttemptV1) -> Self {
        Self { terminal, burned }
    }

    /// Returns the burned request and one-use attempt identity.
    pub const fn burned(&self) -> BurnedArtifactAttemptV1 {
        self.burned
    }

    /// Returns the exact terminal admission retained after evaluator failure.
    pub const fn terminal(&self) -> &TerminalRefreshEvaluationV1 {
        &self.terminal
    }

    /// Recovers the terminal admission; the admitted request remains burned.
    pub fn into_terminal(self) -> TerminalRefreshEvaluationV1 {
        self.terminal
    }
}

/// Host-reference artifact evaluation failure retaining branch-specific lifecycle state.
pub struct ArtifactEvaluationFailureV1<Retained> {
    abort: UniformLifecycleAbortV1,
    source: SemanticArtifactErrorV1,
    retained: Box<Retained>,
}

impl<Retained> ArtifactEvaluationFailureV1<Retained> {
    /// Returns the only public failure projection.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        self.abort
    }

    /// Returns the internal semantic failure for crate-owned audit handling.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn source(&self) -> SemanticArtifactErrorV1 {
        self.source
    }

    /// Recovers the branch-specific retained value; admitted requests remain burned.
    pub fn into_retained(self) -> Retained {
        *self.retained
    }
}

impl<Retained> fmt::Debug for ArtifactEvaluationFailureV1<Retained> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactEvaluationFailureV1")
            .field("abort", &self.abort)
            .field("retained", &"retained lifecycle state")
            .finish()
    }
}

/// Single-use registration semantic artifact session.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RegistrationArtifactSessionV1 {
    request: RegistrationRequestV1,
    one_use_execution_id: OneUseExecutionId32V1,
    terminal_selection: TerminalRegistrationSelectionV1,
    semantic: RegistrationActivationSemanticArtifactContextV1,
}

/// Single-use recovery semantic artifact session.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RecoveryArtifactSessionV1 {
    request: RecoveryRequestV1,
    terminal: TerminalRecoveryEvaluationV1,
    semantic: RecoveryActivationSemanticArtifactContextV1,
}

/// Single-use refresh semantic artifact session.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RefreshArtifactSessionV1 {
    request: RefreshRequestV1,
    terminal: TerminalRefreshEvaluationV1,
    semantic: RefreshActivationSemanticArtifactContextV1,
}

/// Single-use export semantic artifact session.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ExportArtifactSessionV1 {
    request: ExportRequestV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    one_use_execution_id: OneUseExecutionId32V1,
    semantic: ExportSemanticArtifactContextV1,
}

impl RegistrationRequestV1 {
    /// Consumes this request into its only semantic artifact session.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn begin_host_reference_artifact_session(
        self,
        issuance: RegistrationArtifactIssuanceV1,
        input_provenance: &RoleInputProvenancePairV1,
    ) -> Result<
        RegistrationArtifactSessionV1,
        RejectedArtifactSessionV1<Self, RegistrationArtifactIssuanceV1>,
    > {
        let result = issuance
            .admission
            .validate_for(
                &self,
                input_provenance,
                issuance.activation_epoch,
                issuance.one_use_execution_id,
            )
            .map_err(|_| ArtifactSessionErrorV1::RegistrationAdmissionRejected)
            .and_then(|()| {
                RegistrationActivationSemanticArtifactContextV1::new(
                    &self.request_context,
                    &self.authorization,
                    &self.transcript,
                    issuance.activation_epoch,
                    issuance.one_use_execution_id,
                    input_provenance,
                    issuance.admission.evaluation_evidence_digest(),
                )
                .map_err(ArtifactSessionErrorV1::from)
            });
        match result {
            Ok(semantic) => Ok(RegistrationArtifactSessionV1 {
                request: self,
                one_use_execution_id: issuance.one_use_execution_id,
                terminal_selection: issuance.admission.into_terminal_selection(),
                semantic,
            }),
            Err(error) => Err(RejectedArtifactSessionV1 {
                reason: error,
                request: Box::new(self),
                issuance: Box::new(issuance),
            }),
        }
    }
}

impl RecoveryRequestV1 {
    /// Consumes this request and one accepted admission into a recovery session.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn begin_host_reference_artifact_session(
        self,
        admission: AcceptedRecoveryAdmissionV1,
        input_provenance: &RoleInputProvenancePairV1,
    ) -> Result<
        RecoveryArtifactSessionV1,
        RejectedArtifactSessionV1<Self, AcceptedRecoveryAdmissionV1>,
    > {
        let result = admission
            .validate_for(&self, input_provenance)
            .map_err(|_| ArtifactSessionErrorV1::RecoveryAdmissionRejected)
            .and_then(|()| {
                RecoveryActivationSemanticArtifactContextV1::new(
                    &self.request_context,
                    &self.authorization,
                    &self.transcript,
                    admission.terminal().next_activation_epoch(),
                    admission.terminal().one_use_execution_id(),
                    input_provenance,
                    admission.evaluation_evidence_digest(),
                )
                .map_err(ArtifactSessionErrorV1::from)
            });
        match result {
            Ok(semantic) => Ok(RecoveryArtifactSessionV1 {
                request: self,
                terminal: admission.into_terminal(),
                semantic,
            }),
            Err(reason) => Err(RejectedArtifactSessionV1 {
                reason,
                request: Box::new(self),
                issuance: Box::new(admission),
            }),
        }
    }
}

impl RefreshRequestV1 {
    /// Consumes this request and one accepted admission into a refresh session.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn begin_host_reference_artifact_session(
        self,
        admission: AcceptedRefreshAdmissionV1,
        input_provenance: &RoleInputProvenancePairV1,
    ) -> Result<RefreshArtifactSessionV1, RejectedArtifactSessionV1<Self, AcceptedRefreshAdmissionV1>>
    {
        let result = admission
            .validate_for(&self, input_provenance)
            .map_err(|_| ArtifactSessionErrorV1::RefreshAdmissionRejected)
            .and_then(|()| {
                RefreshActivationSemanticArtifactContextV1::new(
                    &self.request_context,
                    &self.authorization,
                    &self.transcript,
                    admission.terminal().next_activation_epoch(),
                    admission.terminal().one_use_execution_id(),
                    input_provenance,
                    admission.evaluation_evidence_digest(),
                )
                .map_err(ArtifactSessionErrorV1::from)
            });
        match result {
            Ok(semantic) => Ok(RefreshArtifactSessionV1 {
                request: self,
                terminal: admission.into_terminal(),
                semantic,
            }),
            Err(reason) => Err(RejectedArtifactSessionV1 {
                reason,
                request: Box::new(self),
                issuance: Box::new(admission),
            }),
        }
    }
}

impl ExportRequestV1 {
    /// Consumes this request and store state into one export artifact session.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn begin_host_reference_artifact_session(
        self,
        issuance: ExportArtifactIssuanceV1,
        input_provenance: &RoleInputProvenancePairV1,
        acceptance_pair: VerifiedExportAuthorizationAcceptancePairV1,
    ) -> Result<ExportArtifactSessionV1, RejectedArtifactSessionV1<Self, ExportArtifactIssuanceV1>>
    {
        let result = issuance
            .state
            .validate_for(
                &self.request_context,
                self.validated_dag(),
                input_provenance,
            )
            .map_err(|_| ArtifactSessionErrorV1::AuthenticatedStoreAuthorityRejected)
            .and_then(|()| {
                acceptance_pair
                    .validate_for(
                        &self,
                        &issuance.state,
                        input_provenance,
                        issuance.one_use_execution_id,
                        issuance.acceptance_authorities,
                    )
                    .map_err(|_| ArtifactSessionErrorV1::ExportAuthorizationAcceptanceRejected)
            })
            .and_then(|()| {
                ExportSemanticArtifactContextV1::new(
                    &self.request_context,
                    &self.authorization,
                    &self.transcript,
                    issuance.one_use_execution_id,
                    input_provenance,
                    acceptance_pair.evaluation_evidence_digest(),
                )
                .map_err(ArtifactSessionErrorV1::from)
            });
        match result {
            Ok(semantic) => Ok(ExportArtifactSessionV1 {
                request: self,
                state: issuance.state,
                one_use_execution_id: issuance.one_use_execution_id,
                semantic,
            }),
            Err(reason) => Err(RejectedArtifactSessionV1 {
                reason,
                request: Box::new(self),
                issuance: Box::new(issuance),
            }),
        }
    }
}

/// Move-owned activation artifacts and exact shares from one evaluation.
pub struct HostOnlyActivationOutputCommittedV1 {
    artifacts: CommittedActivationArtifactsV1,
    shares: HostOnlyActivationOutputSharesV1,
}

impl HostOnlyActivationOutputCommittedV1 {
    /// Returns the exact output-committed artifacts.
    pub const fn artifacts(&self) -> &CommittedActivationArtifactsV1 {
        &self.artifacts
    }

    pub(crate) const fn shares(&self) -> &HostOnlyActivationOutputSharesV1 {
        &self.shares
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CommittedActivationArtifactsV1,
        HostOnlyActivationOutputSharesV1,
    ) {
        (self.artifacts, self.shares)
    }
}

/// Registration output committed and awaiting metadata/control consumption.
pub struct RegistrationPendingActivationV1 {
    origin: RegistrationRequestV1,
    candidate: RegistrationCandidateStateV1,
    output: HostOnlyActivationOutputCommittedV1,
}

/// Recovery output committed with the old credential suspended.
pub struct RecoveryPendingActivationV1 {
    origin: RecoveryRequestV1,
    terminal: TerminalRecoveryEvaluationV1,
    output: HostOnlyActivationOutputCommittedV1,
}

/// Refresh output committed with current and proposed next state authority.
pub struct RefreshPendingActivationV1 {
    origin: RefreshRequestV1,
    terminal: TerminalRefreshEvaluationV1,
    output: HostOnlyActivationOutputCommittedV1,
}

impl RegistrationPendingActivationV1 {
    /// Returns the consumed registration ceremony.
    pub const fn origin(&self) -> &RegistrationRequestV1 {
        &self.origin
    }

    /// Returns the terminal input-selection identity retained through commitment.
    pub const fn terminal_selection(&self) -> &TerminalRegistrationSelectionV1 {
        self.candidate.terminal_selection()
    }

    /// Returns the exact candidate identity established by evaluation.
    pub const fn candidate(&self) -> &RegistrationCandidateStateV1 {
        &self.candidate
    }

    /// Returns the exact output-committed artifacts.
    pub const fn artifacts(&self) -> &CommittedActivationArtifactsV1 {
        self.output.artifacts()
    }
}

impl RecoveryPendingActivationV1 {
    /// Returns the consumed host-reference recovery ceremony.
    pub const fn origin(&self) -> &RecoveryRequestV1 {
        &self.origin
    }

    /// Returns the registered metadata beneath the credential suspension.
    pub const fn state(&self) -> &RegisteredLifecyclePreStateV1 {
        self.terminal.suspension().state()
    }

    /// Returns the exact authenticated credential suspension.
    pub const fn suspension(&self) -> &AuthenticatedRecoveryCredentialSuspensionV1 {
        self.terminal.suspension()
    }

    /// Returns the exact terminal evaluator admission.
    pub const fn terminal(&self) -> &TerminalRecoveryEvaluationV1 {
        &self.terminal
    }

    /// Returns the authenticated old-to-replacement credential binding.
    pub const fn credential_continuity(
        &self,
    ) -> AuthenticatedRecoveryCredentialContinuityEvidenceV1 {
        self.terminal.credential_continuity()
    }

    /// Returns the exact output-committed artifacts.
    pub const fn artifacts(&self) -> &CommittedActivationArtifactsV1 {
        self.output.artifacts()
    }
}

impl RefreshPendingActivationV1 {
    /// Returns the consumed host-reference refresh ceremony.
    pub const fn origin(&self) -> &RefreshRequestV1 {
        &self.origin
    }

    /// Returns the unchanged current registered metadata projection.
    pub const fn state(&self) -> &RegisteredLifecyclePreStateV1 {
        self.terminal.state().state()
    }

    /// Returns proposed, unauthenticated Deriver A next-state metadata.
    pub const fn proposed_next_deriver_a(
        &self,
    ) -> ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1> {
        self.terminal.proposed_next_deriver_a()
    }

    /// Returns proposed, unauthenticated Deriver B next-state metadata.
    pub const fn proposed_next_deriver_b(
        &self,
    ) -> ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1> {
        self.terminal.proposed_next_deriver_b()
    }

    /// Returns the exact terminal evaluator admission.
    pub const fn terminal(&self) -> &TerminalRefreshEvaluationV1 {
        &self.terminal
    }

    /// Returns the exact output-committed artifacts.
    pub const fn artifacts(&self) -> &CommittedActivationArtifactsV1 {
        self.output.artifacts()
    }
}

/// Move-only pending metadata restricted to evaluation-producing origins.
pub enum PendingActivationPreStateV1 {
    /// Registration-origin metadata.
    Registration(Box<RegistrationPendingActivationV1>),
    /// Recovery-origin metadata.
    Recovery(Box<RecoveryPendingActivationV1>),
    /// Refresh-origin metadata.
    Refresh(Box<RefreshPendingActivationV1>),
}

impl PendingActivationPreStateV1 {
    /// Returns the artifact-producing branch.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        match self {
            Self::Registration(_) => ActivationPackageOriginV1::Registration,
            Self::Recovery(_) => ActivationPackageOriginV1::Recovery,
            Self::Refresh(_) => ActivationPackageOriginV1::Refresh,
        }
    }

    /// Returns the exact committed artifact binding.
    pub const fn artifact_binding(&self) -> ActivationArtifactBindingV1 {
        self.artifacts().binding()
    }

    /// Returns the exact output-committed artifacts.
    pub const fn artifacts(&self) -> &CommittedActivationArtifactsV1 {
        match self {
            Self::Registration(pending) => pending.output.artifacts(),
            Self::Recovery(pending) => pending.output.artifacts(),
            Self::Refresh(pending) => pending.output.artifacts(),
        }
    }

    pub(crate) const fn committed_output(&self) -> &HostOnlyActivationOutputCommittedV1 {
        match self {
            Self::Registration(pending) => &pending.output,
            Self::Recovery(pending) => &pending.output,
            Self::Refresh(pending) => &pending.output,
        }
    }

    pub(crate) fn into_committed_output(self) -> HostOnlyActivationOutputCommittedV1 {
        match self {
            Self::Registration(pending) => pending.output,
            Self::Recovery(pending) => pending.output,
            Self::Refresh(pending) => pending.output,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn origin_request_context(&self) -> &CeremonyPublicRequestContextV1 {
        match self {
            Self::Registration(pending) => pending.origin.request_context(),
            Self::Recovery(pending) => pending.origin.request_context(),
            Self::Refresh(pending) => pending.origin.request_context(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn origin_transcript(&self) -> &CeremonyTranscriptV1 {
        match self {
            Self::Registration(pending) => pending.origin.transcript(),
            Self::Recovery(pending) => pending.origin.transcript(),
            Self::Refresh(pending) => pending.origin.transcript(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    const fn origin_dag(&self) -> CeremonyValidatedDagV1 {
        match self {
            Self::Registration(pending) => pending.origin.validated_dag(),
            Self::Recovery(pending) => pending.origin.validated_dag(),
            Self::Refresh(pending) => pending.origin.validated_dag(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn commit_activation_artifacts(
    packaged: HostOnlyPackagedActivationV1,
    evidence: ActivationReceiptEvidenceV1,
) -> Result<HostOnlyActivationOutputCommittedV1, SemanticArtifactErrorV1> {
    let (packages, shares) = packaged.into_parts();
    let artifacts =
        CommittedActivationArtifactsV1::new(packages, evidence.deriver_a, evidence.deriver_b)?;
    Ok(HostOnlyActivationOutputCommittedV1 { artifacts, shares })
}

impl RegistrationArtifactSessionV1 {
    /// Evaluates, commits, and returns registration-origin pending metadata.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn evaluate_and_commit_host_reference(
        self,
        inputs: HostOnlyRegistrationReferenceInputsV1<'_>,
        coins: HostOnlyRegistrationIdealCoinsV1,
        bindings: OpaqueHostReferenceActivationPackageBindingsV1,
        receipt_evidence: ActivationReceiptEvidenceV1,
    ) -> Result<
        RegistrationPendingActivationV1,
        ArtifactEvaluationFailureV1<FailedRegistrationArtifactAttemptV1>,
    > {
        let Self {
            request,
            one_use_execution_id,
            terminal_selection,
            semantic,
        } = self;
        let abort = UniformLifecycleAbortV1::rejected(&request.validated_dag());
        let burned =
            BurnedArtifactAttemptV1::from_dag(request.validated_dag(), one_use_execution_id);
        let admitted_scope = terminal_selection.provenance_binding().stable_scope();
        let supplied_scope = StableKdfScopeV1::from_context(inputs.stable_context());
        let result = if supplied_scope != admitted_scope {
            Err(SemanticArtifactErrorV1::RegistrationStableScopeMismatch)
        } else {
            semantic
                .evaluate_and_package_host_reference(inputs, coins, bindings)
                .and_then(|packages| commit_activation_artifacts(packages, receipt_evidence))
                .and_then(|output| {
                    if terminal_selection.matches_committed_output(output.artifacts()) {
                        Ok(output)
                    } else {
                        Err(SemanticArtifactErrorV1::RegistrationCandidateBindingMismatch)
                    }
                })
        };
        match result {
            Ok(output) => {
                let candidate = RegistrationCandidateStateV1::from_validated_committed_output(
                    terminal_selection,
                    output.artifacts(),
                );
                Ok(RegistrationPendingActivationV1 {
                    origin: request,
                    candidate,
                    output,
                })
            }
            Err(source) => Err(ArtifactEvaluationFailureV1 {
                abort,
                source,
                retained: Box::new(FailedRegistrationArtifactAttemptV1::new(
                    burned,
                    terminal_selection,
                )),
            }),
        }
    }
}

impl RecoveryArtifactSessionV1 {
    /// Evaluates, commits, and returns recovery-origin pending metadata.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn evaluate_and_commit_host_reference(
        self,
        inputs: HostOnlyRecoveryReferenceInputsV1<'_>,
        coins: HostOnlyRecoveryIdealCoinsV1,
        bindings: OpaqueHostReferenceActivationPackageBindingsV1,
        receipt_evidence: ActivationReceiptEvidenceV1,
    ) -> Result<
        RecoveryPendingActivationV1,
        ArtifactEvaluationFailureV1<FailedRecoveryArtifactAttemptV1>,
    > {
        let Self {
            request,
            terminal,
            semantic,
        } = self;
        let abort = UniformLifecycleAbortV1::rejected(&request.validated_dag());
        let burned = BurnedArtifactAttemptV1::from_dag(
            request.validated_dag(),
            terminal.one_use_execution_id(),
        );
        let admitted_scope = terminal.credential_continuity().stable_scope();
        let supplied_scope = StableKdfScopeV1::from_context(inputs.stable_context());
        let result = if supplied_scope != admitted_scope {
            Err(SemanticArtifactErrorV1::RecoveryStableScopeMismatch)
        } else {
            semantic
                .evaluate_and_package_host_reference(inputs, coins, bindings)
                .and_then(|packages| commit_activation_artifacts(packages, receipt_evidence))
                .and_then(|output| {
                    if terminal.matches_committed_output(output.artifacts()) {
                        Ok(output)
                    } else {
                        Err(SemanticArtifactErrorV1::RecoveryCommittedOutputBindingMismatch)
                    }
                })
        };
        match result {
            Ok(output) => Ok(RecoveryPendingActivationV1 {
                origin: request,
                terminal,
                output,
            }),
            Err(source) => Err(ArtifactEvaluationFailureV1 {
                abort,
                source,
                retained: Box::new(FailedRecoveryArtifactAttemptV1::new(terminal, burned)),
            }),
        }
    }
}

impl RefreshArtifactSessionV1 {
    /// Evaluates, commits, and returns refresh-origin pending metadata.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn evaluate_and_commit_host_reference(
        self,
        inputs: HostOnlyRefreshReferenceInputsV1<'_>,
        coins: HostOnlyRefreshIdealCoinsV1,
        bindings: OpaqueHostReferenceActivationPackageBindingsV1,
        receipt_evidence: ActivationReceiptEvidenceV1,
    ) -> Result<
        RefreshPendingActivationV1,
        ArtifactEvaluationFailureV1<FailedRefreshArtifactAttemptV1>,
    > {
        let Self {
            request,
            terminal,
            semantic,
        } = self;
        let abort = UniformLifecycleAbortV1::rejected(&request.validated_dag());
        let burned = BurnedArtifactAttemptV1::from_dag(
            request.validated_dag(),
            terminal.one_use_execution_id(),
        );
        let result = semantic
            .evaluate_and_package_host_reference(inputs, coins, bindings)
            .and_then(|packages| commit_activation_artifacts(packages, receipt_evidence))
            .and_then(|output| {
                if terminal.matches_committed_output(output.artifacts()) {
                    Ok(output)
                } else {
                    Err(SemanticArtifactErrorV1::RefreshCommittedOutputBindingMismatch)
                }
            });
        match result {
            Ok(output) => Ok(RefreshPendingActivationV1 {
                origin: request,
                terminal,
                output,
            }),
            Err(source) => Err(ArtifactEvaluationFailureV1 {
                abort,
                source,
                retained: Box::new(FailedRefreshArtifactAttemptV1::new(terminal, burned)),
            }),
        }
    }
}

/// Export output commitment retaining request authority, exact shares, and registered state.
#[cfg_attr(not(test), allow(dead_code))]
pub struct HostOnlyExportOutputCommittedV1 {
    request: ExportRequestV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    artifacts: OutputCommittedExportArtifactsV1,
    shares: HostOnlySeedExportSharesV1,
}

#[cfg_attr(not(test), allow(dead_code))]
impl HostOnlyExportOutputCommittedV1 {
    /// Returns the still-unconsumed export request and authorization.
    pub const fn request(&self) -> &ExportRequestV1 {
        &self.request
    }

    /// Returns the unchanged authenticated registered state.
    pub const fn state(&self) -> &AuthenticatedRegisteredStoreResolutionV1 {
        &self.state
    }

    /// Returns the exact output-committed package set and receipt.
    pub const fn artifacts(&self) -> &OutputCommittedExportArtifactsV1 {
        &self.artifacts
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ExportRequestV1,
        AuthenticatedRegisteredStoreResolutionV1,
        OutputCommittedExportArtifactsV1,
        HostOnlySeedExportSharesV1,
    ) {
        (self.request, self.state, self.artifacts, self.shares)
    }
}

impl ExportArtifactSessionV1 {
    /// Evaluates and commits one export package set without releasing it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn evaluate_and_commit_host_reference(
        self,
        inputs: HostOnlyExportReferenceInputsV1<'_>,
        coin: HostOnlyExportIdealCoinV1,
        bindings: OpaqueHostReferenceExportPackageBindingsV1,
        receipt_evidence: ExportOutputCommitmentEvidenceV1,
    ) -> Result<
        HostOnlyExportOutputCommittedV1,
        ArtifactEvaluationFailureV1<FailedExportArtifactAttemptV1>,
    > {
        let Self {
            request,
            state,
            one_use_execution_id,
            semantic,
        } = self;
        let abort = UniformLifecycleAbortV1::rejected(&request.validated_dag());
        let burned =
            BurnedArtifactAttemptV1::from_dag(request.validated_dag(), one_use_execution_id);
        match semantic.evaluate_and_package_host_reference(inputs, coin, bindings) {
            Ok(packaged) => {
                let (packages, shares) = packaged.into_parts();
                Ok(HostOnlyExportOutputCommittedV1 {
                    request,
                    state,
                    artifacts: OutputCommittedExportArtifactsV1::new(
                        packages,
                        receipt_evidence.deriver_a,
                        receipt_evidence.deriver_b,
                    ),
                    shares,
                })
            }
            Err(source) => Err(ArtifactEvaluationFailureV1 {
                abort,
                source,
                retained: Box::new(FailedExportArtifactAttemptV1::new(state, burned)),
            }),
        }
    }
}

/// Attempt-local public fields for host-reference activation metadata consumption.
#[cfg_attr(not(test), allow(dead_code))]
pub struct ActivationControlFreshFieldsV1 {
    request_id: CeremonyRequestIdV1,
    replay_nonce: CeremonyReplayNonce32V1,
    request_expiry: CeremonyRequestExpiryV1,
    authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
    transcript_nonce: CeremonyTranscriptNonce32V1,
    transport_binding_digest: CeremonyTransportBindingDigest32V1,
    artifact_suite_digest: CeremonyArtifactSuiteDigest32V1,
}

impl ActivationControlFreshFieldsV1 {
    /// Creates the complete attempt-local field set.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn new(
        request_id: CeremonyRequestIdV1,
        replay_nonce: CeremonyReplayNonce32V1,
        request_expiry: CeremonyRequestExpiryV1,
        authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
        transcript_nonce: CeremonyTranscriptNonce32V1,
        transport_binding_digest: CeremonyTransportBindingDigest32V1,
        artifact_suite_digest: CeremonyArtifactSuiteDigest32V1,
    ) -> Self {
        Self {
            request_id,
            replay_nonce,
            request_expiry,
            authorization_record_digest,
            transcript_nonce,
            transport_binding_digest,
            artifact_suite_digest,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ActivationCeremonyV1 {
    request_context: CeremonyPublicRequestContextV1,
    authorization: CeremonyActivationAuthorizationV1,
    transcript: CeremonyTranscriptV1,
    validated_dag: CeremonyValidatedDagV1,
}

impl ActivationCeremonyV1 {
    #[cfg_attr(not(test), allow(dead_code))]
    fn derive(
        fresh: ActivationControlFreshFieldsV1,
        pending: &PendingActivationPreStateV1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        let origin_dag = pending.origin_dag();
        let binding = pending.artifact_binding();
        let request_context = pending
            .origin_request_context()
            .derive_activation_control_request_for_attempt(
                fresh.request_id,
                fresh.replay_nonce,
                fresh.request_expiry,
            );
        let authorization = CeremonyActivationAuthorizationV1::new_for_lifecycle_attempt(
            &request_context,
            fresh.authorization_record_digest,
            origin_dag.activation_origin()?,
            binding.package_set_digest(),
            binding.activation_epoch(),
        )?;
        let authorization_union = CeremonyAuthorizationV1::from(authorization);
        let transcript = CeremonyTranscriptV1::new(
            &request_context,
            &authorization_union,
            fresh.transcript_nonce,
            fresh.transport_binding_digest,
            fresh.artifact_suite_digest,
        )?;
        let validated_dag = CeremonyValidatedDagV1::from_components(
            &request_context,
            &authorization_union,
            &transcript,
        )?;
        Ok(Self {
            request_context,
            authorization,
            transcript,
            validated_dag,
        })
    }
}

/// Single redacted public abort code for host-reference rejection evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactedFailureCodeV1 {
    /// The requested semantic transition was rejected.
    Rejected,
}

/// Closed terminal marker for a rejected lifecycle attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortedTerminalStateV1 {
    /// The attempt terminated without a successful lifecycle result.
    Aborted,
}

/// Exact public-only uniform lifecycle abort envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniformLifecycleAbortV1 {
    request_kind: CeremonyRequestKindV1,
    public_transcript_digest: crate::ceremony_context::CeremonyTranscriptDigest32V1,
    public_failure_code: RedactedFailureCodeV1,
    terminal: AbortedTerminalStateV1,
}

impl UniformLifecycleAbortV1 {
    /// Projects any validated lifecycle ceremony into the one host-reference rejection shape.
    pub fn rejected(validated_dag: &CeremonyValidatedDagV1) -> Self {
        Self {
            request_kind: validated_dag.request_kind(),
            public_transcript_digest: validated_dag.transcript_digest(),
            public_failure_code: RedactedFailureCodeV1::Rejected,
            terminal: AbortedTerminalStateV1::Aborted,
        }
    }

    /// Returns the rejected request kind.
    pub const fn request_kind(&self) -> CeremonyRequestKindV1 {
        self.request_kind
    }

    /// Returns the public transcript digest.
    pub const fn public_transcript_digest(
        &self,
    ) -> crate::ceremony_context::CeremonyTranscriptDigest32V1 {
        self.public_transcript_digest
    }

    /// Returns the single redacted rejection code.
    pub const fn public_failure_code(&self) -> RedactedFailureCodeV1 {
        self.public_failure_code
    }

    /// Returns the closed terminal state.
    pub const fn terminal(&self) -> AbortedTerminalStateV1 {
        self.terminal
    }
}

/// Retry-preserving rejection retaining the exact output-committed metadata.
pub struct RejectedActivationControlProposalV1 {
    abort: UniformLifecycleAbortV1,
    pending: PendingActivationPreStateV1,
}

impl RejectedActivationControlProposalV1 {
    /// Returns the uniform public abort.
    pub const fn abort(&self) -> UniformLifecycleAbortV1 {
        self.abort
    }

    /// Returns the unchanged pending metadata.
    pub const fn pending(&self) -> &PendingActivationPreStateV1 {
        &self.pending
    }

    /// Recovers the exact pending metadata for a fresh attempt.
    pub fn into_pending(self) -> PendingActivationPreStateV1 {
        self.pending
    }
}

impl fmt::Debug for RejectedActivationControlProposalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedActivationControlProposalV1")
            .field("abort", &self.abort)
            .field("pending", &"retained output-committed metadata")
            .finish()
    }
}

/// Internal failure while constructing an admitted activation attempt.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ActivationControlConstructionFailureV1 {
    source: CeremonyContextErrorV1,
    pending: PendingActivationPreStateV1,
}

impl fmt::Debug for ActivationControlConstructionFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivationControlConstructionFailureV1")
            .field("source", &self.source)
            .field("pending", &"retained metadata")
            .finish()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl ActivationControlConstructionFailureV1 {
    pub(crate) fn into_pending(self) -> PendingActivationPreStateV1 {
        self.pending
    }
}

/// Crate-private activation attempt failure; external callers cannot distinguish internals.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ActivationRequestFailureV1 {
    Rejected(RejectedActivationControlProposalV1),
    Construction(ActivationControlConstructionFailureV1),
}

impl fmt::Debug for ActivationRequestFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(value) => value.fmt(formatter),
            Self::Construction(value) => value.fmt(formatter),
        }
    }
}

/// Canonical activation-control ceremony plus its pending metadata.
pub struct ActivationRequestV1 {
    ceremony: ActivationCeremonyV1,
    #[cfg_attr(not(test), allow(dead_code))]
    pending: PendingActivationPreStateV1,
}

impl ActivationRequestV1 {
    /// Derives a host-reference activation metadata attempt.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        fresh: ActivationControlFreshFieldsV1,
        pending: PendingActivationPreStateV1,
    ) -> Result<Self, ActivationRequestFailureV1> {
        let ceremony = match ActivationCeremonyV1::derive(fresh, &pending) {
            Ok(ceremony) => ceremony,
            Err(source) => {
                return Err(ActivationRequestFailureV1::Construction(
                    ActivationControlConstructionFailureV1 { source, pending },
                ))
            }
        };
        let origin_request = pending.origin_request_context();
        let origin_transcript = pending.origin_transcript();
        let origin_dag = pending.origin_dag();
        let distinct = ceremony.request_context.request_id() != origin_request.request_id()
            && ceremony.request_context.replay_nonce() != origin_request.replay_nonce()
            && ceremony.validated_dag.request_context_digest()
                != origin_dag.request_context_digest()
            && ceremony.transcript.transcript_nonce() != origin_transcript.transcript_nonce()
            && ceremony.validated_dag.transcript_digest() != origin_dag.transcript_digest();
        if !distinct {
            return Err(ActivationRequestFailureV1::Rejected(
                RejectedActivationControlProposalV1 {
                    abort: UniformLifecycleAbortV1::rejected(&ceremony.validated_dag),
                    pending,
                },
            ));
        }
        Ok(Self { ceremony, pending })
    }

    /// Returns the canonical activation request context.
    pub const fn request_context(&self) -> &CeremonyPublicRequestContextV1 {
        &self.ceremony.request_context
    }

    /// Returns the package-bound activation authorization.
    pub const fn authorization(&self) -> &CeremonyActivationAuthorizationV1 {
        &self.ceremony.authorization
    }

    /// Returns the activation transcript.
    pub const fn transcript(&self) -> &CeremonyTranscriptV1 {
        &self.ceremony.transcript
    }

    /// Returns the sealed activation DAG.
    pub const fn validated_dag(&self) -> CeremonyValidatedDagV1 {
        self.ceremony.validated_dag
    }

    pub(crate) const fn pending(&self) -> &PendingActivationPreStateV1 {
        &self.pending
    }
}

macro_rules! define_metadata_consumed_activation {
    ($(#[$meta:meta])* $name:ident, $origin:ty $(, $extra:ident : $extra_ty:ty)*) => {
        $(#[$meta])*
        pub struct $name {
            origin: $origin,
            activation: ActivationCeremonyV1,
            output: HostOnlyActivationOutputCommittedV1,
            $($extra: $extra_ty,)*
        }
    };
}

define_metadata_consumed_activation!(
    /// Registration-origin metadata consumed by activation control only.
    MetadataConsumedRegistrationActivationV1,
    RegistrationRequestV1,
    candidate: RegistrationCandidateStateV1
);

impl MetadataConsumedRegistrationActivationV1 {
    /// Returns the registration request context that fixed recipient identity.
    #[allow(dead_code)]
    pub(crate) const fn origin_request_context(&self) -> &CeremonyPublicRequestContextV1 {
        self.origin.request_context()
    }

    /// Returns the unchanged registration candidate retained after metadata consumption.
    pub const fn candidate(&self) -> &RegistrationCandidateStateV1 {
        &self.candidate
    }

    /// Recovers the origin ceremony and retained committed artifacts.
    pub fn into_parts(
        self,
    ) -> (
        RegistrationRequestV1,
        RegistrationCandidateStateV1,
        HostOnlyActivationOutputCommittedV1,
    ) {
        (self.origin, self.candidate, self.output)
    }
}

impl MetadataConsumedRecoveryActivationV1 {
    /// Returns the recovery request context that fixed recipient identity.
    #[allow(dead_code)]
    pub(crate) const fn origin_request_context(&self) -> &CeremonyPublicRequestContextV1 {
        self.origin.request_context()
    }

    /// Returns the authenticated old-to-replacement credential binding.
    pub const fn credential_continuity(
        &self,
    ) -> AuthenticatedRecoveryCredentialContinuityEvidenceV1 {
        self.terminal.credential_continuity()
    }

    /// Returns the retained authenticated credential suspension.
    pub const fn suspension(&self) -> &AuthenticatedRecoveryCredentialSuspensionV1 {
        self.terminal.suspension()
    }

    /// Returns the exact terminal evaluator admission.
    pub const fn terminal(&self) -> &TerminalRecoveryEvaluationV1 {
        &self.terminal
    }

    /// Recovers the origin, terminal admission, and committed artifacts.
    pub fn into_parts(
        self,
    ) -> (
        RecoveryRequestV1,
        TerminalRecoveryEvaluationV1,
        HostOnlyActivationOutputCommittedV1,
    ) {
        (self.origin, self.terminal, self.output)
    }
}

impl MetadataConsumedRefreshActivationV1 {
    /// Returns the refresh request context that fixed recipient identity.
    #[allow(dead_code)]
    pub(crate) const fn origin_request_context(&self) -> &CeremonyPublicRequestContextV1 {
        self.origin.request_context()
    }

    /// Returns the exact terminal evaluator admission.
    pub const fn terminal(&self) -> &TerminalRefreshEvaluationV1 {
        &self.terminal
    }

    /// Recovers the terminal admission without promoting the proposed bindings.
    pub fn into_parts(
        self,
    ) -> (
        RefreshRequestV1,
        TerminalRefreshEvaluationV1,
        HostOnlyActivationOutputCommittedV1,
    ) {
        (self.origin, self.terminal, self.output)
    }
}
define_metadata_consumed_activation!(
    /// Recovery-origin metadata consumed while retaining terminal admission.
    MetadataConsumedRecoveryActivationV1,
    RecoveryRequestV1,
    terminal: TerminalRecoveryEvaluationV1
);
define_metadata_consumed_activation!(
    /// Refresh-origin metadata consumed with proposed, non-promotable next bindings.
    MetadataConsumedRefreshActivationV1,
    RefreshRequestV1,
    terminal: TerminalRefreshEvaluationV1
);

/// Origin-preserving metadata/control-consumed state.
pub enum MetadataConsumedActivationStateV1 {
    /// Registration-origin metadata.
    Registration(Box<MetadataConsumedRegistrationActivationV1>),
    /// Recovery-origin metadata with the old credential still suspended.
    Recovery(Box<MetadataConsumedRecoveryActivationV1>),
    /// Refresh-origin metadata with unpromoted proposed next bindings.
    Refresh(Box<MetadataConsumedRefreshActivationV1>),
}

impl MetadataConsumedActivationStateV1 {
    /// Returns the artifact-producing origin.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        match self {
            Self::Registration(_) => ActivationPackageOriginV1::Registration,
            Self::Recovery(_) => ActivationPackageOriginV1::Recovery,
            Self::Refresh(_) => ActivationPackageOriginV1::Refresh,
        }
    }

    /// Returns the metadata-consumed artifact binding.
    pub const fn artifact_binding(&self) -> ActivationArtifactBindingV1 {
        self.artifacts().binding()
    }

    /// Returns the retained output-committed artifacts.
    pub const fn artifacts(&self) -> &CommittedActivationArtifactsV1 {
        match self {
            Self::Registration(value) => value.output.artifacts(),
            Self::Recovery(value) => value.output.artifacts(),
            Self::Refresh(value) => value.output.artifacts(),
        }
    }

    pub(crate) const fn committed_output(&self) -> &HostOnlyActivationOutputCommittedV1 {
        match self {
            Self::Registration(value) => &value.output,
            Self::Recovery(value) => &value.output,
            Self::Refresh(value) => &value.output,
        }
    }

    /// Returns the activation-control DAG that consumed metadata authority.
    pub const fn activation_dag(&self) -> CeremonyValidatedDagV1 {
        match self {
            Self::Registration(value) => value.activation.validated_dag,
            Self::Recovery(value) => value.activation.validated_dag,
            Self::Refresh(value) => value.activation.validated_dag,
        }
    }
}

/// Host-reference witness that this metadata path invoked no evaluator or sampler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroReevaluationWitnessV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    output_share_samples: u8,
}

impl ZeroReevaluationWitnessV1 {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn no_private_evaluation_work() -> Self {
        Self {
            yao_evaluations: 0,
            deriver_a_invocations: 0,
            deriver_b_invocations: 0,
            contribution_derivations: 0,
            output_share_samples: 0,
        }
    }

    /// Returns the number of new Yao evaluations.
    pub const fn yao_evaluations(&self) -> u8 {
        self.yao_evaluations
    }

    /// Returns the number of new Deriver A invocations.
    pub const fn deriver_a_invocations(&self) -> u8 {
        self.deriver_a_invocations
    }

    /// Returns the number of new Deriver B invocations.
    pub const fn deriver_b_invocations(&self) -> u8 {
        self.deriver_b_invocations
    }

    /// Returns the number of new contribution derivations.
    pub const fn contribution_derivations(&self) -> u8 {
        self.contribution_derivations
    }

    /// Returns the number of new output-share samples.
    pub const fn output_share_samples(&self) -> u8 {
        self.output_share_samples
    }
}

/// Successful metadata/control consumption without a worker-activation claim.
pub struct ActivationMetadataConsumptionSuccessV1 {
    post_state: MetadataConsumedActivationStateV1,
    zero_reevaluation: ZeroReevaluationWitnessV1,
}

impl ActivationMetadataConsumptionSuccessV1 {
    /// Returns the metadata-consumed state.
    pub const fn post_state(&self) -> &MetadataConsumedActivationStateV1 {
        &self.post_state
    }

    /// Returns the exact zero-reevaluation witness.
    pub const fn zero_reevaluation(&self) -> ZeroReevaluationWitnessV1 {
        self.zero_reevaluation
    }

    /// Consumes the metadata-control success into its origin-preserving state.
    #[allow(dead_code)]
    pub(crate) fn into_post_state(self) -> MetadataConsumedActivationStateV1 {
        self.post_state
    }
}

/// Consumes activation metadata without opening or activating worker packages.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn consume_activation_metadata_v1(
    request: ActivationRequestV1,
) -> ActivationMetadataConsumptionSuccessV1 {
    let ActivationRequestV1 { ceremony, pending } = request;
    let post_state = match pending {
        PendingActivationPreStateV1::Registration(value) => {
            let value = *value;
            MetadataConsumedActivationStateV1::Registration(Box::new(
                MetadataConsumedRegistrationActivationV1 {
                    origin: value.origin,
                    activation: ceremony,
                    output: value.output,
                    candidate: value.candidate,
                },
            ))
        }
        PendingActivationPreStateV1::Recovery(value) => {
            let value = *value;
            MetadataConsumedActivationStateV1::Recovery(Box::new(
                MetadataConsumedRecoveryActivationV1 {
                    origin: value.origin,
                    activation: ceremony,
                    output: value.output,
                    terminal: value.terminal,
                },
            ))
        }
        PendingActivationPreStateV1::Refresh(value) => {
            let value = *value;
            MetadataConsumedActivationStateV1::Refresh(Box::new(
                MetadataConsumedRefreshActivationV1 {
                    origin: value.origin,
                    activation: ceremony,
                    output: value.output,
                    terminal: value.terminal,
                },
            ))
        }
    };
    ActivationMetadataConsumptionSuccessV1 {
        post_state,
        zero_reevaluation: ZeroReevaluationWitnessV1::no_private_evaluation_work(),
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::authenticated_store::{
        ActiveStoreStateVersionV1, AuthenticatedRegisteredStoreResolutionV1,
        StoreAuthorityKeyEpochV1, StoreAuthoritySignature64V1, StoreAuthorityVerifyingKeyV1,
        UnverifiedRegisteredStoreResolutionV1,
    };
    use crate::ceremony_context::*;
    use crate::export_evaluation_acceptance_fixtures::{
        canonical_export_acceptance_authorities_v1, canonical_verified_export_acceptance_pair_v1,
    };
    use crate::lifecycle_persistence::{
        AttemptRejectedActivationProjectionV1, EvaluationAbortPreStateClassV1,
        EvaluationAbortedPersistenceProjectionV1, MetadataConsumedActivationProjectionV1,
        OutputCommittedActivationProjectionV1,
    };
    use crate::output_party_views::build_host_only_evaluator_abort_party_view_set_v1;
    use crate::semantic_artifacts_tests::{
        export_ceremony, provenance_pair, recovery_ceremony, refresh_ceremony,
        registration_ceremony,
    };
    use crate::semantic_fixture_material::{
        activation_bindings, export_bindings, export_ideal_coin, export_inputs,
        recovery_admission, recovery_ideal_coins, recovery_inputs, reference_fixture,
        refresh_admission, refresh_ideal_coins, refresh_inputs, registration_admission,
        registration_ideal_coins, registration_inputs,
    };

    fn activation_receipt_evidence() -> ActivationReceiptEvidenceV1 {
        ActivationReceiptEvidenceV1::new(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0x92; 32])
                .expect("A receipt"),
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0x93; 32])
                .expect("B receipt"),
        )
    }

    fn export_output_commitment_evidence() -> ExportOutputCommitmentEvidenceV1 {
        ExportOutputCommitmentEvidenceV1::new(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0x94; 32])
                .expect("A receipt"),
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0x95; 32])
                .expect("B receipt"),
        )
    }

    fn state_from_provenance(
        binding: RegisteredStateProvenanceBindingV1,
        active_epoch: u64,
    ) -> RegisteredLifecyclePreStateV1 {
        let a = binding.deriver_a();
        let b = binding.deriver_b();
        RegisteredLifecyclePreStateV1::from_host_reference_store_projection(
            binding.registered_public_key(),
            ActiveCredentialBindingDigest32V1::new([0x41; 32]).expect("active credential binding"),
            binding.stable_scope(),
            CeremonyActivationEpochV1::new(active_epoch).expect("active epoch"),
            a.role_root_record_digest(),
            a.root_binding_artifact_digest(),
            a.role_root_epoch(),
            a.record_digest(),
            a.epoch(),
            b.role_root_record_digest(),
            b.root_binding_artifact_digest(),
            b.role_root_epoch(),
            b.record_digest(),
            b.epoch(),
        )
    }

    fn authenticate_state(
        request: &CeremonyPublicRequestContextV1,
        dag: CeremonyValidatedDagV1,
        provenance: &RoleInputProvenancePairV1,
        state: RegisteredLifecyclePreStateV1,
        state_version: u64,
    ) -> AuthenticatedRegisteredStoreResolutionV1 {
        let (signing_key, authority) = store_authority();
        let resolution = UnverifiedRegisteredStoreResolutionV1::new(
            request,
            dag,
            provenance,
            ActiveStoreStateVersionV1::new(state_version).expect("state version"),
            state,
            authority,
        )
        .expect("coherent store resolution");
        let signature = signing_key.sign(
            &resolution
                .signing_bytes()
                .expect("store resolution signing bytes"),
        );
        resolution
            .verify(
                StoreAuthoritySignature64V1::from_bytes(signature.to_bytes()),
                authority,
            )
            .expect("authenticated store resolution")
    }

    fn store_authority() -> (SigningKey, StoreAuthorityVerifyingKeyV1) {
        let signing_key = SigningKey::from_bytes(&[0x59; 32]);
        let authority = StoreAuthorityVerifyingKeyV1::parse(
            StoreAuthorityKeyEpochV1::new(1).expect("authority key epoch"),
            signing_key.verifying_key().to_bytes(),
        )
        .expect("authority key");
        (signing_key, authority)
    }

    fn apply_registered_state_splice(
        state: &mut RegisteredLifecyclePreStateV1,
        field: RegisteredStateBindingFieldV1,
    ) {
        match field {
            RegisteredStateBindingFieldV1::RegisteredPublicKey => {
                state.registered_public_key = RegisteredEd25519PublicKey32V1::parse(
                    (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
                        .compress()
                        .to_bytes(),
                )
                .expect("alternate registered key");
            }
            RegisteredStateBindingFieldV1::StableScope => {
                let context = crate::StableKeyDerivationContext::new([0xee; 32], 1, 2)
                    .expect("alternate stable context");
                state.stable_scope = StableKdfScopeV1::from_context(&context);
            }
            RegisteredStateBindingFieldV1::DeriverARootRecord => {
                state.deriver_a_root_record =
                    RoleRootRecordDigest32V1::from_synthetic_fixture_bytes([0xe1; 32]);
            }
            RegisteredStateBindingFieldV1::DeriverARootBinding => {
                state.deriver_a_root_binding =
                    RootBindingArtifactDigest32V1::from_synthetic_artifact_bytes(
                        b"store-splice-deriver-a-root-binding-v1",
                    )
                    .expect("alternate Deriver A root binding");
            }
            RegisteredStateBindingFieldV1::DeriverARootEpoch => {
                state.deriver_a_root_epoch =
                    RoleRootEpochV1::new(state.deriver_a_root_epoch.value() + 100)
                        .expect("alternate Deriver A root epoch");
            }
            RegisteredStateBindingFieldV1::DeriverAStateRecord => {
                state.deriver_a_state_record =
                    RoleInputStateRecordDigest32V1::from_synthetic_fixture_bytes([0xe2; 32]);
            }
            RegisteredStateBindingFieldV1::DeriverAInputStateEpoch => {
                state.deriver_a_input_state_epoch =
                    RoleInputStateEpochV1::new(state.deriver_a_input_state_epoch.value() + 100)
                        .expect("alternate Deriver A state epoch");
            }
            RegisteredStateBindingFieldV1::DeriverBRootRecord => {
                state.deriver_b_root_record =
                    RoleRootRecordDigest32V1::from_synthetic_fixture_bytes([0xe3; 32]);
            }
            RegisteredStateBindingFieldV1::DeriverBRootBinding => {
                state.deriver_b_root_binding =
                    RootBindingArtifactDigest32V1::from_synthetic_artifact_bytes(
                        b"store-splice-deriver-b-root-binding-v1",
                    )
                    .expect("alternate Deriver B root binding");
            }
            RegisteredStateBindingFieldV1::DeriverBRootEpoch => {
                state.deriver_b_root_epoch =
                    RoleRootEpochV1::new(state.deriver_b_root_epoch.value() + 100)
                        .expect("alternate Deriver B root epoch");
            }
            RegisteredStateBindingFieldV1::DeriverBStateRecord => {
                state.deriver_b_state_record =
                    RoleInputStateRecordDigest32V1::from_synthetic_fixture_bytes([0xe4; 32]);
            }
            RegisteredStateBindingFieldV1::DeriverBInputStateEpoch => {
                state.deriver_b_input_state_epoch =
                    RoleInputStateEpochV1::new(state.deriver_b_input_state_epoch.value() + 100)
                        .expect("alternate Deriver B state epoch");
            }
            RegisteredStateBindingFieldV1::NextDeriverAInputStateEpoch
            | RegisteredStateBindingFieldV1::NextDeriverBInputStateEpoch
            | RegisteredStateBindingFieldV1::AuthorizationCurrentDeriverAInputStateEpoch
            | RegisteredStateBindingFieldV1::AuthorizationNextDeriverAInputStateEpoch
            | RegisteredStateBindingFieldV1::AuthorizationCurrentDeriverBInputStateEpoch
            | RegisteredStateBindingFieldV1::AuthorizationNextDeriverBInputStateEpoch => {
                panic!("field is outside the registered pre-state projection")
            }
        }
    }

    fn registration_pending() -> PendingActivationPreStateV1 {
        let fixture = reference_fixture();
        let (request_context, authorization, transcript) = registration_ceremony("lifecycle");
        let request = RegistrationRequestV1::new(request_context, authorization, transcript)
            .expect("registration request");
        let pair = provenance_pair(request.validated_dag(), None);
        let activation_epoch = CeremonyActivationEpochV1::new(7).expect("epoch");
        let execution_id = OneUseExecutionId32V1::new([0xa1; 32]).expect("one use");
        let admission = registration_admission(&request, &pair, activation_epoch, execution_id);
        let session = request
            .begin_host_reference_artifact_session(
                RegistrationArtifactIssuanceV1::new(activation_epoch, execution_id, admission),
                &pair,
            )
            .expect("registration session");
        PendingActivationPreStateV1::Registration(Box::new(
            session
                .evaluate_and_commit_host_reference(
                    registration_inputs(&fixture),
                    registration_ideal_coins(3, 5),
                    activation_bindings(),
                    activation_receipt_evidence(),
                )
                .expect("registration artifacts"),
        ))
    }

    fn recovery_pending() -> PendingActivationPreStateV1 {
        let fixture = reference_fixture();
        let (request_context, authorization, transcript) = recovery_ceremony();
        let request = RecoveryRequestV1::new(request_context, authorization, transcript)
            .expect("recovery request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = authenticate_state(
            request.request_context(),
            request.validated_dag(),
            &pair,
            state_from_provenance(
                pair.recovery_registered_state_binding()
                    .expect("recovery state binding"),
                7,
            ),
            7,
        );
        let activation_epoch = CeremonyActivationEpochV1::new(8).expect("next epoch");
        let execution_id = OneUseExecutionId32V1::new([0xa2; 32]).expect("one use");
        let admission = recovery_admission(
            &request,
            &pair,
            state,
            activation_epoch,
            execution_id,
        );
        let session = request
            .begin_host_reference_artifact_session(admission, &pair)
            .expect("recovery session");
        PendingActivationPreStateV1::Recovery(Box::new(
            session
                .evaluate_and_commit_host_reference(
                    recovery_inputs(&fixture),
                    recovery_ideal_coins(3, 5),
                    activation_bindings(),
                    activation_receipt_evidence(),
                )
                .expect("recovery artifacts"),
        ))
    }

    fn refresh_pending() -> PendingActivationPreStateV1 {
        let fixture = reference_fixture();
        let (request_context, authorization, transcript) = refresh_ceremony();
        let request = RefreshRequestV1::new(request_context, authorization, transcript)
            .expect("refresh request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let binding = pair
            .refresh_registered_state_binding()
            .expect("refresh state binding");
        let state = authenticate_state(
            request.request_context(),
            request.validated_dag(),
            &pair,
            state_from_provenance(binding.current(), 8),
            8,
        );
        let activation_epoch = CeremonyActivationEpochV1::new(9).expect("next epoch");
        let execution_id = OneUseExecutionId32V1::new([0xa3; 32]).expect("one use");
        let admission = refresh_admission(&request, &pair, state, activation_epoch, execution_id);
        let session = request
            .begin_host_reference_artifact_session(admission, &pair)
            .expect("refresh session");
        PendingActivationPreStateV1::Refresh(Box::new(
            session
                .evaluate_and_commit_host_reference(
                    refresh_inputs(&fixture),
                    refresh_ideal_coins(3, 5),
                    activation_bindings(),
                    activation_receipt_evidence(),
                )
                .expect("refresh artifacts"),
        ))
    }

    fn fresh(
        request_id: &str,
        replay_byte: u8,
        expiry: u64,
        transcript_byte: u8,
    ) -> ActivationControlFreshFieldsV1 {
        ActivationControlFreshFieldsV1::new(
            CeremonyRequestIdV1::parse(request_id).expect("request id"),
            CeremonyReplayNonce32V1::new([replay_byte; 32]),
            CeremonyRequestExpiryV1::new(expiry).expect("expiry"),
            CeremonyAuthorizationRecordDigest32V1::new([0xb1; 32]).expect("authorization"),
            CeremonyTranscriptNonce32V1::new([transcript_byte; 32]),
            CeremonyTransportBindingDigest32V1::new([0xb2; 32]).expect("transport"),
            CeremonyArtifactSuiteDigest32V1::new([0xb3; 32]).expect("artifacts"),
        )
    }

    fn rejected(
        pending: PendingActivationPreStateV1,
        fields: ActivationControlFreshFieldsV1,
    ) -> RejectedActivationControlProposalV1 {
        let result = catch_unwind(AssertUnwindSafe(|| {
            ActivationRequestV1::new(fields, pending)
        }))
        .expect("admitted freshness rejection must not unwind");
        match result {
            Err(ActivationRequestFailureV1::Rejected(rejection)) => rejection,
            Err(ActivationRequestFailureV1::Construction(failure)) => {
                let _ = failure.into_pending();
                panic!("freshness rejection became an internal construction error")
            }
            Ok(_) => panic!("freshness reuse was accepted"),
        }
    }

    #[test]
    fn epoch_issuance_rejects_stale_values_without_dropping_state() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request = RecoveryRequestV1::new(context, authorization, transcript).expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = authenticate_state(
            request.request_context(),
            request.validated_dag(),
            &pair,
            state_from_provenance(
                pair.recovery_registered_state_binding().expect("binding"),
                9,
            ),
            9,
        );
        let rejection = match crate::accept_host_only_recovery_admission_v1(
            &request,
            &pair,
            state,
            CeremonyActivationEpochV1::new(9).expect("same epoch"),
            OneUseExecutionId32V1::new([0xc1; 32]).expect("one use"),
            crate::RecoveryAdmissionCheckedAtUnixMsV1::new(
                request.request_context().request_expiry().value(),
            )
            .expect("checked at"),
            crate::OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1::new([0xc2; 32])
                .expect("acceptance evidence"),
        ) {
            Err(rejection) => rejection,
            Ok(_) => panic!("stale activation epoch was accepted"),
        };
        assert_eq!(
            rejection.reason(),
            crate::RecoveryAdmissionErrorV1::ActivationEpochDidNotAdvance
        );
        let state = rejection.into_state();
        assert_eq!(state.state().active_activation_epoch().value(), 9);
    }

    #[test]
    fn recovery_session_seals_authenticated_old_to_replacement_credential_evidence() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request = RecoveryRequestV1::new(context, authorization, transcript).expect("request");
        let expected_replacement = request
            .authorization()
            .replacement_credential_binding_digest();
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let expected_same_root = pair
            .recovery_same_root_evidence_artifact_digest()
            .expect("same-root evidence");
        let state = authenticate_state(
            request.request_context(),
            request.validated_dag(),
            &pair,
            state_from_provenance(
                pair.recovery_registered_state_binding().expect("binding"),
                7,
            ),
            13,
        );
        let activation_epoch = CeremonyActivationEpochV1::new(8).expect("next epoch");
        let execution_id = OneUseExecutionId32V1::new([0xc2; 32]).expect("one use");
        let admission = recovery_admission(
            &request,
            &pair,
            state,
            activation_epoch,
            execution_id,
        );
        let session = request
            .begin_host_reference_artifact_session(admission, &pair)
            .expect("session");

        let evidence = session.terminal.credential_continuity();
        assert_eq!(evidence.active_state_version().value(), 13);
        assert_eq!(
            evidence.active_credential_binding_digest().as_bytes(),
            &[0x41; 32]
        );
        assert_eq!(
            evidence.replacement_credential_binding_digest(),
            expected_replacement
        );
        assert_ne!(
            evidence.active_credential_binding_digest().as_bytes(),
            evidence.replacement_credential_binding_digest().as_bytes()
        );
        assert_eq!(
            evidence.same_root_evidence_artifact_digest(),
            expected_same_root
        );
        assert_eq!(
            evidence.registered_public_key(),
            fixture.registered_public_key
        );
    }

    #[test]
    fn recovery_rejects_an_authorized_credential_that_is_already_active() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request = RecoveryRequestV1::new(context, authorization, transcript).expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let mut raw_state = state_from_provenance(
            pair.recovery_registered_state_binding().expect("binding"),
            7,
        );
        raw_state.active_credential_binding_digest = ActiveCredentialBindingDigest32V1::new(
            *request
                .authorization()
                .replacement_credential_binding_digest()
                .as_bytes(),
        )
        .expect("replacement is nonzero");
        let state = authenticate_state(
            request.request_context(),
            request.validated_dag(),
            &pair,
            raw_state,
            7,
        );
        let rejection = match crate::accept_host_only_recovery_admission_v1(
            &request,
            &pair,
            state,
            CeremonyActivationEpochV1::new(8).expect("next epoch"),
            OneUseExecutionId32V1::new([0xc4; 32]).expect("one use"),
            crate::RecoveryAdmissionCheckedAtUnixMsV1::new(
                request.request_context().request_expiry().value(),
            )
            .expect("checked at"),
            crate::OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1::new([0xc5; 32])
                .expect("acceptance evidence"),
        ) {
            Err(rejection) => rejection,
            Ok(_) => panic!("same credential was accepted as a replacement"),
        };
        assert_eq!(
            rejection.reason(),
            crate::RecoveryAdmissionErrorV1::CredentialContinuity(
                RecoveryCredentialContinuityErrorV1::ReplacementCredentialDidNotChange
            )
        );
        let state = rejection.into_state();
        assert_eq!(
            state
                .state()
                .active_credential_binding_digest()
                .as_bytes(),
            request
                .authorization()
                .replacement_credential_binding_digest()
                .as_bytes()
        );
    }

    #[test]
    fn recovery_credential_evidence_survives_metadata_consumption() {
        let pending = match recovery_pending() {
            PendingActivationPreStateV1::Recovery(pending) => pending,
            _ => panic!("recovery helper produced another origin"),
        };
        let expected = pending.credential_continuity();
        let request = ActivationRequestV1::new(
            fresh("activate-recovery-credential-evidence", 0xd1, 150, 0xd2),
            PendingActivationPreStateV1::Recovery(pending),
        )
        .expect("activation request");
        let success = consume_activation_metadata_v1(request);
        let retained = match success.post_state() {
            MetadataConsumedActivationStateV1::Recovery(retained) => retained,
            _ => panic!("recovery activation became another origin"),
        };
        assert_eq!(retained.credential_continuity(), expected);
        assert_eq!(success.zero_reevaluation().yao_evaluations(), 0);
    }

    #[test]
    fn store_authority_rejects_incoherent_state_before_issuance() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request = RecoveryRequestV1::new(context, authorization, transcript).expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let binding = pair.recovery_registered_state_binding().expect("binding");
        let wrong_key = RegisteredEd25519PublicKey32V1::parse(
            (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        )
        .expect("wrong key");
        let a = binding.deriver_a();
        let b = binding.deriver_b();
        let wrong_state = RegisteredLifecyclePreStateV1::from_host_reference_store_projection(
            wrong_key,
            ActiveCredentialBindingDigest32V1::new([0x41; 32]).expect("active credential binding"),
            binding.stable_scope(),
            CeremonyActivationEpochV1::new(7).expect("active epoch"),
            a.role_root_record_digest(),
            a.root_binding_artifact_digest(),
            a.role_root_epoch(),
            a.record_digest(),
            a.epoch(),
            b.role_root_record_digest(),
            b.root_binding_artifact_digest(),
            b.role_root_epoch(),
            b.record_digest(),
            b.epoch(),
        );
        let (_, authority) = store_authority();
        let rejection = UnverifiedRegisteredStoreResolutionV1::new(
            request.request_context(),
            request.validated_dag(),
            &pair,
            ActiveStoreStateVersionV1::new(7).expect("state version"),
            wrong_state,
            authority,
        );
        assert!(matches!(
            rejection,
            Err(
                crate::authenticated_store::AuthenticatedStoreErrorV1::RegisteredStateMismatch(
                    RegisteredStateBindingFieldV1::RegisteredPublicKey
                )
            )
        ));
        assert_eq!(request.request_kind(), CeremonyRequestKindV1::Recovery);
    }

    #[test]
    fn every_provenance_bound_registered_state_field_rejects_a_single_field_splice() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request = RecoveryRequestV1::new(context, authorization, transcript).expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let binding = pair.recovery_registered_state_binding().expect("binding");
        let fields = [
            RegisteredStateBindingFieldV1::RegisteredPublicKey,
            RegisteredStateBindingFieldV1::StableScope,
            RegisteredStateBindingFieldV1::DeriverARootRecord,
            RegisteredStateBindingFieldV1::DeriverARootBinding,
            RegisteredStateBindingFieldV1::DeriverARootEpoch,
            RegisteredStateBindingFieldV1::DeriverAStateRecord,
            RegisteredStateBindingFieldV1::DeriverAInputStateEpoch,
            RegisteredStateBindingFieldV1::DeriverBRootRecord,
            RegisteredStateBindingFieldV1::DeriverBRootBinding,
            RegisteredStateBindingFieldV1::DeriverBRootEpoch,
            RegisteredStateBindingFieldV1::DeriverBStateRecord,
            RegisteredStateBindingFieldV1::DeriverBInputStateEpoch,
        ];

        for field in fields {
            let mut state = state_from_provenance(binding, 7);
            apply_registered_state_splice(&mut state, field);
            assert_eq!(
                validate_registered_state(&state, binding),
                Err(ArtifactSessionErrorV1::RegisteredStateMismatch(field)),
                "single-field splice escaped at {field:?}"
            );
        }
    }

    #[test]
    fn recovery_evaluation_failure_is_uniform_and_retains_credential_suspension() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = recovery_ceremony();
        let request = RecoveryRequestV1::new(context, authorization, transcript).expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = authenticate_state(
            request.request_context(),
            request.validated_dag(),
            &pair,
            state_from_provenance(
                pair.recovery_registered_state_binding().expect("binding"),
                7,
            ),
            7,
        );
        let activation_epoch = CeremonyActivationEpochV1::new(8).expect("next epoch");
        let execution_id = OneUseExecutionId32V1::new([0xc3; 32]).expect("one use");
        let admission = recovery_admission(
            &request,
            &pair,
            state,
            activation_epoch,
            execution_id,
        );
        let session = request
            .begin_host_reference_artifact_session(admission, &pair)
            .expect("session");
        let wrong_root = crate::SyntheticClientDerivationRootV1::from_fixture_bytes([0xff; 32]);
        let bad_inputs = crate::HostOnlyRecoveryReferenceInputsV1::new(
            &fixture.client_root,
            &wrong_root,
            &fixture.context,
            &fixture.deriver_a,
            &fixture.deriver_b,
        );
        let failure = match session.evaluate_and_commit_host_reference(
            bad_inputs,
            recovery_ideal_coins(3, 5),
            activation_bindings(),
            activation_receipt_evidence(),
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("mismatched recovered root was accepted"),
        };
        assert_eq!(
            failure.abort().request_kind(),
            CeremonyRequestKindV1::Recovery
        );
        assert_eq!(
            failure.abort().public_failure_code(),
            RedactedFailureCodeV1::Rejected
        );
        assert_eq!(failure.abort().terminal(), AbortedTerminalStateV1::Aborted);
        assert!(matches!(
            failure.source(),
            SemanticArtifactErrorV1::RecoveryReference(_)
        ));
        assert!(!format!("{failure:?}").contains("RecoveryReference"));
        let projection = EvaluationAbortedPersistenceProjectionV1::from_recovery_failure(failure);
        assert_eq!(
            projection.pre_state_class(),
            EvaluationAbortPreStateClassV1::RecoveryCredentialSuspended
        );
        let expected_abort = projection.abort();
        for observed in [
            build_host_only_evaluator_abort_party_view_set_v1(&projection)
                .observe_deriver_a_v1()
                .common(),
            build_host_only_evaluator_abort_party_view_set_v1(&projection)
                .observe_deriver_b_v1()
                .common(),
            build_host_only_evaluator_abort_party_view_set_v1(&projection)
                .observe_client_v1()
                .common(),
            build_host_only_evaluator_abort_party_view_set_v1(&projection)
                .observe_signing_worker_v1()
                .common(),
            build_host_only_evaluator_abort_party_view_set_v1(&projection)
                .observe_router_v1()
                .common(),
            build_host_only_evaluator_abort_party_view_set_v1(&projection)
                .observe_observer_v1()
                .common(),
            build_host_only_evaluator_abort_party_view_set_v1(&projection)
                .observe_diagnostics_v1()
                .common(),
        ] {
            assert_eq!(observed.abort(), expected_abort);
        }
        let retained = match projection {
            EvaluationAbortedPersistenceProjectionV1::Recovery(retained) => retained,
            _ => panic!("recovery failure projected into another branch"),
        };
        assert_eq!(
            retained.before().continuity(),
            retained.after().continuity()
        );
        assert_eq!(
            retained.burned().request_kind(),
            CeremonyRequestKindV1::Recovery
        );
        assert_eq!(
            retained
                .into_terminal()
                .suspension()
                .state()
                .active_activation_epoch()
                .value(),
            7
        );
    }

    fn activation_share_fixture_bytes(shares: &HostOnlyActivationOutputSharesV1) -> [[u8; 32]; 4] {
        [
            shares.deriver_a().client().expose_fixture_bytes(),
            shares.deriver_a().signing_worker().expose_fixture_bytes(),
            shares.deriver_b().client().expose_fixture_bytes(),
            shares.deriver_b().signing_worker().expose_fixture_bytes(),
        ]
    }

    #[test]
    fn all_origins_consume_metadata_with_zero_reevaluation_and_no_activation_claim() {
        for (index, pending) in [
            registration_pending(),
            recovery_pending(),
            refresh_pending(),
        ]
        .into_iter()
        .enumerate()
        {
            let origin = pending.origin();
            let binding = pending.artifact_binding();
            let expected_shares = match &pending {
                PendingActivationPreStateV1::Registration(value) => {
                    activation_share_fixture_bytes(&value.output.shares)
                }
                PendingActivationPreStateV1::Recovery(value) => {
                    activation_share_fixture_bytes(&value.output.shares)
                }
                PendingActivationPreStateV1::Refresh(value) => {
                    activation_share_fixture_bytes(&value.output.shares)
                }
            };
            let request = ActivationRequestV1::new(
                fresh(
                    &format!("activation-valid-{index}"),
                    0xd0_u8.wrapping_add(index as u8),
                    20_000 + index as u64,
                    0xe0_u8.wrapping_add(index as u8),
                ),
                pending,
            )
            .expect("valid metadata attempt");
            let success = consume_activation_metadata_v1(request);
            assert_eq!(success.post_state().origin(), origin);
            assert_eq!(success.post_state().artifact_binding(), binding);
            let retained_shares = match success.post_state() {
                MetadataConsumedActivationStateV1::Registration(value) => {
                    activation_share_fixture_bytes(&value.output.shares)
                }
                MetadataConsumedActivationStateV1::Recovery(value) => {
                    activation_share_fixture_bytes(&value.output.shares)
                }
                MetadataConsumedActivationStateV1::Refresh(value) => {
                    activation_share_fixture_bytes(&value.output.shares)
                }
            };
            assert_eq!(retained_shares, expected_shares);
            let zero = success.zero_reevaluation();
            assert_eq!(zero.yao_evaluations(), 0);
            assert_eq!(zero.deriver_a_invocations(), 0);
            assert_eq!(zero.deriver_b_invocations(), 0);
            assert_eq!(zero.contribution_derivations(), 0);
            assert_eq!(zero.output_share_samples(), 0);
            let projection = MetadataConsumedActivationProjectionV1::from_success(&success);
            assert_eq!(projection.committed().identity().origin(), origin);
        }
    }

    #[test]
    fn every_freshness_failure_is_one_uniform_retry_preserving_abort() {
        let cases = [
            ("semantic-lifecycle", 0xf1, 30_001, 0xf2),
            ("activation-new", 0x11, 30_002, 0xf3),
            ("activation-new", 0xf4, 30_003, 0x31),
            ("semantic-lifecycle", 0x11, 10_000, 0x31),
        ];
        for (request_id, replay, expiry, transcript_nonce) in cases {
            let pending = registration_pending();
            let before = OutputCommittedActivationProjectionV1::from_pending(&pending);
            let rejection = rejected(pending, fresh(request_id, replay, expiry, transcript_nonce));
            let projection = AttemptRejectedActivationProjectionV1::from_rejection(&rejection);
            assert_eq!(projection.before(), before);
            assert_eq!(projection.after(), before);
            assert_eq!(
                projection.abort().request_kind(),
                CeremonyRequestKindV1::Activation
            );
            assert_eq!(
                projection.abort().public_failure_code(),
                RedactedFailureCodeV1::Rejected
            );
            assert_eq!(
                projection.abort().terminal(),
                AbortedTerminalStateV1::Aborted
            );
        }
    }

    #[test]
    fn export_session_consumes_request_and_retains_registered_state_in_commitment() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = export_ceremony(fixture.registered_public_key);
        let request = ExportRequestV1::new(context, authorization, transcript).expect("request");
        let pair = provenance_pair(request.validated_dag(), Some(fixture.registered_public_key));
        let state = authenticate_state(
            request.request_context(),
            request.validated_dag(),
            &pair,
            state_from_provenance(pair.export_registered_state_binding().expect("binding"), 9),
            9,
        );
        let one_use_execution_id = OneUseExecutionId32V1::new([0xc4; 32]).expect("one use");
        let acceptance_authorities = canonical_export_acceptance_authorities_v1(&request);
        let acceptance_pair = canonical_verified_export_acceptance_pair_v1(
            &request,
            &state,
            &pair,
            one_use_execution_id,
            acceptance_authorities,
        );
        let session = request
            .begin_host_reference_artifact_session(
                ExportArtifactIssuanceV1::new(state, one_use_execution_id, acceptance_authorities),
                &pair,
                acceptance_pair,
            )
            .expect("session");
        let commitment = session
            .evaluate_and_commit_host_reference(
                export_inputs(&fixture),
                export_ideal_coin(),
                export_bindings(),
                export_output_commitment_evidence(),
            )
            .expect("export commitment");
        let (_request, state, artifacts, _shares) = commitment.into_parts();
        assert_eq!(state.state().active_activation_epoch().value(), 9);
        assert_eq!(
            artifacts.receipt().package_set_digest(),
            artifacts.packages().digest()
        );
    }
}
