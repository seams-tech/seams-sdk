//! Construction-independent refresh admission for the host evaluator.
//!
//! The selected production mechanism must authenticate the proposed opposite-
//! delta transition before this boundary is admitted. Phase 1 binds that
//! acceptance as an opaque digest and retains the exact store/provenance state.

use core::{fmt, num::NonZeroU64};

use sha2::{Digest, Sha256};

use crate::authenticated_store::{
    AuthenticatedRegisteredStoreResolutionV1, AuthenticatedStoreErrorV1,
};
use crate::ceremony_context::{
    CeremonyActivationEpochV1, CeremonyContextErrorV1, CeremonyDurableStoreIdentityScopeV1,
    CeremonyRequestKindV1,
};
use crate::lifecycle_domain::{RefreshRequestV1, RegisteredStateBindingFieldV1};
use crate::provenance::{
    DeriverAProvenanceRoleV1, DeriverBProvenanceRoleV1, ProvenanceEncodingErrorV1,
    ProvenanceRoleStateBindingV1, RefreshStateProvenanceBindingV1,
    RegisteredStateProvenanceErrorV1, RoleInputProvenancePairV1,
};
use crate::semantic_artifacts::{
    CommittedActivationArtifactsV1, OneUseExecutionId32V1,
    OpaqueHostReferenceEvaluationEvidenceDigest32V1, SemanticArtifactErrorV1,
};

/// Canonical refresh evaluator-admission encoding domain.
pub const REFRESH_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/refresh-evaluator-admission/v1";
/// Domain separating the refresh evaluator-admission digest.
pub const REFRESH_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/refresh-evaluator-admission-digest/v1";

const ACCEPTED_REFRESH_TAG_V1: u8 = 0x01;

/// Opaque evidence that the selected mechanism accepted the refresh transition.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1([u8; 32]);

impl OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1 {
    /// Records one nonzero selected-mechanism acceptance-evidence digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, RefreshAdmissionErrorV1> {
        if is_zero_32(&bytes) {
            return Err(RefreshAdmissionErrorV1::ZeroTransitionAcceptanceEvidence);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque evidence digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1([opaque digest])")
    }
}

/// Nonzero Unix timestamp used by the ideal refresh admission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefreshAdmissionCheckedAtUnixMsV1(NonZeroU64);

impl RefreshAdmissionCheckedAtUnixMsV1 {
    /// Validates a nonzero admission timestamp.
    pub const fn new(value: u64) -> Result<Self, RefreshAdmissionErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(RefreshAdmissionErrorV1::ZeroCheckedAt),
        }
    }

    /// Returns the Unix timestamp.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RefreshAdmissionCommonV1 {
    durable_identity: CeremonyDurableStoreIdentityScopeV1,
    request_id: String,
    replay_nonce: [u8; 32],
    request_expiry: u64,
    checked_at: RefreshAdmissionCheckedAtUnixMsV1,
    request_context_digest: [u8; 32],
    authorization_digest: [u8; 32],
    transcript_digest: [u8; 32],
    provenance_pair_digest: [u8; 32],
    deriver_a_statement_digest: [u8; 32],
    deriver_b_statement_digest: [u8; 32],
    signed_store_resolution_digest: [u8; 32],
    store_authority_key_epoch: u64,
    store_authority_key_digest: [u8; 32],
    active_state_version: u64,
    active_credential_binding_digest: [u8; 32],
    registered_public_key: [u8; 32],
    stable_scope_encoding: Vec<u8>,
    current_activation_epoch: u64,
    next_activation_epoch: CeremonyActivationEpochV1,
    current_deriver_a_input_state_epoch: u64,
    next_deriver_a: ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1>,
    current_deriver_b_input_state_epoch: u64,
    next_deriver_b: ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1>,
    continuity_evidence_artifact_digest: [u8; 32],
    selected_mechanism_acceptance_evidence_digest:
        OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1,
    one_use_execution_id: OneUseExecutionId32V1,
}

impl RefreshAdmissionCommonV1 {
    #[allow(clippy::too_many_arguments)]
    fn validate(
        request: &RefreshRequestV1,
        provenance: &RoleInputProvenancePairV1,
        state: &AuthenticatedRegisteredStoreResolutionV1,
        next_activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
        checked_at: RefreshAdmissionCheckedAtUnixMsV1,
        selected_mechanism_acceptance_evidence_digest:
            OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1,
    ) -> Result<(Self, RefreshStateProvenanceBindingV1), RefreshAdmissionErrorV1> {
        if request.request_kind() != CeremonyRequestKindV1::Refresh {
            return Err(RefreshAdmissionErrorV1::RequestKindMismatch);
        }
        let context = request.request_context();
        if checked_at.value() > context.request_expiry().value() {
            return Err(RefreshAdmissionErrorV1::RequestExpired);
        }
        state
            .validate_for(context, request.validated_dag(), provenance)
            .map_err(|_| RefreshAdmissionErrorV1::AuthenticatedStoreRejected)?;
        let binding = provenance.refresh_registered_state_binding()?;
        validate_epochs(request, state, binding, next_activation_epoch)?;
        let authority = state.trusted_transition_authority();
        let dag = request.validated_dag();
        Ok((
            Self {
                durable_identity: context.durable_store_identity_scope(),
                request_id: context.request_id().as_str().to_owned(),
                replay_nonce: *context.replay_nonce().as_bytes(),
                request_expiry: context.request_expiry().value(),
                checked_at,
                request_context_digest: *dag.request_context_digest().as_bytes(),
                authorization_digest: *dag.authorization_digest().as_bytes(),
                transcript_digest: *dag.transcript_digest().as_bytes(),
                provenance_pair_digest: *provenance.digest()?.as_bytes(),
                deriver_a_statement_digest: *provenance.deriver_a().digest()?.as_bytes(),
                deriver_b_statement_digest: *provenance.deriver_b().digest()?.as_bytes(),
                signed_store_resolution_digest: state.signed_resolution_digest()?,
                store_authority_key_epoch: authority.key_epoch().value(),
                store_authority_key_digest: authority.key_digest(),
                active_state_version: state.active_state_version().value(),
                active_credential_binding_digest: *state
                    .state()
                    .active_credential_binding_digest()
                    .as_bytes(),
                registered_public_key: *state.state().registered_public_key().as_bytes(),
                stable_scope_encoding: state.state().stable_scope().encode()?,
                current_activation_epoch: state.state().active_activation_epoch().value(),
                next_activation_epoch,
                current_deriver_a_input_state_epoch: state
                    .state()
                    .deriver_a_input_state_epoch()
                    .value(),
                next_deriver_a: binding.next_deriver_a(),
                current_deriver_b_input_state_epoch: state
                    .state()
                    .deriver_b_input_state_epoch()
                    .value(),
                next_deriver_b: binding.next_deriver_b(),
                continuity_evidence_artifact_digest: *provenance
                    .refresh_continuity_evidence_artifact_digest()?
                    .as_bytes(),
                selected_mechanism_acceptance_evidence_digest,
                one_use_execution_id,
            },
            binding,
        ))
    }

    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RefreshAdmissionErrorV1> {
        push_lp32(output, &self.durable_identity.encode()?)?;
        push_lp32(output, self.request_id.as_bytes())?;
        push_lp32(output, &self.replay_nonce)?;
        push_lp32(output, &self.request_expiry.to_be_bytes())?;
        push_lp32(output, &self.checked_at.value().to_be_bytes())?;
        push_lp32(output, &self.request_context_digest)?;
        push_lp32(output, &self.authorization_digest)?;
        push_lp32(output, &self.transcript_digest)?;
        push_lp32(output, &self.provenance_pair_digest)?;
        push_lp32(output, &self.deriver_a_statement_digest)?;
        push_lp32(output, &self.deriver_b_statement_digest)?;
        push_lp32(output, &self.signed_store_resolution_digest)?;
        push_lp32(output, &self.store_authority_key_epoch.to_be_bytes())?;
        push_lp32(output, &self.store_authority_key_digest)?;
        push_lp32(output, &self.active_state_version.to_be_bytes())?;
        push_lp32(output, &self.active_credential_binding_digest)?;
        push_lp32(output, &self.registered_public_key)?;
        push_lp32(output, &self.stable_scope_encoding)?;
        push_lp32(output, &self.current_activation_epoch.to_be_bytes())?;
        push_lp32(output, &self.next_activation_epoch.value().to_be_bytes())?;
        push_lp32(
            output,
            &self.current_deriver_a_input_state_epoch.to_be_bytes(),
        )?;
        encode_role_state(output, self.next_deriver_a)?;
        push_lp32(
            output,
            &self.current_deriver_b_input_state_epoch.to_be_bytes(),
        )?;
        encode_role_state(output, self.next_deriver_b)?;
        push_lp32(output, &self.continuity_evidence_artifact_digest)?;
        push_lp32(
            output,
            self.selected_mechanism_acceptance_evidence_digest
                .as_bytes(),
        )?;
        push_lp32(output, self.one_use_execution_id.as_bytes())
    }
}

/// Terminal refresh admission retained through evaluation and promotion.
pub struct TerminalRefreshEvaluationV1 {
    common: RefreshAdmissionCommonV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    encoding: Vec<u8>,
    admission_digest: [u8; 32],
}

impl TerminalRefreshEvaluationV1 {
    /// Returns the exact canonical refresh-admission bytes.
    pub fn encode(&self) -> &[u8] {
        &self.encoding
    }

    /// Returns the admission digest used as semantic evaluation evidence.
    pub const fn admission_digest(&self) -> &[u8; 32] {
        &self.admission_digest
    }

    /// Returns the unchanged authenticated current state.
    pub const fn state(&self) -> &AuthenticatedRegisteredStoreResolutionV1 {
        &self.state
    }

    /// Returns the proposed Deriver A next-state binding.
    pub const fn proposed_next_deriver_a(
        &self,
    ) -> ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1> {
        self.common.next_deriver_a
    }

    /// Returns the proposed Deriver B next-state binding.
    pub const fn proposed_next_deriver_b(
        &self,
    ) -> ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1> {
        self.common.next_deriver_b
    }

    /// Returns the opaque selected-mechanism acceptance evidence.
    pub const fn selected_mechanism_acceptance_evidence_digest(
        &self,
    ) -> OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1 {
        self.common.selected_mechanism_acceptance_evidence_digest
    }

    /// Returns the admitted next activation epoch.
    pub const fn next_activation_epoch(&self) -> CeremonyActivationEpochV1 {
        self.common.next_activation_epoch
    }

    /// Returns the one-use evaluator identity burned by this admission.
    pub const fn one_use_execution_id(&self) -> OneUseExecutionId32V1 {
        self.common.one_use_execution_id
    }

    pub(crate) fn matches_committed_output(
        &self,
        artifacts: &CommittedActivationArtifactsV1,
    ) -> bool {
        let binding = artifacts.binding();
        let receipt = artifacts.receipt();
        binding.origin_request_kind() == CeremonyRequestKindV1::Refresh
            && binding.origin_request_context_digest().as_bytes()
                == &self.common.request_context_digest
            && binding.origin_authorization_digest().as_bytes() == &self.common.authorization_digest
            && binding.origin_transcript_digest().as_bytes() == &self.common.transcript_digest
            && binding.activation_epoch() == self.common.next_activation_epoch
            && binding.one_use_execution_id() == self.common.one_use_execution_id
            && receipt.evaluation_evidence_digest().as_bytes() == &self.admission_digest
            && receipt.registered_public_key().as_bytes() == &self.common.registered_public_key
    }
}

impl fmt::Debug for TerminalRefreshEvaluationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalRefreshEvaluationV1")
            .field("active_state_version", &self.common.active_state_version)
            .field("next_activation_epoch", &self.common.next_activation_epoch)
            .field("admission_digest", &"[computed SHA-256]")
            .finish()
    }
}

/// Move-only ideal refresh evaluator admission.
///
/// ```compile_fail
/// use ed25519_yao_generator::AcceptedRefreshAdmissionV1;
///
/// fn cannot_admit_twice(admission: AcceptedRefreshAdmissionV1) {
///     drop(admission);
///     drop(admission);
/// }
/// ```
pub struct AcceptedRefreshAdmissionV1 {
    terminal: TerminalRefreshEvaluationV1,
    evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
}

impl AcceptedRefreshAdmissionV1 {
    /// Returns the terminal admitted refresh identity.
    pub const fn terminal(&self) -> &TerminalRefreshEvaluationV1 {
        &self.terminal
    }

    pub(crate) fn validate_for(
        &self,
        request: &RefreshRequestV1,
        provenance: &RoleInputProvenancePairV1,
    ) -> Result<(), RefreshAdmissionErrorV1> {
        let (expected, _) = RefreshAdmissionCommonV1::validate(
            request,
            provenance,
            &self.terminal.state,
            self.terminal.common.next_activation_epoch,
            self.terminal.common.one_use_execution_id,
            self.terminal.common.checked_at,
            self.terminal
                .common
                .selected_mechanism_acceptance_evidence_digest,
        )?;
        if expected != self.terminal.common {
            return Err(RefreshAdmissionErrorV1::AdmissionBindingMismatch);
        }
        Ok(())
    }

    pub(crate) const fn evaluation_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceEvaluationEvidenceDigest32V1 {
        self.evaluation_evidence_digest
    }

    pub(crate) fn into_terminal(self) -> TerminalRefreshEvaluationV1 {
        self.terminal
    }
}

/// Accepts one signed registered-state resolution into the ideal refresh evaluator.
#[allow(clippy::too_many_arguments)]
pub fn accept_host_only_refresh_admission_v1(
    request: &RefreshRequestV1,
    provenance: &RoleInputProvenancePairV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    next_activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
    checked_at: RefreshAdmissionCheckedAtUnixMsV1,
    selected_mechanism_acceptance_evidence_digest:
        OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1,
) -> Result<AcceptedRefreshAdmissionV1, RejectedRefreshAdmissionV1> {
    let (common, _) = match RefreshAdmissionCommonV1::validate(
        request,
        provenance,
        &state,
        next_activation_epoch,
        one_use_execution_id,
        checked_at,
        selected_mechanism_acceptance_evidence_digest,
    ) {
        Ok(value) => value,
        Err(reason) => return Err(RejectedRefreshAdmissionV1 { reason, state }),
    };
    let mut encoding = Vec::new();
    let encoded = (|| {
        push_lp32(
            &mut encoding,
            REFRESH_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1,
        )?;
        common.encode_into(&mut encoding)?;
        push_lp32(&mut encoding, &[ACCEPTED_REFRESH_TAG_V1])?;
        let mut digest_input = Vec::new();
        push_lp32(
            &mut digest_input,
            REFRESH_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1,
        )?;
        push_lp32(&mut digest_input, &encoding)?;
        let admission_digest: [u8; 32] = Sha256::digest(digest_input).into();
        let evidence = OpaqueHostReferenceEvaluationEvidenceDigest32V1::new(admission_digest)?;
        Ok::<_, RefreshAdmissionErrorV1>((admission_digest, evidence))
    })();
    let (admission_digest, evaluation_evidence_digest) = match encoded {
        Ok(value) => value,
        Err(reason) => return Err(RejectedRefreshAdmissionV1 { reason, state }),
    };
    Ok(AcceptedRefreshAdmissionV1 {
        terminal: TerminalRefreshEvaluationV1 {
            common,
            state,
            encoding,
            admission_digest,
        },
        evaluation_evidence_digest,
    })
}

/// Rejected refresh admission retaining the unchanged authenticated state.
pub struct RejectedRefreshAdmissionV1 {
    reason: RefreshAdmissionErrorV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
}

impl RejectedRefreshAdmissionV1 {
    /// Returns the precise admission rejection.
    pub const fn reason(&self) -> RefreshAdmissionErrorV1 {
        self.reason
    }

    /// Recovers the state; no evaluator admission was established.
    pub fn into_state(self) -> AuthenticatedRegisteredStoreResolutionV1 {
        self.state
    }
}

impl fmt::Debug for RejectedRefreshAdmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRefreshAdmissionV1")
            .field("reason", &self.reason)
            .field("state", &"[retained authenticated state]")
            .finish()
    }
}

/// Failure while constructing or consuming a refresh admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshAdmissionErrorV1 {
    /// Admission timestamps must be nonzero.
    ZeroCheckedAt,
    /// Selected-mechanism transition acceptance evidence must be nonzero.
    ZeroTransitionAcceptanceEvidence,
    /// The supplied request was not refresh.
    RequestKindMismatch,
    /// The request was expired when admission was accepted.
    RequestExpired,
    /// The next activation epoch did not strictly advance.
    ActivationEpochDidNotAdvance,
    /// A role-state epoch or authorization epoch was incoherent.
    EpochBindingMismatch(RegisteredStateBindingFieldV1),
    /// The admission was replayed against different bound inputs.
    AdmissionBindingMismatch,
    /// The authenticated store resolution did not bind the request and provenance.
    AuthenticatedStoreRejected,
    /// Canonical ceremony encoding failed.
    Ceremony(CeremonyContextErrorV1),
    /// Canonical provenance encoding failed.
    Provenance(ProvenanceEncodingErrorV1),
    /// Provenance belonged to another lifecycle branch.
    ProvenanceRequestKindMismatch,
    /// Semantic evidence digest construction failed.
    Semantic(SemanticArtifactErrorV1),
    /// One LP32 field exceeded the version-one length bound.
    ValueTooLong,
}

impl fmt::Display for RefreshAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCheckedAt => formatter.write_str("refresh checked-at must be nonzero"),
            Self::ZeroTransitionAcceptanceEvidence => {
                formatter.write_str("refresh transition acceptance evidence must be nonzero")
            }
            Self::RequestKindMismatch => {
                formatter.write_str("refresh admission requires a refresh request")
            }
            Self::RequestExpired => formatter.write_str("refresh request expired"),
            Self::ActivationEpochDidNotAdvance => {
                formatter.write_str("refresh activation epoch must strictly advance")
            }
            Self::EpochBindingMismatch(field) => {
                write!(formatter, "refresh epoch binding mismatch: {field:?}")
            }
            Self::AdmissionBindingMismatch => {
                formatter.write_str("refresh admission binding mismatch")
            }
            Self::AuthenticatedStoreRejected => {
                formatter.write_str("authenticated refresh store resolution rejected")
            }
            Self::Ceremony(error) => error.fmt(formatter),
            Self::Provenance(error) => error.fmt(formatter),
            Self::ProvenanceRequestKindMismatch => {
                formatter.write_str("refresh admission requires refresh provenance")
            }
            Self::Semantic(error) => error.fmt(formatter),
            Self::ValueTooLong => formatter.write_str("refresh admission LP32 overflow"),
        }
    }
}

impl std::error::Error for RefreshAdmissionErrorV1 {}

fn validate_epochs(
    request: &RefreshRequestV1,
    state: &AuthenticatedRegisteredStoreResolutionV1,
    binding: RefreshStateProvenanceBindingV1,
    next_activation_epoch: CeremonyActivationEpochV1,
) -> Result<(), RefreshAdmissionErrorV1> {
    if next_activation_epoch.value() <= state.state().active_activation_epoch().value() {
        return Err(RefreshAdmissionErrorV1::ActivationEpochDidNotAdvance);
    }
    let authorization = request.authorization();
    let checks = [
        (
            authorization.current_deriver_a_input_state_epoch().value()
                == state.state().deriver_a_input_state_epoch().value(),
            RegisteredStateBindingFieldV1::AuthorizationCurrentDeriverAInputStateEpoch,
        ),
        (
            authorization.next_deriver_a_input_state_epoch().value()
                == binding.next_deriver_a().epoch().value(),
            RegisteredStateBindingFieldV1::AuthorizationNextDeriverAInputStateEpoch,
        ),
        (
            authorization.current_deriver_b_input_state_epoch().value()
                == state.state().deriver_b_input_state_epoch().value(),
            RegisteredStateBindingFieldV1::AuthorizationCurrentDeriverBInputStateEpoch,
        ),
        (
            authorization.next_deriver_b_input_state_epoch().value()
                == binding.next_deriver_b().epoch().value(),
            RegisteredStateBindingFieldV1::AuthorizationNextDeriverBInputStateEpoch,
        ),
    ];
    for (valid, field) in checks {
        if !valid {
            return Err(RefreshAdmissionErrorV1::EpochBindingMismatch(field));
        }
    }
    Ok(())
}

fn encode_role_state<Role: crate::provenance::ProvenanceRoleV1>(
    output: &mut Vec<u8>,
    binding: ProvenanceRoleStateBindingV1<Role>,
) -> Result<(), RefreshAdmissionErrorV1> {
    push_lp32(output, binding.role_root_record_digest().as_bytes())?;
    push_lp32(output, binding.root_binding_artifact_digest().as_bytes())?;
    push_lp32(output, &binding.role_root_epoch().value().to_be_bytes())?;
    push_lp32(output, binding.record_digest().as_bytes())?;
    push_lp32(output, &binding.epoch().value().to_be_bytes())
}

impl From<AuthenticatedStoreErrorV1> for RefreshAdmissionErrorV1 {
    fn from(_: AuthenticatedStoreErrorV1) -> Self {
        Self::AuthenticatedStoreRejected
    }
}

impl From<CeremonyContextErrorV1> for RefreshAdmissionErrorV1 {
    fn from(error: CeremonyContextErrorV1) -> Self {
        Self::Ceremony(error)
    }
}

impl From<ProvenanceEncodingErrorV1> for RefreshAdmissionErrorV1 {
    fn from(error: ProvenanceEncodingErrorV1) -> Self {
        Self::Provenance(error)
    }
}

impl From<RegisteredStateProvenanceErrorV1> for RefreshAdmissionErrorV1 {
    fn from(_: RegisteredStateProvenanceErrorV1) -> Self {
        Self::ProvenanceRequestKindMismatch
    }
}

impl From<SemanticArtifactErrorV1> for RefreshAdmissionErrorV1 {
    fn from(error: SemanticArtifactErrorV1) -> Self {
        Self::Semantic(error)
    }
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RefreshAdmissionErrorV1> {
    let length = u32::try_from(value.len()).map_err(|_| RefreshAdmissionErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

const fn is_zero_32(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    let mut nonzero = 0u8;
    while index < bytes.len() {
        nonzero |= bytes[index];
        index += 1;
    }
    nonzero == 0
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    use super::*;
    use crate::ceremony_fixtures::canonical_refresh_ceremony_fixture_v1;
    use crate::joint_refresh_delta::{
        HostOnlyDeriverARefreshDeltaContributionV1, HostOnlyDeriverBRefreshDeltaContributionV1,
        HostOnlyJointRefreshDeltaCoinsV1,
    };
    use crate::lifecycle_domain::{ActivationReceiptEvidenceV1, ArtifactSessionErrorV1};
    use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
    use crate::semantic_artifacts::{
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    };
    use crate::semantic_fixture_material::{
        activation_bindings, reference_fixture, refresh_ideal_coins, refresh_inputs,
    };
    use crate::semantic_lifecycle_fixtures::authenticated_state_from_provenance;
    use crate::{HostOnlyRefreshReferenceInputsV1, RegisteredEd25519PublicKey32V1};

    fn fixture() -> (
        RefreshRequestV1,
        RoleInputProvenancePairV1,
        AuthenticatedRegisteredStoreResolutionV1,
    ) {
        let material = reference_fixture();
        let (context, authorization, transcript) = canonical_refresh_ceremony_fixture_v1();
        let request = RefreshRequestV1::new(context, authorization, transcript).expect("request");
        let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
            CeremonyRequestKindV1::Refresh,
            material.registered_public_key,
        );
        let binding = provenance
            .refresh_registered_state_binding()
            .expect("refresh binding");
        let state = authenticated_state_from_provenance(
            request.request_context(),
            request.validated_dag(),
            &provenance,
            binding.current(),
            10,
            12,
        );
        (request, provenance, state)
    }

    fn checked_at(request: &RefreshRequestV1) -> RefreshAdmissionCheckedAtUnixMsV1 {
        RefreshAdmissionCheckedAtUnixMsV1::new(request.request_context().request_expiry().value())
            .expect("checked at")
    }

    fn evidence(byte: u8) -> OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1 {
        OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1::new([byte; 32])
            .expect("acceptance evidence")
    }

    fn receipt_evidence() -> ActivationReceiptEvidenceV1 {
        ActivationReceiptEvidenceV1::new(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xb7; 32])
                .expect("A receipt"),
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xb8; 32])
                .expect("B receipt"),
        )
    }

    fn accepted(
        request: &RefreshRequestV1,
        provenance: &RoleInputProvenancePairV1,
        state: AuthenticatedRegisteredStoreResolutionV1,
        execution: OneUseExecutionId32V1,
        selected_evidence: OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1,
    ) -> AcceptedRefreshAdmissionV1 {
        accept_host_only_refresh_admission_v1(
            request,
            provenance,
            state,
            CeremonyActivationEpochV1::new(11).expect("next epoch"),
            execution,
            checked_at(request),
            selected_evidence,
        )
        .expect("accepted refresh")
    }

    #[test]
    fn accepted_admission_is_the_only_evaluation_evidence_and_survives_commitment() {
        let material = reference_fixture();
        let (request, provenance, state) = fixture();
        let admission = accepted(
            &request,
            &provenance,
            state,
            OneUseExecutionId32V1::new([0xb1; 32]).expect("execution"),
            evidence(0xa3),
        );
        let expected_digest = *admission.terminal().admission_digest();
        let pending = request
            .begin_host_reference_artifact_session(admission, &provenance)
            .expect("session")
            .evaluate_and_commit_host_reference(
                refresh_inputs(&material),
                refresh_ideal_coins(3, 5),
                activation_bindings(),
                receipt_evidence(),
            )
            .expect("committed refresh");
        assert_eq!(pending.terminal().admission_digest(), &expected_digest);
        assert_eq!(
            pending
                .artifacts()
                .receipt()
                .evaluation_evidence_digest()
                .as_bytes(),
            &expected_digest
        );
    }

    #[test]
    fn expired_request_rejects_and_returns_the_authenticated_state() {
        let (request, provenance, state) = fixture();
        let expired = RefreshAdmissionCheckedAtUnixMsV1::new(
            request.request_context().request_expiry().value() + 1,
        )
        .expect("expired time");
        let rejection = match accept_host_only_refresh_admission_v1(
            &request,
            &provenance,
            state,
            CeremonyActivationEpochV1::new(11).expect("next epoch"),
            OneUseExecutionId32V1::new([0xb2; 32]).expect("execution"),
            expired,
            evidence(0xa3),
        ) {
            Err(rejection) => rejection,
            Ok(_) => panic!("expired request accepted"),
        };
        assert_eq!(rejection.reason(), RefreshAdmissionErrorV1::RequestExpired);
        assert_eq!(rejection.into_state().active_state_version().value(), 12);
    }

    #[test]
    fn zero_time_and_selected_mechanism_evidence_are_rejected() {
        assert_eq!(
            RefreshAdmissionCheckedAtUnixMsV1::new(0),
            Err(RefreshAdmissionErrorV1::ZeroCheckedAt)
        );
        assert_eq!(
            OpaqueRefreshTransitionAcceptanceEvidenceDigest32V1::new([0; 32]),
            Err(RefreshAdmissionErrorV1::ZeroTransitionAcceptanceEvidence)
        );
    }

    #[test]
    fn stale_activation_epoch_rejects_before_evaluation() {
        let (request, provenance, state) = fixture();
        let rejection = match accept_host_only_refresh_admission_v1(
            &request,
            &provenance,
            state,
            CeremonyActivationEpochV1::new(10).expect("stale epoch"),
            OneUseExecutionId32V1::new([0xb3; 32]).expect("execution"),
            checked_at(&request),
            evidence(0xa3),
        ) {
            Err(rejection) => rejection,
            Ok(_) => panic!("stale activation epoch accepted"),
        };
        assert_eq!(
            rejection.reason(),
            RefreshAdmissionErrorV1::ActivationEpochDidNotAdvance
        );
        assert_eq!(
            rejection
                .into_state()
                .state()
                .active_activation_epoch()
                .value(),
            10
        );
    }

    #[test]
    fn provenance_and_registered_identity_splices_are_rejected() {
        let (request, provenance, state) = fixture();
        let admission = accepted(
            &request,
            &provenance,
            state,
            OneUseExecutionId32V1::new([0xb4; 32]).expect("execution"),
            evidence(0xa3),
        );
        let alternate_key = RegisteredEd25519PublicKey32V1::parse(
            (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        )
        .expect("alternate key");
        let alternate = canonical_provenance_fixture_pair_for_registered_key_v1(
            CeremonyRequestKindV1::Refresh,
            alternate_key,
        );
        let rejection = match request.begin_host_reference_artifact_session(admission, &alternate) {
            Err(rejection) => rejection,
            Ok(_) => panic!("spliced provenance accepted"),
        };
        assert_eq!(
            rejection.reason(),
            ArtifactSessionErrorV1::RefreshAdmissionRejected
        );
    }

    #[test]
    fn selected_mechanism_evidence_changes_the_admission_identity() {
        let (request_a, provenance_a, state_a) = fixture();
        let a = accepted(
            &request_a,
            &provenance_a,
            state_a,
            OneUseExecutionId32V1::new([0xb5; 32]).expect("execution"),
            evidence(0xa3),
        );
        let (request_b, provenance_b, state_b) = fixture();
        let b = accepted(
            &request_b,
            &provenance_b,
            state_b,
            OneUseExecutionId32V1::new([0xb5; 32]).expect("execution"),
            evidence(0xa4),
        );
        assert_ne!(
            a.terminal().admission_digest(),
            b.terminal().admission_digest()
        );
    }

    #[test]
    fn arithmetic_failure_burns_execution_and_retains_terminal_state() {
        let material = reference_fixture();
        let (request, provenance, state) = fixture();
        let execution = OneUseExecutionId32V1::new([0xb6; 32]).expect("execution");
        let admission = accepted(&request, &provenance, state, execution, evidence(0xa3));
        let expected_digest = *admission.terminal().admission_digest();
        let cancelling = HostOnlyJointRefreshDeltaCoinsV1::new(
            HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture(
                [0; 32],
                Scalar::ONE.to_bytes(),
            )
            .expect("A contribution"),
            HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture(
                [0; 32],
                (-Scalar::ONE).to_bytes(),
            )
            .expect("B contribution"),
        );
        let failure = match request
            .begin_host_reference_artifact_session(admission, &provenance)
            .expect("session")
            .evaluate_and_commit_host_reference(
                HostOnlyRefreshReferenceInputsV1::new(
                    &material.deriver_a,
                    &material.deriver_b,
                    cancelling,
                ),
                refresh_ideal_coins(3, 5),
                activation_bindings(),
                receipt_evidence(),
            ) {
            Err(failure) => failure,
            Ok(_) => panic!("cancelling delta accepted"),
        };
        let retained = failure.into_retained();
        assert_eq!(retained.burned().one_use_execution_id(), execution);
        assert_eq!(retained.terminal().admission_digest(), &expected_digest);
        assert_eq!(
            retained
                .terminal()
                .state()
                .state()
                .active_activation_epoch()
                .value(),
            10
        );
    }

    #[test]
    fn source_guards_exclude_legacy_raw_evidence_and_profile_fields() {
        let lifecycle = include_str!("lifecycle_domain.rs");
        let admission = include_str!("refresh_evaluation_admission.rs");
        assert!(!lifecycle.contains("RefreshArtifactIssuanceV1"));
        assert!(!lifecycle.contains(
            "input_provenance: &RoleInputProvenancePairV1,\n        evaluation_evidence_digest"
        ));
        for forbidden in [
            ["security", "profile"].join("_"),
            ["garbled", "circuit"].join("_"),
            ["private", "delta"].join("_"),
            ["seed", "output"].join("_"),
        ] {
            assert!(!admission.contains(&forbidden));
        }
    }
}
