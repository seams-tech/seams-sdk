//! Construction-independent recovery admission for the host evaluator.
//!
//! The selected production mechanism must authenticate the same-root artifact
//! before the store authority seals the registered-state resolution. This
//! module consumes that sealed resolution into one ideal evaluator admission.

use core::{fmt, num::NonZeroU64};

use sha2::{Digest, Sha256};

use crate::authenticated_store::{
    AuthenticatedRegisteredStoreResolutionV1, AuthenticatedStoreErrorV1,
};
use crate::ceremony_context::{
    CeremonyActivationEpochV1, CeremonyContextErrorV1, CeremonyDurableStoreIdentityScopeV1,
    CeremonyRequestKindV1,
};
use crate::lifecycle_domain::{
    AuthenticatedRecoveryCredentialContinuityEvidenceV1, RecoveryCredentialContinuityErrorV1,
    RecoveryRequestV1,
};
use crate::provenance::{
    ProvenanceEncodingErrorV1, RegisteredStateProvenanceErrorV1, RoleInputProvenancePairV1,
};
use crate::recovery_credential_transition::{
    AuthenticatedRecoveryCredentialSuspensionV1,
};
use crate::semantic_artifacts::{
    CommittedActivationArtifactsV1, OneUseExecutionId32V1,
    OpaqueHostReferenceEvaluationEvidenceDigest32V1, SemanticArtifactErrorV1,
};

/// Canonical recovery evaluator-admission encoding domain.
pub const RECOVERY_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recovery-evaluator-admission/v1";
/// Domain separating the recovery evaluator-admission digest.
pub const RECOVERY_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/recovery-evaluator-admission-digest/v1";

const ACCEPTED_RECOVERY_TAG_V1: u8 = 0x01;

/// Opaque evidence that the selected mechanism accepted the same-root artifact.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1([u8; 32]);

impl OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1 {
    /// Records one nonzero selected-mechanism acceptance-evidence digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, RecoveryAdmissionErrorV1> {
        if is_zero_32(&bytes) {
            return Err(RecoveryAdmissionErrorV1::ZeroContinuityAcceptanceEvidence);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque evidence digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1([opaque digest])",
        )
    }
}

/// Nonzero Unix timestamp used by the ideal recovery admission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryAdmissionCheckedAtUnixMsV1(NonZeroU64);

impl RecoveryAdmissionCheckedAtUnixMsV1 {
    /// Validates a nonzero admission timestamp.
    pub const fn new(value: u64) -> Result<Self, RecoveryAdmissionErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(RecoveryAdmissionErrorV1::ZeroCheckedAt),
        }
    }

    /// Returns the Unix timestamp.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveryAdmissionCommonV1 {
    durable_identity: CeremonyDurableStoreIdentityScopeV1,
    request_id: String,
    replay_nonce: [u8; 32],
    request_expiry: u64,
    checked_at: RecoveryAdmissionCheckedAtUnixMsV1,
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
    replacement_credential_binding_digest: [u8; 32],
    registered_public_key: [u8; 32],
    stable_scope_encoding: Vec<u8>,
    same_root_evidence_artifact_digest: [u8; 32],
    selected_mechanism_acceptance_evidence_digest:
        OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1,
    current_activation_epoch: u64,
    next_activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
}

impl RecoveryAdmissionCommonV1 {
    fn validate(
        request: &RecoveryRequestV1,
        provenance: &RoleInputProvenancePairV1,
        state: &AuthenticatedRegisteredStoreResolutionV1,
        next_activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
        checked_at: RecoveryAdmissionCheckedAtUnixMsV1,
        selected_mechanism_acceptance_evidence_digest:
            OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1,
    ) -> Result<
        (
            Self,
            AuthenticatedRecoveryCredentialContinuityEvidenceV1,
        ),
        RecoveryAdmissionErrorV1,
    > {
        if request.request_kind() != CeremonyRequestKindV1::Recovery {
            return Err(RecoveryAdmissionErrorV1::RequestKindMismatch);
        }
        let context = request.request_context();
        if checked_at.value() > context.request_expiry().value() {
            return Err(RecoveryAdmissionErrorV1::RequestExpired);
        }
        state
            .validate_for(context, request.validated_dag(), provenance)
            .map_err(|_| RecoveryAdmissionErrorV1::AuthenticatedStoreRejected)?;
        if next_activation_epoch.value() <= state.state().active_activation_epoch().value() {
            return Err(RecoveryAdmissionErrorV1::ActivationEpochDidNotAdvance);
        }
        let continuity =
            AuthenticatedRecoveryCredentialContinuityEvidenceV1::from_authenticated_bindings(
                state,
                request.authorization(),
                provenance,
            )
            .map_err(RecoveryAdmissionErrorV1::CredentialContinuity)?;
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
                active_state_version: continuity.active_state_version().value(),
                active_credential_binding_digest: *continuity
                    .active_credential_binding_digest()
                    .as_bytes(),
                replacement_credential_binding_digest: *continuity
                    .replacement_credential_binding_digest()
                    .as_bytes(),
                registered_public_key: *continuity.registered_public_key().as_bytes(),
                stable_scope_encoding: continuity.stable_scope().encode()?,
                same_root_evidence_artifact_digest: *continuity
                    .same_root_evidence_artifact_digest()
                    .as_bytes(),
                selected_mechanism_acceptance_evidence_digest,
                current_activation_epoch: state.state().active_activation_epoch().value(),
                next_activation_epoch,
                one_use_execution_id,
            },
            continuity,
        ))
    }

    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecoveryAdmissionErrorV1> {
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
        push_lp32(output, &self.replacement_credential_binding_digest)?;
        push_lp32(output, &self.registered_public_key)?;
        push_lp32(output, &self.stable_scope_encoding)?;
        push_lp32(output, &self.same_root_evidence_artifact_digest)?;
        push_lp32(
            output,
            self.selected_mechanism_acceptance_evidence_digest.as_bytes(),
        )?;
        push_lp32(output, &self.current_activation_epoch.to_be_bytes())?;
        push_lp32(output, &self.next_activation_epoch.value().to_be_bytes())?;
        push_lp32(output, self.one_use_execution_id.as_bytes())?;
        Ok(())
    }
}

/// Terminal recovery admission retained through evaluation and promotion.
pub struct TerminalRecoveryEvaluationV1 {
    common: RecoveryAdmissionCommonV1,
    suspension: AuthenticatedRecoveryCredentialSuspensionV1,
    encoding: Vec<u8>,
    admission_digest: [u8; 32],
}

impl TerminalRecoveryEvaluationV1 {
    /// Returns the exact canonical recovery-admission bytes.
    pub fn encode(&self) -> &[u8] {
        &self.encoding
    }

    /// Returns the admission digest used as semantic evaluation evidence.
    pub const fn admission_digest(&self) -> &[u8; 32] {
        &self.admission_digest
    }

    /// Returns the exact authenticated old-credential suspension.
    pub const fn suspension(&self) -> &AuthenticatedRecoveryCredentialSuspensionV1 {
        &self.suspension
    }

    /// Returns the exact old-to-replacement credential binding.
    pub const fn credential_continuity(
        &self,
    ) -> AuthenticatedRecoveryCredentialContinuityEvidenceV1 {
        self.suspension.continuity()
    }

    /// Returns the opaque selected-mechanism acceptance evidence.
    pub const fn selected_mechanism_acceptance_evidence_digest(
        &self,
    ) -> OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1 {
        self.common
            .selected_mechanism_acceptance_evidence_digest
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
        binding.origin_request_kind() == CeremonyRequestKindV1::Recovery
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

impl fmt::Debug for TerminalRecoveryEvaluationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalRecoveryEvaluationV1")
            .field("active_state_version", &self.common.active_state_version)
            .field("next_activation_epoch", &self.common.next_activation_epoch)
            .field("admission_digest", &"[computed SHA-256]")
            .finish()
    }
}

/// Move-only ideal recovery evaluator admission.
///
/// ```compile_fail
/// use ed25519_yao_generator::AcceptedRecoveryAdmissionV1;
///
/// fn cannot_admit_twice(admission: AcceptedRecoveryAdmissionV1) {
///     drop(admission);
///     drop(admission);
/// }
/// ```
pub struct AcceptedRecoveryAdmissionV1 {
    terminal: TerminalRecoveryEvaluationV1,
    evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
}

impl AcceptedRecoveryAdmissionV1 {
    /// Returns the terminal admitted recovery identity.
    pub const fn terminal(&self) -> &TerminalRecoveryEvaluationV1 {
        &self.terminal
    }

    pub(crate) fn validate_for(
        &self,
        request: &RecoveryRequestV1,
        provenance: &RoleInputProvenancePairV1,
    ) -> Result<(), RecoveryAdmissionErrorV1> {
        let (expected, continuity) = RecoveryAdmissionCommonV1::validate(
            request,
            provenance,
            self.terminal.suspension.store_resolution(),
            self.terminal.common.next_activation_epoch,
            self.terminal.common.one_use_execution_id,
            self.terminal.common.checked_at,
            self.terminal
                .common
                .selected_mechanism_acceptance_evidence_digest,
        )?;
        if expected != self.terminal.common || continuity != self.terminal.suspension.continuity() {
            return Err(RecoveryAdmissionErrorV1::AdmissionBindingMismatch);
        }
        Ok(())
    }

    pub(crate) const fn evaluation_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceEvaluationEvidenceDigest32V1 {
        self.evaluation_evidence_digest
    }

    pub(crate) fn into_terminal(self) -> TerminalRecoveryEvaluationV1 {
        self.terminal
    }
}

/// Accepts one signed registered-state resolution into the ideal recovery evaluator.
pub fn accept_host_only_recovery_admission_v1(
    request: &RecoveryRequestV1,
    provenance: &RoleInputProvenancePairV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
    next_activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
    checked_at: RecoveryAdmissionCheckedAtUnixMsV1,
    selected_mechanism_acceptance_evidence_digest:
        OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1,
) -> Result<AcceptedRecoveryAdmissionV1, RejectedRecoveryAdmissionV1> {
    let (common, continuity) = match RecoveryAdmissionCommonV1::validate(
        request,
        provenance,
        &state,
        next_activation_epoch,
        one_use_execution_id,
        checked_at,
        selected_mechanism_acceptance_evidence_digest,
    ) {
        Ok(value) => value,
        Err(reason) => return Err(RejectedRecoveryAdmissionV1 { reason, state }),
    };
    let mut encoding = Vec::new();
    let encoded = (|| {
        push_lp32(&mut encoding, RECOVERY_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1)?;
        common.encode_into(&mut encoding)?;
        push_lp32(&mut encoding, &[ACCEPTED_RECOVERY_TAG_V1])?;
        let mut digest_input = Vec::new();
        push_lp32(
            &mut digest_input,
            RECOVERY_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1,
        )?;
        push_lp32(&mut digest_input, &encoding)?;
        let admission_digest: [u8; 32] = Sha256::digest(digest_input).into();
        let evidence = OpaqueHostReferenceEvaluationEvidenceDigest32V1::new(admission_digest)?;
        Ok::<_, RecoveryAdmissionErrorV1>((admission_digest, evidence))
    })();
    let (admission_digest, evaluation_evidence_digest) = match encoded {
        Ok(value) => value,
        Err(reason) => return Err(RejectedRecoveryAdmissionV1 { reason, state }),
    };
    let suspension = match AuthenticatedRecoveryCredentialSuspensionV1::try_from_admitted(
        state, continuity,
    ) {
        Ok(value) => value,
        Err(rejected) => {
            let (reason, state) = rejected.into_parts();
            return Err(RejectedRecoveryAdmissionV1 {
                reason: RecoveryAdmissionErrorV1::CredentialContinuity(reason),
                state,
            });
        }
    };
    Ok(AcceptedRecoveryAdmissionV1 {
        terminal: TerminalRecoveryEvaluationV1 {
            common,
            suspension,
            encoding,
            admission_digest,
        },
        evaluation_evidence_digest,
    })
}

/// Rejected recovery admission retaining the unchanged authenticated state.
pub struct RejectedRecoveryAdmissionV1 {
    reason: RecoveryAdmissionErrorV1,
    state: AuthenticatedRegisteredStoreResolutionV1,
}

impl RejectedRecoveryAdmissionV1 {
    /// Returns the precise admission rejection.
    pub const fn reason(&self) -> RecoveryAdmissionErrorV1 {
        self.reason
    }

    /// Recovers the state; no suspension was established.
    pub fn into_state(self) -> AuthenticatedRegisteredStoreResolutionV1 {
        self.state
    }
}

impl fmt::Debug for RejectedRecoveryAdmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedRecoveryAdmissionV1")
            .field("reason", &self.reason)
            .field("state", &"[retained authenticated state]")
            .finish()
    }
}

/// Failure while constructing or consuming a recovery admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAdmissionErrorV1 {
    /// Admission timestamps must be nonzero.
    ZeroCheckedAt,
    /// Selected-mechanism same-root acceptance evidence must be nonzero.
    ZeroContinuityAcceptanceEvidence,
    /// The supplied request was not recovery.
    RequestKindMismatch,
    /// The request was expired when admission was accepted.
    RequestExpired,
    /// The next activation epoch did not strictly advance.
    ActivationEpochDidNotAdvance,
    /// The admission was replayed against different bound inputs.
    AdmissionBindingMismatch,
    /// The authenticated store resolution did not bind the request and provenance.
    AuthenticatedStoreRejected,
    /// The old/replacement credential relation was invalid.
    CredentialContinuity(RecoveryCredentialContinuityErrorV1),
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

impl fmt::Display for RecoveryAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCheckedAt => formatter.write_str("recovery checked-at must be nonzero"),
            Self::ZeroContinuityAcceptanceEvidence => formatter
                .write_str("recovery continuity acceptance evidence must be nonzero"),
            Self::RequestKindMismatch => {
                formatter.write_str("recovery admission requires a recovery request")
            }
            Self::RequestExpired => formatter.write_str("recovery request expired"),
            Self::ActivationEpochDidNotAdvance => {
                formatter.write_str("recovery activation epoch must strictly advance")
            }
            Self::AdmissionBindingMismatch => {
                formatter.write_str("recovery admission binding mismatch")
            }
            Self::AuthenticatedStoreRejected => {
                formatter.write_str("authenticated recovery store resolution rejected")
            }
            Self::CredentialContinuity(error) => error.fmt(formatter),
            Self::Ceremony(error) => error.fmt(formatter),
            Self::Provenance(error) => error.fmt(formatter),
            Self::ProvenanceRequestKindMismatch => {
                formatter.write_str("recovery admission requires recovery provenance")
            }
            Self::Semantic(error) => error.fmt(formatter),
            Self::ValueTooLong => formatter.write_str("recovery admission LP32 overflow"),
        }
    }
}

impl std::error::Error for RecoveryAdmissionErrorV1 {}

impl From<AuthenticatedStoreErrorV1> for RecoveryAdmissionErrorV1 {
    fn from(_: AuthenticatedStoreErrorV1) -> Self {
        Self::AuthenticatedStoreRejected
    }
}

impl From<CeremonyContextErrorV1> for RecoveryAdmissionErrorV1 {
    fn from(error: CeremonyContextErrorV1) -> Self {
        Self::Ceremony(error)
    }
}

impl From<ProvenanceEncodingErrorV1> for RecoveryAdmissionErrorV1 {
    fn from(error: ProvenanceEncodingErrorV1) -> Self {
        Self::Provenance(error)
    }
}

impl From<RegisteredStateProvenanceErrorV1> for RecoveryAdmissionErrorV1 {
    fn from(_: RegisteredStateProvenanceErrorV1) -> Self {
        Self::ProvenanceRequestKindMismatch
    }
}

impl From<SemanticArtifactErrorV1> for RecoveryAdmissionErrorV1 {
    fn from(error: SemanticArtifactErrorV1) -> Self {
        Self::Semantic(error)
    }
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RecoveryAdmissionErrorV1> {
    let length = u32::try_from(value.len()).map_err(|_| RecoveryAdmissionErrorV1::ValueTooLong)?;
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

    use super::*;
    use crate::ceremony_fixtures::canonical_recovery_ceremony_fixture_v1;
    use crate::lifecycle_domain::{ActivationReceiptEvidenceV1, RecoveryRequestV1};
    use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
    use crate::semantic_artifacts::{
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    };
    use crate::semantic_fixture_material::{
        activation_bindings, recovery_ideal_coins, recovery_inputs, reference_fixture,
    };
    use crate::semantic_lifecycle_fixtures::authenticated_state_from_provenance;
    use crate::{
        HostOnlyRecoveryReferenceInputsV1, RegisteredEd25519PublicKey32V1,
        StableKeyDerivationContext, SyntheticClientDerivationRootV1,
    };

    fn fixture(
    ) -> (
        RecoveryRequestV1,
        RoleInputProvenancePairV1,
        AuthenticatedRegisteredStoreResolutionV1,
    ) {
        let material = reference_fixture();
        let (context, authorization, transcript) = canonical_recovery_ceremony_fixture_v1();
        let request = RecoveryRequestV1::new(context, authorization, transcript).expect("request");
        let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
            CeremonyRequestKindV1::Recovery,
            material.registered_public_key,
        );
        let state = authenticated_state_from_provenance(
            request.request_context(),
            request.validated_dag(),
            &provenance,
            provenance
                .recovery_registered_state_binding()
                .expect("recovery binding"),
            9,
            11,
        );
        (request, provenance, state)
    }

    fn checked_at(request: &RecoveryRequestV1) -> RecoveryAdmissionCheckedAtUnixMsV1 {
        RecoveryAdmissionCheckedAtUnixMsV1::new(
            request.request_context().request_expiry().value(),
        )
        .expect("checked at")
    }

    fn evidence(byte: u8) -> OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1 {
        OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1::new([byte; 32])
            .expect("acceptance evidence")
    }

    fn receipt_evidence() -> ActivationReceiptEvidenceV1 {
        ActivationReceiptEvidenceV1::new(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xa3; 32])
                .expect("A receipt"),
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xa4; 32])
                .expect("B receipt"),
        )
    }

    fn accepted(
        request: &RecoveryRequestV1,
        provenance: &RoleInputProvenancePairV1,
        state: AuthenticatedRegisteredStoreResolutionV1,
        execution: OneUseExecutionId32V1,
    ) -> AcceptedRecoveryAdmissionV1 {
        accept_host_only_recovery_admission_v1(
            request,
            provenance,
            state,
            CeremonyActivationEpochV1::new(10).expect("next epoch"),
            execution,
            checked_at(request),
            evidence(0xa2),
        )
        .expect("accepted recovery")
    }

    #[test]
    fn accepted_admission_is_the_only_evaluation_evidence_and_survives_commitment() {
        let material = reference_fixture();
        let (request, provenance, state) = fixture();
        let execution = OneUseExecutionId32V1::new([0xb1; 32]).expect("execution");
        let admission = accepted(&request, &provenance, state, execution);
        let expected_digest = *admission.terminal().admission_digest();
        let session = request
            .begin_host_reference_artifact_session(admission, &provenance)
            .expect("session");
        let pending = session
            .evaluate_and_commit_host_reference(
                recovery_inputs(&material),
                recovery_ideal_coins(3, 5),
                activation_bindings(),
                receipt_evidence(),
            )
            .expect("committed recovery");
        assert_eq!(pending.terminal().admission_digest(), &expected_digest);
        assert_eq!(
            pending
                .artifacts()
                .receipt()
                .evaluation_evidence_digest()
                .as_bytes(),
            &expected_digest
        );
        assert_eq!(
            pending.credential_continuity().registered_public_key(),
            material.registered_public_key
        );
    }

    #[test]
    fn expired_request_rejects_and_returns_the_authenticated_state() {
        let (request, provenance, state) = fixture();
        let expired = RecoveryAdmissionCheckedAtUnixMsV1::new(
            request.request_context().request_expiry().value() + 1,
        )
        .expect("expired checked at");
        let rejection = match accept_host_only_recovery_admission_v1(
            &request,
            &provenance,
            state,
            CeremonyActivationEpochV1::new(10).expect("next epoch"),
            OneUseExecutionId32V1::new([0xb2; 32]).expect("execution"),
            expired,
            evidence(0xa2),
        ) {
            Err(rejection) => rejection,
            Ok(_) => panic!("expired request accepted"),
        };
        assert_eq!(rejection.reason(), RecoveryAdmissionErrorV1::RequestExpired);
        assert_eq!(rejection.into_state().active_state_version().value(), 11);
    }

    #[test]
    fn zero_time_and_selected_mechanism_evidence_are_rejected() {
        assert_eq!(
            RecoveryAdmissionCheckedAtUnixMsV1::new(0),
            Err(RecoveryAdmissionErrorV1::ZeroCheckedAt)
        );
        assert_eq!(
            OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1::new([0; 32]),
            Err(RecoveryAdmissionErrorV1::ZeroContinuityAcceptanceEvidence)
        );
    }

    #[test]
    fn stale_activation_epoch_rejects_before_suspension() {
        let (request, provenance, state) = fixture();
        let rejection = match accept_host_only_recovery_admission_v1(
            &request,
            &provenance,
            state,
            CeremonyActivationEpochV1::new(9).expect("stale epoch"),
            OneUseExecutionId32V1::new([0xb3; 32]).expect("execution"),
            checked_at(&request),
            evidence(0xa2),
        ) {
            Err(rejection) => rejection,
            Ok(_) => panic!("stale epoch accepted"),
        };
        assert_eq!(
            rejection.reason(),
            RecoveryAdmissionErrorV1::ActivationEpochDidNotAdvance
        );
        assert_eq!(
            rejection
                .into_state()
                .state()
                .active_activation_epoch()
                .value(),
            9
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
        );
        let alternate_key = RegisteredEd25519PublicKey32V1::parse(
            (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        )
        .expect("alternate key");
        let alternate_provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
            CeremonyRequestKindV1::Recovery,
            alternate_key,
        );
        assert_eq!(
            admission.validate_for(&request, &alternate_provenance),
            Err(RecoveryAdmissionErrorV1::AuthenticatedStoreRejected)
        );
    }

    #[test]
    fn selected_mechanism_evidence_changes_the_admission_identity() {
        let (request_one, provenance_one, state_one) = fixture();
        let execution = OneUseExecutionId32V1::new([0xb5; 32]).expect("execution");
        let first = accept_host_only_recovery_admission_v1(
            &request_one,
            &provenance_one,
            state_one,
            CeremonyActivationEpochV1::new(10).expect("next epoch"),
            execution,
            checked_at(&request_one),
            evidence(0xa2),
        )
        .expect("first admission");
        let (request_two, provenance_two, state_two) = fixture();
        let second = accept_host_only_recovery_admission_v1(
            &request_two,
            &provenance_two,
            state_two,
            CeremonyActivationEpochV1::new(10).expect("next epoch"),
            execution,
            checked_at(&request_two),
            evidence(0xa3),
        )
        .expect("second admission");
        assert_ne!(
            first.terminal().admission_digest(),
            second.terminal().admission_digest()
        );
    }

    #[test]
    fn stable_scope_mismatch_aborts_and_retains_the_terminal_admission() {
        let material = reference_fixture();
        let (request, provenance, state) = fixture();
        let execution = OneUseExecutionId32V1::new([0xb6; 32]).expect("execution");
        let admission = accepted(&request, &provenance, state, execution);
        let expected_digest = *admission.terminal().admission_digest();
        let session = request
            .begin_host_reference_artifact_session(admission, &provenance)
            .expect("session");
        let alternate_context =
            StableKeyDerivationContext::new([0xff; 32], 1, 2).expect("alternate context");
        let inputs = HostOnlyRecoveryReferenceInputsV1::new(
            &material.client_root,
            &material.client_root,
            &alternate_context,
            &material.deriver_a,
            &material.deriver_b,
        );
        let failure = match session.evaluate_and_commit_host_reference(
                inputs,
                recovery_ideal_coins(3, 5),
                activation_bindings(),
                receipt_evidence(),
            ) {
            Err(failure) => failure,
            Ok(_) => panic!("alternate stable scope accepted"),
        };
        assert_eq!(
            failure.source(),
            SemanticArtifactErrorV1::RecoveryStableScopeMismatch
        );
        let retained = failure.into_retained();
        assert_eq!(retained.terminal().admission_digest(), &expected_digest);
        assert_eq!(retained.burned().one_use_execution_id(), execution);
    }

    #[test]
    fn arithmetic_failure_burns_execution_and_retains_terminal_suspension() {
        let material = reference_fixture();
        let (request, provenance, state) = fixture();
        let execution = OneUseExecutionId32V1::new([0xb7; 32]).expect("execution");
        let admission = accepted(&request, &provenance, state, execution);
        let expected_version = admission
            .terminal()
            .suspension()
            .active_state_version();
        let session = request
            .begin_host_reference_artifact_session(admission, &provenance)
            .expect("session");
        let wrong_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0xff; 32]);
        let inputs = HostOnlyRecoveryReferenceInputsV1::new(
            &material.client_root,
            &wrong_root,
            &material.context,
            &material.deriver_a,
            &material.deriver_b,
        );
        let failure = match session.evaluate_and_commit_host_reference(
                inputs,
                recovery_ideal_coins(3, 5),
                activation_bindings(),
                receipt_evidence(),
            ) {
            Err(failure) => failure,
            Ok(_) => panic!("wrong recovered root accepted"),
        };
        let retained = failure.into_retained();
        assert_eq!(retained.burned().one_use_execution_id(), execution);
        assert_eq!(
            retained.terminal().suspension().active_state_version(),
            expected_version
        );
    }
}
