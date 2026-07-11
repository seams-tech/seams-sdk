//! Construction-independent registration admission for the host evaluator.
//!
//! This module models an already accepted ideal relation. Profile-specific
//! input selection, durable uniqueness, and production records are deferred.

use core::{fmt, num::NonZeroU64};

use sha2::{Digest, Sha256};

use crate::ceremony_context::{
    CeremonyActivationEpochV1, CeremonyContextErrorV1, CeremonyDurableStoreIdentityScopeV1,
    CeremonyRequestKindV1,
};
use crate::lifecycle_domain::RegistrationRequestV1;
use crate::provenance::{
    ProvenanceEncodingErrorV1, RegisteredStateProvenanceErrorV1, RegistrationProvenanceBindingV1,
    RoleInputProvenancePairV1,
};
use crate::registered_key::RegisteredEd25519PublicKey32V1;
use crate::semantic_artifacts::{
    CommittedActivationArtifactsV1, OneUseExecutionId32V1,
    OpaqueHostReferenceEvaluationEvidenceDigest32V1, SemanticArtifactErrorV1,
};

/// Canonical registration-admission encoding domain.
pub const REGISTRATION_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/registration-evaluator-admission/v1";
/// Domain separating the accepted admission digest.
pub const REGISTRATION_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/registration-evaluator-admission-digest/v1";
/// Canonical registration-candidate encoding domain.
pub const REGISTRATION_CANDIDATE_STATE_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/registration-candidate-state/v1";
/// Domain separating the registration-candidate digest.
pub const REGISTRATION_CANDIDATE_STATE_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/registration-candidate-state-digest/v1";

const ACCEPTED_SELECTION_TAG_V1: u8 = 0x01;

/// Nonzero identity of one fixed registration input-selection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegistrationSelectionAttemptId32V1([u8; 32]);

impl RegistrationSelectionAttemptId32V1 {
    /// Validates a nonzero attempt identity.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, RegistrationAdmissionErrorV1> {
        if is_zero_32(&bytes) {
            return Err(RegistrationAdmissionErrorV1::ZeroSelectionAttemptId);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact attempt identity.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque evidence for the Phase 6A-selected input-selection relation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueRegistrationInputSelectionEvidenceDigest32V1([u8; 32]);

impl OpaqueRegistrationInputSelectionEvidenceDigest32V1 {
    /// Records a nonzero evidence slot without verifying its production meaning.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, RegistrationAdmissionErrorV1> {
        if is_zero_32(&bytes) {
            return Err(RegistrationAdmissionErrorV1::ZeroInputSelectionEvidence);
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque selected-mechanism evidence digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nonzero Unix timestamp used by the ideal admission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegistrationAdmissionCheckedAtUnixMsV1(NonZeroU64);

impl RegistrationAdmissionCheckedAtUnixMsV1 {
    /// Validates a nonzero admission timestamp.
    pub const fn new(value: u64) -> Result<Self, RegistrationAdmissionErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(RegistrationAdmissionErrorV1::ZeroCheckedAt),
        }
    }

    /// Returns the Unix timestamp.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for OpaqueRegistrationInputSelectionEvidenceDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueRegistrationInputSelectionEvidenceDigest32V1([opaque digest])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistrationAdmissionCommonV1 {
    durable_identity: CeremonyDurableStoreIdentityScopeV1,
    request_id: String,
    replay_nonce: [u8; 32],
    request_expiry: u64,
    checked_at: RegistrationAdmissionCheckedAtUnixMsV1,
    request_context_digest: [u8; 32],
    authorization_digest: [u8; 32],
    transcript_digest: [u8; 32],
    registration_intent_digest: [u8; 32],
    provenance_pair_digest: [u8; 32],
    deriver_a_statement_digest: [u8; 32],
    deriver_b_statement_digest: [u8; 32],
    binding: RegistrationProvenanceBindingV1,
    activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
}

impl RegistrationAdmissionCommonV1 {
    fn validate(
        request: &RegistrationRequestV1,
        provenance: &RoleInputProvenancePairV1,
        activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
        checked_at: RegistrationAdmissionCheckedAtUnixMsV1,
    ) -> Result<Self, RegistrationAdmissionErrorV1> {
        if request.request_kind() != CeremonyRequestKindV1::Registration {
            return Err(RegistrationAdmissionErrorV1::RequestKindMismatch);
        }
        let dag = request.validated_dag();
        if provenance.ceremony_request_context_digest().as_bytes()
            != dag.request_context_digest().as_bytes()
            || provenance.ceremony_authorization_digest().as_bytes()
                != dag.authorization_digest().as_bytes()
            || provenance.ceremony_transcript_digest().as_bytes()
                != dag.transcript_digest().as_bytes()
        {
            return Err(RegistrationAdmissionErrorV1::CeremonyBindingMismatch);
        }
        let binding = provenance.registration_binding()?;
        if request
            .authorization()
            .registration_intent_digest()
            .as_bytes()
            != binding.registration_intent_digest().as_bytes()
        {
            return Err(RegistrationAdmissionErrorV1::RegistrationIntentMismatch);
        }
        let context = request.request_context();
        if checked_at.value() > context.request_expiry().value() {
            return Err(RegistrationAdmissionErrorV1::RequestExpired);
        }
        Ok(Self {
            durable_identity: context.durable_store_identity_scope(),
            request_id: context.request_id().as_str().to_owned(),
            replay_nonce: *context.replay_nonce().as_bytes(),
            request_expiry: context.request_expiry().value(),
            checked_at,
            request_context_digest: *dag.request_context_digest().as_bytes(),
            authorization_digest: *dag.authorization_digest().as_bytes(),
            transcript_digest: *dag.transcript_digest().as_bytes(),
            registration_intent_digest: *binding.registration_intent_digest().as_bytes(),
            provenance_pair_digest: *provenance.digest()?.as_bytes(),
            deriver_a_statement_digest: *provenance.deriver_a().digest()?.as_bytes(),
            deriver_b_statement_digest: *provenance.deriver_b().digest()?.as_bytes(),
            binding,
            activation_epoch,
            one_use_execution_id,
        })
    }

    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RegistrationAdmissionErrorV1> {
        push_lp32(output, &self.durable_identity.encode()?)?;
        push_lp32(output, self.request_id.as_bytes())?;
        push_lp32(output, &self.replay_nonce)?;
        push_lp32(output, &self.request_expiry.to_be_bytes())?;
        push_lp32(output, &self.checked_at.value().to_be_bytes())?;
        push_lp32(output, &self.request_context_digest)?;
        push_lp32(output, &self.authorization_digest)?;
        push_lp32(output, &self.transcript_digest)?;
        push_lp32(output, &self.registration_intent_digest)?;
        push_lp32(output, &self.provenance_pair_digest)?;
        push_lp32(output, &self.deriver_a_statement_digest)?;
        push_lp32(output, &self.deriver_b_statement_digest)?;
        push_lp32(output, &self.binding.stable_scope().encode()?)?;
        push_lp32(
            output,
            self.binding.input_selection_evidence_digest().as_bytes(),
        )?;
        push_lp32(output, self.binding.client_envelope_set_digest().as_bytes())?;
        encode_role_state(output, self.binding.deriver_a())?;
        encode_role_state(output, self.binding.deriver_b())?;
        push_lp32(output, &self.activation_epoch.value().to_be_bytes())?;
        push_lp32(output, self.one_use_execution_id.as_bytes())?;
        Ok(())
    }
}

/// Terminal accepted input-selection state retained after admission.
pub struct TerminalRegistrationSelectionV1 {
    common: RegistrationAdmissionCommonV1,
    attempt_id: RegistrationSelectionAttemptId32V1,
    selected_mechanism_evidence_digest: OpaqueRegistrationInputSelectionEvidenceDigest32V1,
    admission_digest: [u8; 32],
}

impl TerminalRegistrationSelectionV1 {
    /// Returns the fixed selection-attempt identity.
    pub const fn attempt_id(&self) -> RegistrationSelectionAttemptId32V1 {
        self.attempt_id
    }

    /// Returns the opaque selected-mechanism evidence slot.
    pub const fn selected_mechanism_evidence_digest(
        &self,
    ) -> OpaqueRegistrationInputSelectionEvidenceDigest32V1 {
        self.selected_mechanism_evidence_digest
    }

    /// Returns the admission digest that transitively binds semantic artifacts.
    pub const fn admission_digest(&self) -> &[u8; 32] {
        &self.admission_digest
    }

    /// Returns the unregistered public identity scope accepted at admission.
    pub const fn unregistered_public_identity_scope(&self) -> &CeremonyDurableStoreIdentityScopeV1 {
        &self.common.durable_identity
    }

    /// Returns the registration intent shared by ceremony and provenance.
    pub const fn registration_intent_digest(&self) -> &[u8; 32] {
        &self.common.registration_intent_digest
    }

    /// Returns the frozen registration provenance binding.
    pub const fn provenance_binding(&self) -> RegistrationProvenanceBindingV1 {
        self.common.binding
    }

    /// Returns the first activation epoch fixed at admission.
    pub const fn activation_epoch(&self) -> CeremonyActivationEpochV1 {
        self.common.activation_epoch
    }

    /// Returns the one-use evaluator execution fixed at admission.
    pub const fn one_use_execution_id(&self) -> OneUseExecutionId32V1 {
        self.common.one_use_execution_id
    }

    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RegistrationAdmissionErrorV1> {
        self.common.encode_into(output)?;
        push_lp32(output, self.attempt_id.as_bytes())?;
        push_lp32(output, self.selected_mechanism_evidence_digest.as_bytes())?;
        push_lp32(output, &self.admission_digest)?;
        Ok(())
    }

    pub(crate) fn matches_committed_output(
        &self,
        artifacts: &CommittedActivationArtifactsV1,
    ) -> bool {
        let binding = artifacts.binding();
        let receipt = artifacts.receipt();
        binding.origin_request_kind() == CeremonyRequestKindV1::Registration
            && binding.origin_request_context_digest().as_bytes()
                == &self.common.request_context_digest
            && binding.origin_authorization_digest().as_bytes() == &self.common.authorization_digest
            && binding.origin_transcript_digest().as_bytes() == &self.common.transcript_digest
            && binding.activation_epoch() == self.common.activation_epoch
            && binding.one_use_execution_id() == self.common.one_use_execution_id
            && receipt.evaluation_evidence_digest().as_bytes() == &self.admission_digest
    }
}

impl fmt::Debug for TerminalRegistrationSelectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalRegistrationSelectionV1")
            .field("attempt_id", &self.attempt_id)
            .field("admission_digest", &"[computed SHA-256]")
            .finish()
    }
}

/// Move-only construction-independent registration evaluator admission.
///
/// ```compile_fail
/// use ed25519_yao_generator::AcceptedRegistrationAdmissionV1;
///
/// fn cannot_admit_twice(admission: AcceptedRegistrationAdmissionV1) {
///     drop(admission);
///     drop(admission);
/// }
/// ```
pub struct AcceptedRegistrationAdmissionV1 {
    terminal_selection: TerminalRegistrationSelectionV1,
    encoding: Vec<u8>,
    evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
}

impl AcceptedRegistrationAdmissionV1 {
    /// Returns the exact canonical admission bytes.
    pub fn encode(&self) -> &[u8] {
        &self.encoding
    }

    /// Returns the accepted selection retained by this admission.
    pub const fn terminal_selection(&self) -> &TerminalRegistrationSelectionV1 {
        &self.terminal_selection
    }

    /// Returns the frozen registration provenance binding.
    pub const fn provenance_binding(&self) -> RegistrationProvenanceBindingV1 {
        self.terminal_selection.common.binding
    }

    /// Returns the exact unregistered durable identity scope.
    pub const fn unregistered_public_identity_scope(&self) -> &CeremonyDurableStoreIdentityScopeV1 {
        &self.terminal_selection.common.durable_identity
    }

    pub(crate) fn validate_for(
        &self,
        request: &RegistrationRequestV1,
        provenance: &RoleInputProvenancePairV1,
        activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
    ) -> Result<(), RegistrationAdmissionErrorV1> {
        let expected = RegistrationAdmissionCommonV1::validate(
            request,
            provenance,
            activation_epoch,
            one_use_execution_id,
            self.terminal_selection.common.checked_at,
        )?;
        if self.terminal_selection.common != expected {
            return Err(RegistrationAdmissionErrorV1::AdmissionBindingMismatch);
        }
        Ok(())
    }

    pub(crate) const fn evaluation_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceEvaluationEvidenceDigest32V1 {
        self.evaluation_evidence_digest
    }

    pub(crate) fn into_terminal_selection(self) -> TerminalRegistrationSelectionV1 {
        self.terminal_selection
    }
}

/// Accepts the construction-independent ideal registration admission relation.
///
/// The opaque evidence is interpreted only by the Phase 6B-selected mechanism.
pub fn accept_host_only_registration_admission_v1(
    request: &RegistrationRequestV1,
    provenance: &RoleInputProvenancePairV1,
    activation_epoch: CeremonyActivationEpochV1,
    one_use_execution_id: OneUseExecutionId32V1,
    checked_at: RegistrationAdmissionCheckedAtUnixMsV1,
    selection_attempt_id: RegistrationSelectionAttemptId32V1,
    selected_mechanism_evidence_digest: OpaqueRegistrationInputSelectionEvidenceDigest32V1,
) -> Result<AcceptedRegistrationAdmissionV1, RegistrationAdmissionErrorV1> {
    let common = RegistrationAdmissionCommonV1::validate(
        request,
        provenance,
        activation_epoch,
        one_use_execution_id,
        checked_at,
    )?;
    let mut encoding = Vec::new();
    push_lp32(
        &mut encoding,
        REGISTRATION_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1,
    )?;
    common.encode_into(&mut encoding)?;
    push_lp32(&mut encoding, selection_attempt_id.as_bytes())?;
    push_lp32(&mut encoding, selected_mechanism_evidence_digest.as_bytes())?;
    push_lp32(&mut encoding, &[ACCEPTED_SELECTION_TAG_V1])?;
    let mut digest_input = Vec::new();
    push_lp32(
        &mut digest_input,
        REGISTRATION_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1,
    )?;
    push_lp32(&mut digest_input, &encoding)?;
    let admission_digest: [u8; 32] = Sha256::digest(digest_input).into();
    let evaluation_evidence_digest =
        OpaqueHostReferenceEvaluationEvidenceDigest32V1::new(admission_digest)?;
    Ok(AcceptedRegistrationAdmissionV1 {
        terminal_selection: TerminalRegistrationSelectionV1 {
            common,
            attempt_id: selection_attempt_id,
            selected_mechanism_evidence_digest,
            admission_digest,
        },
        encoding,
        evaluation_evidence_digest,
    })
}

/// Domain-separated digest of one committed registration candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegistrationCandidateStateDigest32V1([u8; 32]);

impl RegistrationCandidateStateDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Move-owned candidate registered identity awaiting activation.
pub struct RegistrationCandidateStateV1 {
    terminal_selection: TerminalRegistrationSelectionV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    output_committed_receipt_digest: [u8; 32],
    encoding: Vec<u8>,
    digest: RegistrationCandidateStateDigest32V1,
}

impl RegistrationCandidateStateV1 {
    pub(crate) fn from_validated_committed_output(
        terminal_selection: TerminalRegistrationSelectionV1,
        artifacts: &CommittedActivationArtifactsV1,
    ) -> Self {
        let receipt = artifacts.receipt();
        let registered_public_key = receipt.registered_public_key();
        let output_committed_receipt_digest = *receipt.digest().as_bytes();
        let mut encoding = Vec::new();
        push_lp32(
            &mut encoding,
            REGISTRATION_CANDIDATE_STATE_ENCODING_DOMAIN_V1,
        )
        .expect("static registration-candidate domain fits LP32");
        terminal_selection
            .encode_into(&mut encoding)
            .expect("accepted registration admission already has valid LP32 fields");
        push_lp32(&mut encoding, registered_public_key.as_bytes())
            .expect("fixed registered public key fits LP32");
        push_lp32(&mut encoding, &output_committed_receipt_digest)
            .expect("fixed receipt digest fits LP32");
        let mut digest_input = Vec::new();
        push_lp32(
            &mut digest_input,
            REGISTRATION_CANDIDATE_STATE_DIGEST_DOMAIN_V1,
        )
        .expect("static registration-candidate digest domain fits LP32");
        push_lp32(&mut digest_input, &encoding).expect("candidate encoding fits LP32");
        let digest = RegistrationCandidateStateDigest32V1(Sha256::digest(digest_input).into());
        Self {
            terminal_selection,
            registered_public_key,
            output_committed_receipt_digest,
            encoding,
            digest,
        }
    }

    /// Returns the exact canonical candidate bytes.
    pub fn encode(&self) -> &[u8] {
        &self.encoding
    }

    /// Returns the candidate-state digest.
    pub const fn digest(&self) -> RegistrationCandidateStateDigest32V1 {
        self.digest
    }

    /// Returns the accepted selection retained by this candidate.
    pub const fn terminal_selection(&self) -> &TerminalRegistrationSelectionV1 {
        &self.terminal_selection
    }

    /// Returns the registered public key established by the committed output.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the receipt digest that fixed this candidate.
    pub const fn output_committed_receipt_digest(&self) -> &[u8; 32] {
        &self.output_committed_receipt_digest
    }
}

impl fmt::Debug for RegistrationCandidateStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationCandidateStateV1")
            .field("terminal_selection", &self.terminal_selection)
            .field("registered_public_key", &self.registered_public_key)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Failure while constructing or consuming registration admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationAdmissionErrorV1 {
    /// Selection attempt identities must be nonzero.
    ZeroSelectionAttemptId,
    /// Admission timestamps must be nonzero.
    ZeroCheckedAt,
    /// Selected-mechanism evidence digests must be nonzero.
    ZeroInputSelectionEvidence,
    /// The supplied request was not registration.
    RequestKindMismatch,
    /// The request was expired when admission was accepted.
    RequestExpired,
    /// Ceremony and provenance digests did not describe one request.
    CeremonyBindingMismatch,
    /// Authorization and provenance named different registration intents.
    RegistrationIntentMismatch,
    /// The admission was replayed against different bound inputs.
    AdmissionBindingMismatch,
    /// Provenance belonged to another lifecycle branch.
    ProvenanceRequestKindMismatch,
    /// Canonical ceremony encoding failed.
    Ceremony(CeremonyContextErrorV1),
    /// Canonical provenance encoding failed.
    Provenance(ProvenanceEncodingErrorV1),
    /// Semantic evidence digest construction failed.
    Semantic(SemanticArtifactErrorV1),
    /// One LP32 field exceeded the version-one length bound.
    ValueTooLong,
}

impl fmt::Display for RegistrationAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSelectionAttemptId => {
                formatter.write_str("registration selection attempt id must be nonzero")
            }
            Self::ZeroCheckedAt => formatter.write_str("registration checked-at must be nonzero"),
            Self::ZeroInputSelectionEvidence => {
                formatter.write_str("registration input-selection evidence must be nonzero")
            }
            Self::RequestKindMismatch => {
                formatter.write_str("registration admission requires a registration request")
            }
            Self::RequestExpired => formatter.write_str("registration request expired"),
            Self::CeremonyBindingMismatch => {
                formatter.write_str("registration admission ceremony binding mismatch")
            }
            Self::RegistrationIntentMismatch => {
                formatter.write_str("registration authorization/provenance intent mismatch")
            }
            Self::AdmissionBindingMismatch => {
                formatter.write_str("registration admission binding mismatch")
            }
            Self::ProvenanceRequestKindMismatch => {
                formatter.write_str("registration admission requires registration provenance")
            }
            Self::Ceremony(error) => error.fmt(formatter),
            Self::Provenance(error) => error.fmt(formatter),
            Self::Semantic(error) => error.fmt(formatter),
            Self::ValueTooLong => formatter.write_str("registration admission LP32 overflow"),
        }
    }
}

impl std::error::Error for RegistrationAdmissionErrorV1 {}

impl From<CeremonyContextErrorV1> for RegistrationAdmissionErrorV1 {
    fn from(error: CeremonyContextErrorV1) -> Self {
        Self::Ceremony(error)
    }
}

impl From<ProvenanceEncodingErrorV1> for RegistrationAdmissionErrorV1 {
    fn from(error: ProvenanceEncodingErrorV1) -> Self {
        Self::Provenance(error)
    }
}

impl From<RegisteredStateProvenanceErrorV1> for RegistrationAdmissionErrorV1 {
    fn from(_: RegisteredStateProvenanceErrorV1) -> Self {
        Self::ProvenanceRequestKindMismatch
    }
}

impl From<SemanticArtifactErrorV1> for RegistrationAdmissionErrorV1 {
    fn from(error: SemanticArtifactErrorV1) -> Self {
        Self::Semantic(error)
    }
}

fn encode_role_state<Role: crate::provenance::ProvenanceRoleV1>(
    output: &mut Vec<u8>,
    state: crate::provenance::ProvenanceRoleStateBindingV1<Role>,
) -> Result<(), RegistrationAdmissionErrorV1> {
    push_lp32(output, state.role_root_record_digest().as_bytes())?;
    push_lp32(output, state.root_binding_artifact_digest().as_bytes())?;
    push_lp32(output, &state.role_root_epoch().value().to_be_bytes())?;
    push_lp32(output, state.record_digest().as_bytes())?;
    push_lp32(output, &state.epoch().value().to_be_bytes())?;
    Ok(())
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RegistrationAdmissionErrorV1> {
    let length =
        u32::try_from(value.len()).map_err(|_| RegistrationAdmissionErrorV1::ValueTooLong)?;
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
    use super::*;
    use crate::ceremony_context::{
        CeremonyArtifactSuiteDigest32V1, CeremonyAuthorizationRecordDigest32V1,
        CeremonyRegistrationAuthorizationV1, CeremonyRegistrationIntentDigest32V1,
        CeremonyTranscriptNonce32V1, CeremonyTranscriptV1, CeremonyTransportBindingDigest32V1,
    };
    use crate::lifecycle_domain::{ActivationReceiptEvidenceV1, RegistrationArtifactIssuanceV1};
    use crate::semantic_artifacts::{
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    };
    use crate::semantic_artifacts_tests::{provenance_pair, registration_ceremony};
    use crate::semantic_fixture_material::{
        activation_bindings, reference_fixture, registration_ideal_coins, registration_inputs,
    };
    use crate::{HostOnlyRegistrationReferenceInputsV1, StableKeyDerivationContext};

    fn accepted(
        request: &RegistrationRequestV1,
        provenance: &RoleInputProvenancePairV1,
        activation_epoch: CeremonyActivationEpochV1,
        execution_id: OneUseExecutionId32V1,
    ) -> AcceptedRegistrationAdmissionV1 {
        accept_host_only_registration_admission_v1(
            request,
            provenance,
            activation_epoch,
            execution_id,
            RegistrationAdmissionCheckedAtUnixMsV1::new(
                request.request_context().request_expiry().value(),
            )
            .expect("checked at"),
            RegistrationSelectionAttemptId32V1::new([0xa1; 32]).expect("attempt"),
            OpaqueRegistrationInputSelectionEvidenceDigest32V1::new([0xa2; 32])
                .expect("selection evidence"),
        )
        .expect("accepted registration admission")
    }

    fn receipt_evidence() -> ActivationReceiptEvidenceV1 {
        ActivationReceiptEvidenceV1::new(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xa3; 32])
                .expect("A receipt"),
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xa4; 32])
                .expect("B receipt"),
        )
    }

    #[test]
    fn accepted_admission_is_required_and_retained_through_commitment() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = registration_ceremony("admission-success");
        let request = RegistrationRequestV1::new(context, authorization, transcript)
            .expect("registration request");
        let provenance = provenance_pair(request.validated_dag(), None);
        let activation_epoch = CeremonyActivationEpochV1::new(7).expect("activation epoch");
        let execution_id = OneUseExecutionId32V1::new([0xb1; 32]).expect("execution id");
        let admission = accepted(&request, &provenance, activation_epoch, execution_id);
        let expected_digest = *admission.terminal_selection().admission_digest();
        let session = request
            .begin_host_reference_artifact_session(
                RegistrationArtifactIssuanceV1::new(activation_epoch, execution_id, admission),
                &provenance,
            )
            .expect("registration session");
        let pending = session
            .evaluate_and_commit_host_reference(
                registration_inputs(&fixture),
                registration_ideal_coins(3, 5),
                activation_bindings(),
                receipt_evidence(),
            )
            .expect("registration commitment");
        assert_eq!(
            pending.terminal_selection().admission_digest(),
            &expected_digest
        );
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
    fn request_authorization_transcript_and_scope_splices_are_rejected() {
        let (context, authorization, transcript) = registration_ceremony("admission-one");
        let request =
            RegistrationRequestV1::new(context, authorization, transcript).expect("request one");
        let provenance = provenance_pair(request.validated_dag(), None);
        let epoch = CeremonyActivationEpochV1::new(7).expect("epoch");
        let execution = OneUseExecutionId32V1::new([0xb2; 32]).expect("execution");
        let admission = accepted(&request, &provenance, epoch, execution);

        let (other_context, other_authorization, other_transcript) =
            registration_ceremony("admission-two");
        let other_request =
            RegistrationRequestV1::new(other_context, other_authorization, other_transcript)
                .expect("request two");
        let other_provenance = provenance_pair(other_request.validated_dag(), None);
        assert_eq!(
            admission.validate_for(&other_request, &other_provenance, epoch, execution),
            Err(RegistrationAdmissionErrorV1::AdmissionBindingMismatch)
        );
    }

    #[test]
    fn intent_provenance_and_input_selection_splices_are_rejected() {
        let (context, _, _) = registration_ceremony("intent-splice");
        let authorization = CeremonyRegistrationAuthorizationV1::new(
            &context,
            CeremonyAuthorizationRecordDigest32V1::new([0x61; 32]).expect("authorization record"),
            CeremonyRegistrationIntentDigest32V1::new([0x63; 32]).expect("alternate intent"),
        )
        .expect("registration authorization");
        let transcript = CeremonyTranscriptV1::new(
            &context,
            &authorization.into(),
            CeremonyTranscriptNonce32V1::new([0x31; 32]),
            CeremonyTransportBindingDigest32V1::new([0x41; 32]).expect("transport binding"),
            CeremonyArtifactSuiteDigest32V1::new([0x51; 32]).expect("artifact suite"),
        )
        .expect("transcript");
        let request =
            RegistrationRequestV1::new(context, authorization, transcript).expect("request");
        let provenance = provenance_pair(request.validated_dag(), None);
        assert!(matches!(
            accept_host_only_registration_admission_v1(
                &request,
                &provenance,
                CeremonyActivationEpochV1::new(7).expect("epoch"),
                OneUseExecutionId32V1::new([0xb3; 32]).expect("execution"),
                RegistrationAdmissionCheckedAtUnixMsV1::new(
                    request.request_context().request_expiry().value(),
                )
                .expect("checked at"),
                RegistrationSelectionAttemptId32V1::new([0xb4; 32]).expect("attempt"),
                OpaqueRegistrationInputSelectionEvidenceDigest32V1::new([0xb5; 32])
                    .expect("evidence"),
            ),
            Err(RegistrationAdmissionErrorV1::RegistrationIntentMismatch)
        ));
    }

    #[test]
    fn activation_epoch_and_execution_splices_are_rejected() {
        let (context, authorization, transcript) = registration_ceremony("epoch-splice");
        let request =
            RegistrationRequestV1::new(context, authorization, transcript).expect("request");
        let provenance = provenance_pair(request.validated_dag(), None);
        let epoch = CeremonyActivationEpochV1::new(7).expect("epoch");
        let execution = OneUseExecutionId32V1::new([0xb6; 32]).expect("execution");
        let admission = accepted(&request, &provenance, epoch, execution);
        assert_eq!(
            admission.validate_for(
                &request,
                &provenance,
                CeremonyActivationEpochV1::new(8).expect("other epoch"),
                execution,
            ),
            Err(RegistrationAdmissionErrorV1::AdmissionBindingMismatch)
        );
        assert_eq!(
            admission.validate_for(
                &request,
                &provenance,
                epoch,
                OneUseExecutionId32V1::new([0xb7; 32]).expect("other execution"),
            ),
            Err(RegistrationAdmissionErrorV1::AdmissionBindingMismatch)
        );
    }

    #[test]
    fn selection_identifiers_and_evidence_reject_zero() {
        assert_eq!(
            RegistrationAdmissionCheckedAtUnixMsV1::new(0),
            Err(RegistrationAdmissionErrorV1::ZeroCheckedAt)
        );
        assert_eq!(
            RegistrationSelectionAttemptId32V1::new([0; 32]),
            Err(RegistrationAdmissionErrorV1::ZeroSelectionAttemptId)
        );
        assert_eq!(
            OpaqueRegistrationInputSelectionEvidenceDigest32V1::new([0; 32]),
            Err(RegistrationAdmissionErrorV1::ZeroInputSelectionEvidence)
        );
    }

    #[test]
    fn expired_registration_request_is_rejected() {
        let (context, authorization, transcript) = registration_ceremony("expired-admission");
        let request =
            RegistrationRequestV1::new(context, authorization, transcript).expect("request");
        let provenance = provenance_pair(request.validated_dag(), None);
        let expired_at = request
            .request_context()
            .request_expiry()
            .value()
            .checked_add(1)
            .expect("fixture expiry has headroom");
        assert!(matches!(
            accept_host_only_registration_admission_v1(
                &request,
                &provenance,
                CeremonyActivationEpochV1::new(7).expect("epoch"),
                OneUseExecutionId32V1::new([0xc1; 32]).expect("execution"),
                RegistrationAdmissionCheckedAtUnixMsV1::new(expired_at).expect("checked at"),
                RegistrationSelectionAttemptId32V1::new([0xc2; 32]).expect("attempt"),
                OpaqueRegistrationInputSelectionEvidenceDigest32V1::new([0xc3; 32])
                    .expect("evidence"),
            ),
            Err(RegistrationAdmissionErrorV1::RequestExpired)
        ));
    }

    #[test]
    fn evaluation_failure_burns_attempt_and_retains_terminal_selection() {
        let fixture = reference_fixture();
        let (context, authorization, transcript) = registration_ceremony("admission-abort");
        let request =
            RegistrationRequestV1::new(context, authorization, transcript).expect("request");
        let provenance = provenance_pair(request.validated_dag(), None);
        let epoch = CeremonyActivationEpochV1::new(7).expect("epoch");
        let execution = OneUseExecutionId32V1::new([0xd1; 32]).expect("execution");
        let admission = accepted(&request, &provenance, epoch, execution);
        let expected_admission_digest = *admission.terminal_selection().admission_digest();
        let expected_request_digest = *request.validated_dag().request_context_digest().as_bytes();
        let session = request
            .begin_host_reference_artifact_session(
                RegistrationArtifactIssuanceV1::new(epoch, execution, admission),
                &provenance,
            )
            .expect("session");
        let mismatched_context =
            StableKeyDerivationContext::new([0xee; 32], 1, 2).expect("mismatched context");
        let mismatched_inputs = HostOnlyRegistrationReferenceInputsV1::new(
            &fixture.client_root,
            &fixture.deriver_a_root,
            &fixture.deriver_b_root,
            &mismatched_context,
        );
        let failure = match session.evaluate_and_commit_host_reference(
            mismatched_inputs,
            registration_ideal_coins(3, 5),
            activation_bindings(),
            receipt_evidence(),
        ) {
            Ok(_) => panic!("stable-scope splice must abort"),
            Err(failure) => failure,
        };
        assert_eq!(
            failure.source(),
            SemanticArtifactErrorV1::RegistrationStableScopeMismatch
        );
        let retained = failure.into_retained();
        assert_eq!(
            retained.burned().request_context_digest().as_bytes(),
            &expected_request_digest
        );
        assert_eq!(retained.burned().one_use_execution_id(), execution);
        assert_eq!(
            retained.terminal_selection().admission_digest(),
            &expected_admission_digest
        );
    }

    #[test]
    fn source_and_api_guards_exclude_profile_negotiation_signatures_and_export_values() {
        let source = include_str!("registration_evaluation_admission.rs");
        let forbidden = [
            ["ed25519", "_dalek"].concat(),
            ["Security", "ProfileV1"].concat(),
            ["Signing", "Key"].concat(),
            ["seed", "_output"].concat(),
            ["joined", "_seed"].concat(),
        ];
        for forbidden in forbidden {
            assert!(!source.contains(&forbidden), "forbidden token: {forbidden}");
        }
    }
}
