//! Canonical public synthetic registration evaluator-admission fixture material.

use core::fmt;

use serde::Serialize;

use crate::ceremony_context::{CeremonyActivationEpochV1, CeremonyRequestKindV1};
use crate::ceremony_fixtures::canonical_registration_ceremony_fixture_v1;
use crate::lifecycle_domain::{
    ActivationReceiptEvidenceV1, RegistrationArtifactIssuanceV1, RegistrationRequestV1,
};
use crate::provenance::ProvenanceRoleStateBindingV1;
use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
use crate::registration_evaluation_admission::{
    accept_host_only_registration_admission_v1, OpaqueRegistrationInputSelectionEvidenceDigest32V1,
    RegistrationAdmissionCheckedAtUnixMsV1, RegistrationSelectionAttemptId32V1,
};
use crate::semantic_artifacts::{
    OneUseExecutionId32V1, OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
};
use crate::semantic_fixture_material::{
    activation_bindings, reference_fixture, registration_ideal_coins, registration_inputs,
};

/// Schema identifier for the registration evaluator-admission corpus.
pub const REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:registration-evaluator-admission-vectors:v1";
/// Scope separating ideal host evidence from production protocol claims.
pub const REGISTRATION_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_construction_independent_registration_evaluator_admission_v1";

const CHECKED_AT_UNIX_MS_V1: u64 = 1;
const ACTIVATION_EPOCH_V1: u64 = 7;
const EXECUTION_ID_V1: [u8; 32] = [0x79; 32];
const SELECTION_ATTEMPT_ID_V1: [u8; 32] = [0x90; 32];
const SELECTED_MECHANISM_EVIDENCE_V1: [u8; 32] = [0x91; 32];

#[derive(Serialize)]
/// Strict one-case construction-independent registration evaluator corpus.
pub struct RegistrationEvaluatorAdmissionVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<RegistrationEvaluatorAdmissionVectorCaseV1>,
}

impl RegistrationEvaluatorAdmissionVectorCorpusV1 {
    /// Returns the exact corpus schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the fixed protocol identifier.
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Returns the narrow host-only evidence scope.
    pub fn evidence_scope(&self) -> &str {
        &self.evidence_scope
    }

    /// Returns the exact case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
struct RegistrationEvaluatorAdmissionVectorCaseV1 {
    case_id: String,
    request_kind: RegistrationRequestKindVectorV1,
    source_references: RegistrationEvaluatorSourceReferencesV1,
    admission: RegistrationAdmissionVectorV1,
    evaluation: RegistrationEvaluationOutcomeVectorV1,
    retry: RegistrationRetryVectorV1,
    claim_boundary: RegistrationClaimBoundaryVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RegistrationRequestKindVectorV1 {
    Registration,
}

#[derive(Serialize)]
struct RegistrationEvaluatorSourceReferencesV1 {
    ceremony_context_case_id: String,
    provenance_case_id: String,
    evaluation_input_party_view_case_id: String,
    semantic_lifecycle_case_id: String,
    output_party_view_case_id: String,
    activation_delivery_case_id: String,
    activation_recipient_party_view_case_id: String,
    evaluator_abort_corpus_schema: String,
    evaluator_abort_request_kind: String,
}

#[derive(Serialize)]
struct RegistrationAdmissionVectorV1 {
    relation: String,
    unregistered_public_identity_scope_encoding_hex: String,
    request_id: String,
    replay_nonce_hex: String,
    request_expiry_unix_ms: u64,
    checked_at_unix_ms: u64,
    request_context_digest_hex: String,
    authorization_record_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    registration_intent_digest_hex: String,
    provenance_pair_digest_hex: String,
    deriver_a_statement_digest_hex: String,
    deriver_b_statement_digest_hex: String,
    stable_scope_encoding_hex: String,
    provenance_input_selection_artifact_digest_hex: String,
    selected_mechanism_acceptance_evidence_digest_hex: String,
    client_envelope_set_digest_hex: String,
    deriver_a_initial_state: RegistrationRoleStateVectorV1,
    deriver_b_initial_state: RegistrationRoleStateVectorV1,
    activation_epoch: u64,
    one_use_execution_id_hex: String,
    selection_attempt_id_hex: String,
    selection_state: String,
    encoding_hex: String,
    digest_hex: String,
}

#[derive(Serialize)]
struct RegistrationRoleStateVectorV1 {
    role: String,
    role_root_record_digest_hex: String,
    root_binding_artifact_digest_hex: String,
    role_root_epoch: u64,
    input_state_record_digest_hex: String,
    input_state_epoch: u64,
}

#[derive(Serialize)]
struct RegistrationEvaluationOutcomeVectorV1 {
    evaluation_plan: String,
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    output_share_samples: u8,
    registered_public_key_hex: String,
    package_set_digest_hex: String,
    output_committed_receipt_encoding_hex: String,
    output_committed_receipt_digest_hex: String,
    output_committed_evaluation_evidence_digest_hex: String,
    candidate_encoding_hex: String,
    candidate_digest_hex: String,
    candidate_output_committed_receipt_digest_hex: String,
    pending_state: String,
    terminal_selection_retained: bool,
}

#[derive(Serialize)]
struct RegistrationRetryVectorV1 {
    accepted_selection_is_terminal: bool,
    evaluator_abort_preserves_public_state: String,
    evaluator_abort_retains_terminal_selection: bool,
    retry_requires_fresh_execution: bool,
    retry_may_resample_selection: bool,
}

#[derive(Serialize)]
struct RegistrationClaimBoundaryVectorV1 {
    unregistered_scope_claim: String,
    provenance_input_selection_artifact_semantics: String,
    selected_mechanism_acceptance_evidence_semantics: String,
    excluded_claims: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Failure returned for noncanonical registration evaluator corpus bytes.
pub struct RegistrationEvaluatorAdmissionVectorCorpusParseErrorV1;

impl fmt::Display for RegistrationEvaluatorAdmissionVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "registration evaluator-admission corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for RegistrationEvaluatorAdmissionVectorCorpusParseErrorV1 {}

/// Builds the canonical one-case registration evaluator-admission corpus.
pub fn canonical_registration_evaluator_admission_vector_corpus_v1(
) -> RegistrationEvaluatorAdmissionVectorCorpusV1 {
    RegistrationEvaluatorAdmissionVectorCorpusV1 {
        schema: REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: REGISTRATION_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![registration_evaluator_admission_case()],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(&canonical_registration_evaluator_admission_vector_corpus_v1())
            .expect("fixed registration evaluator-admission corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_registration_evaluator_admission_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<
    RegistrationEvaluatorAdmissionVectorCorpusV1,
    RegistrationEvaluatorAdmissionVectorCorpusParseErrorV1,
> {
    if encoded != canonical_registration_evaluator_admission_vector_corpus_json_bytes_v1() {
        return Err(RegistrationEvaluatorAdmissionVectorCorpusParseErrorV1);
    }
    Ok(canonical_registration_evaluator_admission_vector_corpus_v1())
}

fn registration_evaluator_admission_case() -> RegistrationEvaluatorAdmissionVectorCaseV1 {
    let material = reference_fixture();
    let (context, authorization, transcript) = canonical_registration_ceremony_fixture_v1();
    let request = RegistrationRequestV1::new(context, authorization, transcript)
        .expect("canonical registration request");
    let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Registration,
        material.registered_public_key,
    );
    let activation_epoch =
        CeremonyActivationEpochV1::new(ACTIVATION_EPOCH_V1).expect("activation epoch");
    let execution_id = OneUseExecutionId32V1::new(EXECUTION_ID_V1).expect("execution id");
    let checked_at =
        RegistrationAdmissionCheckedAtUnixMsV1::new(CHECKED_AT_UNIX_MS_V1).expect("checked at");
    let selection_attempt = RegistrationSelectionAttemptId32V1::new(SELECTION_ATTEMPT_ID_V1)
        .expect("selection attempt");
    let selected_mechanism_evidence =
        OpaqueRegistrationInputSelectionEvidenceDigest32V1::new(SELECTED_MECHANISM_EVIDENCE_V1)
            .expect("selected mechanism evidence");
    let admission = accept_host_only_registration_admission_v1(
        &request,
        &provenance,
        activation_epoch,
        execution_id,
        checked_at,
        selection_attempt,
        selected_mechanism_evidence,
    )
    .expect("canonical registration admission");
    let admission_encoding = admission.encode().to_vec();
    let admission_digest = *admission.terminal_selection().admission_digest();
    let binding = admission.provenance_binding();
    let admission_vector = RegistrationAdmissionVectorV1 {
        relation: "construction_independent_ideal_acceptance".to_owned(),
        unregistered_public_identity_scope_encoding_hex: encode_hex(
            &admission
                .unregistered_public_identity_scope()
                .encode()
                .expect("identity scope encoding"),
        ),
        request_id: request.request_context().request_id().as_str().to_owned(),
        replay_nonce_hex: encode_hex(request.request_context().replay_nonce().as_bytes()),
        request_expiry_unix_ms: request.request_context().request_expiry().value(),
        checked_at_unix_ms: checked_at.value(),
        request_context_digest_hex: encode_hex(
            request.validated_dag().request_context_digest().as_bytes(),
        ),
        authorization_record_digest_hex: encode_hex(
            request
                .authorization()
                .authorization_record_digest()
                .as_bytes(),
        ),
        authorization_digest_hex: encode_hex(
            request.validated_dag().authorization_digest().as_bytes(),
        ),
        transcript_digest_hex: encode_hex(request.validated_dag().transcript_digest().as_bytes()),
        registration_intent_digest_hex: encode_hex(
            request
                .authorization()
                .registration_intent_digest()
                .as_bytes(),
        ),
        provenance_pair_digest_hex: encode_hex(
            provenance.digest().expect("provenance digest").as_bytes(),
        ),
        deriver_a_statement_digest_hex: encode_hex(
            provenance
                .deriver_a()
                .digest()
                .expect("A statement digest")
                .as_bytes(),
        ),
        deriver_b_statement_digest_hex: encode_hex(
            provenance
                .deriver_b()
                .digest()
                .expect("B statement digest")
                .as_bytes(),
        ),
        stable_scope_encoding_hex: encode_hex(
            &binding
                .stable_scope()
                .encode()
                .expect("stable scope encoding"),
        ),
        provenance_input_selection_artifact_digest_hex: encode_hex(
            binding.input_selection_evidence_digest().as_bytes(),
        ),
        selected_mechanism_acceptance_evidence_digest_hex: encode_hex(
            selected_mechanism_evidence.as_bytes(),
        ),
        client_envelope_set_digest_hex: encode_hex(binding.client_envelope_set_digest().as_bytes()),
        deriver_a_initial_state: role_state_vector("deriver_a", binding.deriver_a()),
        deriver_b_initial_state: role_state_vector("deriver_b", binding.deriver_b()),
        activation_epoch: activation_epoch.value(),
        one_use_execution_id_hex: encode_hex(execution_id.as_bytes()),
        selection_attempt_id_hex: encode_hex(selection_attempt.as_bytes()),
        selection_state: "accepted_terminal".to_owned(),
        encoding_hex: encode_hex(&admission_encoding),
        digest_hex: encode_hex(&admission_digest),
    };
    let session = request
        .begin_host_reference_artifact_session(
            RegistrationArtifactIssuanceV1::new(activation_epoch, execution_id, admission),
            &provenance,
        )
        .expect("accepted registration evaluator session");
    let pending = session
        .evaluate_and_commit_host_reference(
            registration_inputs(&material),
            registration_ideal_coins(3, 5),
            activation_bindings(),
            ActivationReceiptEvidenceV1::new(
                OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0x94; 32])
                    .expect("A output receipt"),
                OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0x95; 32])
                    .expect("B output receipt"),
            ),
        )
        .expect("registration output commitment");
    let receipt = pending.artifacts().receipt();
    let candidate = pending.candidate();
    assert_eq!(
        receipt.evaluation_evidence_digest().as_bytes(),
        &admission_digest
    );
    assert_eq!(
        candidate.output_committed_receipt_digest(),
        receipt.digest().as_bytes()
    );
    RegistrationEvaluatorAdmissionVectorCaseV1 {
        case_id: "registration_admitted_evaluation_output_committed_v1".to_owned(),
        request_kind: RegistrationRequestKindVectorV1::Registration,
        source_references: RegistrationEvaluatorSourceReferencesV1 {
            ceremony_context_case_id: "ceremony-registration-v1".to_owned(),
            provenance_case_id: "registration_provenance_outer_v1".to_owned(),
            evaluation_input_party_view_case_id: "registration_evaluation_input_party_views_v1"
                .to_owned(),
            semantic_lifecycle_case_id: "registration_semantic_artifacts_output_committed_v1"
                .to_owned(),
            output_party_view_case_id: "registration_output_party_views_package_prepared_v1"
                .to_owned(),
            activation_delivery_case_id: "registration_activation_delivery_v1".to_owned(),
            activation_recipient_party_view_case_id:
                "registration_activation_recipient_party_views_v1".to_owned(),
            evaluator_abort_corpus_schema:
                "seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1".to_owned(),
            evaluator_abort_request_kind: "registration".to_owned(),
        },
        admission: admission_vector,
        evaluation: RegistrationEvaluationOutcomeVectorV1 {
            evaluation_plan: "one_registration_evaluation".to_owned(),
            yao_evaluations: 1,
            deriver_a_invocations: 1,
            deriver_b_invocations: 1,
            contribution_derivations: 0,
            output_share_samples: 2,
            registered_public_key_hex: encode_hex(candidate.registered_public_key().as_bytes()),
            package_set_digest_hex: encode_hex(receipt.package_set_digest().as_bytes()),
            output_committed_receipt_encoding_hex: encode_hex(&receipt.encode()),
            output_committed_receipt_digest_hex: encode_hex(receipt.digest().as_bytes()),
            output_committed_evaluation_evidence_digest_hex: encode_hex(
                receipt.evaluation_evidence_digest().as_bytes(),
            ),
            candidate_encoding_hex: encode_hex(candidate.encode()),
            candidate_digest_hex: encode_hex(candidate.digest().as_bytes()),
            candidate_output_committed_receipt_digest_hex: encode_hex(
                candidate.output_committed_receipt_digest(),
            ),
            pending_state: "registration_pending_activation".to_owned(),
            terminal_selection_retained: true,
        },
        retry: RegistrationRetryVectorV1 {
            accepted_selection_is_terminal: true,
            evaluator_abort_preserves_public_state: "unregistered".to_owned(),
            evaluator_abort_retains_terminal_selection: true,
            retry_requires_fresh_execution: true,
            retry_may_resample_selection: false,
        },
        claim_boundary: RegistrationClaimBoundaryVectorV1 {
            unregistered_scope_claim: "public_identity_scope_only".to_owned(),
            provenance_input_selection_artifact_semantics:
                "opaque_artifact_committed_by_both_provenance_statements".to_owned(),
            selected_mechanism_acceptance_evidence_semantics:
                "opaque_acceptance_slot_instantiated_by_phase_6b".to_owned(),
            excluded_claims: vec![
                "authenticated_absence".to_owned(),
                "durable_uniqueness".to_owned(),
                "retry_coordination".to_owned(),
                "profile_security".to_owned(),
                "signature_unforgeability".to_owned(),
                "input_opening_consistency".to_owned(),
                "production_randomness".to_owned(),
                "transport_security".to_owned(),
                "production_constant_time".to_owned(),
            ],
        },
    }
}

fn role_state_vector<Role: crate::provenance::ProvenanceRoleV1>(
    role: &str,
    state: ProvenanceRoleStateBindingV1<Role>,
) -> RegistrationRoleStateVectorV1 {
    RegistrationRoleStateVectorV1 {
        role: role.to_owned(),
        role_root_record_digest_hex: encode_hex(state.role_root_record_digest().as_bytes()),
        root_binding_artifact_digest_hex: encode_hex(
            state.root_binding_artifact_digest().as_bytes(),
        ),
        role_root_epoch: state.role_root_epoch().value(),
        input_state_record_digest_hex: encode_hex(state.record_digest().as_bytes()),
        input_state_epoch: state.epoch().value(),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
