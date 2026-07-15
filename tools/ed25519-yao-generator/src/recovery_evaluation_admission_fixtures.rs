//! Canonical public synthetic recovery evaluator-admission fixture material.

use core::fmt;

use serde::Serialize;

use crate::ceremony_context::{CeremonyActivationEpochV1, CeremonyRequestKindV1};
use crate::ceremony_fixtures::canonical_recovery_ceremony_fixture_v1;
use crate::lifecycle_domain::{ActivationReceiptEvidenceV1, RecoveryRequestV1};
use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
use crate::recovery_evaluation_admission::{
    accept_host_only_recovery_admission_v1, OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1,
    RecoveryAdmissionCheckedAtUnixMsV1,
};
use crate::semantic_artifacts::{
    OneUseExecutionId32V1, OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
};
use crate::semantic_fixture_material::{
    activation_bindings, recovery_ideal_coins, recovery_inputs, reference_fixture,
};
use crate::semantic_lifecycle_fixtures::authenticated_state_from_provenance;

/// Schema identifier for the recovery evaluator-admission corpus.
pub const RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:recovery-evaluator-admission-vectors:v1";
/// Scope separating ideal host evidence from production protocol claims.
pub const RECOVERY_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_construction_independent_recovery_evaluator_admission_v1";

const CHECKED_AT_UNIX_MS_V1: u64 = 1;
const CURRENT_ACTIVATION_EPOCH_V1: u64 = 9;
const NEXT_ACTIVATION_EPOCH_V1: u64 = 10;
const ACTIVE_STATE_VERSION_V1: u64 = 9;
const EXECUTION_ID_V1: [u8; 32] = [0x73; 32];
const SELECTED_MECHANISM_EVIDENCE_V1: [u8; 32] = [0x92; 32];

#[derive(Serialize)]
/// Strict one-case construction-independent recovery evaluator corpus.
pub struct RecoveryEvaluatorAdmissionVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<RecoveryEvaluatorAdmissionVectorCaseV1>,
}

impl RecoveryEvaluatorAdmissionVectorCorpusV1 {
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
struct RecoveryEvaluatorAdmissionVectorCaseV1 {
    case_id: String,
    request_kind: RecoveryRequestKindVectorV1,
    source_references: RecoveryEvaluatorSourceReferencesV1,
    authenticated_store_resolution: RecoveryStoreResolutionVectorV1,
    admission: RecoveryAdmissionVectorV1,
    evaluation: RecoveryEvaluationOutcomeVectorV1,
    retry: RecoveryRetryVectorV1,
    claim_boundary: RecoveryClaimBoundaryVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryRequestKindVectorV1 {
    Recovery,
}

#[derive(Serialize)]
struct RecoveryEvaluatorSourceReferencesV1 {
    ceremony_context_case_id: String,
    provenance_case_id: String,
    evaluation_input_party_view_case_id: String,
    semantic_lifecycle_case_id: String,
    output_party_view_case_id: String,
    activation_delivery_case_id: String,
    activation_recipient_party_view_case_id: String,
    recovery_credential_transition_case_id: String,
    evaluator_abort_corpus_schema: String,
    evaluator_abort_request_kind: String,
}

#[derive(Serialize)]
struct RecoveryStoreResolutionVectorV1 {
    signing_bytes_hex: String,
    signing_bytes_sha256_hex: String,
    authority_key_epoch: u64,
    authority_verifying_key_hex: String,
    authority_key_digest_hex: String,
    authority_signature_hex: String,
    active_state_version: u64,
    registered_public_key_hex: String,
    active_credential_binding_digest_hex: String,
    stable_scope_encoding_hex: String,
    active_activation_epoch: u64,
    deriver_a_root_record_digest_hex: String,
    deriver_a_root_binding_artifact_digest_hex: String,
    deriver_a_root_epoch: u64,
    deriver_a_input_state_record_digest_hex: String,
    deriver_a_input_state_epoch: u64,
    deriver_b_root_record_digest_hex: String,
    deriver_b_root_binding_artifact_digest_hex: String,
    deriver_b_root_epoch: u64,
    deriver_b_input_state_record_digest_hex: String,
    deriver_b_input_state_epoch: u64,
}

#[derive(Serialize)]
struct RecoveryAdmissionVectorV1 {
    relation: String,
    durable_identity_scope_encoding_hex: String,
    request_id: String,
    replay_nonce_hex: String,
    request_expiry_unix_ms: u64,
    checked_at_unix_ms: u64,
    request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    provenance_pair_digest_hex: String,
    deriver_a_statement_digest_hex: String,
    deriver_b_statement_digest_hex: String,
    active_credential_binding_digest_hex: String,
    replacement_credential_binding_digest_hex: String,
    registered_public_key_hex: String,
    stable_scope_encoding_hex: String,
    provenance_same_root_artifact_digest_hex: String,
    selected_mechanism_acceptance_evidence_digest_hex: String,
    current_activation_epoch: u64,
    next_activation_epoch: u64,
    one_use_execution_id_hex: String,
    admission_state: String,
    encoding_hex: String,
    digest_hex: String,
}

#[derive(Serialize)]
struct RecoveryEvaluationOutcomeVectorV1 {
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
    pending_state: String,
    old_credential_state: String,
    terminal_admission_retained: bool,
}

#[derive(Serialize)]
struct RecoveryRetryVectorV1 {
    evaluator_abort_preserves_public_state: String,
    evaluator_abort_retains_terminal_admission: bool,
    evaluator_abort_retains_credential_suspension: bool,
    evaluator_abort_burns_execution: bool,
    retry_requires_fresh_authorization: bool,
    retry_requires_fresh_execution: bool,
}

#[derive(Serialize)]
struct RecoveryClaimBoundaryVectorV1 {
    provenance_same_root_artifact_semantics: String,
    selected_mechanism_acceptance_evidence_semantics: String,
    excluded_claims: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Failure returned for noncanonical recovery evaluator corpus bytes.
pub struct RecoveryEvaluatorAdmissionVectorCorpusParseErrorV1;

impl fmt::Display for RecoveryEvaluatorAdmissionVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "recovery evaluator-admission corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for RecoveryEvaluatorAdmissionVectorCorpusParseErrorV1 {}

/// Builds the canonical one-case recovery evaluator-admission corpus.
pub fn canonical_recovery_evaluator_admission_vector_corpus_v1(
) -> RecoveryEvaluatorAdmissionVectorCorpusV1 {
    RecoveryEvaluatorAdmissionVectorCorpusV1 {
        schema: RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: RECOVERY_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![recovery_evaluator_admission_case()],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(&canonical_recovery_evaluator_admission_vector_corpus_v1())
            .expect("fixed recovery evaluator-admission corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_recovery_evaluator_admission_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<
    RecoveryEvaluatorAdmissionVectorCorpusV1,
    RecoveryEvaluatorAdmissionVectorCorpusParseErrorV1,
> {
    if encoded != canonical_recovery_evaluator_admission_vector_corpus_json_bytes_v1() {
        return Err(RecoveryEvaluatorAdmissionVectorCorpusParseErrorV1);
    }
    Ok(canonical_recovery_evaluator_admission_vector_corpus_v1())
}

fn recovery_evaluator_admission_case() -> RecoveryEvaluatorAdmissionVectorCaseV1 {
    let material = reference_fixture();
    let (context, authorization, transcript) = canonical_recovery_ceremony_fixture_v1();
    let request =
        RecoveryRequestV1::new(context, authorization, transcript).expect("recovery request");
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
            .expect("recovery state binding"),
        CURRENT_ACTIVATION_EPOCH_V1,
        ACTIVE_STATE_VERSION_V1,
    );
    let state_projection = state.state();
    let authority = state.trusted_transition_authority();
    let store_signing_bytes = state
        .signed_resolution_bytes()
        .expect("store signing bytes");
    let store_digest = state.signed_resolution_digest().expect("store digest");
    let store_vector = RecoveryStoreResolutionVectorV1 {
        signing_bytes_hex: encode_hex(&store_signing_bytes),
        signing_bytes_sha256_hex: encode_hex(&store_digest),
        authority_key_epoch: authority.key_epoch().value(),
        authority_verifying_key_hex: encode_hex(&authority.verifying_key_bytes()),
        authority_key_digest_hex: encode_hex(&authority.key_digest()),
        authority_signature_hex: encode_hex(state.authority_signature().as_bytes()),
        active_state_version: state.active_state_version().value(),
        registered_public_key_hex: encode_hex(state_projection.registered_public_key.as_bytes()),
        active_credential_binding_digest_hex: encode_hex(
            state_projection.active_credential_binding_digest.as_bytes(),
        ),
        stable_scope_encoding_hex: encode_hex(
            &state_projection
                .stable_scope
                .encode()
                .expect("stable scope encoding"),
        ),
        active_activation_epoch: state_projection.active_activation_epoch.value(),
        deriver_a_root_record_digest_hex: encode_hex(
            state_projection.deriver_a_root_record.as_bytes(),
        ),
        deriver_a_root_binding_artifact_digest_hex: encode_hex(
            state_projection.deriver_a_root_binding.as_bytes(),
        ),
        deriver_a_root_epoch: state_projection.deriver_a_root_epoch.value(),
        deriver_a_input_state_record_digest_hex: encode_hex(
            state_projection.deriver_a_state_record.as_bytes(),
        ),
        deriver_a_input_state_epoch: state_projection.deriver_a_input_state_epoch.value(),
        deriver_b_root_record_digest_hex: encode_hex(
            state_projection.deriver_b_root_record.as_bytes(),
        ),
        deriver_b_root_binding_artifact_digest_hex: encode_hex(
            state_projection.deriver_b_root_binding.as_bytes(),
        ),
        deriver_b_root_epoch: state_projection.deriver_b_root_epoch.value(),
        deriver_b_input_state_record_digest_hex: encode_hex(
            state_projection.deriver_b_state_record.as_bytes(),
        ),
        deriver_b_input_state_epoch: state_projection.deriver_b_input_state_epoch.value(),
    };
    let next_epoch = CeremonyActivationEpochV1::new(NEXT_ACTIVATION_EPOCH_V1).expect("next epoch");
    let execution = OneUseExecutionId32V1::new(EXECUTION_ID_V1).expect("execution");
    let checked_at =
        RecoveryAdmissionCheckedAtUnixMsV1::new(CHECKED_AT_UNIX_MS_V1).expect("checked at");
    let selected_evidence =
        OpaqueRecoveryContinuityAcceptanceEvidenceDigest32V1::new(SELECTED_MECHANISM_EVIDENCE_V1)
            .expect("selected mechanism evidence");
    let admission = accept_host_only_recovery_admission_v1(
        &request,
        &provenance,
        state,
        next_epoch,
        execution,
        checked_at,
        selected_evidence,
    )
    .expect("accepted recovery admission");
    let continuity = admission.terminal().credential_continuity();
    let admission_digest = *admission.terminal().admission_digest();
    let admission_vector = RecoveryAdmissionVectorV1 {
        relation: "construction_independent_ideal_acceptance".to_owned(),
        durable_identity_scope_encoding_hex: encode_hex(
            &request
                .request_context()
                .durable_store_identity_scope()
                .encode()
                .expect("durable identity encoding"),
        ),
        request_id: request.request_context().request_id().as_str().to_owned(),
        replay_nonce_hex: encode_hex(request.request_context().replay_nonce().as_bytes()),
        request_expiry_unix_ms: request.request_context().request_expiry().value(),
        checked_at_unix_ms: checked_at.value(),
        request_context_digest_hex: encode_hex(
            request.validated_dag().request_context_digest().as_bytes(),
        ),
        authorization_digest_hex: encode_hex(
            request.validated_dag().authorization_digest().as_bytes(),
        ),
        transcript_digest_hex: encode_hex(request.validated_dag().transcript_digest().as_bytes()),
        provenance_pair_digest_hex: encode_hex(
            provenance.digest().expect("pair digest").as_bytes(),
        ),
        deriver_a_statement_digest_hex: encode_hex(
            provenance
                .deriver_a()
                .digest()
                .expect("A digest")
                .as_bytes(),
        ),
        deriver_b_statement_digest_hex: encode_hex(
            provenance
                .deriver_b()
                .digest()
                .expect("B digest")
                .as_bytes(),
        ),
        active_credential_binding_digest_hex: encode_hex(
            continuity.active_credential_binding_digest().as_bytes(),
        ),
        replacement_credential_binding_digest_hex: encode_hex(
            continuity
                .replacement_credential_binding_digest()
                .as_bytes(),
        ),
        registered_public_key_hex: encode_hex(continuity.registered_public_key().as_bytes()),
        stable_scope_encoding_hex: encode_hex(
            &continuity
                .stable_scope()
                .encode()
                .expect("stable scope encoding"),
        ),
        provenance_same_root_artifact_digest_hex: encode_hex(
            continuity.same_root_evidence_artifact_digest().as_bytes(),
        ),
        selected_mechanism_acceptance_evidence_digest_hex: encode_hex(selected_evidence.as_bytes()),
        current_activation_epoch: CURRENT_ACTIVATION_EPOCH_V1,
        next_activation_epoch: next_epoch.value(),
        one_use_execution_id_hex: encode_hex(execution.as_bytes()),
        admission_state: "accepted_terminal_credential_suspended".to_owned(),
        encoding_hex: encode_hex(admission.terminal().encode()),
        digest_hex: encode_hex(&admission_digest),
    };
    let session = request
        .begin_host_reference_artifact_session(admission, &provenance)
        .expect("recovery session");
    let pending = session
        .evaluate_and_commit_host_reference(
            recovery_inputs(&material),
            recovery_ideal_coins(3, 5),
            activation_bindings(),
            ActivationReceiptEvidenceV1::new(
                OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0x94; 32])
                    .expect("A receipt"),
                OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0x95; 32])
                    .expect("B receipt"),
            ),
        )
        .expect("committed recovery");
    let receipt = pending.artifacts().receipt();
    assert_eq!(
        receipt.evaluation_evidence_digest().as_bytes(),
        &admission_digest
    );
    RecoveryEvaluatorAdmissionVectorCaseV1 {
        case_id: "recovery_admitted_evaluation_output_committed_v1".to_owned(),
        request_kind: RecoveryRequestKindVectorV1::Recovery,
        source_references: RecoveryEvaluatorSourceReferencesV1 {
            ceremony_context_case_id: "ceremony-recovery-v1".to_owned(),
            provenance_case_id: "recovery_provenance_outer_v1".to_owned(),
            evaluation_input_party_view_case_id: "recovery_evaluation_input_party_views_v1"
                .to_owned(),
            semantic_lifecycle_case_id: "recovery_semantic_artifacts_output_committed_v1"
                .to_owned(),
            output_party_view_case_id: "recovery_output_party_views_package_prepared_v1".to_owned(),
            activation_delivery_case_id: "recovery_activation_delivery_v1".to_owned(),
            activation_recipient_party_view_case_id: "recovery_activation_recipient_party_views_v1"
                .to_owned(),
            recovery_credential_transition_case_id: "recovery_credential_suspension_promotion_v1"
                .to_owned(),
            evaluator_abort_corpus_schema:
                "seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1".to_owned(),
            evaluator_abort_request_kind: "recovery".to_owned(),
        },
        authenticated_store_resolution: store_vector,
        admission: admission_vector,
        evaluation: RecoveryEvaluationOutcomeVectorV1 {
            evaluation_plan: "one_recovery_activation_evaluation".to_owned(),
            yao_evaluations: 1,
            deriver_a_invocations: 1,
            deriver_b_invocations: 1,
            contribution_derivations: 4,
            output_share_samples: 2,
            registered_public_key_hex: encode_hex(receipt.registered_public_key().as_bytes()),
            package_set_digest_hex: encode_hex(receipt.package_set_digest().as_bytes()),
            output_committed_receipt_encoding_hex: encode_hex(&receipt.encode()),
            output_committed_receipt_digest_hex: encode_hex(receipt.digest().as_bytes()),
            output_committed_evaluation_evidence_digest_hex: encode_hex(
                receipt.evaluation_evidence_digest().as_bytes(),
            ),
            pending_state: "recovery_pending_activation".to_owned(),
            old_credential_state: "suspended".to_owned(),
            terminal_admission_retained: true,
        },
        retry: RecoveryRetryVectorV1 {
            evaluator_abort_preserves_public_state: "credential_suspended".to_owned(),
            evaluator_abort_retains_terminal_admission: true,
            evaluator_abort_retains_credential_suspension: true,
            evaluator_abort_burns_execution: true,
            retry_requires_fresh_authorization: true,
            retry_requires_fresh_execution: true,
        },
        claim_boundary: RecoveryClaimBoundaryVectorV1 {
            provenance_same_root_artifact_semantics:
                "opaque_artifact_committed_by_both_provenance_statements".to_owned(),
            selected_mechanism_acceptance_evidence_semantics:
                "opaque_acceptance_slot_instantiated_by_phase_6b".to_owned(),
            excluded_claims: vec![
                "same_root_proof_validity".to_owned(),
                "input_opening_consistency".to_owned(),
                "durable_suspension".to_owned(),
                "global_replay_prevention".to_owned(),
                "durable_one_use_uniqueness".to_owned(),
                "atomic_promotion".to_owned(),
                "rollback_floor".to_owned(),
                "crash_recovery".to_owned(),
                "profile_security".to_owned(),
                "transport_security".to_owned(),
                "production_constant_time".to_owned(),
            ],
        },
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
