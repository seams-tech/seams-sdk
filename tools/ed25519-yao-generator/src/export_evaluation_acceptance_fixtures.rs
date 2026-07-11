//! Canonical public synthetic export-acceptance fixture material.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::authenticated_store::AuthenticatedRegisteredStoreResolutionV1;
use crate::ceremony_context::{CeremonyRequestKindV1, CeremonyValidatedDagV1};
use crate::ceremony_fixtures::canonical_export_ceremony_fixture_for_registered_key_v1;
use crate::export_delivery::HostOnlyExportClientReleaseEvidenceV1;
use crate::export_evaluation_acceptance::{
    prepare_deriver_a_export_authorization_acceptance_v1,
    prepare_deriver_b_export_authorization_acceptance_v1,
    DeriverAExportAuthorizationAcceptanceAuthorityV1,
    DeriverAExportAuthorizationAcceptanceSignature64V1,
    DeriverBExportAuthorizationAcceptanceAuthorityV1,
    DeriverBExportAuthorizationAcceptanceSignature64V1, ExportAuthorizationAcceptanceAuthoritiesV1,
    ExportAuthorizationCheckedAtUnixMsV1, VerifiedExportAuthorizationAcceptancePairV1,
};
use crate::lifecycle_domain::{
    ExportArtifactIssuanceV1, ExportOutputCommitmentEvidenceV1, ExportRequestV1,
};
use crate::provenance::RoleInputProvenancePairV1;
use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
use crate::semantic_artifacts::{
    OneUseExecutionId32V1, OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
    OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
};
use crate::semantic_fixture_material::{
    export_bindings, export_ideal_coin, export_inputs, reference_fixture,
};
use crate::semantic_lifecycle_fixtures::authenticated_state_from_provenance;

const DERIVER_A_ACCEPTANCE_SIGNING_SEED_V1: [u8; 32] = [0x6a; 32];
const DERIVER_B_ACCEPTANCE_SIGNING_SEED_V1: [u8; 32] = [0x6b; 32];

/// Schema identifier for the strict export evaluator-authorization corpus.
pub const EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:export-evaluator-authorization-vectors:v1";
/// Scope separating host authorization evidence from production protocol claims.
pub const EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_export_evaluator_authorization_v1";

#[derive(Serialize)]
/// Strict one-case authenticated export-evaluator corpus.
pub struct ExportEvaluatorAuthorizationVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<ExportEvaluatorAuthorizationVectorCaseV1>,
}

impl ExportEvaluatorAuthorizationVectorCorpusV1 {
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
struct ExportEvaluatorAuthorizationVectorCaseV1 {
    case_id: String,
    request_kind: ExportRequestKindVectorV1,
    source_references: ExportEvaluatorSourceReferencesV1,
    common: ExportEvaluatorCommonVectorV1,
    authorities: ExportEvaluatorAuthoritiesVectorV1,
    acceptances: ExportEvaluatorAcceptancesVectorV1,
    accepted_pair: ExportEvaluatorAcceptedPairVectorV1,
    evaluation: ExportEvaluatorOutcomeVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ExportRequestKindVectorV1 {
    Export,
}

#[derive(Serialize)]
struct ExportEvaluatorSourceReferencesV1 {
    ceremony_context_case_id: String,
    provenance_case_id: String,
    evaluation_input_party_view_case_id: String,
    semantic_lifecycle_case_id: String,
    export_delivery_case_id: String,
}

#[derive(Serialize)]
struct ExportEvaluatorCommonVectorV1 {
    request_id: String,
    replay_nonce_hex: String,
    request_expiry_unix_ms: u64,
    client_recipient_key_hex: String,
    request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    provenance_pair_digest_hex: String,
    signed_store_resolution_digest_hex: String,
    store_authority_key_epoch: u64,
    store_authority_key_digest_hex: String,
    active_state_version: u64,
    registered_public_key_hex: String,
    one_use_execution_id_hex: String,
}

#[derive(Serialize)]
struct ExportEvaluatorAuthoritiesVectorV1 {
    deriver_a: ExportEvaluatorAuthorityVectorV1,
    deriver_b: ExportEvaluatorAuthorityVectorV1,
}

#[derive(Serialize)]
struct ExportEvaluatorAuthorityVectorV1 {
    role: String,
    deriver_id: String,
    key_epoch: u64,
    verifying_key_hex: String,
    key_digest_hex: String,
}

#[derive(Serialize)]
struct ExportEvaluatorAcceptancesVectorV1 {
    deriver_a: ExportEvaluatorAcceptanceVectorV1,
    deriver_b: ExportEvaluatorAcceptanceVectorV1,
}

#[derive(Serialize)]
struct ExportEvaluatorAcceptanceVectorV1 {
    role: String,
    checked_at_unix_ms: u64,
    provenance_statement_digest_hex: String,
    signing_bytes_hex: String,
    signature_hex: String,
    signed_artifact_digest_hex: String,
}

#[derive(Serialize)]
struct ExportEvaluatorAcceptedPairVectorV1 {
    encoding_hex: String,
    digest_hex: String,
}

#[derive(Serialize)]
struct ExportEvaluatorOutcomeVectorV1 {
    evaluation_plan: String,
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    output_committed_authorization_state: String,
    output_committed_receipt_encoding_hex: String,
    output_committed_receipt_digest_hex: String,
    output_committed_evaluation_evidence_digest_hex: String,
    released_authorization_state: String,
    released_receipt_encoding_hex: String,
    released_receipt_digest_hex: String,
    released_evaluation_evidence_digest_hex: String,
    registered_state_retained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Failure returned for noncanonical export evaluator corpus bytes.
pub struct ExportEvaluatorAuthorizationVectorCorpusParseErrorV1;

impl fmt::Display for ExportEvaluatorAuthorizationVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("export evaluator-authorization corpus must equal the exact canonical LF-terminated JSON bytes")
    }
}

impl std::error::Error for ExportEvaluatorAuthorizationVectorCorpusParseErrorV1 {}

/// Builds the canonical one-case export evaluator-authorization corpus.
pub fn canonical_export_evaluator_authorization_vector_corpus_v1(
) -> ExportEvaluatorAuthorizationVectorCorpusV1 {
    ExportEvaluatorAuthorizationVectorCorpusV1 {
        schema: EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![export_evaluator_authorization_case()],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(&canonical_export_evaluator_authorization_vector_corpus_v1())
            .expect("fixed export evaluator-authorization corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_export_evaluator_authorization_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<
    ExportEvaluatorAuthorizationVectorCorpusV1,
    ExportEvaluatorAuthorizationVectorCorpusParseErrorV1,
> {
    if encoded != canonical_export_evaluator_authorization_vector_corpus_json_bytes_v1() {
        return Err(ExportEvaluatorAuthorizationVectorCorpusParseErrorV1);
    }
    Ok(canonical_export_evaluator_authorization_vector_corpus_v1())
}

pub(crate) fn canonical_export_acceptance_authorities_v1(
    request: &ExportRequestV1,
) -> ExportAuthorizationAcceptanceAuthoritiesV1 {
    let deriver_a_signing_key = SigningKey::from_bytes(&DERIVER_A_ACCEPTANCE_SIGNING_SEED_V1);
    let deriver_b_signing_key = SigningKey::from_bytes(&DERIVER_B_ACCEPTANCE_SIGNING_SEED_V1);
    ExportAuthorizationAcceptanceAuthoritiesV1::new(
        DeriverAExportAuthorizationAcceptanceAuthorityV1::parse(
            request.request_context().deriver_a_binding().key_epoch(),
            deriver_a_signing_key.verifying_key().to_bytes(),
        )
        .expect("canonical Deriver A export-acceptance authority"),
        DeriverBExportAuthorizationAcceptanceAuthorityV1::parse(
            request.request_context().deriver_b_binding().key_epoch(),
            deriver_b_signing_key.verifying_key().to_bytes(),
        )
        .expect("canonical Deriver B export-acceptance authority"),
    )
    .expect("canonical export-acceptance authorities are distinct")
}

pub(crate) fn canonical_verified_export_acceptance_pair_v1(
    request: &ExportRequestV1,
    state: &AuthenticatedRegisteredStoreResolutionV1,
    provenance: &RoleInputProvenancePairV1,
    one_use_execution_id: OneUseExecutionId32V1,
    authorities: ExportAuthorizationAcceptanceAuthoritiesV1,
) -> VerifiedExportAuthorizationAcceptancePairV1 {
    let checked_at =
        ExportAuthorizationCheckedAtUnixMsV1::new(1).expect("canonical export admission timestamp");
    let prepared_a = prepare_deriver_a_export_authorization_acceptance_v1(
        request,
        state,
        provenance,
        one_use_execution_id,
        checked_at,
        authorities.deriver_a(),
    )
    .expect("canonical Deriver A export acceptance");
    let prepared_b = prepare_deriver_b_export_authorization_acceptance_v1(
        request,
        state,
        provenance,
        one_use_execution_id,
        checked_at,
        authorities.deriver_b(),
    )
    .expect("canonical Deriver B export acceptance");
    let signing_key_a = SigningKey::from_bytes(&DERIVER_A_ACCEPTANCE_SIGNING_SEED_V1);
    let signing_key_b = SigningKey::from_bytes(&DERIVER_B_ACCEPTANCE_SIGNING_SEED_V1);
    let signature_a = DeriverAExportAuthorizationAcceptanceSignature64V1::from_bytes(
        signing_key_a
            .sign(&prepared_a.signing_bytes().expect("Deriver A signing bytes"))
            .to_bytes(),
    );
    let signature_b = DeriverBExportAuthorizationAcceptanceSignature64V1::from_bytes(
        signing_key_b
            .sign(&prepared_b.signing_bytes().expect("Deriver B signing bytes"))
            .to_bytes(),
    );
    VerifiedExportAuthorizationAcceptancePairV1::new(
        prepared_a
            .verify(signature_a)
            .expect("verified Deriver A acceptance"),
        prepared_b
            .verify(signature_b)
            .expect("verified Deriver B acceptance"),
    )
    .expect("coherent canonical export acceptance pair")
}

fn export_evaluator_authorization_case() -> ExportEvaluatorAuthorizationVectorCaseV1 {
    let material = reference_fixture();
    let (context, authorization, transcript) =
        canonical_export_ceremony_fixture_for_registered_key_v1(material.registered_public_key);
    let request =
        ExportRequestV1::new(context, authorization, transcript).expect("canonical export request");
    let provenance = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Export,
        material.registered_public_key,
    );
    let state = authenticated_state_from_provenance(
        request.request_context(),
        request.validated_dag(),
        &provenance,
        provenance
            .export_registered_state_binding()
            .expect("export state binding"),
        11,
        11,
    );
    let execution_id = OneUseExecutionId32V1::new([0x79; 32]).expect("execution id");
    let authorities = canonical_export_acceptance_authorities_v1(&request);
    let pair = canonical_verified_export_acceptance_pair_v1(
        &request,
        &state,
        &provenance,
        execution_id,
        authorities,
    );
    let dag: CeremonyValidatedDagV1 = request.validated_dag();
    let store_authority = state.trusted_transition_authority();
    let common = ExportEvaluatorCommonVectorV1 {
        request_id: request.request_context().request_id().as_str().to_owned(),
        replay_nonce_hex: encode_hex(request.request_context().replay_nonce().as_bytes()),
        request_expiry_unix_ms: request.request_context().request_expiry().value(),
        client_recipient_key_hex: encode_hex(
            request
                .request_context()
                .client_ephemeral_public_key()
                .as_bytes(),
        ),
        request_context_digest_hex: encode_hex(dag.request_context_digest().as_bytes()),
        authorization_digest_hex: encode_hex(dag.authorization_digest().as_bytes()),
        transcript_digest_hex: encode_hex(dag.transcript_digest().as_bytes()),
        provenance_pair_digest_hex: encode_hex(
            provenance
                .digest()
                .expect("provenance pair digest")
                .as_bytes(),
        ),
        signed_store_resolution_digest_hex: encode_hex(
            &state
                .signed_resolution_digest()
                .expect("signed store resolution digest"),
        ),
        store_authority_key_epoch: store_authority.key_epoch().value(),
        store_authority_key_digest_hex: encode_hex(&store_authority.key_digest()),
        active_state_version: state.active_state_version().value(),
        registered_public_key_hex: encode_hex(state.state().registered_public_key().as_bytes()),
        one_use_execution_id_hex: encode_hex(execution_id.as_bytes()),
    };
    let authorities_vector = ExportEvaluatorAuthoritiesVectorV1 {
        deriver_a: ExportEvaluatorAuthorityVectorV1 {
            role: "deriver_a".to_owned(),
            deriver_id: request
                .request_context()
                .deriver_a_binding()
                .id()
                .as_str()
                .to_owned(),
            key_epoch: authorities.deriver_a().key_epoch(),
            verifying_key_hex: encode_hex(&authorities.deriver_a().verifying_key_bytes()),
            key_digest_hex: encode_hex(&authorities.deriver_a().key_digest()),
        },
        deriver_b: ExportEvaluatorAuthorityVectorV1 {
            role: "deriver_b".to_owned(),
            deriver_id: request
                .request_context()
                .deriver_b_binding()
                .id()
                .as_str()
                .to_owned(),
            key_epoch: authorities.deriver_b().key_epoch(),
            verifying_key_hex: encode_hex(&authorities.deriver_b().verifying_key_bytes()),
            key_digest_hex: encode_hex(&authorities.deriver_b().key_digest()),
        },
    };
    let acceptances = ExportEvaluatorAcceptancesVectorV1 {
        deriver_a: acceptance_a_vector(pair.deriver_a()),
        deriver_b: acceptance_b_vector(pair.deriver_b()),
    };
    let pair_vector = ExportEvaluatorAcceptedPairVectorV1 {
        encoding_hex: encode_hex(pair.encode()),
        digest_hex: encode_hex(pair.digest()),
    };
    let expected_pair_digest = *pair.digest();
    let session = request
        .begin_host_reference_artifact_session(
            ExportArtifactIssuanceV1::new(state, execution_id, authorities),
            &provenance,
            pair,
        )
        .expect("accepted export evaluator session");
    let committed = session
        .evaluate_and_commit_host_reference(
            export_inputs(&material),
            export_ideal_coin(),
            export_bindings(),
            ExportOutputCommitmentEvidenceV1::new(
                OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0x94; 32])
                    .expect("A output receipt"),
                OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0x95; 32])
                    .expect("B output receipt"),
            ),
        )
        .expect("output commitment");
    let committed_receipt_digest = committed.artifacts().receipt().digest();
    let committed_receipt_encoding = committed.artifacts().receipt().encode();
    let committed_evaluation_digest = committed.artifacts().receipt().evaluation_evidence_digest();
    assert_eq!(
        committed_evaluation_digest.as_bytes(),
        &expected_pair_digest
    );
    let release_evidence = HostOnlyExportClientReleaseEvidenceV1::for_output_committed(
        &committed,
        OpaqueHostReferenceClientDeliveryEvidenceDigest32V1::new([0xa5; 32])
            .expect("client delivery evidence"),
        OpaqueHostReferenceConsumedExportAuthorizationDigest32V1::new([0xa6; 32])
            .expect("consumed authorization evidence"),
    );
    let released = committed
        .release_v1(release_evidence)
        .expect("released export");
    let released_receipt = released.artifacts().receipt();
    assert_eq!(
        released_receipt.evaluation_evidence_digest().as_bytes(),
        &expected_pair_digest
    );
    ExportEvaluatorAuthorizationVectorCaseV1 {
        case_id: "export_authorized_evaluation_released_v1".to_owned(),
        request_kind: ExportRequestKindVectorV1::Export,
        source_references: ExportEvaluatorSourceReferencesV1 {
            ceremony_context_case_id: "ceremony-export-v1".to_owned(),
            provenance_case_id: "export_provenance_outer_v1".to_owned(),
            evaluation_input_party_view_case_id: "export_evaluation_input_party_views_v1"
                .to_owned(),
            semantic_lifecycle_case_id: "export_semantic_artifacts_host_reference_receipt_v1"
                .to_owned(),
            export_delivery_case_id: "export_output_commit_release_redelivery_v1".to_owned(),
        },
        common,
        authorities: authorities_vector,
        acceptances,
        accepted_pair: pair_vector,
        evaluation: ExportEvaluatorOutcomeVectorV1 {
            evaluation_plan: "one_export_evaluation".to_owned(),
            yao_evaluations: 1,
            deriver_a_invocations: 1,
            deriver_b_invocations: 1,
            output_committed_authorization_state: "unconsumed".to_owned(),
            output_committed_receipt_encoding_hex: encode_hex(&committed_receipt_encoding),
            output_committed_receipt_digest_hex: encode_hex(committed_receipt_digest.as_bytes()),
            output_committed_evaluation_evidence_digest_hex: encode_hex(
                committed_evaluation_digest.as_bytes(),
            ),
            released_authorization_state: "consumed".to_owned(),
            released_receipt_encoding_hex: encode_hex(&released_receipt.encode()),
            released_receipt_digest_hex: encode_hex(released_receipt.digest().as_bytes()),
            released_evaluation_evidence_digest_hex: encode_hex(
                released_receipt.evaluation_evidence_digest().as_bytes(),
            ),
            registered_state_retained: true,
        },
    }
}

fn acceptance_a_vector(
    acceptance: &crate::export_evaluation_acceptance::VerifiedDeriverAExportAuthorizationAcceptanceV1,
) -> ExportEvaluatorAcceptanceVectorV1 {
    ExportEvaluatorAcceptanceVectorV1 {
        role: "deriver_a".to_owned(),
        checked_at_unix_ms: acceptance.checked_at(),
        provenance_statement_digest_hex: encode_hex(acceptance.provenance_statement_digest()),
        signing_bytes_hex: encode_hex(&acceptance.signing_bytes().expect("A signing bytes")),
        signature_hex: encode_hex(acceptance.signature_bytes()),
        signed_artifact_digest_hex: encode_hex(&acceptance.digest().expect("A artifact digest")),
    }
}

fn acceptance_b_vector(
    acceptance: &crate::export_evaluation_acceptance::VerifiedDeriverBExportAuthorizationAcceptanceV1,
) -> ExportEvaluatorAcceptanceVectorV1 {
    ExportEvaluatorAcceptanceVectorV1 {
        role: "deriver_b".to_owned(),
        checked_at_unix_ms: acceptance.checked_at(),
        provenance_statement_digest_hex: encode_hex(acceptance.provenance_statement_digest()),
        signing_bytes_hex: encode_hex(&acceptance.signing_bytes().expect("B signing bytes")),
        signature_hex: encode_hex(acceptance.signature_bytes()),
        signed_artifact_digest_hex: encode_hex(&acceptance.digest().expect("B artifact digest")),
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
