//! Strict synthetic corpus for export output commitment, release, and redelivery.

use core::fmt;

use serde::Serialize;

use crate::output_party_views::build_host_only_export_released_party_view_set_v1;
use crate::semantic_lifecycle_fixtures::{
    canonical_export_output_committed_v1, canonical_export_released_v1,
    EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1,
};

/// Schema identifier for the strict export-delivery lifecycle corpus.
pub const EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:export-delivery-vectors:v1";

/// Scope separating host release semantics from production delivery claims.
pub const EXPORT_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1: &str = "host_only_synthetic_export_delivery_v1";

/// Strict one-case export-delivery lifecycle corpus.
#[derive(Serialize)]
pub struct ExportDeliveryVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<ExportDeliveryVectorCaseV1>,
}

impl ExportDeliveryVectorCorpusV1 {
    /// Returns the fixed corpus schema.
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
struct ExportDeliveryVectorCaseV1 {
    case_id: String,
    request_kind: ExportDeliveryRequestKindVectorV1,
    semantic_lifecycle_case_id: String,
    output_committed: ExportOutputCommittedVectorV1,
    delivery_uncertain: ExportDeliveryUncertainVectorV1,
    released: ExportReleasedVectorV1,
    redelivered: ExportRedeliveredVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ExportDeliveryRequestKindVectorV1 {
    Export,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ExportAuthorizationStateVectorV1 {
    Unconsumed,
    Consumed,
}

#[derive(Serialize)]
struct ExportOutputCommittedVectorV1 {
    request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    package_set_digest_hex: String,
    output_committed_receipt_encoding_hex: String,
    output_committed_receipt_digest_hex: String,
    deriver_a_receipt_evidence_digest_hex: String,
    deriver_b_receipt_evidence_digest_hex: String,
    registered_public_key_hex: String,
    active_state_version: u64,
    authorization_state: ExportAuthorizationStateVectorV1,
}

#[derive(Serialize)]
struct ExportDeliveryUncertainVectorV1 {
    before_package_set_digest_hex: String,
    after_package_set_digest_hex: String,
    authorization_state: ExportAuthorizationStateVectorV1,
    zero_private_evaluation_work: ZeroPrivateEvaluationWorkVectorV1,
}

#[derive(Serialize)]
struct ExportReleasedVectorV1 {
    package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    released_receipt_encoding_hex: String,
    released_receipt_digest_hex: String,
    client_delivery_evidence_digest_hex: String,
    consumed_authorization_evidence_digest_hex: String,
    registered_public_key_hex: String,
    active_state_version: u64,
    authorization_state: ExportAuthorizationStateVectorV1,
    client_seed_hex: String,
    zero_private_evaluation_work: ZeroPrivateEvaluationWorkVectorV1,
}

#[derive(Serialize)]
struct ExportRedeliveredVectorV1 {
    before_released_receipt_digest_hex: String,
    after_released_receipt_digest_hex: String,
    client_seed_hex: String,
    zero_private_evaluation_work: ZeroPrivateEvaluationWorkVectorV1,
}

#[derive(Serialize)]
struct ZeroPrivateEvaluationWorkVectorV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    output_share_samples: u8,
}

/// Failure returned for any noncanonical corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportDeliveryVectorCorpusParseErrorV1;

impl fmt::Display for ExportDeliveryVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "export-delivery corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for ExportDeliveryVectorCorpusParseErrorV1 {}

/// Builds the canonical one-case synthetic export-delivery corpus.
pub fn canonical_export_delivery_vector_corpus_v1() -> ExportDeliveryVectorCorpusV1 {
    ExportDeliveryVectorCorpusV1 {
        schema: EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: EXPORT_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![ExportDeliveryVectorCaseV1 {
            case_id: "export_output_commit_release_redelivery_v1".to_owned(),
            request_kind: ExportDeliveryRequestKindVectorV1::Export,
            semantic_lifecycle_case_id: EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1.to_owned(),
            output_committed: output_committed_vector(),
            delivery_uncertain: delivery_uncertain_vector(),
            released: released_vector(),
            redelivered: redelivered_vector(),
        }],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_export_delivery_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded = serde_json::to_vec_pretty(&canonical_export_delivery_vector_corpus_v1())
        .expect("fixed export-delivery corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_export_delivery_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<ExportDeliveryVectorCorpusV1, ExportDeliveryVectorCorpusParseErrorV1> {
    if encoded != canonical_export_delivery_vector_corpus_json_bytes_v1() {
        return Err(ExportDeliveryVectorCorpusParseErrorV1);
    }
    Ok(canonical_export_delivery_vector_corpus_v1())
}

fn output_committed_vector() -> ExportOutputCommittedVectorV1 {
    let committed = canonical_export_output_committed_v1();
    let dag = committed.request().validated_dag();
    let receipt = committed.artifacts().receipt();
    ExportOutputCommittedVectorV1 {
        request_context_digest_hex: encode_hex(dag.request_context_digest().as_bytes()),
        authorization_digest_hex: encode_hex(dag.authorization_digest().as_bytes()),
        transcript_digest_hex: encode_hex(dag.transcript_digest().as_bytes()),
        package_set_digest_hex: encode_hex(receipt.package_set_digest().as_bytes()),
        output_committed_receipt_encoding_hex: encode_hex(&receipt.encode()),
        output_committed_receipt_digest_hex: encode_hex(receipt.digest().as_bytes()),
        deriver_a_receipt_evidence_digest_hex: encode_hex(
            receipt.deriver_a_receipt_evidence_digest().as_bytes(),
        ),
        deriver_b_receipt_evidence_digest_hex: encode_hex(
            receipt.deriver_b_receipt_evidence_digest().as_bytes(),
        ),
        registered_public_key_hex: encode_hex(receipt.registered_public_key().as_bytes()),
        active_state_version: committed.state().active_state_version().value(),
        authorization_state: ExportAuthorizationStateVectorV1::Unconsumed,
    }
}

fn delivery_uncertain_vector() -> ExportDeliveryUncertainVectorV1 {
    let committed = canonical_export_output_committed_v1();
    let before = committed.artifacts().packages().digest();
    let pending = committed.delivery_uncertain_v1();
    ExportDeliveryUncertainVectorV1 {
        before_package_set_digest_hex: encode_hex(before.as_bytes()),
        after_package_set_digest_hex: encode_hex(pending.package_set_digest().as_bytes()),
        authorization_state: ExportAuthorizationStateVectorV1::Unconsumed,
        zero_private_evaluation_work: zero_work_vector(pending.zero_private_evaluation_work()),
    }
}

fn released_vector() -> ExportReleasedVectorV1 {
    let released = canonical_export_released_v1();
    let receipt = released.artifacts().receipt();
    let projection = ExportReleasedVectorV1 {
        package_set_digest_hex: encode_hex(receipt.package_set_digest().as_bytes()),
        output_committed_receipt_digest_hex: encode_hex(
            receipt.output_committed_receipt_digest().as_bytes(),
        ),
        released_receipt_encoding_hex: encode_hex(&receipt.encode()),
        released_receipt_digest_hex: encode_hex(receipt.digest().as_bytes()),
        client_delivery_evidence_digest_hex: encode_hex(
            receipt.client_delivery_evidence_digest().as_bytes(),
        ),
        consumed_authorization_evidence_digest_hex: encode_hex(
            receipt.consumed_authorization_digest().as_bytes(),
        ),
        registered_public_key_hex: encode_hex(receipt.registered_public_key().as_bytes()),
        active_state_version: released.state().active_state_version().value(),
        authorization_state: ExportAuthorizationStateVectorV1::Consumed,
        client_seed_hex: encode_hex(
            build_host_only_export_released_party_view_set_v1(released)
                .expect("canonical released view")
                .observe_client_v1()
                .seed()
                .expose_bytes()
                .as_slice(),
        ),
        zero_private_evaluation_work: zero_work_vector(
            canonical_export_released_v1().zero_private_evaluation_work(),
        ),
    };
    projection
}

fn redelivered_vector() -> ExportRedeliveredVectorV1 {
    let redelivery = canonical_export_released_v1().redeliver_v1();
    let before = redelivery.before_receipt_digest();
    let after = redelivery.after_receipt_digest();
    let zero = redelivery.zero_private_evaluation_work();
    let client = build_host_only_export_released_party_view_set_v1(redelivery.into_released())
        .expect("canonical redelivered view")
        .observe_client_v1();
    ExportRedeliveredVectorV1 {
        before_released_receipt_digest_hex: encode_hex(before.as_bytes()),
        after_released_receipt_digest_hex: encode_hex(after.as_bytes()),
        client_seed_hex: encode_hex(client.seed().expose_bytes().as_slice()),
        zero_private_evaluation_work: zero_work_vector(zero),
    }
}

fn zero_work_vector(
    witness: crate::lifecycle_domain::ZeroReevaluationWitnessV1,
) -> ZeroPrivateEvaluationWorkVectorV1 {
    ZeroPrivateEvaluationWorkVectorV1 {
        yao_evaluations: witness.yao_evaluations(),
        deriver_a_invocations: witness.deriver_a_invocations(),
        deriver_b_invocations: witness.deriver_b_invocations(),
        contribution_derivations: witness.contribution_derivations(),
        output_share_samples: witness.output_share_samples(),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
