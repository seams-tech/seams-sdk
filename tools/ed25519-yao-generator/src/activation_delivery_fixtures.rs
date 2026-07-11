//! Strict synthetic corpus for activation authorization and recipient delivery.

use core::fmt;

use serde::Serialize;

use crate::activation_delivery::{
    HostOnlyActivationRecipientReleaseEvidenceV1, HostOnlyActivationRecipientsReleasedV1,
};
use crate::lifecycle_domain::{
    ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1, ActivationRequestV1,
    PendingActivationPreStateV1, ZeroReevaluationWitnessV1,
};
use crate::output_sharing::reconstruct_host_only_client_scalar_output_v1;
use crate::semantic_artifacts::{
    OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
    OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
};
use crate::semantic_lifecycle_fixtures::{
    canonical_activation_metadata_success_v1, canonical_activation_request_v1, recovery_pending,
    refresh_pending, registration_pending, ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
    RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1, REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1,
    REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
};

/// Schema identifier for the strict activation-delivery corpus.
pub const ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:activation-delivery-vectors:v1";

/// Scope separating host lifecycle evidence from deployed delivery claims.
pub const ACTIVATION_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_activation_delivery_v1";

/// Strict registration/recovery/refresh activation-delivery corpus.
#[derive(Serialize)]
pub struct ActivationDeliveryVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<ActivationDeliveryVectorCaseV1>,
}

impl ActivationDeliveryVectorCorpusV1 {
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
struct ActivationDeliveryVectorCaseV1 {
    case_id: String,
    origin_request_kind: ActivationOriginRequestKindVectorV1,
    semantic_lifecycle_case_id: String,
    activation_semantic_lifecycle_case_id: String,
    output_committed: ActivationOutputCommittedVectorV1,
    activation_control_admitted: ActivationControlAdmittedVectorV1,
    metadata_consumed: ActivationMetadataConsumedVectorV1,
    delivery_uncertain: ActivationDeliveryUncertainVectorV1,
    recipients_released: ActivationRecipientsReleasedVectorV1,
    redelivered: ActivationRedeliveredVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationOriginRequestKindVectorV1 {
    Registration,
    Recovery,
    Refresh,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationAuthorizationStateVectorV1 {
    NotIssued,
    Unconsumed,
    Consumed,
}

#[derive(Serialize)]
struct ActivationOutputCommittedVectorV1 {
    origin_request_context_digest_hex: String,
    origin_authorization_digest_hex: String,
    origin_transcript_digest_hex: String,
    package_set_digest_hex: String,
    output_committed_receipt_encoding_hex: String,
    output_committed_receipt_digest_hex: String,
    x_client_hex: String,
    x_server_hex: String,
    registered_public_key_hex: String,
    activation_authorization_state: ActivationAuthorizationStateVectorV1,
}

#[derive(Serialize)]
struct ActivationControlAdmittedVectorV1 {
    request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    activation_authorization_state: ActivationAuthorizationStateVectorV1,
}

#[derive(Serialize)]
struct ActivationMetadataConsumedVectorV1 {
    request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    activation_authorization_state: ActivationAuthorizationStateVectorV1,
    zero_private_evaluation_work: ZeroPrivateEvaluationWorkVectorV1,
}

#[derive(Serialize)]
struct ActivationDeliveryUncertainVectorV1 {
    before_package_set_digest_hex: String,
    after_package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    activation_transcript_digest_hex: String,
    activation_authorization_state: ActivationAuthorizationStateVectorV1,
    zero_private_evaluation_work: ZeroPrivateEvaluationWorkVectorV1,
}

#[derive(Serialize)]
struct ActivationRecipientsReleasedVectorV1 {
    package_set_digest_hex: String,
    output_committed_receipt_digest_hex: String,
    activation_transcript_digest_hex: String,
    client: ActivationClientReleasedCapabilityVectorV1,
    signing_worker: ActivationSigningWorkerReleaseAuthorityVectorV1,
    activation_authorization_state: ActivationAuthorizationStateVectorV1,
    zero_private_evaluation_work: ZeroPrivateEvaluationWorkVectorV1,
}

#[derive(Serialize)]
struct ActivationClientReleasedCapabilityVectorV1 {
    capability_kind: ActivationClientCapabilityKindVectorV1,
    package_set_digest_hex: String,
    delivery_evidence_digest_hex: String,
    x_client_base_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationClientCapabilityKindVectorV1 {
    ActivationClientScalarRelease,
}

#[derive(Serialize)]
struct ActivationSigningWorkerReleaseAuthorityVectorV1 {
    capability_kind: ActivationSigningWorkerCapabilityKindVectorV1,
    package_set_digest_hex: String,
    delivery_evidence_digest_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationSigningWorkerCapabilityKindVectorV1 {
    SigningWorkerActivationReleaseAuthority,
}

#[derive(Serialize)]
struct ActivationRedeliveredVectorV1 {
    before_package_set_digest_hex: String,
    after_package_set_digest_hex: String,
    before_client_scalar_hex: String,
    after_client_scalar_hex: String,
    before_client_delivery_evidence_digest_hex: String,
    after_client_delivery_evidence_digest_hex: String,
    before_signing_worker_delivery_evidence_digest_hex: String,
    after_signing_worker_delivery_evidence_digest_hex: String,
    before_signing_worker_authority_package_set_digest_hex: String,
    after_signing_worker_authority_package_set_digest_hex: String,
    activation_authorization_state: ActivationAuthorizationStateVectorV1,
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

/// Failure returned for any noncanonical activation-delivery corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationDeliveryVectorCorpusParseErrorV1;

impl fmt::Display for ActivationDeliveryVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "activation-delivery corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for ActivationDeliveryVectorCorpusParseErrorV1 {}

/// Builds the canonical three-origin activation-delivery corpus.
pub fn canonical_activation_delivery_vector_corpus_v1() -> ActivationDeliveryVectorCorpusV1 {
    ActivationDeliveryVectorCorpusV1 {
        schema: ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: ACTIVATION_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            activation_delivery_case(ActivationPackageOriginV1::Registration),
            activation_delivery_case(ActivationPackageOriginV1::Recovery),
            activation_delivery_case(ActivationPackageOriginV1::Refresh),
        ],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_activation_delivery_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded = serde_json::to_vec_pretty(&canonical_activation_delivery_vector_corpus_v1())
        .expect("fixed activation-delivery corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_activation_delivery_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<ActivationDeliveryVectorCorpusV1, ActivationDeliveryVectorCorpusParseErrorV1> {
    if encoded != canonical_activation_delivery_vector_corpus_json_bytes_v1() {
        return Err(ActivationDeliveryVectorCorpusParseErrorV1);
    }
    Ok(canonical_activation_delivery_vector_corpus_v1())
}

fn activation_delivery_case(origin: ActivationPackageOriginV1) -> ActivationDeliveryVectorCaseV1 {
    ActivationDeliveryVectorCaseV1 {
        case_id: case_id(origin).to_owned(),
        origin_request_kind: origin_request_kind(origin),
        semantic_lifecycle_case_id: semantic_lifecycle_case_id(origin).to_owned(),
        activation_semantic_lifecycle_case_id: ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1.to_owned(),
        output_committed: output_committed_vector(origin),
        activation_control_admitted: activation_control_admitted_vector(origin),
        metadata_consumed: metadata_consumed_vector(origin),
        delivery_uncertain: delivery_uncertain_vector(origin),
        recipients_released: recipients_released_vector(origin),
        redelivered: redelivered_vector(origin),
    }
}

fn output_committed_vector(origin: ActivationPackageOriginV1) -> ActivationOutputCommittedVectorV1 {
    let pending = pending(origin);
    let output = pending.committed_output();
    let artifacts = output.artifacts();
    let binding = artifacts.binding();
    let receipt = artifacts.receipt();
    ActivationOutputCommittedVectorV1 {
        origin_request_context_digest_hex: encode_hex(
            binding.origin_request_context_digest().as_bytes(),
        ),
        origin_authorization_digest_hex: encode_hex(
            binding.origin_authorization_digest().as_bytes(),
        ),
        origin_transcript_digest_hex: encode_hex(binding.origin_transcript_digest().as_bytes()),
        package_set_digest_hex: encode_hex(receipt.package_set_digest().as_bytes()),
        output_committed_receipt_encoding_hex: encode_hex(&receipt.encode()),
        output_committed_receipt_digest_hex: encode_hex(receipt.digest().as_bytes()),
        x_client_hex: encode_hex(receipt.x_client()),
        x_server_hex: encode_hex(receipt.x_server()),
        registered_public_key_hex: encode_hex(receipt.registered_public_key().as_bytes()),
        activation_authorization_state: ActivationAuthorizationStateVectorV1::NotIssued,
    }
}

fn activation_control_admitted_vector(
    origin: ActivationPackageOriginV1,
) -> ActivationControlAdmittedVectorV1 {
    let request = activation_request(origin);
    let dag = request.validated_dag();
    let artifacts = request.pending().artifacts();
    ActivationControlAdmittedVectorV1 {
        request_context_digest_hex: encode_hex(dag.request_context_digest().as_bytes()),
        authorization_digest_hex: encode_hex(dag.authorization_digest().as_bytes()),
        transcript_digest_hex: encode_hex(dag.transcript_digest().as_bytes()),
        package_set_digest_hex: encode_hex(artifacts.packages().digest().as_bytes()),
        output_committed_receipt_digest_hex: encode_hex(artifacts.receipt().digest().as_bytes()),
        activation_authorization_state: ActivationAuthorizationStateVectorV1::Unconsumed,
    }
}

fn metadata_consumed_vector(
    origin: ActivationPackageOriginV1,
) -> ActivationMetadataConsumedVectorV1 {
    let metadata = metadata(origin);
    let dag = metadata.post_state().activation_dag();
    let artifacts = metadata.post_state().artifacts();
    ActivationMetadataConsumedVectorV1 {
        request_context_digest_hex: encode_hex(dag.request_context_digest().as_bytes()),
        authorization_digest_hex: encode_hex(dag.authorization_digest().as_bytes()),
        transcript_digest_hex: encode_hex(dag.transcript_digest().as_bytes()),
        package_set_digest_hex: encode_hex(artifacts.packages().digest().as_bytes()),
        output_committed_receipt_digest_hex: encode_hex(artifacts.receipt().digest().as_bytes()),
        activation_authorization_state: ActivationAuthorizationStateVectorV1::Consumed,
        zero_private_evaluation_work: zero_work_vector(metadata.zero_reevaluation()),
    }
}

fn delivery_uncertain_vector(
    origin: ActivationPackageOriginV1,
) -> ActivationDeliveryUncertainVectorV1 {
    let metadata = metadata(origin);
    let before = metadata.post_state().artifacts().packages().digest();
    let receipt = metadata.post_state().artifacts().receipt().digest();
    let transcript = metadata.post_state().activation_dag().transcript_digest();
    let pending = metadata.delivery_uncertain_v1();
    ActivationDeliveryUncertainVectorV1 {
        before_package_set_digest_hex: encode_hex(before.as_bytes()),
        after_package_set_digest_hex: encode_hex(pending.package_set_digest().as_bytes()),
        output_committed_receipt_digest_hex: encode_hex(receipt.as_bytes()),
        activation_transcript_digest_hex: encode_hex(transcript.as_bytes()),
        activation_authorization_state: ActivationAuthorizationStateVectorV1::Consumed,
        zero_private_evaluation_work: zero_work_vector(pending.zero_private_evaluation_work()),
    }
}

fn recipients_released_vector(
    origin: ActivationPackageOriginV1,
) -> ActivationRecipientsReleasedVectorV1 {
    let metadata = metadata(origin);
    let receipt = metadata.post_state().artifacts().receipt().digest();
    let transcript = metadata.post_state().activation_dag().transcript_digest();
    let evidence = release_evidence(&metadata, origin);
    let released = metadata
        .release_recipients_v1(evidence)
        .expect("canonical activation recipient release");
    released_vector(released, receipt, transcript)
}

fn released_vector(
    released: HostOnlyActivationRecipientsReleasedV1,
    receipt: crate::semantic_artifacts::ActivationOutputCommittedReceiptDigest32V1,
    transcript: crate::ceremony_context::CeremonyTranscriptDigest32V1,
) -> ActivationRecipientsReleasedVectorV1 {
    let zero = released.zero_private_evaluation_work();
    let (client, worker) = released.into_capabilities();
    ActivationRecipientsReleasedVectorV1 {
        package_set_digest_hex: encode_hex(client.package_set_digest().as_bytes()),
        output_committed_receipt_digest_hex: encode_hex(receipt.as_bytes()),
        activation_transcript_digest_hex: encode_hex(transcript.as_bytes()),
        client: ActivationClientReleasedCapabilityVectorV1 {
            capability_kind: ActivationClientCapabilityKindVectorV1::ActivationClientScalarRelease,
            package_set_digest_hex: encode_hex(client.package_set_digest().as_bytes()),
            delivery_evidence_digest_hex: encode_hex(client.delivery_evidence().as_bytes()),
            x_client_base_hex: encode_hex(&client.x_client_base().expose_bytes()),
        },
        signing_worker: ActivationSigningWorkerReleaseAuthorityVectorV1 {
            capability_kind: ActivationSigningWorkerCapabilityKindVectorV1::SigningWorkerActivationReleaseAuthority,
            package_set_digest_hex: encode_hex(worker.package_set_digest().as_bytes()),
            delivery_evidence_digest_hex: encode_hex(worker.delivery_evidence().as_bytes()),
        },
        activation_authorization_state: ActivationAuthorizationStateVectorV1::Consumed,
        zero_private_evaluation_work: zero_work_vector(zero),
    }
}

fn redelivered_vector(origin: ActivationPackageOriginV1) -> ActivationRedeliveredVectorV1 {
    let metadata = metadata(origin);
    let evidence = release_evidence(&metadata, origin);
    let output = metadata.post_state().committed_output();
    let shares = output.shares();
    let before_client = reconstruct_host_only_client_scalar_output_v1(
        shares.deriver_a().client(),
        shares.deriver_b().client(),
    );
    let before_package = output.artifacts().packages().digest();
    let before_client_evidence = evidence.client_delivery_evidence();
    let before_worker_evidence = evidence.signing_worker_delivery_evidence();
    let redelivery = metadata
        .release_recipients_v1(evidence)
        .expect("canonical activation recipient release")
        .redeliver_v1();
    let before = redelivery.before_package_set_digest();
    let after = redelivery.after_package_set_digest();
    let zero = redelivery.zero_private_evaluation_work();
    let (client, worker) = redelivery.into_released().into_capabilities();
    ActivationRedeliveredVectorV1 {
        before_package_set_digest_hex: encode_hex(before.as_bytes()),
        after_package_set_digest_hex: encode_hex(after.as_bytes()),
        before_client_scalar_hex: encode_hex(&before_client.expose_bytes()),
        after_client_scalar_hex: encode_hex(&client.x_client_base().expose_bytes()),
        before_client_delivery_evidence_digest_hex: encode_hex(before_client_evidence.as_bytes()),
        after_client_delivery_evidence_digest_hex: encode_hex(
            client.delivery_evidence().as_bytes(),
        ),
        before_signing_worker_delivery_evidence_digest_hex: encode_hex(
            before_worker_evidence.as_bytes(),
        ),
        after_signing_worker_delivery_evidence_digest_hex: encode_hex(
            worker.delivery_evidence().as_bytes(),
        ),
        before_signing_worker_authority_package_set_digest_hex: encode_hex(
            before_package.as_bytes(),
        ),
        after_signing_worker_authority_package_set_digest_hex: encode_hex(
            worker.package_set_digest().as_bytes(),
        ),
        activation_authorization_state: ActivationAuthorizationStateVectorV1::Consumed,
        zero_private_evaluation_work: zero_work_vector(zero),
    }
}

fn activation_request(origin: ActivationPackageOriginV1) -> ActivationRequestV1 {
    canonical_activation_request_v1(origin)
}

fn metadata(origin: ActivationPackageOriginV1) -> ActivationMetadataConsumptionSuccessV1 {
    canonical_activation_metadata_success_v1(origin)
}

fn release_evidence(
    metadata: &ActivationMetadataConsumptionSuccessV1,
    origin: ActivationPackageOriginV1,
) -> HostOnlyActivationRecipientReleaseEvidenceV1 {
    HostOnlyActivationRecipientReleaseEvidenceV1::for_metadata_consumed(
        metadata,
        OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1::new(
            [0xa1 + origin_index(origin); 32],
        )
        .expect("client delivery evidence"),
        OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1::new(
            [0xb1 + origin_index(origin); 32],
        )
        .expect("SigningWorker delivery evidence"),
    )
}

fn pending(origin: ActivationPackageOriginV1) -> PendingActivationPreStateV1 {
    match origin {
        ActivationPackageOriginV1::Registration => registration_pending(),
        ActivationPackageOriginV1::Recovery => recovery_pending(),
        ActivationPackageOriginV1::Refresh => refresh_pending(),
    }
}

const fn origin_index(origin: ActivationPackageOriginV1) -> u8 {
    match origin {
        ActivationPackageOriginV1::Registration => 0,
        ActivationPackageOriginV1::Recovery => 1,
        ActivationPackageOriginV1::Refresh => 2,
    }
}

const fn case_id(origin: ActivationPackageOriginV1) -> &'static str {
    match origin {
        ActivationPackageOriginV1::Registration => "registration_activation_delivery_v1",
        ActivationPackageOriginV1::Recovery => "recovery_activation_delivery_v1",
        ActivationPackageOriginV1::Refresh => "refresh_activation_delivery_v1",
    }
}

const fn semantic_lifecycle_case_id(origin: ActivationPackageOriginV1) -> &'static str {
    match origin {
        ActivationPackageOriginV1::Registration => REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
        ActivationPackageOriginV1::Recovery => RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1,
        ActivationPackageOriginV1::Refresh => REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1,
    }
}

const fn origin_request_kind(
    origin: ActivationPackageOriginV1,
) -> ActivationOriginRequestKindVectorV1 {
    match origin {
        ActivationPackageOriginV1::Registration => {
            ActivationOriginRequestKindVectorV1::Registration
        }
        ActivationPackageOriginV1::Recovery => ActivationOriginRequestKindVectorV1::Recovery,
        ActivationPackageOriginV1::Refresh => ActivationOriginRequestKindVectorV1::Refresh,
    }
}

fn zero_work_vector(witness: ZeroReevaluationWitnessV1) -> ZeroPrivateEvaluationWorkVectorV1 {
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
