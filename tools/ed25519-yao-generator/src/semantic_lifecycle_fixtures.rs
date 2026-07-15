//! Strict public vectors for semantic artifacts and host lifecycle projections.
//!
//! The corpus contains public encodings, digests, points, epochs, and redacted
//! abort metadata only. Synthetic roots, contributions, joined secrets, output
//! coins, scalar/seed shares, ciphertext bytes, and refresh deltas never cross
//! this fixture boundary.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::authenticated_store::{
    ActiveStoreStateVersionV1, AuthenticatedRegisteredStoreResolutionV1, StoreAuthorityKeyEpochV1,
    StoreAuthoritySignature64V1, StoreAuthorityVerifyingKeyV1,
    UnverifiedRegisteredStoreResolutionV1,
};
use crate::ceremony_context::{
    CeremonyActivationEpochV1, CeremonyArtifactSuiteDigest32V1,
    CeremonyAuthorizationRecordDigest32V1, CeremonyAuthorizationV1, CeremonyPublicRequestContextV1,
    CeremonyReplayNonce32V1, CeremonyRequestExpiryV1, CeremonyRequestIdV1, CeremonyRequestKindV1,
    CeremonyTranscriptNonce32V1, CeremonyTranscriptV1, CeremonyTransportBindingDigest32V1,
    CeremonyValidatedDagV1,
};
use crate::ceremony_fixtures::{
    canonical_export_ceremony_fixture_for_registered_key_v1,
    canonical_recovery_ceremony_fixture_v1, canonical_refresh_ceremony_fixture_v1,
    canonical_registration_ceremony_fixture_v1,
};
use crate::export_delivery::{HostOnlyExportClientReleaseEvidenceV1, HostOnlyExportReleasedV1};
use crate::export_evaluation_acceptance_fixtures::{
    canonical_export_acceptance_authorities_v1, canonical_verified_export_acceptance_pair_v1,
};
use crate::lifecycle_domain::{
    consume_activation_metadata_v1, AbortedTerminalStateV1, ActivationControlFreshFieldsV1,
    ActivationMetadataConsumptionSuccessV1, ActivationPackageOriginV1, ActivationReceiptEvidenceV1,
    ActivationRequestFailureV1, ActivationRequestV1, ActiveCredentialBindingDigest32V1,
    ExportArtifactIssuanceV1, ExportOutputCommitmentEvidenceV1, ExportRequestV1,
    HostOnlyExportOutputCommittedV1, PendingActivationPreStateV1, RecoveryRequestV1,
    RedactedFailureCodeV1, RefreshRequestV1, RegisteredLifecyclePreStateV1,
    RegistrationArtifactIssuanceV1, RegistrationRequestV1, RejectedActivationControlProposalV1,
    UniformLifecycleAbortV1,
};
use crate::lifecycle_persistence::{
    AttemptRejectedActivationProjectionV1, MetadataConsumedActivationProjectionV1,
    OutputCommittedActivationProjectionV1, OutputCommittedArtifactIdentityV1,
};
use crate::provenance::{RegisteredStateProvenanceBindingV1, RoleInputProvenancePairV1};
use crate::provenance_fixtures::canonical_provenance_fixture_pair_for_registered_key_v1;
use crate::semantic_artifacts::{
    ActivationOutputCommittedReceiptBodyV1, ActivationPackageSetV1, ExportPackageSetV1,
    ExportReleasedReceiptBodyV1, OneUseExecutionId32V1,
    OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
    OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
};
use crate::semantic_fixture_material::{
    activation_bindings, export_bindings, export_ideal_coin, export_inputs, recovery_admission,
    recovery_ideal_coins, recovery_inputs, reference_fixture, refresh_admission,
    refresh_ideal_coins, refresh_inputs, registration_admission, registration_ideal_coins,
    registration_inputs,
};

/// Schema identifier for the strict semantic-artifact lifecycle corpus.
pub const SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:semantic-artifact-lifecycle-vectors:v1";
/// Scope preventing public fixture evidence from implying production cryptography.
pub const SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_public_semantic_artifact_lifecycle_v1";

pub(crate) const REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1: &str =
    "registration_semantic_artifacts_output_committed_v1";
pub(crate) const ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1: &str = "activation_metadata_control_v1";
pub(crate) const RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1: &str =
    "recovery_semantic_artifacts_output_committed_v1";
pub(crate) const REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1: &str =
    "refresh_semantic_artifacts_output_committed_v1";
pub(crate) const EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1: &str =
    "export_semantic_artifacts_host_reference_receipt_v1";

const REGISTRATION_ACTIVATION_REQUEST_ID_V1: &str = "activation-registration-valid";
const RECOVERY_ACTIVATION_REQUEST_ID_V1: &str = "activation-recovery-valid";
const REFRESH_ACTIVATION_REQUEST_ID_V1: &str = "activation-refresh-valid";

/// Strict five-branch semantic lifecycle corpus.
#[derive(Serialize)]
pub struct SemanticLifecycleVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<SemanticLifecycleVectorCaseV1>,
}

impl SemanticLifecycleVectorCorpusV1 {
    /// Returns the exact schema identifier.
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

    /// Returns the fixed top-level case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
#[serde(tag = "request_kind", content = "vector", rename_all = "snake_case")]
enum SemanticLifecycleVectorCaseV1 {
    Registration(ActivationArtifactCaseVectorV1),
    Activation(ActivationControlVectorV1),
    Recovery(ActivationArtifactCaseVectorV1),
    Refresh(ActivationArtifactCaseVectorV1),
    Export(ExportArtifactCaseVectorV1),
}

#[derive(Serialize)]
struct ActivationArtifactCaseVectorV1 {
    case_id: String,
    ceremony: SemanticCeremonyEncodingVectorV1,
    packages: ActivationPackageSetVectorV1,
    receipt: ReceiptBodyVectorV1,
    persistence: ActivationPersistenceProjectionVectorV1,
}

#[derive(Serialize)]
struct ExportArtifactCaseVectorV1 {
    case_id: String,
    ceremony: SemanticCeremonyEncodingVectorV1,
    packages: ExportPackageSetVectorV1,
    receipt: ReceiptBodyVectorV1,
    state_effect: ExportStateEffectVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ExportStateEffectVectorV1 {
    RegisteredStateRetained,
}

#[derive(Serialize)]
struct SemanticCeremonyEncodingVectorV1 {
    public_request_context_encoding_hex: String,
    public_request_context_digest_sha256_hex: String,
    authorization_encoding_hex: String,
    authorization_digest_sha256_hex: String,
    transcript_encoding_hex: String,
    transcript_digest_sha256_hex: String,
}

#[derive(Serialize)]
struct ActivationPackageSetVectorV1 {
    deriver_a_client_descriptor_encoding_hex: String,
    deriver_b_client_descriptor_encoding_hex: String,
    deriver_a_signing_worker_descriptor_encoding_hex: String,
    deriver_b_signing_worker_descriptor_encoding_hex: String,
    package_set_encoding_hex: String,
    package_set_digest_sha256_hex: String,
}

#[derive(Serialize)]
struct ExportPackageSetVectorV1 {
    deriver_a_client_descriptor_encoding_hex: String,
    deriver_b_client_descriptor_encoding_hex: String,
    package_set_encoding_hex: String,
    package_set_digest_sha256_hex: String,
}

#[derive(Serialize)]
struct ReceiptBodyVectorV1 {
    receipt_body_encoding_hex: String,
    receipt_body_digest_sha256_hex: String,
}

#[derive(Serialize)]
struct ActivationControlVectorV1 {
    case_id: String,
    metadata_consumed: Vec<ActivationMetadataConsumedVectorV1>,
    rejected_attempts: Vec<ActivationRejectedAttemptVectorV1>,
}

#[derive(Serialize)]
struct ActivationMetadataConsumedVectorV1 {
    origin_kind: SemanticActivationOriginVectorV1,
    origin_case_id: String,
    activation_ceremony: SemanticCeremonyEncodingVectorV1,
    persistence: ActivationPersistenceProjectionVectorV1,
    zero_reevaluation: ZeroReevaluationVectorV1,
}

#[derive(Serialize)]
struct ActivationRejectedAttemptVectorV1 {
    fixture_class: ActivationFreshnessReuseFixtureV1,
    fresh_fields: ActivationFreshFieldsVectorV1,
    persistence: ActivationPersistenceProjectionVectorV1,
}

#[derive(Serialize)]
struct ActivationFreshFieldsVectorV1 {
    request_id: String,
    replay_nonce_hex: String,
    request_expiry: u64,
    authorization_record_digest_hex: String,
    transcript_nonce_hex: String,
    transport_binding_digest_hex: String,
    artifact_suite_digest_hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationFreshnessReuseFixtureV1 {
    RequestId,
    ReplayNonce,
    TranscriptNonce,
    OriginContextAndTranscript,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SemanticActivationOriginVectorV1 {
    Registration,
    Recovery,
    Refresh,
}

#[derive(Serialize)]
struct ZeroReevaluationVectorV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    output_share_samples: u8,
}

#[derive(Serialize)]
#[serde(tag = "state", content = "projection", rename_all = "snake_case")]
enum ActivationPersistenceProjectionVectorV1 {
    OutputCommitted(OutputCommittedProjectionVectorV1),
    AttemptRejected(AttemptRejectedProjectionVectorV1),
    MetadataConsumed(MetadataConsumedProjectionVectorV1),
}

#[derive(Serialize, Clone, PartialEq, Eq)]
struct OutputCommittedProjectionVectorV1 {
    identity: OutputCommittedArtifactIdentityVectorV1,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
struct OutputCommittedArtifactIdentityVectorV1 {
    origin_kind: SemanticActivationOriginVectorV1,
    origin_request_kind: CeremonyRequestKindV1,
    origin_request_context_digest_hex: String,
    origin_authorization_digest_hex: String,
    origin_transcript_digest_hex: String,
    one_use_execution_id_hex: String,
    package_set_digest_hex: String,
    receipt_digest_hex: String,
    activation_epoch: u64,
    registered_public_key_hex: String,
}

#[derive(Serialize)]
struct AttemptRejectedProjectionVectorV1 {
    before: OutputCommittedProjectionVectorV1,
    after: OutputCommittedProjectionVectorV1,
    abort: UniformLifecycleAbortVectorV1,
}

#[derive(Serialize)]
struct MetadataConsumedProjectionVectorV1 {
    committed: OutputCommittedProjectionVectorV1,
    activation_request_context_digest_hex: String,
    activation_authorization_digest_hex: String,
    activation_transcript_digest_hex: String,
}

#[derive(Serialize)]
struct UniformLifecycleAbortVectorV1 {
    request_kind: CeremonyRequestKindV1,
    public_transcript_digest_hex: String,
    public_failure_code: RedactedFailureCodeVectorV1,
    terminal: AbortedTerminalStateVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RedactedFailureCodeVectorV1 {
    Rejected,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AbortedTerminalStateVectorV1 {
    Aborted,
}

/// Failure returned for any noncanonical semantic-lifecycle corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticLifecycleVectorCorpusParseErrorV1;

impl fmt::Display for SemanticLifecycleVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "semantic lifecycle corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for SemanticLifecycleVectorCorpusParseErrorV1 {}

/// Builds the canonical five-branch public semantic-lifecycle corpus.
pub fn canonical_semantic_lifecycle_vector_corpus_v1() -> SemanticLifecycleVectorCorpusV1 {
    SemanticLifecycleVectorCorpusV1 {
        schema: SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            SemanticLifecycleVectorCaseV1::Registration(activation_artifact_case(
                REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
                registration_pending(),
            )),
            SemanticLifecycleVectorCaseV1::Activation(activation_control_case()),
            SemanticLifecycleVectorCaseV1::Recovery(activation_artifact_case(
                RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1,
                recovery_pending(),
            )),
            SemanticLifecycleVectorCaseV1::Refresh(activation_artifact_case(
                REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1,
                refresh_pending(),
            )),
            SemanticLifecycleVectorCaseV1::Export(export_artifact_case()),
        ],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_semantic_lifecycle_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded = serde_json::to_vec_pretty(&canonical_semantic_lifecycle_vector_corpus_v1())
        .expect("fixed semantic lifecycle corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_semantic_lifecycle_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<SemanticLifecycleVectorCorpusV1, SemanticLifecycleVectorCorpusParseErrorV1> {
    if encoded != canonical_semantic_lifecycle_vector_corpus_json_bytes_v1() {
        return Err(SemanticLifecycleVectorCorpusParseErrorV1);
    }
    Ok(canonical_semantic_lifecycle_vector_corpus_v1())
}

pub(crate) fn registration_pending() -> PendingActivationPreStateV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) = canonical_registration_ceremony_fixture_v1();
    let request = RegistrationRequestV1::new(context, authorization, transcript)
        .expect("canonical registration request");
    let pair = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Registration,
        fixture.registered_public_key,
    );
    let activation_epoch = CeremonyActivationEpochV1::new(9).expect("activation epoch");
    let execution_id = OneUseExecutionId32V1::new([0x70; 32]).expect("execution id");
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

pub(crate) fn recovery_pending() -> PendingActivationPreStateV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) = canonical_recovery_ceremony_fixture_v1();
    let request = RecoveryRequestV1::new(context, authorization, transcript)
        .expect("canonical recovery request");
    let pair = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Recovery,
        fixture.registered_public_key,
    );
    let binding = pair
        .recovery_registered_state_binding()
        .expect("recovery registered-state binding");
    let state = authenticated_state_from_provenance(
        request.request_context(),
        request.validated_dag(),
        &pair,
        binding,
        9,
        9,
    );
    let activation_epoch = CeremonyActivationEpochV1::new(10).expect("next activation epoch");
    let execution_id = OneUseExecutionId32V1::new([0x73; 32]).expect("execution id");
    let admission = recovery_admission(&request, &pair, state, activation_epoch, execution_id);
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

pub(crate) fn refresh_pending() -> PendingActivationPreStateV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) = canonical_refresh_ceremony_fixture_v1();
    let request = RefreshRequestV1::new(context, authorization, transcript)
        .expect("canonical refresh request");
    let pair = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Refresh,
        fixture.registered_public_key,
    );
    let binding = pair
        .refresh_registered_state_binding()
        .expect("refresh registered-state binding");
    let state = authenticated_state_from_provenance(
        request.request_context(),
        request.validated_dag(),
        &pair,
        binding.current(),
        10,
        10,
    );
    let activation_epoch = CeremonyActivationEpochV1::new(11).expect("next activation epoch");
    let execution_id = OneUseExecutionId32V1::new([0x75; 32]).expect("execution id");
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

fn export_artifact_case() -> ExportArtifactCaseVectorV1 {
    let released = canonical_export_released_v1();
    let (_state, artifacts, _shares, consumed_authorization) = released.into_parts();
    let request = consumed_authorization.request();
    let ceremony = ceremony_vector(
        request.request_context(),
        &CeremonyAuthorizationV1::from(*request.authorization()),
        request.transcript(),
    );
    ExportArtifactCaseVectorV1 {
        case_id: EXPORT_SEMANTIC_LIFECYCLE_CASE_ID_V1.to_owned(),
        ceremony,
        packages: export_packages_vector(artifacts.packages()),
        receipt: export_receipt_vector(artifacts.receipt()),
        state_effect: ExportStateEffectVectorV1::RegisteredStateRetained,
    }
}

pub(crate) fn canonical_export_output_committed_v1() -> HostOnlyExportOutputCommittedV1 {
    let fixture = reference_fixture();
    let (context, authorization, transcript) =
        canonical_export_ceremony_fixture_for_registered_key_v1(fixture.registered_public_key);
    let request =
        ExportRequestV1::new(context, authorization, transcript).expect("canonical export request");
    let pair = canonical_provenance_fixture_pair_for_registered_key_v1(
        CeremonyRequestKindV1::Export,
        fixture.registered_public_key,
    );
    let state = authenticated_state_from_provenance(
        request.request_context(),
        request.validated_dag(),
        &pair,
        pair.export_registered_state_binding()
            .expect("export registered-state binding"),
        11,
        11,
    );
    let one_use_execution_id = OneUseExecutionId32V1::new([0x79; 32]).expect("execution id");
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
        .expect("export session");
    session
        .evaluate_and_commit_host_reference(
            export_inputs(&fixture),
            export_ideal_coin(),
            export_bindings(),
            export_output_commitment_evidence(),
        )
        .expect("export artifacts")
}

pub(crate) fn canonical_export_released_v1() -> HostOnlyExportReleasedV1 {
    let committed = canonical_export_output_committed_v1();
    let evidence = HostOnlyExportClientReleaseEvidenceV1::for_output_committed(
        &committed,
        OpaqueHostReferenceClientDeliveryEvidenceDigest32V1::new([0xa5; 32])
            .expect("client delivery evidence"),
        OpaqueHostReferenceConsumedExportAuthorizationDigest32V1::new([0xa6; 32])
            .expect("consumed authorization"),
    );
    committed.release_v1(evidence).expect("export release")
}

fn state_from_provenance(
    binding: RegisteredStateProvenanceBindingV1,
    active_activation_epoch: u64,
) -> RegisteredLifecyclePreStateV1 {
    let a = binding.deriver_a();
    let b = binding.deriver_b();
    RegisteredLifecyclePreStateV1::from_host_reference_store_projection(
        binding.registered_public_key(),
        ActiveCredentialBindingDigest32V1::new([0x41; 32]).expect("active credential binding"),
        binding.stable_scope(),
        CeremonyActivationEpochV1::new(active_activation_epoch).expect("active activation epoch"),
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

pub(crate) fn authenticated_state_from_provenance(
    request: &CeremonyPublicRequestContextV1,
    dag: CeremonyValidatedDagV1,
    provenance: &RoleInputProvenancePairV1,
    binding: RegisteredStateProvenanceBindingV1,
    active_activation_epoch: u64,
    active_state_version: u64,
) -> AuthenticatedRegisteredStoreResolutionV1 {
    let state = state_from_provenance(binding, active_activation_epoch);
    let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
    let authority = StoreAuthorityVerifyingKeyV1::parse(
        StoreAuthorityKeyEpochV1::new(1).expect("store authority key epoch"),
        signing_key.verifying_key().to_bytes(),
    )
    .expect("store authority verifying key");
    let resolution = UnverifiedRegisteredStoreResolutionV1::new(
        request,
        dag,
        provenance,
        ActiveStoreStateVersionV1::new(active_state_version).expect("active store state version"),
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

fn activation_receipt_evidence() -> ActivationReceiptEvidenceV1 {
    ActivationReceiptEvidenceV1::new(
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xa1; 32])
            .expect("A receipt evidence"),
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xa2; 32])
            .expect("B receipt evidence"),
    )
}

fn export_output_commitment_evidence() -> ExportOutputCommitmentEvidenceV1 {
    ExportOutputCommitmentEvidenceV1::new(
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xa3; 32])
            .expect("A receipt evidence"),
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xa4; 32])
            .expect("B receipt evidence"),
    )
}

fn activation_artifact_case(
    case_id: &str,
    pending: PendingActivationPreStateV1,
) -> ActivationArtifactCaseVectorV1 {
    let (ceremony, packages, receipt) = match &pending {
        PendingActivationPreStateV1::Registration(value) => (
            ceremony_vector(
                value.origin().request_context(),
                &CeremonyAuthorizationV1::from(*value.origin().authorization()),
                value.origin().transcript(),
            ),
            activation_packages_vector(value.artifacts().packages()),
            activation_receipt_vector(value.artifacts().receipt()),
        ),
        PendingActivationPreStateV1::Recovery(value) => (
            ceremony_vector(
                value.origin().request_context(),
                &CeremonyAuthorizationV1::from(*value.origin().authorization()),
                value.origin().transcript(),
            ),
            activation_packages_vector(value.artifacts().packages()),
            activation_receipt_vector(value.artifacts().receipt()),
        ),
        PendingActivationPreStateV1::Refresh(value) => (
            ceremony_vector(
                value.origin().request_context(),
                &CeremonyAuthorizationV1::from(*value.origin().authorization()),
                value.origin().transcript(),
            ),
            activation_packages_vector(value.artifacts().packages()),
            activation_receipt_vector(value.artifacts().receipt()),
        ),
    };
    ActivationArtifactCaseVectorV1 {
        case_id: case_id.to_owned(),
        ceremony,
        packages,
        receipt,
        persistence: ActivationPersistenceProjectionVectorV1::OutputCommitted(
            output_committed_vector(OutputCommittedActivationProjectionV1::from_pending(
                &pending,
            )),
        ),
    }
}

fn ceremony_vector(
    request: &CeremonyPublicRequestContextV1,
    authorization: &CeremonyAuthorizationV1,
    transcript: &CeremonyTranscriptV1,
) -> SemanticCeremonyEncodingVectorV1 {
    let dag = CeremonyValidatedDagV1::from_components(request, authorization, transcript)
        .expect("fixture ceremony is coherent");
    SemanticCeremonyEncodingVectorV1 {
        public_request_context_encoding_hex: encode_hex(
            &request.encode().expect("request context encodes"),
        ),
        public_request_context_digest_sha256_hex: encode_hex(
            dag.request_context_digest().as_bytes(),
        ),
        authorization_encoding_hex: encode_hex(
            &authorization.encode().expect("authorization encodes"),
        ),
        authorization_digest_sha256_hex: encode_hex(dag.authorization_digest().as_bytes()),
        transcript_encoding_hex: encode_hex(&transcript.encode().expect("transcript encodes")),
        transcript_digest_sha256_hex: encode_hex(dag.transcript_digest().as_bytes()),
    }
}

fn activation_packages_vector(packages: &ActivationPackageSetV1) -> ActivationPackageSetVectorV1 {
    ActivationPackageSetVectorV1 {
        deriver_a_client_descriptor_encoding_hex: encode_hex(&packages.deriver_a_client().encode()),
        deriver_b_client_descriptor_encoding_hex: encode_hex(&packages.deriver_b_client().encode()),
        deriver_a_signing_worker_descriptor_encoding_hex: encode_hex(
            &packages.deriver_a_signing_worker().encode(),
        ),
        deriver_b_signing_worker_descriptor_encoding_hex: encode_hex(
            &packages.deriver_b_signing_worker().encode(),
        ),
        package_set_encoding_hex: encode_hex(&packages.encode()),
        package_set_digest_sha256_hex: encode_hex(packages.digest().as_bytes()),
    }
}

fn export_packages_vector(packages: &ExportPackageSetV1) -> ExportPackageSetVectorV1 {
    ExportPackageSetVectorV1 {
        deriver_a_client_descriptor_encoding_hex: encode_hex(&packages.deriver_a_client().encode()),
        deriver_b_client_descriptor_encoding_hex: encode_hex(&packages.deriver_b_client().encode()),
        package_set_encoding_hex: encode_hex(&packages.encode()),
        package_set_digest_sha256_hex: encode_hex(packages.digest().as_bytes()),
    }
}

fn activation_receipt_vector(
    receipt: &ActivationOutputCommittedReceiptBodyV1,
) -> ReceiptBodyVectorV1 {
    ReceiptBodyVectorV1 {
        receipt_body_encoding_hex: encode_hex(&receipt.encode()),
        receipt_body_digest_sha256_hex: encode_hex(receipt.digest().as_bytes()),
    }
}

fn export_receipt_vector(receipt: &ExportReleasedReceiptBodyV1) -> ReceiptBodyVectorV1 {
    ReceiptBodyVectorV1 {
        receipt_body_encoding_hex: encode_hex(&receipt.encode()),
        receipt_body_digest_sha256_hex: encode_hex(receipt.digest().as_bytes()),
    }
}

fn output_committed_vector(
    projection: OutputCommittedActivationProjectionV1,
) -> OutputCommittedProjectionVectorV1 {
    OutputCommittedProjectionVectorV1 {
        identity: output_committed_identity_vector(projection.identity()),
    }
}

fn output_committed_identity_vector(
    identity: OutputCommittedArtifactIdentityV1,
) -> OutputCommittedArtifactIdentityVectorV1 {
    OutputCommittedArtifactIdentityVectorV1 {
        origin_kind: origin_vector(identity.origin()),
        origin_request_kind: identity.origin_request_kind(),
        origin_request_context_digest_hex: encode_hex(
            identity.origin_request_context_digest().as_bytes(),
        ),
        origin_authorization_digest_hex: encode_hex(
            identity.origin_authorization_digest().as_bytes(),
        ),
        origin_transcript_digest_hex: encode_hex(identity.origin_transcript_digest().as_bytes()),
        one_use_execution_id_hex: encode_hex(identity.one_use_execution_id().as_bytes()),
        package_set_digest_hex: encode_hex(identity.package_set_digest().as_bytes()),
        receipt_digest_hex: encode_hex(identity.receipt_digest().as_bytes()),
        activation_epoch: identity.activation_epoch().value(),
        registered_public_key_hex: encode_hex(identity.registered_public_key().as_bytes()),
    }
}

fn origin_vector(origin: ActivationPackageOriginV1) -> SemanticActivationOriginVectorV1 {
    match origin {
        ActivationPackageOriginV1::Registration => SemanticActivationOriginVectorV1::Registration,
        ActivationPackageOriginV1::Recovery => SemanticActivationOriginVectorV1::Recovery,
        ActivationPackageOriginV1::Refresh => SemanticActivationOriginVectorV1::Refresh,
    }
}

fn activation_control_case() -> ActivationControlVectorV1 {
    ActivationControlVectorV1 {
        case_id: ACTIVATION_SEMANTIC_LIFECYCLE_CASE_ID_V1.to_owned(),
        metadata_consumed: vec![
            metadata_consumed_vector(
                registration_pending(),
                REGISTRATION_SEMANTIC_LIFECYCLE_CASE_ID_V1,
                REGISTRATION_ACTIVATION_REQUEST_ID_V1,
                0xd1,
                20_001,
                0xe1,
            ),
            metadata_consumed_vector(
                recovery_pending(),
                RECOVERY_SEMANTIC_LIFECYCLE_CASE_ID_V1,
                RECOVERY_ACTIVATION_REQUEST_ID_V1,
                0xd2,
                20_002,
                0xe2,
            ),
            metadata_consumed_vector(
                refresh_pending(),
                REFRESH_SEMANTIC_LIFECYCLE_CASE_ID_V1,
                REFRESH_ACTIVATION_REQUEST_ID_V1,
                0xd3,
                20_003,
                0xe3,
            ),
        ],
        rejected_attempts: vec![
            rejected_attempt_vector(
                ActivationFreshnessReuseFixtureV1::RequestId,
                "request-registration-001",
                0xf1,
                30_001,
                0xf2,
            ),
            rejected_attempt_vector(
                ActivationFreshnessReuseFixtureV1::ReplayNonce,
                "activation-new",
                0x11,
                30_002,
                0xf3,
            ),
            rejected_attempt_vector(
                ActivationFreshnessReuseFixtureV1::TranscriptNonce,
                "activation-new",
                0xf4,
                30_003,
                0x61,
            ),
            rejected_attempt_vector(
                ActivationFreshnessReuseFixtureV1::OriginContextAndTranscript,
                "request-registration-001",
                0x11,
                2_000_001,
                0x61,
            ),
        ],
    }
}

pub(crate) fn canonical_activation_metadata_success_v1(
    origin: ActivationPackageOriginV1,
) -> ActivationMetadataConsumptionSuccessV1 {
    consume_activation_metadata_v1(canonical_activation_request_v1(origin))
}

pub(crate) fn canonical_activation_request_v1(
    origin: ActivationPackageOriginV1,
) -> ActivationRequestV1 {
    let (pending, request_id, replay_byte, expiry, transcript_byte) = match origin {
        ActivationPackageOriginV1::Registration => (
            registration_pending(),
            REGISTRATION_ACTIVATION_REQUEST_ID_V1,
            0xd1,
            20_001,
            0xe1,
        ),
        ActivationPackageOriginV1::Recovery => (
            recovery_pending(),
            RECOVERY_ACTIVATION_REQUEST_ID_V1,
            0xd2,
            20_002,
            0xe2,
        ),
        ActivationPackageOriginV1::Refresh => (
            refresh_pending(),
            REFRESH_ACTIVATION_REQUEST_ID_V1,
            0xd3,
            20_003,
            0xe3,
        ),
    };
    ActivationRequestV1::new(
        activation_fresh_fields(request_id, replay_byte, expiry, transcript_byte),
        pending,
    )
    .expect("canonical activation metadata request")
}

fn activation_fresh_fields(
    request_id: &str,
    replay_byte: u8,
    expiry: u64,
    transcript_byte: u8,
) -> ActivationControlFreshFieldsV1 {
    ActivationControlFreshFieldsV1::new(
        CeremonyRequestIdV1::parse(request_id).expect("activation request id"),
        CeremonyReplayNonce32V1::new([replay_byte; 32]),
        CeremonyRequestExpiryV1::new(expiry).expect("activation expiry"),
        CeremonyAuthorizationRecordDigest32V1::new([0xb1; 32])
            .expect("activation authorization record"),
        CeremonyTranscriptNonce32V1::new([transcript_byte; 32]),
        CeremonyTransportBindingDigest32V1::new([0xb2; 32]).expect("activation transport binding"),
        CeremonyArtifactSuiteDigest32V1::new([0xb3; 32]).expect("activation artifact suite"),
    )
}

fn metadata_consumed_vector(
    pending: PendingActivationPreStateV1,
    origin_case_id: &str,
    request_id: &str,
    replay_byte: u8,
    expiry: u64,
    transcript_byte: u8,
) -> ActivationMetadataConsumedVectorV1 {
    let origin = pending.origin();
    let request = ActivationRequestV1::new(
        activation_fresh_fields(request_id, replay_byte, expiry, transcript_byte),
        pending,
    )
    .expect("fresh activation metadata request");
    let ceremony = ceremony_vector(
        request.request_context(),
        &CeremonyAuthorizationV1::from(*request.authorization()),
        request.transcript(),
    );
    let success = consume_activation_metadata_v1(request);
    let zero = success.zero_reevaluation();
    ActivationMetadataConsumedVectorV1 {
        origin_kind: origin_vector(origin),
        origin_case_id: origin_case_id.to_owned(),
        activation_ceremony: ceremony,
        persistence: ActivationPersistenceProjectionVectorV1::MetadataConsumed(
            metadata_consumed_projection_vector(&success),
        ),
        zero_reevaluation: ZeroReevaluationVectorV1 {
            yao_evaluations: zero.yao_evaluations(),
            deriver_a_invocations: zero.deriver_a_invocations(),
            deriver_b_invocations: zero.deriver_b_invocations(),
            contribution_derivations: zero.contribution_derivations(),
            output_share_samples: zero.output_share_samples(),
        },
    }
}

fn metadata_consumed_projection_vector(
    success: &ActivationMetadataConsumptionSuccessV1,
) -> MetadataConsumedProjectionVectorV1 {
    let projection = MetadataConsumedActivationProjectionV1::from_success(success);
    MetadataConsumedProjectionVectorV1 {
        committed: output_committed_vector(projection.committed()),
        activation_request_context_digest_hex: encode_hex(
            projection.activation_request_context_digest().as_bytes(),
        ),
        activation_authorization_digest_hex: encode_hex(
            projection.activation_authorization_digest().as_bytes(),
        ),
        activation_transcript_digest_hex: encode_hex(
            projection.activation_transcript_digest().as_bytes(),
        ),
    }
}

fn rejected_attempt_vector(
    fixture_class: ActivationFreshnessReuseFixtureV1,
    request_id: &str,
    replay_byte: u8,
    expiry: u64,
    transcript_byte: u8,
) -> ActivationRejectedAttemptVectorV1 {
    let fresh_fields = ActivationFreshFieldsVectorV1 {
        request_id: request_id.to_owned(),
        replay_nonce_hex: encode_hex(&[replay_byte; 32]),
        request_expiry: expiry,
        authorization_record_digest_hex: encode_hex(&[0xb1; 32]),
        transcript_nonce_hex: encode_hex(&[transcript_byte; 32]),
        transport_binding_digest_hex: encode_hex(&[0xb2; 32]),
        artifact_suite_digest_hex: encode_hex(&[0xb3; 32]),
    };
    let pending = registration_pending();
    let failure = match ActivationRequestV1::new(
        activation_fresh_fields(request_id, replay_byte, expiry, transcript_byte),
        pending,
    ) {
        Ok(_) => panic!("freshness reuse was accepted"),
        Err(failure) => failure,
    };
    let rejection = match failure {
        ActivationRequestFailureV1::Rejected(rejection) => rejection,
        ActivationRequestFailureV1::Construction(failure) => {
            let _pending = failure.into_pending();
            panic!("freshness fixture became a construction failure")
        }
    };
    ActivationRejectedAttemptVectorV1 {
        fixture_class,
        fresh_fields,
        persistence: ActivationPersistenceProjectionVectorV1::AttemptRejected(
            attempt_rejected_projection_vector(&rejection),
        ),
    }
}

fn attempt_rejected_projection_vector(
    rejection: &RejectedActivationControlProposalV1,
) -> AttemptRejectedProjectionVectorV1 {
    let projection = AttemptRejectedActivationProjectionV1::from_rejection(rejection);
    AttemptRejectedProjectionVectorV1 {
        before: output_committed_vector(projection.before()),
        after: output_committed_vector(projection.after()),
        abort: abort_vector(projection.abort()),
    }
}

fn abort_vector(abort: UniformLifecycleAbortV1) -> UniformLifecycleAbortVectorV1 {
    let public_failure_code = match abort.public_failure_code() {
        RedactedFailureCodeV1::Rejected => RedactedFailureCodeVectorV1::Rejected,
    };
    let terminal = match abort.terminal() {
        AbortedTerminalStateV1::Aborted => AbortedTerminalStateVectorV1::Aborted,
    };
    UniformLifecycleAbortVectorV1 {
        request_kind: abort.request_kind(),
        public_transcript_digest_hex: encode_hex(abort.public_transcript_digest().as_bytes()),
        public_failure_code,
        terminal,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
