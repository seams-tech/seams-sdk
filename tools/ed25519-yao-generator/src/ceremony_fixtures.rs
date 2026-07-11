//! Strict public-synthetic vectors for canonical ceremony context bytes.

use serde::{Deserialize, Serialize};

use crate::ceremony_context::{
    CeremonyAccountIdV1, CeremonyActivationAuthorizationV1, CeremonyActivationEpochV1,
    CeremonyArtifactSuiteDigest32V1, CeremonyAuthorizationRecordDigest32V1,
    CeremonyAuthorizationV1, CeremonyChainTargetV1, CeremonyClientEphemeralPublicKey32V1,
    CeremonyCurrentDeriverAInputStateEpochV1, CeremonyCurrentDeriverBInputStateEpochV1,
    CeremonyDeriverABindingV1, CeremonyDeriverAIdV1, CeremonyDeriverAKeyEpochV1,
    CeremonyDeriverBBindingV1, CeremonyDeriverBIdV1, CeremonyDeriverBKeyEpochV1,
    CeremonyDeriverSetIdV1, CeremonyEnvironmentIdV1, CeremonyExportAuthorizationV1,
    CeremonyIdentityScopeV1, CeremonyInfrastructureV1, CeremonyNextDeriverAInputStateEpochV1,
    CeremonyNextDeriverBInputStateEpochV1, CeremonyOrganizationIdV1, CeremonyPackageSetDigest32V1,
    CeremonyProjectIdV1, CeremonyPublicRequestContextV1, CeremonyRecoveryAuthorizationV1,
    CeremonyRefreshAuthorizationV1, CeremonyRegistrationAuthorizationV1,
    CeremonyRegistrationIntentDigest32V1, CeremonyReplacementCredentialBindingDigest32V1,
    CeremonyReplayNonce32V1, CeremonyRequestExpiryV1, CeremonyRequestIdV1, CeremonyRequestKindV1,
    CeremonyRootShareEpochV1, CeremonyRouterIdV1, CeremonySessionIdV1, CeremonySigningRootIdV1,
    CeremonySigningRootVersionV1, CeremonySigningWorkerBindingV1, CeremonySigningWorkerIdV1,
    CeremonySigningWorkerKeyEpochV1, CeremonyTranscriptNonce32V1, CeremonyTranscriptV1,
    CeremonyTransportBindingDigest32V1, CeremonyValidatedDagV1, CeremonyWalletIdV1,
};
use crate::kdf_fixtures::canonical_registered_public_key_v1;
use crate::RegisteredEd25519PublicKey32V1;

/// Schema identifier for the strict five-case ceremony context corpus.
pub const CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:ceremony-context-vectors:v1";
/// Scope label preventing public byte vectors from implying authentication.
pub const CEREMONY_CONTEXT_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_public_ceremony_byte_contract_v1";

/// Strict five-case ceremony context vector corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyContextVectorCorpusV1 {
    /// Fixed schema identifier.
    pub schema: String,
    /// Fixed protocol identifier.
    pub protocol_id: String,
    /// Explicitly narrow host-only evidence scope.
    pub evidence_scope: String,
    /// Registration, activation, recovery, refresh, and export in fixed order.
    pub cases: Vec<CeremonyContextVectorCaseV1>,
}

/// Request-kind-tagged ceremony case. Authorization fields remain branch-specific.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "request_kind",
    content = "vector",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CeremonyContextVectorCaseV1 {
    /// Registration ceremony bytes.
    Registration(CeremonyCaseVectorV1<CeremonyRegistrationAuthorizationVectorV1>),
    /// Activation-control ceremony bytes.
    Activation(CeremonyCaseVectorV1<CeremonyActivationAuthorizationVectorV1>),
    /// Recovery ceremony bytes.
    Recovery(CeremonyCaseVectorV1<CeremonyRecoveryAuthorizationVectorV1>),
    /// Refresh ceremony bytes.
    Refresh(CeremonyCaseVectorV1<CeremonyRefreshAuthorizationVectorV1>),
    /// Export ceremony bytes.
    Export(CeremonyCaseVectorV1<CeremonyExportAuthorizationVectorV1>),
}

/// Complete source inputs and computed bytes for one branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyCaseVectorV1<Authorization> {
    /// Stable case identifier.
    pub case_id: String,
    /// Source fields for the public request-context preimage.
    pub public_request_context: CeremonyPublicRequestContextVectorV1,
    /// Branch-specific authorization source fields.
    pub authorization: Authorization,
    /// Final transcript-only source fields.
    pub transcript: CeremonyTranscriptInputVectorV1,
    /// Exact encodings and SHA-256 digests.
    pub expected: CeremonyExpectedEncodingsV1,
}

/// Raw public request-context fields copied into each self-contained case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyPublicRequestContextVectorV1 {
    /// Fixed numeric protocol version.
    pub protocol_version: u64,
    /// Required visible-ASCII request identifier.
    pub request_id: String,
    /// Exactly 32 replay-nonce bytes.
    pub replay_nonce_hex: String,
    /// Required visible-ASCII account identifier.
    pub account_id: String,
    /// Required visible-ASCII wallet identifier.
    pub wallet_id: String,
    /// Required visible-ASCII session identifier.
    pub session_id: String,
    /// Required visible-ASCII organization identifier.
    pub organization_id: String,
    /// Required visible-ASCII project identifier.
    pub project_id: String,
    /// Required visible-ASCII environment identifier.
    pub environment_id: String,
    /// Required visible-ASCII signing-root identifier.
    pub signing_root_id: String,
    /// Nonzero signing-root version.
    pub signing_root_version: u64,
    /// Required visible-ASCII chain target.
    pub chain_target: String,
    /// Nonzero root-share epoch.
    pub root_share_epoch: u64,
    /// Required visible-ASCII Router identifier.
    pub router_id: String,
    /// Required visible-ASCII Deriver-set identifier.
    pub deriver_set_id: String,
    /// Required visible-ASCII Deriver A identifier.
    pub deriver_a_id: String,
    /// Nonzero Deriver A key epoch.
    pub deriver_a_key_epoch: u64,
    /// Required visible-ASCII Deriver B identifier.
    pub deriver_b_id: String,
    /// Nonzero Deriver B key epoch.
    pub deriver_b_key_epoch: u64,
    /// Required visible-ASCII SigningWorker identifier.
    pub signing_worker_id: String,
    /// Nonzero SigningWorker key epoch.
    pub signing_worker_key_epoch: u64,
    /// Exactly 32 client ephemeral public-key bytes.
    pub client_ephemeral_public_key_hex: String,
    /// Recipient plan derived from the request kind.
    pub recipient_plan: String,
    /// Output package kind derived from the request kind.
    pub output_package_kind: String,
    /// Nonzero public request expiry.
    pub request_expiry: u64,
}

/// Registration authorization source fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyRegistrationAuthorizationVectorV1 {
    /// Nonzero opaque authorization-record digest.
    pub authorization_record_digest_hex: String,
    /// Nonzero registration-intent digest.
    pub registration_intent_digest_hex: String,
}

/// Activation authorization source fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyActivationAuthorizationVectorV1 {
    /// Nonzero opaque authorization-record digest.
    pub authorization_record_digest_hex: String,
    /// Evaluation-producing request kind of the coherent origin DAG.
    pub origin_request_kind: CeremonyRequestKindV1,
    /// Registration-origin public request-context digest.
    pub origin_request_context_digest_hex: String,
    /// Registration-origin ceremony transcript digest.
    pub origin_transcript_digest_hex: String,
    /// Nonzero committed activation package-set digest.
    pub package_set_digest_hex: String,
    /// Nonzero activation epoch.
    pub activation_epoch: u64,
}

/// Recovery authorization source fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyRecoveryAuthorizationVectorV1 {
    /// Nonzero opaque authorization-record digest.
    pub authorization_record_digest_hex: String,
    /// Nonzero replacement-credential binding digest.
    pub replacement_credential_binding_digest_hex: String,
}

/// Refresh authorization source fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyRefreshAuthorizationVectorV1 {
    /// Nonzero opaque authorization-record digest.
    pub authorization_record_digest_hex: String,
    /// Current Deriver A input-state epoch.
    pub current_deriver_a_input_state_epoch: u64,
    /// Strictly advancing Deriver A input-state epoch.
    pub next_deriver_a_input_state_epoch: u64,
    /// Current Deriver B input-state epoch.
    pub current_deriver_b_input_state_epoch: u64,
    /// Strictly advancing Deriver B input-state epoch.
    pub next_deriver_b_input_state_epoch: u64,
}

/// Export authorization source fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyExportAuthorizationVectorV1 {
    /// Nonzero opaque authorization-record digest.
    pub authorization_record_digest_hex: String,
    /// Canonical registered Ed25519 public key.
    pub registered_ed25519_public_key_hex: String,
}

/// Source values introduced only in the final transcript layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyTranscriptInputVectorV1 {
    /// Exactly 32 transcript-nonce bytes, separate from the replay nonce type.
    pub transcript_nonce_hex: String,
    /// Nonzero public transport-binding digest slot.
    pub transport_binding_digest_hex: String,
    /// Nonzero public artifact-suite digest slot.
    pub artifact_suite_digest_hex: String,
}

/// Exact bytes and digests produced from one case's source fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyExpectedEncodingsV1 {
    /// Canonical public request-context bytes.
    pub public_request_context_encoding_hex: String,
    /// SHA-256 over the exact public request-context bytes.
    pub public_request_context_digest_sha256_hex: String,
    /// Canonical branch-specific authorization bytes.
    pub authorization_encoding_hex: String,
    /// SHA-256 over the exact authorization bytes.
    pub authorization_digest_sha256_hex: String,
    /// Canonical final transcript bytes.
    pub transcript_encoding_hex: String,
    /// SHA-256 over the exact transcript bytes.
    pub transcript_digest_sha256_hex: String,
}

struct BuiltCaseV1 {
    case: CeremonyContextVectorCaseV1,
    dag: CeremonyValidatedDagV1,
}

struct BuiltContextV1 {
    context: CeremonyPublicRequestContextV1,
    vector: CeremonyPublicRequestContextVectorV1,
}

/// Builds the exact five-case canonical ceremony context corpus.
pub fn canonical_ceremony_context_vector_corpus_v1() -> CeremonyContextVectorCorpusV1 {
    let cases = build_cases();
    CeremonyContextVectorCorpusV1 {
        schema: CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: CEREMONY_CONTEXT_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: cases.into_iter().map(|built| built.case).collect(),
    }
}

/// Returns the sealed coherent DAG for one canonical public-synthetic fixture.
pub fn canonical_ceremony_fixture_dag_v1(kind: CeremonyRequestKindV1) -> CeremonyValidatedDagV1 {
    build_cases()
        .into_iter()
        .find(|built| case_kind(&built.case) == kind)
        .expect("all five canonical ceremony cases exist")
        .dag
}

fn build_cases() -> Vec<BuiltCaseV1> {
    let registration = build_registration_case();
    let activation = build_activation_case(registration.dag);
    vec![
        registration,
        activation,
        build_recovery_case(),
        build_refresh_case(),
        build_export_case(),
    ]
}

fn build_registration_case() -> BuiltCaseV1 {
    let (built, authorization, transcript) = build_registration_fixture();
    let authorization_vector = CeremonyRegistrationAuthorizationVectorV1 {
        authorization_record_digest_hex: repeated_hex(0x31),
        registration_intent_digest_hex: repeated_hex(0x41),
    };
    finish_case(
        CeremonyRequestKindV1::Registration,
        built,
        authorization.into(),
        transcript,
        authorization_vector,
        CeremonyContextVectorCaseV1::Registration,
    )
}

fn build_activation_case(origin: CeremonyValidatedDagV1) -> BuiltCaseV1 {
    let built = build_context(CeremonyRequestKindV1::Activation);
    let authorization_vector = CeremonyActivationAuthorizationVectorV1 {
        authorization_record_digest_hex: repeated_hex(0x32),
        origin_request_kind: origin.request_kind(),
        origin_request_context_digest_hex: encode_hex(origin.request_context_digest().as_bytes()),
        origin_transcript_digest_hex: encode_hex(origin.transcript_digest().as_bytes()),
        package_set_digest_hex: repeated_hex(0x42),
        activation_epoch: 19,
    };
    let authorization = CeremonyActivationAuthorizationV1::new(
        &built.context,
        nonzero_authorization_record(0x32),
        origin
            .activation_origin()
            .expect("registration DAG is an activation origin"),
        CeremonyPackageSetDigest32V1::new([0x42; 32])
            .expect("fixture package-set digest is nonzero"),
        CeremonyActivationEpochV1::new(19).expect("fixture activation epoch is nonzero"),
    )
    .expect("activation context matches authorization");
    let transcript = fixture_transcript(
        CeremonyRequestKindV1::Activation,
        &built.context,
        &authorization.into(),
    );
    finish_case(
        CeremonyRequestKindV1::Activation,
        built,
        authorization.into(),
        transcript,
        authorization_vector,
        CeremonyContextVectorCaseV1::Activation,
    )
}

fn build_recovery_case() -> BuiltCaseV1 {
    let (built, authorization, transcript) = build_recovery_fixture();
    let authorization_vector = CeremonyRecoveryAuthorizationVectorV1 {
        authorization_record_digest_hex: repeated_hex(0x33),
        replacement_credential_binding_digest_hex: repeated_hex(0x43),
    };
    finish_case(
        CeremonyRequestKindV1::Recovery,
        built,
        authorization.into(),
        transcript,
        authorization_vector,
        CeremonyContextVectorCaseV1::Recovery,
    )
}

fn build_refresh_case() -> BuiltCaseV1 {
    let (built, authorization, transcript) = build_refresh_fixture();
    let authorization_vector = CeremonyRefreshAuthorizationVectorV1 {
        authorization_record_digest_hex: repeated_hex(0x34),
        current_deriver_a_input_state_epoch: 41,
        next_deriver_a_input_state_epoch: 42,
        current_deriver_b_input_state_epoch: 51,
        next_deriver_b_input_state_epoch: 53,
    };
    finish_case(
        CeremonyRequestKindV1::Refresh,
        built,
        authorization.into(),
        transcript,
        authorization_vector,
        CeremonyContextVectorCaseV1::Refresh,
    )
}

fn build_export_case() -> BuiltCaseV1 {
    let (built, authorization, transcript) = build_export_fixture();
    let authorization_vector = CeremonyExportAuthorizationVectorV1 {
        authorization_record_digest_hex: repeated_hex(0x35),
        registered_ed25519_public_key_hex: encode_hex(
            authorization.registered_public_key().as_bytes(),
        ),
    };
    finish_case(
        CeremonyRequestKindV1::Export,
        built,
        authorization.into(),
        transcript,
        authorization_vector,
        CeremonyContextVectorCaseV1::Export,
    )
}

fn build_registration_fixture() -> (
    BuiltContextV1,
    CeremonyRegistrationAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let built = build_context(CeremonyRequestKindV1::Registration);
    let authorization = CeremonyRegistrationAuthorizationV1::new(
        &built.context,
        nonzero_authorization_record(0x31),
        CeremonyRegistrationIntentDigest32V1::new([0x41; 32])
            .expect("fixture intent digest is nonzero"),
    )
    .expect("registration context matches authorization");
    let transcript = fixture_transcript(
        CeremonyRequestKindV1::Registration,
        &built.context,
        &authorization.into(),
    );
    (built, authorization, transcript)
}

fn build_recovery_fixture() -> (
    BuiltContextV1,
    CeremonyRecoveryAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let built = build_context(CeremonyRequestKindV1::Recovery);
    let authorization = CeremonyRecoveryAuthorizationV1::new(
        &built.context,
        nonzero_authorization_record(0x33),
        CeremonyReplacementCredentialBindingDigest32V1::new([0x43; 32])
            .expect("fixture credential digest is nonzero"),
    )
    .expect("recovery context matches authorization");
    let transcript = fixture_transcript(
        CeremonyRequestKindV1::Recovery,
        &built.context,
        &authorization.into(),
    );
    (built, authorization, transcript)
}

fn build_refresh_fixture() -> (
    BuiltContextV1,
    CeremonyRefreshAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let built = build_context(CeremonyRequestKindV1::Refresh);
    let authorization = CeremonyRefreshAuthorizationV1::new(
        &built.context,
        nonzero_authorization_record(0x34),
        CeremonyCurrentDeriverAInputStateEpochV1::new(41).expect("nonzero current A epoch"),
        CeremonyNextDeriverAInputStateEpochV1::new(42).expect("nonzero next A epoch"),
        CeremonyCurrentDeriverBInputStateEpochV1::new(51).expect("nonzero current B epoch"),
        CeremonyNextDeriverBInputStateEpochV1::new(53).expect("nonzero next B epoch"),
    )
    .expect("refresh epochs strictly advance");
    let transcript = fixture_transcript(
        CeremonyRequestKindV1::Refresh,
        &built.context,
        &authorization.into(),
    );
    (built, authorization, transcript)
}

fn build_export_fixture() -> (
    BuiltContextV1,
    CeremonyExportAuthorizationV1,
    CeremonyTranscriptV1,
) {
    build_export_fixture_for_key(canonical_registered_public_key_v1())
}

fn build_export_fixture_for_key(
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> (
    BuiltContextV1,
    CeremonyExportAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let built = build_context(CeremonyRequestKindV1::Export);
    let authorization = CeremonyExportAuthorizationV1::new(
        &built.context,
        nonzero_authorization_record(0x35),
        registered_public_key,
    )
    .expect("export context matches authorization");
    let transcript = fixture_transcript(
        CeremonyRequestKindV1::Export,
        &built.context,
        &authorization.into(),
    );
    (built, authorization, transcript)
}

fn fixture_transcript(
    kind: CeremonyRequestKindV1,
    request: &CeremonyPublicRequestContextV1,
    authorization: &CeremonyAuthorizationV1,
) -> CeremonyTranscriptV1 {
    CeremonyTranscriptV1::new(
        request,
        authorization,
        CeremonyTranscriptNonce32V1::new([0x60_u8.wrapping_add(kind.tag()); 32]),
        CeremonyTransportBindingDigest32V1::new([0x70_u8.wrapping_add(kind.tag()); 32])
            .expect("fixture transport digest is nonzero"),
        CeremonyArtifactSuiteDigest32V1::new([0x80_u8.wrapping_add(kind.tag()); 32])
            .expect("fixture artifact digest is nonzero"),
    )
    .expect("fixture transcript DAG is valid")
}

pub(crate) fn canonical_registration_ceremony_fixture_v1() -> (
    CeremonyPublicRequestContextV1,
    CeremonyRegistrationAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let (built, authorization, transcript) = build_registration_fixture();
    (built.context, authorization, transcript)
}

pub(crate) fn canonical_recovery_ceremony_fixture_v1() -> (
    CeremonyPublicRequestContextV1,
    CeremonyRecoveryAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let (built, authorization, transcript) = build_recovery_fixture();
    (built.context, authorization, transcript)
}

pub(crate) fn canonical_refresh_ceremony_fixture_v1() -> (
    CeremonyPublicRequestContextV1,
    CeremonyRefreshAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let (built, authorization, transcript) = build_refresh_fixture();
    (built.context, authorization, transcript)
}

pub(crate) fn canonical_export_ceremony_fixture_v1() -> (
    CeremonyPublicRequestContextV1,
    CeremonyExportAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let (built, authorization, transcript) = build_export_fixture();
    (built.context, authorization, transcript)
}

pub(crate) fn canonical_export_ceremony_fixture_for_registered_key_v1(
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> (
    CeremonyPublicRequestContextV1,
    CeremonyExportAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let (built, authorization, transcript) = build_export_fixture_for_key(registered_public_key);
    (built.context, authorization, transcript)
}

fn finish_case<Authorization, Wrap>(
    kind: CeremonyRequestKindV1,
    built: BuiltContextV1,
    authorization: CeremonyAuthorizationV1,
    transcript: CeremonyTranscriptV1,
    authorization_vector: Authorization,
    wrap: Wrap,
) -> BuiltCaseV1
where
    Wrap: FnOnce(CeremonyCaseVectorV1<Authorization>) -> CeremonyContextVectorCaseV1,
{
    let transcript_vector = CeremonyTranscriptInputVectorV1 {
        transcript_nonce_hex: repeated_hex(0x60_u8.wrapping_add(kind.tag())),
        transport_binding_digest_hex: repeated_hex(0x70_u8.wrapping_add(kind.tag())),
        artifact_suite_digest_hex: repeated_hex(0x80_u8.wrapping_add(kind.tag())),
    };
    let request_encoding = built.context.encode().expect("fixture request encodes");
    let authorization_encoding = authorization
        .encode()
        .expect("fixture authorization encodes");
    let transcript_encoding = transcript.encode().expect("fixture transcript encodes");
    let dag = CeremonyValidatedDagV1::from_components(&built.context, &authorization, &transcript)
        .expect("fixture ceremony DAG is coherent");
    let vector = CeremonyCaseVectorV1 {
        case_id: format!("ceremony-{}-v1", kind.as_str()),
        public_request_context: built.vector,
        authorization: authorization_vector,
        transcript: transcript_vector,
        expected: CeremonyExpectedEncodingsV1 {
            public_request_context_encoding_hex: encode_hex(&request_encoding),
            public_request_context_digest_sha256_hex: encode_hex(
                dag.request_context_digest().as_bytes(),
            ),
            authorization_encoding_hex: encode_hex(&authorization_encoding),
            authorization_digest_sha256_hex: encode_hex(dag.authorization_digest().as_bytes()),
            transcript_encoding_hex: encode_hex(&transcript_encoding),
            transcript_digest_sha256_hex: encode_hex(dag.transcript_digest().as_bytes()),
        },
    };
    BuiltCaseV1 {
        case: wrap(vector),
        dag,
    }
}

fn build_context(kind: CeremonyRequestKindV1) -> BuiltContextV1 {
    let tag = kind.tag();
    let request_id = format!("request-{}-001", kind.as_str());
    let session_id = format!("session-{}-001", kind.as_str());
    let recipient_plan = match kind {
        CeremonyRequestKindV1::Registration
        | CeremonyRequestKindV1::Recovery
        | CeremonyRequestKindV1::Refresh => "activation_family",
        CeremonyRequestKindV1::Activation => "activation_continuation",
        CeremonyRequestKindV1::Export => "export",
    };
    let output_package_kind = match kind {
        CeremonyRequestKindV1::Registration
        | CeremonyRequestKindV1::Activation
        | CeremonyRequestKindV1::Recovery
        | CeremonyRequestKindV1::Refresh => "activation_scalar_shares",
        CeremonyRequestKindV1::Export => "export_seed_shares",
    };
    let vector = CeremonyPublicRequestContextVectorV1 {
        protocol_version: 1,
        request_id: request_id.clone(),
        replay_nonce_hex: repeated_hex(0x10_u8.wrapping_add(tag)),
        account_id: "account-fixture".to_owned(),
        wallet_id: "wallet-fixture".to_owned(),
        session_id: session_id.clone(),
        organization_id: "organization-fixture".to_owned(),
        project_id: "project-fixture".to_owned(),
        environment_id: "environment-fixture".to_owned(),
        signing_root_id: "project-fixture:environment-fixture".to_owned(),
        signing_root_version: 3,
        chain_target: "near:testnet".to_owned(),
        root_share_epoch: 7,
        router_id: "router-fixture".to_owned(),
        deriver_set_id: "deriver-set-fixture".to_owned(),
        deriver_a_id: "deriver-a-fixture".to_owned(),
        deriver_a_key_epoch: 11,
        deriver_b_id: "deriver-b-fixture".to_owned(),
        deriver_b_key_epoch: 13,
        signing_worker_id: "signing-worker-fixture".to_owned(),
        signing_worker_key_epoch: 17,
        client_ephemeral_public_key_hex: repeated_hex(0x20_u8.wrapping_add(tag)),
        recipient_plan: recipient_plan.to_owned(),
        output_package_kind: output_package_kind.to_owned(),
        request_expiry: 2_000_000 + u64::from(tag),
    };
    let identity_scope = CeremonyIdentityScopeV1::new(
        CeremonyAccountIdV1::parse(&vector.account_id).expect("fixture account is valid"),
        CeremonyWalletIdV1::parse(&vector.wallet_id).expect("fixture wallet is valid"),
        CeremonySessionIdV1::parse(&session_id).expect("fixture session is valid"),
        CeremonyOrganizationIdV1::parse(&vector.organization_id)
            .expect("fixture organization is valid"),
        CeremonyProjectIdV1::parse(&vector.project_id).expect("fixture project is valid"),
        CeremonyEnvironmentIdV1::parse(&vector.environment_id)
            .expect("fixture environment is valid"),
        CeremonySigningRootIdV1::parse(&vector.signing_root_id)
            .expect("fixture signing root is valid"),
        CeremonySigningRootVersionV1::new(vector.signing_root_version)
            .expect("fixture signing-root version is nonzero"),
        CeremonyChainTargetV1::parse(&vector.chain_target).expect("fixture chain is valid"),
    );
    let infrastructure = CeremonyInfrastructureV1::new(
        CeremonyRouterIdV1::parse(&vector.router_id).expect("fixture Router id is valid"),
        CeremonyDeriverSetIdV1::parse(&vector.deriver_set_id)
            .expect("fixture Deriver-set id is valid"),
        CeremonyDeriverABindingV1::new(
            CeremonyDeriverAIdV1::parse(&vector.deriver_a_id).expect("fixture A id is valid"),
            CeremonyDeriverAKeyEpochV1::new(vector.deriver_a_key_epoch)
                .expect("fixture A key epoch is nonzero"),
        ),
        CeremonyDeriverBBindingV1::new(
            CeremonyDeriverBIdV1::parse(&vector.deriver_b_id).expect("fixture B id is valid"),
            CeremonyDeriverBKeyEpochV1::new(vector.deriver_b_key_epoch)
                .expect("fixture B key epoch is nonzero"),
        ),
        CeremonySigningWorkerBindingV1::new(
            CeremonySigningWorkerIdV1::parse(&vector.signing_worker_id)
                .expect("fixture SigningWorker id is valid"),
            CeremonySigningWorkerKeyEpochV1::new(vector.signing_worker_key_epoch)
                .expect("fixture SigningWorker key epoch is nonzero"),
        ),
    );
    let context = CeremonyPublicRequestContextV1::new(
        kind,
        CeremonyRequestIdV1::parse(&request_id).expect("fixture request id is valid"),
        CeremonyReplayNonce32V1::new([0x10_u8.wrapping_add(tag); 32]),
        identity_scope,
        CeremonyRootShareEpochV1::new(vector.root_share_epoch)
            .expect("fixture root-share epoch is nonzero"),
        infrastructure,
        CeremonyClientEphemeralPublicKey32V1::new([0x20_u8.wrapping_add(tag); 32]),
        CeremonyRequestExpiryV1::new(vector.request_expiry)
            .expect("fixture request expiry is nonzero"),
    );
    BuiltContextV1 { context, vector }
}

fn nonzero_authorization_record(byte: u8) -> CeremonyAuthorizationRecordDigest32V1 {
    CeremonyAuthorizationRecordDigest32V1::new([byte; 32])
        .expect("fixture authorization-record digest is nonzero")
}

fn case_kind(case: &CeremonyContextVectorCaseV1) -> CeremonyRequestKindV1 {
    match case {
        CeremonyContextVectorCaseV1::Registration(_) => CeremonyRequestKindV1::Registration,
        CeremonyContextVectorCaseV1::Activation(_) => CeremonyRequestKindV1::Activation,
        CeremonyContextVectorCaseV1::Recovery(_) => CeremonyRequestKindV1::Recovery,
        CeremonyContextVectorCaseV1::Refresh(_) => CeremonyRequestKindV1::Refresh,
        CeremonyContextVectorCaseV1::Export(_) => CeremonyRequestKindV1::Export,
    }
}

fn repeated_hex(byte: u8) -> String {
    encode_hex(&[byte; 32])
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
