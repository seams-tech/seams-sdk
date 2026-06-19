use rand_core::{CryptoRng, Error as RandError, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::candidate_mpc_prf::{
    MpcPrfDleqProofWireV1, MpcPrfOutputRequestV1, MpcPrfPartialProofBundleV1,
    MpcPrfPartialVerificationInputV1, MpcPrfSignerPartialInputV1, MpcPrfSuiteId,
};
use crate::derivation::candidate_mpc_prf_threshold_backend::{
    combine_mpc_prf_proof_bundles_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_partial_with_threshold_backend_v1,
    verify_mpc_prf_partial_with_threshold_backend_v1, MpcPrfSigningRootShareWireV1,
    MpcPrfThresholdCombineInputV1, MpcPrfThresholdSignerInputV1,
};
use crate::derivation::context::{
    context_digest_v1, AccountScope, CandidateId, CorrectnessLevel, DerivationContext, RequestKind,
    RootShareEpoch,
};
use crate::derivation::diagnostics::redacted_diagnostic;
use crate::derivation::envelope::{
    envelope_aad_v1, envelope_idempotency_key_v1, package_commitment_v1, ContentKind,
    DeliveryPackageV1, EnvelopeHeaderV1, EnvelopeKind, EnvelopeVersion,
};
use crate::derivation::error::{
    RedactedDiagnostic, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult,
};
use crate::derivation::evidence::{
    verify_minimum_level_c_v1, AcceptedReplayCacheDecisionV1, AuthenticatedSignerReceiptV1,
    MinimumLevelCEvidenceV1, MinimumLevelCVerificationInputV1, SignerReceiptVersion,
};
use crate::derivation::material::{OpenedShareKind, PublicDigest32, Role};
use crate::derivation::scope::RefreshScope;
use crate::derivation::transcript::{
    transcript_digest_v1, IndexedSignerBinding, QuorumPolicy, SignerSetBinding, TranscriptBinding,
};

/// Current JSON vector fixture version.
pub const VECTOR_VERSION_V1: &str = "router_ab_split_derivation_candidates_v1";
/// Current generated contract vector corpus version.
pub const CONTRACT_VECTOR_VERSION_V1: &str = "router_ab_core_contract_vectors_v1";
const VECTOR_ROUTER_ID: &str = "role:router:local:sha256-router";
const VECTOR_SIGNER_SET_ID: &str = "signer-set-v1";
const VECTOR_SIGNER_A_ID: &str = "role:signer-a:local:sha256-a";
const VECTOR_SIGNER_B_ID: &str = "role:signer-b:local:sha256-b";
const VECTOR_SIGNER_A_KEY_EPOCH: &str = "key-epoch-a-1";
const VECTOR_SIGNER_B_KEY_EPOCH: &str = "key-epoch-b-1";
const VECTOR_SERVER_ID: &str = "role:server:local:sha256-r";
const VECTOR_SERVER_RECIPIENT_ENCRYPTION_KEY: &str =
    "x25519:1111111111111111111111111111111111111111111111111111111111111111";
const VECTOR_CLIENT_ID: &str = "role:client:local:sha256-c";
const VECTOR_CLIENT_EPHEMERAL_PUBLIC_KEY: &str = "x25519:client-ephemeral-public-key";

/// Top-level split-derivation vector fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationVectorFixtureV1 {
    /// Fixture format version.
    pub vector_version: String,
    /// Fixture cases.
    pub cases: Vec<DerivationVectorCaseV1>,
}

/// One split-derivation vector case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationVectorCaseV1 {
    /// Stable case identifier.
    pub case_id: String,
    /// Candidate family under test.
    pub candidate_id: CandidateId,
    /// Request kind under test.
    pub request_kind: RequestKind,
    /// Output correctness level under test.
    pub correctness_level: CorrectnessLevel,
    /// Network namespace.
    pub network_id: String,
    /// Account identifier.
    pub account_id: String,
    /// Canonical account public key string.
    pub account_public_key: String,
    /// Root share epoch.
    pub root_share_epoch: String,
    /// Ceremony identifier.
    pub ceremony_id: String,
    /// Expected context digest encoded as lowercase hex, once committed.
    pub expected_context_digest_hex: String,
    /// Expected transcript digest encoded as lowercase hex, once committed.
    pub expected_transcript_digest_hex: String,
}

/// Generated contract vector corpus for metadata-only scaffolding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVectorCorpusV1 {
    /// Corpus version.
    pub vector_version: String,
    /// Context and transcript vectors.
    pub context_transcripts: Vec<ContextTranscriptVectorV1>,
    /// Envelope vector.
    pub envelope: EnvelopeVectorV1,
    /// Minimum Level C vectors.
    pub minimum_level_c_cases: Vec<MinimumLevelCVectorV1>,
    /// Candidate-output decision-gate vectors.
    pub candidate_output_cases: Vec<CandidateOutputVectorV1>,
    /// Candidate A backend success vectors.
    pub mpc_threshold_prf_backend_cases: Vec<MpcThresholdPrfBackendVectorV1>,
    /// Candidate A backend rejection vectors.
    pub mpc_threshold_prf_backend_rejection_cases: Vec<RejectionVectorV1>,
    /// Diagnostic vector.
    pub diagnostic: DiagnosticVectorV1,
    /// Rejection vectors for stable public error-code contracts.
    pub rejection_cases: Vec<RejectionVectorV1>,
}

/// Context and transcript digest vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextTranscriptVectorV1 {
    /// Case identifier.
    pub case_id: String,
    /// Candidate family.
    pub candidate_id: CandidateId,
    /// Request kind.
    pub request_kind: RequestKind,
    /// Root-share epoch.
    pub root_share_epoch: String,
    /// Expected context digest in lowercase hex.
    pub context_digest_hex: String,
    /// Expected transcript digest in lowercase hex.
    pub transcript_digest_hex: String,
    /// Signer-set id bound into the transcript.
    pub signer_set_id: String,
    /// Quorum policy bound into the transcript.
    pub quorum_policy: String,
    /// Selected server identity.
    pub selected_server_id: String,
}

/// Envelope commitment vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeVectorV1 {
    /// Case identifier.
    pub case_id: String,
    /// Envelope AAD bytes encoded as lowercase hex.
    pub aad_hex: String,
    /// Delivery package commitment encoded as lowercase hex.
    pub package_commitment_hex: String,
    /// Envelope idempotency key encoded as lowercase hex.
    pub idempotency_key_hex: String,
}

/// Minimum Level C acceptance vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimumLevelCVectorV1 {
    /// Case identifier.
    pub case_id: String,
    /// Verified evidence.
    pub evidence: MinimumLevelCEvidenceV1,
}

/// Candidate output decision-gate vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateOutputVectorV1 {
    /// Case identifier.
    pub case_id: String,
    /// Candidate family.
    pub candidate_id: CandidateId,
    /// Request kind.
    pub request_kind: RequestKind,
    /// Digest of the candidate context.
    pub context_digest_hex: String,
    /// Digest of the candidate transcript.
    pub transcript_digest_hex: String,
    /// Opened-share kind the future candidate output is scoped to.
    pub opened_share_kind: OpenedShareKind,
    /// Current decision-gate error code.
    pub expected_error_code: RouterAbDerivationErrorCode,
}

/// Candidate A backend vector containing proof-bundle and combined-output wires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcThresholdPrfBackendVectorV1 {
    /// Case identifier.
    pub case_id: String,
    /// Request kind under test.
    pub request_kind: RequestKind,
    /// Opened-share kind under test.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Digest of the candidate context.
    pub context_digest_hex: String,
    /// Digest of the candidate transcript.
    pub transcript_digest_hex: String,
    /// Signer A fixed-width partial wire.
    pub signer_a_partial_wire_hex: String,
    /// Signer A fixed-width share commitment wire.
    pub signer_a_commitment_wire_hex: String,
    /// Signer A fixed-width DLEQ proof wire.
    pub signer_a_proof_wire_hex: String,
    /// Signer B fixed-width partial wire.
    pub signer_b_partial_wire_hex: String,
    /// Signer B fixed-width share commitment wire.
    pub signer_b_commitment_wire_hex: String,
    /// Signer B fixed-width DLEQ proof wire.
    pub signer_b_proof_wire_hex: String,
    /// Recipient-local combined output material.
    pub combined_output_hex: String,
}

/// Redacted diagnostic vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticVectorV1 {
    /// Case identifier.
    pub case_id: String,
    /// Stable error code.
    pub error_code: RouterAbDerivationErrorCode,
    /// Redacted diagnostic metadata.
    pub redacted_diagnostic: RedactedDiagnostic,
}

/// Rejection vector for one stable public error-code contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectionVectorV1 {
    /// Case identifier.
    pub case_id: String,
    /// Error code expected for the rejected public input.
    pub expected_error_code: RouterAbDerivationErrorCode,
}

/// Generates the deterministic V1 contract vector corpus.
pub fn generated_contract_vectors_v1() -> RouterAbDerivationResult<ContractVectorCorpusV1> {
    let context = sample_context()?;
    let transcript = sample_transcript(context.clone())?;
    let transcript_digest = transcript_digest_v1(&transcript)?;
    let export_context = sample_context_for(
        CandidateId::MpcThresholdPrfV1,
        RequestKind::Export,
        "epoch-1",
        "ceremony-export-1",
    )?;
    let export_transcript = sample_transcript(export_context.clone())?;
    let refresh_context = sample_context_for(
        CandidateId::MpcThresholdPrfV1,
        RequestKind::Refresh,
        "epoch-2",
        "ceremony-refresh-1",
    )?;
    let refresh_transcript = sample_transcript(refresh_context.clone())?;

    let context_transcripts = vec![
        sample_context_transcript_vector(
            "context_transcript_registration_v1",
            context.clone(),
            transcript.clone(),
        )?,
        sample_context_transcript_vector(
            "context_transcript_export_v1",
            export_context.clone(),
            export_transcript.clone(),
        )?,
        sample_context_transcript_vector(
            "context_transcript_refresh_v1",
            refresh_context.clone(),
            refresh_transcript.clone(),
        )?,
    ];

    let envelope_package = sample_delivery_package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerAToClient,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Client,
        "role:client:local:sha256-c",
        ContentKind::ClientOutputShare,
        deterministic_public_digest("envelope/a-client-ciphertext", 0),
    )?;

    let envelope = EnvelopeVectorV1 {
        case_id: "envelope_a_to_client_v1".to_owned(),
        aad_hex: hex::encode(envelope_aad_v1(envelope_package.header())?),
        package_commitment_hex: digest_hex(package_commitment_v1(&envelope_package)?),
        idempotency_key_hex: digest_hex(envelope_idempotency_key_v1(envelope_package.header())?),
    };

    let minimum_level_c_cases = vec![
        MinimumLevelCVectorV1 {
            case_id: "minimum_level_c_accept_registration_v1".to_owned(),
            evidence: sample_minimum_level_c_evidence(context.clone(), transcript.clone())?,
        },
        MinimumLevelCVectorV1 {
            case_id: "minimum_level_c_accept_export_v1".to_owned(),
            evidence: sample_minimum_level_c_evidence(export_context, export_transcript)?,
        },
        MinimumLevelCVectorV1 {
            case_id: "minimum_level_c_accept_refresh_v1".to_owned(),
            evidence: sample_minimum_level_c_evidence(refresh_context, refresh_transcript)?,
        },
    ];

    let diagnostic = DiagnosticVectorV1 {
        case_id: "diagnostic_transcript_mismatch_v1".to_owned(),
        error_code: RouterAbDerivationErrorCode::TranscriptMismatch,
        redacted_diagnostic: redacted_diagnostic(&RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "transcript mismatch",
        )),
    };
    let candidate_output_cases = sample_candidate_output_vectors()?;
    let mpc_threshold_prf_backend_cases = sample_mpc_threshold_prf_backend_vectors()?;
    let mpc_threshold_prf_backend_rejection_cases =
        sample_mpc_threshold_prf_backend_rejection_vectors()?;
    let rejection_cases = sample_rejection_vectors(&context, &transcript)?;

    Ok(ContractVectorCorpusV1 {
        vector_version: CONTRACT_VECTOR_VERSION_V1.to_owned(),
        context_transcripts,
        envelope,
        minimum_level_c_cases,
        candidate_output_cases,
        mpc_threshold_prf_backend_cases,
        mpc_threshold_prf_backend_rejection_cases,
        diagnostic,
        rejection_cases,
    })
}

/// Generates the deterministic V1 contract vector corpus as pretty JSON.
pub fn generated_contract_vectors_json_v1() -> RouterAbDerivationResult<String> {
    serde_json::to_string_pretty(&generated_contract_vectors_v1()?).map_err(|err| {
        RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("failed to serialize generated contract vectors: {err}"),
        )
    })
}

/// Parses and validates a V1 derivation-vector fixture.
pub fn parse_vector_fixture_v1(json: &str) -> RouterAbDerivationResult<DerivationVectorFixtureV1> {
    let fixture: DerivationVectorFixtureV1 = serde_json::from_str(json).map_err(|err| {
        RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("invalid derivation vector fixture: {err}"),
        )
    })?;
    validate_vector_fixture_v1(&fixture)?;
    Ok(fixture)
}

/// Builds the canonical context committed by one V1 vector case.
pub fn vector_case_context_v1(
    case: &DerivationVectorCaseV1,
) -> RouterAbDerivationResult<DerivationContext> {
    DerivationContext::new(
        case.candidate_id,
        case.request_kind,
        case.correctness_level,
        AccountScope::new(
            case.network_id.clone(),
            case.account_id.clone(),
            case.account_public_key.clone(),
        )?,
        RootShareEpoch::new(case.root_share_epoch.clone())?,
        case.ceremony_id.clone(),
    )
}

/// Builds the canonical local transcript committed by V1 vector cases.
pub fn vector_case_transcript_v1(
    context: DerivationContext,
) -> RouterAbDerivationResult<TranscriptBinding> {
    TranscriptBinding::new(
        context,
        VECTOR_ROUTER_ID,
        SignerSetBinding::v1_all2(
            VECTOR_SIGNER_SET_ID,
            VECTOR_SIGNER_A_ID,
            VECTOR_SIGNER_A_KEY_EPOCH,
            VECTOR_SIGNER_B_ID,
            VECTOR_SIGNER_B_KEY_EPOCH,
        )?,
        VECTOR_SERVER_ID,
        VECTOR_SERVER_RECIPIENT_ENCRYPTION_KEY,
        VECTOR_CLIENT_ID,
        VECTOR_CLIENT_EPHEMERAL_PUBLIC_KEY,
    )
}

/// Validates a parsed V1 derivation-vector fixture.
pub fn validate_vector_fixture_v1(
    fixture: &DerivationVectorFixtureV1,
) -> RouterAbDerivationResult<()> {
    if fixture.vector_version != VECTOR_VERSION_V1 {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedVectorVersion,
            format!("unsupported vector version: {}", fixture.vector_version),
        ));
    }

    if fixture.cases.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "fixture must contain at least one case",
        ));
    }

    for case in &fixture.cases {
        require_non_empty("case_id", &case.case_id)?;
        require_non_empty("network_id", &case.network_id)?;
        require_non_empty("account_id", &case.account_id)?;
        require_non_empty("account_public_key", &case.account_public_key)?;
        require_non_empty("root_share_epoch", &case.root_share_epoch)?;
        require_non_empty("ceremony_id", &case.ceremony_id)?;
        let context = vector_case_context_v1(case)?;
        let expected_context_digest = digest_hex(context_digest_v1(&context)?);
        require_committed_digest_hex(
            "expected_context_digest_hex",
            &case.expected_context_digest_hex,
            &expected_context_digest,
        )?;

        let transcript = vector_case_transcript_v1(context)?;
        let expected_transcript_digest = digest_hex(transcript_digest_v1(&transcript)?);
        require_committed_digest_hex(
            "expected_transcript_digest_hex",
            &case.expected_transcript_digest_hex,
            &expected_transcript_digest,
        )?;
    }

    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} is required in vector fixture"),
        ));
    }
    Ok(())
}

fn require_committed_digest_hex(
    field: &'static str,
    actual: &str,
    expected: &str,
) -> RouterAbDerivationResult<()> {
    let is_lower_hex = actual
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if actual.len() != 64 || !is_lower_hex {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} must be committed lowercase hex"),
        ));
    }

    if actual != expected {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            format!("{field} does not match committed digest; expected {expected}"),
        ));
    }

    Ok(())
}

fn sample_context() -> RouterAbDerivationResult<DerivationContext> {
    sample_context_for(
        CandidateId::MpcThresholdPrfV1,
        RequestKind::Registration,
        "epoch-1",
        "ceremony-1",
    )
}

fn sample_context_for(
    candidate_id: CandidateId,
    request_kind: RequestKind,
    root_share_epoch: &str,
    ceremony_id: &str,
) -> RouterAbDerivationResult<DerivationContext> {
    DerivationContext::new(
        candidate_id,
        request_kind,
        CorrectnessLevel::MinimumLevelC,
        AccountScope::new(
            "near-testnet",
            "alice.testnet",
            "ed25519:11111111111111111111111111111111",
        )?,
        RootShareEpoch::new(root_share_epoch)?,
        ceremony_id,
    )
}

fn sample_transcript(context: DerivationContext) -> RouterAbDerivationResult<TranscriptBinding> {
    vector_case_transcript_v1(context)
}

fn sample_context_transcript_vector(
    case_id: &str,
    context: DerivationContext,
    transcript: TranscriptBinding,
) -> RouterAbDerivationResult<ContextTranscriptVectorV1> {
    Ok(ContextTranscriptVectorV1 {
        case_id: case_id.to_owned(),
        candidate_id: context.candidate_id(),
        request_kind: context.request_kind(),
        root_share_epoch: context.root_share_epoch().as_str().to_owned(),
        context_digest_hex: digest_hex(context_digest_v1(&context)?),
        transcript_digest_hex: digest_hex(transcript_digest_v1(&transcript)?),
        signer_set_id: transcript.signer_set().signer_set_id().to_owned(),
        quorum_policy: transcript
            .signer_set()
            .quorum_policy()
            .as_canonical_string(),
        selected_server_id: transcript.selected_server_id().to_owned(),
    })
}

fn sample_candidate_output_vectors() -> RouterAbDerivationResult<Vec<CandidateOutputVectorV1>> {
    let mut vectors = Vec::new();
    for request_kind in [
        RequestKind::Registration,
        RequestKind::Export,
        RequestKind::Refresh,
    ] {
        vectors.push(sample_candidate_output_vector(
            CandidateId::MpcThresholdPrfV1,
            request_kind,
        )?);
    }
    Ok(vectors)
}

fn sample_candidate_output_vector(
    candidate_id: CandidateId,
    request_kind: RequestKind,
) -> RouterAbDerivationResult<CandidateOutputVectorV1> {
    let context = sample_context_for(
        candidate_id,
        request_kind,
        candidate_vector_epoch(request_kind),
        &format!(
            "candidate-{}-{}-1",
            candidate_id.as_str(),
            request_kind.as_str()
        ),
    )?;
    let transcript = sample_transcript(context.clone())?;
    let expected_error_code =
        expected_candidate_gate_error(candidate_id, context.clone(), transcript.clone())?;

    Ok(CandidateOutputVectorV1 {
        case_id: format!(
            "candidate_output_gate_{}_{}_v1",
            candidate_id.as_str(),
            request_kind.as_str()
        ),
        candidate_id,
        request_kind,
        context_digest_hex: digest_hex(context_digest_v1(&context)?),
        transcript_digest_hex: digest_hex(transcript_digest_v1(&transcript)?),
        opened_share_kind: OpenedShareKind::XClientBase,
        expected_error_code,
    })
}

fn expected_candidate_gate_error(
    _candidate_id: CandidateId,
    context: DerivationContext,
    transcript: TranscriptBinding,
) -> RouterAbDerivationResult<RouterAbDerivationErrorCode> {
    let result = disabled_candidate_gate_error(
        context,
        transcript,
        "mpc_threshold_prf_v1 candidate-level output gate is disabled; use proof-bundle backend APIs",
    );

    match result {
        Ok(()) => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "candidate output gate vector unexpectedly succeeded",
        )),
        Err(err) => Ok(err.code()),
    }
}

fn disabled_candidate_gate_error(
    context: DerivationContext,
    transcript: TranscriptBinding,
    message: &'static str,
) -> RouterAbDerivationResult<()> {
    context.validate()?;
    transcript.validate()?;
    Err(RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::NotImplemented,
        message,
    ))
}

fn candidate_vector_epoch(request_kind: RequestKind) -> &'static str {
    match request_kind {
        RequestKind::Registration | RequestKind::Export => "epoch-1",
        RequestKind::Refresh => "epoch-2",
    }
}

fn sample_mpc_threshold_prf_backend_vectors(
) -> RouterAbDerivationResult<Vec<MpcThresholdPrfBackendVectorV1>> {
    let mut vectors = Vec::new();
    for request_kind in [
        RequestKind::Registration,
        RequestKind::Export,
        RequestKind::Refresh,
    ] {
        for opened_share_kind in [OpenedShareKind::XClientBase, OpenedShareKind::XServerBase] {
            vectors.push(sample_mpc_threshold_prf_backend_vector(
                request_kind,
                opened_share_kind,
            )?);
        }
    }
    Ok(vectors)
}

fn sample_mpc_threshold_prf_backend_vector(
    request_kind: RequestKind,
    opened_share_kind: OpenedShareKind,
) -> RouterAbDerivationResult<MpcThresholdPrfBackendVectorV1> {
    let (context, transcript, bundle_a, bundle_b) =
        sample_mpc_threshold_prf_backend_bundles(request_kind, opened_share_kind)?;
    let request = mpc_output_request(opened_share_kind)?;
    let combined =
        combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
            transcript: transcript.clone(),
            opened_share_kind,
            recipient_role: request.recipient_role,
            recipient_identity: request.recipient_identity.clone(),
            left: bundle_a.clone(),
            right: bundle_b.clone(),
        })?;

    Ok(MpcThresholdPrfBackendVectorV1 {
        case_id: format!(
            "mpc_threshold_prf_backend_{}_{}_v1",
            request_kind.as_str(),
            opened_share_kind.as_str()
        ),
        request_kind,
        opened_share_kind,
        recipient_role: request.recipient_role,
        recipient_identity: request.recipient_identity,
        context_digest_hex: digest_hex(context_digest_v1(&context)?),
        transcript_digest_hex: digest_hex(transcript_digest_v1(&transcript)?),
        signer_a_partial_wire_hex: hex::encode(bundle_a.signer_partial.partial_wire.as_bytes()),
        signer_a_commitment_wire_hex: hex::encode(bundle_a.commitment_wire.as_bytes()),
        signer_a_proof_wire_hex: hex::encode(bundle_a.proof_wire.as_bytes()),
        signer_b_partial_wire_hex: hex::encode(bundle_b.signer_partial.partial_wire.as_bytes()),
        signer_b_commitment_wire_hex: hex::encode(bundle_b.commitment_wire.as_bytes()),
        signer_b_proof_wire_hex: hex::encode(bundle_b.proof_wire.as_bytes()),
        combined_output_hex: hex::encode(combined.output_material.as_bytes()),
    })
}

fn sample_mpc_threshold_prf_backend_rejection_vectors(
) -> RouterAbDerivationResult<Vec<RejectionVectorV1>> {
    let request_kind = RequestKind::Registration;
    let opened_share_kind = OpenedShareKind::XClientBase;
    let (context, transcript, bundle_a, bundle_b) =
        sample_mpc_threshold_prf_backend_bundles(request_kind, opened_share_kind)?;
    let request = mpc_output_request(opened_share_kind)?;

    let bad_proof = MpcPrfPartialProofBundleV1::new(
        bundle_a.signer_partial.clone(),
        bundle_a.commitment_wire.clone(),
        MpcPrfDleqProofWireV1::new(vec![0; 64])?,
    )?;

    let mismatched_transcript = TranscriptBinding::new(
        context.clone(),
        "role:router:local:sha256-other",
        transcript.signer_set().clone(),
        transcript.selected_server_id(),
        transcript.selected_server_recipient_encryption_key(),
        transcript.client_id(),
        transcript.client_ephemeral_public_key(),
    )?;

    let mut wrong_epoch_signer = mpc_signer_input(
        context.clone(),
        transcript.clone(),
        Role::SignerA,
        VECTOR_SIGNER_A_ID,
    )?;
    wrong_epoch_signer.root_share_epoch = RootShareEpoch::new("epoch-wrong")?;

    Ok(vec![
        expect_rejection_code(
            "mpc_threshold_prf_backend_bad_dleq_proof_v1",
            verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
                transcript: transcript.clone(),
                proof_bundle: bad_proof,
            }),
        )?,
        expect_rejection_code(
            "mpc_threshold_prf_backend_transcript_mismatch_v1",
            verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
                transcript: mismatched_transcript,
                proof_bundle: bundle_a.clone(),
            }),
        )?,
        expect_rejection_code(
            "mpc_threshold_prf_backend_duplicate_signer_role_v1",
            combine_mpc_prf_proof_bundles_with_threshold_backend_v1(
                MpcPrfThresholdCombineInputV1 {
                    transcript: transcript.clone(),
                    opened_share_kind,
                    recipient_role: request.recipient_role,
                    recipient_identity: request.recipient_identity.clone(),
                    left: bundle_a.clone(),
                    right: bundle_a.clone(),
                },
            ),
        )?,
        expect_rejection_code(
            "mpc_threshold_prf_backend_recipient_mismatch_v1",
            combine_mpc_prf_proof_bundles_with_threshold_backend_v1(
                MpcPrfThresholdCombineInputV1 {
                    transcript: transcript.clone(),
                    opened_share_kind,
                    recipient_role: request.recipient_role,
                    recipient_identity: "role:client:local:sha256-wrong".to_owned(),
                    left: bundle_a.clone(),
                    right: bundle_b.clone(),
                },
            ),
        )?,
        expect_rejection_code(
            "mpc_threshold_prf_backend_wrong_share_id_v1",
            evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
                MpcPrfThresholdSignerInputV1 {
                    signer_input: mpc_signer_input(
                        context.clone(),
                        transcript.clone(),
                        Role::SignerA,
                        VECTOR_SIGNER_A_ID,
                    )?,
                    output_request: request.clone(),
                    signing_root_share_wire: fixed_mpc_signing_root_share_wire(Role::SignerB)?,
                },
                &mut DeterministicVectorRng::new("mpc-threshold-prf/reject/wrong-share-id"),
            ),
        )?,
        expect_rejection_code(
            "mpc_threshold_prf_backend_wrong_root_epoch_v1",
            evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
                MpcPrfThresholdSignerInputV1 {
                    signer_input: wrong_epoch_signer,
                    output_request: request,
                    signing_root_share_wire: fixed_mpc_signing_root_share_wire(Role::SignerA)?,
                },
                &mut DeterministicVectorRng::new("mpc-threshold-prf/reject/wrong-root-epoch"),
            ),
        )?,
    ])
}

fn sample_mpc_threshold_prf_backend_bundles(
    request_kind: RequestKind,
    opened_share_kind: OpenedShareKind,
) -> RouterAbDerivationResult<(
    DerivationContext,
    TranscriptBinding,
    MpcPrfPartialProofBundleV1,
    MpcPrfPartialProofBundleV1,
)> {
    let context = sample_context_for(
        CandidateId::MpcThresholdPrfV1,
        request_kind,
        candidate_vector_epoch(request_kind),
        &format!(
            "mpc-threshold-prf-backend-{}-{}-1",
            request_kind.as_str(),
            opened_share_kind.as_str()
        ),
    )?;
    let transcript = sample_transcript(context.clone())?;
    let request = mpc_output_request(opened_share_kind)?;
    let signer_a = mpc_signer_input(
        context.clone(),
        transcript.clone(),
        Role::SignerA,
        VECTOR_SIGNER_A_ID,
    )?;
    let signer_b = mpc_signer_input(
        context.clone(),
        transcript.clone(),
        Role::SignerB,
        VECTOR_SIGNER_B_ID,
    )?;

    let bundle_a = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_a,
            output_request: request.clone(),
            signing_root_share_wire: fixed_mpc_signing_root_share_wire(Role::SignerA)?,
        },
        &mut DeterministicVectorRng::new(format!(
            "mpc-threshold-prf/{}/{}/signer-a-proof",
            request_kind.as_str(),
            opened_share_kind.as_str()
        )),
    )?;
    let bundle_b = evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
        MpcPrfThresholdSignerInputV1 {
            signer_input: signer_b,
            output_request: request,
            signing_root_share_wire: fixed_mpc_signing_root_share_wire(Role::SignerB)?,
        },
        &mut DeterministicVectorRng::new(format!(
            "mpc-threshold-prf/{}/{}/signer-b-proof",
            request_kind.as_str(),
            opened_share_kind.as_str()
        )),
    )?;
    Ok((context, transcript, bundle_a, bundle_b))
}

fn mpc_signer_input(
    context: DerivationContext,
    transcript: TranscriptBinding,
    signer_role: Role,
    signer_identity: &str,
) -> RouterAbDerivationResult<MpcPrfSignerPartialInputV1> {
    MpcPrfSignerPartialInputV1::new(
        context.clone(),
        transcript,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512,
        signer_role,
        signer_identity,
        context.root_share_epoch().clone(),
        vec![
            mpc_output_request(OpenedShareKind::XClientBase)?,
            mpc_output_request(OpenedShareKind::XServerBase)?,
        ],
    )
}

fn mpc_output_request(
    opened_share_kind: OpenedShareKind,
) -> RouterAbDerivationResult<MpcPrfOutputRequestV1> {
    match opened_share_kind {
        OpenedShareKind::XClientBase => {
            MpcPrfOutputRequestV1::new(OpenedShareKind::XClientBase, Role::Client, VECTOR_CLIENT_ID)
        }
        OpenedShareKind::XServerBase => {
            MpcPrfOutputRequestV1::new(OpenedShareKind::XServerBase, Role::Server, VECTOR_SERVER_ID)
        }
    }
}

fn fixed_mpc_signing_root_share_wire(
    signer_role: Role,
) -> RouterAbDerivationResult<MpcPrfSigningRootShareWireV1> {
    let (share_id, scalar_byte) = match signer_role {
        Role::SignerA => (1u16, 11u8),
        Role::SignerB => (3u16, 29u8),
        _ => {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "fixed MPC PRF vector share requires signer role",
            ));
        }
    };
    let mut bytes = vec![0u8; 34];
    bytes[0..2].copy_from_slice(&share_id.to_be_bytes());
    bytes[2] = scalar_byte;
    MpcPrfSigningRootShareWireV1::new(bytes)
}

fn sample_delivery_package(
    context: &DerivationContext,
    transcript_digest: PublicDigest32,
    envelope_kind: EnvelopeKind,
    sender_role: Role,
    sender_identity: &str,
    recipient_role: Role,
    recipient_identity: &str,
    content_kind: ContentKind,
    ciphertext_digest: PublicDigest32,
) -> RouterAbDerivationResult<DeliveryPackageV1> {
    DeliveryPackageV1::new(EnvelopeHeaderV1::new(
        EnvelopeVersion::V1,
        envelope_kind,
        context.candidate_id(),
        context.request_kind(),
        context.correctness_level(),
        context.ceremony_id().to_owned(),
        context.root_share_epoch().clone(),
        transcript_digest,
        sender_role,
        sender_identity,
        recipient_role,
        recipient_identity,
        content_kind,
        ciphertext_digest,
        128,
    )?)
}

fn sample_minimum_level_c_evidence(
    context: DerivationContext,
    transcript: TranscriptBinding,
) -> RouterAbDerivationResult<MinimumLevelCEvidenceV1> {
    Ok(
        verify_minimum_level_c_v1(sample_minimum_level_c_input(context, transcript)?)?
            .into_evidence(),
    )
}

fn sample_minimum_level_c_input(
    context: DerivationContext,
    transcript: TranscriptBinding,
) -> RouterAbDerivationResult<MinimumLevelCVerificationInputV1> {
    let transcript_digest = transcript_digest_v1(&transcript)?;

    let a_client = sample_delivery_package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerAToClient,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Client,
        "role:client:local:sha256-c",
        ContentKind::ClientOutputShare,
        deterministic_public_digest("minimum-level-c/a-client", 0),
    )?;
    let b_client = sample_delivery_package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerBToClient,
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        Role::Client,
        "role:client:local:sha256-c",
        ContentKind::ClientOutputShare,
        deterministic_public_digest("minimum-level-c/b-client", 0),
    )?;
    let a_server = sample_delivery_package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerAToServer,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Server,
        "role:server:local:sha256-r",
        ContentKind::ServerOutputShare,
        deterministic_public_digest("minimum-level-c/a-server", 0),
    )?;
    let b_server = sample_delivery_package(
        &context,
        transcript_digest,
        EnvelopeKind::SignerBToServer,
        Role::SignerB,
        "role:signer-b:local:sha256-b",
        Role::Server,
        "role:server:local:sha256-r",
        ContentKind::ServerOutputShare,
        deterministic_public_digest("minimum-level-c/b-server", 0),
    )?;

    let input = MinimumLevelCVerificationInputV1 {
        context: context.clone(),
        transcript,
        signer_a_receipt: AuthenticatedSignerReceiptV1::new(
            SignerReceiptVersion::V1,
            Role::SignerA,
            "role:signer-a:local:sha256-a",
            transcript_digest,
            context.root_share_epoch().clone(),
            vec![
                package_commitment_v1(&a_client)?,
                package_commitment_v1(&a_server)?,
            ],
        )?,
        signer_b_receipt: AuthenticatedSignerReceiptV1::new(
            SignerReceiptVersion::V1,
            Role::SignerB,
            "role:signer-b:local:sha256-b",
            transcript_digest,
            context.root_share_epoch().clone(),
            vec![
                package_commitment_v1(&b_client)?,
                package_commitment_v1(&b_server)?,
            ],
        )?,
        client_packages: vec![a_client, b_client],
        server_packages: vec![a_server, b_server],
        replay_cache_decision: AcceptedReplayCacheDecisionV1 {
            replay_cache_key: deterministic_public_digest("minimum-level-c/replay", 0),
            accepted_transcript_digest: transcript_digest,
        },
    };

    Ok(input)
}

fn sample_rejection_vectors(
    context: &DerivationContext,
    transcript: &TranscriptBinding,
) -> RouterAbDerivationResult<Vec<RejectionVectorV1>> {
    let mut replay_mismatch = sample_minimum_level_c_input(context.clone(), transcript.clone())?;
    replay_mismatch
        .replay_cache_decision
        .accepted_transcript_digest =
        deterministic_public_digest("minimum-level-c/replay-mismatch", 0);

    let mut recipient_mismatch = sample_minimum_level_c_input(context.clone(), transcript.clone())?;
    recipient_mismatch.client_packages[0] = sample_delivery_package(
        context,
        transcript_digest_v1(transcript)?,
        EnvelopeKind::SignerAToClient,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Client,
        "role:client:local:sha256-wrong",
        ContentKind::ClientOutputShare,
        deterministic_public_digest("minimum-level-c/a-client-ciphertext", 0),
    )?;

    let mut commitment_mismatch =
        sample_minimum_level_c_input(context.clone(), transcript.clone())?;
    let mut mismatched_commitments = commitment_mismatch
        .signer_a_receipt
        .output_package_commitments()
        .to_vec();
    mismatched_commitments[0] =
        deterministic_public_digest("minimum-level-c/commitment-mismatch", 0);
    commitment_mismatch.signer_a_receipt = AuthenticatedSignerReceiptV1::new(
        SignerReceiptVersion::V1,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        transcript_digest_v1(transcript)?,
        context.root_share_epoch().clone(),
        mismatched_commitments,
    )?;

    let mut signer_identity_mismatch =
        sample_minimum_level_c_input(context.clone(), transcript.clone())?;
    let signer_identity_commitments = signer_identity_mismatch
        .signer_a_receipt
        .output_package_commitments()
        .to_vec();
    signer_identity_mismatch.signer_a_receipt = AuthenticatedSignerReceiptV1::new(
        SignerReceiptVersion::V1,
        Role::SignerA,
        "role:signer-a:local:sha256-wrong",
        transcript_digest_v1(transcript)?,
        context.root_share_epoch().clone(),
        signer_identity_commitments,
    )?;

    let mut root_epoch_mismatch =
        sample_minimum_level_c_input(context.clone(), transcript.clone())?;
    let root_epoch_commitments = root_epoch_mismatch
        .signer_a_receipt
        .output_package_commitments()
        .to_vec();
    root_epoch_mismatch.signer_a_receipt = AuthenticatedSignerReceiptV1::new(
        SignerReceiptVersion::V1,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        transcript_digest_v1(transcript)?,
        RootShareEpoch::new("epoch-2")?,
        root_epoch_commitments,
    )?;

    let mut package_context_mismatch =
        sample_minimum_level_c_input(context.clone(), transcript.clone())?;
    package_context_mismatch.client_packages[0] = DeliveryPackageV1::new(EnvelopeHeaderV1::new(
        EnvelopeVersion::V1,
        EnvelopeKind::SignerAToClient,
        context.candidate_id(),
        RequestKind::Export,
        context.correctness_level(),
        context.ceremony_id().to_owned(),
        context.root_share_epoch().clone(),
        transcript_digest_v1(transcript)?,
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Client,
        "role:client:local:sha256-c",
        ContentKind::ClientOutputShare,
        deterministic_public_digest("minimum-level-c/a-client-ciphertext", 0),
        128,
    )?)?;

    let duplicate_signer_identity = SignerSetBinding::v1_all2(
        "signer-set-v1",
        "role:signer-duplicate:local:sha256",
        "key-epoch-a-1",
        "role:signer-duplicate:local:sha256",
        "key-epoch-b-1",
    );

    let non_all2_signer_set = SignerSetBinding::from_indexed_v1(
        "signer-set-v1",
        QuorumPolicy::All { signer_count: 3 },
        vec![
            IndexedSignerBinding::new(
                0,
                Role::SignerA,
                "role:signer-a:local:sha256-a",
                "key-epoch-a-1",
            )?,
            IndexedSignerBinding::new(
                1,
                Role::SignerB,
                "role:signer-b:local:sha256-b",
                "key-epoch-b-1",
            )?,
        ],
    );
    let refresh_same_epoch = RefreshScope {
        old_root_share_epoch: context.root_share_epoch().clone(),
        new_root_share_epoch: context.root_share_epoch().clone(),
        refresh_id: "refresh-1".to_owned(),
        account_scope: context.account_scope().clone(),
        old_signer_set_id: "signer-set-v1".to_owned(),
        new_signer_set_id: "signer-set-v2".to_owned(),
        expected_router_id: "role:router:local:sha256-router".to_owned(),
        expected_client_id: "role:client:local:sha256-c".to_owned(),
        expected_server_id: "role:server:local:sha256-r".to_owned(),
        address_verification_requirement: "required".to_owned(),
    };

    Ok(vec![
        expect_rejection_code(
            "minimum_level_c_replay_mismatch_v1",
            verify_minimum_level_c_v1(replay_mismatch),
        )?,
        expect_rejection_code(
            "minimum_level_c_recipient_mismatch_v1",
            verify_minimum_level_c_v1(recipient_mismatch),
        )?,
        expect_rejection_code(
            "minimum_level_c_receipt_commitment_mismatch_v1",
            verify_minimum_level_c_v1(commitment_mismatch),
        )?,
        expect_rejection_code(
            "minimum_level_c_signer_identity_mismatch_v1",
            verify_minimum_level_c_v1(signer_identity_mismatch),
        )?,
        expect_rejection_code(
            "minimum_level_c_root_epoch_mismatch_v1",
            verify_minimum_level_c_v1(root_epoch_mismatch),
        )?,
        expect_rejection_code(
            "minimum_level_c_package_context_mismatch_v1",
            verify_minimum_level_c_v1(package_context_mismatch),
        )?,
        expect_rejection_code(
            "transcript_duplicate_signer_identity_v1",
            duplicate_signer_identity,
        )?,
        expect_rejection_code("transcript_non_all2_quorum_v1", non_all2_signer_set)?,
        expect_rejection_code(
            "refresh_same_old_new_epoch_v1",
            refresh_same_epoch.validate(),
        )?,
    ])
}

fn expect_rejection_code<T>(
    case_id: &str,
    result: RouterAbDerivationResult<T>,
) -> RouterAbDerivationResult<RejectionVectorV1> {
    match result {
        Ok(_) => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{case_id} did not reject"),
        )),
        Err(err) => Ok(RejectionVectorV1 {
            case_id: case_id.to_owned(),
            expected_error_code: err.code(),
        }),
    }
}

fn deterministic_public_digest(seed: &str, counter: u32) -> PublicDigest32 {
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, seed.as_bytes());
    push_hash_field(&mut hasher, &counter.to_be_bytes());
    PublicDigest32::new(hasher.finalize().into())
}

fn digest_hex(digest: PublicDigest32) -> String {
    hex::encode(digest.bytes)
}

fn push_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let len = value.len() as u32;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}

struct DeterministicVectorRng {
    seed: Vec<u8>,
    counter: u64,
    block: [u8; 32],
    offset: usize,
}

impl DeterministicVectorRng {
    fn new(seed: impl AsRef<[u8]>) -> Self {
        Self {
            seed: seed.as_ref().to_vec(),
            counter: 0,
            block: [0u8; 32],
            offset: 32,
        }
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        push_hash_field(&mut hasher, b"router-ab-derivation/vector-rng/v1");
        push_hash_field(&mut hasher, &self.seed);
        push_hash_field(&mut hasher, &self.counter.to_be_bytes());
        self.block = hasher.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }
}

impl RngCore for DeterministicVectorRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            if self.offset == self.block.len() {
                self.refill();
            }
            *byte = self.block[self.offset];
            self.offset += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicVectorRng {}
