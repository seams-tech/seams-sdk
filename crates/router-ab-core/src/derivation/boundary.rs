use serde::{Deserialize, Serialize};

use crate::derivation::context::{
    AccountScope, CandidateId, CorrectnessLevel, DerivationContext, RequestKind, RootShareEpoch,
};
use crate::derivation::envelope::{ContentKind, EnvelopeHeaderV1, EnvelopeKind, EnvelopeVersion};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::evidence::{MinimumLevelCEvidenceV1, MinimumLevelCEvidenceVersion};
use crate::derivation::material::{PublicDigest32, Role};
use crate::derivation::transcript::{
    IndexedSignerBinding, QuorumPolicy, SignerSetBinding, TranscriptBinding,
};

/// Raw 32-byte public digest as received at an adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawPublicDigest32V1 {
    /// Digest bytes before fixed-width validation.
    pub bytes: Vec<u8>,
}

/// Raw account scope before boundary normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAccountScopeV1 {
    /// Network namespace.
    pub network_id: String,
    /// Account identifier.
    pub account_id: String,
    /// Canonical account public key string.
    pub account_public_key: String,
}

/// Raw derivation context before boundary normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawContextV1 {
    /// Candidate family label.
    pub candidate_id: String,
    /// Request-kind label.
    pub request_kind: String,
    /// Correctness-level label.
    pub correctness_level: String,
    /// Account scope fields.
    pub account_scope: RawAccountScopeV1,
    /// Root-share epoch label.
    pub root_share_epoch: String,
    /// Router-assigned ceremony identifier.
    pub ceremony_id: String,
}

/// Raw indexed signer binding before boundary normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawIndexedSignerBindingV1 {
    /// Stable signer index inside the signer set.
    pub signer_index: u16,
    /// Signer role label.
    pub role: String,
    /// Canonical signer identity string.
    pub signer_id: String,
    /// Signer key epoch.
    pub key_epoch: String,
}

/// Raw signer-set binding before boundary normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSignerSetBindingV1 {
    /// Stable signer-set identifier.
    pub signer_set_id: String,
    /// Canonical quorum policy string, such as `all(2)`.
    pub quorum_policy: String,
    /// Indexed signer entries.
    pub signers: Vec<RawIndexedSignerBindingV1>,
}

/// Raw transcript binding before boundary normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawTranscriptV1 {
    /// Raw derivation context.
    pub context: RawContextV1,
    /// Router identity string.
    pub router_id: String,
    /// Raw signer set.
    pub signer_set: RawSignerSetBindingV1,
    /// Selected server identity string.
    pub selected_server_id: String,
    /// Selected server recipient encryption public key.
    pub selected_server_recipient_encryption_key: String,
    /// Client identity string.
    pub client_id: String,
    /// Client ephemeral public key for client-output encryption.
    pub client_ephemeral_public_key: String,
}

/// Raw envelope header before boundary normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEnvelopeHeaderV1 {
    /// Envelope version label.
    pub envelope_version: String,
    /// Envelope kind label.
    pub envelope_kind: String,
    /// Candidate family label.
    pub candidate_id: String,
    /// Request-kind label.
    pub request_kind: String,
    /// Correctness-level label.
    pub correctness_level: String,
    /// Router-assigned ceremony identifier.
    pub ceremony_id: String,
    /// Root-share epoch label.
    pub root_share_epoch: String,
    /// Transcript digest bytes.
    pub transcript_digest: RawPublicDigest32V1,
    /// Sender role label.
    pub sender_role: String,
    /// Sender identity.
    pub sender_identity: String,
    /// Recipient role label.
    pub recipient_role: String,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Plaintext content kind label.
    pub content_kind: String,
    /// Ciphertext digest bytes.
    pub ciphertext_digest: RawPublicDigest32V1,
    /// Ciphertext length in bytes.
    pub ciphertext_len: u64,
}

/// Raw Minimum Level C evidence before boundary normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawMinimumLevelCEvidenceV1 {
    /// Evidence version label.
    pub evidence_version: String,
    /// Correctness-level label.
    pub correctness_level: String,
    /// Context digest bytes.
    pub context_digest: RawPublicDigest32V1,
    /// Transcript digest bytes.
    pub transcript_digest: RawPublicDigest32V1,
    /// Signer A receipt digest bytes.
    pub signer_a_receipt_digest: RawPublicDigest32V1,
    /// Signer B receipt digest bytes.
    pub signer_b_receipt_digest: RawPublicDigest32V1,
    /// Client package commitment digests.
    pub client_package_commitments: Vec<RawPublicDigest32V1>,
    /// Server package commitment digests.
    pub server_package_commitments: Vec<RawPublicDigest32V1>,
    /// Replay cache key bytes.
    pub replay_cache_key: RawPublicDigest32V1,
}

/// Parses and validates a raw derivation context.
pub fn parse_context_v1(raw: RawContextV1) -> RouterAbDerivationResult<DerivationContext> {
    DerivationContext::new(
        parse_candidate_id_v1(&raw.candidate_id)?,
        parse_request_kind_v1(&raw.request_kind)?,
        parse_correctness_level_v1(&raw.correctness_level)?,
        AccountScope::new(
            raw.account_scope.network_id,
            raw.account_scope.account_id,
            raw.account_scope.account_public_key,
        )?,
        RootShareEpoch::new(raw.root_share_epoch)?,
        raw.ceremony_id,
    )
}

/// Parses and validates a raw transcript binding.
pub fn parse_transcript_v1(raw: RawTranscriptV1) -> RouterAbDerivationResult<TranscriptBinding> {
    TranscriptBinding::new(
        parse_context_v1(raw.context)?,
        raw.router_id,
        parse_signer_set_v1(raw.signer_set)?,
        raw.selected_server_id,
        raw.selected_server_recipient_encryption_key,
        raw.client_id,
        raw.client_ephemeral_public_key,
    )
}

/// Parses and validates a raw envelope header.
pub fn parse_envelope_header_v1(
    raw: RawEnvelopeHeaderV1,
) -> RouterAbDerivationResult<EnvelopeHeaderV1> {
    EnvelopeHeaderV1::new(
        parse_envelope_version_v1(&raw.envelope_version)?,
        parse_envelope_kind_v1(&raw.envelope_kind)?,
        parse_candidate_id_v1(&raw.candidate_id)?,
        parse_request_kind_v1(&raw.request_kind)?,
        parse_correctness_level_v1(&raw.correctness_level)?,
        raw.ceremony_id,
        RootShareEpoch::new(raw.root_share_epoch)?,
        parse_public_digest32_v1(raw.transcript_digest, "transcript_digest")?,
        parse_role_v1(&raw.sender_role)?,
        raw.sender_identity,
        parse_role_v1(&raw.recipient_role)?,
        raw.recipient_identity,
        parse_content_kind_v1(&raw.content_kind)?,
        parse_public_digest32_v1(raw.ciphertext_digest, "ciphertext_digest")?,
        raw.ciphertext_len,
    )
}

/// Parses public Minimum Level C evidence.
pub fn parse_minimum_level_c_evidence_v1(
    raw: RawMinimumLevelCEvidenceV1,
) -> RouterAbDerivationResult<MinimumLevelCEvidenceV1> {
    MinimumLevelCEvidenceV1::new(
        parse_minimum_level_c_evidence_version_v1(&raw.evidence_version)?,
        parse_correctness_level_v1(&raw.correctness_level)?,
        parse_public_digest32_v1(raw.context_digest, "context_digest")?,
        parse_public_digest32_v1(raw.transcript_digest, "transcript_digest")?,
        parse_public_digest32_v1(raw.signer_a_receipt_digest, "signer_a_receipt_digest")?,
        parse_public_digest32_v1(raw.signer_b_receipt_digest, "signer_b_receipt_digest")?,
        parse_public_digest32_vec_v1(raw.client_package_commitments, "client_package_commitments")?,
        parse_public_digest32_vec_v1(raw.server_package_commitments, "server_package_commitments")?,
        parse_public_digest32_v1(raw.replay_cache_key, "replay_cache_key")?,
    )
}

fn parse_signer_set_v1(raw: RawSignerSetBindingV1) -> RouterAbDerivationResult<SignerSetBinding> {
    SignerSetBinding::from_indexed_v1(
        raw.signer_set_id,
        parse_quorum_policy_v1(&raw.quorum_policy)?,
        raw.signers
            .into_iter()
            .map(parse_indexed_signer_v1)
            .collect::<RouterAbDerivationResult<Vec<_>>>()?,
    )
}

fn parse_indexed_signer_v1(
    raw: RawIndexedSignerBindingV1,
) -> RouterAbDerivationResult<IndexedSignerBinding> {
    IndexedSignerBinding::new(
        raw.signer_index,
        parse_role_v1(&raw.role)?,
        raw.signer_id,
        raw.key_epoch,
    )
}

fn parse_public_digest32_vec_v1(
    raw: Vec<RawPublicDigest32V1>,
    field: &'static str,
) -> RouterAbDerivationResult<Vec<PublicDigest32>> {
    raw.into_iter()
        .enumerate()
        .map(|(index, digest)| {
            parse_public_digest32_v1(digest, field).map_err(|err| {
                RouterAbDerivationError::new(
                    err.code(),
                    format!("{field}[{index}] invalid: {}", err.message()),
                )
            })
        })
        .collect()
}

fn parse_public_digest32_v1(
    raw: RawPublicDigest32V1,
    field: &'static str,
) -> RouterAbDerivationResult<PublicDigest32> {
    let bytes: [u8; 32] = raw.bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} must be exactly 32 bytes, got {}", bytes.len()),
        )
    })?;
    Ok(PublicDigest32::new(bytes))
}

fn parse_candidate_id_v1(raw: &str) -> RouterAbDerivationResult<CandidateId> {
    match raw {
        "mpc_threshold_prf_v1" => Ok(CandidateId::MpcThresholdPrfV1),
        "split_root_derivation_v1" => Ok(CandidateId::SplitRootDerivationV1),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedCandidate,
            format!("unsupported candidate_id `{raw}`"),
        )),
    }
}

fn parse_request_kind_v1(raw: &str) -> RouterAbDerivationResult<RequestKind> {
    match raw {
        "registration" => Ok(RequestKind::Registration),
        "export" => Ok(RequestKind::Export),
        "refresh" => Ok(RequestKind::Refresh),
        _ => malformed_enum("request_kind", raw),
    }
}

fn parse_correctness_level_v1(raw: &str) -> RouterAbDerivationResult<CorrectnessLevel> {
    match raw {
        "minimum_level_c" => Ok(CorrectnessLevel::MinimumLevelC),
        "public_share_binding_v1" => Ok(CorrectnessLevel::PublicShareBindingV1),
        _ => malformed_enum("correctness_level", raw),
    }
}

fn parse_quorum_policy_v1(raw: &str) -> RouterAbDerivationResult<QuorumPolicy> {
    let Some(inner) = raw
        .strip_prefix("all(")
        .and_then(|value| value.strip_suffix(')'))
    else {
        return malformed_enum("quorum_policy", raw);
    };
    let signer_count = inner.parse::<u16>().map_err(|_| {
        RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("quorum_policy `{raw}` has invalid signer count"),
        )
    })?;
    Ok(QuorumPolicy::All { signer_count })
}

fn parse_role_v1(raw: &str) -> RouterAbDerivationResult<Role> {
    match raw {
        "router" => Ok(Role::Router),
        "signer_a" => Ok(Role::SignerA),
        "signer_b" => Ok(Role::SignerB),
        "server" => Ok(Role::Server),
        "client" => Ok(Role::Client),
        _ => malformed_enum("role", raw),
    }
}

fn parse_envelope_version_v1(raw: &str) -> RouterAbDerivationResult<EnvelopeVersion> {
    match raw {
        "v1" => Ok(EnvelopeVersion::V1),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedVersion,
            format!("unsupported envelope_version `{raw}`"),
        )),
    }
}

fn parse_envelope_kind_v1(raw: &str) -> RouterAbDerivationResult<EnvelopeKind> {
    match raw {
        "router_to_signer_a" => Ok(EnvelopeKind::RouterToSignerA),
        "router_to_signer_b" => Ok(EnvelopeKind::RouterToSignerB),
        "signer_a_to_signer_b" => Ok(EnvelopeKind::SignerAToSignerB),
        "signer_b_to_signer_a" => Ok(EnvelopeKind::SignerBToSignerA),
        "signer_a_to_client" => Ok(EnvelopeKind::SignerAToClient),
        "signer_b_to_client" => Ok(EnvelopeKind::SignerBToClient),
        "signer_a_to_server" => Ok(EnvelopeKind::SignerAToServer),
        "signer_b_to_server" => Ok(EnvelopeKind::SignerBToServer),
        _ => malformed_enum("envelope_kind", raw),
    }
}

fn parse_content_kind_v1(raw: &str) -> RouterAbDerivationResult<ContentKind> {
    match raw {
        "signer_input" => Ok(ContentKind::SignerInput),
        "a_to_b_coordination" => Ok(ContentKind::AToBCoordination),
        "b_to_a_coordination" => Ok(ContentKind::BToACoordination),
        "client_output_share" => Ok(ContentKind::ClientOutputShare),
        "server_output_share" => Ok(ContentKind::ServerOutputShare),
        "minimum_level_c_evidence" => Ok(ContentKind::MinimumLevelCEvidence),
        "public_share_binding_evidence" => Ok(ContentKind::PublicShareBindingEvidence),
        _ => malformed_enum("content_kind", raw),
    }
}

fn parse_minimum_level_c_evidence_version_v1(
    raw: &str,
) -> RouterAbDerivationResult<MinimumLevelCEvidenceVersion> {
    match raw {
        "v1" => Ok(MinimumLevelCEvidenceVersion::V1),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedVersion,
            format!("unsupported evidence_version `{raw}`"),
        )),
    }
}

fn malformed_enum<T>(field: &'static str, raw: &str) -> RouterAbDerivationResult<T> {
    Err(RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::MalformedInput,
        format!("{field} has unsupported value `{raw}`"),
    ))
}
