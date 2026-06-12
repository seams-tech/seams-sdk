use crate::derivation::{CandidateId, CorrectnessLevel, PublicDigest32, Role};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::envelope::{role_encrypted_envelope_digest_v1, RoleEncryptedEnvelopeV1};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::identity::{RoleEnvelopeAssignmentV1, SignerSetV1};
use crate::protocol::lifecycle::LifecycleScopeV1;
use crate::protocol::payload::{
    encode_router_to_signer_payload_v1, router_transcript_digest_v1, RouterEnvelopeDigestSetV1,
    RouterToSignerPayloadV1, RouterTranscriptMetadataV1,
};
use crate::protocol::wire::{CanonicalWireBytesV1, WireMessageKindV1, WireMessageV1};

const PUBLIC_ROUTER_REQUEST_VERSION_V1: &[u8] = b"router-ab-protocol/public-router-request/v1";
const PUBLIC_ROUTER_REQUEST_CONTEXT_VERSION_V1: &[u8] =
    b"router-ab-protocol/public-router-request-context/v1";
const PUBLIC_ROUTER_SELECTED_DERIVATION_CANDIDATE_V1: CandidateId = CandidateId::MpcThresholdPrfV1;

/// Public client-to-Router request version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRouterRequestVersionV1 {
    /// Router A/B v1 public request shape.
    V1,
}

impl PublicRouterRequestVersionV1 {
    /// Returns the canonical version label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

/// Public client-to-Router request context known before signer-envelope encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRouterRequestContextV1 {
    /// Public request version.
    pub version: PublicRouterRequestVersionV1,
    /// Client request nonce used by Router replay checks.
    pub request_nonce: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Router lifecycle scope.
    pub lifecycle: LifecycleScopeV1,
    /// Client-required split derivation candidate.
    pub required_derivation_candidate: CandidateId,
    /// Signer set bound into the transcript.
    pub signer_set: SignerSetV1,
    /// Network namespace bound into derivation.
    pub network_id: String,
    /// Account public key bound into derivation.
    pub account_public_key: String,
    /// Router identity bound into the transcript.
    pub router_id: String,
    /// Client identity bound into the transcript.
    pub client_id: String,
    /// Client ephemeral public key used for client-output encryption.
    pub client_ephemeral_public_key: String,
}

impl PublicRouterRequestContextV1 {
    /// Creates a validated pre-envelope Router request context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_nonce: impl Into<String>,
        expires_at_ms: u64,
        lifecycle: LifecycleScopeV1,
        required_derivation_candidate: CandidateId,
        signer_set: SignerSetV1,
        network_id: impl Into<String>,
        account_public_key: impl Into<String>,
        router_id: impl Into<String>,
        client_id: impl Into<String>,
        client_ephemeral_public_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self {
            version: PublicRouterRequestVersionV1::V1,
            request_nonce: request_nonce.into(),
            expires_at_ms,
            lifecycle,
            required_derivation_candidate,
            signer_set,
            network_id: network_id.into(),
            account_public_key: account_public_key.into(),
            router_id: router_id.into(),
            client_id: client_id.into(),
            client_ephemeral_public_key: client_ephemeral_public_key.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates public pre-envelope request metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("request_nonce", &self.request_nonce)?;
        if self.expires_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "public Router request context expires_at_ms must be greater than zero",
            ));
        }
        self.lifecycle.validate()?;
        self.require_selected_derivation_candidate()?;
        self.signer_set.validate()?;
        require_non_empty("network_id", &self.network_id)?;
        require_non_empty("account_public_key", &self.account_public_key)?;
        require_non_empty("router_id", &self.router_id)?;
        require_non_empty("client_id", &self.client_id)?;
        require_non_empty(
            "client_ephemeral_public_key",
            &self.client_ephemeral_public_key,
        )?;
        if self.lifecycle.signer_set_id != self.signer_set.signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "public Router request context lifecycle signer-set id does not match signer set",
            ));
        }
        if self.lifecycle.selected_relayer_id != self.signer_set.selected_relayer.relayer_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "public Router request context selected relayer does not match signer set",
            ));
        }
        Ok(())
    }

    /// Rejects contexts that do not require the selected v1 split derivation.
    pub fn require_selected_derivation_candidate(&self) -> RouterAbProtocolResult<()> {
        if self.required_derivation_candidate == PUBLIC_ROUTER_SELECTED_DERIVATION_CANDIDATE_V1 {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::DowngradeRejected,
            format!(
                "public Router request context requires {}, selected Router A/B v1 candidate is {}",
                self.required_derivation_candidate.as_str(),
                PUBLIC_ROUTER_SELECTED_DERIVATION_CANDIDATE_V1.as_str()
            ),
        ))
    }

    /// Validates context shape and expiry against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "public Router request context expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical pre-envelope context bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_public_request_context_v1(&mut out, self);
        out
    }

    /// Returns the pre-envelope context digest used by signer AAD and plaintext.
    pub fn context_digest(&self) -> PublicDigest32 {
        digest_bytes(&self.canonical_bytes())
    }

    /// Builds transcript metadata from public pre-envelope context.
    pub fn transcript_metadata(&self) -> RouterAbProtocolResult<RouterTranscriptMetadataV1> {
        RouterTranscriptMetadataV1::new(
            self.network_id.clone(),
            self.account_public_key.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )
    }

    /// Returns the pre-envelope derivation transcript digest for HSS/output binding.
    pub fn derivation_transcript_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        router_transcript_digest_v1(
            &self.lifecycle,
            &self.signer_set,
            &self.transcript_metadata()?,
            self.required_derivation_candidate,
            CorrectnessLevel::MinimumLevelC,
            self.lifecycle.root_share_epoch.clone(),
        )
    }
}

/// Public client-to-Router request for a derivation-time Router A/B ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRouterRequestV1 {
    /// Public request version.
    pub version: PublicRouterRequestVersionV1,
    /// Client request nonce used by Router replay checks.
    pub request_nonce: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Router lifecycle scope.
    pub lifecycle: LifecycleScopeV1,
    /// Client-required split derivation candidate.
    pub required_derivation_candidate: CandidateId,
    /// Signer set bound into the transcript.
    pub signer_set: SignerSetV1,
    /// Network namespace bound into derivation.
    pub network_id: String,
    /// Account public key bound into derivation.
    pub account_public_key: String,
    /// Router identity bound into the transcript.
    pub router_id: String,
    /// Client identity bound into the transcript.
    pub client_id: String,
    /// Client ephemeral public key used for client-output encryption.
    pub client_ephemeral_public_key: String,
    /// Public transcript digest for the ceremony.
    pub transcript_digest: PublicDigest32,
    /// Role-specific encrypted Signer A envelope.
    pub signer_a_envelope: RoleEncryptedEnvelopeV1,
    /// Role-specific encrypted Signer B envelope.
    pub signer_b_envelope: RoleEncryptedEnvelopeV1,
}

impl PublicRouterRequestV1 {
    /// Creates a validated public Router request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_nonce: impl Into<String>,
        expires_at_ms: u64,
        lifecycle: LifecycleScopeV1,
        required_derivation_candidate: CandidateId,
        signer_set: SignerSetV1,
        network_id: impl Into<String>,
        account_public_key: impl Into<String>,
        router_id: impl Into<String>,
        client_id: impl Into<String>,
        client_ephemeral_public_key: impl Into<String>,
        transcript_digest: PublicDigest32,
        signer_a_envelope: RoleEncryptedEnvelopeV1,
        signer_b_envelope: RoleEncryptedEnvelopeV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            version: PublicRouterRequestVersionV1::V1,
            request_nonce: request_nonce.into(),
            expires_at_ms,
            lifecycle,
            required_derivation_candidate,
            signer_set,
            network_id: network_id.into(),
            account_public_key: account_public_key.into(),
            router_id: router_id.into(),
            client_id: client_id.into(),
            client_ephemeral_public_key: client_ephemeral_public_key.into(),
            transcript_digest,
            signer_a_envelope,
            signer_b_envelope,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates public request metadata and role-envelope assignment.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context()?.validate()?;
        self.require_transcript_digest()?;
        self.signer_a_envelope.validate()?;
        self.signer_b_envelope.validate()?;
        require_envelope_role(&self.signer_a_envelope, Role::SignerA)?;
        require_envelope_role(&self.signer_b_envelope, Role::SignerB)
    }

    /// Rejects requests whose transcript digest does not match public pre-envelope context.
    pub fn require_transcript_digest(&self) -> RouterAbProtocolResult<()> {
        let expected = self.derivation_transcript_digest()?;
        if self.transcript_digest == expected {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "public Router request transcript digest does not match pre-envelope context",
        ))
    }

    /// Rejects requests that do not require the selected v1 split derivation.
    pub fn require_selected_derivation_candidate(&self) -> RouterAbProtocolResult<()> {
        if self.required_derivation_candidate == PUBLIC_ROUTER_SELECTED_DERIVATION_CANDIDATE_V1 {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::DowngradeRejected,
            format!(
                "public Router request requires {}, selected Router A/B v1 candidate is {}",
                self.required_derivation_candidate.as_str(),
                PUBLIC_ROUTER_SELECTED_DERIVATION_CANDIDATE_V1.as_str()
            ),
        ))
    }

    /// Validates request shape and expiry against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "public Router request expired",
            ));
        }
        Ok(())
    }

    /// Returns the full-envelope Router replay/idempotency digest.
    pub fn router_replay_digest(&self) -> PublicDigest32 {
        digest_bytes(&self.canonical_bytes())
    }

    /// Returns the pre-envelope public request context.
    pub fn context(&self) -> RouterAbProtocolResult<PublicRouterRequestContextV1> {
        PublicRouterRequestContextV1::new(
            self.request_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.required_derivation_candidate,
            self.signer_set.clone(),
            self.network_id.clone(),
            self.account_public_key.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )
    }

    /// Returns the pre-envelope request context digest for signer AAD/plaintext binding.
    pub fn request_context_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(self.context()?.context_digest())
    }

    /// Returns the pre-envelope derivation transcript digest for HSS/output binding.
    pub fn derivation_transcript_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.context()?.derivation_transcript_digest()
    }

    /// Returns canonical public request bytes for replay and transcript binding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_len32(&mut out, PUBLIC_ROUTER_REQUEST_VERSION_V1);
        push_len32(&mut out, self.version.as_str().as_bytes());
        push_string(&mut out, &self.request_nonce);
        push_u64(&mut out, self.expires_at_ms);
        push_len32(
            &mut out,
            self.required_derivation_candidate.as_str().as_bytes(),
        );
        push_lifecycle_scope(&mut out, &self.lifecycle);
        push_signer_set(&mut out, &self.signer_set);
        push_string(&mut out, &self.network_id);
        push_string(&mut out, &self.account_public_key);
        push_string(&mut out, &self.router_id);
        push_string(&mut out, &self.client_id);
        push_string(&mut out, &self.client_ephemeral_public_key);
        push_public_digest(&mut out, self.transcript_digest);
        push_role_envelope(&mut out, &self.signer_a_envelope);
        push_role_envelope(&mut out, &self.signer_b_envelope);
        out
    }

    /// Builds the two Router-to-signer payloads for this public request.
    pub fn to_signer_payloads(
        &self,
    ) -> RouterAbProtocolResult<(RouterToSignerPayloadV1, RouterToSignerPayloadV1)> {
        self.validate()?;
        let transcript_metadata = self.transcript_metadata()?;
        let envelope_digest_set = self.envelope_digest_set()?;
        let signer_a_assignment = RoleEnvelopeAssignmentV1::new(
            self.signer_set.signer_a.clone(),
            self.signer_a_envelope.clone(),
        )?;
        let signer_b_assignment = RoleEnvelopeAssignmentV1::new(
            self.signer_set.signer_b.clone(),
            self.signer_b_envelope.clone(),
        )?;
        Ok((
            RouterToSignerPayloadV1::signer_a(
                self.lifecycle.clone(),
                self.signer_set.clone(),
                transcript_metadata.clone(),
                envelope_digest_set,
                self.transcript_digest,
                signer_a_assignment,
            )?,
            RouterToSignerPayloadV1::signer_b(
                self.lifecycle.clone(),
                self.signer_set.clone(),
                transcript_metadata,
                envelope_digest_set,
                self.transcript_digest,
                signer_b_assignment,
            )?,
        ))
    }

    /// Builds transcript metadata shared by both Router-to-signer payloads.
    pub fn transcript_metadata(&self) -> RouterAbProtocolResult<RouterTranscriptMetadataV1> {
        self.context()?.transcript_metadata()
    }

    /// Builds encrypted-envelope digest metadata shared by both Router-to-signer payloads.
    pub fn envelope_digest_set(&self) -> RouterAbProtocolResult<RouterEnvelopeDigestSetV1> {
        self.validate()?;
        Ok(RouterEnvelopeDigestSetV1::new(
            role_encrypted_envelope_digest_v1(&self.signer_a_envelope)?,
            role_encrypted_envelope_digest_v1(&self.signer_b_envelope)?,
        ))
    }

    /// Builds the two canonical Router-to-signer wire messages.
    pub fn to_signer_wire_messages(
        &self,
    ) -> RouterAbProtocolResult<(WireMessageV1, WireMessageV1)> {
        let (signer_a, signer_b) = self.to_signer_payloads()?;
        Ok((
            WireMessageV1::new(
                WireMessageKindV1::RouterToSignerA,
                self.transcript_digest,
                CanonicalWireBytesV1::new(encode_router_to_signer_payload_v1(&signer_a))?,
            )?,
            WireMessageV1::new(
                WireMessageKindV1::RouterToSignerB,
                self.transcript_digest,
                CanonicalWireBytesV1::new(encode_router_to_signer_payload_v1(&signer_b))?,
            )?,
        ))
    }
}

fn require_envelope_role(
    envelope: &RoleEncryptedEnvelopeV1,
    expected: Role,
) -> RouterAbProtocolResult<()> {
    if envelope.recipient_role == expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidRole,
        format!(
            "public Router request expected {} envelope, received {}",
            expected.as_str(),
            envelope.recipient_role.as_str()
        ),
    ))
}

fn push_lifecycle_scope(out: &mut Vec<u8>, lifecycle: &LifecycleScopeV1) {
    push_string(out, &lifecycle.lifecycle_id);
    push_len32(out, lifecycle.work_kind.as_str().as_bytes());
    push_len32(out, lifecycle.primitive_request_kind.as_str().as_bytes());
    push_string(out, lifecycle.root_share_epoch.as_str());
    push_string(out, &lifecycle.account_id);
    push_string(out, &lifecycle.session_id);
    push_string(out, &lifecycle.signer_set_id);
    push_string(out, &lifecycle.selected_relayer_id);
}

fn push_public_request_context_v1(out: &mut Vec<u8>, context: &PublicRouterRequestContextV1) {
    push_len32(out, PUBLIC_ROUTER_REQUEST_CONTEXT_VERSION_V1);
    push_len32(out, context.version.as_str().as_bytes());
    push_string(out, &context.request_nonce);
    push_u64(out, context.expires_at_ms);
    push_len32(
        out,
        context.required_derivation_candidate.as_str().as_bytes(),
    );
    push_lifecycle_scope(out, &context.lifecycle);
    push_signer_set(out, &context.signer_set);
    push_string(out, &context.network_id);
    push_string(out, &context.account_public_key);
    push_string(out, &context.router_id);
    push_string(out, &context.client_id);
    push_string(out, &context.client_ephemeral_public_key);
}

fn push_signer_set(out: &mut Vec<u8>, signer_set: &SignerSetV1) {
    push_string(out, &signer_set.signer_set_id);
    push_len32(out, signer_set.policy.as_str().as_bytes());
    push_len32(out, signer_set.signer_a.role.as_str().as_bytes());
    push_string(out, &signer_set.signer_a.signer_id);
    push_string(out, &signer_set.signer_a.key_epoch);
    push_len32(out, signer_set.signer_b.role.as_str().as_bytes());
    push_string(out, &signer_set.signer_b.signer_id);
    push_string(out, &signer_set.signer_b.key_epoch);
    push_string(out, &signer_set.selected_relayer.relayer_id);
    push_string(out, &signer_set.selected_relayer.key_epoch);
    push_string(out, &signer_set.selected_relayer.recipient_encryption_key);
}

fn push_role_envelope(out: &mut Vec<u8>, envelope: &RoleEncryptedEnvelopeV1) {
    push_len32(out, envelope.recipient_role.as_str().as_bytes());
    push_public_digest(out, envelope.header_digest);
    push_public_digest(out, envelope.aad_digest);
    push_len32(out, envelope.ciphertext.as_bytes());
}

fn push_public_digest(out: &mut Vec<u8>, digest: PublicDigest32) {
    push_len32(out, digest.as_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_len32(out, value.as_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn digest_bytes(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}
