use crate::derivation::PublicDigest32;
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::identity::RelayerIdentityV1;
use crate::protocol::lifecycle::NormalSigningScopeV1;
use crate::protocol::wire::CanonicalWireBytesV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const NORMAL_SIGNING_REQUEST_VERSION_V1: &[u8] = b"router-ab-protocol/normal-signing/request/v1";

/// Signature algorithm returned by the active SigningWorker normal-signing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalSigningSignatureSchemeV1 {
    /// Ed25519 account signature.
    Ed25519V1,
}

impl NormalSigningSignatureSchemeV1 {
    /// Returns the canonical signature-scheme label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519V1 => "ed25519_v1",
        }
    }
}

/// Client-facing normal-signing request after Router boundary parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalSigningRequestV1 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Digest of the canonical user intent authorized by policy.
    pub intent_digest: PublicDigest32,
    /// Canonical payload bytes to sign.
    pub signing_payload: CanonicalWireBytesV1,
}

impl NormalSigningRequestV1 {
    /// Creates a validated normal-signing request.
    pub fn new(
        scope: NormalSigningScopeV1,
        expires_at_ms: u64,
        intent_digest: PublicDigest32,
        signing_payload: CanonicalWireBytesV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            expires_at_ms,
            intent_digest,
            signing_payload,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates request shape without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        if self.expires_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "normal signing request expires_at_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Validates request shape and expiry against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "normal signing request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical request bytes for replay and Router-to-SigningWorker binding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_len32(&mut out, NORMAL_SIGNING_REQUEST_VERSION_V1);
        push_normal_signing_scope(&mut out, &self.scope);
        push_u64(&mut out, self.expires_at_ms);
        out.extend_from_slice(self.intent_digest.as_bytes());
        push_len32(&mut out, self.signing_payload.as_bytes());
        out
    }

    /// Returns the SHA-256 digest of canonical request bytes.
    pub fn digest(&self) -> PublicDigest32 {
        public_digest(&self.canonical_bytes())
    }

    /// Returns the SHA-256 digest of the payload bytes to sign.
    pub fn signing_payload_digest(&self) -> PublicDigest32 {
        public_digest(self.signing_payload.as_bytes())
    }
}

/// SigningWorker activation state required before normal signing can be forwarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSigningWorkerStateV1 {
    /// Canonical account or wallet id.
    pub account_id: String,
    /// Canonical session id.
    pub session_id: String,
    /// Active SigningWorker identity.
    pub signing_worker: RelayerIdentityV1,
    /// Transcript that activated the SigningWorker output.
    pub activation_transcript_digest: PublicDigest32,
    /// Digest of stored SigningWorker activation material.
    pub activation_digest: PublicDigest32,
    /// SigningWorker-local storage handle for opened signing material.
    pub signing_worker_material_handle: String,
    /// Activation timestamp in Unix milliseconds.
    pub activated_at_ms: u64,
}

impl ActiveSigningWorkerStateV1 {
    /// Creates a validated active SigningWorker state descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        signing_worker: RelayerIdentityV1,
        activation_transcript_digest: PublicDigest32,
        activation_digest: PublicDigest32,
        signing_worker_material_handle: impl Into<String>,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let state = Self {
            account_id: account_id.into(),
            session_id: session_id.into(),
            signing_worker,
            activation_transcript_digest,
            activation_digest,
            signing_worker_material_handle: signing_worker_material_handle.into(),
            activated_at_ms,
        };
        state.validate()?;
        Ok(state)
    }

    /// Validates active SigningWorker identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("active signing worker account_id", &self.account_id)?;
        require_non_empty("active signing worker session_id", &self.session_id)?;
        require_non_empty(
            "active signing worker material handle",
            &self.signing_worker_material_handle,
        )?;
        self.signing_worker.validate()?;
        if self.activated_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "active signing worker activated_at_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Validates the active SigningWorker state matches a normal-signing scope.
    pub fn validate_for_scope(&self, scope: &NormalSigningScopeV1) -> RouterAbProtocolResult<()> {
        self.validate()?;
        scope.validate()?;
        if self.account_id != scope.account_id
            || self.session_id != scope.session_id
            || self.signing_worker.relayer_id != scope.signing_worker_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "active signing worker state does not match normal signing scope",
            ));
        }
        Ok(())
    }
}

/// Router-to-SigningWorker normal-signing forwarding request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterToSigningWorkerSigningRequestV1 {
    /// Client-facing normal-signing request.
    pub request: NormalSigningRequestV1,
    /// Active SigningWorker state selected by the Router.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
}

impl RouterToSigningWorkerSigningRequestV1 {
    /// Creates a validated Router-to-SigningWorker signing request.
    pub fn new(
        request: NormalSigningRequestV1,
        active_signing_worker: ActiveSigningWorkerStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let relay_request = Self {
            request,
            active_signing_worker,
        };
        relay_request.validate()?;
        Ok(relay_request)
    }

    /// Validates active SigningWorker state matches the forwarded request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.active_signing_worker
            .validate_for_scope(&self.request.scope)
    }
}

/// SigningWorker-produced normal-signing response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalSigningResponseV1 {
    /// Normal signing scope that produced the signature.
    pub scope: NormalSigningScopeV1,
    /// Digest of the canonical payload bytes that were signed.
    pub signing_payload_digest: PublicDigest32,
    /// Active SigningWorker identity used for signing.
    pub signing_worker: RelayerIdentityV1,
    /// Signature scheme.
    pub signature_scheme: NormalSigningSignatureSchemeV1,
    /// Signature bytes.
    pub signature: CanonicalWireBytesV1,
    /// Signing timestamp in Unix milliseconds.
    pub signed_at_ms: u64,
}

impl NormalSigningResponseV1 {
    /// Creates a validated normal-signing response.
    pub fn new(
        scope: NormalSigningScopeV1,
        signing_payload_digest: PublicDigest32,
        signing_worker: RelayerIdentityV1,
        signature_scheme: NormalSigningSignatureSchemeV1,
        signature: CanonicalWireBytesV1,
        signed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            scope,
            signing_payload_digest,
            signing_worker,
            signature_scheme,
            signature,
            signed_at_ms,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates response identity and signature metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        self.signing_worker.validate()?;
        if self.signing_worker.relayer_id != self.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "normal signing response SigningWorker does not match scope",
            ));
        }
        if self.signed_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "normal signing response signed_at_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Validates the response binds to the forwarded Router request.
    pub fn validate_for_request(
        &self,
        request: &NormalSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.scope != request.scope
            || self.signing_payload_digest != request.signing_payload_digest()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "normal signing response does not match request",
            ));
        }
        Ok(())
    }
}

fn public_digest(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn push_normal_signing_scope(out: &mut Vec<u8>, scope: &NormalSigningScopeV1) {
    push_len32(out, scope.request_id.as_bytes());
    push_len32(out, scope.account_id.as_bytes());
    push_len32(out, scope.session_id.as_bytes());
    push_len32(out, scope.signing_worker_id.as_bytes());
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if !value.is_empty() {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::EmptyField,
        format!("{field} must be non-empty"),
    ))
}
