use core::fmt;

use crate::derivation::PublicDigest32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

const WIRE_MESSAGE_VERSION_V1: &[u8] = b"router-ab-protocol/wire-message/v1";

/// Canonical inter-service message kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireMessageKindV1 {
    /// Router forwarding an A-only encrypted envelope.
    RouterToSignerA,
    /// Router forwarding a B-only encrypted envelope.
    RouterToSignerB,
    /// Signer A sending a transcript-bound protocol message to Signer B.
    SignerAToSignerB,
    /// Signer B sending a transcript-bound protocol message to Signer A.
    SignerBToSignerA,
    /// Encrypted recipient-scoped proof bundle for client or relayer delivery.
    RecipientProofBundle,
}

impl WireMessageKindV1 {
    /// Returns the canonical message-kind label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouterToSignerA => "router_to_signer_a",
            Self::RouterToSignerB => "router_to_signer_b",
            Self::SignerAToSignerB => "signer_a_to_signer_b",
            Self::SignerBToSignerA => "signer_b_to_signer_a",
            Self::RecipientProofBundle => "recipient_proof_bundle",
        }
    }
}

/// Canonical bytes for a transport-neutral Router/A/B message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalWireBytesV1 {
    bytes: Vec<u8>,
}

impl CanonicalWireBytesV1 {
    /// Creates non-empty canonical wire bytes.
    pub fn new(bytes: Vec<u8>) -> RouterAbProtocolResult<Self> {
        if bytes.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "canonical wire bytes must be non-empty",
            ));
        }
        Ok(Self { bytes })
    }

    /// Returns canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for CanonicalWireBytesV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalWireBytesV1")
            .field("len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Transport-neutral message wrapper for local, Workers, and HTTPS adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessageV1 {
    /// Message kind.
    pub kind: WireMessageKindV1,
    /// Public transcript digest this message binds to.
    pub transcript_digest: PublicDigest32,
    /// Canonical payload bytes.
    pub payload: CanonicalWireBytesV1,
}

impl WireMessageV1 {
    /// Creates a validated wire message.
    pub fn new(
        kind: WireMessageKindV1,
        transcript_digest: PublicDigest32,
        payload: CanonicalWireBytesV1,
    ) -> RouterAbProtocolResult<Self> {
        if payload.as_bytes().is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "wire message payload must be non-empty",
            ));
        }
        Ok(Self {
            kind,
            transcript_digest,
            payload,
        })
    }

    /// Returns canonical bytes for transcript and transport binding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_wire_message_v1(self)
    }

    /// Returns the SHA-256 digest of canonical wire bytes.
    pub fn digest(&self) -> PublicDigest32 {
        wire_message_digest_v1(self)
    }
}

/// Encodes a wire message with fixed field order and length-prefixing.
pub fn encode_wire_message_v1(message: &WireMessageV1) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, WIRE_MESSAGE_VERSION_V1);
    push_len32(&mut out, message.kind.as_str().as_bytes());
    push_len32(&mut out, message.transcript_digest.as_bytes());
    push_len32(&mut out, message.payload.as_bytes());
    out
}

/// Computes the public digest of canonical wire bytes.
pub fn wire_message_digest_v1(message: &WireMessageV1) -> PublicDigest32 {
    let digest = Sha256::digest(encode_wire_message_v1(message));
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    PublicDigest32::new(bytes)
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
