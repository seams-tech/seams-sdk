use core::fmt;

use crate::derivation::{PublicDigest32, RequestKind, Role};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::gate::ExpensiveWorkKindV1;
use crate::protocol::identity::{ServerIdentityV1, SignerIdentityV1};

const ROLE_ENVELOPE_AAD_VERSION_V1: &[u8] = b"router-ab-protocol/role-envelope-aad/v1";
const ROLE_ENCRYPTED_ENVELOPE_DIGEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/role-encrypted-envelope-digest/v1";
const SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/signer-envelope-hpke/v1";
const SIGNER_ENVELOPE_HPKE_ALGORITHM_V1: &[u8] = b"hpke-x25519-hkdf-sha256-aes256gcm/v1";
/// Signer-envelope HPKE X25519 encapsulated key length.
pub const SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1: usize = 32;
/// Signer-envelope HPKE AES-GCM tag length.
pub const SIGNER_ENVELOPE_HPKE_TAG_LEN_V1: usize = 16;

/// Encrypted payload bytes. Debug output is redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayloadV1 {
    bytes: Vec<u8>,
}

impl EncryptedPayloadV1 {
    /// Creates a non-empty encrypted payload wrapper.
    pub fn new(bytes: Vec<u8>) -> RouterAbProtocolResult<Self> {
        if bytes.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "encrypted payload must be non-empty",
            ));
        }
        Ok(Self { bytes })
    }

    /// Returns encrypted payload bytes for transport.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for EncryptedPayloadV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPayloadV1")
            .field("len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Parsed signer-envelope HPKE payload before platform-specific decryption.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerEnvelopeHpkePayloadV1 {
    /// Signer role allowed to decrypt this envelope.
    pub recipient_role: Role,
    /// Public envelope decrypt-key epoch.
    pub key_epoch: String,
    /// Public X25519 recipient key used by the client for HPKE seal.
    pub recipient_public_key: String,
    /// Digest of canonical associated-data bytes used during encryption.
    pub aad_digest: PublicDigest32,
    encapped_key: [u8; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1],
    ciphertext_and_tag: Vec<u8>,
}

impl SignerEnvelopeHpkePayloadV1 {
    /// Creates a validated signer-envelope HPKE payload.
    pub fn new(
        recipient_role: Role,
        key_epoch: impl Into<String>,
        recipient_public_key: impl Into<String>,
        aad_digest: PublicDigest32,
        encapped_key: [u8; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1],
        ciphertext_and_tag: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self {
            recipient_role,
            key_epoch: key_epoch.into(),
            recipient_public_key: recipient_public_key.into(),
            aad_digest,
            encapped_key,
            ciphertext_and_tag,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Validates public HPKE payload metadata and ciphertext/tag shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.recipient_role)?;
        require_non_empty("key_epoch", &self.key_epoch)?;
        require_x25519_public_key_encoding("recipient_public_key", &self.recipient_public_key)?;
        if self.ciphertext_and_tag.len() <= SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "signer-envelope HPKE ciphertext must include non-empty ciphertext plus tag",
            ));
        }
        Ok(())
    }

    /// Returns the HPKE encapsulated X25519 key.
    pub fn encapped_key(&self) -> &[u8; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1] {
        &self.encapped_key
    }

    /// Returns ciphertext bytes followed by the HPKE AEAD tag.
    pub fn ciphertext_and_tag(&self) -> &[u8] {
        &self.ciphertext_and_tag
    }

    /// Returns canonical signer-envelope HPKE payload bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_signer_envelope_hpke_payload_v1(self)
    }

    /// Validates this parsed payload against its outer role envelope and key descriptor.
    pub fn validate_for_envelope(
        &self,
        envelope: &RoleEncryptedEnvelopeV1,
        expected_key_epoch: &str,
        expected_recipient_public_key: &str,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        envelope.validate()?;
        require_non_empty("expected_key_epoch", expected_key_epoch)?;
        require_x25519_public_key_encoding(
            "expected_recipient_public_key",
            expected_recipient_public_key,
        )?;
        if self.recipient_role != envelope.recipient_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "signer-envelope HPKE recipient role does not match outer envelope",
            ));
        }
        if self.key_epoch != expected_key_epoch {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-envelope HPKE key epoch does not match expected signer key epoch",
            ));
        }
        if self.recipient_public_key != expected_recipient_public_key {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-envelope HPKE public key does not match expected signer key",
            ));
        }
        if self.aad_digest != envelope.aad_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "signer-envelope HPKE AAD digest does not match outer envelope",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for SignerEnvelopeHpkePayloadV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerEnvelopeHpkePayloadV1")
            .field("recipient_role", &self.recipient_role)
            .field("key_epoch", &self.key_epoch)
            .field("recipient_public_key", &self.recipient_public_key)
            .field("aad_digest", &self.aad_digest)
            .field("encapped_key", &"[redacted]")
            .field("ciphertext_and_tag_len", &self.ciphertext_and_tag.len())
            .field("ciphertext_and_tag", &"[redacted]")
            .finish()
    }
}

/// Public associated data bound to signer-envelope encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEnvelopeAadV1 {
    /// Router lifecycle id.
    pub lifecycle_id: String,
    /// Product-level work kind.
    pub work_kind: ExpensiveWorkKindV1,
    /// Primitive derivation request kind.
    pub primitive_request_kind: RequestKind,
    /// Signer-set id.
    pub signer_set_id: String,
    /// Recipient signer identity.
    pub recipient: SignerIdentityV1,
    /// Selected server identity.
    pub selected_server: ServerIdentityV1,
    /// Public transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Router request digest.
    pub router_request_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl RoleEnvelopeAadV1 {
    /// Creates validated role-envelope associated data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: impl Into<String>,
        work_kind: ExpensiveWorkKindV1,
        signer_set_id: impl Into<String>,
        recipient: SignerIdentityV1,
        selected_server: ServerIdentityV1,
        transcript_digest: PublicDigest32,
        router_request_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let aad = Self {
            lifecycle_id: lifecycle_id.into(),
            work_kind,
            primitive_request_kind: work_kind.primitive_request_kind(),
            signer_set_id: signer_set_id.into(),
            recipient,
            selected_server,
            transcript_digest,
            router_request_digest,
            expires_at_ms,
        };
        aad.validate()?;
        Ok(aad)
    }

    /// Validates role-envelope associated data fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        self.recipient.validate()?;
        self.selected_server.validate()?;
        if self.primitive_request_kind != self.work_kind.primitive_request_kind() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "role-envelope AAD primitive request kind does not match work kind",
            ));
        }
        if self.expires_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "role-envelope AAD expires_at_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    /// Returns canonical associated-data bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_role_envelope_aad_v1(self)
    }

    /// Returns the SHA-256 digest of canonical associated-data bytes.
    pub fn digest(&self) -> PublicDigest32 {
        role_envelope_aad_digest_v1(self)
    }
}

/// Signer-role encrypted envelope forwarded by Router without decryption.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEncryptedEnvelopeV1 {
    /// Signer role allowed to decrypt this envelope.
    pub recipient_role: Role,
    /// Digest of canonical public envelope header bytes.
    pub header_digest: PublicDigest32,
    /// Digest of canonical associated-data bytes.
    pub aad_digest: PublicDigest32,
    /// Opaque ciphertext for the recipient signer.
    pub ciphertext: EncryptedPayloadV1,
}

impl RoleEncryptedEnvelopeV1 {
    /// Creates a validated role-encrypted signer envelope.
    pub fn new(
        recipient_role: Role,
        header_digest: PublicDigest32,
        aad_digest: PublicDigest32,
        ciphertext: EncryptedPayloadV1,
    ) -> RouterAbProtocolResult<Self> {
        require_signer_role(recipient_role)?;
        Ok(Self {
            recipient_role,
            header_digest,
            aad_digest,
            ciphertext,
        })
    }

    /// Validates recipient role and payload shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.recipient_role)?;
        if self.ciphertext.as_bytes().is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "encrypted envelope ciphertext must be non-empty",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for RoleEncryptedEnvelopeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoleEncryptedEnvelopeV1")
            .field("recipient_role", &self.recipient_role)
            .field("header_digest", &self.header_digest)
            .field("aad_digest", &self.aad_digest)
            .field("ciphertext", &"[redacted]")
            .finish()
    }
}

/// Encodes role-envelope associated data with fixed field order.
pub fn encode_role_envelope_aad_v1(aad: &RoleEnvelopeAadV1) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, ROLE_ENVELOPE_AAD_VERSION_V1);
    push_string(&mut out, &aad.lifecycle_id);
    push_len32(&mut out, aad.work_kind.as_str().as_bytes());
    push_len32(&mut out, aad.primitive_request_kind.as_str().as_bytes());
    push_string(&mut out, &aad.signer_set_id);
    push_signer_identity(&mut out, &aad.recipient);
    push_server_identity(&mut out, &aad.selected_server);
    push_public_digest(&mut out, aad.transcript_digest);
    push_public_digest(&mut out, aad.router_request_digest);
    push_u64(&mut out, aad.expires_at_ms);
    out
}

/// Computes the public digest of role-envelope associated data.
pub fn role_envelope_aad_digest_v1(aad: &RoleEnvelopeAadV1) -> PublicDigest32 {
    let digest = Sha256::digest(encode_role_envelope_aad_v1(aad));
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

/// Computes the transcript-bound digest of a role-encrypted signer envelope.
pub fn role_encrypted_envelope_digest_v1(
    envelope: &RoleEncryptedEnvelopeV1,
) -> RouterAbProtocolResult<PublicDigest32> {
    envelope.validate()?;
    let mut bytes = Vec::new();
    push_len32(&mut bytes, ROLE_ENCRYPTED_ENVELOPE_DIGEST_VERSION_V1);
    push_len32(&mut bytes, envelope.recipient_role.as_str().as_bytes());
    push_public_digest(&mut bytes, envelope.header_digest);
    push_public_digest(&mut bytes, envelope.aad_digest);
    push_len32(&mut bytes, envelope.ciphertext.as_bytes());
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(PublicDigest32::new(out))
}

/// Encodes signer-envelope HPKE payload metadata with fixed field order.
pub fn encode_signer_envelope_hpke_payload_v1(payload: &SignerEnvelopeHpkePayloadV1) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1);
    push_len32(&mut out, SIGNER_ENVELOPE_HPKE_ALGORITHM_V1);
    push_len32(&mut out, payload.recipient_role.as_str().as_bytes());
    push_string(&mut out, &payload.key_epoch);
    push_string(&mut out, &payload.recipient_public_key);
    push_public_digest(&mut out, payload.aad_digest);
    push_len32(&mut out, &payload.encapped_key);
    push_u32(&mut out, SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 as u32);
    push_len32(&mut out, &payload.ciphertext_and_tag);
    out
}

/// Decodes canonical signer-envelope HPKE payload bytes.
pub fn decode_signer_envelope_hpke_payload_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<SignerEnvelopeHpkePayloadV1> {
    let mut decoder = EnvelopeDecoder::new(bytes);
    decoder.read_expected_bytes(
        "signer_envelope_hpke_payload_version",
        SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1,
    )?;
    decoder.read_expected_bytes(
        "signer_envelope_hpke_algorithm",
        SIGNER_ENVELOPE_HPKE_ALGORITHM_V1,
    )?;
    let recipient_role = parse_role(decoder.read_string("recipient_role")?)?;
    let key_epoch = decoder.read_string("key_epoch")?;
    let recipient_public_key = decoder.read_string("recipient_public_key")?;
    let aad_digest = decoder.read_public_digest("aad_digest")?;
    let encapped_key = decoder.read_hpke_encapped_key()?;
    let tag_len = decoder.read_u32("tag_len")?;
    if tag_len != SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 as u32 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "signer-envelope HPKE tag length must be 16 bytes",
        ));
    }
    let ciphertext_and_tag = decoder.read_bytes("ciphertext_and_tag")?.to_vec();
    decoder.finish()?;
    SignerEnvelopeHpkePayloadV1::new(
        recipient_role,
        key_epoch,
        recipient_public_key,
        aad_digest,
        encapped_key,
        ciphertext_and_tag,
    )
}

/// Decodes and validates signer-envelope HPKE payload bytes from an outer envelope.
pub fn decode_and_validate_signer_envelope_hpke_payload_v1(
    envelope: &RoleEncryptedEnvelopeV1,
    expected_key_epoch: &str,
    expected_recipient_public_key: &str,
) -> RouterAbProtocolResult<SignerEnvelopeHpkePayloadV1> {
    let payload = decode_signer_envelope_hpke_payload_v1(envelope.ciphertext.as_bytes())?;
    payload.validate_for_envelope(envelope, expected_key_epoch, expected_recipient_public_key)?;
    Ok(payload)
}

fn require_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "role-encrypted envelope recipient must be Signer A or Signer B",
        )),
    }
}

fn require_x25519_public_key_encoding(
    field: &'static str,
    value: &str,
) -> RouterAbProtocolResult<()> {
    let hex = value.strip_prefix("x25519:").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use x25519:<64 lowercase hex chars> encoding"),
        )
    })?;
    if hex.len() != 64 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} hex must be 64 characters"),
        ));
    }
    if !hex
        .as_bytes()
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} hex must be lowercase"),
        ));
    }
    Ok(())
}

fn push_signer_identity(out: &mut Vec<u8>, identity: &SignerIdentityV1) {
    push_len32(out, identity.role.as_str().as_bytes());
    push_string(out, &identity.signer_id);
    push_string(out, &identity.key_epoch);
}

fn push_server_identity(out: &mut Vec<u8>, identity: &ServerIdentityV1) {
    push_string(out, &identity.server_id);
    push_string(out, &identity.key_epoch);
    push_string(out, &identity.recipient_encryption_key);
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

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn parse_role(value: &str) -> RouterAbProtocolResult<Role> {
    match value {
        "signer_a" => Ok(Role::SignerA),
        "signer_b" => Ok(Role::SignerB),
        "router" => Ok(Role::Router),
        "server" => Ok(Role::Server),
        "client" => Ok(Role::Client),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "unknown role-encrypted envelope role",
        )),
    }
}

struct EnvelopeDecoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> EnvelopeDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn read_expected_bytes(
        &mut self,
        field: &'static str,
        expected: &[u8],
    ) -> RouterAbProtocolResult<()> {
        let actual = self.read_bytes(field)?;
        if actual != expected {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} is unsupported"),
            ));
        }
        Ok(())
    }

    fn read_string(&mut self, field: &'static str) -> RouterAbProtocolResult<&'a str> {
        let bytes = self.read_bytes(field)?;
        core::str::from_utf8(bytes).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} must be UTF-8"),
            )
        })
    }

    fn read_public_digest(
        &mut self,
        field: &'static str,
    ) -> RouterAbProtocolResult<PublicDigest32> {
        let bytes = self.read_bytes(field)?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} must be 32 bytes"),
            )
        })?;
        Ok(PublicDigest32::new(digest))
    }

    fn read_hpke_encapped_key(
        &mut self,
    ) -> RouterAbProtocolResult<[u8; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1]> {
        let bytes = self.read_bytes("encapped_key")?;
        bytes.try_into().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "signer-envelope HPKE encapsulated key must be 32 bytes",
            )
        })
    }

    fn read_u32(&mut self, field: &'static str) -> RouterAbProtocolResult<u32> {
        if self.input.len().saturating_sub(self.pos) < 4 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length is truncated"),
            ));
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.input[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_bytes(&mut self, field: &'static str) -> RouterAbProtocolResult<&'a [u8]> {
        let len = self.read_len(field)?;
        if self.input.len().saturating_sub(self.pos) < len {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length exceeds remaining bytes"),
            ));
        }
        let bytes = &self.input[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn read_len(&mut self, field: &'static str) -> RouterAbProtocolResult<usize> {
        if self.input.len().saturating_sub(self.pos) < 4 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length is truncated"),
            ));
        }
        let mut len = [0u8; 4];
        len.copy_from_slice(&self.input[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(len) as usize)
    }

    fn finish(&self) -> RouterAbProtocolResult<()> {
        if self.pos == self.input.len() {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "signer-envelope payload has trailing bytes",
        ))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> PublicDigest32 {
        PublicDigest32::new([byte; 32])
    }

    fn x25519_key(byte: u8) -> String {
        let mut out = String::from("x25519:");
        for _ in 0..32 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn hpke_payload(public_key: &str) -> SignerEnvelopeHpkePayloadV1 {
        SignerEnvelopeHpkePayloadV1::new(
            Role::SignerA,
            "envelope-key-epoch-a",
            public_key,
            digest(0x11),
            [0x44; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1],
            vec![0x55; SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 + 1],
        )
        .expect("hpke payload")
    }

    #[test]
    fn signer_envelope_hpke_payload_round_trips_and_validates_outer_envelope() {
        let public_key = x25519_key(0x11);
        let payload = hpke_payload(&public_key);
        let envelope = RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            digest(0x33),
            digest(0x11),
            EncryptedPayloadV1::new(payload.canonical_bytes()).expect("payload bytes"),
        )
        .expect("outer envelope");

        let decoded = decode_and_validate_signer_envelope_hpke_payload_v1(
            &envelope,
            "envelope-key-epoch-a",
            &public_key,
        )
        .expect("validated hpke payload");

        assert_eq!(decoded, payload);
        assert_eq!(
            decoded.encapped_key(),
            &[0x44; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1]
        );
        assert_eq!(
            decoded.ciphertext_and_tag(),
            &[0x55; SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 + 1]
        );
    }

    #[test]
    fn signer_envelope_hpke_payload_rejects_wrong_expected_public_key() {
        let public_key = x25519_key(0x11);
        let payload = hpke_payload(&public_key);
        let envelope = RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            digest(0x33),
            digest(0x11),
            EncryptedPayloadV1::new(payload.canonical_bytes()).expect("payload bytes"),
        )
        .expect("outer envelope");

        let err = decode_and_validate_signer_envelope_hpke_payload_v1(
            &envelope,
            "envelope-key-epoch-a",
            &x25519_key(0x22),
        )
        .expect_err("wrong expected public key must fail");

        assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
    }

    #[test]
    fn signer_envelope_hpke_payload_rejects_bad_public_key_encoding() {
        let err = SignerEnvelopeHpkePayloadV1::new(
            Role::SignerA,
            "envelope-key-epoch-a",
            "x25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            digest(0x11),
            [0x44; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1],
            vec![0x55; SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 + 1],
        )
        .expect_err("uppercase public key hex must fail");

        assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
    }
}
