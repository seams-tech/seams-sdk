use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::context::{CandidateId, CorrectnessLevel, RequestKind, RootShareEpoch};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{PublicDigest32, Role};

const ENVELOPE_AAD_VERSION: &[u8] = b"router-ab-derivation/envelope-aad/v1";
const PACKAGE_COMMITMENT_VERSION: &[u8] = b"router-ab-derivation/package-commitment/v1";
const ENVELOPE_IDEMPOTENCY_VERSION: &[u8] = b"router-ab-derivation/envelope-idempotency/v1";

/// Envelope wire version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeVersion {
    /// Initial envelope version.
    V1,
}

impl EnvelopeVersion {
    fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

/// Public envelope kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// Router sends signer input to Signer A.
    RouterToSignerA,
    /// Router sends signer input to Signer B.
    RouterToSignerB,
    /// Signer A sends coordination material to Signer B.
    SignerAToSignerB,
    /// Signer B sends coordination material to Signer A.
    SignerBToSignerA,
    /// Signer A sends client output material to the client.
    SignerAToClient,
    /// Signer B sends client output material to the client.
    SignerBToClient,
    /// Signer A sends relayer output material to the relayer.
    SignerAToRelayer,
    /// Signer B sends relayer output material to the relayer.
    SignerBToRelayer,
}

impl EnvelopeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::RouterToSignerA => "router_to_signer_a",
            Self::RouterToSignerB => "router_to_signer_b",
            Self::SignerAToSignerB => "signer_a_to_signer_b",
            Self::SignerBToSignerA => "signer_b_to_signer_a",
            Self::SignerAToClient => "signer_a_to_client",
            Self::SignerBToClient => "signer_b_to_client",
            Self::SignerAToRelayer => "signer_a_to_relayer",
            Self::SignerBToRelayer => "signer_b_to_relayer",
        }
    }

    fn expected_roles(self) -> (Role, Role) {
        match self {
            Self::RouterToSignerA => (Role::Router, Role::SignerA),
            Self::RouterToSignerB => (Role::Router, Role::SignerB),
            Self::SignerAToSignerB => (Role::SignerA, Role::SignerB),
            Self::SignerBToSignerA => (Role::SignerB, Role::SignerA),
            Self::SignerAToClient => (Role::SignerA, Role::Client),
            Self::SignerBToClient => (Role::SignerB, Role::Client),
            Self::SignerAToRelayer => (Role::SignerA, Role::Relayer),
            Self::SignerBToRelayer => (Role::SignerB, Role::Relayer),
        }
    }
}

/// Envelope plaintext content kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    /// Signer input material.
    SignerInput,
    /// A-to-B coordination message.
    AToBCoordination,
    /// B-to-A coordination message.
    BToACoordination,
    /// Client-output share.
    ClientOutputShare,
    /// Relayer-output share.
    RelayerOutputShare,
    /// Minimum Level C evidence.
    MinimumLevelCEvidence,
    /// Public-share-binding evidence.
    PublicShareBindingEvidence,
}

impl ContentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignerInput => "signer_input",
            Self::AToBCoordination => "a_to_b_coordination",
            Self::BToACoordination => "b_to_a_coordination",
            Self::ClientOutputShare => "client_output_share",
            Self::RelayerOutputShare => "relayer_output_share",
            Self::MinimumLevelCEvidence => "minimum_level_c_evidence",
            Self::PublicShareBindingEvidence => "public_share_binding_evidence",
        }
    }
}

/// Public envelope header. Ciphertext bytes stay adapter-owned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeHeaderV1 {
    /// Envelope version.
    pub envelope_version: EnvelopeVersion,
    /// Envelope kind.
    pub envelope_kind: EnvelopeKind,
    /// Candidate family.
    pub candidate_id: CandidateId,
    /// Request kind.
    pub request_kind: RequestKind,
    /// Correctness level.
    pub correctness_level: CorrectnessLevel,
    /// Router-assigned ceremony id.
    pub ceremony_id: String,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Sender role.
    pub sender_role: Role,
    /// Sender identity.
    pub sender_identity: String,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Plaintext content kind.
    pub content_kind: ContentKind,
    /// Ciphertext digest.
    pub ciphertext_digest: PublicDigest32,
    /// Ciphertext length in bytes.
    pub ciphertext_len: u64,
}

impl EnvelopeHeaderV1 {
    /// Validates the public envelope header.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("ceremony_id", &self.ceremony_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("sender_identity", &self.sender_identity)?;
        require_non_empty("recipient_identity", &self.recipient_identity)?;

        let (expected_sender, expected_recipient) = self.envelope_kind.expected_roles();
        if self.sender_role != expected_sender || self.recipient_role != expected_recipient {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "envelope kind does not match sender and recipient roles",
            ));
        }

        Ok(())
    }
}

/// Delivery package public commitment input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryPackageV1 {
    /// Public envelope header.
    pub header: EnvelopeHeaderV1,
}

impl DeliveryPackageV1 {
    /// Validates package metadata.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        self.header.validate()
    }
}

/// Encodes envelope associated data V1.
pub fn envelope_aad_v1(header: &EnvelopeHeaderV1) -> RouterAbDerivationResult<Vec<u8>> {
    header.validate()?;

    let mut out = Vec::new();
    push_vec_field(&mut out, ENVELOPE_AAD_VERSION);
    push_header_aad_fields(&mut out, header);
    Ok(out)
}

/// Computes the V1 delivery package commitment.
pub fn package_commitment_v1(
    package: &DeliveryPackageV1,
) -> RouterAbDerivationResult<PublicDigest32> {
    package.validate()?;

    let header_encoding = envelope_header_commitment_encoding_v1(&package.header)?;
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, PACKAGE_COMMITMENT_VERSION);
    push_hash_field(&mut hasher, &header_encoding);
    push_hash_field(&mut hasher, package.header.ciphertext_digest.as_bytes());
    Ok(PublicDigest32::new(hasher.finalize().into()))
}

/// Computes the V1 envelope idempotency key.
pub fn envelope_idempotency_key_v1(
    header: &EnvelopeHeaderV1,
) -> RouterAbDerivationResult<PublicDigest32> {
    header.validate()?;

    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, ENVELOPE_IDEMPOTENCY_VERSION);
    push_hash_field(&mut hasher, header.transcript_digest.as_bytes());
    push_hash_field(&mut hasher, header.envelope_kind.as_str().as_bytes());
    push_hash_field(&mut hasher, header.sender_identity.as_bytes());
    push_hash_field(&mut hasher, header.recipient_identity.as_bytes());
    push_hash_field(&mut hasher, header.content_kind.as_str().as_bytes());
    Ok(PublicDigest32::new(hasher.finalize().into()))
}

fn envelope_header_commitment_encoding_v1(
    header: &EnvelopeHeaderV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    header.validate()?;

    let mut out = Vec::new();
    push_header_aad_fields(&mut out, header);
    push_vec_field(&mut out, header.ciphertext_len.to_string().as_bytes());
    Ok(out)
}

fn push_header_aad_fields(out: &mut Vec<u8>, header: &EnvelopeHeaderV1) {
    push_vec_field(out, header.envelope_version.as_str().as_bytes());
    push_vec_field(out, header.envelope_kind.as_str().as_bytes());
    push_vec_field(out, header.candidate_id.as_str().as_bytes());
    push_vec_field(out, header.request_kind.as_str().as_bytes());
    push_vec_field(out, header.correctness_level.as_str().as_bytes());
    push_vec_field(out, header.ceremony_id.as_bytes());
    push_vec_field(out, header.root_share_epoch.as_str().as_bytes());
    push_vec_field(out, header.transcript_digest.as_bytes());
    push_vec_field(out, header.sender_role.as_str().as_bytes());
    push_vec_field(out, header.sender_identity.as_bytes());
    push_vec_field(out, header.recipient_role.as_str().as_bytes());
    push_vec_field(out, header.recipient_identity.as_bytes());
    push_vec_field(out, header.content_kind.as_str().as_bytes());
}

fn push_vec_field(out: &mut Vec<u8>, value: &[u8]) {
    let len = value.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

fn push_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let len = value.len() as u32;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}
