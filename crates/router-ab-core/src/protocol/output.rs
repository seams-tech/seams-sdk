use crate::derivation::{
    combine_mpc_prf_proof_bundles_with_threshold_backend_v1, MpcPrfPartialProofBundleV1,
    MpcPrfThresholdCombineInputV1, MpcPrfThresholdCombinedOutputV1,
    MpcPrfThresholdSignerBatchOutputV1, OpenedShareKind, PublicDigest32, Role,
    RootShareCommitmentRegistryV1, RouterAbDerivationError, SecretMaterial32,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::envelope::EncryptedPayloadV1;
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::identity::{SignerIdentityV1, SignerSetV1};
use crate::protocol::lifecycle::LifecycleScopeV1;
use crate::protocol::payload::{
    router_transcript_binding_v1, EcdsaThresholdPrfProofBatchPayloadV1,
    RecipientProofBundlePayloadV1, RouterToSignerPayloadV1, RouterTranscriptMetadataV1,
    SigningWorkerActivationContextV1,
};
use crate::protocol::wire::{CanonicalWireBytesV1, WireMessageKindV1, WireMessageV1};

const RECIPIENT_OUTPUT_CIPHERTEXT_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-output-ciphertext/v1";
const RECIPIENT_OUTPUT_CIPHERTEXT_AAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-output-ciphertext-aad/v1";
const RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-proof-bundle-ciphertext/v1";
const RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_AAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-proof-bundle-ciphertext-aad/v1";
const FIXED_ECDSA_DERIVATION_SUITE_V1: &[u8] = b"threshold-prf/ristretto255-sha512";
/// Nonce length used by the recipient-output AEAD envelope.
pub const RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1: usize = 12;

/// Recipient-output encryption algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientOutputEncryptionAlgorithmV1 {
    /// Local deterministic development envelope; production adapters must replace it.
    LocalDeterministicSha256V1,
    /// HPKE-style recipient delivery using X25519, HKDF-SHA256, and AES-256-GCM.
    HpkeX25519HkdfSha256Aes256GcmV1,
}

impl RecipientOutputEncryptionAlgorithmV1 {
    /// Returns the canonical algorithm label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalDeterministicSha256V1 => "local_deterministic_sha256_v1",
            Self::HpkeX25519HkdfSha256Aes256GcmV1 => "hpke_x25519_hkdf_sha256_aes256gcm_v1",
        }
    }
}

/// Typed ciphertext envelope for recipient-bound output delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientOutputCiphertextV1 {
    /// Encryption algorithm identifier.
    pub algorithm: RecipientOutputEncryptionAlgorithmV1,
    /// Intended recipient role.
    pub recipient_role: Role,
    /// Opened share kind carried by the plaintext.
    pub opened_share_kind: OpenedShareKind,
    /// Intended recipient identity.
    pub recipient_identity: String,
    /// Recipient encryption key or public-key reference.
    pub recipient_encryption_key: String,
    /// Transcript digest bound into the envelope.
    pub transcript_digest: PublicDigest32,
    /// Output package commitment bound into the envelope.
    pub package_commitment: PublicDigest32,
    nonce: [u8; RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1],
    ciphertext_and_tag: EncryptedPayloadV1,
}

impl RecipientOutputCiphertextV1 {
    /// Creates a validated recipient output ciphertext envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        algorithm: RecipientOutputEncryptionAlgorithmV1,
        recipient_role: Role,
        opened_share_kind: OpenedShareKind,
        recipient_identity: impl Into<String>,
        recipient_encryption_key: impl Into<String>,
        transcript_digest: PublicDigest32,
        package_commitment: PublicDigest32,
        nonce: [u8; RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1],
        ciphertext_and_tag: EncryptedPayloadV1,
    ) -> RouterAbProtocolResult<Self> {
        let envelope = Self {
            algorithm,
            recipient_role,
            opened_share_kind,
            recipient_identity: recipient_identity.into(),
            recipient_encryption_key: recipient_encryption_key.into(),
            transcript_digest,
            package_commitment,
            nonce,
            ciphertext_and_tag,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates recipient and envelope metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        require_non_empty("recipient_encryption_key", &self.recipient_encryption_key)?;
        validate_recipient_output_binding(self.recipient_role, self.opened_share_kind)?;
        validate_recipient_encryption_key(self.algorithm, &self.recipient_encryption_key)
    }

    /// Returns the AEAD nonce.
    pub fn nonce(&self) -> &[u8; RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1] {
        &self.nonce
    }

    /// Returns ciphertext bytes followed by authentication tag bytes.
    pub fn ciphertext_and_tag(&self) -> &EncryptedPayloadV1 {
        &self.ciphertext_and_tag
    }

    /// Returns canonical envelope bytes.
    pub fn canonical_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        encode_recipient_output_ciphertext_v1(self)
    }
}

/// Typed ciphertext envelope for recipient-bound proof-bundle delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientProofBundleCiphertextV1 {
    /// Encryption algorithm identifier.
    pub algorithm: RecipientOutputEncryptionAlgorithmV1,
    /// Producing signer identity.
    pub signer: SignerIdentityV1,
    /// Intended recipient role.
    pub recipient_role: Role,
    /// Opened share kind carried by the encrypted proof bundle.
    pub opened_share_kind: OpenedShareKind,
    /// Intended recipient identity.
    pub recipient_identity: String,
    /// Recipient encryption key or public-key reference.
    pub recipient_encryption_key: String,
    /// Transcript digest bound into the envelope.
    pub transcript_digest: PublicDigest32,
    /// Digest of the encrypted canonical `RecipientProofBundlePayloadV1`.
    pub payload_digest: PublicDigest32,
    nonce: [u8; RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1],
    ciphertext_and_tag: EncryptedPayloadV1,
}

impl RecipientProofBundleCiphertextV1 {
    /// Creates a validated recipient proof-bundle ciphertext envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        algorithm: RecipientOutputEncryptionAlgorithmV1,
        signer: SignerIdentityV1,
        recipient_role: Role,
        opened_share_kind: OpenedShareKind,
        recipient_identity: impl Into<String>,
        recipient_encryption_key: impl Into<String>,
        transcript_digest: PublicDigest32,
        payload_digest: PublicDigest32,
        nonce: [u8; RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1],
        ciphertext_and_tag: EncryptedPayloadV1,
    ) -> RouterAbProtocolResult<Self> {
        let envelope = Self {
            algorithm,
            signer,
            recipient_role,
            opened_share_kind,
            recipient_identity: recipient_identity.into(),
            recipient_encryption_key: recipient_encryption_key.into(),
            transcript_digest,
            payload_digest,
            nonce,
            ciphertext_and_tag,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates recipient and envelope metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.signer.validate()?;
        match self.signer.role {
            Role::SignerA | Role::SignerB => {}
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidRole,
                    "recipient proof-bundle ciphertext signer must be Signer A or Signer B",
                ));
            }
        }
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        require_non_empty("recipient_encryption_key", &self.recipient_encryption_key)?;
        validate_recipient_output_binding(self.recipient_role, self.opened_share_kind)?;
        validate_recipient_encryption_key(self.algorithm, &self.recipient_encryption_key)
    }

    /// Returns the AEAD nonce.
    pub fn nonce(&self) -> &[u8; RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1] {
        &self.nonce
    }

    /// Returns ciphertext bytes followed by authentication tag bytes.
    pub fn ciphertext_and_tag(&self) -> &EncryptedPayloadV1 {
        &self.ciphertext_and_tag
    }

    /// Returns canonical envelope bytes.
    pub fn canonical_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        encode_recipient_proof_bundle_ciphertext_v1(self)
    }

    /// Returns the SHA-256 digest of canonical envelope bytes.
    pub fn digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        recipient_proof_bundle_ciphertext_digest_v1(self)
    }
}

/// Validated request passed into adapter-owned recipient-output encryption.
pub struct RecipientOutputEncryptionRequestV1<'a> {
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    recipient_identity: String,
    recipient_encryption_key: String,
    transcript_digest: PublicDigest32,
    package_commitment: PublicDigest32,
    plaintext: &'a SecretMaterial32,
}

impl<'a> RecipientOutputEncryptionRequestV1<'a> {
    /// Creates a validated recipient-output encryption request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recipient_role: Role,
        opened_share_kind: OpenedShareKind,
        recipient_identity: impl Into<String>,
        recipient_encryption_key: impl Into<String>,
        transcript_digest: PublicDigest32,
        package_commitment: PublicDigest32,
        plaintext: &'a SecretMaterial32,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            recipient_role,
            opened_share_kind,
            recipient_identity: recipient_identity.into(),
            recipient_encryption_key: recipient_encryption_key.into(),
            transcript_digest,
            package_commitment,
            plaintext,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates public encryption request metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        require_non_empty("recipient_encryption_key", &self.recipient_encryption_key)?;
        validate_recipient_output_binding(self.recipient_role, self.opened_share_kind)
    }

    /// Returns the recipient role.
    pub fn recipient_role(&self) -> Role {
        self.recipient_role
    }

    /// Returns the opened share kind.
    pub fn opened_share_kind(&self) -> OpenedShareKind {
        self.opened_share_kind
    }

    /// Returns the recipient identity.
    pub fn recipient_identity(&self) -> &str {
        &self.recipient_identity
    }

    /// Returns the recipient encryption key or key reference.
    pub fn recipient_encryption_key(&self) -> &str {
        &self.recipient_encryption_key
    }

    /// Returns the transcript digest.
    pub fn transcript_digest(&self) -> PublicDigest32 {
        self.transcript_digest
    }

    /// Returns the package commitment.
    pub fn package_commitment(&self) -> PublicDigest32 {
        self.package_commitment
    }

    /// Returns the secret plaintext material for adapter encryption.
    pub fn plaintext(&self) -> &SecretMaterial32 {
        self.plaintext
    }
}

/// Adapter-owned recipient-output encryption boundary.
pub trait RecipientOutputEncryptorV1 {
    /// Encrypts one recipient output and returns the typed ciphertext envelope.
    fn encrypt_recipient_output_v1(
        &mut self,
        request: RecipientOutputEncryptionRequestV1<'_>,
    ) -> RouterAbProtocolResult<RecipientOutputCiphertextV1>;
}

/// Validated request passed into adapter-owned proof-bundle encryption.
pub struct RecipientProofBundleEncryptionRequestV1 {
    signer: SignerIdentityV1,
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    recipient_identity: String,
    recipient_encryption_key: String,
    transcript_digest: PublicDigest32,
    payload_digest: PublicDigest32,
    plaintext: Vec<u8>,
}

impl core::fmt::Debug for RecipientProofBundleEncryptionRequestV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecipientProofBundleEncryptionRequestV1")
            .field("recipient_role", &self.recipient_role)
            .field("signer", &self.signer)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("recipient_identity", &self.recipient_identity)
            .field("recipient_encryption_key", &self.recipient_encryption_key)
            .field("transcript_digest", &self.transcript_digest)
            .field("payload_digest", &self.payload_digest)
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

impl RecipientProofBundleEncryptionRequestV1 {
    /// Creates a validated proof-bundle encryption request from a typed payload.
    pub fn new(
        payload: &RecipientProofBundlePayloadV1,
        recipient_encryption_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        payload.validate()?;
        let request = Self {
            recipient_role: payload.recipient_role,
            signer: payload.signer.clone(),
            opened_share_kind: payload.opened_share_kind,
            recipient_identity: payload.recipient_identity.clone(),
            recipient_encryption_key: recipient_encryption_key.into(),
            transcript_digest: payload.transcript_digest,
            payload_digest: payload.digest(),
            plaintext: payload.canonical_bytes(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates public proof-bundle encryption request metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        require_non_empty("recipient_encryption_key", &self.recipient_encryption_key)?;
        self.signer.validate()?;
        match self.signer.role {
            Role::SignerA | Role::SignerB => {}
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidRole,
                    "recipient proof-bundle encryption signer must be Signer A or Signer B",
                ));
            }
        }
        if self.plaintext.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "recipient proof-bundle encryption plaintext must be non-empty",
            ));
        }
        validate_recipient_output_binding(self.recipient_role, self.opened_share_kind)
    }

    /// Returns the recipient role.
    pub fn recipient_role(&self) -> Role {
        self.recipient_role
    }

    /// Returns the producing signer.
    pub fn signer(&self) -> &SignerIdentityV1 {
        &self.signer
    }

    /// Returns the opened share kind.
    pub fn opened_share_kind(&self) -> OpenedShareKind {
        self.opened_share_kind
    }

    /// Returns the recipient identity.
    pub fn recipient_identity(&self) -> &str {
        &self.recipient_identity
    }

    /// Returns the recipient encryption key or key reference.
    pub fn recipient_encryption_key(&self) -> &str {
        &self.recipient_encryption_key
    }

    /// Returns the transcript digest.
    pub fn transcript_digest(&self) -> PublicDigest32 {
        self.transcript_digest
    }

    /// Returns the proof-bundle payload digest.
    pub fn payload_digest(&self) -> PublicDigest32 {
        self.payload_digest
    }

    /// Returns canonical `RecipientProofBundlePayloadV1` plaintext bytes.
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// Adapter-owned proof-bundle encryption boundary.
pub trait RecipientProofBundleEncryptorV1 {
    /// Encrypts one recipient proof bundle and returns the typed ciphertext envelope.
    fn encrypt_recipient_proof_bundle_v1(
        &mut self,
        request: RecipientProofBundleEncryptionRequestV1,
    ) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1>;
}

/// Converts a validated A/B proof-batch payload into an ECDSA threshold-PRF batch output.
pub fn mpc_prf_batch_output_from_ab_proof_batch_v1(
    proof_batch: EcdsaThresholdPrfProofBatchPayloadV1,
) -> RouterAbProtocolResult<MpcPrfThresholdSignerBatchOutputV1> {
    proof_batch.validate()?;
    Ok(MpcPrfThresholdSignerBatchOutputV1 {
        transcript_digest: proof_batch.transcript_digest,
        signer_role: proof_batch.from.role,
        signer_identity: proof_batch.from.signer_id,
        root_share_epoch: proof_batch.root_share_epoch,
        proof_bundles: proof_batch.proof_bundles,
    })
}

/// Returns a proof-batch view containing only one recipient output binding.
pub fn ecdsa_threshold_prf_proof_batch_recipient_view_v1(
    proof_batch: EcdsaThresholdPrfProofBatchPayloadV1,
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: &str,
) -> RouterAbProtocolResult<EcdsaThresholdPrfProofBatchPayloadV1> {
    validate_recipient_output_binding(recipient_role, opened_share_kind)?;
    require_non_empty("recipient_identity", recipient_identity)?;
    proof_batch.validate()?;
    let EcdsaThresholdPrfProofBatchPayloadV1 {
        from,
        to,
        transcript_digest,
        root_share_epoch,
        proof_bundles,
    } = proof_batch;
    let matching_bundles = proof_bundles
        .into_iter()
        .filter(|bundle| {
            let binding = &bundle.signer_partial.binding;
            binding.opened_share_kind == opened_share_kind
                && binding.recipient_role == recipient_role
                && binding.recipient_identity == recipient_identity
        })
        .collect::<Vec<_>>();
    if matching_bundles.len() != 1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "recipient proof-batch view requires exactly one matching output binding",
        ));
    }
    EcdsaThresholdPrfProofBatchPayloadV1::new(
        from,
        to,
        transcript_digest,
        root_share_epoch,
        matching_bundles,
    )
}

/// Builds a recipient-scoped proof-bundle payload from a full signer proof batch.
pub fn recipient_proof_bundle_payload_from_ab_proof_batch_v1(
    lifecycle_id: &str,
    proof_batch: EcdsaThresholdPrfProofBatchPayloadV1,
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: &str,
) -> RouterAbProtocolResult<RecipientProofBundlePayloadV1> {
    let proof_batch = ecdsa_threshold_prf_proof_batch_recipient_view_v1(
        proof_batch,
        opened_share_kind,
        recipient_role,
        recipient_identity,
    )?;
    RecipientProofBundlePayloadV1::new(
        lifecycle_id,
        proof_batch.from.clone(),
        recipient_role,
        opened_share_kind,
        recipient_identity,
        proof_batch.transcript_digest,
        proof_batch,
    )
}

/// Encrypts a recipient-scoped proof-bundle payload through an adapter boundary.
pub fn encrypt_recipient_proof_bundle_payload_v1(
    payload: &RecipientProofBundlePayloadV1,
    recipient_encryption_key: &str,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
    let request = RecipientProofBundleEncryptionRequestV1::new(payload, recipient_encryption_key)?;
    encryptor.encrypt_recipient_proof_bundle_v1(request)
}

/// Builds an encrypted recipient proof-bundle wire message from one signer proof batch.
pub fn recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
    lifecycle_id: &str,
    proof_batch: EcdsaThresholdPrfProofBatchPayloadV1,
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: &str,
    recipient_encryption_key: &str,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    let payload = recipient_proof_bundle_payload_from_ab_proof_batch_v1(
        lifecycle_id,
        proof_batch,
        opened_share_kind,
        recipient_role,
        recipient_identity,
    )?;
    let envelope =
        encrypt_recipient_proof_bundle_payload_v1(&payload, recipient_encryption_key, encryptor)?;
    WireMessageV1::new(
        WireMessageKindV1::RecipientProofBundle,
        envelope.transcript_digest,
        CanonicalWireBytesV1::new(envelope.canonical_bytes()?)?,
    )
}

/// Combines exactly one recipient-scoped output from authenticated A/B proof batches.
pub fn combine_mpc_prf_recipient_output_from_ab_proof_batches_v1(
    router_payload: &RouterToSignerPayloadV1,
    commitment_registry: &RootShareCommitmentRegistryV1,
    proof_batch_a: EcdsaThresholdPrfProofBatchPayloadV1,
    proof_batch_b: EcdsaThresholdPrfProofBatchPayloadV1,
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: &str,
) -> RouterAbProtocolResult<MpcPrfThresholdCombinedOutputV1> {
    router_payload.validate()?;
    combine_mpc_prf_recipient_output_from_public_context_v1(
        router_payload.lifecycle(),
        router_payload.signer_set(),
        router_payload.transcript_metadata(),
        router_payload.transcript_digest(),
        commitment_registry,
        proof_batch_a,
        proof_batch_b,
        opened_share_kind,
        recipient_role,
        recipient_identity,
    )
}

/// Combines one recipient output from decrypted Signer A/B proof-bundle payloads.
pub fn combine_mpc_prf_recipient_output_from_proof_bundle_payloads_v1(
    router_payload: &RouterToSignerPayloadV1,
    commitment_registry: &RootShareCommitmentRegistryV1,
    signer_a_payload: RecipientProofBundlePayloadV1,
    signer_b_payload: RecipientProofBundlePayloadV1,
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: &str,
) -> RouterAbProtocolResult<MpcPrfThresholdCombinedOutputV1> {
    require_recipient_proof_bundle_payload_v1(
        "signer_a_payload",
        &signer_a_payload,
        Role::SignerA,
        opened_share_kind,
        recipient_role,
        recipient_identity,
        router_payload,
    )?;
    require_recipient_proof_bundle_payload_v1(
        "signer_b_payload",
        &signer_b_payload,
        Role::SignerB,
        opened_share_kind,
        recipient_role,
        recipient_identity,
        router_payload,
    )?;
    combine_mpc_prf_recipient_output_from_ab_proof_batches_v1(
        router_payload,
        commitment_registry,
        signer_a_payload.proof_batch,
        signer_b_payload.proof_batch,
        opened_share_kind,
        recipient_role,
        recipient_identity,
    )
}

/// Combines SigningWorker `x_server_base` output from decrypted A/B proof-bundle payloads.
pub fn combine_mpc_prf_signing_worker_output_from_activation_context_v1(
    activation_context: &SigningWorkerActivationContextV1,
    commitment_registry: &RootShareCommitmentRegistryV1,
    signer_a_payload: RecipientProofBundlePayloadV1,
    signer_b_payload: RecipientProofBundlePayloadV1,
) -> RouterAbProtocolResult<MpcPrfThresholdCombinedOutputV1> {
    activation_context.validate()?;
    let selected_worker = &activation_context.signer_set().selected_server;
    require_recipient_proof_bundle_payload_for_transcript_v1(
        "signer_a_payload",
        &signer_a_payload,
        Role::SignerA,
        OpenedShareKind::XServerBase,
        Role::Server,
        &selected_worker.server_id,
        activation_context.transcript_digest(),
    )?;
    require_recipient_proof_bundle_payload_for_transcript_v1(
        "signer_b_payload",
        &signer_b_payload,
        Role::SignerB,
        OpenedShareKind::XServerBase,
        Role::Server,
        &selected_worker.server_id,
        activation_context.transcript_digest(),
    )?;
    combine_mpc_prf_recipient_output_from_public_context_v1(
        activation_context.lifecycle(),
        activation_context.signer_set(),
        activation_context.transcript_metadata(),
        activation_context.transcript_digest(),
        commitment_registry,
        signer_a_payload.proof_batch,
        signer_b_payload.proof_batch,
        OpenedShareKind::XServerBase,
        Role::Server,
        &selected_worker.server_id,
    )
}

fn require_recipient_proof_bundle_payload_v1(
    field: &str,
    payload: &RecipientProofBundlePayloadV1,
    expected_signer_role: Role,
    expected_opened_share_kind: OpenedShareKind,
    expected_recipient_role: Role,
    expected_recipient_identity: &str,
    router_payload: &RouterToSignerPayloadV1,
) -> RouterAbProtocolResult<()> {
    payload.validate()?;
    router_payload.validate()?;
    require_recipient_proof_bundle_payload_for_transcript_v1(
        field,
        payload,
        expected_signer_role,
        expected_opened_share_kind,
        expected_recipient_role,
        expected_recipient_identity,
        router_payload.transcript_digest(),
    )
}

fn require_recipient_proof_bundle_payload_for_transcript_v1(
    field: &str,
    payload: &RecipientProofBundlePayloadV1,
    expected_signer_role: Role,
    expected_opened_share_kind: OpenedShareKind,
    expected_recipient_role: Role,
    expected_recipient_identity: &str,
    expected_transcript_digest: PublicDigest32,
) -> RouterAbProtocolResult<()> {
    payload.validate()?;
    require_proof_batch_role_v1(field, &payload.proof_batch, expected_signer_role)?;
    if payload.opened_share_kind != expected_opened_share_kind
        || payload.recipient_role != expected_recipient_role
        || payload.recipient_identity != expected_recipient_identity
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} recipient binding does not match requested output"),
        ));
    }
    if payload.transcript_digest != expected_transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} transcript does not match activation context"),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn combine_mpc_prf_recipient_output_from_public_context_v1(
    lifecycle: &LifecycleScopeV1,
    signer_set: &SignerSetV1,
    transcript_metadata: &RouterTranscriptMetadataV1,
    expected_transcript_digest: PublicDigest32,
    commitment_registry: &RootShareCommitmentRegistryV1,
    proof_batch_a: EcdsaThresholdPrfProofBatchPayloadV1,
    proof_batch_b: EcdsaThresholdPrfProofBatchPayloadV1,
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: &str,
) -> RouterAbProtocolResult<MpcPrfThresholdCombinedOutputV1> {
    lifecycle.validate()?;
    signer_set.validate()?;
    transcript_metadata.validate()?;
    validate_recipient_output_binding(recipient_role, opened_share_kind)?;
    require_non_empty("recipient_identity", recipient_identity)?;
    let proof_batch_a = ecdsa_threshold_prf_proof_batch_recipient_view_v1(
        proof_batch_a,
        opened_share_kind,
        recipient_role,
        recipient_identity,
    )?;
    let proof_batch_b = ecdsa_threshold_prf_proof_batch_recipient_view_v1(
        proof_batch_b,
        opened_share_kind,
        recipient_role,
        recipient_identity,
    )?;
    require_proof_batch_role_v1("proof_batch_a", &proof_batch_a, Role::SignerA)?;
    require_proof_batch_role_v1("proof_batch_b", &proof_batch_b, Role::SignerB)?;
    require_proof_batches_match_public_context_v1(
        lifecycle,
        expected_transcript_digest,
        &proof_batch_a,
        &proof_batch_b,
    )?;
    let transcript = router_transcript_binding_v1(
        lifecycle,
        signer_set,
        transcript_metadata,
        lifecycle.root_share_epoch.clone(),
    )?;
    let left = single_proof_bundle_v1("proof_batch_a", proof_batch_a.proof_bundles)?;
    let right = single_proof_bundle_v1("proof_batch_b", proof_batch_b.proof_bundles)?;
    combine_mpc_prf_proof_bundles_with_threshold_backend_v1(MpcPrfThresholdCombineInputV1 {
        transcript,
        commitment_registry: commitment_registry.clone(),
        opened_share_kind,
        recipient_role,
        recipient_identity: recipient_identity.to_owned(),
        left,
        right,
    })
    .map_err(map_derivation_to_protocol_error)
}

fn require_proof_batch_role_v1(
    field: &str,
    proof_batch: &EcdsaThresholdPrfProofBatchPayloadV1,
    expected_role: Role,
) -> RouterAbProtocolResult<()> {
    if proof_batch.from.role == expected_role {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidRole,
        format!("{field} must be sent by {}", expected_role.as_str()),
    ))
}

fn require_proof_batches_match_public_context_v1(
    lifecycle: &LifecycleScopeV1,
    expected_transcript_digest: PublicDigest32,
    proof_batch_a: &EcdsaThresholdPrfProofBatchPayloadV1,
    proof_batch_b: &EcdsaThresholdPrfProofBatchPayloadV1,
) -> RouterAbProtocolResult<()> {
    if proof_batch_a.transcript_digest != expected_transcript_digest
        || proof_batch_b.transcript_digest != expected_transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "MPC PRF output combine proof transcript mismatch",
        ));
    }
    if proof_batch_a.root_share_epoch != lifecycle.root_share_epoch
        || proof_batch_b.root_share_epoch != lifecycle.root_share_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "MPC PRF output combine root-share epoch does not match activation context",
        ));
    }
    Ok(())
}

fn single_proof_bundle_v1(
    field: &'static str,
    proof_bundles: Vec<MpcPrfPartialProofBundleV1>,
) -> RouterAbProtocolResult<MpcPrfPartialProofBundleV1> {
    let mut proof_bundles = proof_bundles.into_iter();
    let Some(first) = proof_bundles.next() else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} recipient view is missing proof bundle"),
        ));
    };
    if proof_bundles.next().is_some() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} recipient view has multiple proof bundles"),
        ));
    }
    Ok(first)
}

/// Encodes a recipient output ciphertext envelope with fixed field order.
pub fn encode_recipient_output_ciphertext_v1(
    envelope: &RecipientOutputCiphertextV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    envelope.validate()?;
    let mut out = Vec::new();
    push_len32(&mut out, RECIPIENT_OUTPUT_CIPHERTEXT_VERSION_V1);
    push_len32(&mut out, envelope.algorithm.as_str().as_bytes());
    push_len32(&mut out, envelope.recipient_role.as_str().as_bytes());
    push_len32(&mut out, envelope.opened_share_kind.as_str().as_bytes());
    push_string(&mut out, &envelope.recipient_identity);
    push_string(&mut out, &envelope.recipient_encryption_key);
    push_public_digest(&mut out, envelope.transcript_digest);
    push_public_digest(&mut out, envelope.package_commitment);
    push_len32(&mut out, &envelope.nonce);
    push_len32(&mut out, envelope.ciphertext_and_tag.as_bytes());
    Ok(out)
}

/// Encodes recipient-output AEAD associated data with fixed field order.
pub fn encode_recipient_output_ciphertext_aad_v1(
    envelope: &RecipientOutputCiphertextV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    envelope.validate()?;
    let mut out = Vec::new();
    push_len32(&mut out, RECIPIENT_OUTPUT_CIPHERTEXT_AAD_VERSION_V1);
    push_len32(&mut out, envelope.algorithm.as_str().as_bytes());
    push_len32(&mut out, envelope.recipient_role.as_str().as_bytes());
    push_len32(&mut out, envelope.opened_share_kind.as_str().as_bytes());
    push_string(&mut out, &envelope.recipient_identity);
    push_string(&mut out, &envelope.recipient_encryption_key);
    push_public_digest(&mut out, envelope.transcript_digest);
    push_public_digest(&mut out, envelope.package_commitment);
    push_len32(&mut out, &envelope.nonce);
    Ok(out)
}

/// Computes the public digest of recipient-output AEAD associated data.
pub fn recipient_output_ciphertext_aad_digest_v1(
    envelope: &RecipientOutputCiphertextV1,
) -> RouterAbProtocolResult<PublicDigest32> {
    let digest = Sha256::digest(encode_recipient_output_ciphertext_aad_v1(envelope)?);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(PublicDigest32::new(out))
}

/// Encodes a recipient proof-bundle ciphertext envelope with fixed field order.
pub fn encode_recipient_proof_bundle_ciphertext_v1(
    envelope: &RecipientProofBundleCiphertextV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    envelope.validate()?;
    let mut out = Vec::new();
    push_len32(&mut out, RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_VERSION_V1);
    push_len32(&mut out, envelope.algorithm.as_str().as_bytes());
    push_signer_identity(&mut out, &envelope.signer);
    push_len32(&mut out, envelope.recipient_role.as_str().as_bytes());
    push_len32(&mut out, envelope.opened_share_kind.as_str().as_bytes());
    push_string(&mut out, &envelope.recipient_identity);
    push_string(&mut out, &envelope.recipient_encryption_key);
    push_public_digest(&mut out, envelope.transcript_digest);
    push_public_digest(&mut out, envelope.payload_digest);
    push_len32(&mut out, &envelope.nonce);
    push_len32(&mut out, envelope.ciphertext_and_tag.as_bytes());
    Ok(out)
}

/// Encodes recipient proof-bundle AEAD associated data with fixed field order.
pub fn encode_recipient_proof_bundle_ciphertext_aad_v1(
    envelope: &RecipientProofBundleCiphertextV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    envelope.validate()?;
    let mut out = Vec::new();
    push_len32(&mut out, RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_AAD_VERSION_V1);
    push_len32(&mut out, FIXED_ECDSA_DERIVATION_SUITE_V1);
    push_len32(&mut out, envelope.algorithm.as_str().as_bytes());
    push_signer_identity(&mut out, &envelope.signer);
    push_len32(&mut out, envelope.recipient_role.as_str().as_bytes());
    push_len32(&mut out, envelope.opened_share_kind.as_str().as_bytes());
    push_string(&mut out, &envelope.recipient_identity);
    push_string(&mut out, &envelope.recipient_encryption_key);
    push_public_digest(&mut out, envelope.transcript_digest);
    push_public_digest(&mut out, envelope.payload_digest);
    push_len32(&mut out, &envelope.nonce);
    Ok(out)
}

/// Computes the public digest of recipient proof-bundle AEAD associated data.
pub fn recipient_proof_bundle_ciphertext_aad_digest_v1(
    envelope: &RecipientProofBundleCiphertextV1,
) -> RouterAbProtocolResult<PublicDigest32> {
    let digest = Sha256::digest(encode_recipient_proof_bundle_ciphertext_aad_v1(envelope)?);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(PublicDigest32::new(out))
}

/// Computes the public digest of recipient proof-bundle ciphertext canonical bytes.
pub fn recipient_proof_bundle_ciphertext_digest_v1(
    envelope: &RecipientProofBundleCiphertextV1,
) -> RouterAbProtocolResult<PublicDigest32> {
    let digest = Sha256::digest(encode_recipient_proof_bundle_ciphertext_v1(envelope)?);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(PublicDigest32::new(out))
}

/// Decodes and validates a recipient output ciphertext envelope.
pub fn decode_recipient_output_ciphertext_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<RecipientOutputCiphertextV1> {
    let mut decoder = OutputDecoder::new(bytes);
    decoder.expect_bytes(
        RECIPIENT_OUTPUT_CIPHERTEXT_VERSION_V1,
        "recipient output ciphertext version",
    )?;
    let algorithm = parse_recipient_output_algorithm(&decoder.read_string("algorithm")?)?;
    let recipient_role = parse_role(&decoder.read_string("recipient_role")?)?;
    let opened_share_kind = parse_opened_share_kind(&decoder.read_string("opened_share_kind")?)?;
    let recipient_identity = decoder.read_string("recipient_identity")?;
    let recipient_encryption_key = decoder.read_string("recipient_encryption_key")?;
    let transcript_digest = decoder.read_public_digest("transcript_digest")?;
    let package_commitment = decoder.read_public_digest("package_commitment")?;
    let nonce = decoder.read_nonce()?;
    let ciphertext_and_tag =
        EncryptedPayloadV1::new(decoder.read_bytes("ciphertext_and_tag")?.to_vec())?;
    decoder.finish()?;
    RecipientOutputCiphertextV1::new(
        algorithm,
        recipient_role,
        opened_share_kind,
        recipient_identity,
        recipient_encryption_key,
        transcript_digest,
        package_commitment,
        nonce,
        ciphertext_and_tag,
    )
}

/// Decodes and validates a recipient proof-bundle ciphertext envelope.
pub fn decode_recipient_proof_bundle_ciphertext_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
    let mut decoder = OutputDecoder::new(bytes);
    decoder.expect_bytes(
        RECIPIENT_PROOF_BUNDLE_CIPHERTEXT_VERSION_V1,
        "recipient proof-bundle ciphertext version",
    )?;
    let algorithm = parse_recipient_output_algorithm(&decoder.read_string("algorithm")?)?;
    let signer = decoder.read_signer_identity()?;
    let recipient_role = parse_role(&decoder.read_string("recipient_role")?)?;
    let opened_share_kind = parse_opened_share_kind(&decoder.read_string("opened_share_kind")?)?;
    let recipient_identity = decoder.read_string("recipient_identity")?;
    let recipient_encryption_key = decoder.read_string("recipient_encryption_key")?;
    let transcript_digest = decoder.read_public_digest("transcript_digest")?;
    let payload_digest = decoder.read_public_digest("payload_digest")?;
    let nonce = decoder.read_nonce()?;
    let ciphertext_and_tag =
        EncryptedPayloadV1::new(decoder.read_bytes("ciphertext_and_tag")?.to_vec())?;
    decoder.finish()?;
    RecipientProofBundleCiphertextV1::new(
        algorithm,
        signer,
        recipient_role,
        opened_share_kind,
        recipient_identity,
        recipient_encryption_key,
        transcript_digest,
        payload_digest,
        nonce,
        ciphertext_and_tag,
    )
}

/// Verifies decrypted proof-bundle payload metadata against its ciphertext envelope.
pub fn verify_recipient_proof_bundle_ciphertext_payload_v1(
    envelope: &RecipientProofBundleCiphertextV1,
    payload: &RecipientProofBundlePayloadV1,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    payload.validate()?;
    if envelope.recipient_role != payload.recipient_role
        || envelope.signer != payload.signer
        || envelope.opened_share_kind != payload.opened_share_kind
        || envelope.recipient_identity != payload.recipient_identity
        || envelope.transcript_digest != payload.transcript_digest
        || envelope.payload_digest != payload.digest()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "recipient proof-bundle ciphertext metadata does not match decrypted payload",
        ));
    }
    Ok(())
}

fn parse_recipient_output_algorithm(
    value: &str,
) -> RouterAbProtocolResult<RecipientOutputEncryptionAlgorithmV1> {
    match value {
        "local_deterministic_sha256_v1" => {
            Ok(RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1)
        }
        "hpke_x25519_hkdf_sha256_aes256gcm_v1" => {
            Ok(RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1)
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown recipient output encryption algorithm",
        )),
    }
}

fn parse_role(value: &str) -> RouterAbProtocolResult<Role> {
    match value {
        "client" => Ok(Role::Client),
        "server" => Ok(Role::Server),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "recipient output ciphertext role must be client or server",
        )),
    }
}

fn parse_signer_role(value: &str) -> RouterAbProtocolResult<Role> {
    match value {
        "signer_a" => Ok(Role::SignerA),
        "signer_b" => Ok(Role::SignerB),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "recipient proof-bundle ciphertext signer role must be Signer A or Signer B",
        )),
    }
}

fn parse_opened_share_kind(value: &str) -> RouterAbProtocolResult<OpenedShareKind> {
    match value {
        "x_client_base" => Ok(OpenedShareKind::XClientBase),
        "x_server_base" => Ok(OpenedShareKind::XServerBase),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown recipient output opened share kind",
        )),
    }
}

fn validate_recipient_output_binding(
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
) -> RouterAbProtocolResult<()> {
    match (recipient_role, opened_share_kind) {
        (Role::Client, OpenedShareKind::XClientBase)
        | (Role::Server, OpenedShareKind::XServerBase) => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "recipient output has invalid recipient or opened share kind",
        )),
    }
}

fn validate_recipient_encryption_key(
    algorithm: RecipientOutputEncryptionAlgorithmV1,
    recipient_encryption_key: &str,
) -> RouterAbProtocolResult<()> {
    match algorithm {
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1 => Ok(()),
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1 => {
            require_x25519_public_key_encoding("recipient_encryption_key", recipient_encryption_key)
        }
    }
}

fn require_x25519_public_key_encoding(
    field: &'static str,
    value: &str,
) -> RouterAbProtocolResult<()> {
    let Some(hex) = value.strip_prefix("x25519:") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use x25519:<64 lowercase hex chars> public-key encoding"),
        ));
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field} must use x25519:<64 lowercase hex chars> public-key encoding"),
    ))
}

fn map_derivation_to_protocol_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!(
            "MPC PRF output combine rejected proof batch: {:?}",
            error.code()
        ),
    )
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

fn push_signer_identity(out: &mut Vec<u8>, identity: &SignerIdentityV1) {
    push_len32(out, identity.role.as_str().as_bytes());
    push_string(out, &identity.signer_id);
    push_string(out, &identity.key_epoch);
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_len32(out, value.as_bytes());
}

fn push_public_digest(out: &mut Vec<u8>, digest: PublicDigest32) {
    push_len32(out, digest.as_bytes());
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct OutputDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> OutputDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> RouterAbProtocolResult<()> {
        if self.offset == self.bytes.len() {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "recipient output ciphertext has trailing bytes",
        ))
    }

    fn expect_bytes(&mut self, expected: &[u8], field: &'static str) -> RouterAbProtocolResult<()> {
        let actual = self.read_bytes(field)?;
        if actual == expected {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} mismatch"),
        ))
    }

    fn read_string(&mut self, field: &'static str) -> RouterAbProtocolResult<String> {
        let bytes = self.read_bytes(field)?;
        let value = core::str::from_utf8(bytes).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} must be valid UTF-8"),
            )
        })?;
        Ok(value.to_owned())
    }

    fn read_signer_identity(&mut self) -> RouterAbProtocolResult<SignerIdentityV1> {
        let role = parse_signer_role(&self.read_string("signer_role")?)?;
        let signer_id = self.read_string("signer_id")?;
        let key_epoch = self.read_string("signer_key_epoch")?;
        SignerIdentityV1::new(role, signer_id, key_epoch)
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

    fn read_nonce(
        &mut self,
    ) -> RouterAbProtocolResult<[u8; RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1]> {
        let bytes = self.read_bytes("nonce")?;
        bytes.try_into().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "recipient output ciphertext nonce has invalid length",
            )
        })
    }

    fn read_bytes(&mut self, field: &'static str) -> RouterAbProtocolResult<&'a [u8]> {
        if self.bytes.len().saturating_sub(self.offset) < 4 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length prefix is truncated"),
            ));
        }
        let len = u32::from_be_bytes(
            self.bytes[self.offset..self.offset + 4]
                .try_into()
                .expect("length prefix slice has four bytes"),
        ) as usize;
        self.offset += 4;
        if self.bytes.len().saturating_sub(self.offset) < len {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} bytes are truncated"),
            ));
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }
}
