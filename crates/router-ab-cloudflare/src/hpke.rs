use crate::*;
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core::{CryptoRng, RngCore};
use router_ab_ecdsa_client_protocol::{
    open_ecdsa_signer_envelope_v1, seal_ecdsa_signer_envelope_v1, EcdsaDeriverRoleV1,
    EcdsaRoleEnvelopeAadV1, EcdsaSelectedServerIdentityV1, EcdsaSignerEnvelopeHpkePayloadV1,
    EcdsaSignerEnvelopePublicKeyV1, EcdsaSignerIdentityV1,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Cloudflare production recipient-output encryptor using HPKE base mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareHpkeRecipientOutputEncryptorV1;

impl CloudflareHpkeRecipientOutputEncryptorV1 {
    /// Creates the default HPKE recipient-output encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl RecipientOutputEncryptorV1 for CloudflareHpkeRecipientOutputEncryptorV1 {
    fn encrypt_recipient_output_v1(
        &mut self,
        request: RecipientOutputEncryptionRequestV1<'_>,
    ) -> RouterAbProtocolResult<RecipientOutputCiphertextV1> {
        request.validate()?;
        let recipient_public_key =
            parse_cloudflare_hpke_x25519_public_key_v1(request.recipient_encryption_key())?;
        let aad = cloudflare_hpke_recipient_output_aad_v1(&request)?;
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &recipient_public_key,
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1,
            &aad,
            request.plaintext().as_bytes(),
        )
        .map_err(map_cloudflare_hpke_error)?;
        let mut ciphertext_and_tag =
            Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
        ciphertext_and_tag.extend_from_slice(&ciphertext);

        RecipientOutputCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.package_commitment(),
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
}

/// Cloudflare production recipient proof-bundle encryptor using HPKE base mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareHpkeRecipientProofBundleEncryptorV1;

impl CloudflareHpkeRecipientProofBundleEncryptorV1 {
    /// Creates the default HPKE recipient proof-bundle encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl RecipientProofBundleEncryptorV1 for CloudflareHpkeRecipientProofBundleEncryptorV1 {
    fn encrypt_recipient_proof_bundle_v1(
        &mut self,
        request: RecipientProofBundleEncryptionRequestV1,
    ) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
        request.validate()?;
        let recipient_public_key =
            parse_cloudflare_hpke_x25519_public_key_v1(request.recipient_encryption_key())?;
        let aad = cloudflare_hpke_recipient_proof_bundle_aad_v1(&request)?;
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &recipient_public_key,
            CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
            &aad,
            request.plaintext(),
        )
        .map_err(map_cloudflare_hpke_error)?;
        let mut ciphertext_and_tag =
            Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
        ciphertext_and_tag.extend_from_slice(&ciphertext);

        RecipientProofBundleCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
            request.signer().clone(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.payload_digest(),
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
}

/// Serializable Cloudflare-local secret material. Debug output redacts bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CloudflareSecretMaterial32V1 {
    bytes: [u8; 32],
}

impl CloudflareSecretMaterial32V1 {
    /// Creates a validated 32-byte secret material record.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Creates a serializable record from core secret material.
    pub fn from_secret_material(secret: &SecretMaterial32) -> Self {
        Self::new(*secret.as_bytes())
    }

    /// Returns secret bytes for server-local cryptographic use.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Converts this record back to core secret material.
    pub fn to_secret_material(&self) -> SecretMaterial32 {
        SecretMaterial32::new(self.bytes)
    }
}

impl core::fmt::Debug for CloudflareSecretMaterial32V1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareSecretMaterial32V1")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Server-local material opened from encrypted A/B proof bundles.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareServerOutputMaterialRecordV1 {
    /// Transcript digest that produced the server material.
    pub transcript_digest: PublicDigest32,
    /// Opened share kind. Must be `x_server_base`.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role. Must be `server`.
    pub recipient_role: Role,
    /// Server identity that owns the material.
    pub recipient_identity: String,
    /// Server-local output material.
    pub output_material: CloudflareSecretMaterial32V1,
}

impl CloudflareServerOutputMaterialRecordV1 {
    /// Creates a validated server-output material record.
    pub fn new(
        transcript_digest: PublicDigest32,
        opened_share_kind: OpenedShareKind,
        recipient_role: Role,
        recipient_identity: impl Into<String>,
        output_material: CloudflareSecretMaterial32V1,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            transcript_digest,
            opened_share_kind,
            recipient_role,
            recipient_identity: recipient_identity.into(),
            output_material,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates this record holds only server output material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "server output material recipient_identity",
            &self.recipient_identity,
        )?;
        if self.opened_share_kind == OpenedShareKind::XServerBase
            && self.recipient_role == Role::Server
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare server output material must be x_server_base for server",
        ))
    }

    /// Validates this material record matches the activation request that opened it.
    pub fn validate_for_activation_request(
        &self,
        request: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        let selected_server = &request.activation_context.signer_set().selected_server;
        if self.transcript_digest == request.activation_context.transcript_digest()
            && self.recipient_identity == selected_server.server_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare server output material does not match activation request",
        ))
    }
}

impl core::fmt::Debug for CloudflareServerOutputMaterialRecordV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareServerOutputMaterialRecordV1")
            .field("transcript_digest", &self.transcript_digest)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("recipient_role", &self.recipient_role)
            .field("recipient_identity", &self.recipient_identity)
            .field("output_material", &"[redacted]")
            .finish()
    }
}

/// Opens one Cloudflare HPKE recipient proof-bundle envelope.
pub fn open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
    envelope: &RecipientProofBundleCiphertextV1,
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<RecipientProofBundlePayloadV1> {
    envelope.validate()?;
    if envelope.algorithm != RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare recipient proof-bundle opening requires HPKE",
        ));
    }
    let private_key = parse_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
        private_key_bytes,
        &envelope.recipient_encryption_key,
    )?;
    let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes();
    if ciphertext_and_tag.len() <= CloudflareHpkeKemV1::ENCAPPED_KEY_LEN {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare recipient proof-bundle ciphertext is too short",
        ));
    }
    let (encapped_key, ciphertext) =
        ciphertext_and_tag.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
    let encapped_key =
        CloudflareHpkeKemV1::enc_from_bytes(encapped_key).map_err(map_cloudflare_hpke_error)?;
    let aad = encode_recipient_proof_bundle_ciphertext_aad_v1(envelope)?;
    let plaintext = CloudflareHpkeSuiteV1::open_base(
        &encapped_key,
        &private_key,
        CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
        &aad,
        ciphertext,
    )
    .map_err(map_cloudflare_hpke_error)?;
    let payload = decode_recipient_proof_bundle_payload_v1(&plaintext)?;
    verify_recipient_proof_bundle_ciphertext_payload_v1(envelope, &payload)?;
    Ok(payload)
}

/// Opens encrypted server proof bundles into a serializable server-output material record.
pub fn cloudflare_server_output_material_record_from_activation_request_v1(
    request: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareServerOutputMaterialRecordV1> {
    request.validate()?;
    let deriver_a_envelope = decode_cloudflare_recipient_proof_bundle_wire_v1(
        "deriver_a_bundle",
        &request.activation.deriver_a_bundle,
        Role::SignerA,
        Role::Server,
        OpenedShareKind::XServerBase,
    )?;
    let deriver_b_envelope = decode_cloudflare_recipient_proof_bundle_wire_v1(
        "deriver_b_server_bundle",
        &request.activation.deriver_b_server_bundle,
        Role::SignerB,
        Role::Server,
        OpenedShareKind::XServerBase,
    )?;
    let deriver_a_payload = open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
        &deriver_a_envelope,
        private_key_bytes,
    )?;
    let deriver_b_payload = open_cloudflare_recipient_proof_bundle_hpke_payload_v1(
        &deriver_b_envelope,
        private_key_bytes,
    )?;
    let output = combine_mpc_prf_signing_worker_output_from_activation_context_v1(
        &request.activation_context,
        deriver_a_payload,
        deriver_b_payload,
    )?;
    let record = CloudflareServerOutputMaterialRecordV1::new(
        output.transcript_digest,
        output.opened_share_kind,
        output.recipient_role,
        output.recipient_identity,
        CloudflareSecretMaterial32V1::from_secret_material(&output.output_material),
    )?;
    record.validate_for_activation_request(request)?;
    Ok(record)
}

/// Seals signer-input plaintext into a production HPKE signer-envelope payload.
pub fn seal_cloudflare_signer_envelope_hpke_payload_v1(
    recipient_key: &CloudflareSignerEnvelopeHpkePublicKeyV1,
    aad: &RoleEnvelopeAadV1,
    plaintext: &[u8],
) -> RouterAbProtocolResult<SignerEnvelopeHpkePayloadV1> {
    recipient_key.validate()?;
    aad.validate()?;
    if aad.recipient.role != recipient_key.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare signer-envelope HPKE recipient key does not match AAD recipient",
        ));
    }
    if plaintext.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare signer-envelope HPKE plaintext must be non-empty",
        ));
    }
    let mut rng = CloudflareHpkeGetrandomRngV1;
    let mut seal_seed = [0_u8; 32];
    rng.fill_bytes(&mut seal_seed);
    let protocol_key = ecdsa_client_protocol_public_key(recipient_key)?;
    let protocol_aad = ecdsa_client_protocol_aad(aad)?;
    let payload = seal_ecdsa_signer_envelope_v1(&protocol_key, &protocol_aad, plaintext, seal_seed)
        .map_err(map_ecdsa_client_protocol_error)?;
    SignerEnvelopeHpkePayloadV1::new(
        recipient_key.role,
        payload.key_epoch,
        payload.recipient_public_key,
        PublicDigest32::new(payload.aad_digest),
        payload.encapped_key,
        payload.ciphertext_and_tag,
    )
}

/// Opens a production HPKE signer-envelope payload after public metadata validation.
pub fn open_cloudflare_signer_envelope_hpke_payload_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<Vec<u8>> {
    let payload = decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1(
        worker_role,
        message,
        envelope_decrypt_key,
    )?;
    aad.validate()?;
    if aad.digest() != payload.aad_digest || aad.recipient.role != payload.recipient_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare signer envelope AAD does not match parsed HPKE payload",
        ));
    }
    parse_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
        private_key_bytes,
        &envelope_decrypt_key.public_key,
    )?;
    let private_key_bytes: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare signer-envelope HPKE private key must be 32 bytes",
        )
    })?;
    let protocol_payload = EcdsaSignerEnvelopeHpkePayloadV1 {
        recipient_role: ecdsa_client_protocol_role(payload.recipient_role)?,
        key_epoch: payload.key_epoch.clone(),
        recipient_public_key: payload.recipient_public_key.clone(),
        aad_digest: *payload.aad_digest.as_bytes(),
        encapped_key: *payload.encapped_key(),
        ciphertext_and_tag: payload.ciphertext_and_tag().to_vec(),
    };
    open_ecdsa_signer_envelope_v1(
        &protocol_payload,
        &ecdsa_client_protocol_aad(aad)?,
        &private_key_bytes,
    )
    .map_err(map_ecdsa_client_protocol_error)
}

fn ecdsa_client_protocol_role(role: Role) -> RouterAbProtocolResult<EcdsaDeriverRoleV1> {
    match role {
        Role::SignerA => Ok(EcdsaDeriverRoleV1::A),
        Role::SignerB => Ok(EcdsaDeriverRoleV1::B),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "ECDSA signer-envelope protocol requires a Deriver role",
        )),
    }
}

fn ecdsa_client_protocol_aad(
    aad: &RoleEnvelopeAadV1,
) -> RouterAbProtocolResult<EcdsaRoleEnvelopeAadV1> {
    aad.validate()?;
    Ok(EcdsaRoleEnvelopeAadV1 {
        lifecycle_id: aad.lifecycle_id.clone(),
        work_kind: aad.work_kind.as_str().to_owned(),
        primitive_request_kind: aad.primitive_request_kind.as_str().to_owned(),
        signer_set_id: aad.signer_set_id.clone(),
        recipient: EcdsaSignerIdentityV1 {
            role: ecdsa_client_protocol_role(aad.recipient.role)?,
            signer_id: aad.recipient.signer_id.clone(),
            key_epoch: aad.recipient.key_epoch.clone(),
        },
        selected_server: EcdsaSelectedServerIdentityV1 {
            server_id: aad.selected_server.server_id.clone(),
            key_epoch: aad.selected_server.key_epoch.clone(),
            recipient_encryption_key: aad.selected_server.recipient_encryption_key.clone(),
        },
        transcript_digest: *aad.transcript_digest.as_bytes(),
        router_request_digest: *aad.router_request_digest.as_bytes(),
        expires_at_ms: aad.expires_at_ms,
    })
}

fn ecdsa_client_protocol_public_key(
    key: &CloudflareSignerEnvelopeHpkePublicKeyV1,
) -> RouterAbProtocolResult<EcdsaSignerEnvelopePublicKeyV1> {
    key.validate()?;
    Ok(EcdsaSignerEnvelopePublicKeyV1 {
        role: ecdsa_client_protocol_role(key.role)?,
        key_epoch: key.key_epoch.clone(),
        public_key: key.public_key.clone(),
    })
}

fn map_ecdsa_client_protocol_error(
    _error: router_ab_ecdsa_client_protocol::EcdsaClientProtocolError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        "ECDSA client-safe signer-envelope protocol rejected the request",
    )
}

pub(crate) type CloudflareHpkeSuiteV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;
pub(crate) type CloudflareHpkeKemV1 = DhKemX25519HkdfSha256;

pub(crate) const CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1: &[u8] =
    b"router-ab-cloudflare/recipient-output/hpke-x25519-hkdf-sha256-aes256gcm/v1";
pub(crate) const CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1: &[u8] =
    b"router-ab-cloudflare/recipient-proof-bundle/hpke-x25519-hkdf-sha256-aes256gcm/v1";
pub(crate) const CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1: [u8; 12] = [0u8; 12];

pub(crate) struct CloudflareHpkeGetrandomRngV1;

impl RngCore for CloudflareHpkeGetrandomRngV1 {
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

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::getrandom(dst).expect("Cloudflare HPKE recipient-output RNG failed");
    }
}

impl CryptoRng for CloudflareHpkeGetrandomRngV1 {}

pub(crate) struct CloudflareSignerProofGetrandomRngV1;

impl rand_core_06::RngCore for CloudflareSignerProofGetrandomRngV1 {
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

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::getrandom(dst).expect("Cloudflare signer proof RNG failed");
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for CloudflareSignerProofGetrandomRngV1 {}

fn cloudflare_hpke_recipient_output_aad_v1(
    request: &RecipientOutputEncryptionRequestV1<'_>,
) -> RouterAbProtocolResult<Vec<u8>> {
    let placeholder = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        request.recipient_role(),
        request.opened_share_kind(),
        request.recipient_identity(),
        request.recipient_encryption_key(),
        request.transcript_digest(),
        request.package_commitment(),
        CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
        EncryptedPayloadV1::new(vec![0u8])?,
    )?;
    encode_recipient_output_ciphertext_aad_v1(&placeholder)
}

pub(crate) fn cloudflare_hpke_recipient_proof_bundle_aad_v1(
    request: &RecipientProofBundleEncryptionRequestV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    let placeholder = RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        request.signer().clone(),
        request.recipient_role(),
        request.opened_share_kind(),
        request.recipient_identity(),
        request.recipient_encryption_key(),
        request.transcript_digest(),
        request.payload_digest(),
        CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
        EncryptedPayloadV1::new(vec![0u8])?,
    )?;
    encode_recipient_proof_bundle_ciphertext_aad_v1(&placeholder)
}

pub(crate) fn parse_cloudflare_hpke_x25519_public_key_v1(
    encoded: &str,
) -> RouterAbProtocolResult<<CloudflareHpkeKemV1 as Kem>::PublicKey> {
    let hex_value = encoded.strip_prefix("x25519:").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key must use x25519:<64 lowercase hex chars> encoding",
        )
    })?;
    let public_key_bytes = decode_cloudflare_hpke_x25519_hex_v1(hex_value)?;
    let public_key =
        CloudflareHpkeKemV1::pk_from_bytes(&public_key_bytes).map_err(map_cloudflare_hpke_error)?;
    if CloudflareHpkeKemV1::pk_to_bytes(&public_key) != public_key_bytes {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key must be canonical X25519 bytes",
        ));
    }
    Ok(public_key)
}

fn decode_cloudflare_hpke_x25519_hex_v1(hex_value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    if hex_value.len() != 64 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key hex must be 64 characters",
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex_value.as_bytes().chunks_exact(2).enumerate() {
        out[index] =
            (decode_cloudflare_lower_hex_nibble_v1("HPKE recipient public key", chunk[0])? << 4)
                | decode_cloudflare_lower_hex_nibble_v1("HPKE recipient public key", chunk[1])?;
    }
    Ok(out)
}

fn decode_cloudflare_hpke_private_key_hex_v1(
    field: &'static str,
    hex_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    if hex_value.len() != 64 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} HPKE private key hex must be 64 characters"),
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex_value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (decode_cloudflare_lower_hex_nibble_for_config_v1(field, chunk[0])? << 4)
            | decode_cloudflare_lower_hex_nibble_for_config_v1(field, chunk[1])?;
    }
    Ok(out)
}

/// Encodes signer-envelope HPKE private-key bytes for Cloudflare Secrets.
pub fn encode_cloudflare_signer_envelope_hpke_private_key_secret_v1(
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<String> {
    encode_cloudflare_hpke_private_key_secret_v1(
        CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
        private_key_bytes,
    )
}

/// Decodes signer-envelope HPKE private-key bytes from a Cloudflare Secret value.
pub fn decode_cloudflare_signer_envelope_hpke_private_key_secret_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    decode_cloudflare_hpke_private_key_secret_v1(
        secret_value,
        CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
        "Cloudflare signer-envelope",
        "Cloudflare signer-envelope HPKE private key secret has unsupported prefix",
    )
}

/// Encodes server-output HPKE private-key bytes for Cloudflare Secrets.
pub fn encode_cloudflare_server_output_hpke_private_key_secret_v1(
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<String> {
    encode_cloudflare_hpke_private_key_secret_v1(
        CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
        private_key_bytes,
    )
}

fn encode_cloudflare_hpke_private_key_secret_v1(
    prefix: &str,
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<String> {
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(private_key_bytes)?;
    let mut out = String::from(prefix);
    push_lower_hex_v1(&mut out, private_key_bytes);
    Ok(out)
}

/// Decodes server-output HPKE private-key bytes from a Cloudflare Secret value.
pub fn decode_cloudflare_server_output_hpke_private_key_secret_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    decode_cloudflare_hpke_private_key_secret_v1(
        secret_value,
        CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
        "Cloudflare server-output",
        "Cloudflare server-output HPKE private key secret has unsupported prefix",
    )
}

fn decode_cloudflare_hpke_private_key_secret_v1(
    secret_value: &str,
    prefix: &str,
    field: &'static str,
    prefix_error: &'static str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let trimmed = secret_value.trim();
    let hex_value = trimmed.strip_prefix(prefix).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            prefix_error,
        )
    })?;
    let private_key_bytes = decode_cloudflare_hpke_private_key_hex_v1(field, hex_value)?;
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(&private_key_bytes)?;
    Ok(private_key_bytes)
}

fn validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
    private_key_bytes: &[u8],
) -> RouterAbProtocolResult<()> {
    if private_key_bytes.len() != CloudflareHpkeKemV1::PRIVATE_KEY_LEN {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare signer-envelope HPKE private key must be 32 bytes",
        ));
    }
    let private_key = CloudflareHpkeKemV1::sk_from_bytes(private_key_bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare signer-envelope HPKE private key is invalid: {err}"),
        )
    })?;
    drop(private_key);
    Ok(())
}

fn parse_cloudflare_signer_envelope_hpke_private_key_bytes_v1(
    private_key_bytes: &[u8],
    expected_public_key: &str,
) -> RouterAbProtocolResult<<CloudflareHpkeKemV1 as Kem>::PrivateKey> {
    validate_cloudflare_signer_envelope_hpke_private_key_bytes_v1(private_key_bytes)?;
    parse_cloudflare_hpke_x25519_public_key_v1(expected_public_key)?;
    CloudflareHpkeKemV1::sk_from_bytes(private_key_bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare signer-envelope HPKE private key is invalid: {err}"),
        )
    })
}

pub(crate) fn push_lower_hex_v1(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_cloudflare_lower_hex_nibble_v1(
    field: &'static str,
    byte: u8,
) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use lowercase hex"),
        )),
    }
}

fn decode_cloudflare_lower_hex_nibble_for_config_v1(
    field: &'static str,
    byte: u8,
) -> RouterAbProtocolResult<u8> {
    decode_cloudflare_lower_hex_nibble_v1(field, byte).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            err.message().to_owned(),
        )
    })
}

fn map_cloudflare_hpke_error(err: hpke_ng::HpkeError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("Cloudflare HPKE recipient-output encryption failed: {err}"),
    )
}
