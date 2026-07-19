#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Client-safe cryptographic wire protocol for Router A/B ECDSA ceremonies.
//!
//! This crate owns public AAD framing and signer-envelope HPKE. It contains no
//! Router admission, Deriver evaluation, root shares, or threshold-PRF backend.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "hpke")]
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
#[cfg(feature = "hpke")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "hpke")]
use rand_core::SeedableRng;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

#[cfg(feature = "hpke")]
mod activation;
#[cfg(feature = "hpke")]
mod export_share;
mod material_possession;
#[cfg(feature = "hpke")]
mod post_registration;
#[cfg(feature = "hpke")]
mod recipient_proof;
#[cfg(feature = "hpke")]
mod registration;

#[cfg(feature = "hpke")]
pub use activation::EcdsaVerifiedClientActivationFactsV1;
#[cfg(feature = "hpke")]
pub use export_share::{
    open_ecdsa_signing_worker_export_share_v1, seal_ecdsa_signing_worker_export_share_v1,
    EcdsaSigningWorkerExportShareBindingV1, EcdsaSigningWorkerExportShareEnvelopeV1,
};
pub use material_possession::{
    verify_ecdsa_client_material_possession_proof_v1, EcdsaClientMaterialPossessionChallengeV1,
    EcdsaClientMaterialPossessionError, EcdsaClientMaterialPossessionProofSchemeV1,
    EcdsaClientMaterialPossessionProofV1,
};
#[cfg(feature = "hpke")]
pub use post_registration::{
    build_ecdsa_post_registration_request_v1, EcdsaPostRegistrationCeremonyV1,
    EcdsaPostRegistrationHeaderInputV1, EcdsaPostRegistrationHeaderV1,
    EcdsaPostRegistrationLifecycleV1, EcdsaPostRegistrationLifecycleWireV1,
    EcdsaPostRegistrationOperationV1, EcdsaPostRegistrationRecipientV1,
    EcdsaPostRegistrationRequestV1, EcdsaPublicIdentityInputV1, EcdsaPublicIdentityV1,
};
#[cfg(feature = "hpke")]
pub use recipient_proof::{
    decode_ecdsa_client_proof_bundle_envelope_v1, ecdsa_client_prf_public_context_v1,
    open_ecdsa_client_proof_bundle_v1, pair_ecdsa_opened_client_proof_bundles_v1,
    EcdsaClientProofBundleEnvelopeV1, EcdsaOpenedClientProofBundlePairV1,
    EcdsaOpenedClientProofBundleV1,
};
#[cfg(feature = "hpke")]
pub use registration::{
    build_ecdsa_registration_request_v1, derive_ecdsa_client_ephemeral_keypair_v1,
    EcdsaClientEphemeralKeyPairV1, EcdsaRegistrationEncryptedEnvelopeV1,
    EcdsaRegistrationHeaderInputV1, EcdsaRegistrationHeaderV1, EcdsaRegistrationLifecycleV1,
    EcdsaRegistrationLifecycleWireV1, EcdsaRegistrationPurposeV1, EcdsaRegistrationRecipientKeysV1,
    EcdsaRegistrationRequestV1, EcdsaRegistrationSealSeedsV1, EcdsaRegistrationSignerSetV1,
    EcdsaStableKeyContextV1,
};

#[cfg(feature = "hpke")]
type SignerEnvelopeHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

const ROLE_ENVELOPE_AAD_VERSION_V1: &[u8] = b"router-ab-protocol/role-envelope-aad/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/signer-envelope-hpke/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_ALGORITHM_V1: &[u8] = b"hpke-x25519-hkdf-sha256-aes256gcm/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_INFO_V1: &[u8] =
    b"router-ab-cloudflare/signer-envelope/hpke-x25519-hkdf-sha256-aes256gcm/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_TAG_LEN_V1: usize = 16;
const PRF_INPUT_DOMAIN_V1: &[u8] = b"threshold-prf/input";
const PRF_PARTIAL_CONTEXT_DOMAIN_V1: &[u8] = b"threshold-prf/partial-context";
const PRF_DLEQ_DOMAIN_V1: &[u8] = b"threshold-prf/dleq";
const PRF_SUITE_V1: &[u8] = b"threshold-prf/ristretto255-sha512";

/// One Deriver role in the fixed all(2) protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaDeriverRoleV1 {
    /// Deriver A.
    A,
    /// Deriver B.
    B,
}

impl EcdsaDeriverRoleV1 {
    /// Returns the canonical backend wire label.
    pub fn wire_label(self) -> &'static str {
        match self {
            Self::A => "signer_a",
            Self::B => "signer_b",
        }
    }
}

/// Public signer identity committed into role-envelope AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignerIdentityV1 {
    /// Recipient Deriver role.
    pub role: EcdsaDeriverRoleV1,
    /// Stable signer id.
    pub signer_id: String,
    /// Signer key epoch.
    pub key_epoch: String,
}

/// Public SigningWorker identity committed into role-envelope AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSelectedServerIdentityV1 {
    /// Stable server id.
    pub server_id: String,
    /// Server key epoch.
    pub key_epoch: String,
    /// Recipient encryption key for server output delivery.
    pub recipient_encryption_key: String,
}

/// Exact public fields used as signer-envelope associated data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRoleEnvelopeAadV1 {
    /// Router lifecycle id.
    pub lifecycle_id: String,
    /// Product work-kind wire label.
    pub work_kind: String,
    /// Primitive request-kind wire label.
    pub primitive_request_kind: String,
    /// Selected signer-set id.
    pub signer_set_id: String,
    /// Recipient Deriver identity.
    pub recipient: EcdsaSignerIdentityV1,
    /// Selected SigningWorker identity.
    pub selected_server: EcdsaSelectedServerIdentityV1,
    /// Public derivation transcript digest.
    pub transcript_digest: [u8; 32],
    /// Pre-envelope lifecycle header digest.
    pub router_request_digest: [u8; 32],
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl EcdsaRoleEnvelopeAadV1 {
    /// Validates required identity and lifecycle fields.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        require_non_empty(&self.lifecycle_id)?;
        require_non_empty(&self.work_kind)?;
        require_non_empty(&self.primitive_request_kind)?;
        require_non_empty(&self.signer_set_id)?;
        require_non_empty(&self.recipient.signer_id)?;
        require_non_empty(&self.recipient.key_epoch)?;
        require_non_empty(&self.selected_server.server_id)?;
        require_non_empty(&self.selected_server.key_epoch)?;
        require_non_empty(&self.selected_server.recipient_encryption_key)?;
        if self.expires_at_ms == 0 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }

    /// Returns canonical backend-compatible AAD bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        self.validate()?;
        let mut out = Vec::new();
        push_bytes(&mut out, ROLE_ENVELOPE_AAD_VERSION_V1);
        push_string(&mut out, &self.lifecycle_id);
        push_bytes(&mut out, self.work_kind.as_bytes());
        push_bytes(&mut out, self.primitive_request_kind.as_bytes());
        push_string(&mut out, &self.signer_set_id);
        push_bytes(&mut out, self.recipient.role.wire_label().as_bytes());
        push_string(&mut out, &self.recipient.signer_id);
        push_string(&mut out, &self.recipient.key_epoch);
        push_string(&mut out, &self.selected_server.server_id);
        push_string(&mut out, &self.selected_server.key_epoch);
        push_string(&mut out, &self.selected_server.recipient_encryption_key);
        push_bytes(&mut out, &self.transcript_digest);
        push_bytes(&mut out, &self.router_request_digest);
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(out)
    }

    /// Returns the SHA-256 digest of canonical AAD bytes.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

/// Public HPKE recipient key selected from an authenticated deployment keyset.
#[cfg(feature = "hpke")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignerEnvelopePublicKeyV1 {
    /// Recipient Deriver role.
    pub role: EcdsaDeriverRoleV1,
    /// Recipient decrypt-key epoch.
    pub key_epoch: String,
    /// Canonical `x25519:<64 lowercase hex>` public key.
    pub public_key: String,
}

/// Parsed signer-envelope HPKE packet.
#[cfg(feature = "hpke")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignerEnvelopeHpkePayloadV1 {
    /// Recipient Deriver role.
    pub recipient_role: EcdsaDeriverRoleV1,
    /// Recipient decrypt-key epoch.
    pub key_epoch: String,
    /// Canonical X25519 recipient public key.
    pub recipient_public_key: String,
    /// Digest of exact AAD bytes used for sealing.
    pub aad_digest: [u8; 32],
    /// HPKE encapsulated key.
    pub encapped_key: [u8; 32],
    /// Ciphertext followed by the AES-GCM tag.
    pub ciphertext_and_tag: Vec<u8>,
}

#[cfg(feature = "hpke")]
impl EcdsaSignerEnvelopeHpkePayloadV1 {
    /// Returns canonical backend-compatible packet bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        require_non_empty(&self.key_epoch)?;
        decode_x25519_public_key(&self.recipient_public_key)?;
        if self.ciphertext_and_tag.len() <= SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let mut out = Vec::new();
        push_bytes(&mut out, SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1);
        push_bytes(&mut out, SIGNER_ENVELOPE_HPKE_ALGORITHM_V1);
        push_bytes(&mut out, self.recipient_role.wire_label().as_bytes());
        push_string(&mut out, &self.key_epoch);
        push_string(&mut out, &self.recipient_public_key);
        push_bytes(&mut out, &self.aad_digest);
        push_bytes(&mut out, &self.encapped_key);
        out.extend_from_slice(&(SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 as u32).to_be_bytes());
        push_bytes(&mut out, &self.ciphertext_and_tag);
        Ok(out)
    }
}

/// Client-safe protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaClientProtocolError {
    /// A public identity, key, or wire field was malformed.
    InvalidShape,
    /// HPKE sealing or opening failed.
    HpkeFailed,
    /// Public DLEQ proof verification failed.
    InvalidDleqProof,
    /// Public PRF proof was created for a different canonical context.
    ContextMismatch,
}

/// Fixed public threshold-PRF purpose verified by the browser client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaPrfPurposeV1 {
    /// ECDSA server-share derivation output.
    YServer,
    /// Client recipient base output.
    XClientBase,
    /// SigningWorker recipient base output.
    XServerBase,
}

impl EcdsaPrfPurposeV1 {
    fn wire_label(self) -> &'static [u8] {
        match self {
            Self::YServer => b"router-ab-ecdsa-derivation/y-server/v1",
            Self::XClientBase => b"router-ab/x_client_base/v1",
            Self::XServerBase => b"router-ab/x_server_base/v1",
        }
    }
}

/// Public threshold-PRF context required for proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPrfPublicContextV1 {
    /// Fixed output purpose.
    pub purpose: EcdsaPrfPurposeV1,
    /// Canonical transcript context bytes.
    pub context_bytes: Vec<u8>,
}

/// Canonical public proof-bundle wire material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPrfPublicProofBundleV1 {
    /// `share_id(2) || context_tag(32) || partial_point(32)`.
    pub partial_wire: [u8; 66],
    /// `share_id(2) || commitment_point(32)`.
    pub commitment_wire: [u8; 34],
    /// `challenge_scalar(32) || response_scalar(32)`.
    pub proof_wire: [u8; 64],
}

/// One role-bound public proof bundle accepted by the client finalizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRoleBoundPrfProofV1 {
    /// Deriver role that produced this proof.
    pub role: EcdsaDeriverRoleV1,
    /// Public proof material.
    pub proof: EcdsaPrfPublicProofBundleV1,
}

/// Client-ready recipient-encrypted proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcdsaClientProofBundleDeliveryV1 {
    /// Fixed recipient proof-bundle wire kind.
    pub kind: EcdsaClientProofBundleDeliveryKindV1,
    /// Base64url transcript digest.
    pub transcript_digest_b64u: String,
    /// Base64url recipient-encrypted proof-bundle payload.
    pub payload_b64u: String,
}

/// Fixed client proof-bundle delivery kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaClientProofBundleDeliveryKindV1 {
    /// Recipient-encrypted proof bundle.
    RecipientProofBundle,
}

/// Exact Deriver A/B client proof bundles for one ceremony transcript.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcdsaClientProofBundlePairDeliveryV1 {
    /// Deriver A client proof bundle.
    pub signer_a: EcdsaClientProofBundleDeliveryV1,
    /// Deriver B client proof bundle.
    pub signer_b: EcdsaClientProofBundleDeliveryV1,
}

/// Verifies both proof-contained commitments and DLEQs, then combines the output.
pub fn finalize_ecdsa_prf_two_party_output_v1(
    context: &EcdsaPrfPublicContextV1,
    deriver_a: &EcdsaRoleBoundPrfProofV1,
    deriver_b: &EcdsaRoleBoundPrfProofV1,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    finalize_role_bound_ecdsa_prf_two_party_output_v1(context, deriver_a, deriver_b)
}

/// Verifies one Deriver partial against its public root-share commitment.
pub fn verify_ecdsa_prf_public_dleq_proof_v1(
    context: &EcdsaPrfPublicContextV1,
    bundle: &EcdsaPrfPublicProofBundleV1,
) -> Result<(), EcdsaClientProtocolError> {
    if context.context_bytes.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let partial_share_id = u16::from_be_bytes([bundle.partial_wire[0], bundle.partial_wire[1]]);
    let commitment_share_id =
        u16::from_be_bytes([bundle.commitment_wire[0], bundle.commitment_wire[1]]);
    if partial_share_id == 0 || partial_share_id != commitment_share_id {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    let expected_context_tag = prf_context_tag(context)?;
    if !bool::from(bundle.partial_wire[2..34].ct_eq(&expected_context_tag)) {
        return Err(EcdsaClientProtocolError::ContextMismatch);
    }
    let partial_point = decompress_ristretto(&bundle.partial_wire[34..66])?;
    let commitment_point = decompress_ristretto(&bundle.commitment_wire[2..34])?;
    let challenge = canonical_scalar(&bundle.proof_wire[0..32])?;
    let response = canonical_scalar(&bundle.proof_wire[32..64])?;
    let input_point = prf_input_point(context)?;
    let nonce_g = (response * RISTRETTO_BASEPOINT_POINT) - (challenge * commitment_point);
    let nonce_p = (response * input_point) - (challenge * partial_point);
    let expected_challenge = prf_dleq_challenge(
        context,
        &expected_context_tag,
        partial_share_id,
        &input_point,
        &commitment_point,
        &partial_point,
        &nonce_g,
        &nonce_p,
    )?;
    if bool::from(challenge.to_bytes().ct_eq(&expected_challenge.to_bytes())) {
        return Ok(());
    }
    Err(EcdsaClientProtocolError::InvalidDleqProof)
}

fn finalize_role_bound_ecdsa_prf_two_party_output_v1(
    context: &EcdsaPrfPublicContextV1,
    deriver_a: &EcdsaRoleBoundPrfProofV1,
    deriver_b: &EcdsaRoleBoundPrfProofV1,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    if deriver_a.role != EcdsaDeriverRoleV1::A || deriver_b.role != EcdsaDeriverRoleV1::B {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    if proof_share_id(&deriver_a.proof) != 1 || proof_share_id(&deriver_b.proof) != 2 {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    verify_ecdsa_prf_public_dleq_proof_v1(context, &deriver_a.proof)?;
    verify_ecdsa_prf_public_dleq_proof_v1(context, &deriver_b.proof)?;
    let partial_a = decompress_ristretto(&deriver_a.proof.partial_wire[34..66])?;
    let partial_b = decompress_ristretto(&deriver_b.proof.partial_wire[34..66])?;
    let combined = (Scalar::from(2_u64) * partial_a) - partial_b;
    prf_output(context, &combined)
}

/// Seals canonical signer input for exactly one Deriver role.
#[cfg(feature = "hpke")]
pub fn seal_ecdsa_signer_envelope_v1(
    recipient_key: &EcdsaSignerEnvelopePublicKeyV1,
    aad: &EcdsaRoleEnvelopeAadV1,
    plaintext: &[u8],
    seal_seed: [u8; 32],
) -> Result<EcdsaSignerEnvelopeHpkePayloadV1, EcdsaClientProtocolError> {
    aad.validate()?;
    if recipient_key.role != aad.recipient.role || plaintext.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let recipient_public_key_bytes = decode_x25519_public_key(&recipient_key.public_key)?;
    let recipient_public_key = DhKemX25519HkdfSha256::pk_from_bytes(&recipient_public_key_bytes)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let aad_bytes = aad.canonical_bytes()?;
    let mut rng = ChaCha20Rng::from_seed(seal_seed);
    let (encapped_key, ciphertext_and_tag) = SignerEnvelopeHpkeV1::seal_base(
        &mut rng,
        &recipient_public_key,
        SIGNER_ENVELOPE_HPKE_INFO_V1,
        &aad_bytes,
        plaintext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let encapped_key = encapped_key
        .as_ref()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    Ok(EcdsaSignerEnvelopeHpkePayloadV1 {
        recipient_role: recipient_key.role,
        key_epoch: recipient_key.key_epoch.clone(),
        recipient_public_key: recipient_key.public_key.clone(),
        aad_digest: aad.digest()?,
        encapped_key,
        ciphertext_and_tag,
    })
}

/// Opens a signer envelope after checking public key and AAD bindings.
#[cfg(feature = "hpke")]
pub fn open_ecdsa_signer_envelope_v1(
    payload: &EcdsaSignerEnvelopeHpkePayloadV1,
    aad: &EcdsaRoleEnvelopeAadV1,
    recipient_private_key: &[u8; 32],
) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    if payload.recipient_role != aad.recipient.role || payload.aad_digest != aad.digest()? {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient_private_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    decode_x25519_public_key(&payload.recipient_public_key)?;
    let encapped_key = DhKemX25519HkdfSha256::enc_from_bytes(&payload.encapped_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    SignerEnvelopeHpkeV1::open_base(
        &encapped_key,
        &private_key,
        SIGNER_ENVELOPE_HPKE_INFO_V1,
        &aad.canonical_bytes()?,
        &payload.ciphertext_and_tag,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)
}

fn require_non_empty(value: &str) -> Result<(), EcdsaClientProtocolError> {
    if value.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let digest = Sha256::digest(bytes);
    digest
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn prf_input_point(
    context: &EcdsaPrfPublicContextV1,
) -> Result<RistrettoPoint, EcdsaClientProtocolError> {
    let transcript = prf_transcript(PRF_INPUT_DOMAIN_V1, context, &[])?;
    Ok(RistrettoPoint::hash_from_bytes::<Sha512>(&transcript))
}

fn prf_context_tag(
    context: &EcdsaPrfPublicContextV1,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let transcript = prf_transcript(PRF_PARTIAL_CONTEXT_DOMAIN_V1, context, &[])?;
    let digest = Sha512::digest(transcript);
    digest[..32]
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn proof_share_id(bundle: &EcdsaPrfPublicProofBundleV1) -> u16 {
    u16::from_be_bytes([bundle.partial_wire[0], bundle.partial_wire[1]])
}

fn prf_output(
    context: &EcdsaPrfPublicContextV1,
    point: &RistrettoPoint,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let transcript = prf_transcript(
        b"threshold-prf/output",
        context,
        point.compress().as_bytes(),
    )?;
    let digest = Sha512::digest(transcript);
    let mut output: [u8; 32] = digest[..32]
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    if matches!(
        context.purpose,
        EcdsaPrfPurposeV1::XClientBase | EcdsaPrfPurposeV1::XServerBase
    ) {
        output = Scalar::from_bytes_mod_order(output).to_bytes();
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn prf_dleq_challenge(
    context: &EcdsaPrfPublicContextV1,
    context_tag: &[u8; 32],
    share_id: u16,
    input_point: &RistrettoPoint,
    commitment_point: &RistrettoPoint,
    partial_point: &RistrettoPoint,
    nonce_g: &RistrettoPoint,
    nonce_p: &RistrettoPoint,
) -> Result<Scalar, EcdsaClientProtocolError> {
    let mut transcript = Vec::new();
    push_len16(&mut transcript, PRF_DLEQ_DOMAIN_V1)?;
    push_len16(&mut transcript, PRF_SUITE_V1)?;
    push_len16(&mut transcript, context.purpose.wire_label())?;
    transcript.extend_from_slice(context_tag);
    transcript.extend_from_slice(&share_id.to_be_bytes());
    transcript.extend_from_slice(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    transcript.extend_from_slice(input_point.compress().as_bytes());
    transcript.extend_from_slice(commitment_point.compress().as_bytes());
    transcript.extend_from_slice(partial_point.compress().as_bytes());
    transcript.extend_from_slice(nonce_g.compress().as_bytes());
    transcript.extend_from_slice(nonce_p.compress().as_bytes());
    let digest = Sha512::digest(transcript);
    let wide: [u8; 64] = digest
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn prf_transcript(
    domain: &[u8],
    context: &EcdsaPrfPublicContextV1,
    payload: &[u8],
) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    let mut transcript = Vec::new();
    push_len16(&mut transcript, domain)?;
    push_len16(&mut transcript, PRF_SUITE_V1)?;
    push_len16(&mut transcript, context.purpose.wire_label())?;
    push_bytes(&mut transcript, &context.context_bytes);
    push_bytes(&mut transcript, payload);
    Ok(transcript)
}

fn push_len16(out: &mut Vec<u8>, value: &[u8]) -> Result<(), EcdsaClientProtocolError> {
    let length = u16::try_from(value.len()).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn decompress_ristretto(value: &[u8]) -> Result<RistrettoPoint, EcdsaClientProtocolError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidDleqProof)?;
    CompressedRistretto(bytes)
        .decompress()
        .ok_or(EcdsaClientProtocolError::InvalidDleqProof)
}

fn canonical_scalar(value: &[u8]) -> Result<Scalar, EcdsaClientProtocolError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidDleqProof)?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(EcdsaClientProtocolError::InvalidDleqProof)
}

#[cfg(feature = "hpke")]
fn decode_x25519_public_key(value: &str) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let hex = value
        .strip_prefix("x25519:")
        .ok_or(EcdsaClientProtocolError::InvalidShape)?;
    if hex.len() != 64 {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_lower_hex_nibble(chunk[0])?;
        let low = decode_lower_hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

#[cfg(feature = "hpke")]
fn encode_x25519_public_key(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity("x25519:".len() + bytes.len() * 2);
    encoded.push_str("x25519:");
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(feature = "hpke")]
fn decode_lower_hex_nibble(value: u8) -> Result<u8, EcdsaClientProtocolError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(EcdsaClientProtocolError::InvalidShape),
    }
}

#[cfg(all(test, feature = "hpke"))]
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(all(test, feature = "hpke"))]
mod tests {
    use super::*;

    fn aad() -> EcdsaRoleEnvelopeAadV1 {
        EcdsaRoleEnvelopeAadV1 {
            lifecycle_id: "lifecycle-1".to_owned(),
            work_kind: "registration_prepare".to_owned(),
            primitive_request_kind: "registration".to_owned(),
            signer_set_id: "signer-set-1".to_owned(),
            recipient: EcdsaSignerIdentityV1 {
                role: EcdsaDeriverRoleV1::A,
                signer_id: "deriver-a-1".to_owned(),
                key_epoch: "deriver-a-epoch-1".to_owned(),
            },
            selected_server: EcdsaSelectedServerIdentityV1 {
                server_id: "server-1".to_owned(),
                key_epoch: "server-epoch-1".to_owned(),
                recipient_encryption_key: "x25519:server-output-key".to_owned(),
            },
            transcript_digest: [0x11; 32],
            router_request_digest: [0x22; 32],
            expires_at_ms: 2_000,
        }
    }

    #[test]
    fn signer_envelope_round_trip_rejects_aad_drift() {
        let (private_key, public_key) =
            DhKemX25519HkdfSha256::derive_key_pair(&[0x41; 32]).expect("keypair");
        let private_key: [u8; 32] = DhKemX25519HkdfSha256::sk_to_bytes(&private_key)
            .as_slice()
            .try_into()
            .expect("private key bytes");
        let recipient = EcdsaSignerEnvelopePublicKeyV1 {
            role: EcdsaDeriverRoleV1::A,
            key_epoch: "deriver-a-epoch-1".to_owned(),
            public_key: format!(
                "x25519:{}",
                lower_hex(&DhKemX25519HkdfSha256::pk_to_bytes(&public_key)),
            ),
        };
        let aad = aad();
        let payload =
            seal_ecdsa_signer_envelope_v1(&recipient, &aad, b"canonical-signer-input", [0x52; 32])
                .expect("seal");
        assert_eq!(
            open_ecdsa_signer_envelope_v1(&payload, &aad, &private_key).expect("open"),
            b"canonical-signer-input",
        );
        let mut drifted = aad;
        drifted.router_request_digest[0] ^= 1;
        assert_eq!(
            open_ecdsa_signer_envelope_v1(&payload, &drifted, &private_key),
            Err(EcdsaClientProtocolError::InvalidShape),
        );
    }
}
