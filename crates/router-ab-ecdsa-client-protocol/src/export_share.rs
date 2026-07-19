use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const ECDSA_SIGNING_WORKER_EXPORT_SHARE_ENVELOPE_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/signing-worker-export-share-envelope/v1";
const ECDSA_SIGNING_WORKER_EXPORT_SHARE_AAD_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/signing-worker-export-share-aad/v1";
const ECDSA_SIGNING_WORKER_EXPORT_SHARE_HPKE_INFO_V1: &[u8] =
    b"router-ab-ecdsa-derivation/signing-worker-export-share-hpke/v1";
const ECDSA_SIGNING_WORKER_EXPORT_SHARE_ALGORITHM_V1: &str = "hpke_x25519_hkdf_sha256_aes256gcm_v1";
const HPKE_AUTH_TAG_LEN_V1: usize = 16;

/// Public authority, capability, key, and recipient binding for one exact export redemption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaSigningWorkerExportShareBindingV1 {
    /// Wallet that owns the active ECDSA capability.
    pub wallet_id: String,
    /// Exact wallet key handle selected by the authenticated Wallet Session.
    pub key_handle: String,
    /// Exact threshold ECDSA key identifier.
    pub ecdsa_threshold_key_id: String,
    /// Signing-root identifier used by the active capability.
    pub signing_root_id: String,
    /// Signing-root version used by the active capability.
    pub signing_root_version: String,
    /// Exact active SigningWorker root-share epoch.
    pub activation_epoch: String,
    /// Exact active SigningWorker identity.
    pub signing_worker_id: String,
    /// Stable context binding encoded as unpadded base64url.
    pub context_binding_b64u: String,
    /// Registered threshold public key encoded as unpadded base64url.
    pub threshold_public_key33_b64u: String,
    /// Canonical strict export request digest encoded as unpadded base64url.
    pub export_request_digest_b64u: String,
    /// User-confirmed export authorization digest encoded as unpadded base64url.
    pub export_authorization_digest_b64u: String,
    /// One-time export nonce.
    pub export_nonce: String,
    /// Authenticated threshold Wallet Session identifier.
    pub threshold_session_id: String,
    /// Authenticated Wallet Session signing grant.
    pub signing_grant_id: String,
    /// Exact export lifecycle identifier.
    pub lifecycle_id: String,
    /// Authorized browser recipient identity.
    pub recipient_identity: String,
    /// Authorized browser X25519 recipient key.
    pub recipient_public_key: String,
    /// Export authorization expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl EcdsaSigningWorkerExportShareBindingV1 {
    /// Validates every public export-share binding field.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        for value in [
            &self.wallet_id,
            &self.key_handle,
            &self.ecdsa_threshold_key_id,
            &self.signing_root_id,
            &self.signing_root_version,
            &self.activation_epoch,
            &self.signing_worker_id,
            &self.export_nonce,
            &self.threshold_session_id,
            &self.signing_grant_id,
            &self.lifecycle_id,
            &self.recipient_identity,
        ] {
            require_non_empty(value)?;
        }
        decode_base64url_fixed::<32>(&self.context_binding_b64u)?;
        decode_base64url_fixed::<33>(&self.threshold_public_key33_b64u)?;
        decode_base64url_fixed::<32>(&self.export_request_digest_b64u)?;
        decode_base64url_fixed::<32>(&self.export_authorization_digest_b64u)?;
        decode_x25519_public_key(&self.recipient_public_key)?;
        if self.expires_at_ms == 0 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }

    fn aad_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        self.validate()?;
        let mut out = Vec::new();
        push_bytes(&mut out, ECDSA_SIGNING_WORKER_EXPORT_SHARE_AAD_VERSION_V1);
        push_bytes(
            &mut out,
            ECDSA_SIGNING_WORKER_EXPORT_SHARE_ALGORITHM_V1.as_bytes(),
        );
        for value in [
            &self.wallet_id,
            &self.key_handle,
            &self.ecdsa_threshold_key_id,
            &self.signing_root_id,
            &self.signing_root_version,
            &self.activation_epoch,
            &self.signing_worker_id,
            &self.context_binding_b64u,
            &self.threshold_public_key33_b64u,
            &self.export_request_digest_b64u,
            &self.export_authorization_digest_b64u,
            &self.export_nonce,
            &self.threshold_session_id,
            &self.signing_grant_id,
            &self.lifecycle_id,
            &self.recipient_identity,
            &self.recipient_public_key,
        ] {
            push_bytes(&mut out, value.as_bytes());
        }
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(out)
    }
}

/// HPKE envelope carrying the exact active SigningWorker additive share to one browser recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaSigningWorkerExportShareEnvelopeV1 {
    /// Fixed protocol version.
    pub version: String,
    /// Fixed HPKE algorithm.
    pub algorithm: String,
    /// Exact public export authority and capability binding.
    pub binding: EcdsaSigningWorkerExportShareBindingV1,
    /// HPKE encapsulated key followed by ciphertext and authentication tag.
    pub ciphertext_and_tag: Vec<u8>,
}

impl EcdsaSigningWorkerExportShareEnvelopeV1 {
    /// Validates the public envelope shape and binding.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        if self.version
            != String::from_utf8_lossy(ECDSA_SIGNING_WORKER_EXPORT_SHARE_ENVELOPE_VERSION_V1)
            || self.algorithm != ECDSA_SIGNING_WORKER_EXPORT_SHARE_ALGORITHM_V1
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        self.binding.validate()?;
        if self.ciphertext_and_tag.len()
            <= DhKemX25519HkdfSha256::ENCAPPED_KEY_LEN + HPKE_AUTH_TAG_LEN_V1
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }
}

/// Seals the exact active SigningWorker share to the authorized browser recipient.
pub fn seal_ecdsa_signing_worker_export_share_v1(
    binding: EcdsaSigningWorkerExportShareBindingV1,
    server_share32: &[u8; 32],
    mut seal_seed: [u8; 32],
) -> Result<EcdsaSigningWorkerExportShareEnvelopeV1, EcdsaClientProtocolError> {
    binding.validate()?;
    let recipient_public_key = decode_x25519_public_key(&binding.recipient_public_key)?;
    let recipient_public_key = DhKemX25519HkdfSha256::pk_from_bytes(&recipient_public_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let mut rng = ChaCha20Rng::from_seed(seal_seed);
    seal_seed.zeroize();
    let (encapped_key, ciphertext) = SignerEnvelopeHpkeV1::seal_base(
        &mut rng,
        &recipient_public_key,
        ECDSA_SIGNING_WORKER_EXPORT_SHARE_HPKE_INFO_V1,
        &binding.aad_bytes()?,
        server_share32,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let mut ciphertext_and_tag = Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
    ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
    ciphertext_and_tag.extend_from_slice(&ciphertext);
    let envelope = EcdsaSigningWorkerExportShareEnvelopeV1 {
        version: String::from_utf8_lossy(ECDSA_SIGNING_WORKER_EXPORT_SHARE_ENVELOPE_VERSION_V1)
            .into_owned(),
        algorithm: ECDSA_SIGNING_WORKER_EXPORT_SHARE_ALGORITHM_V1.to_owned(),
        binding,
        ciphertext_and_tag,
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Opens one export-share envelope after requiring the exact expected public binding.
pub fn open_ecdsa_signing_worker_export_share_v1(
    envelope: &EcdsaSigningWorkerExportShareEnvelopeV1,
    expected_binding: &EcdsaSigningWorkerExportShareBindingV1,
    recipient_private_key: &[u8; 32],
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    envelope.validate()?;
    expected_binding.validate()?;
    if envelope.binding != *expected_binding {
        return Err(EcdsaClientProtocolError::ContextMismatch);
    }
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient_private_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let (encapped_key, ciphertext) = envelope
        .ciphertext_and_tag
        .split_at(DhKemX25519HkdfSha256::ENCAPPED_KEY_LEN);
    let encapped_key = DhKemX25519HkdfSha256::enc_from_bytes(encapped_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let mut plaintext = SignerEnvelopeHpkeV1::open_base(
        &encapped_key,
        &private_key,
        ECDSA_SIGNING_WORKER_EXPORT_SHARE_HPKE_INFO_V1,
        &expected_binding.aad_bytes()?,
        ciphertext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let server_share32 = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape);
    plaintext.zeroize();
    server_share32
}

fn decode_base64url_fixed<const N: usize>(
    value: &str,
) -> Result<[u8; N], EcdsaClientProtocolError> {
    let decoded =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}
