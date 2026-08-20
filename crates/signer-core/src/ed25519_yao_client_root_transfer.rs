//! Cross-device transfer of an Ed25519 Yao Client root.
//!
//! Device linking transfers the smallest capability that can satisfy the
//! ordinary Ed25519 Yao export flow. The wallet custody seed stays in the
//! source worker. Device 1 derives the Client root against the exact
//! application binding digest, then seals that fixed-width root to Device 2's
//! one-use X25519 recipient. Device 2 opens the package and immediately
//! writes a factor-bound root envelope.
//!
//! The package binding is authenticated as AEAD additional data and includes
//! the exact relay, wallet-key, target-factor, enrollment, device, revocation,
//! application, recipient, and registered-public-key facts.

use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::ed25519_yao_derivation::Ed25519YaoClientRootV1;
use crate::error::{CoreResult, SignerCoreError};
use crate::passkey_custody::{
    open_verified_passkey_custody_secret_v1, seal_custody_secret, PasskeyCustodyEnvelopeBindingV1,
    PasskeyCustodySecretBindingV1, PasskeyCustodySecretKind, PasskeyCustodyTargetFactorV1,
    SealedPasskeyCustodyEnvelopeV1, WalletCustodySeedFromSealedEnvelopeV1, PASSKEY_CUSTODY_KEY_LEN,
    PASSKEY_CUSTODY_NONCE_LEN,
};
use crate::wallet_seed_derivation::derive_ed25519_yao_client_root_from_seed_v1;

/// The frozen X25519/HKDF-SHA256/ChaCha20-Poly1305 package algorithm.
pub const ED25519_YAO_CLIENT_ROOT_TRANSFER_ALG_V1: &str = "x25519-hkdf-sha256-chacha20poly1305-v1";

const TRANSFER_AAD_CONTEXT_V1: &[u8] = b"seams/ed25519-yao-client-root-transfer/aad/v1";
const TRANSFER_KEK_SALT_V1: &[u8] = b"seams/ed25519-yao-client-root-transfer/kek/salt/v1";
const TRANSFER_KEK_INFO_V1: &[u8] = b"seams/ed25519-yao-client-root-transfer/kek/info/v1";
const X25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const APPLICATION_BINDING_DIGEST_LEN: usize = 32;
const CLIENT_ROOT_LEN: usize = 32;
const MAX_TRANSFER_FIELD_LEN: usize = 512;

/// Public facts authenticated to one Ed25519 Yao Client-root package.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ed25519YaoClientRootTransferBindingV1 {
    pub link_session_id: String,
    pub wallet_id: String,
    pub wallet_key_id: String,
    pub target_factor: PasskeyCustodyTargetFactorV1,
    pub enrollment_id: String,
    pub device_id: String,
    pub revocation_epoch: u64,
    pub application_binding_digest_b64u: String,
    pub registered_public_key_b64u: String,
    pub recipient_public_key_b64u: String,
}

impl Ed25519YaoClientRootTransferBindingV1 {
    /// Returns the exact application binding digest carried by this package.
    pub fn application_binding_digest(&self) -> CoreResult<[u8; APPLICATION_BINDING_DIGEST_LEN]> {
        decode_fixed_b64u(
            "applicationBindingDigestB64u",
            &self.application_binding_digest_b64u,
        )
    }

    /// Returns the public identity the root must reproduce during export.
    pub fn registered_public_key(&self) -> CoreResult<[u8; ED25519_PUBLIC_KEY_LEN]> {
        decode_fixed_b64u("registeredPublicKeyB64u", &self.registered_public_key_b64u)
    }

    /// Returns the X25519 key that receives this package.
    pub fn recipient_public_key(&self) -> CoreResult<[u8; X25519_PUBLIC_KEY_LEN]> {
        decode_fixed_b64u("recipientPublicKeyB64u", &self.recipient_public_key_b64u)
    }
}

/// A root package safe to relay through application JavaScript and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEd25519YaoClientRootTransferV1 {
    pub ephemeral_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    pub nonce: [u8; PASSKEY_CUSTODY_NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub binding_digest: [u8; 32],
    pub ciphertext_digest: [u8; 32],
}

impl SealedEd25519YaoClientRootTransferV1 {
    /// Encodes the ephemeral X25519 public key for the wire boundary.
    pub fn ephemeral_public_key_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ephemeral_public_key)
    }

    /// Encodes the package nonce for the wire boundary.
    pub fn nonce_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.nonce)
    }

    /// Encodes the sealed root for the wire boundary.
    pub fn ciphertext_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ciphertext)
    }

    /// Encodes the AAD binding digest for the wire boundary.
    pub fn binding_digest_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.binding_digest)
    }

    /// Encodes the ciphertext digest for the wire boundary.
    pub fn ciphertext_digest_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ciphertext_digest)
    }
}

/// Device 2's one-use X25519 recipient.
///
/// The private key is generated and retained in the crypto worker. It is
/// intentionally neither cloneable nor serializable.
pub struct Ed25519YaoClientRootTransferRecipientV1 {
    secret: Zeroizing<[u8; X25519_PUBLIC_KEY_LEN]>,
    public_key: [u8; X25519_PUBLIC_KEY_LEN],
}

impl Ed25519YaoClientRootTransferRecipientV1 {
    /// Builds a recipient from worker-owned random key material.
    pub fn from_secret_bytes(secret_bytes: &[u8]) -> CoreResult<Self> {
        if secret_bytes.len() != X25519_PUBLIC_KEY_LEN {
            return Err(SignerCoreError::invalid_length(
                "Ed25519 Yao Client-root recipient secret must be 32 bytes",
            ));
        }
        let mut secret = Zeroizing::new([0u8; X25519_PUBLIC_KEY_LEN]);
        secret.copy_from_slice(secret_bytes);
        let scalar = clamped_scalar(&secret);
        let public_key = MontgomeryPoint::mul_base(&scalar).to_bytes();
        Ok(Self { secret, public_key })
    }

    /// Returns the public half safe to publish to Device 1.
    pub fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.public_key
    }

    /// Returns the public half in canonical base64url form.
    pub fn public_key_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.public_key)
    }
}

impl core::fmt::Debug for Ed25519YaoClientRootTransferRecipientV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Ed25519YaoClientRootTransferRecipientV1")
    }
}

/// Proof that a Client root was opened from one authenticated root package.
///
/// The proof is consumed only by the factor-sealing operation. It cannot be
/// serialized, cloned, or used to prepare a second transfer.
pub struct Ed25519YaoClientRootFromLinkedDeviceTransferV1 {
    link_session_id: String,
    wallet_id: String,
    wallet_key_id: String,
    target_factor: PasskeyCustodyTargetFactorV1,
    enrollment_id: String,
    device_id: String,
    revocation_epoch: u64,
    application_binding_digest: [u8; APPLICATION_BINDING_DIGEST_LEN],
    registered_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl Ed25519YaoClientRootFromLinkedDeviceTransferV1 {
    /// Returns the linking session identity authenticated by the package.
    pub fn link_session_id(&self) -> &str {
        &self.link_session_id
    }

    /// Returns the wallet identity authenticated by the package.
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    /// Returns the exact wallet-key identity authenticated by the package.
    pub fn wallet_key_id(&self) -> &str {
        &self.wallet_key_id
    }

    /// Returns the exact target factor authenticated by the package.
    pub const fn target_factor(&self) -> PasskeyCustodyTargetFactorV1 {
        self.target_factor
    }

    /// Returns the target enrollment identity authenticated by the package.
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }

    /// Returns the target device identity authenticated by the package.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Returns the target revocation epoch authenticated by the package.
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    /// Returns the application binding digest authenticated by the package.
    pub fn application_binding_digest(&self) -> &[u8; APPLICATION_BINDING_DIGEST_LEN] {
        &self.application_binding_digest
    }

    /// Returns the registered Ed25519 public key authenticated by the package.
    pub fn registered_public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.registered_public_key
    }
}

impl core::fmt::Debug for Ed25519YaoClientRootFromLinkedDeviceTransferV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Ed25519YaoClientRootFromLinkedDeviceTransferV1")
    }
}

/// Derives the exact Ed25519 Yao Client root for one approved target.
///
/// The seed must already have been opened from a verified local factor
/// envelope. The proof is checked against the transfer wallet before the root
/// is derived, and the root is returned only as a zeroizing Rust capability.
pub fn derive_ed25519_yao_client_root_for_linked_device_v1(
    admitted: &WalletCustodySeedFromSealedEnvelopeV1,
    custody_seed: &[u8],
    transfer: &Ed25519YaoClientRootTransferBindingV1,
) -> CoreResult<Ed25519YaoClientRootV1> {
    validate_transfer_binding(transfer)?;
    if admitted.wallet_id() != transfer.wallet_id {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 Yao Client-root transfer wallet does not match the verified custody seed",
        ));
    }
    let application_binding_digest = transfer.application_binding_digest()?;
    if custody_seed.len() != CLIENT_ROOT_LEN {
        return Err(SignerCoreError::invalid_length(
            "wallet custody seed must be 32 bytes",
        ));
    }
    let root =
        derive_ed25519_yao_client_root_from_seed_v1(custody_seed, &application_binding_digest)?;
    Ok(Ed25519YaoClientRootV1::from_secret_bytes(*root))
}

/// Seals the derived Client root to Device 2's one-use recipient.
///
/// This is the only source-device transfer entry point. It takes the verified
/// seed proof and derives the root internally, so a caller cannot hand this
/// path an arbitrary root or a custody seed from an unverified source.
pub fn seal_ed25519_yao_client_root_for_linked_device_v1(
    admitted: &WalletCustodySeedFromSealedEnvelopeV1,
    custody_seed: &[u8],
    transfer: &Ed25519YaoClientRootTransferBindingV1,
    ephemeral_secret_bytes: &[u8],
    nonce: &[u8],
) -> CoreResult<SealedEd25519YaoClientRootTransferV1> {
    let root =
        derive_ed25519_yao_client_root_for_linked_device_v1(admitted, custody_seed, transfer)?;
    seal_root_to_recipient_v1(&root, transfer, ephemeral_secret_bytes, nonce)
}

/// Opens one package addressed to this exact recipient.
pub fn open_ed25519_yao_client_root_from_linked_device_v1(
    recipient: Ed25519YaoClientRootTransferRecipientV1,
    transfer: &Ed25519YaoClientRootTransferBindingV1,
    ephemeral_public_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    expected_binding_digest: &[u8],
    expected_ciphertext_digest: &[u8],
) -> CoreResult<(
    Ed25519YaoClientRootV1,
    Ed25519YaoClientRootFromLinkedDeviceTransferV1,
)> {
    validate_transfer_binding(transfer)?;
    let recipient_public_key = transfer.recipient_public_key()?;
    if recipient_public_key != recipient.public_key {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 Yao Client-root transfer is addressed to another recipient key",
        ));
    }
    let nonce = require_nonce(nonce)?;
    let ephemeral_public_key = require_fixed_bytes(
        "Ed25519 Yao Client-root transfer ephemeral public key",
        ephemeral_public_key,
    )?;
    let aad = encode_transfer_aad_v1(transfer)?;
    let expected_binding_digest = require_digest(
        "Ed25519 Yao Client-root transfer binding digest",
        expected_binding_digest,
    )?;
    if expected_binding_digest != sha256_digest(&aad) {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 Yao Client-root transfer binding digest does not match its binding",
        ));
    }
    let expected_ciphertext_digest = require_digest(
        "Ed25519 Yao Client-root transfer ciphertext digest",
        expected_ciphertext_digest,
    )?;
    if expected_ciphertext_digest != sha256_digest(ciphertext) {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 Yao Client-root transfer ciphertext digest does not match its ciphertext",
        ));
    }
    if ciphertext.len() != CLIENT_ROOT_LEN + 16 {
        return Err(SignerCoreError::invalid_length(
            "Ed25519 Yao Client-root transfer ciphertext must contain one sealed 32-byte root",
        ));
    }
    let recipient_scalar = clamped_scalar(&recipient.secret);
    let shared = diffie_hellman(&recipient_scalar, &ephemeral_public_key)?;
    let key = derive_transfer_key_v1(&shared, &ephemeral_public_key, &recipient_public_key, &aad)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| SignerCoreError::crypto_error("invalid Ed25519 Yao Client-root key"))?;
    let opened = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            SignerCoreError::crypto_error("Ed25519 Yao Client-root transfer open failed")
        })?;
    let root_bytes: Zeroizing<[u8; CLIENT_ROOT_LEN]> =
        Zeroizing::new(opened.try_into().map_err(|_| {
            SignerCoreError::invalid_length("opened Ed25519 Yao Client root must be 32 bytes")
        })?);
    let root = Ed25519YaoClientRootV1::from_secret_bytes(*root_bytes);
    let admitted = Ed25519YaoClientRootFromLinkedDeviceTransferV1 {
        link_session_id: transfer.link_session_id.clone(),
        wallet_id: transfer.wallet_id.clone(),
        wallet_key_id: transfer.wallet_key_id.clone(),
        target_factor: transfer.target_factor,
        enrollment_id: transfer.enrollment_id.clone(),
        device_id: transfer.device_id.clone(),
        revocation_epoch: transfer.revocation_epoch,
        application_binding_digest: transfer.application_binding_digest()?,
        registered_public_key: transfer.registered_public_key()?,
    };
    Ok((root, admitted))
}

/// Seals an opened root under Device 2's verified factor.
///
/// The envelope binding may select a new factor and envelope id. Wallet,
/// enrollment, device, application digest, and registered public key must
/// remain exactly those authenticated by the transfer package, including its
/// target factor and revocation epoch.
pub fn seal_ed25519_yao_client_root_under_factor_v1(
    factor_secret: &[u8],
    new_binding: &PasskeyCustodyEnvelopeBindingV1,
    admitted: Ed25519YaoClientRootFromLinkedDeviceTransferV1,
    root: &Ed25519YaoClientRootV1,
    nonce: &[u8],
) -> CoreResult<SealedPasskeyCustodyEnvelopeV1> {
    match &new_binding.binding {
        PasskeyCustodySecretBindingV1::Ed25519YaoClientRoot {
            link_session_id,
            wallet_key_id,
            target_factor,
            enrollment_id,
            device_id,
            revocation_epoch,
            application_binding_digest_b64u,
            registered_public_key_b64u,
        } => {
            if link_session_id != &admitted.link_session_id
                || wallet_key_id != &admitted.wallet_key_id
                || *target_factor != admitted.target_factor
                || enrollment_id != &admitted.enrollment_id
                || device_id != &admitted.device_id
                || *revocation_epoch != admitted.revocation_epoch
                || decode_fixed_b64u(
                    "applicationBindingDigestB64u",
                    application_binding_digest_b64u,
                )? != admitted.application_binding_digest
                || decode_fixed_b64u("registeredPublicKeyB64u", registered_public_key_b64u)?
                    != admitted.registered_public_key
            {
                return Err(SignerCoreError::invalid_input(
                    "Ed25519 Yao Client-root factor binding does not match the transfer",
                ));
            }
        }
        _ => {
            return Err(SignerCoreError::invalid_input(
                "Ed25519 Yao Client-root reseal requires an Ed25519 Yao Client-root binding",
            ))
        }
    };
    if new_binding.wallet_id != admitted.wallet_id {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 Yao Client-root factor binding names another wallet",
        ));
    }
    seal_custody_secret(factor_secret, new_binding, nonce, root.as_bytes())
}

/// Opens an already factor-sealed Client root for ordinary Yao operations.
///
/// This source path accepts only the dedicated root branch. It never accepts
/// or reconstructs a wallet custody seed.
pub fn open_ed25519_yao_client_root_under_factor_v1(
    factor_secret: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    ciphertext: &[u8],
    expected_aad_hash: &[u8],
    expected_ciphertext_digest: &[u8],
) -> CoreResult<Ed25519YaoClientRootV1> {
    if binding.binding.kind() != PasskeyCustodySecretKind::Ed25519YaoClientRoot {
        return Err(SignerCoreError::invalid_input(
            "Ed25519 Yao Client-root source requires an Ed25519 Yao Client-root envelope",
        ));
    }
    let opened = open_verified_passkey_custody_secret_v1(
        factor_secret,
        binding,
        nonce,
        ciphertext,
        expected_aad_hash,
        expected_ciphertext_digest,
    )?;
    let bytes: Zeroizing<[u8; CLIENT_ROOT_LEN]> =
        Zeroizing::new(opened.as_slice().try_into().map_err(|_| {
            SignerCoreError::invalid_length(
                "factor-sealed Ed25519 Yao Client root must be 32 bytes",
            )
        })?);
    Ok(Ed25519YaoClientRootV1::from_secret_bytes(*bytes))
}

fn seal_root_to_recipient_v1(
    root: &Ed25519YaoClientRootV1,
    transfer: &Ed25519YaoClientRootTransferBindingV1,
    ephemeral_secret_bytes: &[u8],
    nonce: &[u8],
) -> CoreResult<SealedEd25519YaoClientRootTransferV1> {
    validate_transfer_binding(transfer)?;
    let nonce = require_nonce(nonce)?;
    let recipient_public_key = transfer.recipient_public_key()?;
    let ephemeral_secret_bytes = require_fixed_bytes(
        "Ed25519 Yao Client-root transfer ephemeral secret",
        ephemeral_secret_bytes,
    )?;
    let ephemeral_secret = Zeroizing::new(ephemeral_secret_bytes);
    let ephemeral_scalar = clamped_scalar(&ephemeral_secret);
    let ephemeral_public_key = MontgomeryPoint::mul_base(&ephemeral_scalar).to_bytes();
    let aad = encode_transfer_aad_v1(transfer)?;
    let shared = diffie_hellman(&ephemeral_scalar, &recipient_public_key)?;
    let key = derive_transfer_key_v1(&shared, &ephemeral_public_key, &recipient_public_key, &aad)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| SignerCoreError::crypto_error("invalid Ed25519 Yao Client-root key"))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: root.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| {
            SignerCoreError::crypto_error("Ed25519 Yao Client-root transfer seal failed")
        })?;
    Ok(SealedEd25519YaoClientRootTransferV1 {
        ephemeral_public_key,
        nonce,
        binding_digest: sha256_digest(&aad),
        ciphertext_digest: sha256_digest(&ciphertext),
        ciphertext,
    })
}

fn validate_transfer_binding(transfer: &Ed25519YaoClientRootTransferBindingV1) -> CoreResult<()> {
    require_transfer_field("linkSessionId", &transfer.link_session_id)?;
    require_transfer_field("walletId", &transfer.wallet_id)?;
    require_transfer_field("walletKeyId", &transfer.wallet_key_id)?;
    require_transfer_field("enrollmentId", &transfer.enrollment_id)?;
    require_transfer_field("deviceId", &transfer.device_id)?;
    let _ = transfer.application_binding_digest()?;
    let _ = transfer.registered_public_key()?;
    let _ = transfer.recipient_public_key()?;
    Ok(())
}

/// Encodes the frozen transfer AAD. Each field is `u32 BE label length || label
/// || u32 BE value length || value`; the order is context, algorithm,
/// link-session, wallet, wallet-key, target-factor, enrollment, device,
/// revocation epoch, application digest, registered key, recipient key.
fn encode_transfer_aad_v1(transfer: &Ed25519YaoClientRootTransferBindingV1) -> CoreResult<Vec<u8>> {
    validate_transfer_binding(transfer)?;
    let application_binding_digest = transfer.application_binding_digest()?;
    let registered_public_key = transfer.registered_public_key()?;
    let recipient_public_key = transfer.recipient_public_key()?;
    let mut out = Vec::new();
    labeled(&mut out, b"context", TRANSFER_AAD_CONTEXT_V1);
    labeled(
        &mut out,
        b"transferAlg",
        ED25519_YAO_CLIENT_ROOT_TRANSFER_ALG_V1.as_bytes(),
    );
    labeled(
        &mut out,
        b"linkSessionId",
        transfer.link_session_id.as_bytes(),
    );
    labeled(&mut out, b"walletId", transfer.wallet_id.as_bytes());
    labeled(&mut out, b"walletKeyId", transfer.wallet_key_id.as_bytes());
    labeled(
        &mut out,
        b"targetFactor",
        transfer.target_factor.as_str().as_bytes(),
    );
    labeled(&mut out, b"enrollmentId", transfer.enrollment_id.as_bytes());
    labeled(&mut out, b"deviceId", transfer.device_id.as_bytes());
    labeled(
        &mut out,
        b"revocationEpoch",
        &transfer.revocation_epoch.to_be_bytes(),
    );
    labeled(
        &mut out,
        b"applicationBindingDigest",
        &application_binding_digest,
    );
    labeled(&mut out, b"registeredPublicKey", &registered_public_key);
    labeled(&mut out, b"recipientPublicKey", &recipient_public_key);
    Ok(out)
}

fn derive_transfer_key_v1(
    shared_secret: &Zeroizing<[u8; X25519_PUBLIC_KEY_LEN]>,
    ephemeral_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    recipient_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    aad: &[u8],
) -> CoreResult<Zeroizing<[u8; PASSKEY_CUSTODY_KEY_LEN]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(&shared_secret[..]);
    ikm.extend_from_slice(ephemeral_public_key);
    ikm.extend_from_slice(recipient_public_key);
    let hkdf = Hkdf::<Sha256>::new(Some(TRANSFER_KEK_SALT_V1), &ikm[..]);
    let aad_digest = sha256_digest(aad);
    let mut key = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
    hkdf.expand_multi_info(&[TRANSFER_KEK_INFO_V1, &aad_digest], &mut key[..])
        .map_err(|_| {
            SignerCoreError::hkdf_error("Ed25519 Yao Client-root transfer key derivation failed")
        })?;
    Ok(key)
}

fn diffie_hellman(
    scalar: &Scalar,
    public_key: &[u8; X25519_PUBLIC_KEY_LEN],
) -> CoreResult<Zeroizing<[u8; X25519_PUBLIC_KEY_LEN]>> {
    let shared = Zeroizing::new((MontgomeryPoint(*public_key) * scalar).to_bytes());
    if bool::from(shared.ct_eq(&[0u8; X25519_PUBLIC_KEY_LEN])) {
        return Err(SignerCoreError::crypto_error(
            "Ed25519 Yao Client-root transfer peer key is degenerate",
        ));
    }
    Ok(shared)
}

fn clamped_scalar(secret: &[u8; X25519_PUBLIC_KEY_LEN]) -> Zeroizing<Scalar> {
    let mut clamped = Zeroizing::new(*secret);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    Zeroizing::new(Scalar::from_bytes_mod_order(*clamped))
}

fn decode_fixed_b64u<const N: usize>(label: &str, value: &str) -> CoreResult<[u8; N]> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| {
        SignerCoreError::decode_error(format!("{label} must be unpadded base64url"))
    })?;
    bytes
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length(format!("{label} must decode to {N} bytes")))
}

fn require_fixed_bytes<const N: usize>(label: &str, bytes: &[u8]) -> CoreResult<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length(format!("{label} must contain {N} bytes")))
}

fn require_digest(label: &str, bytes: &[u8]) -> CoreResult<[u8; 32]> {
    require_fixed_bytes(label, bytes)
}

fn require_nonce(nonce: &[u8]) -> CoreResult<[u8; PASSKEY_CUSTODY_NONCE_LEN]> {
    require_fixed_bytes("Ed25519 Yao Client-root transfer nonce", nonce)
}

fn require_transfer_field(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() || value.len() > MAX_TRANSFER_FIELD_LEN {
        return Err(SignerCoreError::invalid_input(format!(
            "Ed25519 Yao Client-root transfer {label} is invalid"
        )));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(SignerCoreError::invalid_input(format!(
            "Ed25519 Yao Client-root transfer {label} must contain visible ASCII"
        )));
    }
    Ok(())
}

fn sha256_digest(input: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    Sha256::digest(input).into()
}

fn labeled(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    out.extend_from_slice(&(label.len() as u32).to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
