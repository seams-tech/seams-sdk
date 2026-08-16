//! Refactor 103 Phase 8: carrying a wallet custody seed to a newly linked
//! device.
//!
//! Adding a factor normally happens on one machine: the same worker holds the
//! secret that opens the existing envelope and the secret that seals the new
//! one. Device linking splits those across two machines. Device 1 holds the
//! owner factor and can open the envelope; Device 2 creates the new passkey
//! and is the only place its PRF exists. Neither secret may cross to the other
//! device, so the *seed* is what moves, sealed to a recipient key that exists
//! only inside Device 2's worker.
//!
//! Frozen wrap: X25519 ephemeral-static Diffie-Hellman into HKDF-SHA256 into
//! ChaCha20Poly1305, matching the custody envelope's AEAD and KDF rather than
//! introducing a second cryptographic style. The transfer facts are the AAD,
//! so a package prepared for one enrollment cannot open under another even if
//! it reaches the right recipient key.
//!
//! What crosses the wire is ciphertext plus an ephemeral public key. The seed,
//! both factor secrets, the recipient private key, and the derived transfer
//! key stay inside their own workers.

use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CoreResult, SignerCoreError};
use crate::passkey_custody::{
    seal_custody_secret, sha256_digest, PasskeyCustodyEnvelopeBindingV1,
    PasskeyCustodySecretBindingV1, PasskeyCustodySecretKind, SealedPasskeyCustodyEnvelopeV1,
    WalletCustodySeedFromSealedEnvelopeV1, PASSKEY_CUSTODY_KEY_LEN, PASSKEY_CUSTODY_NONCE_LEN,
};

pub const LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1: &str = "x25519-hkdf-sha256-chacha20poly1305-v1";

const TRANSFER_AAD_CONTEXT_V1: &[u8] = b"seams/linked-device-custody-transfer/aad/v1";
const TRANSFER_KEK_SALT_V1: &[u8] = b"seams/linked-device-custody-transfer/kek/salt/v1";
const TRANSFER_KEK_INFO_V1: &[u8] = b"seams/linked-device-custody-transfer/kek/info/v1";
const X25519_PUBLIC_KEY_LEN: usize = 32;
const MAX_TRANSFER_FIELD_LEN: usize = 512;
const MAX_TRANSFERRED_SEED_LEN: usize = 1024;

/// Every public fact one transfer is bound to.
///
/// Both devices reconstruct this independently — Device 1 from the envelope it
/// opened and the approved enrollment, Device 2 from its own recipient key and
/// the same approved enrollment — and it is authenticated as AAD. A package
/// resealed against another wallet, enrollment, device, or recipient key
/// therefore fails to open rather than yielding a seed.
///
/// `binding` is the admitted envelope's custody binding, carried across
/// verbatim. It is what lets Device 2's reseal preserve the exact claim the
/// original envelope made instead of minting a new one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedDeviceCustodyTransferBindingV1 {
    pub wallet_id: String,
    pub enrollment_id: String,
    pub device_id: String,
    pub recipient_public_key_b64u: String,
    pub binding: PasskeyCustodySecretBindingV1,
}

/// A sealed transfer package. Nothing here is secret: the ephemeral public key
/// and ciphertext are safe to relay, and the digest is what the server and both
/// devices compare before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedLinkedDeviceCustodyTransferV1 {
    pub ephemeral_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    pub nonce: [u8; PASSKEY_CUSTODY_NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub aad_hash: [u8; 32],
    pub ciphertext_digest: [u8; 32],
}

impl SealedLinkedDeviceCustodyTransferV1 {
    pub fn ephemeral_public_key_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ephemeral_public_key)
    }

    pub fn nonce_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.nonce)
    }

    pub fn ciphertext_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ciphertext)
    }

    pub fn aad_hash_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.aad_hash)
    }

    pub fn ciphertext_digest_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ciphertext_digest)
    }
}

/// Device 2's transfer recipient key pair.
///
/// Generated inside the worker that will do the reseal, so the private half
/// never reaches JavaScript and never reaches the device-linking key worker
/// that holds the QR's link key. Publishing the public half through the
/// authenticated enrollment is what tells Device 1 where to seal.
///
/// Not `Clone` or `Serialize`: it is a within-session capability.
pub struct LinkedDeviceCustodyTransferRecipientV1 {
    secret: Zeroizing<[u8; 32]>,
    public_key: [u8; X25519_PUBLIC_KEY_LEN],
}

impl LinkedDeviceCustodyTransferRecipientV1 {
    /// Builds a recipient from 32 bytes of caller-supplied randomness. The
    /// caller is the wasm boundary, which draws from `getrandom`; taking the
    /// bytes as an argument keeps this crate free of an RNG dependency and
    /// keeps the function testable against fixed vectors.
    pub fn from_secret_bytes(secret_bytes: &[u8]) -> CoreResult<Self> {
        if secret_bytes.len() != 32 {
            return Err(SignerCoreError::invalid_length(
                "linked-device custody transfer recipient secret must be 32 bytes",
            ));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(secret_bytes);
        let scalar = clamped_scalar(&secret);
        let public_key = (MontgomeryPoint::mul_base(&scalar)).to_bytes();
        Ok(Self { secret, public_key })
    }

    pub fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.public_key
    }

    pub fn public_key_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.public_key)
    }
}

impl core::fmt::Debug for LinkedDeviceCustodyTransferRecipientV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("LinkedDeviceCustodyTransferRecipientV1")
    }
}

/// A seed that arrived through an authenticated linked-device transfer.
///
/// Deliberately a third proof rather than a conversion into
/// `WalletCustodySeedFromSealedEnvelopeV1`. That type means "this seed came out
/// of an envelope this device opened"; this one means "this seed came from a
/// device that had opened such an envelope, over a channel bound to this exact
/// enrollment and recipient key". They admit different reseals and must not be
/// interchangeable — the linked reseal below is the only thing this one opens.
///
/// Not `Clone` or `Serialize`: a within-session capability that must not cross
/// the wasm boundary.
pub struct WalletCustodySeedFromLinkedDeviceTransferV1 {
    wallet_id: String,
    enrollment_id: String,
    device_id: String,
    binding: PasskeyCustodySecretBindingV1,
}

impl WalletCustodySeedFromLinkedDeviceTransferV1 {
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn binding(&self) -> &PasskeyCustodySecretBindingV1 {
        &self.binding
    }
}

impl core::fmt::Debug for WalletCustodySeedFromLinkedDeviceTransferV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WalletCustodySeedFromLinkedDeviceTransferV1")
    }
}

/// Seals an already-admitted seed for exactly one linked device.
///
/// Requires the admission proof rather than a bare seed, so this cannot be used
/// to publish a seed the caller merely holds: only a device that opened a real
/// envelope for this wallet can prepare a transfer. The wallet and custody
/// binding are checked against that proof, so a transfer cannot relabel the
/// seed or move it to another wallet on the way out.
pub fn seal_wallet_custody_seed_for_linked_device_v1(
    admitted: &WalletCustodySeedFromSealedEnvelopeV1,
    custody_seed: &[u8],
    transfer: &LinkedDeviceCustodyTransferBindingV1,
    ephemeral_secret_bytes: &[u8],
    nonce: &[u8],
) -> CoreResult<SealedLinkedDeviceCustodyTransferV1> {
    if transfer.wallet_id != admitted.wallet_id() {
        return Err(SignerCoreError::invalid_input(
            "a linked-device transfer cannot move a custody seed to another wallet",
        ));
    }
    if transfer.binding.kind() != PasskeyCustodySecretKind::WalletCustodySeed {
        return Err(SignerCoreError::invalid_input(
            "a linked-device transfer carries wallet custody seeds only",
        ));
    }
    if custody_seed.is_empty() || custody_seed.len() > MAX_TRANSFERRED_SEED_LEN {
        return Err(SignerCoreError::invalid_input(
            "transferred custody seed length is invalid",
        ));
    }
    let nonce = require_transfer_nonce(nonce)?;
    let recipient_public_key = decode_public_key(&transfer.recipient_public_key_b64u)?;
    if ephemeral_secret_bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(
            "linked-device custody transfer ephemeral secret must be 32 bytes",
        ));
    }
    let mut ephemeral_secret = Zeroizing::new([0u8; 32]);
    ephemeral_secret.copy_from_slice(ephemeral_secret_bytes);
    let ephemeral_scalar = clamped_scalar(&ephemeral_secret);
    let ephemeral_public_key = (MontgomeryPoint::mul_base(&ephemeral_scalar)).to_bytes();

    let aad = encode_transfer_aad_v1(transfer)?;
    let shared = diffie_hellman(&ephemeral_scalar, &recipient_public_key)?;
    let key = derive_transfer_key_v1(&shared, &ephemeral_public_key, &recipient_public_key, &aad)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| SignerCoreError::crypto_error("invalid linked-device transfer key"))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: custody_seed,
                aad: &aad,
            },
        )
        .map_err(|_| SignerCoreError::crypto_error("linked-device custody transfer seal failed"))?;
    Ok(SealedLinkedDeviceCustodyTransferV1 {
        ephemeral_public_key,
        nonce,
        aad_hash: sha256_digest(&aad),
        ciphertext_digest: sha256_digest(&ciphertext),
        ciphertext,
    })
}

/// Opens a transfer addressed to this device's recipient key.
///
/// The recipient public key in the binding must be this recipient's own, so a
/// package prepared for a different device fails before decryption rather than
/// relying on the AEAD alone. The digests are compared for the same reason the
/// envelope open compares them: a package that drifted from what the server
/// recorded fails here instead of decrypting into unexpected material.
pub fn open_wallet_custody_seed_from_linked_device_v1(
    recipient: &LinkedDeviceCustodyTransferRecipientV1,
    transfer: &LinkedDeviceCustodyTransferBindingV1,
    ephemeral_public_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    expected_aad_hash: &[u8],
    expected_ciphertext_digest: &[u8],
) -> CoreResult<(
    Zeroizing<Vec<u8>>,
    WalletCustodySeedFromLinkedDeviceTransferV1,
)> {
    if transfer.binding.kind() != PasskeyCustodySecretKind::WalletCustodySeed {
        return Err(SignerCoreError::invalid_input(
            "a linked-device transfer carries wallet custody seeds only",
        ));
    }
    let recipient_public_key = decode_public_key(&transfer.recipient_public_key_b64u)?;
    if recipient_public_key != recipient.public_key {
        return Err(SignerCoreError::invalid_input(
            "linked-device custody transfer is addressed to another recipient key",
        ));
    }
    let nonce = require_transfer_nonce(nonce)?;
    let ephemeral_public_key = require_public_key_bytes(
        "linked-device custody transfer ephemeral public key",
        ephemeral_public_key,
    )?;
    let aad = encode_transfer_aad_v1(transfer)?;
    if expected_aad_hash != sha256_digest(&aad) {
        return Err(SignerCoreError::invalid_input(
            "linked-device custody transfer aad hash does not match its binding",
        ));
    }
    if expected_ciphertext_digest != sha256_digest(ciphertext) {
        return Err(SignerCoreError::invalid_input(
            "linked-device custody transfer ciphertext digest does not match its ciphertext",
        ));
    }
    let recipient_scalar = clamped_scalar(&recipient.secret);
    let shared = diffie_hellman(&recipient_scalar, &ephemeral_public_key)?;
    let key = derive_transfer_key_v1(&shared, &ephemeral_public_key, &recipient_public_key, &aad)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| SignerCoreError::crypto_error("invalid linked-device transfer key"))?;
    let seed = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                SignerCoreError::crypto_error("linked-device custody transfer open failed")
            })?,
    );
    if seed.is_empty() || seed.len() > MAX_TRANSFERRED_SEED_LEN {
        return Err(SignerCoreError::invalid_input(
            "transferred custody seed length is invalid",
        ));
    }
    Ok((
        seed,
        WalletCustodySeedFromLinkedDeviceTransferV1 {
            wallet_id: transfer.wallet_id.clone(),
            enrollment_id: transfer.enrollment_id.clone(),
            device_id: transfer.device_id.clone(),
            binding: transfer.binding.clone(),
        },
    ))
}

/// Seals a transferred seed under the linked device's own new factor.
///
/// The linked-device twin of `reseal_wallet_custody_seed_under_new_factor_v1`,
/// and it enforces the same rule: everything except the factor and the
/// envelope id must match what the transfer admitted. Device 2 therefore ends
/// up with an envelope making exactly the claim Device 1's envelope made — same
/// wallet, same custody binding, same key manifest — differing only in which
/// factor opens it. Adding Device 2 cannot relabel the wallet's keys.
pub fn reseal_transferred_wallet_custody_seed_v1(
    new_factor_secret: &[u8],
    new_binding: &PasskeyCustodyEnvelopeBindingV1,
    admitted: &WalletCustodySeedFromLinkedDeviceTransferV1,
    nonce: &[u8],
    custody_seed: &[u8],
) -> CoreResult<SealedPasskeyCustodyEnvelopeV1> {
    if new_binding.wallet_id != admitted.wallet_id {
        return Err(SignerCoreError::invalid_input(
            "a linked-device reseal cannot move a custody seed to another wallet",
        ));
    }
    if new_binding.binding != admitted.binding {
        return Err(SignerCoreError::invalid_input(
            "a linked-device reseal may change only the factor and the envelope id",
        ));
    }
    seal_custody_secret(new_factor_secret, new_binding, nonce, custody_seed)
}

fn encode_transfer_aad_v1(transfer: &LinkedDeviceCustodyTransferBindingV1) -> CoreResult<Vec<u8>> {
    require_transfer_field("walletId", &transfer.wallet_id)?;
    require_transfer_field("enrollmentId", &transfer.enrollment_id)?;
    require_transfer_field("deviceId", &transfer.device_id)?;
    let recipient_public_key = decode_public_key(&transfer.recipient_public_key_b64u)?;

    let mut out = Vec::new();
    labeled(&mut out, b"context", TRANSFER_AAD_CONTEXT_V1);
    labeled(
        &mut out,
        b"transferAlg",
        LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1.as_bytes(),
    );
    labeled(&mut out, b"walletId", transfer.wallet_id.as_bytes());
    labeled(&mut out, b"enrollmentId", transfer.enrollment_id.as_bytes());
    labeled(&mut out, b"deviceId", transfer.device_id.as_bytes());
    labeled(&mut out, b"recipientPublicKey", &recipient_public_key);
    labeled(
        &mut out,
        b"custodySecretKind",
        transfer.binding.kind().as_str().as_bytes(),
    );
    // The custody binding is what Device 2's reseal must preserve verbatim, so
    // it is authenticated field-for-field rather than by digest: a transfer
    // cannot hand over a seed described one way and reseal it another.
    let binding_json = serde_json::to_vec(&transfer.binding)
        .map_err(|_| SignerCoreError::invalid_input("custody binding is not serializable"))?;
    labeled(&mut out, b"custodyBinding", &binding_json);
    Ok(out)
}

fn derive_transfer_key_v1(
    shared_secret: &Zeroizing<[u8; 32]>,
    ephemeral_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    recipient_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    aad: &[u8],
) -> CoreResult<Zeroizing<[u8; PASSKEY_CUSTODY_KEY_LEN]>> {
    // Both public keys enter the KDF alongside the shared secret so the key is
    // bound to the exact pair, not just to the DH output.
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(&shared_secret[..]);
    ikm.extend_from_slice(ephemeral_public_key);
    ikm.extend_from_slice(recipient_public_key);
    let hkdf = Hkdf::<Sha256>::new(Some(TRANSFER_KEK_SALT_V1), &ikm[..]);
    let aad_digest = sha256_digest(aad);
    let mut key = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
    hkdf.expand_multi_info(&[TRANSFER_KEK_INFO_V1, &aad_digest], &mut key[..])
        .map_err(|_| {
            SignerCoreError::hkdf_error("linked-device custody transfer key derivation failed")
        })?;
    Ok(key)
}

fn diffie_hellman(
    scalar: &Scalar,
    public_key: &[u8; X25519_PUBLIC_KEY_LEN],
) -> CoreResult<Zeroizing<[u8; 32]>> {
    let shared = (MontgomeryPoint(*public_key) * scalar).to_bytes();
    // An all-zero output means a small-order peer key contributed nothing.
    if shared.iter().all(|byte| *byte == 0) {
        return Err(SignerCoreError::crypto_error(
            "linked-device custody transfer peer key is degenerate",
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&shared);
    Ok(out)
}

fn clamped_scalar(secret: &Zeroizing<[u8; 32]>) -> Scalar {
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&secret[..]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    Scalar::from_bytes_mod_order(clamped)
}

fn decode_public_key(value: &str) -> CoreResult<[u8; X25519_PUBLIC_KEY_LEN]> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| {
        SignerCoreError::invalid_input(
            "linked-device custody transfer public key must be unpadded base64url",
        )
    })?;
    require_public_key_bytes("linked-device custody transfer public key", &bytes)
}

fn require_public_key_bytes(label: &str, bytes: &[u8]) -> CoreResult<[u8; X25519_PUBLIC_KEY_LEN]> {
    if bytes.len() != X25519_PUBLIC_KEY_LEN {
        return Err(SignerCoreError::invalid_length(format!(
            "{label} must be {X25519_PUBLIC_KEY_LEN} bytes"
        )));
    }
    let mut out = [0u8; X25519_PUBLIC_KEY_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn require_transfer_nonce(nonce: &[u8]) -> CoreResult<[u8; PASSKEY_CUSTODY_NONCE_LEN]> {
    if nonce.len() != PASSKEY_CUSTODY_NONCE_LEN {
        return Err(SignerCoreError::invalid_length(format!(
            "linked-device custody transfer nonce must be {PASSKEY_CUSTODY_NONCE_LEN} bytes"
        )));
    }
    let mut out = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
    out.copy_from_slice(nonce);
    Ok(out)
}

fn require_transfer_field(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() || value.len() > MAX_TRANSFER_FIELD_LEN {
        return Err(SignerCoreError::invalid_input(format!(
            "linked-device custody transfer {label} is invalid"
        )));
    }
    Ok(())
}

fn labeled(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    out.extend_from_slice(&(label.len() as u32).to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
