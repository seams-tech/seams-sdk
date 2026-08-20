//! Browser-worker boundary for passkey custody envelopes.
//!
//! Opened custody material never crosses back into JavaScript. Every operation
//! that produces a custody secret returns an opaque handle whose bytes only
//! Rust can read, which is what keeps the Refactor 100 invariant that
//! JavaScript, the app origin, Router, and persistence adapters never receive a
//! plaintext client root, holder share, PRF output, or KEK.
//!
//! Callers pass parsed envelope records as JSON. The AAD is recomputed inside
//! `signer_core` from those records, so a caller cannot supply an arbitrary AAD
//! blob and cannot bind ciphertext to facts the record does not carry.
//!
//! Scope: this module serves unlock — opening an existing envelope into a
//! handle on the recurring signing path. Custody *ceremonies* (registration and
//! recovery re-establishment) need the owner roots derived and the key manifest
//! verified, which requires protocol crates `near_signer` does not link, so
//! they live in the wallet custody ceremony module instead.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;
use signer_core::ed25519_yao_client_root_transfer::{
    open_ed25519_yao_client_root_from_linked_device_v1,
    seal_ed25519_yao_client_root_for_linked_device_v1,
    seal_ed25519_yao_client_root_under_factor_v1, Ed25519YaoClientRootFromLinkedDeviceTransferV1,
    Ed25519YaoClientRootTransferBindingV1, Ed25519YaoClientRootTransferRecipientV1,
};
use signer_core::passkey_custody::open_passkey_custody_secret_v1;
use signer_core::passkey_custody::{
    open_verified_passkey_custody_secret_v1, open_wallet_custody_seed_envelope_v1,
    reseal_wallet_custody_seed_under_new_factor_v1, seal_passkey_custody_secret_v1,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodySecretKind,
    WalletCustodySeedFromSealedEnvelopeV1, PASSKEY_CUSTODY_NONCE_LEN,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Largest custody secret this boundary will generate or accept.
const MAX_CUSTODY_SECRET_LEN: usize = 1024;

fn js_error(message: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

fn decode_b64u(value: &str, label: &str) -> Result<Vec<u8>, JsValue> {
    Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| js_error(format!("{label} must be unpadded base64url")))
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; 32], JsValue> {
    let bytes = decode_b64u(value, label)?;
    bytes
        .try_into()
        .map_err(|_| js_error(format!("{label} must decode to 32 bytes")))
}

/// How an admitted custody secret reached this handle.
///
/// The two proofs authorize different writes — an envelope open may reseal
/// locally, a linked-device transfer may reseal for the device it was
/// addressed to — so the handle holds exactly one and each reseal entry point
/// requires its own branch. An enum rather than two `Option`s keeps "admitted
/// twice, by different routes" unrepresentable.
enum WasmCustodyAdmissionV1 {
    SealedEnvelope(WalletCustodySeedFromSealedEnvelopeV1),
    Ed25519YaoClientRootTransfer(Ed25519YaoClientRootFromLinkedDeviceTransferV1),
}

/// An opened custody secret held in Rust memory.
///
/// There is deliberately no accessor for the bytes: JavaScript can learn the
/// secret's kind and length, hand the handle back into another custody
/// operation, or drop it. The bytes are zeroized when the handle is freed.
#[wasm_bindgen]
pub struct WasmPasskeyCustodyHandleV1 {
    secret: Zeroizing<Vec<u8>>,
    kind: PasskeyCustodySecretKind,
    /// Present only when this handle came through a verified envelope or an
    /// authenticated root transfer. The branch-specific proof authorizes the
    /// matching factor-seal operation and never crosses back into JavaScript.
    admitted: Option<WasmCustodyAdmissionV1>,
}

#[wasm_bindgen]
impl WasmPasskeyCustodyHandleV1 {
    /// The custody-secret branch this handle restores.
    pub fn kind(&self) -> String {
        self.kind.as_str().to_string()
    }

    /// Byte length of the held secret. Exposed for length assertions only; it
    /// reveals nothing about the secret's value.
    pub fn byte_length(&self) -> usize {
        self.secret.len()
    }

    /// Zeroizes the held secret immediately, before the handle is dropped.
    /// Callers use this at lock, page lifecycle termination, success, and
    /// failure rather than waiting for garbage collection.
    pub fn destroy(&mut self) {
        self.secret = Zeroizing::new(Vec::new());
        self.admitted = None;
    }

    /// Whether this handle may be resealed under another factor. False for a
    /// lane share, and false for a seed opened through the unverified path.
    pub fn can_add_factor(&self) -> bool {
        self.admitted.is_some()
    }
}

impl WasmPasskeyCustodyHandleV1 {
    fn new(secret: Zeroizing<Vec<u8>>, kind: PasskeyCustodySecretKind) -> Self {
        Self {
            secret,
            kind,
            admitted: None,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedEnvelopeWireV1 {
    sealed_custody_secret_b64u: String,
    aad_hash_b64u: String,
    ciphertext_digest_b64u: String,
}

fn parse_envelope_binding(binding_json: &str) -> Result<PasskeyCustodyEnvelopeBindingV1, JsValue> {
    serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(binding_json).map_err(js_error)
}

/// Generates a random custody secret inside Rust and returns it as a handle.
///
/// This is the only way a custody secret enters this boundary: JavaScript can
/// never supply plaintext custody material, so a caller cannot seal a root it
/// chose or observed.
#[wasm_bindgen]
pub fn passkey_custody_generate_secret_v1(
    custody_secret_kind: &str,
    byte_length: usize,
) -> Result<WasmPasskeyCustodyHandleV1, JsValue> {
    let kind = PasskeyCustodySecretKind::parse(custody_secret_kind).map_err(js_error)?;
    if !matches!(
        kind,
        PasskeyCustodySecretKind::Ed25519LaneHolderShare
            | PasskeyCustodySecretKind::EcdsaLaneHolderShare
    ) {
        return Err(js_error(
            "only lane-holder material may be generated through the generic custody operation",
        ));
    }
    if byte_length == 0 || byte_length > MAX_CUSTODY_SECRET_LEN {
        return Err(js_error("custody secret length is invalid"));
    }
    let mut secret = Zeroizing::new(vec![0u8; byte_length]);
    getrandom::getrandom(&mut secret[..])
        .map_err(|_| js_error("custody secret randomness is unavailable"))?;
    Ok(WasmPasskeyCustodyHandleV1::new(secret, kind))
}

/// Seals a held lane holder share under the KEK derived from `prf_first`.
///
/// A wallet custody seed is rejected: its envelope records the key manifest the
/// seed must reproduce, and only a ceremony that derived the owner roots can
/// have verified that. Seed envelopes are sealed in the ceremony module.
#[wasm_bindgen]
pub fn passkey_custody_seal_v1(
    passkey_prf_first: &[u8],
    envelope_binding_json: &str,
    nonce12: &[u8],
    handle: &WasmPasskeyCustodyHandleV1,
) -> Result<JsValue, JsValue> {
    let binding = parse_envelope_binding(envelope_binding_json)?;
    if !matches!(
        binding.binding.kind(),
        PasskeyCustodySecretKind::Ed25519LaneHolderShare
            | PasskeyCustodySecretKind::EcdsaLaneHolderShare
    ) {
        return Err(js_error(
            "wallet custody seeds and Ed25519 Yao Client roots use dedicated operations",
        ));
    }
    if binding.binding.kind() != handle.kind {
        return Err(js_error(
            "custody handle kind does not match the envelope binding",
        ));
    }
    let prf_first = Zeroizing::new(passkey_prf_first.to_vec());
    let sealed = seal_passkey_custody_secret_v1(&prf_first, &binding, nonce12, &handle.secret[..])
        .map_err(js_error)?;
    serde_wasm_bindgen::to_value(&SealedEnvelopeWireV1 {
        sealed_custody_secret_b64u: sealed.ciphertext_b64u(),
        aad_hash_b64u: sealed.aad_hash_b64u(),
        ciphertext_digest_b64u: sealed.ciphertext_digest_b64u(),
    })
    .map_err(js_error)
}

/// Opens an envelope into a handle. Prefer the verified variant for anything
/// read from a browser cache.
#[wasm_bindgen]
pub fn passkey_custody_open_v1(
    passkey_prf_first: &[u8],
    envelope_binding_json: &str,
    nonce12: &[u8],
    sealed_custody_secret_b64u: &str,
) -> Result<WasmPasskeyCustodyHandleV1, JsValue> {
    let binding = parse_envelope_binding(envelope_binding_json)?;
    if !matches!(
        binding.binding.kind(),
        PasskeyCustodySecretKind::Ed25519LaneHolderShare
            | PasskeyCustodySecretKind::EcdsaLaneHolderShare
    ) {
        return Err(js_error(
            "wallet custody seeds and Ed25519 Yao Client roots use dedicated operations",
        ));
    }
    let ciphertext = decode_b64u(sealed_custody_secret_b64u, "sealedCustodySecretB64u")?;
    let prf_first = Zeroizing::new(passkey_prf_first.to_vec());
    let opened = open_passkey_custody_secret_v1(&prf_first, &binding, nonce12, &ciphertext)
        .map_err(js_error)?;
    Ok(WasmPasskeyCustodyHandleV1::new(
        opened,
        binding.binding.kind(),
    ))
}

/// Opens a wallet custody seed envelope into a handle that can add a factor.
///
/// This is the second-factor enrolment path: a wallet with an Email OTP factor
/// gains a passkey, or the reverse. It needs no owner-root derivation and no
/// protocol crate, because the seed's key manifest was established when its
/// first envelope was written — opening authenticates the seed against that
/// manifest, and the reseal below may only carry the claim forward.
#[wasm_bindgen]
pub fn passkey_custody_open_wallet_seed_v1(
    factor_secret: &[u8],
    envelope_binding_json: &str,
    nonce12: &[u8],
    sealed_custody_secret_b64u: &str,
    aad_hash_b64u: &str,
    ciphertext_digest_b64u: &str,
) -> Result<WasmPasskeyCustodyHandleV1, JsValue> {
    let binding = parse_envelope_binding(envelope_binding_json)?;
    let ciphertext = decode_b64u(sealed_custody_secret_b64u, "sealedCustodySecretB64u")?;
    let expected_aad_hash = decode_digest(aad_hash_b64u, "aadHashB64u")?;
    let expected_ciphertext_digest = decode_digest(ciphertext_digest_b64u, "ciphertextDigestB64u")?;
    let factor_secret = Zeroizing::new(factor_secret.to_vec());
    let (secret, admitted) = open_wallet_custody_seed_envelope_v1(
        &factor_secret,
        &binding,
        nonce12,
        &ciphertext,
        &expected_aad_hash,
        &expected_ciphertext_digest,
    )
    .map_err(js_error)?;
    Ok(WasmPasskeyCustodyHandleV1 {
        secret,
        kind: PasskeyCustodySecretKind::WalletCustodySeed,
        admitted: Some(WasmCustodyAdmissionV1::SealedEnvelope(admitted)),
    })
}

/// Seals an admitted seed under a second factor.
///
/// The nonce is generated here rather than accepted, so a caller cannot reuse
/// one across two seals. Everything except the factor and the envelope id must
/// match the envelope the handle was opened from; `signer_core` enforces that,
/// so a reseal cannot move the seed to another wallet or relabel its keys.
#[wasm_bindgen]
pub fn passkey_custody_reseal_wallet_seed_v1(
    handle: &WasmPasskeyCustodyHandleV1,
    new_factor_secret: &[u8],
    new_envelope_binding_json: &str,
) -> Result<JsValue, JsValue> {
    let admitted = match handle.admitted.as_ref() {
        Some(WasmCustodyAdmissionV1::SealedEnvelope(admitted)) => admitted,
        Some(WasmCustodyAdmissionV1::Ed25519YaoClientRootTransfer(_)) => {
            return Err(js_error(
                "an Ed25519 Yao Client root reseals through its dedicated factor operation",
            ))
        }
        None => {
            return Err(js_error(
                "this handle was not opened from a verified wallet custody seed envelope",
            ))
        }
    };
    let binding = parse_envelope_binding(new_envelope_binding_json)?;
    let mut nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| js_error("envelope nonce randomness is unavailable"))?;
    let new_factor_secret = Zeroizing::new(new_factor_secret.to_vec());
    let sealed = reseal_wallet_custody_seed_under_new_factor_v1(
        &new_factor_secret,
        &binding,
        admitted,
        &nonce,
        &handle.secret[..],
    )
    .map_err(js_error)?;
    serde_wasm_bindgen::to_value(&ResealedEnvelopeWireV1 {
        nonce_b64u: Base64UrlUnpadded::encode_string(&nonce),
        sealed_custody_secret_b64u: sealed.ciphertext_b64u(),
        aad_hash_b64u: sealed.aad_hash_b64u(),
        ciphertext_digest_b64u: sealed.ciphertext_digest_b64u(),
    })
    .map_err(js_error)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResealedEnvelopeWireV1 {
    nonce_b64u: String,
    sealed_custody_secret_b64u: String,
    aad_hash_b64u: String,
    ciphertext_digest_b64u: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedEd25519YaoClientRootEnvelopeWireV1 {
    nonce_b64u: String,
    sealed_export_root_b64u: String,
    aad_hash_b64u: String,
    ciphertext_digest_b64u: String,
}

/// Opens an envelope only when the record's stored AAD hash and ciphertext
/// digest match what this binding and ciphertext actually produce. A cache row
/// that drifted from the server revision fails here instead of decrypting into
/// stale material.
#[wasm_bindgen]
pub fn passkey_custody_open_verified_v1(
    passkey_prf_first: &[u8],
    envelope_binding_json: &str,
    nonce12: &[u8],
    sealed_custody_secret_b64u: &str,
    aad_hash_b64u: &str,
    ciphertext_digest_b64u: &str,
) -> Result<WasmPasskeyCustodyHandleV1, JsValue> {
    let binding = parse_envelope_binding(envelope_binding_json)?;
    if !matches!(
        binding.binding.kind(),
        PasskeyCustodySecretKind::Ed25519LaneHolderShare
            | PasskeyCustodySecretKind::EcdsaLaneHolderShare
    ) {
        return Err(js_error(
            "wallet custody seeds and Ed25519 Yao Client roots use dedicated operations",
        ));
    }
    let ciphertext = decode_b64u(sealed_custody_secret_b64u, "sealedCustodySecretB64u")?;
    let expected_aad_hash = decode_digest(aad_hash_b64u, "aadHashB64u")?;
    let expected_ciphertext_digest = decode_digest(ciphertext_digest_b64u, "ciphertextDigestB64u")?;
    let prf_first = Zeroizing::new(passkey_prf_first.to_vec());
    let opened = open_verified_passkey_custody_secret_v1(
        &prf_first,
        &binding,
        nonce12,
        &ciphertext,
        &expected_aad_hash,
        &expected_ciphertext_digest,
    )
    .map_err(js_error)?;
    Ok(WasmPasskeyCustodyHandleV1::new(
        opened,
        binding.binding.kind(),
    ))
}

/// Device 2's one-use X25519 recipient for an Ed25519 Yao Client root.
///
/// The private key remains in this WASM object. JavaScript receives only the
/// public routing key and an opaque handle id managed by its worker.
#[wasm_bindgen]
pub struct WasmEd25519YaoClientRootTransferRecipientV1 {
    inner: Option<Ed25519YaoClientRootTransferRecipientV1>,
    public_key: [u8; 32],
}

#[wasm_bindgen]
impl WasmEd25519YaoClientRootTransferRecipientV1 {
    /// Returns the public X25519 recipient key.
    pub fn public_key_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.public_key)
    }
}

/// Generates Device 2's one-use root recipient inside WASM.
#[wasm_bindgen]
pub fn ed25519_yao_client_root_transfer_recipient_v1(
) -> Result<WasmEd25519YaoClientRootTransferRecipientV1, JsValue> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut secret[..])
        .map_err(|_| js_error("Ed25519 Yao Client-root transfer randomness is unavailable"))?;
    let inner = Ed25519YaoClientRootTransferRecipientV1::from_secret_bytes(&secret[..])
        .map_err(js_error)?;
    Ok(WasmEd25519YaoClientRootTransferRecipientV1 {
        public_key: inner.public_key(),
        inner: Some(inner),
    })
}

/// Device 1 derives and seals only the Ed25519 Yao Client root.
///
/// The input handle must have been opened from a verified local wallet custody
/// envelope. The wallet seed is read only inside this WASM call; the returned
/// value contains ciphertext and public binding facts only.
#[wasm_bindgen]
pub fn passkey_custody_seal_ed25519_yao_client_root_for_linked_device_v1(
    handle: &WasmPasskeyCustodyHandleV1,
    transfer_binding_json: &str,
) -> Result<JsValue, JsValue> {
    let admitted = match handle.admitted.as_ref() {
        Some(WasmCustodyAdmissionV1::SealedEnvelope(admitted)) => admitted,
        Some(WasmCustodyAdmissionV1::Ed25519YaoClientRootTransfer(_)) => {
            return Err(js_error(
                "an Ed25519 Yao Client root cannot be forwarded to another device",
            ))
        }
        None => {
            return Err(js_error(
                "this handle was not opened from a verified wallet custody seed envelope",
            ))
        }
    };
    let transfer = parse_root_transfer_binding(transfer_binding_json)?;
    let mut ephemeral_secret = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut ephemeral_secret[..])
        .map_err(|_| js_error("Ed25519 Yao Client-root transfer randomness is unavailable"))?;
    let mut nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| {
        js_error("Ed25519 Yao Client-root transfer nonce randomness is unavailable")
    })?;
    let sealed = seal_ed25519_yao_client_root_for_linked_device_v1(
        admitted,
        &handle.secret[..],
        &transfer,
        &ephemeral_secret[..],
        &nonce,
    )
    .map_err(js_error)?;
    serde_wasm_bindgen::to_value(&Ed25519YaoClientRootTransferWireV1 {
        ephemeral_public_key_b64u: sealed.ephemeral_public_key_b64u(),
        nonce_b64u: sealed.nonce_b64u(),
        sealed_export_root_b64u: sealed.ciphertext_b64u(),
        binding_digest_b64u: sealed.binding_digest_b64u(),
        ciphertext_digest_b64u: sealed.ciphertext_digest_b64u(),
    })
    .map_err(js_error)
}

/// Device 2 opens one root package addressed to its one-use recipient.
#[wasm_bindgen]
pub fn passkey_custody_open_ed25519_yao_client_root_from_linked_device_v1(
    recipient: &mut WasmEd25519YaoClientRootTransferRecipientV1,
    transfer_binding_json: &str,
    ephemeral_public_key_b64u: &str,
    nonce12: &[u8],
    sealed_export_root_b64u: &str,
    binding_digest_b64u: &str,
    ciphertext_digest_b64u: &str,
) -> Result<WasmPasskeyCustodyHandleV1, JsValue> {
    let recipient_inner = recipient.inner.take().ok_or_else(|| {
        js_error("Ed25519 Yao Client-root transfer recipient was already consumed")
    })?;
    let transfer = parse_root_transfer_binding(transfer_binding_json)?;
    let ephemeral_public_key = decode_b64u(ephemeral_public_key_b64u, "ephemeralPublicKeyB64u")?;
    let ciphertext = decode_b64u(sealed_export_root_b64u, "sealedExportRootB64u")?;
    let expected_binding_digest = decode_digest(binding_digest_b64u, "bindingDigestB64u")?;
    let expected_ciphertext_digest = decode_digest(ciphertext_digest_b64u, "ciphertextDigestB64u")?;
    let (root, admitted) = open_ed25519_yao_client_root_from_linked_device_v1(
        recipient_inner,
        &transfer,
        &ephemeral_public_key,
        nonce12,
        &ciphertext,
        &expected_binding_digest,
        &expected_ciphertext_digest,
    )
    .map_err(js_error)?;
    let root_bytes = Zeroizing::new(root.into_bytes());
    Ok(WasmPasskeyCustodyHandleV1 {
        secret: Zeroizing::new(root_bytes.to_vec()),
        kind: PasskeyCustodySecretKind::Ed25519YaoClientRoot,
        admitted: Some(WasmCustodyAdmissionV1::Ed25519YaoClientRootTransfer(
            admitted,
        )),
    })
}

/// Device 2 immediately factor-seals an opened Client root.
#[wasm_bindgen]
pub fn passkey_custody_seal_ed25519_yao_client_root_under_factor_v1(
    handle: &mut WasmPasskeyCustodyHandleV1,
    factor_secret: &[u8],
    envelope_binding_json: &str,
) -> Result<JsValue, JsValue> {
    let binding = parse_envelope_binding(envelope_binding_json)?;
    if handle.kind != PasskeyCustodySecretKind::Ed25519YaoClientRoot {
        return Err(js_error("custody handle is not an Ed25519 Yao Client root"));
    }
    let admitted = match handle.admitted.take() {
        Some(WasmCustodyAdmissionV1::Ed25519YaoClientRootTransfer(admitted)) => admitted,
        Some(WasmCustodyAdmissionV1::SealedEnvelope(_)) => {
            return Err(js_error(
                "a local wallet custody seed is not an Ed25519 Yao Client root",
            ))
        }
        None => {
            return Err(js_error(
                "this handle was not opened from an Ed25519 Yao Client-root transfer",
            ))
        }
    };
    let root_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        handle
            .secret
            .as_slice()
            .try_into()
            .map_err(|_| js_error("Ed25519 Yao Client root handle must contain 32 bytes"))?,
    );
    let root =
        signer_core::ed25519_yao_derivation::Ed25519YaoClientRootV1::from_secret_bytes(*root_bytes);
    handle.destroy();
    let mut nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| {
        js_error("Ed25519 Yao Client-root envelope nonce randomness is unavailable")
    })?;
    let factor_secret = Zeroizing::new(factor_secret.to_vec());
    let sealed = seal_ed25519_yao_client_root_under_factor_v1(
        &factor_secret,
        &binding,
        admitted,
        &root,
        &nonce,
    )
    .map_err(js_error)?;
    serde_wasm_bindgen::to_value(&SealedEd25519YaoClientRootEnvelopeWireV1 {
        nonce_b64u: Base64UrlUnpadded::encode_string(&nonce),
        sealed_export_root_b64u: sealed.ciphertext_b64u(),
        aad_hash_b64u: sealed.aad_hash_b64u(),
        ciphertext_digest_b64u: sealed.ciphertext_digest_b64u(),
    })
    .map_err(js_error)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519YaoClientRootTransferWireV1 {
    ephemeral_public_key_b64u: String,
    nonce_b64u: String,
    sealed_export_root_b64u: String,
    binding_digest_b64u: String,
    ciphertext_digest_b64u: String,
}

fn parse_root_transfer_binding(
    binding_json: &str,
) -> Result<Ed25519YaoClientRootTransferBindingV1, JsValue> {
    serde_json::from_str::<Ed25519YaoClientRootTransferBindingV1>(binding_json).map_err(js_error)
}

// The wallet recovery envelope set is deliberately absent from this module.
//
// Both of its flows are custody ceremonies: issuing a set requires a verified
// key manifest, and opening one is the first step of recovery re-establishment,
// which must verify the manifest before the recovered seed becomes a
// capability. `near_signer` links no protocol crate, so it cannot derive the
// owner roots a manifest check needs — a recovery open exported from here would
// be an unverified path to the seed. Those exports live in the wallet custody
// ceremony module, which links both protocols and completes the whole flow in
// one instance.
