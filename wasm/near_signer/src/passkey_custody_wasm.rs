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

/// An opened custody secret held in Rust memory.
///
/// There is deliberately no accessor for the bytes: JavaScript can learn the
/// secret's kind and length, hand the handle back into another custody
/// operation, or drop it. The bytes are zeroized when the handle is freed.
#[wasm_bindgen]
pub struct WasmPasskeyCustodyHandleV1 {
    secret: Zeroizing<Vec<u8>>,
    kind: PasskeyCustodySecretKind,
    /// Present only when this handle came from opening a wallet custody seed
    /// envelope. It is what lets the seed be resealed under a second factor,
    /// and it never crosses back into JavaScript.
    admitted: Option<WalletCustodySeedFromSealedEnvelopeV1>,
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
        admitted: Some(admitted),
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
    let admitted = handle.admitted.as_ref().ok_or_else(|| {
        js_error("this handle was not opened from a verified wallet custody seed envelope")
    })?;
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
