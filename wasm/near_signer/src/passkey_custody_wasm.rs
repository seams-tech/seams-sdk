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

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use signer_core::passkey_custody::open_passkey_custody_secret_v1;
use signer_core::passkey_custody::{
    open_verified_passkey_custody_secret_v1, seal_passkey_custody_secret_v1,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodyLaneScopeV1, PasskeyCustodySecretKind,
    PASSKEY_CUSTODY_KEY_LEN,
};
use signer_core::wallet_recovery_custody::{
    open_wallet_recovery_entry_v1, open_wallet_recovery_manifest_kek_v1,
    seal_wallet_recovery_entry_v1, seal_wallet_recovery_manifest_kek_v1, WalletRecoveryCodeScopeV1,
    WalletRecoveryEntryScopeV1,
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
    }
}

impl WasmPasskeyCustodyHandleV1 {
    fn new(secret: Zeroizing<Vec<u8>>, kind: PasskeyCustodySecretKind) -> Self {
        Self { secret, kind }
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

/// Seals a held custody secret under the passkey KEK derived from `prf_first`.
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

/// The manifest KEK for one wallet recovery envelope set, held in Rust memory.
/// As with custody handles, JavaScript never sees the key bytes.
#[wasm_bindgen]
pub struct WasmWalletRecoveryManifestKekV1 {
    manifest_kek: Zeroizing<[u8; PASSKEY_CUSTODY_KEY_LEN]>,
}

#[wasm_bindgen]
impl WasmWalletRecoveryManifestKekV1 {
    /// Zeroizes the manifest KEK immediately.
    pub fn destroy(&mut self) {
        self.manifest_kek = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletRecoveryCodeScopeWireV1 {
    wallet_id: String,
    recovery_key_id: String,
    key_manifest_digest_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletRecoveryEntryScopeWireV1 {
    wallet_id: String,
    wallet_key_id: String,
    lane_id: String,
    lane_share_epoch: String,
    custody_secret_kind: String,
    key_manifest_digest_b64u: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealedRecoveryWrapWireV1 {
    ciphertext_b64u: String,
    aad_hash_b64u: String,
}

fn parse_code_scope(scope_json: &str) -> Result<WalletRecoveryCodeScopeV1, JsValue> {
    let wire =
        serde_json::from_str::<WalletRecoveryCodeScopeWireV1>(scope_json).map_err(js_error)?;
    Ok(WalletRecoveryCodeScopeV1 {
        wallet_id: wire.wallet_id,
        recovery_key_id: wire.recovery_key_id,
        key_manifest_digest: decode_digest(
            &wire.key_manifest_digest_b64u,
            "keyManifestDigestB64u",
        )?,
    })
}

fn parse_entry_scope(scope_json: &str) -> Result<WalletRecoveryEntryScopeV1, JsValue> {
    let wire =
        serde_json::from_str::<WalletRecoveryEntryScopeWireV1>(scope_json).map_err(js_error)?;
    Ok(WalletRecoveryEntryScopeV1 {
        wallet_id: wire.wallet_id,
        lane: PasskeyCustodyLaneScopeV1 {
            wallet_key_id: wire.wallet_key_id,
            lane_id: wire.lane_id,
            lane_share_epoch: wire.lane_share_epoch,
        },
        custody_secret_kind: PasskeyCustodySecretKind::parse(&wire.custody_secret_kind)
            .map_err(js_error)?,
        key_manifest_digest: decode_digest(
            &wire.key_manifest_digest_b64u,
            "keyManifestDigestB64u",
        )?,
    })
}

/// Generates the random manifest KEK a recovery envelope set is built around.
#[wasm_bindgen]
pub fn wallet_recovery_generate_manifest_kek_v1() -> Result<WasmWalletRecoveryManifestKekV1, JsValue>
{
    let mut manifest_kek = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
    getrandom::getrandom(&mut manifest_kek[..])
        .map_err(|_| js_error("manifest KEK randomness is unavailable"))?;
    Ok(WasmWalletRecoveryManifestKekV1 { manifest_kek })
}

/// Wraps the manifest KEK under one recovery code.
#[wasm_bindgen]
pub fn wallet_recovery_seal_manifest_kek_v1(
    recovery_code_bytes: &[u8],
    code_scope_json: &str,
    nonce12: &[u8],
    manifest_kek: &WasmWalletRecoveryManifestKekV1,
) -> Result<JsValue, JsValue> {
    let scope = parse_code_scope(code_scope_json)?;
    let code_bytes = Zeroizing::new(recovery_code_bytes.to_vec());
    let sealed = seal_wallet_recovery_manifest_kek_v1(
        &code_bytes,
        &scope,
        nonce12,
        &manifest_kek.manifest_kek[..],
    )
    .map_err(js_error)?;
    serde_wasm_bindgen::to_value(&SealedRecoveryWrapWireV1 {
        ciphertext_b64u: sealed.ciphertext_b64u(),
        aad_hash_b64u: sealed.aad_hash_b64u(),
    })
    .map_err(js_error)
}

/// Opens the manifest KEK with one recovery code.
#[wasm_bindgen]
pub fn wallet_recovery_open_manifest_kek_v1(
    recovery_code_bytes: &[u8],
    code_scope_json: &str,
    nonce12: &[u8],
    wrapped_manifest_kek_b64u: &str,
) -> Result<WasmWalletRecoveryManifestKekV1, JsValue> {
    let scope = parse_code_scope(code_scope_json)?;
    let ciphertext = decode_b64u(wrapped_manifest_kek_b64u, "wrappedManifestKekB64u")?;
    let code_bytes = Zeroizing::new(recovery_code_bytes.to_vec());
    let manifest_kek =
        open_wallet_recovery_manifest_kek_v1(&code_bytes, &scope, nonce12, &ciphertext)
            .map_err(js_error)?;
    Ok(WasmWalletRecoveryManifestKekV1 { manifest_kek })
}

/// Wraps one custody secret under the manifest KEK for recovery.
#[wasm_bindgen]
pub fn wallet_recovery_seal_entry_v1(
    manifest_kek: &WasmWalletRecoveryManifestKekV1,
    entry_scope_json: &str,
    nonce12: &[u8],
    handle: &WasmPasskeyCustodyHandleV1,
) -> Result<JsValue, JsValue> {
    let scope = parse_entry_scope(entry_scope_json)?;
    if scope.custody_secret_kind != handle.kind {
        return Err(js_error(
            "custody handle kind does not match the recovery entry scope",
        ));
    }
    let sealed = seal_wallet_recovery_entry_v1(
        &manifest_kek.manifest_kek[..],
        &scope,
        nonce12,
        &handle.secret[..],
    )
    .map_err(js_error)?;
    serde_wasm_bindgen::to_value(&SealedRecoveryWrapWireV1 {
        ciphertext_b64u: sealed.ciphertext_b64u(),
        aad_hash_b64u: sealed.aad_hash_b64u(),
    })
    .map_err(js_error)
}

/// Opens one recovery entry into a custody handle.
#[wasm_bindgen]
pub fn wallet_recovery_open_entry_v1(
    manifest_kek: &WasmWalletRecoveryManifestKekV1,
    entry_scope_json: &str,
    nonce12: &[u8],
    wrapped_custody_secret_b64u: &str,
) -> Result<WasmPasskeyCustodyHandleV1, JsValue> {
    let scope = parse_entry_scope(entry_scope_json)?;
    let ciphertext = decode_b64u(wrapped_custody_secret_b64u, "wrappedCustodySecretB64u")?;
    let opened =
        open_wallet_recovery_entry_v1(&manifest_kek.manifest_kek[..], &scope, nonce12, &ciphertext)
            .map_err(js_error)?;
    Ok(WasmPasskeyCustodyHandleV1::new(
        opened,
        scope.custody_secret_kind,
    ))
}
