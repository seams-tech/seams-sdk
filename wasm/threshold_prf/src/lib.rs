#![forbid(unsafe_code)]

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;
use sha2::{Digest, Sha256};
use threshold_prf::{
    derive_output_from_signing_root_share_wires, PrfContext, PrfPurpose, SigningRootShareWireV1,
    SuiteId,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519HssServerInputsOutput {
    context_binding_b64u: String,
    y_relayer_b64u: String,
    tau_relayer_b64u: String,
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn js_threshold_error(error: impl core::fmt::Display) -> JsValue {
    js_error(format!("threshold-prf error: {error}"))
}

fn validate_ascii_field<'a>(label: &str, value: &'a str) -> Result<&'a str, JsValue> {
    if value.is_empty() {
        return Err(js_error(format!("{label} must be non-empty")));
    }
    if !value.is_ascii() {
        return Err(js_error(format!("{label} must be ASCII-only")));
    }
    if value.len() > usize::from(u16::MAX) {
        return Err(js_error(format!("{label} exceeds u16 length encoding")));
    }
    Ok(value)
}

fn push_len16(out: &mut Vec<u8>, label: &str, value: &str) -> Result<(), JsValue> {
    let value = validate_ascii_field(label, value)?;
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_ecdsa_hss_context_v1(
    signing_root_id: &str,
    near_account_id: &str,
    key_purpose: &str,
    key_version: &str,
) -> Result<Vec<u8>, JsValue> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ecdsa-hss:context:v1");
    push_len16(&mut out, "scheme_id", "ecdsa-hss-v1")?;
    push_len16(&mut out, "curve", "secp256k1")?;
    push_len16(&mut out, "signing_root_id", signing_root_id)?;
    push_len16(&mut out, "near_account_id", near_account_id)?;
    push_len16(&mut out, "key_purpose", key_purpose)?;
    push_len16(&mut out, "key_version", key_version)?;
    out.push(2);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes());
    Ok(out)
}

fn validate_ed25519_field(label: &str, value: &str) -> Result<(), JsValue> {
    if value.is_empty() {
        return Err(js_error(format!("{label} must be non-empty")));
    }
    if value.trim() != value {
        return Err(js_error(format!(
            "{label} must not contain leading or trailing whitespace"
        )));
    }
    Ok(())
}

fn update_len32(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn ed25519_hss_context_binding_v1(
    signing_root_id: &str,
    account_id: &str,
    key_purpose: &str,
    key_version: &str,
    mut participant_ids: Vec<u16>,
    derivation_version: u32,
) -> Result<[u8; 32], JsValue> {
    validate_ed25519_field("signing_root_id", signing_root_id)?;
    validate_ed25519_field("account_id", account_id)?;
    validate_ed25519_field("key_purpose", key_purpose)?;
    validate_ed25519_field("key_version", key_version)?;

    participant_ids.retain(|value| *value > 0);
    participant_ids.sort_unstable();
    participant_ids.dedup();
    if participant_ids.len() < 2 {
        return Err(js_error(
            "participant_ids must contain at least two non-zero identifiers",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"succinct-garbling-proto/context-binding/v1");
    update_len32(&mut hasher, signing_root_id);
    update_len32(&mut hasher, account_id);
    update_len32(&mut hasher, key_purpose);
    update_len32(&mut hasher, key_version);
    hasher.update((participant_ids.len() as u32).to_be_bytes());
    for participant_id in participant_ids {
        hasher.update(participant_id.to_be_bytes());
    }
    hasher.update(derivation_version.to_be_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn decode_signing_root_share_wire(mut bytes: Vec<u8>) -> Result<SigningRootShareWireV1, JsValue> {
    let decoded = SigningRootShareWireV1::decode_slice(&bytes).map_err(js_threshold_error);
    bytes.zeroize();
    decoded
}

fn derive_hss_output(
    share_wire_i: Vec<u8>,
    share_wire_j: Vec<u8>,
    purpose: PrfPurpose,
    context_bytes: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let left = decode_signing_root_share_wire(share_wire_i)?;
    let right = decode_signing_root_share_wire(share_wire_j)?;
    derive_hss_output_from_wires(&[left, right], purpose, context_bytes)
}

fn derive_hss_output_from_wires(
    share_wires: &[SigningRootShareWireV1; 2],
    purpose: PrfPurpose,
    context_bytes: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let context = PrfContext::new(SuiteId::Ristretto255Sha512V1, purpose, context_bytes);
    let output = derive_output_from_signing_root_share_wires(share_wires, &context)
        .map_err(js_threshold_error)?;
    Ok(output.as_bytes().to_vec())
}

fn participant_ids_u16(participant_ids: Vec<u32>) -> Result<Vec<u16>, JsValue> {
    participant_ids
        .into_iter()
        .map(|value| {
            u16::try_from(value)
                .map_err(|_| js_error("participantIds must contain only u16 values"))
        })
        .collect()
}

#[wasm_bindgen]
pub fn init_threshold_prf() {
    // Reserved for future logger/metrics initialization.
}

#[wasm_bindgen]
pub fn threshold_prf_derive_ecdsa_hss_y_relayer(
    share_wire_i: Vec<u8>,
    share_wire_j: Vec<u8>,
    signing_root_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
) -> Result<Vec<u8>, JsValue> {
    let context_bytes = encode_ecdsa_hss_context_v1(
        &signing_root_id,
        &near_account_id,
        &key_purpose,
        &key_version,
    )?;
    derive_hss_output(
        share_wire_i,
        share_wire_j,
        PrfPurpose::EcdsaHssYRelayer,
        context_bytes,
    )
}

#[wasm_bindgen]
pub fn threshold_prf_derive_ed25519_hss_server_inputs(
    share_wire_i: Vec<u8>,
    share_wire_j: Vec<u8>,
    signing_root_id: String,
    account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u32>,
    derivation_version: u32,
) -> Result<JsValue, JsValue> {
    let binding = ed25519_hss_context_binding_v1(
        &signing_root_id,
        &account_id,
        &key_purpose,
        &key_version,
        participant_ids_u16(participant_ids)?,
        derivation_version,
    )?;
    let left = decode_signing_root_share_wire(share_wire_i)?;
    let right = decode_signing_root_share_wire(share_wire_j)?;
    let share_wires = [left, right];
    let y_relayer = derive_hss_output_from_wires(
        &share_wires,
        PrfPurpose::Ed25519HssYRelayer,
        binding.to_vec(),
    )?;
    let tau_relayer = derive_hss_output_from_wires(
        &share_wires,
        PrfPurpose::Ed25519HssTauRelayer,
        binding.to_vec(),
    )?;

    serde_wasm_bindgen::to_value(&Ed25519HssServerInputsOutput {
        context_binding_b64u: Base64UrlUnpadded::encode_string(&binding),
        y_relayer_b64u: Base64UrlUnpadded::encode_string(&y_relayer),
        tau_relayer_b64u: Base64UrlUnpadded::encode_string(&tau_relayer),
    })
    .map_err(|error| {
        js_error(format!(
            "failed to serialize ed25519-hss server inputs: {error}"
        ))
    })
}
