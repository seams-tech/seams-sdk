use crate::js::{get_required_string, get_required_u16_vec, object, set_string, set_u16_vec};
use base64ct::{Base64UrlUnpadded, Encoding};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn derive_threshold_ed25519_hss_client_inputs(args: JsValue) -> Result<JsValue, JsValue> {
    let application_binding_digest_b64u =
        get_required_string(&args, "applicationBindingDigestB64u")?;
    let participant_ids = get_required_u16_vec(&args, "participantIds")?;
    let prf_first_b64u = get_required_string(&args, "prfFirstB64u")?;

    let application_binding_digest = decode_fixed_32(
        "applicationBindingDigestB64u",
        &application_binding_digest_b64u,
    )?;
    let prf_first = Base64UrlUnpadded::decode_vec(&prf_first_b64u)
        .map_err(|e| JsValue::from_str(&format!("Invalid prfFirstB64u: {e}")))?;
    let inputs = signer_core::near_ed25519_recovery::derive_ed25519_hss_client_inputs_v1(
        &prf_first,
        &signer_core::near_ed25519_recovery::Ed25519HssCanonicalContextV1 {
            application_binding_digest,
            participant_ids,
        },
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "applicationBindingDigestB64u",
        &application_binding_digest_b64u,
    )?;
    set_u16_vec(&out, "participantIds", &inputs.context.participant_ids)?;
    set_string(
        &out,
        "contextBindingB64u",
        &Base64UrlUnpadded::encode_string(&inputs.context_binding),
    )?;
    set_string(
        &out,
        "yClientB64u",
        &Base64UrlUnpadded::encode_string(&inputs.y_client),
    )?;
    set_string(
        &out,
        "tauClientB64u",
        &Base64UrlUnpadded::encode_string(&inputs.tau_client),
    )?;
    Ok(out.into())
}

fn decode_fixed_32(label: &str, value: &str) -> Result<[u8; 32], JsValue> {
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|error| JsValue::from_str(&format!("Invalid {label}: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must decode to 32 bytes")))
}
