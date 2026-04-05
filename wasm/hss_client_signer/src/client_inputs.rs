use crate::js::{
    get_required_string, get_required_u16_vec, get_required_u32, object, set_string, set_u16_vec,
    set_u32,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn derive_threshold_ed25519_hss_client_inputs(args: JsValue) -> Result<JsValue, JsValue> {
    let org_id = get_required_string(&args, "orgId")?;
    let near_account_id = get_required_string(&args, "nearAccountId")?;
    let key_purpose = get_required_string(&args, "keyPurpose")?;
    let key_version = get_required_string(&args, "keyVersion")?;
    let participant_ids = get_required_u16_vec(&args, "participantIds")?;
    let derivation_version = get_required_u32(&args, "derivationVersion")?;
    let prf_first_b64u = get_required_string(&args, "prfFirstB64u")?;

    let prf_first = Base64UrlUnpadded::decode_vec(&prf_first_b64u)
        .map_err(|e| JsValue::from_str(&format!("Invalid prfFirstB64u: {e}")))?;
    let inputs = signer_platform_web::near_ed25519_recovery::derive_ed25519_hss_client_inputs_v1(
        &prf_first,
        &signer_platform_web::near_ed25519_recovery::Ed25519HssCanonicalContextV1 {
            org_id: org_id.clone(),
            account_id: near_account_id.clone(),
            key_purpose: key_purpose.clone(),
            key_version: key_version.clone(),
            participant_ids,
            derivation_version,
        },
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(&out, "orgId", &org_id)?;
    set_string(&out, "nearAccountId", &near_account_id)?;
    set_string(&out, "keyPurpose", &key_purpose)?;
    set_string(&out, "keyVersion", &key_version)?;
    set_u16_vec(&out, "participantIds", &inputs.context.participant_ids)?;
    set_u32(&out, "derivationVersion", inputs.context.derivation_version)?;
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
