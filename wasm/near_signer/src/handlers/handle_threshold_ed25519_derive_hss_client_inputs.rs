use base64ct::{Base64UrlUnpadded, Encoding};
use log::debug;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeriveThresholdEd25519HssClientInputsRequest {
    #[wasm_bindgen(getter_with_clone, js_name = "signingRootId")]
    #[serde(rename = "signingRootId")]
    pub org_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "keyPurpose")]
    pub key_purpose: String,
    #[wasm_bindgen(getter_with_clone, js_name = "keyVersion")]
    pub key_version: String,
    #[wasm_bindgen(getter_with_clone, js_name = "participantIds")]
    pub participant_ids: Vec<u16>,
    #[wasm_bindgen(getter_with_clone, js_name = "derivationVersion")]
    pub derivation_version: u32,
    #[wasm_bindgen(getter_with_clone, js_name = "sessionId")]
    pub session_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "prfFirstB64u")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_first_b64u: Option<String>,
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveThresholdEd25519HssClientInputsResult {
    #[wasm_bindgen(getter_with_clone, js_name = "signingRootId")]
    #[serde(rename = "signingRootId")]
    pub org_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "keyPurpose")]
    pub key_purpose: String,
    #[wasm_bindgen(getter_with_clone, js_name = "keyVersion")]
    pub key_version: String,
    #[wasm_bindgen(getter_with_clone, js_name = "participantIds")]
    pub participant_ids: Vec<u16>,
    #[wasm_bindgen(getter_with_clone, js_name = "derivationVersion")]
    pub derivation_version: u32,
    #[wasm_bindgen(getter_with_clone, js_name = "contextBindingB64u")]
    pub context_binding_b64u: String,
    #[wasm_bindgen(getter_with_clone, js_name = "yClientB64u")]
    pub y_client_b64u: String,
    #[wasm_bindgen(getter_with_clone, js_name = "tauClientB64u")]
    pub tau_client_b64u: String,
}

pub async fn handle_threshold_ed25519_derive_hss_client_inputs(
    request: DeriveThresholdEd25519HssClientInputsRequest,
) -> Result<DeriveThresholdEd25519HssClientInputsResult, String> {
    let org_id = request.org_id.trim().to_string();
    if org_id.is_empty() {
        return Err("Missing signingRootId".to_string());
    }
    let near_account_id = request.near_account_id.trim().to_string();
    if near_account_id.is_empty() {
        return Err("Missing nearAccountId".to_string());
    }
    let key_purpose = request.key_purpose.trim().to_string();
    if key_purpose.is_empty() {
        return Err("Missing keyPurpose".to_string());
    }
    let key_version = request.key_version.trim().to_string();
    if key_version.is_empty() {
        return Err("Missing keyVersion".to_string());
    }
    let prf_first_b64u = request
        .prf_first_b64u
        .unwrap_or_default()
        .trim()
        .to_string();
    if prf_first_b64u.is_empty() {
        return Err("Missing prfFirstB64u".to_string());
    }

    debug!(
        "[rust wasm]: derive threshold ed25519 HSS client inputs for signing root {} account {} purpose {} version {}",
        org_id, near_account_id, key_purpose, key_version
    );

    let prf_first = Base64UrlUnpadded::decode_vec(&prf_first_b64u)
        .map_err(|e| format!("Invalid prfFirstB64u: {e}"))?;
    let inputs = signer_platform_web::near_ed25519_recovery::derive_ed25519_hss_client_inputs_v1(
        &prf_first,
        &signer_platform_web::near_ed25519_recovery::Ed25519HssCanonicalContextV1 {
            org_id: org_id.clone(),
            account_id: near_account_id.clone(),
            key_purpose: key_purpose.clone(),
            key_version: key_version.clone(),
            participant_ids: request.participant_ids,
            derivation_version: request.derivation_version,
        },
    )
    .map_err(|e| e.to_string())?;

    Ok(DeriveThresholdEd25519HssClientInputsResult {
        org_id,
        near_account_id,
        key_purpose,
        key_version,
        participant_ids: inputs.context.participant_ids,
        derivation_version: inputs.context.derivation_version,
        context_binding_b64u: Base64UrlUnpadded::encode_string(&inputs.context_binding),
        y_client_b64u: Base64UrlUnpadded::encode_string(&inputs.y_client),
        tau_client_b64u: Base64UrlUnpadded::encode_string(&inputs.tau_client),
    })
}
