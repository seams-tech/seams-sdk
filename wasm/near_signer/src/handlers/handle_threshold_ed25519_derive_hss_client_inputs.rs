use base64ct::{Base64UrlUnpadded, Encoding};
use log::debug;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeriveThresholdEd25519HssClientInputsRequest {
    #[wasm_bindgen(getter_with_clone, js_name = "applicationBindingDigestB64u")]
    pub application_binding_digest_b64u: String,
    #[wasm_bindgen(getter_with_clone, js_name = "participantIds")]
    pub participant_ids: Vec<u16>,
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
    #[wasm_bindgen(getter_with_clone, js_name = "applicationBindingDigestB64u")]
    pub application_binding_digest_b64u: String,
    #[wasm_bindgen(getter_with_clone, js_name = "participantIds")]
    pub participant_ids: Vec<u16>,
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
    let application_binding_digest_b64u =
        request.application_binding_digest_b64u.trim().to_string();
    if application_binding_digest_b64u.is_empty() {
        return Err("Missing applicationBindingDigestB64u".to_string());
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
        "[rust wasm]: derive threshold ed25519 HSS client inputs for application binding digest"
    );

    let application_binding_digest = decode_fixed_32(
        "applicationBindingDigestB64u",
        &application_binding_digest_b64u,
    )?;
    let prf_first = Base64UrlUnpadded::decode_vec(&prf_first_b64u)
        .map_err(|e| format!("Invalid prfFirstB64u: {e}"))?;
    let inputs = signer_core::near_ed25519_recovery::derive_ed25519_hss_client_inputs_v1(
        &prf_first,
        &signer_core::near_ed25519_recovery::Ed25519HssCanonicalContextV1 {
            application_binding_digest,
            participant_ids: request.participant_ids,
        },
    )
    .map_err(|e| e.to_string())?;

    Ok(DeriveThresholdEd25519HssClientInputsResult {
        application_binding_digest_b64u,
        participant_ids: inputs.context.participant_ids,
        context_binding_b64u: Base64UrlUnpadded::encode_string(&inputs.context_binding),
        y_client_b64u: Base64UrlUnpadded::encode_string(&inputs.y_client),
        tau_client_b64u: Base64UrlUnpadded::encode_string(&inputs.tau_client),
    })
}

fn decode_fixed_32(label: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|error| format!("Invalid {label}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must decode to 32 bytes"))
}
