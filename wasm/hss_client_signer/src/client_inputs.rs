use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeriveThresholdEd25519HssClientInputsArgs {
    pub org_id: String,
    pub near_account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub participant_ids: Vec<u16>,
    pub derivation_version: u32,
    pub prf_first_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveThresholdEd25519HssClientInputsOutput {
    pub org_id: String,
    pub near_account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub participant_ids: Vec<u16>,
    pub derivation_version: u32,
    pub context_binding_b64u: String,
    pub y_client_b64u: String,
    pub tau_client_b64u: String,
}

#[wasm_bindgen]
pub fn derive_threshold_ed25519_hss_client_inputs(args: JsValue) -> Result<JsValue, JsValue> {
    let args: DeriveThresholdEd25519HssClientInputsArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output =
        derive_threshold_ed25519_hss_client_inputs_impl(args).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS client inputs: {e}")))
}

fn derive_threshold_ed25519_hss_client_inputs_impl(
    args: DeriveThresholdEd25519HssClientInputsArgs,
) -> Result<DeriveThresholdEd25519HssClientInputsOutput, String> {
    let org_id = args.org_id.trim().to_string();
    if org_id.is_empty() {
        return Err("Missing orgId".to_string());
    }
    let near_account_id = args.near_account_id.trim().to_string();
    if near_account_id.is_empty() {
        return Err("Missing nearAccountId".to_string());
    }
    let key_purpose = args.key_purpose.trim().to_string();
    if key_purpose.is_empty() {
        return Err("Missing keyPurpose".to_string());
    }
    let key_version = args.key_version.trim().to_string();
    if key_version.is_empty() {
        return Err("Missing keyVersion".to_string());
    }
    let prf_first_b64u = args.prf_first_b64u.trim().to_string();
    if prf_first_b64u.is_empty() {
        return Err("Missing prfFirstB64u".to_string());
    }

    let prf_first = Base64UrlUnpadded::decode_vec(&prf_first_b64u)
        .map_err(|e| format!("Invalid prfFirstB64u: {e}"))?;
    let inputs = signer_platform_web::near_ed25519_recovery::derive_ed25519_hss_client_inputs_v1(
        &prf_first,
        &signer_platform_web::near_ed25519_recovery::Ed25519HssCanonicalContextV1 {
            org_id: org_id.clone(),
            account_id: near_account_id.clone(),
            key_purpose: key_purpose.clone(),
            key_version: key_version.clone(),
            participant_ids: args.participant_ids,
            derivation_version: args.derivation_version,
        },
    )
    .map_err(|e| e.to_string())?;

    Ok(DeriveThresholdEd25519HssClientInputsOutput {
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
