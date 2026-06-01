use ecdsa_hss::{
    derive_relayer_share_for_client_public, public_transcript_digest, EcdsaHssStableKeyContext,
    ServerEvalOperation,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::JsValue;

use crate::errors::{js_ecdsa_hss_err, js_invalid_input_err};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct EcdsaHssRoleLocalRelayerBootstrapInputJs {
    pub wallet_id: String,
    pub rp_id: String,
    pub ecdsa_threshold_key_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub key_purpose: String,
    pub key_version: String,
    pub relayer_key_id: String,
    pub y_relayer32_le: Vec<u8>,
    pub client_public_key33: Vec<u8>,
    pub client_share_retry_counter: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaHssRoleLocalRelayerBootstrapResultJs {
    pub context_binding32: Vec<u8>,
    pub relayer_share32: Vec<u8>,
    pub relayer_public_key33: Vec<u8>,
    pub group_public_key33: Vec<u8>,
    pub ethereum_address20: Vec<u8>,
    pub relayer_mapped_private_share32: Vec<u8>,
    pub relayer_share_retry_counter: u32,
    pub public_transcript_digest32: Vec<u8>,
}

pub fn threshold_ecdsa_hss_role_local_relayer_bootstrap(
    payload: JsValue,
) -> Result<JsValue, JsValue> {
    let parsed: EcdsaHssRoleLocalRelayerBootstrapInputJs =
        serde_wasm_bindgen::from_value(payload).map_err(|err| js_invalid_input_err(err))?;
    let context = EcdsaHssStableKeyContext::new(
        parsed.wallet_id,
        parsed.rp_id,
        parsed.ecdsa_threshold_key_id,
        parsed.signing_root_id,
        parsed.signing_root_version,
        parsed.key_purpose,
        parsed.key_version,
    );
    let y_relayer32_le = vec_to_fixed_32(parsed.y_relayer32_le, "yRelayer32Le")?;
    let client_public_key33 = vec_to_fixed_33(parsed.client_public_key33, "clientPublicKey33")?;
    validate_ascii_nonempty("relayerKeyId", &parsed.relayer_key_id)?;
    let (relayer_share, identity) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_public_key33,
        parsed.client_share_retry_counter,
    )
    .map_err(js_ecdsa_hss_err)?;
    let public_transcript_digest32 =
        public_transcript_digest(ServerEvalOperation::SessionBootstrap, &identity)
            .map_err(js_ecdsa_hss_err)?;
    serde_wasm_bindgen::to_value(&EcdsaHssRoleLocalRelayerBootstrapResultJs {
        context_binding32: identity.context_binding32.to_vec(),
        relayer_share32: relayer_share.x_relayer32.to_vec(),
        relayer_public_key33: identity.relayer_public_key33.to_vec(),
        group_public_key33: identity.threshold_public_key33.to_vec(),
        ethereum_address20: identity.threshold_ethereum_address20.to_vec(),
        relayer_mapped_private_share32: relayer_share.mapped_relayer_share32.to_vec(),
        relayer_share_retry_counter: relayer_share.retry_counter,
        public_transcript_digest32: public_transcript_digest32.to_vec(),
    })
    .map_err(|err| js_invalid_input_err(err))
}

fn vec_to_fixed_32(bytes: Vec<u8>, field_name: &str) -> Result<[u8; 32], JsValue> {
    if bytes.len() != 32 {
        return Err(js_invalid_input_err(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    bytes
        .try_into()
        .map_err(|_| js_invalid_input_err(format!("{field_name} must be exactly 32 bytes")))
}

fn vec_to_fixed_33(bytes: Vec<u8>, field_name: &str) -> Result<[u8; 33], JsValue> {
    if bytes.len() != 33 {
        return Err(js_invalid_input_err(format!(
            "{field_name} must be 33 bytes (got {})",
            bytes.len()
        )));
    }
    bytes
        .try_into()
        .map_err(|_| js_invalid_input_err(format!("{field_name} must be exactly 33 bytes")))
}

fn validate_ascii_nonempty(field_name: &str, value: &str) -> Result<(), JsValue> {
    if value.is_empty() {
        return Err(js_invalid_input_err(format!(
            "{field_name} must be non-empty"
        )));
    }
    if !value.is_ascii() {
        return Err(js_invalid_input_err(format!(
            "{field_name} must be ASCII-only"
        )));
    }
    Ok(())
}
