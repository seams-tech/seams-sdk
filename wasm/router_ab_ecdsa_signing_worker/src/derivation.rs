use router_ab_ecdsa_derivation::{
    derive_relayer_share_for_client_public, public_transcript_digest,
    RouterAbEcdsaDerivationStableKeyContext, ServerEvalOperation,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::JsValue;

use crate::errors::{js_derivation_err, js_invalid_input};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
struct RelayerBootstrapInput {
    application_binding_digest: Vec<u8>,
    relayer_key_id: String,
    y_relayer32_le: Vec<u8>,
    client_public_key33: Vec<u8>,
    client_share_retry_counter: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayerBootstrapResult {
    context_binding32: Vec<u8>,
    relayer_share32: Vec<u8>,
    relayer_public_key33: Vec<u8>,
    group_public_key33: Vec<u8>,
    ethereum_address20: Vec<u8>,
    relayer_mapped_private_share32: Vec<u8>,
    relayer_share_retry_counter: u32,
    public_transcript_digest32: Vec<u8>,
}

pub fn relayer_bootstrap(payload: JsValue) -> Result<JsValue, JsValue> {
    let parsed: RelayerBootstrapInput =
        serde_wasm_bindgen::from_value(payload).map_err(js_invalid_input)?;
    if parsed.relayer_key_id.is_empty() || !parsed.relayer_key_id.is_ascii() {
        return Err(js_invalid_input("relayerKeyId must be non-empty ASCII"));
    }
    let context = RouterAbEcdsaDerivationStableKeyContext::new(fixed_32(
        parsed.application_binding_digest,
        "applicationBindingDigest",
    )?);
    let y_relayer32_le = fixed_32(parsed.y_relayer32_le, "yRelayer32Le")?;
    let client_public_key33 = fixed_33(parsed.client_public_key33, "clientPublicKey33")?;
    let (relayer_share, identity) = derive_relayer_share_for_client_public(
        &context,
        y_relayer32_le,
        &client_public_key33,
        parsed.client_share_retry_counter,
    )
    .map_err(js_derivation_err)?;
    let transcript = public_transcript_digest(ServerEvalOperation::SessionBootstrap, &identity)
        .map_err(js_derivation_err)?;
    serde_wasm_bindgen::to_value(&RelayerBootstrapResult {
        context_binding32: identity.context_binding32.to_vec(),
        relayer_share32: relayer_share.x_relayer32.to_vec(),
        relayer_public_key33: identity.relayer_public_key33.to_vec(),
        group_public_key33: identity.threshold_public_key33.to_vec(),
        ethereum_address20: identity.threshold_ethereum_address20.to_vec(),
        relayer_mapped_private_share32: relayer_share.mapped_relayer_share32.to_vec(),
        relayer_share_retry_counter: relayer_share.retry_counter,
        public_transcript_digest32: transcript.to_vec(),
    })
    .map_err(js_invalid_input)
}

fn fixed_32(bytes: Vec<u8>, field: &str) -> Result<[u8; 32], JsValue> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        js_invalid_input(format!("{field} must be 32 bytes (got {})", bytes.len()))
    })
}

fn fixed_33(bytes: Vec<u8>, field: &str) -> Result<[u8; 33], JsValue> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        js_invalid_input(format!("{field} must be 33 bytes (got {})", bytes.len()))
    })
}
