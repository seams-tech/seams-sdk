#![forbid(unsafe_code)]

use router_ab_ecdsa_online::{ClientPresignMaterial, OnlineClientInput, OnlineError};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientErrorWire {
    code: &'static str,
    core_code: &'static str,
    message: String,
}

fn error_serialization_failure(_: serde_wasm_bindgen::Error) -> JsValue {
    JsValue::from_str("SIGNER_INTERNAL: failed to serialize error")
}

fn js_online_error(error: OnlineError) -> JsValue {
    serde_wasm_bindgen::to_value(&ClientErrorWire {
        code: "SIGNER_CRYPTO_ERROR",
        core_code: "EcdsaOnlineClient",
        message: error.to_string(),
    })
    .unwrap_or_else(error_serialization_failure)
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn compute_client_signature_share(
    group_public_key33: Vec<u8>,
    presign_big_r33: Vec<u8>,
    expected_presign_big_r33: Vec<u8>,
    mut client_k_share32: Vec<u8>,
    mut client_sigma_share32: Vec<u8>,
    mut digest32: Vec<u8>,
    mut entropy32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let result = compute_client_signature_share_inner(
        &group_public_key33,
        &presign_big_r33,
        &expected_presign_big_r33,
        &client_k_share32,
        &client_sigma_share32,
        &digest32,
        &entropy32,
    )
    .map(array_to_vec)
    .map_err(js_online_error);
    client_k_share32.zeroize();
    client_sigma_share32.zeroize();
    digest32.zeroize();
    entropy32.zeroize();
    result
}

fn compute_client_signature_share_inner(
    group_public_key33: &[u8],
    presign_big_r33: &[u8],
    expected_presign_big_r33: &[u8],
    client_k_share32: &[u8],
    client_sigma_share32: &[u8],
    digest32: &[u8],
    entropy32: &[u8],
) -> Result<[u8; 32], OnlineError> {
    let material = ClientPresignMaterial::from_bytes(
        fixed_bytes::<33>(presign_big_r33, "presign_big_r33")?,
        fixed_bytes::<32>(client_k_share32, "client_k_share32")?,
        fixed_bytes::<32>(client_sigma_share32, "client_sigma_share32")?,
    )?;
    let input = OnlineClientInput::new(
        fixed_bytes::<33>(group_public_key33, "group_public_key33")?,
        fixed_bytes::<33>(expected_presign_big_r33, "expected_presign_big_r33")?,
        fixed_bytes::<32>(digest32, "digest32")?,
        fixed_bytes::<32>(entropy32, "entropy32")?,
    )?;
    let committed = material.reserve().commit(input)?;
    router_ab_ecdsa_online::compute_client_signature_share(committed)
}

fn array_to_vec(bytes: [u8; 32]) -> Vec<u8> {
    bytes.to_vec()
}

fn fixed_bytes<const N: usize>(bytes: &[u8], _: &str) -> Result<[u8; N], OnlineError> {
    bytes
        .try_into()
        .map_err(|_| OnlineError::NonCanonicalScalar)
}

#[wasm_bindgen]
pub fn init_router_ab_ecdsa_online_client() {}
