mod derivation;
mod errors;
mod presign;

use wasm_bindgen::prelude::*;

pub use presign::ThresholdEcdsaPresignSession;

#[wasm_bindgen]
pub fn init_router_ab_ecdsa_signing_worker() {}

#[wasm_bindgen]
pub fn router_ab_ecdsa_derivation_relayer_bootstrap(payload: JsValue) -> Result<JsValue, JsValue> {
    derivation::relayer_bootstrap(payload)
}

#[wasm_bindgen]
pub fn map_additive_share_to_threshold_signatures_share_2p(
    additive_share32: Vec<u8>,
    participant_id: u32,
) -> Result<Vec<u8>, JsValue> {
    signer_core::secp256k1::map_additive_share_to_threshold_signatures_share_2p(
        additive_share32.as_slice(),
        participant_id,
    )
    .map(|share| share.to_vec())
    .map_err(errors::js_core_err)
}
