mod derivation;
mod errors;
mod presign;

use wasm_bindgen::prelude::*;

pub use presign::SigningWorkerPresignSession;

#[wasm_bindgen]
pub fn init_router_ab_ecdsa_signing_worker() {}

#[wasm_bindgen]
pub fn router_ab_ecdsa_derivation_relayer_bootstrap(payload: JsValue) -> Result<JsValue, JsValue> {
    derivation::relayer_bootstrap(payload)
}
