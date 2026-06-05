use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::errors::js_core_err;

pub fn sign_secp256k1_recoverable(
    mut digest32: Vec<u8>,
    mut private_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let result = signer_core::secp256k1::sign_secp256k1_recoverable(
        digest32.as_slice(),
        private_key32.as_slice(),
    )
    .map_err(js_core_err);
    digest32.zeroize();
    private_key32.zeroize();
    result
}

pub fn verify_secp256k1_recoverable_signature_against_public_key_33(
    mut digest32: Vec<u8>,
    mut signature65: Vec<u8>,
    public_key33: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let result =
        signer_core::secp256k1::verify_secp256k1_recoverable_signature_against_public_key_33(
        digest32.as_slice(),
        signature65.as_slice(),
        public_key33.as_slice(),
    )
    .map_err(js_core_err);
    digest32.zeroize();
    signature65.zeroize();
    result
}
