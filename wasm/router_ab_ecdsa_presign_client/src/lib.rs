#![forbid(unsafe_code)]

use js_sys::{Array, Object, Reflect, Uint8Array};
use rand_core::OsRng;
use router_ab_ecdsa_presign::session::{
    derive_presign_pair_context, ClientPresignSession as FixedClientPresignSession,
    PresignSessionError, PresignSessionProgress,
};
use router_ab_ecdsa_presign::AdditiveKeyShare;
use router_ab_ecdsa_wire::{CompressedPointBytes, ScalarBytes};
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

fn js_error(code: &'static str, core_code: &'static str, message: String) -> JsValue {
    serde_wasm_bindgen::to_value(&ClientErrorWire {
        code,
        core_code,
        message,
    })
    .unwrap_or_else(error_serialization_failure)
}

fn js_invalid_input(message: impl core::fmt::Display) -> JsValue {
    js_error(
        "SIGNER_INVALID_INPUT",
        "InvalidInput",
        message.to_string(),
    )
}

fn js_presign_error(error: PresignSessionError) -> JsValue {
    js_error(
        "SIGNER_CRYPTO_ERROR",
        "CryptoError",
        error.to_string(),
    )
}

fn parse_scalar(bytes: &[u8]) -> Result<ScalarBytes, JsValue> {
    let fixed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| js_invalid_input("Client additive share must be 32 bytes"))?;
    Ok(ScalarBytes::new(fixed))
}

fn parse_point(bytes: &[u8]) -> Result<CompressedPointBytes, JsValue> {
    let fixed: [u8; 33] = bytes
        .try_into()
        .map_err(|_| js_invalid_input("group public key must be 33 bytes"))?;
    Ok(CompressedPointBytes::new(fixed))
}

fn progress_to_js(progress: PresignSessionProgress) -> Result<JsValue, JsValue> {
    let object = Object::new();
    Reflect::set(
        &object,
        &JsValue::from_str("stage"),
        &JsValue::from_str(progress.stage.as_str()),
    )?;
    Reflect::set(
        &object,
        &JsValue::from_str("event"),
        &JsValue::from_str(progress.event.as_str()),
    )?;
    let outgoing = Array::new();
    for message in progress.outgoing {
        outgoing.push(&Uint8Array::from(message.as_slice()));
    }
    Reflect::set(&object, &JsValue::from_str("outgoing"), &outgoing)?;
    Ok(object.into())
}

#[wasm_bindgen]
pub struct ClientPresignSession {
    inner: FixedClientPresignSession,
}

#[wasm_bindgen]
impl ClientPresignSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        mut client_additive_share32: Vec<u8>,
        group_public_key33: Vec<u8>,
        presign_session_id: String,
    ) -> Result<ClientPresignSession, JsValue> {
        let result = (|| {
            let wallet_public_key = parse_point(&group_public_key33)?;
            let context = derive_presign_pair_context(wallet_public_key, &presign_session_id)
                .map_err(js_presign_error)?;
            let key_share = AdditiveKeyShare::from_bytes(parse_scalar(&client_additive_share32)?)
                .map_err(|error| js_invalid_input(error.to_string()))?;
            let inner = FixedClientPresignSession::new(
                context,
                key_share,
                wallet_public_key,
                &mut OsRng,
            )
            .map_err(js_presign_error)?;
            Ok(Self { inner })
        })();
        client_additive_share32.zeroize();
        result
    }

    pub fn stage(&self) -> String {
        self.inner.stage().as_str().to_owned()
    }

    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        progress_to_js(self.inner.poll())
    }

    pub fn message(&mut self, message: Vec<u8>) -> Result<(), JsValue> {
        self.inner
            .message(&message, &mut OsRng)
            .map_err(js_presign_error)
    }

    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        self.inner.start_presign().map_err(js_presign_error)
    }

    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.take_presignature_97().map_err(js_presign_error)
    }
}

#[wasm_bindgen]
pub fn init_router_ab_ecdsa_presign_client() {}
