#![forbid(unsafe_code)]

use js_sys::{Array, Object, Reflect, Uint8Array};
use serde::Serialize;
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientErrorWire {
    code: &'static str,
    core_code: &'static str,
    message: String,
}

fn error_code(code: SignerCoreErrorCode) -> (&'static str, &'static str) {
    match code {
        SignerCoreErrorCode::InvalidInput => ("SIGNER_INVALID_INPUT", "InvalidInput"),
        SignerCoreErrorCode::InvalidLength => ("SIGNER_INVALID_LENGTH", "InvalidLength"),
        SignerCoreErrorCode::DecodeError => ("SIGNER_DECODE_ERROR", "DecodeError"),
        SignerCoreErrorCode::EncodeError => ("SIGNER_ENCODE_ERROR", "EncodeError"),
        SignerCoreErrorCode::HkdfError => ("SIGNER_KDF_ERROR", "HkdfError"),
        SignerCoreErrorCode::CryptoError => ("SIGNER_CRYPTO_ERROR", "CryptoError"),
        SignerCoreErrorCode::Utf8Error => ("SIGNER_UTF8_ERROR", "Utf8Error"),
        SignerCoreErrorCode::Unsupported => ("SIGNER_UNSUPPORTED", "Unsupported"),
        SignerCoreErrorCode::Internal => ("SIGNER_INTERNAL", "Internal"),
    }
}

fn error_serialization_failure(_: serde_wasm_bindgen::Error) -> JsValue {
    JsValue::from_str("SIGNER_INTERNAL: failed to serialize error")
}

fn js_core_error(error: SignerCoreError) -> JsValue {
    let (code, core_code) = error_code(error.code);
    serde_wasm_bindgen::to_value(&ClientErrorWire {
        code,
        core_code,
        message: error.message,
    })
    .unwrap_or_else(error_serialization_failure)
}

fn progress_to_js(
    progress: signer_core::threshold_ecdsa::ThresholdEcdsaPresignProgress,
) -> Result<JsValue, JsValue> {
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
    inner: signer_core::threshold_ecdsa::ThresholdEcdsaPresignSession,
}

#[wasm_bindgen]
impl ClientPresignSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        participant_ids: Vec<u32>,
        client_participant_id: u32,
        threshold: u32,
        mut client_signing_share32: Vec<u8>,
        group_public_key33: Vec<u8>,
    ) -> Result<ClientPresignSession, JsValue> {
        let result = signer_core::threshold_ecdsa::ThresholdEcdsaPresignSession::new(
            participant_ids.as_slice(),
            client_participant_id,
            threshold,
            client_signing_share32.as_slice(),
            group_public_key33.as_slice(),
        );
        client_signing_share32.zeroize();
        Ok(Self {
            inner: result.map_err(js_core_error)?,
        })
    }

    pub fn stage(&self) -> String {
        self.inner.stage().to_owned()
    }

    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        progress_to_js(self.inner.poll().map_err(js_core_error)?)
    }

    pub fn message(
        &mut self,
        signing_worker_participant_id: u32,
        message: Vec<u8>,
    ) -> Result<(), JsValue> {
        self.inner
            .message(signing_worker_participant_id, message.as_slice())
            .map_err(js_core_error)
    }

    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        self.inner.start_presign().map_err(js_core_error)
    }

    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.take_presignature_97().map_err(js_core_error)
    }
}

#[wasm_bindgen]
pub fn init_router_ab_ecdsa_presign_client() {}

#[wasm_bindgen]
pub fn map_client_additive_share_2p(mut additive_share32: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let result = signer_core::secp256k1::map_additive_share_to_threshold_signatures_share_2p(
        additive_share32.as_slice(),
        1,
    );
    additive_share32.zeroize();
    result.map_err(js_core_error)
}
