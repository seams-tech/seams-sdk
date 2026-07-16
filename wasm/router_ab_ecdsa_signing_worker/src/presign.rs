use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::errors::js_core_err;

#[wasm_bindgen]
pub struct ThresholdEcdsaPresignSession {
    inner: signer_core::threshold_ecdsa::ThresholdEcdsaPresignSession,
}

#[wasm_bindgen]
impl ThresholdEcdsaPresignSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        participant_ids: Vec<u32>,
        me: u32,
        threshold: u32,
        mut private_share32: Vec<u8>,
        public_key_sec1: Vec<u8>,
    ) -> Result<ThresholdEcdsaPresignSession, JsValue> {
        let inner = signer_core::threshold_ecdsa::ThresholdEcdsaPresignSession::new(
            participant_ids.as_slice(),
            me,
            threshold,
            private_share32.as_slice(),
            public_key_sec1.as_slice(),
        );
        private_share32.zeroize();
        Ok(Self {
            inner: inner.map_err(js_core_err)?,
        })
    }

    #[wasm_bindgen]
    pub fn stage(&self) -> String {
        self.inner.stage().to_string()
    }

    #[wasm_bindgen]
    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        let progress = self.inner.poll().map_err(js_core_err)?;
        let result = Object::new();
        Reflect::set(
            &result,
            &JsValue::from_str("stage"),
            &JsValue::from_str(progress.stage.as_str()),
        )?;
        Reflect::set(
            &result,
            &JsValue::from_str("event"),
            &JsValue::from_str(progress.event.as_str()),
        )?;
        let outgoing = Array::new();
        for message in progress.outgoing {
            outgoing.push(&Uint8Array::from(message.as_slice()));
        }
        Reflect::set(&result, &JsValue::from_str("outgoing"), &outgoing)?;
        Ok(result.into())
    }

    #[wasm_bindgen]
    pub fn message(&mut self, from: u32, data: Vec<u8>) -> Result<(), JsValue> {
        self.inner
            .message(from, data.as_slice())
            .map_err(js_core_err)
    }

    #[wasm_bindgen]
    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        self.inner.start_presign().map_err(js_core_err)
    }

    #[wasm_bindgen]
    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.take_presignature_97().map_err(js_core_err)
    }
}
