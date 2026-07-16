use js_sys::{Array, Object, Reflect, Uint8Array};
use rand_core::OsRng;
use router_ab_ecdsa_presign::session::{
    derive_presign_pair_context, PresignSessionProgress,
    SigningWorkerPresignSession as FixedSigningWorkerPresignSession,
};
use router_ab_ecdsa_presign::AdditiveKeyShare;
use router_ab_ecdsa_wire::{CompressedPointBytes, ScalarBytes};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::errors::{js_invalid_input, js_presign_err};

fn parse_scalar(bytes: &[u8]) -> Result<ScalarBytes, JsValue> {
    let fixed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| js_invalid_input("SigningWorker additive share must be 32 bytes"))?;
    Ok(ScalarBytes::new(fixed))
}

fn parse_point(bytes: &[u8]) -> Result<CompressedPointBytes, JsValue> {
    let fixed: [u8; 33] = bytes
        .try_into()
        .map_err(|_| js_invalid_input("group public key must be 33 bytes"))?;
    Ok(CompressedPointBytes::new(fixed))
}

fn progress_to_js(progress: PresignSessionProgress) -> Result<JsValue, JsValue> {
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
pub struct SigningWorkerPresignSession {
    inner: FixedSigningWorkerPresignSession,
}

#[wasm_bindgen]
impl SigningWorkerPresignSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        mut private_share32: Vec<u8>,
        public_key_sec1: Vec<u8>,
        presign_session_id: String,
    ) -> Result<SigningWorkerPresignSession, JsValue> {
        let result = (|| {
            let wallet_public_key = parse_point(&public_key_sec1)?;
            let context = derive_presign_pair_context(wallet_public_key, &presign_session_id)
                .map_err(js_presign_err)?;
            let key_share = AdditiveKeyShare::from_bytes(parse_scalar(&private_share32)?)
                .map_err(js_invalid_input)?;
            let inner = FixedSigningWorkerPresignSession::new(
                context,
                key_share,
                wallet_public_key,
                &mut OsRng,
            )
            .map_err(js_presign_err)?;
            Ok(Self { inner })
        })();
        private_share32.zeroize();
        result
    }

    #[wasm_bindgen]
    pub fn stage(&self) -> String {
        self.inner.stage().as_str().to_owned()
    }

    #[wasm_bindgen]
    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        progress_to_js(self.inner.poll())
    }

    #[wasm_bindgen]
    pub fn message(&mut self, data: Vec<u8>) -> Result<(), JsValue> {
        self.inner
            .message(&data, &mut OsRng)
            .map_err(js_presign_err)
    }

    #[wasm_bindgen]
    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        self.inner.start_presign().map_err(js_presign_err)
    }

    #[wasm_bindgen]
    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.take_presignature_97().map_err(js_presign_err)
    }
}
