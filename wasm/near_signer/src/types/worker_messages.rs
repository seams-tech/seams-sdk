use crate::error::ParsePayloadError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WorkerRequestType {
    SignTransactionsWithActions = 0,
    SignNep413Message = 1,
    SignDelegateAction = 2,
    DeriveThresholdEd25519ClientVerifyingShare = 3,
}

impl TryFrom<u32> for WorkerRequestType {
    type Error = JsValue;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SignTransactionsWithActions),
            1 => Ok(Self::SignNep413Message),
            2 => Ok(Self::SignDelegateAction),
            3 => Ok(Self::DeriveThresholdEd25519ClientVerifyingShare),
            _ => Err(JsValue::from_str(&format!(
                "unsupported signer worker request type: {value}"
            ))),
        }
    }
}

impl WorkerRequestType {
    pub fn name(self) -> &'static str {
        worker_request_type_name(self)
    }
}

pub fn worker_request_type_name(request_type: WorkerRequestType) -> &'static str {
    match request_type {
        WorkerRequestType::SignTransactionsWithActions => "SIGN_TRANSACTIONS_WITH_ACTIONS",
        WorkerRequestType::SignNep413Message => "SIGN_NEP413_MESSAGE",
        WorkerRequestType::SignDelegateAction => "SIGN_DELEGATE_ACTION",
        WorkerRequestType::DeriveThresholdEd25519ClientVerifyingShare => {
            "DERIVE_THRESHOLD_ED25519_CLIENT_VERIFYING_SHARE"
        }
    }
}

pub fn parse_typed_payload<T: DeserializeOwned>(
    payload: &JsValue,
    request_type: WorkerRequestType,
) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(payload.clone())
        .map_err(|error| ParsePayloadError::new(request_type.name(), error).into())
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WorkerResponseType {
    SignTransactionsWithActionsSuccess = 0,
    SignNep413MessageSuccess = 1,
    SignDelegateActionSuccess = 2,
    SignTransactionsWithActionsFailure = 3,
    SignNep413MessageFailure = 4,
    SignDelegateActionFailure = 5,
    RegistrationProgress = 6,
    RegistrationComplete = 7,
    ExecuteActionsProgress = 8,
    ExecuteActionsComplete = 9,
    DeriveThresholdEd25519ClientVerifyingShareSuccess = 10,
    DeriveThresholdEd25519ClientVerifyingShareFailure = 11,
}

impl From<WorkerResponseType> for u32 {
    fn from(value: WorkerResponseType) -> Self {
        value as u32
    }
}

impl TryFrom<u32> for WorkerResponseType {
    type Error = JsValue;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SignTransactionsWithActionsSuccess),
            1 => Ok(Self::SignNep413MessageSuccess),
            2 => Ok(Self::SignDelegateActionSuccess),
            3 => Ok(Self::SignTransactionsWithActionsFailure),
            4 => Ok(Self::SignNep413MessageFailure),
            5 => Ok(Self::SignDelegateActionFailure),
            6 => Ok(Self::RegistrationProgress),
            7 => Ok(Self::RegistrationComplete),
            8 => Ok(Self::ExecuteActionsProgress),
            9 => Ok(Self::ExecuteActionsComplete),
            10 => Ok(Self::DeriveThresholdEd25519ClientVerifyingShareSuccess),
            11 => Ok(Self::DeriveThresholdEd25519ClientVerifyingShareFailure),
            _ => Err(JsValue::from_str(&format!(
                "unsupported signer worker response type: {value}"
            ))),
        }
    }
}

pub fn worker_response_type_name(response_type: WorkerResponseType) -> &'static str {
    match response_type {
        WorkerResponseType::SignTransactionsWithActionsSuccess => {
            "SIGN_TRANSACTIONS_WITH_ACTIONS_SUCCESS"
        }
        WorkerResponseType::SignNep413MessageSuccess => "SIGN_NEP413_MESSAGE_SUCCESS",
        WorkerResponseType::SignDelegateActionSuccess => "SIGN_DELEGATE_ACTION_SUCCESS",
        WorkerResponseType::SignTransactionsWithActionsFailure => {
            "SIGN_TRANSACTIONS_WITH_ACTIONS_FAILURE"
        }
        WorkerResponseType::SignNep413MessageFailure => "SIGN_NEP413_MESSAGE_FAILURE",
        WorkerResponseType::SignDelegateActionFailure => "SIGN_DELEGATE_ACTION_FAILURE",
        WorkerResponseType::RegistrationProgress => "REGISTRATION_PROGRESS",
        WorkerResponseType::RegistrationComplete => "REGISTRATION_COMPLETE",
        WorkerResponseType::ExecuteActionsProgress => "EXECUTE_ACTIONS_PROGRESS",
        WorkerResponseType::ExecuteActionsComplete => "EXECUTE_ACTIONS_COMPLETE",
        WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareSuccess => {
            "DERIVE_THRESHOLD_ED25519_CLIENT_VERIFYING_SHARE_SUCCESS"
        }
        WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareFailure => {
            "DERIVE_THRESHOLD_ED25519_CLIENT_VERIFYING_SHARE_FAILURE"
        }
    }
}

pub struct SignerWorkerMessage {
    pub request_type: WorkerRequestType,
    pub request_type_raw: u32,
    pub payload: JsValue,
}

pub fn parse_worker_request_envelope(
    message_value: JsValue,
) -> Result<SignerWorkerMessage, JsValue> {
    let message = if message_value.is_string() {
        let json = message_value.as_string().unwrap_or_default();
        js_sys::JSON::parse(&json).map_err(|error| {
            JsValue::from_str(&format!("failed to parse signer request: {error:?}"))
        })?
    } else {
        message_value
    };
    let request_type_value = js_sys::Reflect::get(&message, &JsValue::from_str("type"))
        .map_err(|error| JsValue::from_str(&format!("failed to read message.type: {error:?}")))?;
    let request_type_raw = request_type_value
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0 && value.fract() == 0.0)
        .ok_or_else(|| JsValue::from_str("message.type must be a non-negative integer"))?
        as u32;
    let request_type = WorkerRequestType::try_from(request_type_raw)?;
    let payload =
        js_sys::Reflect::get(&message, &JsValue::from_str("payload")).map_err(|error| {
            JsValue::from_str(&format!("failed to read message.payload: {error:?}"))
        })?;
    Ok(SignerWorkerMessage {
        request_type,
        request_type_raw,
        payload,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerWorkerResponse {
    #[serde(rename = "type")]
    pub response_type: u32,
    #[serde(with = "serde_wasm_bindgen::preserve")]
    pub payload: JsValue,
}
