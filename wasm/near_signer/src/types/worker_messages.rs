// === WORKER MESSAGES: REQUEST & RESPONSE TYPES ===
// Enums and message structures for worker communication.

use crate::error::ParsePayloadError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRequestType {
    SignTransactionsWithActions,
    SignNep413Message,
    SignDelegateAction,
    DeriveThresholdEd25519ClientVerifyingShare,
    DeriveThresholdEd25519HssClientInputs,
    PrepareThresholdEd25519HssSession,
    PrepareThresholdEd25519HssClientRequest,
    OpenThresholdEd25519HssClientOutput,
    OpenThresholdEd25519HssSeedOutput,
    BuildThresholdEd25519SeedExportArtifact,
    OpenThresholdEcdsaHssRoleLocalSigningShare,
    BuildThresholdEcdsaHssRoleLocalExportArtifact,
    BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact,
    DeriveThresholdEd25519HssClientOutputMask,
    PrepareThresholdEcdsaHssRoleLocalClientBootstrap,
    FinalizeThresholdEcdsaHssRoleLocalClientBootstrap,
    CreateThresholdEd25519RoleSeparatedNormalSigningClientShare,
    StoreThresholdEd25519WorkerMaterialFromHssOutput,
    RestoreThresholdEd25519WorkerMaterial,
    ValidateThresholdEd25519WorkerMaterial,
    CreateThresholdEd25519ClientPresignFromWorkerMaterial,
    SignThresholdEd25519ClientPresignFromWorkerMaterial,
    BurnThresholdEd25519WorkerMaterial,
    PutThresholdEd25519SealedWorkerMaterial,
    ReadThresholdEd25519SealedWorkerMaterial,
    DeleteThresholdEd25519SealedWorkerMaterial,
}

impl From<u32> for WorkerRequestType {
    fn from(value: u32) -> Self {
        match value {
            0 => WorkerRequestType::SignTransactionsWithActions,
            1 => WorkerRequestType::SignNep413Message,
            2 => WorkerRequestType::SignDelegateAction,
            3 => WorkerRequestType::DeriveThresholdEd25519ClientVerifyingShare,
            4 => WorkerRequestType::DeriveThresholdEd25519HssClientInputs,
            5 => WorkerRequestType::PrepareThresholdEd25519HssSession,
            6 => WorkerRequestType::PrepareThresholdEd25519HssClientRequest,
            7 => WorkerRequestType::OpenThresholdEd25519HssClientOutput,
            8 => WorkerRequestType::OpenThresholdEd25519HssSeedOutput,
            9 => WorkerRequestType::BuildThresholdEd25519SeedExportArtifact,
            10 => WorkerRequestType::OpenThresholdEcdsaHssRoleLocalSigningShare,
            11 => WorkerRequestType::BuildThresholdEcdsaHssRoleLocalExportArtifact,
            12 => WorkerRequestType::BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact,
            13 => WorkerRequestType::DeriveThresholdEd25519HssClientOutputMask,
            14 => WorkerRequestType::PrepareThresholdEcdsaHssRoleLocalClientBootstrap,
            15 => WorkerRequestType::FinalizeThresholdEcdsaHssRoleLocalClientBootstrap,
            16 => WorkerRequestType::CreateThresholdEd25519RoleSeparatedNormalSigningClientShare,
            17 => WorkerRequestType::StoreThresholdEd25519WorkerMaterialFromHssOutput,
            18 => WorkerRequestType::RestoreThresholdEd25519WorkerMaterial,
            19 => WorkerRequestType::ValidateThresholdEd25519WorkerMaterial,
            20 => WorkerRequestType::CreateThresholdEd25519ClientPresignFromWorkerMaterial,
            21 => WorkerRequestType::SignThresholdEd25519ClientPresignFromWorkerMaterial,
            22 => WorkerRequestType::BurnThresholdEd25519WorkerMaterial,
            23 => WorkerRequestType::PutThresholdEd25519SealedWorkerMaterial,
            24 => WorkerRequestType::ReadThresholdEd25519SealedWorkerMaterial,
            25 => WorkerRequestType::DeleteThresholdEd25519SealedWorkerMaterial,
            _ => panic!("Invalid WorkerRequestType value: {}", value),
        }
    }
}

impl WorkerRequestType {
    pub fn name(&self) -> &'static str {
        worker_request_type_name(*self)
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
        WorkerRequestType::DeriveThresholdEd25519HssClientInputs => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_INPUTS"
        }
        WorkerRequestType::PrepareThresholdEd25519HssSession => {
            "PREPARE_THRESHOLD_ED25519_HSS_SESSION"
        }
        WorkerRequestType::PrepareThresholdEd25519HssClientRequest => {
            "PREPARE_THRESHOLD_ED25519_HSS_CLIENT_REQUEST"
        }
        WorkerRequestType::OpenThresholdEd25519HssClientOutput => {
            "OPEN_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT"
        }
        WorkerRequestType::OpenThresholdEd25519HssSeedOutput => {
            "OPEN_THRESHOLD_ED25519_HSS_SEED_OUTPUT"
        }
        WorkerRequestType::BuildThresholdEd25519SeedExportArtifact => {
            "BUILD_THRESHOLD_ED25519_SEED_EXPORT_ARTIFACT"
        }
        WorkerRequestType::OpenThresholdEcdsaHssRoleLocalSigningShare => {
            "OPEN_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_SIGNING_SHARE"
        }
        WorkerRequestType::BuildThresholdEcdsaHssRoleLocalExportArtifact => {
            "BUILD_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_EXPORT_ARTIFACT"
        }
        WorkerRequestType::BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact => {
            "BUILD_THRESHOLD_ED25519_HSS_CLIENT_OWNED_STAGED_EVALUATOR_ARTIFACT"
        }
        WorkerRequestType::DeriveThresholdEd25519HssClientOutputMask => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT_MASK"
        }
        WorkerRequestType::PrepareThresholdEcdsaHssRoleLocalClientBootstrap => {
            "PREPARE_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_CLIENT_BOOTSTRAP"
        }
        WorkerRequestType::FinalizeThresholdEcdsaHssRoleLocalClientBootstrap => {
            "FINALIZE_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_CLIENT_BOOTSTRAP"
        }
        WorkerRequestType::CreateThresholdEd25519RoleSeparatedNormalSigningClientShare => {
            "CREATE_THRESHOLD_ED25519_ROLE_SEPARATED_NORMAL_SIGNING_CLIENT_SHARE"
        }
        WorkerRequestType::StoreThresholdEd25519WorkerMaterialFromHssOutput => {
            "STORE_THRESHOLD_ED25519_WORKER_MATERIAL_FROM_HSS_OUTPUT"
        }
        WorkerRequestType::RestoreThresholdEd25519WorkerMaterial => {
            "RESTORE_THRESHOLD_ED25519_WORKER_MATERIAL"
        }
        WorkerRequestType::ValidateThresholdEd25519WorkerMaterial => {
            "VALIDATE_THRESHOLD_ED25519_WORKER_MATERIAL"
        }
        WorkerRequestType::CreateThresholdEd25519ClientPresignFromWorkerMaterial => {
            "CREATE_THRESHOLD_ED25519_CLIENT_PRESIGN_FROM_WORKER_MATERIAL"
        }
        WorkerRequestType::SignThresholdEd25519ClientPresignFromWorkerMaterial => {
            "SIGN_THRESHOLD_ED25519_CLIENT_PRESIGN_FROM_WORKER_MATERIAL"
        }
        WorkerRequestType::BurnThresholdEd25519WorkerMaterial => {
            "BURN_THRESHOLD_ED25519_WORKER_MATERIAL"
        }
        WorkerRequestType::PutThresholdEd25519SealedWorkerMaterial => {
            "PUT_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL"
        }
        WorkerRequestType::ReadThresholdEd25519SealedWorkerMaterial => {
            "READ_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL"
        }
        WorkerRequestType::DeleteThresholdEd25519SealedWorkerMaterial => {
            "DELETE_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL"
        }
    }
}

pub fn parse_typed_payload<T: DeserializeOwned>(
    payload: &JsValue,
    request_type: WorkerRequestType,
) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(payload.clone())
        .map_err(|e| ParsePayloadError::new(request_type.name(), e).into())
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
    DeriveThresholdEd25519HssClientInputsSuccess = 12,
    DeriveThresholdEd25519HssClientInputsFailure = 13,
    PrepareThresholdEd25519HssSessionSuccess = 14,
    PrepareThresholdEd25519HssSessionFailure = 15,
    PrepareThresholdEd25519HssClientRequestSuccess = 16,
    PrepareThresholdEd25519HssClientRequestFailure = 17,
    OpenThresholdEd25519HssClientOutputSuccess = 18,
    OpenThresholdEd25519HssClientOutputFailure = 19,
    OpenThresholdEd25519HssSeedOutputSuccess = 20,
    OpenThresholdEd25519HssSeedOutputFailure = 21,
    BuildThresholdEd25519SeedExportArtifactSuccess = 22,
    BuildThresholdEd25519SeedExportArtifactFailure = 23,
    OpenThresholdEcdsaHssRoleLocalSigningShareSuccess = 24,
    OpenThresholdEcdsaHssRoleLocalSigningShareFailure = 25,
    BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess = 26,
    BuildThresholdEcdsaHssRoleLocalExportArtifactFailure = 27,
    BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess = 28,
    BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFailure = 29,
    DeriveThresholdEd25519HssClientOutputMaskSuccess = 30,
    DeriveThresholdEd25519HssClientOutputMaskFailure = 31,
    PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess = 32,
    PrepareThresholdEcdsaHssRoleLocalClientBootstrapFailure = 33,
    FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess = 34,
    FinalizeThresholdEcdsaHssRoleLocalClientBootstrapFailure = 35,
    CreateThresholdEd25519RoleSeparatedNormalSigningClientShareSuccess = 36,
    CreateThresholdEd25519RoleSeparatedNormalSigningClientShareFailure = 37,
    StoreThresholdEd25519WorkerMaterialFromHssOutputSuccess = 38,
    StoreThresholdEd25519WorkerMaterialFromHssOutputFailure = 39,
    RestoreThresholdEd25519WorkerMaterialSuccess = 40,
    RestoreThresholdEd25519WorkerMaterialFailure = 41,
    ValidateThresholdEd25519WorkerMaterialSuccess = 42,
    ValidateThresholdEd25519WorkerMaterialFailure = 43,
    CreateThresholdEd25519ClientPresignFromWorkerMaterialSuccess = 44,
    CreateThresholdEd25519ClientPresignFromWorkerMaterialFailure = 45,
    SignThresholdEd25519ClientPresignFromWorkerMaterialSuccess = 46,
    SignThresholdEd25519ClientPresignFromWorkerMaterialFailure = 47,
    BurnThresholdEd25519WorkerMaterialSuccess = 48,
    BurnThresholdEd25519WorkerMaterialFailure = 49,
    PutThresholdEd25519SealedWorkerMaterialSuccess = 50,
    PutThresholdEd25519SealedWorkerMaterialFailure = 51,
    ReadThresholdEd25519SealedWorkerMaterialSuccess = 52,
    ReadThresholdEd25519SealedWorkerMaterialFailure = 53,
    DeleteThresholdEd25519SealedWorkerMaterialSuccess = 54,
    DeleteThresholdEd25519SealedWorkerMaterialFailure = 55,
}

impl From<WorkerResponseType> for u32 {
    fn from(value: WorkerResponseType) -> Self {
        value as u32
    }
}

impl From<u32> for WorkerResponseType {
    fn from(value: u32) -> Self {
        match value {
            0 => WorkerResponseType::SignTransactionsWithActionsSuccess,
            1 => WorkerResponseType::SignNep413MessageSuccess,
            2 => WorkerResponseType::SignDelegateActionSuccess,
            3 => WorkerResponseType::SignTransactionsWithActionsFailure,
            4 => WorkerResponseType::SignNep413MessageFailure,
            5 => WorkerResponseType::SignDelegateActionFailure,
            6 => WorkerResponseType::RegistrationProgress,
            7 => WorkerResponseType::RegistrationComplete,
            8 => WorkerResponseType::ExecuteActionsProgress,
            9 => WorkerResponseType::ExecuteActionsComplete,
            10 => WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareSuccess,
            11 => WorkerResponseType::DeriveThresholdEd25519ClientVerifyingShareFailure,
            12 => WorkerResponseType::DeriveThresholdEd25519HssClientInputsSuccess,
            13 => WorkerResponseType::DeriveThresholdEd25519HssClientInputsFailure,
            14 => WorkerResponseType::PrepareThresholdEd25519HssSessionSuccess,
            15 => WorkerResponseType::PrepareThresholdEd25519HssSessionFailure,
            16 => WorkerResponseType::PrepareThresholdEd25519HssClientRequestSuccess,
            17 => WorkerResponseType::PrepareThresholdEd25519HssClientRequestFailure,
            18 => WorkerResponseType::OpenThresholdEd25519HssClientOutputSuccess,
            19 => WorkerResponseType::OpenThresholdEd25519HssClientOutputFailure,
            20 => WorkerResponseType::OpenThresholdEd25519HssSeedOutputSuccess,
            21 => WorkerResponseType::OpenThresholdEd25519HssSeedOutputFailure,
            22 => WorkerResponseType::BuildThresholdEd25519SeedExportArtifactSuccess,
            23 => WorkerResponseType::BuildThresholdEd25519SeedExportArtifactFailure,
            24 => WorkerResponseType::OpenThresholdEcdsaHssRoleLocalSigningShareSuccess,
            25 => WorkerResponseType::OpenThresholdEcdsaHssRoleLocalSigningShareFailure,
            26 => WorkerResponseType::BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess,
            27 => WorkerResponseType::BuildThresholdEcdsaHssRoleLocalExportArtifactFailure,
            28 => WorkerResponseType::BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess,
            29 => WorkerResponseType::BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFailure,
            30 => WorkerResponseType::DeriveThresholdEd25519HssClientOutputMaskSuccess,
            31 => WorkerResponseType::DeriveThresholdEd25519HssClientOutputMaskFailure,
            32 => WorkerResponseType::PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
            33 => WorkerResponseType::PrepareThresholdEcdsaHssRoleLocalClientBootstrapFailure,
            34 => WorkerResponseType::FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
            35 => WorkerResponseType::FinalizeThresholdEcdsaHssRoleLocalClientBootstrapFailure,
            36 => WorkerResponseType::CreateThresholdEd25519RoleSeparatedNormalSigningClientShareSuccess,
            37 => WorkerResponseType::CreateThresholdEd25519RoleSeparatedNormalSigningClientShareFailure,
            38 => WorkerResponseType::StoreThresholdEd25519WorkerMaterialFromHssOutputSuccess,
            39 => WorkerResponseType::StoreThresholdEd25519WorkerMaterialFromHssOutputFailure,
            40 => WorkerResponseType::RestoreThresholdEd25519WorkerMaterialSuccess,
            41 => WorkerResponseType::RestoreThresholdEd25519WorkerMaterialFailure,
            42 => WorkerResponseType::ValidateThresholdEd25519WorkerMaterialSuccess,
            43 => WorkerResponseType::ValidateThresholdEd25519WorkerMaterialFailure,
            44 => WorkerResponseType::CreateThresholdEd25519ClientPresignFromWorkerMaterialSuccess,
            45 => WorkerResponseType::CreateThresholdEd25519ClientPresignFromWorkerMaterialFailure,
            46 => WorkerResponseType::SignThresholdEd25519ClientPresignFromWorkerMaterialSuccess,
            47 => WorkerResponseType::SignThresholdEd25519ClientPresignFromWorkerMaterialFailure,
            48 => WorkerResponseType::BurnThresholdEd25519WorkerMaterialSuccess,
            49 => WorkerResponseType::BurnThresholdEd25519WorkerMaterialFailure,
            50 => WorkerResponseType::PutThresholdEd25519SealedWorkerMaterialSuccess,
            51 => WorkerResponseType::PutThresholdEd25519SealedWorkerMaterialFailure,
            52 => WorkerResponseType::ReadThresholdEd25519SealedWorkerMaterialSuccess,
            53 => WorkerResponseType::ReadThresholdEd25519SealedWorkerMaterialFailure,
            54 => WorkerResponseType::DeleteThresholdEd25519SealedWorkerMaterialSuccess,
            55 => WorkerResponseType::DeleteThresholdEd25519SealedWorkerMaterialFailure,
            _ => panic!("Invalid WorkerResponseType value: {}", value),
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
        WorkerResponseType::DeriveThresholdEd25519HssClientInputsSuccess => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_INPUTS_SUCCESS"
        }
        WorkerResponseType::DeriveThresholdEd25519HssClientInputsFailure => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_INPUTS_FAILURE"
        }
        WorkerResponseType::PrepareThresholdEd25519HssSessionSuccess => {
            "PREPARE_THRESHOLD_ED25519_HSS_SESSION_SUCCESS"
        }
        WorkerResponseType::PrepareThresholdEd25519HssSessionFailure => {
            "PREPARE_THRESHOLD_ED25519_HSS_SESSION_FAILURE"
        }
        WorkerResponseType::PrepareThresholdEd25519HssClientRequestSuccess => {
            "PREPARE_THRESHOLD_ED25519_HSS_CLIENT_REQUEST_SUCCESS"
        }
        WorkerResponseType::PrepareThresholdEd25519HssClientRequestFailure => {
            "PREPARE_THRESHOLD_ED25519_HSS_CLIENT_REQUEST_FAILURE"
        }
        WorkerResponseType::OpenThresholdEd25519HssClientOutputSuccess => {
            "OPEN_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT_SUCCESS"
        }
        WorkerResponseType::OpenThresholdEd25519HssClientOutputFailure => {
            "OPEN_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT_FAILURE"
        }
        WorkerResponseType::OpenThresholdEd25519HssSeedOutputSuccess => {
            "OPEN_THRESHOLD_ED25519_HSS_SEED_OUTPUT_SUCCESS"
        }
        WorkerResponseType::OpenThresholdEd25519HssSeedOutputFailure => {
            "OPEN_THRESHOLD_ED25519_HSS_SEED_OUTPUT_FAILURE"
        }
        WorkerResponseType::BuildThresholdEd25519SeedExportArtifactSuccess => {
            "BUILD_THRESHOLD_ED25519_SEED_EXPORT_ARTIFACT_SUCCESS"
        }
        WorkerResponseType::BuildThresholdEd25519SeedExportArtifactFailure => {
            "BUILD_THRESHOLD_ED25519_SEED_EXPORT_ARTIFACT_FAILURE"
        }
        WorkerResponseType::OpenThresholdEcdsaHssRoleLocalSigningShareSuccess => {
            "OPEN_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_SIGNING_SHARE_SUCCESS"
        }
        WorkerResponseType::OpenThresholdEcdsaHssRoleLocalSigningShareFailure => {
            "OPEN_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_SIGNING_SHARE_FAILURE"
        }
        WorkerResponseType::BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess => {
            "BUILD_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_EXPORT_ARTIFACT_SUCCESS"
        }
        WorkerResponseType::BuildThresholdEcdsaHssRoleLocalExportArtifactFailure => {
            "BUILD_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_EXPORT_ARTIFACT_FAILURE"
        }
        WorkerResponseType::BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess => {
            "BUILD_THRESHOLD_ED25519_HSS_CLIENT_OWNED_STAGED_EVALUATOR_ARTIFACT_SUCCESS"
        }
        WorkerResponseType::BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFailure => {
            "BUILD_THRESHOLD_ED25519_HSS_CLIENT_OWNED_STAGED_EVALUATOR_ARTIFACT_FAILURE"
        }
        WorkerResponseType::DeriveThresholdEd25519HssClientOutputMaskSuccess => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT_MASK_SUCCESS"
        }
        WorkerResponseType::DeriveThresholdEd25519HssClientOutputMaskFailure => {
            "DERIVE_THRESHOLD_ED25519_HSS_CLIENT_OUTPUT_MASK_FAILURE"
        }
        WorkerResponseType::PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess => {
            "PREPARE_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_CLIENT_BOOTSTRAP_SUCCESS"
        }
        WorkerResponseType::PrepareThresholdEcdsaHssRoleLocalClientBootstrapFailure => {
            "PREPARE_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_CLIENT_BOOTSTRAP_FAILURE"
        }
        WorkerResponseType::FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess => {
            "FINALIZE_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_CLIENT_BOOTSTRAP_SUCCESS"
        }
        WorkerResponseType::FinalizeThresholdEcdsaHssRoleLocalClientBootstrapFailure => {
            "FINALIZE_THRESHOLD_ECDSA_HSS_ROLE_LOCAL_CLIENT_BOOTSTRAP_FAILURE"
        }
        WorkerResponseType::CreateThresholdEd25519RoleSeparatedNormalSigningClientShareSuccess => {
            "CREATE_THRESHOLD_ED25519_ROLE_SEPARATED_NORMAL_SIGNING_CLIENT_SHARE_SUCCESS"
        }
        WorkerResponseType::CreateThresholdEd25519RoleSeparatedNormalSigningClientShareFailure => {
            "CREATE_THRESHOLD_ED25519_ROLE_SEPARATED_NORMAL_SIGNING_CLIENT_SHARE_FAILURE"
        }
        WorkerResponseType::StoreThresholdEd25519WorkerMaterialFromHssOutputSuccess => {
            "STORE_THRESHOLD_ED25519_WORKER_MATERIAL_FROM_HSS_OUTPUT_SUCCESS"
        }
        WorkerResponseType::StoreThresholdEd25519WorkerMaterialFromHssOutputFailure => {
            "STORE_THRESHOLD_ED25519_WORKER_MATERIAL_FROM_HSS_OUTPUT_FAILURE"
        }
        WorkerResponseType::RestoreThresholdEd25519WorkerMaterialSuccess => {
            "RESTORE_THRESHOLD_ED25519_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::RestoreThresholdEd25519WorkerMaterialFailure => {
            "RESTORE_THRESHOLD_ED25519_WORKER_MATERIAL_FAILURE"
        }
        WorkerResponseType::ValidateThresholdEd25519WorkerMaterialSuccess => {
            "VALIDATE_THRESHOLD_ED25519_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::ValidateThresholdEd25519WorkerMaterialFailure => {
            "VALIDATE_THRESHOLD_ED25519_WORKER_MATERIAL_FAILURE"
        }
        WorkerResponseType::CreateThresholdEd25519ClientPresignFromWorkerMaterialSuccess => {
            "CREATE_THRESHOLD_ED25519_CLIENT_PRESIGN_FROM_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::CreateThresholdEd25519ClientPresignFromWorkerMaterialFailure => {
            "CREATE_THRESHOLD_ED25519_CLIENT_PRESIGN_FROM_WORKER_MATERIAL_FAILURE"
        }
        WorkerResponseType::SignThresholdEd25519ClientPresignFromWorkerMaterialSuccess => {
            "SIGN_THRESHOLD_ED25519_CLIENT_PRESIGN_FROM_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::SignThresholdEd25519ClientPresignFromWorkerMaterialFailure => {
            "SIGN_THRESHOLD_ED25519_CLIENT_PRESIGN_FROM_WORKER_MATERIAL_FAILURE"
        }
        WorkerResponseType::BurnThresholdEd25519WorkerMaterialSuccess => {
            "BURN_THRESHOLD_ED25519_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::BurnThresholdEd25519WorkerMaterialFailure => {
            "BURN_THRESHOLD_ED25519_WORKER_MATERIAL_FAILURE"
        }
        WorkerResponseType::PutThresholdEd25519SealedWorkerMaterialSuccess => {
            "PUT_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::PutThresholdEd25519SealedWorkerMaterialFailure => {
            "PUT_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL_FAILURE"
        }
        WorkerResponseType::ReadThresholdEd25519SealedWorkerMaterialSuccess => {
            "READ_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::ReadThresholdEd25519SealedWorkerMaterialFailure => {
            "READ_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL_FAILURE"
        }
        WorkerResponseType::DeleteThresholdEd25519SealedWorkerMaterialSuccess => {
            "DELETE_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL_SUCCESS"
        }
        WorkerResponseType::DeleteThresholdEd25519SealedWorkerMaterialFailure => {
            "DELETE_THRESHOLD_ED25519_SEALED_WORKER_MATERIAL_FAILURE"
        }
    }
}

pub struct SignerWorkerMessage {
    pub request_type: WorkerRequestType,
    pub request_type_raw: u32,
    pub payload: JsValue,
}

pub fn parse_worker_request_envelope(message_val: JsValue) -> Result<SignerWorkerMessage, JsValue> {
    let message_obj = if message_val.is_string() {
        let json_str = message_val.as_string().unwrap_or_default();
        js_sys::JSON::parse(&json_str).map_err(|e| {
            JsValue::from_str(&format!("Failed to parse JSON string input: {:?}", e))
        })?
    } else {
        message_val
    };

    let msg_type_js = js_sys::Reflect::get(&message_obj, &JsValue::from_str("type"))
        .map_err(|e| JsValue::from_str(&format!("Failed to read message.type: {:?}", e)))?;
    let msg_type_num = msg_type_js
        .as_f64()
        .ok_or_else(|| JsValue::from_str("message.type must be a number"))?
        as u32;
    let request_type = WorkerRequestType::from(msg_type_num);

    let payload_js = js_sys::Reflect::get(&message_obj, &JsValue::from_str("payload"))
        .map_err(|e| JsValue::from_str(&format!("Failed to read message.payload: {:?}", e)))?;

    Ok(SignerWorkerMessage {
        request_type,
        request_type_raw: msg_type_num,
        payload: payload_js,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignerWorkerResponse {
    #[serde(rename = "type")]
    pub response_type: u32,
    #[serde(with = "serde_wasm_bindgen::preserve")]
    pub payload: JsValue,
}
