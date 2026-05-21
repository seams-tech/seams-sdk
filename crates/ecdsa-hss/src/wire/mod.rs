use core::fmt;

use crate::shared::context::EcdsaHssStableKeyContextV1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEvalOperationV1 {
    RegistrationBootstrap,
    SessionBootstrap,
    NonExportSign,
    ExplicitKeyExport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedOutputKindV1 {
    ThresholdMaterialOnly,
    ThresholdMaterialAndRelayerExportShare,
}

impl ServerEvalOperationV1 {
    pub fn allowed_output_kind(self) -> AllowedOutputKindV1 {
        match self {
            ServerEvalOperationV1::ExplicitKeyExport => {
                AllowedOutputKindV1::ThresholdMaterialAndRelayerExportShare
            }
            ServerEvalOperationV1::RegistrationBootstrap
            | ServerEvalOperationV1::SessionBootstrap
            | ServerEvalOperationV1::NonExportSign => AllowedOutputKindV1::ThresholdMaterialOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareEnvelopeV1 {
    pub operation: ServerEvalOperationV1,
    pub context: EcdsaHssStableKeyContextV1,
    pub relayer_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdRespondRequestV1 {
    pub client_public_key33: [u8; 33],
    pub client_share_retry_counter: u32,
    pub expected_relayer_key_id: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExplicitExportAuthorizationV1 {
    pub wallet_session_user_id: String,
    pub ecdsa_threshold_key_id: String,
    pub client_device_id: String,
    pub client_session_id: String,
    pub relayer_key_id: String,
    pub export_request_nonce32: [u8; 32],
    pub confirmation_digest32: [u8; 32],
    pub authorization_digest32: [u8; 32],
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for ExplicitExportAuthorizationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExplicitExportAuthorizationV1")
            .field("wallet_session_user_id", &self.wallet_session_user_id)
            .field("ecdsa_threshold_key_id", &self.ecdsa_threshold_key_id)
            .field("client_device_id", &self.client_device_id)
            .field("client_session_id", &self.client_session_id)
            .field("relayer_key_id", &self.relayer_key_id)
            .field("export_request_nonce32", &"<redacted>")
            .field("confirmation_digest32", &self.confirmation_digest32)
            .field("authorization_digest32", &self.authorization_digest32)
            .field("issued_at_unix_ms", &self.issued_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitExportRespondRequestV1 {
    pub client_public_key33: [u8; 33],
    pub client_share_retry_counter: u32,
    pub authorization: ExplicitExportAuthorizationV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespondRequestV1 {
    Threshold(ThresholdRespondRequestV1),
    ExplicitExport(ExplicitExportRespondRequestV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeEnvelopeV1 {
    pub operation: ServerEvalOperationV1,
    pub raw_root_material_dropped: bool,
    pub relayer_key_id: String,
    pub context_binding32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}
