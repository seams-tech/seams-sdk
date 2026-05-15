use crate::shared::context::EcdsaHssStableKeyContextV1;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    ThresholdMaterialAndCanonicalSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RootShareInputsV1 {
    pub y_client32_le: [u8; 32],
    pub y_relayer32_le: [u8; 32],
}

impl RootShareInputsV1 {
    pub fn new(y_client32_le: [u8; 32], y_relayer32_le: [u8; 32]) -> Self {
        Self {
            y_client32_le,
            y_relayer32_le,
        }
    }
}

impl ServerEvalOperationV1 {
    pub fn allowed_output_kind(self) -> AllowedOutputKindV1 {
        match self {
            ServerEvalOperationV1::ExplicitKeyExport => {
                AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret
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
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RespondRequestV1 {
    pub y_client32_le: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizeEnvelopeV1 {
    pub operation: ServerEvalOperationV1,
    pub raw_root_material_dropped: bool,
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}
