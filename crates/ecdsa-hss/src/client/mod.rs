use crate::wire::AllowedOutputKindV1;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NonExportClientOutputV1 {
    pub x_client32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ExplicitExportClientOutputV1 {
    pub canonical_x32: [u8; 32],
    pub canonical_public_key33: [u8; 33],
    pub canonical_ethereum_address20: [u8; 20],
    pub x_client32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ClientOutputV1 {
    NonExport(NonExportClientOutputV1),
    ExplicitExport(ExplicitExportClientOutputV1),
}

impl ClientOutputV1 {
    pub fn allowed_output_kind(&self) -> AllowedOutputKindV1 {
        match self {
            ClientOutputV1::NonExport(_) => AllowedOutputKindV1::ThresholdMaterialOnly,
            ClientOutputV1::ExplicitExport(_) => {
                AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret
            }
        }
    }
}
