use crate::wire::AllowedOutputKindV1;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NonExportClientOutputV1 {
    pub client_public_key33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ExplicitExportClientOutputV1 {
    pub relayer_export_share32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}

impl fmt::Debug for ExplicitExportClientOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExplicitExportClientOutputV1")
            .field("relayer_export_share32", &"<redacted>")
            .field("client_public_key33", &self.client_public_key33)
            .field("relayer_public_key33", &self.relayer_public_key33)
            .field("threshold_public_key33", &self.threshold_public_key33)
            .field(
                "threshold_ethereum_address20",
                &self.threshold_ethereum_address20,
            )
            .field(
                "client_share_retry_counter",
                &self.client_share_retry_counter,
            )
            .field(
                "relayer_share_retry_counter",
                &self.relayer_share_retry_counter,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ClientOutputV1 {
    NonExport(NonExportClientOutputV1),
    ExplicitExport(ExplicitExportClientOutputV1),
}

impl fmt::Debug for ClientOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientOutputV1::NonExport(value) => f.debug_tuple("NonExport").field(value).finish(),
            ClientOutputV1::ExplicitExport(value) => {
                f.debug_tuple("ExplicitExport").field(value).finish()
            }
        }
    }
}

impl ClientOutputV1 {
    pub fn allowed_output_kind(&self) -> AllowedOutputKindV1 {
        match self {
            ClientOutputV1::NonExport(_) => AllowedOutputKindV1::ThresholdMaterialOnly,
            ClientOutputV1::ExplicitExport(_) => {
                AllowedOutputKindV1::ThresholdMaterialAndRelayerExportShare
            }
        }
    }
}
