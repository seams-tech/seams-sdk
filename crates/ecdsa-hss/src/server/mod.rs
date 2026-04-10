pub mod reference_boundary;

use signer_core::error::CoreResult;
use signer_core::error::SignerCoreError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::client::{ClientOutputV1, ExplicitExportClientOutputV1, NonExportClientOutputV1};
use crate::shared::context::EcdsaHssContextV1;
use crate::shared::derive::{
    derive_additive_shares_v1, derive_canonical_secret_v1, verify_single_key_invariant_v1,
};
use crate::wire::{
    AllowedOutputKindV1, FinalizeEnvelopeV1, PrepareEnvelopeV1, RespondRequestV1,
    RootShareInputsV1, ServerEvalOperationV1,
};

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ServerPrepareInputsV1 {
    #[zeroize(skip)]
    pub prepare: PrepareEnvelopeV1,
    pub y_relayer32_le: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FinalizedServerSessionV1 {
    #[zeroize(skip)]
    pub operation: ServerEvalOperationV1,
    #[zeroize(skip)]
    pub context: EcdsaHssContextV1,
    pub retained: RetainedServerStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RetainedServerStateV1 {
    pub raw_root_material_dropped: bool,
    pub relayer_threshold_share32: [u8; 32],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct StagedServerSessionV1 {
    #[zeroize(skip)]
    prepare: PrepareEnvelopeV1,
    y_relayer32_le: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RespondResponseV1 {
    pub client_output: ClientOutputV1,
    #[zeroize(skip)]
    pub finalize: FinalizeEnvelopeV1,
    pub finalized_server_session: FinalizedServerSessionV1,
}

impl StagedServerSessionV1 {
    pub fn prepare(inputs: ServerPrepareInputsV1) -> CoreResult<Self> {
        inputs.prepare.context.validate()?;
        Ok(Self {
            prepare: inputs.prepare.clone(),
            y_relayer32_le: inputs.y_relayer32_le,
        })
    }

    pub fn respond(self, request: &RespondRequestV1) -> CoreResult<RespondResponseV1> {
        let root_shares = RootShareInputsV1::new(request.y_client32_le, self.y_relayer32_le);
        let canonical = derive_canonical_secret_v1(&root_shares, &self.prepare.context)?;
        let additive_shares = derive_additive_shares_v1(&canonical.x32, &self.prepare.context)?;
        verify_single_key_invariant_v1(&canonical, &additive_shares)?;

        let client_output = match self.prepare.operation.allowed_output_kind() {
            AllowedOutputKindV1::ThresholdMaterialOnly => {
                ClientOutputV1::NonExport(NonExportClientOutputV1 {
                    x_client32: additive_shares.x_client32,
                    client_public_key33: additive_shares.client_public_key33,
                    threshold_public_key33: additive_shares.threshold_public_key33,
                    threshold_ethereum_address20: additive_shares.threshold_ethereum_address20,
                    retry_counter: additive_shares.retry_counter,
                })
            }
            AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret => {
                ClientOutputV1::ExplicitExport(ExplicitExportClientOutputV1 {
                    canonical_x32: canonical.x32,
                    canonical_public_key33: canonical.public_key33,
                    canonical_ethereum_address20: canonical.ethereum_address20,
                    x_client32: additive_shares.x_client32,
                    client_public_key33: additive_shares.client_public_key33,
                    threshold_public_key33: additive_shares.threshold_public_key33,
                    threshold_ethereum_address20: additive_shares.threshold_ethereum_address20,
                    retry_counter: additive_shares.retry_counter,
                })
            }
        };

        let finalized = FinalizedServerSessionV1 {
            operation: self.prepare.operation,
            context: self.prepare.context.clone(),
            retained: RetainedServerStateV1 {
                raw_root_material_dropped: true,
                relayer_threshold_share32: additive_shares.x_relayer32,
                relayer_public_key33: additive_shares.relayer_public_key33,
                threshold_public_key33: additive_shares.threshold_public_key33,
                threshold_ethereum_address20: additive_shares.threshold_ethereum_address20,
                retry_counter: additive_shares.retry_counter,
            },
        };

        let finalize = FinalizeEnvelopeV1 {
            operation: finalized.operation,
            raw_root_material_dropped: finalized.retained.raw_root_material_dropped,
            threshold_public_key33: finalized.retained.threshold_public_key33,
            threshold_ethereum_address20: finalized.retained.threshold_ethereum_address20,
            retry_counter: finalized.retained.retry_counter,
        };

        Ok(RespondResponseV1 {
            client_output,
            finalize,
            finalized_server_session: finalized,
        })
    }
}

impl FinalizedServerSessionV1 {
    pub fn validate_finalize_envelope(&self, finalize: &FinalizeEnvelopeV1) -> CoreResult<()> {
        if finalize.operation != self.operation {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope operation does not match staged server operation",
            ));
        }
        if !finalize.raw_root_material_dropped || !self.retained.raw_root_material_dropped {
            return Err(SignerCoreError::invalid_input(
                "finalize requires raw root material to be dropped",
            ));
        }
        if finalize.threshold_public_key33 != self.retained.threshold_public_key33 {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope threshold public key does not match retained server state",
            ));
        }
        if finalize.threshold_ethereum_address20 != self.retained.threshold_ethereum_address20 {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope threshold ethereum address does not match retained server state",
            ));
        }
        if finalize.retry_counter != self.retained.retry_counter {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope retry counter does not match retained server state",
            ));
        }
        Ok(())
    }
}
