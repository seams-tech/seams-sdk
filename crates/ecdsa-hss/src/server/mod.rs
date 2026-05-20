use std::collections::HashSet;

use signer_core::error::CoreResult;
use signer_core::error::SignerCoreError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::client::{ClientOutputV1, ExplicitExportClientOutputV1, NonExportClientOutputV1};
use crate::shared::context::EcdsaHssStableKeyContextV1;
use crate::shared::derive::{
    derive_relayer_share_for_client_public_v1, export_authorization_digest_v1, PublicIdentityV1,
};
use crate::wire::{
    ExplicitExportAuthorizationV1, ExplicitExportRespondRequestV1, FinalizeEnvelopeV1,
    PrepareEnvelopeV1, RespondRequestV1, ServerEvalOperationV1, ThresholdRespondRequestV1,
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
    pub context: EcdsaHssStableKeyContextV1,
    pub retained: RetainedServerStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RetainedServerStateV1 {
    pub raw_root_material_dropped: bool,
    #[zeroize(skip)]
    pub relayer_key_id: String,
    pub relayer_share32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ServerRespondResultV1 {
    pub client_response: RespondResponseV1,
    pub finalized_server_session: FinalizedServerSessionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExportNonceKeyV1 {
    pub wallet_session_user_id: String,
    pub ecdsa_threshold_key_id: String,
    pub relayer_key_id: String,
    pub export_request_nonce32: [u8; 32],
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportNonceReplayGuardV1 {
    used: HashSet<ExportNonceKeyV1>,
}

impl ExportNonceReplayGuardV1 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_fresh(&mut self, key: ExportNonceKeyV1) -> CoreResult<()> {
        if !self.used.insert(key) {
            return Err(SignerCoreError::invalid_input("export_nonce_replay"));
        }
        Ok(())
    }
}

impl StagedServerSessionV1 {
    pub fn prepare(inputs: ServerPrepareInputsV1) -> CoreResult<Self> {
        inputs.prepare.context.validate()?;
        validate_ascii_id("relayer_key_id", &inputs.prepare.relayer_key_id)?;
        Ok(Self {
            prepare: inputs.prepare.clone(),
            y_relayer32_le: inputs.y_relayer32_le,
        })
    }

    pub fn respond(self, request: &RespondRequestV1) -> CoreResult<ServerRespondResultV1> {
        let RespondRequestV1::Threshold(request) = request else {
            return Err(SignerCoreError::invalid_input(
                "explicit export requires respond_explicit_export",
            ));
        };
        if self.prepare.operation == ServerEvalOperationV1::ExplicitKeyExport {
            return Err(SignerCoreError::invalid_input(
                "explicit export requires respond_explicit_export",
            ));
        }
        self.respond_threshold(request, None)
    }

    pub fn respond_explicit_export(
        self,
        request: &ExplicitExportRespondRequestV1,
        replay_guard: &mut ExportNonceReplayGuardV1,
        now_unix_ms: u64,
    ) -> CoreResult<ServerRespondResultV1> {
        if self.prepare.operation != ServerEvalOperationV1::ExplicitKeyExport {
            return Err(SignerCoreError::invalid_input(
                "explicit export request requires ExplicitKeyExport operation",
            ));
        }
        replay_guard.insert_fresh(ExportNonceKeyV1 {
            wallet_session_user_id: request.authorization.wallet_session_user_id.clone(),
            ecdsa_threshold_key_id: request.authorization.ecdsa_threshold_key_id.clone(),
            relayer_key_id: request.authorization.relayer_key_id.clone(),
            export_request_nonce32: request.authorization.export_request_nonce32,
        })?;
        validate_export_authorization(&self.prepare, &request.authorization, now_unix_ms)?;
        self.respond_threshold(
            &ThresholdRespondRequestV1 {
                client_public_key33: request.client_public_key33,
                client_share_retry_counter: request.client_share_retry_counter,
                expected_relayer_key_id: request.authorization.relayer_key_id.clone(),
            },
            Some(request.authorization.clone()),
        )
    }

    fn respond_threshold(
        self,
        request: &ThresholdRespondRequestV1,
        export_authorization: Option<ExplicitExportAuthorizationV1>,
    ) -> CoreResult<ServerRespondResultV1> {
        if request.expected_relayer_key_id != self.prepare.relayer_key_id {
            return Err(SignerCoreError::invalid_input("relayer_key_mismatch"));
        }

        let (relayer_share, identity) = derive_relayer_share_for_client_public_v1(
            &self.prepare.context,
            self.y_relayer32_le,
            &request.client_public_key33,
            request.client_share_retry_counter,
        )?;

        let client_output = match self.prepare.operation {
            ServerEvalOperationV1::RegistrationBootstrap
            | ServerEvalOperationV1::SessionBootstrap
            | ServerEvalOperationV1::NonExportSign => {
                if export_authorization.is_some() {
                    return Err(SignerCoreError::invalid_input(
                        "export authorization is only valid for explicit export",
                    ));
                }
                ClientOutputV1::NonExport(NonExportClientOutputV1 {
                    client_public_key33: identity.client_public_key33,
                    relayer_public_key33: identity.relayer_public_key33,
                    threshold_public_key33: identity.threshold_public_key33,
                    threshold_ethereum_address20: identity.threshold_ethereum_address20,
                    client_share_retry_counter: identity.client_share_retry_counter,
                    relayer_share_retry_counter: identity.relayer_share_retry_counter,
                })
            }
            ServerEvalOperationV1::ExplicitKeyExport => {
                let authorization = export_authorization.as_ref().ok_or_else(|| {
                    SignerCoreError::invalid_input("explicit export requires authorization")
                })?;
                validate_export_authorization_digest(
                    self.prepare.operation,
                    &identity,
                    authorization,
                )?;
                ClientOutputV1::ExplicitExport(ExplicitExportClientOutputV1 {
                    relayer_export_share32: relayer_share.x_relayer32,
                    client_public_key33: identity.client_public_key33,
                    relayer_public_key33: identity.relayer_public_key33,
                    threshold_public_key33: identity.threshold_public_key33,
                    threshold_ethereum_address20: identity.threshold_ethereum_address20,
                    client_share_retry_counter: identity.client_share_retry_counter,
                    relayer_share_retry_counter: identity.relayer_share_retry_counter,
                })
            }
        };

        let finalized = FinalizedServerSessionV1 {
            operation: self.prepare.operation,
            context: self.prepare.context.clone(),
            retained: RetainedServerStateV1 {
                raw_root_material_dropped: true,
                relayer_key_id: self.prepare.relayer_key_id.clone(),
                relayer_share32: relayer_share.x_relayer32,
                client_public_key33: identity.client_public_key33,
                relayer_public_key33: identity.relayer_public_key33,
                threshold_public_key33: identity.threshold_public_key33,
                threshold_ethereum_address20: identity.threshold_ethereum_address20,
                client_share_retry_counter: identity.client_share_retry_counter,
                relayer_share_retry_counter: identity.relayer_share_retry_counter,
            },
        };

        let finalize = FinalizeEnvelopeV1 {
            operation: finalized.operation,
            raw_root_material_dropped: finalized.retained.raw_root_material_dropped,
            relayer_key_id: finalized.retained.relayer_key_id.clone(),
            context_binding32: identity.context_binding32,
            client_public_key33: finalized.retained.client_public_key33,
            relayer_public_key33: finalized.retained.relayer_public_key33,
            threshold_public_key33: finalized.retained.threshold_public_key33,
            threshold_ethereum_address20: finalized.retained.threshold_ethereum_address20,
            client_share_retry_counter: finalized.retained.client_share_retry_counter,
            relayer_share_retry_counter: finalized.retained.relayer_share_retry_counter,
        };

        Ok(ServerRespondResultV1 {
            client_response: RespondResponseV1 {
                client_output,
                finalize,
            },
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
        if finalize.relayer_key_id != self.retained.relayer_key_id {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope relayer key id does not match retained server state",
            ));
        }
        let context_binding32 = crate::shared::derive::context_binding_v1(&self.context)?;
        if finalize.context_binding32 != context_binding32 {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope context binding does not match retained server context",
            ));
        }
        if finalize.client_public_key33 != self.retained.client_public_key33 {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope client public key does not match retained server state",
            ));
        }
        if finalize.relayer_public_key33 != self.retained.relayer_public_key33 {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope relayer public key does not match retained server state",
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
        if finalize.client_share_retry_counter != self.retained.client_share_retry_counter {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope client retry counter does not match retained server state",
            ));
        }
        if finalize.relayer_share_retry_counter != self.retained.relayer_share_retry_counter {
            return Err(SignerCoreError::invalid_input(
                "finalize envelope relayer retry counter does not match retained server state",
            ));
        }
        Ok(())
    }
}

fn validate_export_authorization(
    prepare: &PrepareEnvelopeV1,
    authorization: &ExplicitExportAuthorizationV1,
    now_unix_ms: u64,
) -> CoreResult<()> {
    validate_ascii_id(
        "wallet_session_user_id",
        &authorization.wallet_session_user_id,
    )?;
    validate_ascii_id(
        "ecdsa_threshold_key_id",
        &authorization.ecdsa_threshold_key_id,
    )?;
    validate_ascii_id("client_device_id", &authorization.client_device_id)?;
    validate_ascii_id("client_session_id", &authorization.client_session_id)?;
    validate_ascii_id("relayer_key_id", &authorization.relayer_key_id)?;
    if authorization.wallet_session_user_id != prepare.context.wallet_session_user_id {
        return Err(SignerCoreError::invalid_input(
            "export authorization wallet session user mismatch",
        ));
    }
    if authorization.ecdsa_threshold_key_id != prepare.context.ecdsa_threshold_key_id {
        return Err(SignerCoreError::invalid_input(
            "export authorization threshold key mismatch",
        ));
    }
    if authorization.relayer_key_id != prepare.relayer_key_id {
        return Err(SignerCoreError::invalid_input("relayer_key_mismatch"));
    }
    if authorization.issued_at_unix_ms > now_unix_ms {
        return Err(SignerCoreError::invalid_input(
            "export_authorization_not_yet_valid",
        ));
    }
    if now_unix_ms > authorization.expires_at_unix_ms {
        return Err(SignerCoreError::invalid_input(
            "export_authorization_expired",
        ));
    }
    if authorization.issued_at_unix_ms > authorization.expires_at_unix_ms {
        return Err(SignerCoreError::invalid_input(
            "export authorization validity window is invalid",
        ));
    }
    Ok(())
}

fn validate_export_authorization_digest(
    operation: ServerEvalOperationV1,
    identity: &PublicIdentityV1,
    authorization: &ExplicitExportAuthorizationV1,
) -> CoreResult<()> {
    let expected = export_authorization_digest_v1(operation, identity, authorization)?;
    if authorization.authorization_digest32 != expected {
        return Err(SignerCoreError::invalid_input(
            "export_authorization_digest_mismatch",
        ));
    }
    Ok(())
}

fn validate_ascii_id(field_name: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    if !value.is_ascii() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be ASCII-only"
        )));
    }
    Ok(())
}
