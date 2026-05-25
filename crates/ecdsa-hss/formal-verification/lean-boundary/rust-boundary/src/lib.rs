pub mod shared {
    pub mod context {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct EcdsaHssStableKeyContextV2 {
            pub wallet_id: String,
            pub rp_id: String,
            pub ecdsa_threshold_key_id: String,
            pub signing_root_id: String,
            pub signing_root_version: String,
            pub key_purpose: String,
            pub key_version: String,
        }
    }
}

pub mod wire {
    use crate::shared::context::EcdsaHssStableKeyContextV2;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ServerEvalOperationV2 {
        RegistrationBootstrap,
        SessionBootstrap,
        NonExportSign,
        ExplicitKeyExport,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AllowedOutputKindV2 {
        ThresholdMaterialOnly,
        ThresholdMaterialAndRelayerExportShare,
    }

    impl ServerEvalOperationV2 {
        pub fn allowed_output_kind(self) -> AllowedOutputKindV2 {
            match self {
                ServerEvalOperationV2::ExplicitKeyExport => {
                    AllowedOutputKindV2::ThresholdMaterialAndRelayerExportShare
                }
                ServerEvalOperationV2::RegistrationBootstrap
                | ServerEvalOperationV2::SessionBootstrap
                | ServerEvalOperationV2::NonExportSign => {
                    AllowedOutputKindV2::ThresholdMaterialOnly
                }
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PrepareEnvelopeV2 {
        pub operation: ServerEvalOperationV2,
        pub context: EcdsaHssStableKeyContextV2,
        pub relayer_key_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ThresholdRespondRequestV2 {
        pub client_public_key33: [u8; 33],
        pub client_share_retry_counter: u32,
        pub expected_relayer_key_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FinalizeEnvelopeV2 {
        pub operation: ServerEvalOperationV2,
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
}

pub mod client {
    use crate::wire::AllowedOutputKindV2;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NonExportClientOutputV2 {
        pub client_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ExplicitExportClientOutputV2 {
        pub relayer_export_share32: [u8; 32],
        pub client_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ClientOutputV2 {
        NonExport(NonExportClientOutputV2),
        ExplicitExport(ExplicitExportClientOutputV2),
    }

    impl ClientOutputV2 {
        pub fn allowed_output_kind(&self) -> AllowedOutputKindV2 {
            match self {
                ClientOutputV2::NonExport(_) => AllowedOutputKindV2::ThresholdMaterialOnly,
                ClientOutputV2::ExplicitExport(_) => {
                    AllowedOutputKindV2::ThresholdMaterialAndRelayerExportShare
                }
            }
        }
    }
}

pub mod server {
    use crate::client::{ClientOutputV2, ExplicitExportClientOutputV2, NonExportClientOutputV2};
    use crate::shared::context::EcdsaHssStableKeyContextV2;
    use crate::wire::{
        AllowedOutputKindV2, FinalizeEnvelopeV2, PrepareEnvelopeV2, ServerEvalOperationV2,
        ThresholdRespondRequestV2,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RetainedServerStateV2 {
        pub raw_root_material_dropped: bool,
        pub relayer_key_id: String,
        pub relayer_share32: [u8; 32],
        pub client_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FinalizedServerSessionV2 {
        pub operation: ServerEvalOperationV2,
        pub context: EcdsaHssStableKeyContextV2,
        pub retained: RetainedServerStateV2,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StagedServerSessionV2 {
        pub prepare: PrepareEnvelopeV2,
        pub y_relayer32_le: [u8; 32],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RespondResponseV2 {
        pub client_output: ClientOutputV2,
        pub finalize: FinalizeEnvelopeV2,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ServerRespondResultV2 {
        pub client_response: RespondResponseV2,
        pub finalized_server_session: FinalizedServerSessionV2,
    }

    pub mod boundary {
        use super::*;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleOperationBoundaryV2 {
            pub operation: ServerEvalOperationV2,
            pub allowed_output_kind: AllowedOutputKindV2,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleNonExportBoundaryV2 {
            pub client_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleExplicitExportBoundaryV2 {
            pub relayer_export_share32: [u8; 32],
            pub client_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum VisibleClientBoundaryV2 {
            NonExport(VisibleNonExportBoundaryV2),
            ExplicitExport(VisibleExplicitExportBoundaryV2),
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleFinalizeBoundaryV2 {
            pub operation: ServerEvalOperationV2,
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

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleRetainedServerStateBoundaryV2 {
            pub raw_root_material_dropped: bool,
            pub relayer_key_id: String,
            pub relayer_share32: [u8; 32],
            pub client_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleRespondBoundaryV2 {
            pub operation: VisibleOperationBoundaryV2,
            pub client_output: VisibleClientBoundaryV2,
            pub finalize: VisibleFinalizeBoundaryV2,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalInputBoundaryV2 {
            pub operation: ServerEvalOperationV2,
            pub allowed_output_kind: AllowedOutputKindV2,
            pub context: EcdsaHssStableKeyContextV2,
            pub relayer_key_id: String,
            pub client_public_key33: [u8; 33],
            pub client_share_retry_counter: u32,
            pub expected_relayer_key_id: String,
            pub y_relayer32_le: [u8; 32],
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalTransportBoundaryV2 {
            pub operation: VisibleOperationBoundaryV2,
            pub client_output: VisibleClientBoundaryV2,
            pub finalize: VisibleFinalizeBoundaryV2,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalPersistedStateBoundaryV2 {
            pub operation: ServerEvalOperationV2,
            pub raw_root_material_dropped: bool,
            pub relayer_key_id: String,
            pub relayer_share32: [u8; 32],
            pub client_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalBoundaryV2 {
            pub input: HiddenEvalInputBoundaryV2,
            pub transport: HiddenEvalTransportBoundaryV2,
            pub persisted: HiddenEvalPersistedStateBoundaryV2,
        }

        pub fn operation_boundary_from_operation_v2(
            operation: ServerEvalOperationV2,
        ) -> VisibleOperationBoundaryV2 {
            VisibleOperationBoundaryV2 {
                operation,
                allowed_output_kind: operation.allowed_output_kind(),
            }
        }

        pub fn non_export_boundary_from_output_v2(
            output: NonExportClientOutputV2,
        ) -> VisibleNonExportBoundaryV2 {
            VisibleNonExportBoundaryV2 {
                client_public_key33: output.client_public_key33,
                relayer_public_key33: output.relayer_public_key33,
                threshold_public_key33: output.threshold_public_key33,
                threshold_ethereum_address20: output.threshold_ethereum_address20,
                client_share_retry_counter: output.client_share_retry_counter,
                relayer_share_retry_counter: output.relayer_share_retry_counter,
            }
        }

        pub fn explicit_export_boundary_from_output_v2(
            output: ExplicitExportClientOutputV2,
        ) -> VisibleExplicitExportBoundaryV2 {
            VisibleExplicitExportBoundaryV2 {
                relayer_export_share32: output.relayer_export_share32,
                client_public_key33: output.client_public_key33,
                relayer_public_key33: output.relayer_public_key33,
                threshold_public_key33: output.threshold_public_key33,
                threshold_ethereum_address20: output.threshold_ethereum_address20,
                client_share_retry_counter: output.client_share_retry_counter,
                relayer_share_retry_counter: output.relayer_share_retry_counter,
            }
        }

        pub fn visible_client_boundary_from_output_v2(
            output: ClientOutputV2,
        ) -> VisibleClientBoundaryV2 {
            match output {
                ClientOutputV2::NonExport(output) => {
                    VisibleClientBoundaryV2::NonExport(non_export_boundary_from_output_v2(output))
                }
                ClientOutputV2::ExplicitExport(output) => VisibleClientBoundaryV2::ExplicitExport(
                    explicit_export_boundary_from_output_v2(output),
                ),
            }
        }

        pub fn visible_finalize_boundary_from_envelope_v2(
            finalize: FinalizeEnvelopeV2,
        ) -> VisibleFinalizeBoundaryV2 {
            VisibleFinalizeBoundaryV2 {
                operation: finalize.operation,
                raw_root_material_dropped: finalize.raw_root_material_dropped,
                relayer_key_id: finalize.relayer_key_id,
                context_binding32: finalize.context_binding32,
                client_public_key33: finalize.client_public_key33,
                relayer_public_key33: finalize.relayer_public_key33,
                threshold_public_key33: finalize.threshold_public_key33,
                threshold_ethereum_address20: finalize.threshold_ethereum_address20,
                client_share_retry_counter: finalize.client_share_retry_counter,
                relayer_share_retry_counter: finalize.relayer_share_retry_counter,
            }
        }

        pub fn retained_state_boundary_from_retained_v2(
            retained: RetainedServerStateV2,
        ) -> VisibleRetainedServerStateBoundaryV2 {
            VisibleRetainedServerStateBoundaryV2 {
                raw_root_material_dropped: retained.raw_root_material_dropped,
                relayer_key_id: retained.relayer_key_id,
                relayer_share32: retained.relayer_share32,
                client_public_key33: retained.client_public_key33,
                relayer_public_key33: retained.relayer_public_key33,
                threshold_public_key33: retained.threshold_public_key33,
                threshold_ethereum_address20: retained.threshold_ethereum_address20,
                client_share_retry_counter: retained.client_share_retry_counter,
                relayer_share_retry_counter: retained.relayer_share_retry_counter,
            }
        }

        pub fn visible_boundary_from_respond_response_v2(
            response: RespondResponseV2,
        ) -> VisibleRespondBoundaryV2 {
            VisibleRespondBoundaryV2 {
                operation: operation_boundary_from_operation_v2(response.finalize.operation),
                client_output: visible_client_boundary_from_output_v2(response.client_output),
                finalize: visible_finalize_boundary_from_envelope_v2(response.finalize),
            }
        }

        pub fn hidden_eval_input_boundary_from_staged_request_v2(
            staged: StagedServerSessionV2,
            request: ThresholdRespondRequestV2,
        ) -> HiddenEvalInputBoundaryV2 {
            HiddenEvalInputBoundaryV2 {
                operation: staged.prepare.operation,
                allowed_output_kind: staged.prepare.operation.allowed_output_kind(),
                context: staged.prepare.context,
                relayer_key_id: staged.prepare.relayer_key_id,
                client_public_key33: request.client_public_key33,
                client_share_retry_counter: request.client_share_retry_counter,
                expected_relayer_key_id: request.expected_relayer_key_id,
                y_relayer32_le: staged.y_relayer32_le,
            }
        }

        pub fn hidden_eval_transport_boundary_from_respond_response_v2(
            response: RespondResponseV2,
        ) -> HiddenEvalTransportBoundaryV2 {
            let visible = visible_boundary_from_respond_response_v2(response);
            HiddenEvalTransportBoundaryV2 {
                operation: visible.operation,
                client_output: visible.client_output,
                finalize: visible.finalize,
            }
        }

        pub fn hidden_eval_persisted_state_boundary_from_finalized_session_v2(
            session: FinalizedServerSessionV2,
        ) -> HiddenEvalPersistedStateBoundaryV2 {
            HiddenEvalPersistedStateBoundaryV2 {
                operation: session.operation,
                raw_root_material_dropped: session.retained.raw_root_material_dropped,
                relayer_key_id: session.retained.relayer_key_id,
                relayer_share32: session.retained.relayer_share32,
                client_public_key33: session.retained.client_public_key33,
                relayer_public_key33: session.retained.relayer_public_key33,
                threshold_public_key33: session.retained.threshold_public_key33,
                threshold_ethereum_address20: session.retained.threshold_ethereum_address20,
                client_share_retry_counter: session.retained.client_share_retry_counter,
                relayer_share_retry_counter: session.retained.relayer_share_retry_counter,
            }
        }

        pub fn hidden_eval_boundary_from_parts_v2(
            input: HiddenEvalInputBoundaryV2,
            transport: HiddenEvalTransportBoundaryV2,
            persisted: HiddenEvalPersistedStateBoundaryV2,
        ) -> HiddenEvalBoundaryV2 {
            HiddenEvalBoundaryV2 {
                input,
                transport,
                persisted,
            }
        }
    }
}
