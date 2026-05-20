pub mod shared {
    pub mod context {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct EcdsaHssStableKeyContextV1 {
            pub wallet_session_user_id: String,
            pub subject_id: String,
            pub ecdsa_threshold_key_id: String,
            pub signing_root_id: String,
            pub signing_root_version: String,
            pub key_purpose: String,
            pub key_version: String,
        }
    }
}

pub mod wire {
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
                | ServerEvalOperationV1::NonExportSign => {
                    AllowedOutputKindV1::ThresholdMaterialOnly
                }
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
}

pub mod client {
    use crate::wire::AllowedOutputKindV1;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NonExportClientOutputV1 {
        pub client_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ExplicitExportClientOutputV1 {
        pub relayer_export_share32: [u8; 32],
        pub client_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ClientOutputV1 {
        NonExport(NonExportClientOutputV1),
        ExplicitExport(ExplicitExportClientOutputV1),
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
}

pub mod server {
    use crate::client::{ClientOutputV1, ExplicitExportClientOutputV1, NonExportClientOutputV1};
    use crate::shared::context::EcdsaHssStableKeyContextV1;
    use crate::wire::{
        AllowedOutputKindV1, FinalizeEnvelopeV1, PrepareEnvelopeV1, ServerEvalOperationV1,
        ThresholdRespondRequestV1,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RetainedServerStateV1 {
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
    pub struct FinalizedServerSessionV1 {
        pub operation: ServerEvalOperationV1,
        pub context: EcdsaHssStableKeyContextV1,
        pub retained: RetainedServerStateV1,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StagedServerSessionV1 {
        pub prepare: PrepareEnvelopeV1,
        pub y_relayer32_le: [u8; 32],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RespondResponseV1 {
        pub client_output: ClientOutputV1,
        pub finalize: FinalizeEnvelopeV1,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ServerRespondResultV1 {
        pub client_response: RespondResponseV1,
        pub finalized_server_session: FinalizedServerSessionV1,
    }

    pub mod boundary {
        use super::*;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleOperationBoundaryV1 {
            pub operation: ServerEvalOperationV1,
            pub allowed_output_kind: AllowedOutputKindV1,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleNonExportBoundaryV1 {
            pub client_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleExplicitExportBoundaryV1 {
            pub relayer_export_share32: [u8; 32],
            pub client_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum VisibleClientBoundaryV1 {
            NonExport(VisibleNonExportBoundaryV1),
            ExplicitExport(VisibleExplicitExportBoundaryV1),
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleFinalizeBoundaryV1 {
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

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleRetainedServerStateBoundaryV1 {
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
        pub struct VisibleRespondBoundaryV1 {
            pub operation: VisibleOperationBoundaryV1,
            pub client_output: VisibleClientBoundaryV1,
            pub finalize: VisibleFinalizeBoundaryV1,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalInputBoundaryV1 {
            pub operation: ServerEvalOperationV1,
            pub allowed_output_kind: AllowedOutputKindV1,
            pub context: EcdsaHssStableKeyContextV1,
            pub relayer_key_id: String,
            pub client_public_key33: [u8; 33],
            pub client_share_retry_counter: u32,
            pub expected_relayer_key_id: String,
            pub y_relayer32_le: [u8; 32],
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalTransportBoundaryV1 {
            pub operation: VisibleOperationBoundaryV1,
            pub client_output: VisibleClientBoundaryV1,
            pub finalize: VisibleFinalizeBoundaryV1,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalPersistedStateBoundaryV1 {
            pub operation: ServerEvalOperationV1,
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
        pub struct HiddenEvalBoundaryV1 {
            pub input: HiddenEvalInputBoundaryV1,
            pub transport: HiddenEvalTransportBoundaryV1,
            pub persisted: HiddenEvalPersistedStateBoundaryV1,
        }

        pub fn operation_boundary_from_operation_v1(
            operation: ServerEvalOperationV1,
        ) -> VisibleOperationBoundaryV1 {
            VisibleOperationBoundaryV1 {
                operation,
                allowed_output_kind: operation.allowed_output_kind(),
            }
        }

        pub fn non_export_boundary_from_output_v1(
            output: NonExportClientOutputV1,
        ) -> VisibleNonExportBoundaryV1 {
            VisibleNonExportBoundaryV1 {
                client_public_key33: output.client_public_key33,
                relayer_public_key33: output.relayer_public_key33,
                threshold_public_key33: output.threshold_public_key33,
                threshold_ethereum_address20: output.threshold_ethereum_address20,
                client_share_retry_counter: output.client_share_retry_counter,
                relayer_share_retry_counter: output.relayer_share_retry_counter,
            }
        }

        pub fn explicit_export_boundary_from_output_v1(
            output: ExplicitExportClientOutputV1,
        ) -> VisibleExplicitExportBoundaryV1 {
            VisibleExplicitExportBoundaryV1 {
                relayer_export_share32: output.relayer_export_share32,
                client_public_key33: output.client_public_key33,
                relayer_public_key33: output.relayer_public_key33,
                threshold_public_key33: output.threshold_public_key33,
                threshold_ethereum_address20: output.threshold_ethereum_address20,
                client_share_retry_counter: output.client_share_retry_counter,
                relayer_share_retry_counter: output.relayer_share_retry_counter,
            }
        }

        pub fn visible_client_boundary_from_output_v1(
            output: ClientOutputV1,
        ) -> VisibleClientBoundaryV1 {
            match output {
                ClientOutputV1::NonExport(output) => {
                    VisibleClientBoundaryV1::NonExport(non_export_boundary_from_output_v1(output))
                }
                ClientOutputV1::ExplicitExport(output) => VisibleClientBoundaryV1::ExplicitExport(
                    explicit_export_boundary_from_output_v1(output),
                ),
            }
        }

        pub fn visible_finalize_boundary_from_envelope_v1(
            finalize: FinalizeEnvelopeV1,
        ) -> VisibleFinalizeBoundaryV1 {
            VisibleFinalizeBoundaryV1 {
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

        pub fn retained_state_boundary_from_retained_v1(
            retained: RetainedServerStateV1,
        ) -> VisibleRetainedServerStateBoundaryV1 {
            VisibleRetainedServerStateBoundaryV1 {
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

        pub fn visible_boundary_from_respond_response_v1(
            response: RespondResponseV1,
        ) -> VisibleRespondBoundaryV1 {
            VisibleRespondBoundaryV1 {
                operation: operation_boundary_from_operation_v1(response.finalize.operation),
                client_output: visible_client_boundary_from_output_v1(response.client_output),
                finalize: visible_finalize_boundary_from_envelope_v1(response.finalize),
            }
        }

        pub fn hidden_eval_input_boundary_from_staged_request_v1(
            staged: StagedServerSessionV1,
            request: ThresholdRespondRequestV1,
        ) -> HiddenEvalInputBoundaryV1 {
            HiddenEvalInputBoundaryV1 {
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

        pub fn hidden_eval_transport_boundary_from_respond_response_v1(
            response: RespondResponseV1,
        ) -> HiddenEvalTransportBoundaryV1 {
            let visible = visible_boundary_from_respond_response_v1(response);
            HiddenEvalTransportBoundaryV1 {
                operation: visible.operation,
                client_output: visible.client_output,
                finalize: visible.finalize,
            }
        }

        pub fn hidden_eval_persisted_state_boundary_from_finalized_session_v1(
            session: FinalizedServerSessionV1,
        ) -> HiddenEvalPersistedStateBoundaryV1 {
            HiddenEvalPersistedStateBoundaryV1 {
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

        pub fn hidden_eval_boundary_from_parts_v1(
            input: HiddenEvalInputBoundaryV1,
            transport: HiddenEvalTransportBoundaryV1,
            persisted: HiddenEvalPersistedStateBoundaryV1,
        ) -> HiddenEvalBoundaryV1 {
            HiddenEvalBoundaryV1 {
                input,
                transport,
                persisted,
            }
        }
    }
}
