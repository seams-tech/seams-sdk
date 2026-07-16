pub mod shared {
    pub mod context {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct RouterAbEcdsaDerivationStableKeyContext {
            pub application_binding_digest: [u8; 32],
        }
    }
}

pub mod wire {
    use crate::shared::context::RouterAbEcdsaDerivationStableKeyContext;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ServerEvalOperation {
        RegistrationBootstrap,
        SessionBootstrap,
        NonExportSign,
        ExplicitKeyExport,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AllowedOutputKind {
        ThresholdMaterialOnly,
        ThresholdMaterialAndRelayerExportShare,
    }

    impl ServerEvalOperation {
        pub fn allowed_output_kind(self) -> AllowedOutputKind {
            match self {
                ServerEvalOperation::ExplicitKeyExport => {
                    AllowedOutputKind::ThresholdMaterialAndRelayerExportShare
                }
                ServerEvalOperation::RegistrationBootstrap
                | ServerEvalOperation::SessionBootstrap
                | ServerEvalOperation::NonExportSign => AllowedOutputKind::ThresholdMaterialOnly,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PrepareEnvelope {
        pub operation: ServerEvalOperation,
        pub context: RouterAbEcdsaDerivationStableKeyContext,
        pub relayer_key_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ThresholdRespondRequest {
        pub derivation_client_share_public_key33: [u8; 33],
        pub client_share_retry_counter: u32,
        pub expected_relayer_key_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FinalizeEnvelope {
        pub operation: ServerEvalOperation,
        pub raw_root_material_dropped: bool,
        pub relayer_key_id: String,
        pub context_binding32: [u8; 32],
        pub derivation_client_share_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }
}

pub mod client {
    use crate::wire::AllowedOutputKind;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NonExportClientOutput {
        pub derivation_client_share_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ExplicitExportClientOutput {
        pub relayer_export_share32: [u8; 32],
        pub derivation_client_share_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ClientOutput {
        NonExport(NonExportClientOutput),
        ExplicitExport(ExplicitExportClientOutput),
    }

    impl ClientOutput {
        pub fn allowed_output_kind(&self) -> AllowedOutputKind {
            match self {
                ClientOutput::NonExport(_) => AllowedOutputKind::ThresholdMaterialOnly,
                ClientOutput::ExplicitExport(_) => {
                    AllowedOutputKind::ThresholdMaterialAndRelayerExportShare
                }
            }
        }
    }
}

pub mod server {
    use crate::client::{ClientOutput, ExplicitExportClientOutput, NonExportClientOutput};
    use crate::shared::context::RouterAbEcdsaDerivationStableKeyContext;
    use crate::wire::{
        AllowedOutputKind, FinalizeEnvelope, PrepareEnvelope, ServerEvalOperation,
        ThresholdRespondRequest,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RetainedServerState {
        pub raw_root_material_dropped: bool,
        pub relayer_key_id: String,
        pub relayer_share32: [u8; 32],
        pub derivation_client_share_public_key33: [u8; 33],
        pub relayer_public_key33: [u8; 33],
        pub threshold_public_key33: [u8; 33],
        pub threshold_ethereum_address20: [u8; 20],
        pub client_share_retry_counter: u32,
        pub relayer_share_retry_counter: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FinalizedServerSession {
        pub operation: ServerEvalOperation,
        pub context: RouterAbEcdsaDerivationStableKeyContext,
        pub retained: RetainedServerState,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StagedServerSession {
        pub prepare: PrepareEnvelope,
        pub y_relayer32_le: [u8; 32],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RespondResponse {
        pub client_output: ClientOutput,
        pub finalize: FinalizeEnvelope,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ServerRespondResult {
        pub client_response: RespondResponse,
        pub finalized_server_session: FinalizedServerSession,
    }

    pub mod boundary {
        use super::*;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleOperationBoundary {
            pub operation: ServerEvalOperation,
            pub allowed_output_kind: AllowedOutputKind,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleNonExportBoundary {
            pub derivation_client_share_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleExplicitExportBoundary {
            pub relayer_export_share32: [u8; 32],
            pub derivation_client_share_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum VisibleClientBoundary {
            NonExport(VisibleNonExportBoundary),
            ExplicitExport(VisibleExplicitExportBoundary),
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleFinalizeBoundary {
            pub operation: ServerEvalOperation,
            pub raw_root_material_dropped: bool,
            pub relayer_key_id: String,
            pub context_binding32: [u8; 32],
            pub derivation_client_share_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleRetainedServerStateBoundary {
            pub raw_root_material_dropped: bool,
            pub relayer_key_id: String,
            pub relayer_share32: [u8; 32],
            pub derivation_client_share_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct VisibleRespondBoundary {
            pub operation: VisibleOperationBoundary,
            pub client_output: VisibleClientBoundary,
            pub finalize: VisibleFinalizeBoundary,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalInputBoundary {
            pub operation: ServerEvalOperation,
            pub allowed_output_kind: AllowedOutputKind,
            pub context: RouterAbEcdsaDerivationStableKeyContext,
            pub relayer_key_id: String,
            pub derivation_client_share_public_key33: [u8; 33],
            pub client_share_retry_counter: u32,
            pub expected_relayer_key_id: String,
            pub y_relayer32_le: [u8; 32],
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalTransportBoundary {
            pub operation: VisibleOperationBoundary,
            pub client_output: VisibleClientBoundary,
            pub finalize: VisibleFinalizeBoundary,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalPersistedStateBoundary {
            pub operation: ServerEvalOperation,
            pub raw_root_material_dropped: bool,
            pub relayer_key_id: String,
            pub relayer_share32: [u8; 32],
            pub derivation_client_share_public_key33: [u8; 33],
            pub relayer_public_key33: [u8; 33],
            pub threshold_public_key33: [u8; 33],
            pub threshold_ethereum_address20: [u8; 20],
            pub client_share_retry_counter: u32,
            pub relayer_share_retry_counter: u32,
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct HiddenEvalBoundary {
            pub input: HiddenEvalInputBoundary,
            pub transport: HiddenEvalTransportBoundary,
            pub persisted: HiddenEvalPersistedStateBoundary,
        }

        pub fn operation_boundary_from_operation(
            operation: ServerEvalOperation,
        ) -> VisibleOperationBoundary {
            VisibleOperationBoundary {
                operation,
                allowed_output_kind: operation.allowed_output_kind(),
            }
        }

        pub fn non_export_boundary_from_output(
            output: NonExportClientOutput,
        ) -> VisibleNonExportBoundary {
            VisibleNonExportBoundary {
                derivation_client_share_public_key33: output.derivation_client_share_public_key33,
                relayer_public_key33: output.relayer_public_key33,
                threshold_public_key33: output.threshold_public_key33,
                threshold_ethereum_address20: output.threshold_ethereum_address20,
                client_share_retry_counter: output.client_share_retry_counter,
                relayer_share_retry_counter: output.relayer_share_retry_counter,
            }
        }

        pub fn explicit_export_boundary_from_output(
            output: ExplicitExportClientOutput,
        ) -> VisibleExplicitExportBoundary {
            VisibleExplicitExportBoundary {
                relayer_export_share32: output.relayer_export_share32,
                derivation_client_share_public_key33: output.derivation_client_share_public_key33,
                relayer_public_key33: output.relayer_public_key33,
                threshold_public_key33: output.threshold_public_key33,
                threshold_ethereum_address20: output.threshold_ethereum_address20,
                client_share_retry_counter: output.client_share_retry_counter,
                relayer_share_retry_counter: output.relayer_share_retry_counter,
            }
        }

        pub fn visible_client_boundary_from_output(output: ClientOutput) -> VisibleClientBoundary {
            match output {
                ClientOutput::NonExport(output) => {
                    VisibleClientBoundary::NonExport(non_export_boundary_from_output(output))
                }
                ClientOutput::ExplicitExport(output) => VisibleClientBoundary::ExplicitExport(
                    explicit_export_boundary_from_output(output),
                ),
            }
        }

        pub fn visible_finalize_boundary_from_envelope(
            finalize: FinalizeEnvelope,
        ) -> VisibleFinalizeBoundary {
            VisibleFinalizeBoundary {
                operation: finalize.operation,
                raw_root_material_dropped: finalize.raw_root_material_dropped,
                relayer_key_id: finalize.relayer_key_id,
                context_binding32: finalize.context_binding32,
                derivation_client_share_public_key33: finalize.derivation_client_share_public_key33,
                relayer_public_key33: finalize.relayer_public_key33,
                threshold_public_key33: finalize.threshold_public_key33,
                threshold_ethereum_address20: finalize.threshold_ethereum_address20,
                client_share_retry_counter: finalize.client_share_retry_counter,
                relayer_share_retry_counter: finalize.relayer_share_retry_counter,
            }
        }

        pub fn retained_state_boundary_from_retained(
            retained: RetainedServerState,
        ) -> VisibleRetainedServerStateBoundary {
            VisibleRetainedServerStateBoundary {
                raw_root_material_dropped: retained.raw_root_material_dropped,
                relayer_key_id: retained.relayer_key_id,
                relayer_share32: retained.relayer_share32,
                derivation_client_share_public_key33: retained.derivation_client_share_public_key33,
                relayer_public_key33: retained.relayer_public_key33,
                threshold_public_key33: retained.threshold_public_key33,
                threshold_ethereum_address20: retained.threshold_ethereum_address20,
                client_share_retry_counter: retained.client_share_retry_counter,
                relayer_share_retry_counter: retained.relayer_share_retry_counter,
            }
        }

        pub fn visible_boundary_from_respond_response(
            response: RespondResponse,
        ) -> VisibleRespondBoundary {
            VisibleRespondBoundary {
                operation: operation_boundary_from_operation(response.finalize.operation),
                client_output: visible_client_boundary_from_output(response.client_output),
                finalize: visible_finalize_boundary_from_envelope(response.finalize),
            }
        }

        pub fn hidden_eval_input_boundary_from_staged_request(
            staged: StagedServerSession,
            request: ThresholdRespondRequest,
        ) -> HiddenEvalInputBoundary {
            HiddenEvalInputBoundary {
                operation: staged.prepare.operation,
                allowed_output_kind: staged.prepare.operation.allowed_output_kind(),
                context: staged.prepare.context,
                relayer_key_id: staged.prepare.relayer_key_id,
                derivation_client_share_public_key33: request.derivation_client_share_public_key33,
                client_share_retry_counter: request.client_share_retry_counter,
                expected_relayer_key_id: request.expected_relayer_key_id,
                y_relayer32_le: staged.y_relayer32_le,
            }
        }

        pub fn hidden_eval_transport_boundary_from_respond_response(
            response: RespondResponse,
        ) -> HiddenEvalTransportBoundary {
            let visible = visible_boundary_from_respond_response(response);
            HiddenEvalTransportBoundary {
                operation: visible.operation,
                client_output: visible.client_output,
                finalize: visible.finalize,
            }
        }

        pub fn hidden_eval_persisted_state_boundary_from_finalized_session(
            session: FinalizedServerSession,
        ) -> HiddenEvalPersistedStateBoundary {
            HiddenEvalPersistedStateBoundary {
                operation: session.operation,
                raw_root_material_dropped: session.retained.raw_root_material_dropped,
                relayer_key_id: session.retained.relayer_key_id,
                relayer_share32: session.retained.relayer_share32,
                derivation_client_share_public_key33: session.retained.derivation_client_share_public_key33,
                relayer_public_key33: session.retained.relayer_public_key33,
                threshold_public_key33: session.retained.threshold_public_key33,
                threshold_ethereum_address20: session.retained.threshold_ethereum_address20,
                client_share_retry_counter: session.retained.client_share_retry_counter,
                relayer_share_retry_counter: session.retained.relayer_share_retry_counter,
            }
        }

        pub fn hidden_eval_boundary_from_parts(
            input: HiddenEvalInputBoundary,
            transport: HiddenEvalTransportBoundary,
            persisted: HiddenEvalPersistedStateBoundary,
        ) -> HiddenEvalBoundary {
            HiddenEvalBoundary {
                input,
                transport,
                persisted,
            }
        }
    }
}


