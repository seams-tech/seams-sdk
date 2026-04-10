use signer_core::error::{CoreResult, SignerCoreError};

use crate::client::{ClientOutputV1, ExplicitExportClientOutputV1, NonExportClientOutputV1};
use crate::server::{
    FinalizedServerSessionV1, RespondResponseV1, RetainedServerStateV1, StagedServerSessionV1,
};
use crate::wire::{AllowedOutputKindV1, FinalizeEnvelopeV1, ServerEvalOperationV1};
use crate::{EcdsaHssContextV1, RespondRequestV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleOperationBoundaryV1 {
    pub operation: ServerEvalOperationV1,
    pub allowed_output_kind: AllowedOutputKindV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleNonExportBoundaryV1 {
    pub x_client32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleExplicitExportBoundaryV1 {
    pub canonical_x32: [u8; 32],
    pub canonical_public_key33: [u8; 33],
    pub canonical_ethereum_address20: [u8; 20],
    pub x_client32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibleClientBoundaryV1 {
    NonExport(VisibleNonExportBoundaryV1),
    ExplicitExport(VisibleExplicitExportBoundaryV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleFinalizeBoundaryV1 {
    pub operation: ServerEvalOperationV1,
    pub raw_root_material_dropped: bool,
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleRetainedServerStateBoundaryV1 {
    pub raw_root_material_dropped: bool,
    pub relayer_threshold_share32: [u8; 32],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleRespondBoundaryV1 {
    pub operation: VisibleOperationBoundaryV1,
    pub client_output: VisibleClientBoundaryV1,
    pub finalize: VisibleFinalizeBoundaryV1,
    pub retained: VisibleRetainedServerStateBoundaryV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenEvalInputBoundaryV1 {
    pub operation: ServerEvalOperationV1,
    pub allowed_output_kind: AllowedOutputKindV1,
    pub context: EcdsaHssContextV1,
    pub y_client32_le: [u8; 32],
    pub y_relayer32_le: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiddenEvalTransportBoundaryV1 {
    pub operation: VisibleOperationBoundaryV1,
    pub client_output: VisibleClientBoundaryV1,
    pub finalize: VisibleFinalizeBoundaryV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiddenEvalPersistedStateBoundaryV1 {
    pub operation: ServerEvalOperationV1,
    pub raw_root_material_dropped: bool,
    pub relayer_threshold_share32: [u8; 32],
    pub relayer_public_key33: [u8; 33],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
    pub retry_counter: u32,
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

pub fn visible_client_boundary_from_output_v1(output: &ClientOutputV1) -> VisibleClientBoundaryV1 {
    match output {
        ClientOutputV1::NonExport(output) => {
            VisibleClientBoundaryV1::NonExport(non_export_boundary_from_output_v1(output))
        }
        ClientOutputV1::ExplicitExport(output) => {
            VisibleClientBoundaryV1::ExplicitExport(explicit_export_boundary_from_output_v1(output))
        }
    }
}

pub fn visible_finalize_boundary_from_envelope_v1(
    finalize: &FinalizeEnvelopeV1,
) -> VisibleFinalizeBoundaryV1 {
    VisibleFinalizeBoundaryV1 {
        operation: finalize.operation,
        raw_root_material_dropped: finalize.raw_root_material_dropped,
        threshold_public_key33: finalize.threshold_public_key33,
        threshold_ethereum_address20: finalize.threshold_ethereum_address20,
        retry_counter: finalize.retry_counter,
    }
}

pub fn visible_retained_state_boundary_from_finalized_session_v1(
    session: &FinalizedServerSessionV1,
) -> VisibleRetainedServerStateBoundaryV1 {
    retained_state_boundary_from_retained_v1(&session.retained)
}

pub fn visible_boundary_from_respond_response_v1(
    response: &RespondResponseV1,
) -> CoreResult<VisibleRespondBoundaryV1> {
    response
        .finalized_server_session
        .validate_finalize_envelope(&response.finalize)?;

    let operation =
        operation_boundary_from_operation_v1(response.finalized_server_session.operation);
    if operation.allowed_output_kind != response.client_output.allowed_output_kind() {
        return Err(SignerCoreError::invalid_input(
            "client output kind does not match operation output policy",
        ));
    }

    Ok(VisibleRespondBoundaryV1 {
        operation,
        client_output: visible_client_boundary_from_output_v1(&response.client_output),
        finalize: visible_finalize_boundary_from_envelope_v1(&response.finalize),
        retained: visible_retained_state_boundary_from_finalized_session_v1(
            &response.finalized_server_session,
        ),
    })
}

pub fn hidden_eval_input_boundary_from_staged_request_v1(
    staged: &StagedServerSessionV1,
    request: &RespondRequestV1,
) -> HiddenEvalInputBoundaryV1 {
    HiddenEvalInputBoundaryV1 {
        operation: staged.prepare.operation,
        allowed_output_kind: staged.prepare.operation.allowed_output_kind(),
        context: staged.prepare.context.clone(),
        y_client32_le: request.y_client32_le,
        y_relayer32_le: staged.y_relayer32_le,
    }
}

pub fn hidden_eval_transport_boundary_from_respond_response_v1(
    response: &RespondResponseV1,
) -> CoreResult<HiddenEvalTransportBoundaryV1> {
    let visible = visible_boundary_from_respond_response_v1(response)?;
    Ok(HiddenEvalTransportBoundaryV1 {
        operation: visible.operation,
        client_output: visible.client_output,
        finalize: visible.finalize,
    })
}

pub fn hidden_eval_persisted_state_boundary_from_finalized_session_v1(
    session: &FinalizedServerSessionV1,
) -> HiddenEvalPersistedStateBoundaryV1 {
    HiddenEvalPersistedStateBoundaryV1 {
        operation: session.operation,
        raw_root_material_dropped: session.retained.raw_root_material_dropped,
        relayer_threshold_share32: session.retained.relayer_threshold_share32,
        relayer_public_key33: session.retained.relayer_public_key33,
        threshold_public_key33: session.retained.threshold_public_key33,
        threshold_ethereum_address20: session.retained.threshold_ethereum_address20,
        retry_counter: session.retained.retry_counter,
    }
}

pub fn hidden_eval_boundary_from_staged_request_and_response_v1(
    staged: &StagedServerSessionV1,
    request: &RespondRequestV1,
    response: &RespondResponseV1,
) -> CoreResult<HiddenEvalBoundaryV1> {
    if response.finalized_server_session.operation != staged.prepare.operation {
        return Err(SignerCoreError::invalid_input(
            "respond response operation does not match staged server operation",
        ));
    }
    if response.finalized_server_session.context != staged.prepare.context {
        return Err(SignerCoreError::invalid_input(
            "respond response context does not match staged server context",
        ));
    }

    Ok(HiddenEvalBoundaryV1 {
        input: hidden_eval_input_boundary_from_staged_request_v1(staged, request),
        transport: hidden_eval_transport_boundary_from_respond_response_v1(response)?,
        persisted: hidden_eval_persisted_state_boundary_from_finalized_session_v1(
            &response.finalized_server_session,
        ),
    })
}

fn non_export_boundary_from_output_v1(
    output: &NonExportClientOutputV1,
) -> VisibleNonExportBoundaryV1 {
    VisibleNonExportBoundaryV1 {
        x_client32: output.x_client32,
        client_public_key33: output.client_public_key33,
        threshold_public_key33: output.threshold_public_key33,
        threshold_ethereum_address20: output.threshold_ethereum_address20,
        retry_counter: output.retry_counter,
    }
}

fn explicit_export_boundary_from_output_v1(
    output: &ExplicitExportClientOutputV1,
) -> VisibleExplicitExportBoundaryV1 {
    VisibleExplicitExportBoundaryV1 {
        canonical_x32: output.canonical_x32,
        canonical_public_key33: output.canonical_public_key33,
        canonical_ethereum_address20: output.canonical_ethereum_address20,
        x_client32: output.x_client32,
        client_public_key33: output.client_public_key33,
        threshold_public_key33: output.threshold_public_key33,
        threshold_ethereum_address20: output.threshold_ethereum_address20,
        retry_counter: output.retry_counter,
    }
}

fn retained_state_boundary_from_retained_v1(
    retained: &RetainedServerStateV1,
) -> VisibleRetainedServerStateBoundaryV1 {
    VisibleRetainedServerStateBoundaryV1 {
        raw_root_material_dropped: retained.raw_root_material_dropped,
        relayer_threshold_share32: retained.relayer_threshold_share32,
        relayer_public_key33: retained.relayer_public_key33,
        threshold_public_key33: retained.threshold_public_key33,
        threshold_ethereum_address20: retained.threshold_ethereum_address20,
        retry_counter: retained.retry_counter,
    }
}
