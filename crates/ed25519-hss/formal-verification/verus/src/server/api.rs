//! Verification entrypoint for the export exception in `src/server/api.rs`.
//!
//! Narrow proof targets:
//! - allowed output kind mapping for server operations
//! - explicit export as the only seed-capable operation

use vstd::prelude::*;

verus! {

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ServerEvalOperation {
    Registration,
    TxSigning,
    LinkDevice,
    EmailRecovery,
    WarmSessionReconstruction,
    ExplicitKeyExport,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AllowedOutputKind {
    ClientOutputOnly,
    ClientOutputAndSeedOutput,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerFinalizePacketShape {
    pub allowed_output_kind: AllowedOutputKind,
    pub has_seed_output: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OutputProjectionResponseShape {
    pub allowed_output_kind: AllowedOutputKind,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerEvalBoundaryStateShape {
    pub operation: ServerEvalOperation,
    pub output_projection: OutputProjectionResponseShape,
    pub finalize: ServerFinalizePacketShape,
}

pub open spec fn allowed_output_kind_for_operation_spec(
    operation: ServerEvalOperation,
) -> AllowedOutputKind {
    match operation {
        ServerEvalOperation::ExplicitKeyExport => AllowedOutputKind::ClientOutputAndSeedOutput,
        ServerEvalOperation::Registration
        | ServerEvalOperation::TxSigning
        | ServerEvalOperation::LinkDevice
        | ServerEvalOperation::EmailRecovery
        | ServerEvalOperation::WarmSessionReconstruction => AllowedOutputKind::ClientOutputOnly,
    }
}

pub open spec fn is_seed_capable_operation_spec(operation: ServerEvalOperation) -> bool {
    allowed_output_kind_for_operation_spec(operation) == AllowedOutputKind::ClientOutputAndSeedOutput
}

pub fn allowed_output_kind_for_operation(
    operation: ServerEvalOperation,
) -> (out: AllowedOutputKind)
    ensures
        out == allowed_output_kind_for_operation_spec(operation),
{
    match operation {
        ServerEvalOperation::ExplicitKeyExport => AllowedOutputKind::ClientOutputAndSeedOutput,
        ServerEvalOperation::Registration
        | ServerEvalOperation::TxSigning
        | ServerEvalOperation::LinkDevice
        | ServerEvalOperation::EmailRecovery
        | ServerEvalOperation::WarmSessionReconstruction => AllowedOutputKind::ClientOutputOnly,
    }
}

pub open spec fn finalize_packet_shape_for_operation_spec(
    operation: ServerEvalOperation,
) -> ServerFinalizePacketShape {
    let allowed_output_kind = allowed_output_kind_for_operation_spec(operation);
    let has_seed_output = match allowed_output_kind {
        AllowedOutputKind::ClientOutputOnly => false,
        AllowedOutputKind::ClientOutputAndSeedOutput => true,
    };
    ServerFinalizePacketShape {
        allowed_output_kind,
        has_seed_output,
    }
}

pub fn finalize_packet_shape_for_operation(
    operation: ServerEvalOperation,
) -> (out: ServerFinalizePacketShape)
    ensures
        out == finalize_packet_shape_for_operation_spec(operation),
{
    let allowed_output_kind = allowed_output_kind_for_operation(operation);
    let has_seed_output = match allowed_output_kind {
        AllowedOutputKind::ClientOutputOnly => false,
        AllowedOutputKind::ClientOutputAndSeedOutput => true,
    };
    ServerFinalizePacketShape {
        allowed_output_kind,
        has_seed_output,
    }
}

pub open spec fn output_projection_response_shape_for_operation_spec(
    operation: ServerEvalOperation,
) -> OutputProjectionResponseShape {
    OutputProjectionResponseShape {
        allowed_output_kind: allowed_output_kind_for_operation_spec(operation),
    }
}

pub open spec fn output_projection_response_has_seed_output_spec() -> bool {
    false
}

pub fn output_projection_response_shape_for_operation(
    operation: ServerEvalOperation,
) -> (out: OutputProjectionResponseShape)
    ensures
        out == output_projection_response_shape_for_operation_spec(operation),
{
    OutputProjectionResponseShape {
        allowed_output_kind: allowed_output_kind_for_operation(operation),
    }
}

pub open spec fn server_eval_boundary_state_for_operation_spec(
    operation: ServerEvalOperation,
) -> ServerEvalBoundaryStateShape {
    ServerEvalBoundaryStateShape {
        operation,
        output_projection: output_projection_response_shape_for_operation_spec(operation),
        finalize: finalize_packet_shape_for_operation_spec(operation),
    }
}

pub fn server_eval_boundary_state_for_operation(
    operation: ServerEvalOperation,
) -> (out: ServerEvalBoundaryStateShape)
    ensures
        out == server_eval_boundary_state_for_operation_spec(operation),
{
    ServerEvalBoundaryStateShape {
        operation,
        output_projection: output_projection_response_shape_for_operation(operation),
        finalize: finalize_packet_shape_for_operation(operation),
    }
}

// Proves the explicit export exception is isolated: it is the only operation
// allowed to request seed-capable output, while all non-export operations are
// restricted to client-output-only behavior.
pub proof fn explicit_key_export_is_only_seed_capable_operation()
    ensures
        allowed_output_kind_for_operation_spec(ServerEvalOperation::ExplicitKeyExport)
            == AllowedOutputKind::ClientOutputAndSeedOutput,
        allowed_output_kind_for_operation_spec(ServerEvalOperation::Registration)
            == AllowedOutputKind::ClientOutputOnly,
        allowed_output_kind_for_operation_spec(ServerEvalOperation::TxSigning)
            == AllowedOutputKind::ClientOutputOnly,
        allowed_output_kind_for_operation_spec(ServerEvalOperation::LinkDevice)
            == AllowedOutputKind::ClientOutputOnly,
        allowed_output_kind_for_operation_spec(ServerEvalOperation::EmailRecovery)
            == AllowedOutputKind::ClientOutputOnly,
        allowed_output_kind_for_operation_spec(ServerEvalOperation::WarmSessionReconstruction)
            == AllowedOutputKind::ClientOutputOnly,
{
}

// Proves the export exception is exact as a runtime predicate: an operation is
// seed-capable if and only if it is `ExplicitKeyExport`.
pub proof fn seed_capable_operation_is_exactly_explicit_key_export(
    operation: ServerEvalOperation,
)
    ensures
        is_seed_capable_operation_spec(operation)
            <==> operation == ServerEvalOperation::ExplicitKeyExport,
{
}

// Proves the finalize/output-packet boundary enforces the export exception:
// non-export operations never carry seed output, while explicit export does.
pub proof fn finalize_packet_seed_output_matches_allowed_output_kind(
    operation: ServerEvalOperation,
)
    ensures
        finalize_packet_shape_for_operation_spec(operation).has_seed_output
            <==> is_seed_capable_operation_spec(operation),
        finalize_packet_shape_for_operation_spec(operation).has_seed_output
            <==> operation == ServerEvalOperation::ExplicitKeyExport,
{
}

// Proves the output-projection stage response carries the same allowed-output
// boundary as the finalize packet: non-export operations remain client-output
// only, while explicit export is the only seed-capable case.
pub proof fn output_projection_response_allowed_output_kind_matches_operation(
    operation: ServerEvalOperation,
)
    ensures
        output_projection_response_shape_for_operation_spec(operation).allowed_output_kind
            == allowed_output_kind_for_operation_spec(operation),
        output_projection_response_shape_for_operation_spec(operation).allowed_output_kind
            == AllowedOutputKind::ClientOutputAndSeedOutput
            <==> operation == ServerEvalOperation::ExplicitKeyExport,
{
}

// Proves the output-projection response is transport metadata only: it carries
// the allowed-output classification but never carries seed output directly.
pub proof fn output_projection_response_never_carries_seed_output_directly(
    operation: ServerEvalOperation,
)
    ensures
        output_projection_response_has_seed_output_spec() == false,
        output_projection_response_shape_for_operation_spec(operation).allowed_output_kind
            == AllowedOutputKind::ClientOutputAndSeedOutput
            ==> operation == ServerEvalOperation::ExplicitKeyExport,
{
}

// Proves the two runtime output boundaries stay aligned for the same
// operation: the output-projection response and finalize packet agree on
// `allowed_output_kind`, and seed-output presence remains tied to that shared
// export exception.
pub proof fn finalize_and_output_projection_boundaries_are_consistent(
    operation: ServerEvalOperation,
)
    ensures
        finalize_packet_shape_for_operation_spec(operation).allowed_output_kind
            == output_projection_response_shape_for_operation_spec(operation).allowed_output_kind,
        finalize_packet_shape_for_operation_spec(operation).has_seed_output
            <==> output_projection_response_shape_for_operation_spec(operation).allowed_output_kind
                == AllowedOutputKind::ClientOutputAndSeedOutput,
{
}

// Proves the minimal server-side boundary state remains operation-derived:
// the carried operation determines both outward-facing allowed-output
// boundaries and the finalize seed-output bit.
pub proof fn server_eval_boundary_state_is_operation_derived(
    operation: ServerEvalOperation,
)
    ensures
        server_eval_boundary_state_for_operation_spec(operation).operation == operation,
        server_eval_boundary_state_for_operation_spec(operation)
            .output_projection.allowed_output_kind
            == allowed_output_kind_for_operation_spec(operation),
        server_eval_boundary_state_for_operation_spec(operation)
            .finalize.allowed_output_kind
            == allowed_output_kind_for_operation_spec(operation),
        server_eval_boundary_state_for_operation_spec(operation)
            .finalize.has_seed_output
            <==> operation == ServerEvalOperation::ExplicitKeyExport,
{
}

// Proves finalize is the only runtime boundary that can carry seed output
// directly; output projection remains metadata-only for every operation.
pub proof fn finalize_is_only_runtime_seed_output_carrier(
    operation: ServerEvalOperation,
)
    ensures
        output_projection_response_has_seed_output_spec() == false,
        finalize_packet_shape_for_operation_spec(operation).has_seed_output
            ==> operation == ServerEvalOperation::ExplicitKeyExport,
        finalize_packet_shape_for_operation_spec(operation).has_seed_output
            ==> output_projection_response_shape_for_operation_spec(operation).allowed_output_kind
                == AllowedOutputKind::ClientOutputAndSeedOutput,
{
}

// Proves the minimal server boundary state carries a single coherent runtime
// boundary story: operation, output-projection metadata, and finalize
// seed-output behavior all encode the same export exception.
pub proof fn server_eval_boundary_state_is_runtime_consistent(
    operation: ServerEvalOperation,
)
    ensures
        server_eval_boundary_state_for_operation_spec(operation)
            .output_projection.allowed_output_kind
            == server_eval_boundary_state_for_operation_spec(operation)
                .finalize.allowed_output_kind,
        server_eval_boundary_state_for_operation_spec(operation)
            .finalize.has_seed_output
            <==> server_eval_boundary_state_for_operation_spec(operation)
                .output_projection.allowed_output_kind
                == AllowedOutputKind::ClientOutputAndSeedOutput,
        server_eval_boundary_state_for_operation_spec(operation)
            .finalize.has_seed_output
            <==> operation == ServerEvalOperation::ExplicitKeyExport,
{
}

// Proves every non-export operation stays entirely on the client-output-only
// side of the runtime boundary: both packet shapes stay client-output-only and
// finalize never carries seed output.
pub proof fn non_export_runtime_boundaries_are_client_output_only(
    operation: ServerEvalOperation,
)
    requires
        operation != ServerEvalOperation::ExplicitKeyExport,
    ensures
        output_projection_response_shape_for_operation_spec(operation).allowed_output_kind
            == AllowedOutputKind::ClientOutputOnly,
        finalize_packet_shape_for_operation_spec(operation).allowed_output_kind
            == AllowedOutputKind::ClientOutputOnly,
        finalize_packet_shape_for_operation_spec(operation).has_seed_output == false,
        server_eval_boundary_state_for_operation_spec(operation)
            .output_projection.allowed_output_kind
            == AllowedOutputKind::ClientOutputOnly,
        server_eval_boundary_state_for_operation_spec(operation)
            .finalize.allowed_output_kind
            == AllowedOutputKind::ClientOutputOnly,
        server_eval_boundary_state_for_operation_spec(operation)
            .finalize.has_seed_output == false,
{
}

} // verus!
