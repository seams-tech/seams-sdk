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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OutputProjectionMode {
    TrustedServerProjection,
    ClientMaskedProjection,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ClientOutputValueKind {
    UnmaskedClientBase,
    ClientBlindedBase,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ClientOwnedWasmRequestKind {
    BuildClientOwnedStagedEvaluatorArtifact,
    OpenClientOutput,
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
pub struct StagedEvaluatorArtifactShape {
    pub projection_mode: OutputProjectionMode,
    pub client_output_value_kind: ClientOutputValueKind,
    pub has_client_output_commitment: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientOwnedWasmRequestShape {
    pub has_client_output_mask_b64u: bool,
    pub client_output_mask_len: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerEvalFinalizeRetainedShape {
    pub has_seed_commitment: bool,
    pub has_server_output_transport: bool,
    pub has_client_output_bundle: bool,
    pub has_client_output_value_kind: bool,
    pub has_client_output_commitment: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerFinalizeValidationShape {
    pub retained: ServerEvalFinalizeRetainedShape,
    pub artifact: StagedEvaluatorArtifactShape,
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

pub open spec fn client_output_value_kind_for_projection_mode_spec(
    projection_mode: OutputProjectionMode,
) -> ClientOutputValueKind {
    match projection_mode {
        OutputProjectionMode::TrustedServerProjection => ClientOutputValueKind::UnmaskedClientBase,
        OutputProjectionMode::ClientMaskedProjection => ClientOutputValueKind::ClientBlindedBase,
    }
}

pub open spec fn fixed_client_output_mask_bytes_spec() -> nat {
    32nat
}

pub open spec fn client_owned_wasm_request_shape_spec(
    kind: ClientOwnedWasmRequestKind,
) -> ClientOwnedWasmRequestShape {
    match kind {
        ClientOwnedWasmRequestKind::BuildClientOwnedStagedEvaluatorArtifact => {
            ClientOwnedWasmRequestShape {
                has_client_output_mask_b64u: true,
                client_output_mask_len: 32usize,
            }
        },
        ClientOwnedWasmRequestKind::OpenClientOutput => {
            ClientOwnedWasmRequestShape {
                has_client_output_mask_b64u: true,
                client_output_mask_len: 32usize,
            }
        },
    }
}

pub fn fixed_client_output_mask_bytes() -> (len: usize)
    ensures
        len == fixed_client_output_mask_bytes_spec(),
{
    32usize
}

pub fn client_owned_wasm_request_shape(
    kind: ClientOwnedWasmRequestKind,
) -> (out: ClientOwnedWasmRequestShape)
    ensures
        out == client_owned_wasm_request_shape_spec(kind),
        out.has_client_output_mask_b64u,
        out.client_output_mask_len == fixed_client_output_mask_bytes_spec(),
{
    match kind {
        ClientOwnedWasmRequestKind::BuildClientOwnedStagedEvaluatorArtifact => {
            ClientOwnedWasmRequestShape {
                has_client_output_mask_b64u: true,
                client_output_mask_len: fixed_client_output_mask_bytes(),
            }
        },
        ClientOwnedWasmRequestKind::OpenClientOutput => {
            ClientOwnedWasmRequestShape {
                has_client_output_mask_b64u: true,
                client_output_mask_len: fixed_client_output_mask_bytes(),
            }
        },
    }
}

pub fn client_output_value_kind_for_projection_mode(
    projection_mode: OutputProjectionMode,
) -> (out: ClientOutputValueKind)
    ensures
        out == client_output_value_kind_for_projection_mode_spec(projection_mode),
{
    match projection_mode {
        OutputProjectionMode::TrustedServerProjection => ClientOutputValueKind::UnmaskedClientBase,
        OutputProjectionMode::ClientMaskedProjection => ClientOutputValueKind::ClientBlindedBase,
    }
}

pub open spec fn staged_artifact_shape_for_projection_spec(
    projection_mode: OutputProjectionMode,
) -> StagedEvaluatorArtifactShape {
    StagedEvaluatorArtifactShape {
        projection_mode,
        client_output_value_kind: client_output_value_kind_for_projection_mode_spec(
            projection_mode,
        ),
        has_client_output_commitment: true,
    }
}

pub fn staged_artifact_shape_for_projection(
    projection_mode: OutputProjectionMode,
) -> (out: StagedEvaluatorArtifactShape)
    ensures
        out == staged_artifact_shape_for_projection_spec(projection_mode),
{
    StagedEvaluatorArtifactShape {
        projection_mode,
        client_output_value_kind: client_output_value_kind_for_projection_mode(projection_mode),
        has_client_output_commitment: true,
    }
}

pub open spec fn staged_artifact_shape_is_valid_for_finalize_spec(
    artifact: StagedEvaluatorArtifactShape,
) -> bool {
    artifact.has_client_output_commitment
        && artifact.client_output_value_kind
            == client_output_value_kind_for_projection_mode_spec(artifact.projection_mode)
}

pub open spec fn server_finalize_retained_shape_spec() -> ServerEvalFinalizeRetainedShape {
    ServerEvalFinalizeRetainedShape {
        has_seed_commitment: true,
        has_server_output_transport: true,
        has_client_output_bundle: false,
        has_client_output_value_kind: false,
        has_client_output_commitment: false,
    }
}

pub fn server_finalize_retained_shape() -> (out: ServerEvalFinalizeRetainedShape)
    ensures
        out == server_finalize_retained_shape_spec(),
{
    ServerEvalFinalizeRetainedShape {
        has_seed_commitment: true,
        has_server_output_transport: true,
        has_client_output_bundle: false,
        has_client_output_value_kind: false,
        has_client_output_commitment: false,
    }
}

pub open spec fn server_finalize_retained_shape_excludes_client_output_spec(
    retained: ServerEvalFinalizeRetainedShape,
) -> bool {
    retained.has_seed_commitment
        && retained.has_server_output_transport
        && !retained.has_client_output_bundle
        && !retained.has_client_output_value_kind
        && !retained.has_client_output_commitment
}

pub open spec fn server_finalize_validation_shape_for_projection_spec(
    projection_mode: OutputProjectionMode,
) -> ServerFinalizeValidationShape {
    ServerFinalizeValidationShape {
        retained: server_finalize_retained_shape_spec(),
        artifact: staged_artifact_shape_for_projection_spec(projection_mode),
    }
}

pub fn server_finalize_validation_shape_for_projection(
    projection_mode: OutputProjectionMode,
) -> (out: ServerFinalizeValidationShape)
    ensures
        out == server_finalize_validation_shape_for_projection_spec(projection_mode),
{
    ServerFinalizeValidationShape {
        retained: server_finalize_retained_shape(),
        artifact: staged_artifact_shape_for_projection(projection_mode),
    }
}

pub open spec fn server_finalize_validation_accepts_spec(
    validation: ServerFinalizeValidationShape,
) -> bool {
    server_finalize_retained_shape_excludes_client_output_spec(validation.retained)
        && staged_artifact_shape_is_valid_for_finalize_spec(validation.artifact)
}

pub open spec fn client_owned_finalization_projection_mode_spec() -> OutputProjectionMode {
    OutputProjectionMode::ClientMaskedProjection
}

pub fn client_owned_finalization_projection_mode() -> (out: OutputProjectionMode)
    ensures
        out == client_owned_finalization_projection_mode_spec(),
{
    OutputProjectionMode::ClientMaskedProjection
}

pub open spec fn ed25519_scalar_modulus_l_spec() -> int {
    723700557733226221397318656304299424085711635937990760600195093828545425057int
}

pub open spec fn server_only_projector_relayer_expr_spec(a: int, tau: int) -> int {
    (a + 2int * tau) % ed25519_scalar_modulus_l_spec()
}

pub open spec fn legacy_projector_relayer_expr_spec(a: int, tau: int) -> int {
    ((a + tau) + tau) % ed25519_scalar_modulus_l_spec()
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

// Proves the projection-mode boundary is total and deterministic: every mode
// has exactly one valid client-output value kind.
pub proof fn projection_mode_to_client_output_value_kind_is_total_and_deterministic(
    projection_mode: OutputProjectionMode,
)
    ensures
        client_output_value_kind_for_projection_mode_spec(projection_mode)
            == ClientOutputValueKind::UnmaskedClientBase
            <==> projection_mode == OutputProjectionMode::TrustedServerProjection,
        client_output_value_kind_for_projection_mode_spec(projection_mode)
            == ClientOutputValueKind::ClientBlindedBase
            <==> projection_mode == OutputProjectionMode::ClientMaskedProjection,
{
    match projection_mode {
        OutputProjectionMode::TrustedServerProjection => {}
        OutputProjectionMode::ClientMaskedProjection => {}
    }
}

// Proves staged artifacts carry the public client-output metadata that server
// finalization needs after retained server state drops client-output fields.
pub proof fn staged_artifact_shape_matches_projection(
    projection_mode: OutputProjectionMode,
)
    ensures
        staged_artifact_shape_is_valid_for_finalize_spec(
            staged_artifact_shape_for_projection_spec(projection_mode),
        ),
        staged_artifact_shape_for_projection_spec(projection_mode).has_client_output_commitment,
        staged_artifact_shape_for_projection_spec(projection_mode).client_output_value_kind
            == client_output_value_kind_for_projection_mode_spec(projection_mode),
{
}

// Proves retained server finalize state has only the server-side material
// needed for finalization binding.
pub proof fn server_finalize_retained_state_excludes_client_output_metadata()
    ensures
        server_finalize_retained_shape_excludes_client_output_spec(
            server_finalize_retained_shape_spec(),
        ),
        server_finalize_retained_shape_spec().has_seed_commitment,
        server_finalize_retained_shape_spec().has_server_output_transport,
        !server_finalize_retained_shape_spec().has_client_output_bundle,
        !server_finalize_retained_shape_spec().has_client_output_value_kind,
        !server_finalize_retained_shape_spec().has_client_output_commitment,
{
}

// Proves finalization binds client-output metadata from the staged artifact
// while retained server state stays free of client-output metadata.
pub proof fn server_finalize_validation_combines_retained_and_artifact_metadata(
    projection_mode: OutputProjectionMode,
)
    ensures
        server_finalize_validation_accepts_spec(
            server_finalize_validation_shape_for_projection_spec(projection_mode),
        ),
        server_finalize_validation_shape_for_projection_spec(projection_mode)
            .artifact.client_output_value_kind
            == client_output_value_kind_for_projection_mode_spec(projection_mode),
        !server_finalize_validation_shape_for_projection_spec(projection_mode)
            .retained.has_client_output_bundle,
        !server_finalize_validation_shape_for_projection_spec(projection_mode)
            .retained.has_client_output_value_kind,
        !server_finalize_validation_shape_for_projection_spec(projection_mode)
            .retained.has_client_output_commitment,
{
}

// Proves masked projection finalization accepts only blinded client output.
pub proof fn client_masked_projection_finalize_accepts_only_blinded_output()
    ensures
        staged_artifact_shape_for_projection_spec(
            OutputProjectionMode::ClientMaskedProjection,
        ).client_output_value_kind == ClientOutputValueKind::ClientBlindedBase,
        staged_artifact_shape_for_projection_spec(
            OutputProjectionMode::ClientMaskedProjection,
        ).client_output_value_kind != ClientOutputValueKind::UnmaskedClientBase,
{
}

// Proves client-owned finalization uses the masked projection boundary and
// therefore accepts only blinded client output.
pub proof fn client_owned_finalization_requires_client_masked_projection()
    ensures
        client_owned_finalization_projection_mode_spec()
            == OutputProjectionMode::ClientMaskedProjection,
        staged_artifact_shape_for_projection_spec(
            client_owned_finalization_projection_mode_spec(),
        ).client_output_value_kind == ClientOutputValueKind::ClientBlindedBase,
        staged_artifact_shape_for_projection_spec(
            client_owned_finalization_projection_mode_spec(),
        ).client_output_value_kind != ClientOutputValueKind::UnmaskedClientBase,
{
}

// Proves client-owned WASM/SDK boundary calls always include a fixed-width
// client output mask in the modeled request shape.
pub proof fn client_owned_wasm_boundary_requests_require_fixed_client_output_mask()
    ensures
        client_owned_wasm_request_shape_spec(
            ClientOwnedWasmRequestKind::BuildClientOwnedStagedEvaluatorArtifact,
        ).has_client_output_mask_b64u,
        client_owned_wasm_request_shape_spec(
            ClientOwnedWasmRequestKind::BuildClientOwnedStagedEvaluatorArtifact,
        ).client_output_mask_len == fixed_client_output_mask_bytes_spec(),
        client_owned_wasm_request_shape_spec(
            ClientOwnedWasmRequestKind::OpenClientOutput,
        ).has_client_output_mask_b64u,
        client_owned_wasm_request_shape_spec(
            ClientOwnedWasmRequestKind::OpenClientOutput,
        ).client_output_mask_len == fixed_client_output_mask_bytes_spec(),
{
}

// Proves trusted-server projection finalization accepts only unmasked client
// output.
pub proof fn trusted_server_projection_finalize_accepts_only_unmasked_output()
    ensures
        staged_artifact_shape_for_projection_spec(
            OutputProjectionMode::TrustedServerProjection,
        ).client_output_value_kind == ClientOutputValueKind::UnmaskedClientBase,
        staged_artifact_shape_for_projection_spec(
            OutputProjectionMode::TrustedServerProjection,
        ).client_output_value_kind != ClientOutputValueKind::ClientBlindedBase,
{
}

// Proves the server-only projector expression is algebraically equivalent to
// the legacy two-step expression while avoiding an explicit client-output term.
pub proof fn server_only_projector_expression_matches_legacy(a: int, tau: int)
    ensures
        ed25519_scalar_modulus_l_spec() > 0,
        server_only_projector_relayer_expr_spec(a, tau)
            == legacy_projector_relayer_expr_spec(a, tau),
{
    assert(ed25519_scalar_modulus_l_spec() > 0);
    assert(a + 2int * tau == (a + tau) + tau) by(nonlinear_arith);
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
