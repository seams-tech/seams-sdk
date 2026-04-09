//! Verification entrypoint for the narrow output-policy boundary.
//!
//! Planned proof targets:
//! - explicit export as the only canonical-key-revealing operation
//! - non-export operations restricted to signing-only outputs

use vstd::prelude::*;

verus! {

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SessionOperation {
    Sign,
    WarmSessionReconstruction,
    ExplicitKeyExport,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AllowedOutputKind {
    ThresholdSigningOnly,
    CanonicalScalarExport,
}

pub open spec fn allowed_output_kind_for_operation_spec(
    operation: SessionOperation,
) -> AllowedOutputKind {
    match operation {
        SessionOperation::ExplicitKeyExport => AllowedOutputKind::CanonicalScalarExport,
        SessionOperation::Sign | SessionOperation::WarmSessionReconstruction => {
            AllowedOutputKind::ThresholdSigningOnly
        },
    }
}

pub open spec fn is_key_revealing_operation_spec(operation: SessionOperation) -> bool {
    allowed_output_kind_for_operation_spec(operation) == AllowedOutputKind::CanonicalScalarExport
}

pub open spec fn is_non_export_operation_spec(operation: SessionOperation) -> bool {
    operation == SessionOperation::Sign
        || operation == SessionOperation::WarmSessionReconstruction
}

pub proof fn explicit_export_is_the_only_key_revealing_operation(
    operation: SessionOperation,
)
    ensures
        is_key_revealing_operation_spec(operation)
            <==> operation == SessionOperation::ExplicitKeyExport,
{
}

pub proof fn non_export_operations_cannot_return_canonical_x(
    operation: SessionOperation,
)
    requires
        is_non_export_operation_spec(operation),
    ensures
        allowed_output_kind_for_operation_spec(operation)
            == AllowedOutputKind::ThresholdSigningOnly,
        !is_key_revealing_operation_spec(operation),
{
}

}
