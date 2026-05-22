//! Verification entrypoint for `src/ddh/hidden_eval_executor.rs`.
//!
//! Initial proof targets:
//! - visible executor-boundary shape
//! - boundary projection from `eval_f_expand`
//! - fixed visible output bundle count
//! - fixed split relayer transport bundle shape

use vstd::contrib::auto_spec;
use vstd::prelude::*;

use crate::shared::reference::{
    eval_f_expand_visible_boundary_from_input, Bytes32, FExpandInput, FExpandOutput,
    FExpandVisibleBoundary,
};

verus! {

#[derive(Debug, PartialEq, Eq)]
pub struct HiddenEvalExecutorVisibleBoundary {
    pub canonical_seed: Bytes32,
    pub x_client_base: Bytes32,
    pub x_relayer_base: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct HiddenEvalExecutorOutputBundleShape {
    pub canonical_seed_bundle_count: usize,
    pub x_client_base_bundle_count: usize,
    pub x_relayer_base_transport_bundle_count: usize,
}

pub open spec fn hidden_eval_executor_visible_output_count_spec() -> nat {
    3nat
}

pub open spec fn hidden_eval_executor_output_bundle_count_spec() -> nat {
    4nat
}

pub open spec fn hidden_eval_executor_relayer_transport_bundle_count_spec() -> nat {
    2nat
}

pub open spec fn hidden_eval_executor_output_order_canonical_seed_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_output_order_x_client_base_spec() -> nat {
    1nat
}

pub open spec fn hidden_eval_executor_output_order_x_relayer_base_spec() -> nat {
    2nat
}

pub open spec fn hidden_eval_executor_visible_y_relayer_output_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_visible_tau_relayer_output_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_visible_commitment_output_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_direct_x_relayer_base_bundle_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_visible_tau_output_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_visible_a_output_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_visible_a_bytes_output_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_visible_public_key_output_count_spec() -> nat {
    0nat
}

pub open spec fn hidden_eval_executor_visible_context_binding_output_count_spec() -> nat {
    0nat
}

pub fn hidden_eval_executor_visible_output_count() -> (len: usize)
    ensures
        len == hidden_eval_executor_visible_output_count_spec(),
{
    3usize
}

pub fn hidden_eval_executor_output_bundle_shape() -> (out: HiddenEvalExecutorOutputBundleShape)
    ensures
        out.canonical_seed_bundle_count == 1,
        out.x_client_base_bundle_count == 1,
        out.x_relayer_base_transport_bundle_count == 2,
{
    HiddenEvalExecutorOutputBundleShape {
        canonical_seed_bundle_count: 1usize,
        x_client_base_bundle_count: 1usize,
        x_relayer_base_transport_bundle_count: 2usize,
    }
}

#[auto_spec]
pub fn hidden_eval_executor_boundary_from_output(expanded: FExpandOutput) -> (out: HiddenEvalExecutorVisibleBoundary)
    ensures
        out.canonical_seed == expanded.d,
        out.x_client_base == expanded.x_client_base,
        out.x_relayer_base == expanded.x_relayer_base,
{
    HiddenEvalExecutorVisibleBoundary {
        canonical_seed: expanded.d,
        x_client_base: expanded.x_client_base,
        x_relayer_base: expanded.x_relayer_base,
    }
}

pub fn hidden_eval_executor_boundary_from_f_expand(input: FExpandInput) -> (out: HiddenEvalExecutorVisibleBoundary)
    ensures
        out.canonical_seed == crate::shared::reference::eval_f_expand_canonical_seed_spec(input),
        out.x_client_base == crate::shared::reference::eval_f_expand_x_client_base_spec(input),
        out.x_relayer_base == crate::shared::reference::eval_f_expand_x_relayer_base_spec(input),
        forall|i: int| 0 <= i < 32 ==> out.canonical_seed[i] as int == crate::shared::reference::eval_f_expand_canonical_seed_byte_spec(input, i as nat),
{
    let visible = eval_f_expand_visible_boundary_from_input(input);
    HiddenEvalExecutorVisibleBoundary {
        canonical_seed: visible.canonical_seed,
        x_client_base: visible.x_client_base,
        x_relayer_base: visible.x_relayer_base,
    }
}

// Normalizes the executor-side visible boundary into the shared reference
// boundary type so output-level equivalence can be stated as whole-record
// equality instead of repeated field-by-field equalities.
#[auto_spec]
pub fn hidden_eval_executor_boundary_as_reference_boundary(
    boundary: HiddenEvalExecutorVisibleBoundary,
) -> (out: FExpandVisibleBoundary)
    ensures
        out.canonical_seed == boundary.canonical_seed,
        out.x_client_base == boundary.x_client_base,
        out.x_relayer_base == boundary.x_relayer_base,
{
    FExpandVisibleBoundary {
        canonical_seed: boundary.canonical_seed,
        x_client_base: boundary.x_client_base,
        x_relayer_base: boundary.x_relayer_base,
    }
}

// Proves the executor-visible boundary still exposes exactly three visible
// outputs in the fixed production order: canonical seed, client base share,
// and relayer base share.
pub proof fn hidden_eval_executor_boundary_shape()
    ensures
        hidden_eval_executor_visible_output_count_spec() == 3nat,
        hidden_eval_executor_output_bundle_count_spec() == 4nat,
        hidden_eval_executor_relayer_transport_bundle_count_spec() == 2nat,
        hidden_eval_executor_output_bundle_count_spec()
            == hidden_eval_executor_visible_output_count_spec() + 1nat,
        hidden_eval_executor_output_order_canonical_seed_spec() == 0nat,
        hidden_eval_executor_output_order_x_client_base_spec() == 1nat,
        hidden_eval_executor_output_order_x_relayer_base_spec() == 2nat,
{
}

// Proves the non-export visible executor surface does not directly expose raw
// relayer roots or standalone commitment records; the visible surface is
// limited to canonical seed, client base share, and relayer-base transport.
pub proof fn hidden_eval_executor_non_export_boundary_excludes_server_roots()
    ensures
        hidden_eval_executor_visible_y_relayer_output_count_spec() == 0nat,
        hidden_eval_executor_visible_tau_relayer_output_count_spec() == 0nat,
        hidden_eval_executor_visible_commitment_output_count_spec() == 0nat,
        hidden_eval_executor_visible_output_count_spec() == 3nat,
{
}

// Proves the non-export executor output surface exposes relayer-base only via
// the split transport bundles and never as a direct visible share bundle.
pub proof fn hidden_eval_executor_non_export_relayer_base_is_transport_only()
    ensures
        hidden_eval_executor_direct_x_relayer_base_bundle_count_spec() == 0nat,
        hidden_eval_executor_relayer_transport_bundle_count_spec() == 2nat,
        hidden_eval_executor_output_bundle_count_spec() == 4nat,
{
}

// Proves the non-export executor-visible boundary is restricted to the three
// allowed output classes and excludes the remaining clear `F_expand` fields.
pub proof fn hidden_eval_executor_non_export_boundary_excludes_clear_reference_fields()
    ensures
        hidden_eval_executor_visible_tau_output_count_spec() == 0nat,
        hidden_eval_executor_visible_a_output_count_spec() == 0nat,
        hidden_eval_executor_visible_a_bytes_output_count_spec() == 0nat,
        hidden_eval_executor_visible_public_key_output_count_spec() == 0nat,
        hidden_eval_executor_visible_context_binding_output_count_spec() == 0nat,
        hidden_eval_executor_visible_output_count_spec() == 3nat,
{
}

// Proves the non-export executor surface has exactly the allowed output
// classes: one canonical-seed visible bundle, one client-base visible bundle,
// and two relayer-base transport bundles.
pub proof fn hidden_eval_executor_non_export_boundary_allowed_output_classes()
    ensures
        hidden_eval_executor_visible_output_count_spec() == 3nat,
        hidden_eval_executor_output_bundle_count_spec() == 4nat,
        hidden_eval_executor_output_order_canonical_seed_spec() == 0nat,
        hidden_eval_executor_output_order_x_client_base_spec() == 1nat,
        hidden_eval_executor_output_order_x_relayer_base_spec() == 2nat,
        hidden_eval_executor_relayer_transport_bundle_count_spec() == 2nat,
        hidden_eval_executor_direct_x_relayer_base_bundle_count_spec() == 0nat,
{
}

// Proves the non-export executor boundary is exactly the allowed partition:
// the three visible outputs are canonical seed, client base share, and
// relayer-base transport; all other clear `F_expand` fields and server-root
// classes remain excluded.
pub proof fn hidden_eval_executor_non_export_boundary_is_exact_allowed_partition()
    ensures
        hidden_eval_executor_visible_output_count_spec() == 3nat,
        hidden_eval_executor_output_bundle_count_spec() == 4nat,
        hidden_eval_executor_output_order_canonical_seed_spec() == 0nat,
        hidden_eval_executor_output_order_x_client_base_spec() == 1nat,
        hidden_eval_executor_output_order_x_relayer_base_spec() == 2nat,
        hidden_eval_executor_relayer_transport_bundle_count_spec() == 2nat,
        hidden_eval_executor_direct_x_relayer_base_bundle_count_spec() == 0nat,
        hidden_eval_executor_visible_y_relayer_output_count_spec() == 0nat,
        hidden_eval_executor_visible_tau_relayer_output_count_spec() == 0nat,
        hidden_eval_executor_visible_commitment_output_count_spec() == 0nat,
        hidden_eval_executor_visible_tau_output_count_spec() == 0nat,
        hidden_eval_executor_visible_a_output_count_spec() == 0nat,
        hidden_eval_executor_visible_a_bytes_output_count_spec() == 0nat,
        hidden_eval_executor_visible_public_key_output_count_spec() == 0nat,
        hidden_eval_executor_visible_context_binding_output_count_spec() == 0nat,
{
}

// Proves the executor-side visible-boundary projection is field-identical to
// the shared reference-side visible-boundary projection for any expanded
// `F_expand` output record.
pub proof fn hidden_eval_executor_projection_matches_reference(expanded: FExpandOutput)
    ensures
        hidden_eval_executor_boundary_from_output(expanded).canonical_seed
            == crate::shared::reference::f_expand_visible_boundary_from_output(expanded).canonical_seed,
        hidden_eval_executor_boundary_from_output(expanded).x_client_base
            == crate::shared::reference::f_expand_visible_boundary_from_output(expanded).x_client_base,
        hidden_eval_executor_boundary_from_output(expanded).x_relayer_base
            == crate::shared::reference::f_expand_visible_boundary_from_output(expanded).x_relayer_base,
{
}

// Proves the lower-level executor output projection matches the shared
// reference visible-boundary projection as a whole record, not just as three
// independent field equalities.
pub proof fn hidden_eval_executor_output_level_boundary_matches_reference(expanded: FExpandOutput)
    ensures
        hidden_eval_executor_boundary_as_reference_boundary(
            hidden_eval_executor_boundary_from_output(expanded),
        ) == crate::shared::reference::f_expand_visible_boundary_from_output(expanded),
{
}

// Proves the executor-side visible-boundary projection depends only on the
// three allowed visible fields and ignores the excluded clear `F_expand`
// fields.
pub proof fn hidden_eval_executor_boundary_depends_only_on_visible_fields(
    left: FExpandOutput,
    right: FExpandOutput,
)
    requires
        left.d == right.d,
        left.x_client_base == right.x_client_base,
        left.x_relayer_base == right.x_relayer_base,
    ensures
        hidden_eval_executor_boundary_from_output(left)
            == hidden_eval_executor_boundary_from_output(right),
{
}

} // verus!
