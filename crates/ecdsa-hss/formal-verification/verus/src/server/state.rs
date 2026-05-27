//! Verification entrypoint for finalized retained-state exclusions.
//!
//! Planned proof targets:
//! - forbidden root material is excluded from finalized retained state
//! - accepted finalized state keeps only the narrow retained materials
//! - canonical `x` is never retained server-side after finalize

use vstd::prelude::*;

use crate::server::policy::SessionOperation;

verus! {

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RetainedMaterialKind {
    RawClientRootShare,
    RawRelayerRootShare,
    CanonicalScalar,
    RelayerThresholdShare,
    RelayerPublicKey,
    ThresholdPublicKey,
    ThresholdAddress,
    RetryCounter,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FinalizedRetainedState {
    pub operation: SessionOperation,
    pub raw_root_material_dropped: bool,
    pub keeps_relayer_threshold_share: bool,
    pub keeps_relayer_public_key: bool,
    pub keeps_threshold_public_key: bool,
    pub keeps_threshold_address: bool,
    pub keeps_retry_counter: bool,
    pub keeps_canonical_scalar: bool,
    pub keeps_raw_client_root_share: bool,
    pub keeps_raw_relayer_root_share: bool,
}

pub open spec fn retains_material_spec(
    state: FinalizedRetainedState,
    kind: RetainedMaterialKind,
) -> bool {
    match kind {
        RetainedMaterialKind::RawClientRootShare => state.keeps_raw_client_root_share,
        RetainedMaterialKind::RawRelayerRootShare => state.keeps_raw_relayer_root_share,
        RetainedMaterialKind::CanonicalScalar => state.keeps_canonical_scalar,
        RetainedMaterialKind::RelayerThresholdShare => state.keeps_relayer_threshold_share,
        RetainedMaterialKind::RelayerPublicKey => state.keeps_relayer_public_key,
        RetainedMaterialKind::ThresholdPublicKey => state.keeps_threshold_public_key,
        RetainedMaterialKind::ThresholdAddress => state.keeps_threshold_address,
        RetainedMaterialKind::RetryCounter => state.keeps_retry_counter,
    }
}

pub open spec fn is_forbidden_root_material_spec(
    kind: RetainedMaterialKind,
) -> bool {
    ||| kind == RetainedMaterialKind::RawClientRootShare
    ||| kind == RetainedMaterialKind::RawRelayerRootShare
    ||| kind == RetainedMaterialKind::CanonicalScalar
}

pub open spec fn accepted_finalized_retained_state_spec(
    state: FinalizedRetainedState,
) -> bool {
    &&& state.raw_root_material_dropped
    &&& state.keeps_relayer_threshold_share
    &&& state.keeps_relayer_public_key
    &&& state.keeps_threshold_public_key
    &&& state.keeps_threshold_address
    &&& state.keeps_retry_counter
    &&& !state.keeps_canonical_scalar
    &&& !state.keeps_raw_client_root_share
    &&& !state.keeps_raw_relayer_root_share
}

pub proof fn accepted_finalized_state_excludes_forbidden_root_material(
    state: FinalizedRetainedState,
    kind: RetainedMaterialKind,
)
    requires
        accepted_finalized_retained_state_spec(state),
        is_forbidden_root_material_spec(kind),
    ensures
        !retains_material_spec(state, kind),
{
}

pub proof fn accepted_finalized_state_keeps_only_allowed_server_material(
    state: FinalizedRetainedState,
)
    requires
        accepted_finalized_retained_state_spec(state),
    ensures
        retains_material_spec(state, RetainedMaterialKind::RelayerThresholdShare),
        retains_material_spec(state, RetainedMaterialKind::RelayerPublicKey),
        retains_material_spec(state, RetainedMaterialKind::ThresholdPublicKey),
        retains_material_spec(state, RetainedMaterialKind::ThresholdAddress),
        retains_material_spec(state, RetainedMaterialKind::RetryCounter),
{
}

pub proof fn accepted_finalized_state_requires_raw_root_material_dropped(
    state: FinalizedRetainedState,
)
    requires
        accepted_finalized_retained_state_spec(state),
    ensures
        state.raw_root_material_dropped,
{
}

}
