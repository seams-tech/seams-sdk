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
pub enum RetainedMaterialKindV1 {
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
pub struct FinalizedRetainedStateV1 {
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

pub open spec fn retains_material_v1_spec(
    state: FinalizedRetainedStateV1,
    kind: RetainedMaterialKindV1,
) -> bool {
    match kind {
        RetainedMaterialKindV1::RawClientRootShare => state.keeps_raw_client_root_share,
        RetainedMaterialKindV1::RawRelayerRootShare => state.keeps_raw_relayer_root_share,
        RetainedMaterialKindV1::CanonicalScalar => state.keeps_canonical_scalar,
        RetainedMaterialKindV1::RelayerThresholdShare => state.keeps_relayer_threshold_share,
        RetainedMaterialKindV1::RelayerPublicKey => state.keeps_relayer_public_key,
        RetainedMaterialKindV1::ThresholdPublicKey => state.keeps_threshold_public_key,
        RetainedMaterialKindV1::ThresholdAddress => state.keeps_threshold_address,
        RetainedMaterialKindV1::RetryCounter => state.keeps_retry_counter,
    }
}

pub open spec fn is_forbidden_root_material_v1_spec(
    kind: RetainedMaterialKindV1,
) -> bool {
    ||| kind == RetainedMaterialKindV1::RawClientRootShare
    ||| kind == RetainedMaterialKindV1::RawRelayerRootShare
    ||| kind == RetainedMaterialKindV1::CanonicalScalar
}

pub open spec fn accepted_finalized_retained_state_v1_spec(
    state: FinalizedRetainedStateV1,
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

pub proof fn accepted_finalized_state_excludes_forbidden_root_material_v1(
    state: FinalizedRetainedStateV1,
    kind: RetainedMaterialKindV1,
)
    requires
        accepted_finalized_retained_state_v1_spec(state),
        is_forbidden_root_material_v1_spec(kind),
    ensures
        !retains_material_v1_spec(state, kind),
{
}

pub proof fn accepted_finalized_state_keeps_only_allowed_server_material_v1(
    state: FinalizedRetainedStateV1,
)
    requires
        accepted_finalized_retained_state_v1_spec(state),
    ensures
        retains_material_v1_spec(state, RetainedMaterialKindV1::RelayerThresholdShare),
        retains_material_v1_spec(state, RetainedMaterialKindV1::RelayerPublicKey),
        retains_material_v1_spec(state, RetainedMaterialKindV1::ThresholdPublicKey),
        retains_material_v1_spec(state, RetainedMaterialKindV1::ThresholdAddress),
        retains_material_v1_spec(state, RetainedMaterialKindV1::RetryCounter),
{
}

pub proof fn accepted_finalized_state_requires_raw_root_material_dropped_v1(
    state: FinalizedRetainedStateV1,
)
    requires
        accepted_finalized_retained_state_v1_spec(state),
    ensures
        state.raw_root_material_dropped,
{
}

}
