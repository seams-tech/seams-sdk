//! Abstract Verus model for the active threshold-prf policy surface.
//!
//! The model proves boundary and subset properties without depending on
//! Ristretto, SHA-512, or production byte encoders. Cryptographic primitives
//! remain trusted seams.

use vstd::prelude::*;

verus! {

#[derive(PartialEq, Eq)]
pub struct ThresholdPolicySpec {
    pub threshold: nat,
    pub share_count: nat,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SigningRootShareSpec {
    pub id: u16,
    pub value: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SigningRootShareWireSpec {
    pub share_id: u16,
    pub scalar: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrfPartialProofBundleIdsSpec {
    pub partial_id: u16,
    pub commitment_id: u16,
}

pub open spec fn max_share_count_spec() -> nat {
    255nat
}

pub open spec fn scalar_width_bytes_spec() -> nat {
    32nat
}

pub open spec fn signing_root_share_wire_width_bytes_spec() -> nat {
    34nat
}

pub open spec fn partial_wire_width_bytes_spec() -> nat {
    66nat
}

pub open spec fn share_commitment_wire_width_bytes_spec() -> nat {
    34nat
}

pub open spec fn dleq_proof_wire_width_bytes_spec() -> nat {
    64nat
}

pub open spec fn proof_bundle_wire_width_bytes_spec() -> nat {
    partial_wire_width_bytes_spec() + share_commitment_wire_width_bytes_spec()
        + dleq_proof_wire_width_bytes_spec()
}

pub open spec fn is_field_element_spec(value: u8) -> bool {
    value < 251
}

pub open spec fn is_valid_signing_root_scalar_spec(value: u8) -> bool {
    is_field_element_spec(value) && value != 0
}

pub open spec fn is_valid_signing_root_share_scalar_spec(value: u8) -> bool {
    is_field_element_spec(value)
}

pub open spec fn threshold_policy_spec(
    threshold: nat,
    share_count: nat,
) -> Option<ThresholdPolicySpec> {
    if threshold >= 1nat && share_count >= 1nat && threshold <= share_count
        && share_count <= max_share_count_spec()
    {
        Some(ThresholdPolicySpec { threshold, share_count })
    } else {
        None
    }
}

pub open spec fn is_valid_share_id_spec(policy: ThresholdPolicySpec, id: u16) -> bool {
    1nat <= id as nat && id as nat <= policy.share_count
}

pub open spec fn validate_threshold_subset_2_spec(
    policy: ThresholdPolicySpec,
    first: u16,
    second: u16,
) -> bool {
    policy.threshold == 2nat
        && is_valid_share_id_spec(policy, first)
        && is_valid_share_id_spec(policy, second)
        && first != second
}

pub open spec fn validate_threshold_subset_3_spec(
    policy: ThresholdPolicySpec,
    first: u16,
    second: u16,
    third: u16,
) -> bool {
    policy.threshold == 3nat
        && is_valid_share_id_spec(policy, first)
        && is_valid_share_id_spec(policy, second)
        && is_valid_share_id_spec(policy, third)
        && first != second
        && first != third
        && second != third
}

pub open spec fn signing_root_share_spec(id: u16, value: u8) -> SigningRootShareSpec {
    SigningRootShareSpec { id, value }
}

pub open spec fn signing_root_share_wire_from_share_spec(
    share: SigningRootShareSpec,
) -> SigningRootShareWireSpec {
    SigningRootShareWireSpec {
        share_id: share.id,
        scalar: share.value,
    }
}

pub open spec fn decode_signing_root_share_wire_spec(
    policy: ThresholdPolicySpec,
    wire_len: nat,
    wire: SigningRootShareWireSpec,
) -> Option<SigningRootShareSpec> {
    if wire_len == signing_root_share_wire_width_bytes_spec()
        && is_valid_share_id_spec(policy, wire.share_id)
        && is_valid_signing_root_share_scalar_spec(wire.scalar)
    {
        Some(SigningRootShareSpec {
            id: wire.share_id,
            value: wire.scalar,
        })
    } else {
        None
    }
}

pub open spec fn validate_proof_bundle_id_binding_spec(
    policy: ThresholdPolicySpec,
    bundle: PrfPartialProofBundleIdsSpec,
) -> bool {
    is_valid_share_id_spec(policy, bundle.partial_id)
        && is_valid_share_id_spec(policy, bundle.commitment_id)
        && bundle.partial_id == bundle.commitment_id
}

pub uninterp spec fn reconstruct_generated_root_2_spec(
    policy: ThresholdPolicySpec,
    root: u8,
    slope: u8,
    first: u16,
    second: u16,
) -> u8;

pub uninterp spec fn reconstruct_generated_root_3_spec(
    policy: ThresholdPolicySpec,
    root: u8,
    slope_1: u8,
    slope_2: u8,
    first: u16,
    second: u16,
    third: u16,
) -> u8;

pub broadcast axiom fn axiom_two_share_reconstruction_outputs_root(
    policy: ThresholdPolicySpec,
    root: u8,
    slope: u8,
    first: u16,
    second: u16,
)
    requires
        is_valid_signing_root_scalar_spec(root),
        is_valid_signing_root_scalar_spec(slope),
        validate_threshold_subset_2_spec(policy, first, second),
    ensures
        #![trigger reconstruct_generated_root_2_spec(policy, root, slope, first, second)]
        reconstruct_generated_root_2_spec(policy, root, slope, first, second) == root,
;

pub broadcast axiom fn axiom_three_share_reconstruction_outputs_root(
    policy: ThresholdPolicySpec,
    root: u8,
    slope_1: u8,
    slope_2: u8,
    first: u16,
    second: u16,
    third: u16,
)
    requires
        is_valid_signing_root_scalar_spec(root),
        is_valid_signing_root_scalar_spec(slope_1),
        is_valid_signing_root_scalar_spec(slope_2),
        validate_threshold_subset_3_spec(policy, first, second, third),
    ensures
        #![trigger reconstruct_generated_root_3_spec(
            policy,
            root,
            slope_1,
            slope_2,
            first,
            second,
            third,
        )]
        reconstruct_generated_root_3_spec(
            policy,
            root,
            slope_1,
            slope_2,
            first,
            second,
            third,
        ) == root,
;

pub proof fn wire_widths_are_fixed()
    ensures
        scalar_width_bytes_spec() == 32nat,
        signing_root_share_wire_width_bytes_spec() == 34nat,
        partial_wire_width_bytes_spec() == 66nat,
        share_commitment_wire_width_bytes_spec() == 34nat,
        dleq_proof_wire_width_bytes_spec() == 64nat,
        proof_bundle_wire_width_bytes_spec() == 164nat,
{
}

pub proof fn policy_rejects_zero_threshold(share_count: nat)
    ensures
        threshold_policy_spec(0nat, share_count) == None::<ThresholdPolicySpec>,
{
}

pub proof fn policy_rejects_zero_share_count(threshold: nat)
    ensures
        threshold_policy_spec(threshold, 0nat) == None::<ThresholdPolicySpec>,
{
}

pub proof fn policy_rejects_threshold_above_share_count(threshold: nat, share_count: nat)
    requires
        threshold > share_count,
    ensures
        threshold_policy_spec(threshold, share_count) == None::<ThresholdPolicySpec>,
{
}

pub proof fn policy_accepts_common_thresholds()
    ensures
        threshold_policy_spec(1nat, 1nat)
            == Some(ThresholdPolicySpec { threshold: 1nat, share_count: 1nat }),
        threshold_policy_spec(2nat, 3nat)
            == Some(ThresholdPolicySpec { threshold: 2nat, share_count: 3nat }),
        threshold_policy_spec(3nat, 5nat)
            == Some(ThresholdPolicySpec { threshold: 3nat, share_count: 5nat }),
{
}

pub proof fn share_id_membership_matches_policy_range(policy: ThresholdPolicySpec, id: u16)
    ensures
        is_valid_share_id_spec(policy, id)
            == (1nat <= id as nat && id as nat <= policy.share_count),
{
}

pub proof fn two_share_subset_rejects_duplicate_id(policy: ThresholdPolicySpec, id: u16)
    ensures
        !validate_threshold_subset_2_spec(policy, id, id),
{
}

pub proof fn three_share_subset_rejects_duplicate_id(
    policy: ThresholdPolicySpec,
    first: u16,
    second: u16,
    third: u16,
)
    requires
        first == second || first == third || second == third,
    ensures
        !validate_threshold_subset_3_spec(policy, first, second, third),
{
}

pub proof fn two_share_subset_rejects_id_outside_policy(
    policy: ThresholdPolicySpec,
    valid_id: u16,
    outside_id: u16,
)
    requires
        !(1nat <= outside_id as nat && outside_id as nat <= policy.share_count),
    ensures
        !validate_threshold_subset_2_spec(policy, valid_id, outside_id),
{
}

pub proof fn two_of_three_subset_is_valid()
    ensures
        validate_threshold_subset_2_spec(
            ThresholdPolicySpec { threshold: 2nat, share_count: 3nat },
            1u16,
            3u16,
        ),
{
}

pub proof fn three_of_five_subset_is_valid()
    ensures
        validate_threshold_subset_3_spec(
            ThresholdPolicySpec { threshold: 3nat, share_count: 5nat },
            1u16,
            3u16,
            5u16,
        ),
{
}

pub proof fn share_wire_rejects_wrong_length(
    policy: ThresholdPolicySpec,
    wire_len: nat,
    wire: SigningRootShareWireSpec,
)
    requires
        wire_len != signing_root_share_wire_width_bytes_spec(),
    ensures
        decode_signing_root_share_wire_spec(policy, wire_len, wire)
            == None::<SigningRootShareSpec>,
{
}

pub proof fn share_wire_rejects_id_outside_policy(
    policy: ThresholdPolicySpec,
    wire: SigningRootShareWireSpec,
)
    requires
        !is_valid_share_id_spec(policy, wire.share_id),
    ensures
        decode_signing_root_share_wire_spec(
            policy,
            signing_root_share_wire_width_bytes_spec(),
            wire,
        ) == None::<SigningRootShareSpec>,
{
}

pub proof fn share_wire_round_trips_for_policy_member(
    policy: ThresholdPolicySpec,
    share: SigningRootShareSpec,
)
    requires
        is_valid_share_id_spec(policy, share.id),
        is_valid_signing_root_share_scalar_spec(share.value),
    ensures
        decode_signing_root_share_wire_spec(
            policy,
            signing_root_share_wire_width_bytes_spec(),
            signing_root_share_wire_from_share_spec(share),
        ) == Some(share),
{
}

pub proof fn proof_bundle_id_binding_rejects_commitment_partial_id_mismatch(
    policy: ThresholdPolicySpec,
    bundle: PrfPartialProofBundleIdsSpec,
)
    requires
        bundle.partial_id != bundle.commitment_id,
    ensures
        !validate_proof_bundle_id_binding_spec(policy, bundle),
{
}

pub proof fn proof_bundle_id_binding_rejects_commitment_id_outside_policy(
    policy: ThresholdPolicySpec,
    bundle: PrfPartialProofBundleIdsSpec,
)
    requires
        !is_valid_share_id_spec(policy, bundle.commitment_id),
    ensures
        !validate_proof_bundle_id_binding_spec(policy, bundle),
{
}

pub proof fn every_valid_two_share_subset_reconstructs_root(
    policy: ThresholdPolicySpec,
    root: u8,
    slope: u8,
    first: u16,
    second: u16,
)
    requires
        is_valid_signing_root_scalar_spec(root),
        is_valid_signing_root_scalar_spec(slope),
        validate_threshold_subset_2_spec(policy, first, second),
    ensures
        reconstruct_generated_root_2_spec(policy, root, slope, first, second) == root,
{
    broadcast use axiom_two_share_reconstruction_outputs_root;
}

pub proof fn every_valid_three_share_subset_reconstructs_root(
    policy: ThresholdPolicySpec,
    root: u8,
    slope_1: u8,
    slope_2: u8,
    first: u16,
    second: u16,
    third: u16,
)
    requires
        is_valid_signing_root_scalar_spec(root),
        is_valid_signing_root_scalar_spec(slope_1),
        is_valid_signing_root_scalar_spec(slope_2),
        validate_threshold_subset_3_spec(policy, first, second, third),
    ensures
        reconstruct_generated_root_3_spec(
            policy,
            root,
            slope_1,
            slope_2,
            first,
            second,
            third,
        ) == root,
{
    broadcast use axiom_three_share_reconstruction_outputs_root;
}

} // verus!
