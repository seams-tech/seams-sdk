//! Abstract Verus model for the threshold-prf v1 specs.
//!
//! The model uses a tiny abstract field domain (`0..5`) to prove protocol
//! wiring properties without depending on Ristretto, SHA-512, or production
//! byte encoders. The cryptographic primitives remain trusted seams.

use vstd::prelude::*;

verus! {

pub type Bytes32 = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
pub struct PrfContextV1 {
    pub suite_id: u8,
    pub purpose_id: u8,
    pub context_id: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrfOutputDerivationInputV1 {
    pub suite_id: u8,
    pub purpose_id: u8,
    pub context_id: u8,
    pub point_coeff: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProjectRootShareV1 {
    pub id: u8,
    pub value: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProjectRootShareWireV1Spec {
    pub share_id: u8,
    pub scalar: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrfPartialV1 {
    pub id: u8,
    pub context_tag: Bytes32,
    pub point_coeff: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrfPartialWireV1 {
    pub share_id: u8,
    pub context_tag: Bytes32,
    pub compressed_point: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProjectRootShareCommitmentV1Spec {
    pub id: u8,
    pub point_coeff: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrfDleqProofV1Spec {
    pub challenge: u8,
    pub response: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrfPartialProofBundleV1Spec {
    pub partial: PrfPartialV1,
    pub commitment: ProjectRootShareCommitmentV1Spec,
    pub proof: PrfDleqProofV1Spec,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DleqChallengeInputV1Spec {
    pub suite_id: u8,
    pub purpose_id: u8,
    pub context_tag: Bytes32,
    pub share_id: u8,
    pub basepoint_id: u8,
    pub input_point_id: u8,
    pub commitment_point_coeff: u8,
    pub partial_point_coeff: u8,
    pub nonce_g_coeff: u8,
    pub nonce_p_coeff: u8,
}

pub open spec fn abstract_field_order_v1_spec() -> nat {
    5nat
}

pub open spec fn scalar_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn project_root_share_wire_width_bytes_v1_spec() -> nat {
    33nat
}

pub open spec fn prf_output_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn partial_context_tag_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn compressed_point_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn partial_wire_width_bytes_v1_spec() -> nat {
    65nat
}

pub open spec fn share_commitment_wire_width_bytes_v1_spec() -> nat {
    33nat
}

pub open spec fn dleq_proof_wire_width_bytes_v1_spec() -> nat {
    64nat
}

pub open spec fn is_field_element_v1_spec(value: u8) -> bool {
    value < abstract_field_order_v1_spec()
}

pub open spec fn is_valid_project_root_scalar_v1_spec(value: u8) -> bool {
    is_field_element_v1_spec(value) && value != 0u8
}

pub open spec fn is_valid_project_root_share_scalar_v1_spec(value: u8) -> bool {
    is_field_element_v1_spec(value)
}

pub open spec fn is_valid_dleq_nonce_v1_spec(value: u8) -> bool {
    is_field_element_v1_spec(value) && value != 0u8
}

pub open spec fn parse_project_root_scalar_encoding_v1_spec(encoded: u8) -> Option<u8> {
    if is_valid_project_root_scalar_v1_spec(encoded) {
        Some(encoded)
    } else {
        None
    }
}

pub open spec fn parse_project_root_share_scalar_encoding_v1_spec(encoded: u8) -> Option<u8> {
    if is_valid_project_root_share_scalar_v1_spec(encoded) {
        Some(encoded)
    } else {
        None
    }
}

pub open spec fn is_valid_share_id_v1_spec(id: u8) -> bool {
    id == 1u8 || id == 2u8 || id == 3u8
}

pub open spec fn is_valid_share_pair_v1_spec(left: u8, right: u8) -> bool {
    is_valid_share_id_v1_spec(left) && is_valid_share_id_v1_spec(right) && left != right
}

pub open spec fn validate_two_share_subset_v1_spec(
    subset_len: nat,
    left: u8,
    right: u8,
) -> bool {
    subset_len == 2nat && is_valid_share_pair_v1_spec(left, right)
}

pub uninterp spec fn field_add_v1_spec(left: u8, right: u8) -> u8;

pub uninterp spec fn field_mul_v1_spec(left: u8, right: u8) -> u8;

pub uninterp spec fn field_sub_v1_spec(left: u8, right: u8) -> u8;

pub open spec fn share_id_as_field_element_v1_spec(id: u8) -> u8 {
    if id == 1u8 {
        1u8
    } else if id == 2u8 {
        2u8
    } else if id == 3u8 {
        3u8
    } else {
        0u8
    }
}

pub open spec fn lagrange_left_coeff_v1_spec(left: u8, right: u8) -> u8 {
    if left == 1u8 && right == 2u8 {
        2u8
    } else if left == 2u8 && right == 1u8 {
        4u8
    } else if left == 1u8 && right == 3u8 {
        4u8
    } else if left == 3u8 && right == 1u8 {
        2u8
    } else if left == 2u8 && right == 3u8 {
        3u8
    } else if left == 3u8 && right == 2u8 {
        3u8
    } else {
        0u8
    }
}

pub open spec fn lagrange_right_coeff_v1_spec(left: u8, right: u8) -> u8 {
    lagrange_left_coeff_v1_spec(right, left)
}

pub open spec fn shamir_share_value_v1_spec(root: u8, slope: u8, id: u8) -> u8 {
    field_add_v1_spec(
        root,
        field_mul_v1_spec(slope, share_id_as_field_element_v1_spec(id)),
    )
}

pub open spec fn project_root_share_v1_spec(
    root: u8,
    slope: u8,
    id: u8,
) -> ProjectRootShareV1 {
    ProjectRootShareV1 {
        id,
        value: shamir_share_value_v1_spec(root, slope, id),
    }
}

pub open spec fn reconstruct_from_share_values_v1_spec(
    left_id: u8,
    left_value: u8,
    right_id: u8,
    right_value: u8,
) -> u8 {
    field_add_v1_spec(
        field_mul_v1_spec(lagrange_left_coeff_v1_spec(left_id, right_id), left_value),
        field_mul_v1_spec(lagrange_right_coeff_v1_spec(left_id, right_id), right_value),
    )
}

pub open spec fn reconstruct_generated_root_v1_spec(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
) -> u8 {
    reconstruct_from_share_values_v1_spec(
        left_id,
        shamir_share_value_v1_spec(root, slope, left_id),
        right_id,
        shamir_share_value_v1_spec(root, slope, right_id),
    )
}

pub open spec fn refresh_share_from_pair_v1_spec(
    left: ProjectRootShareV1,
    right: ProjectRootShareV1,
    new_slope: u8,
    refreshed_id: u8,
) -> ProjectRootShareV1 {
    project_root_share_v1_spec(
        reconstruct_from_share_values_v1_spec(left.id, left.value, right.id, right.value),
        new_slope,
        refreshed_id,
    )
}

pub open spec fn refresh_generated_share_v1_spec(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    new_slope: u8,
    refreshed_id: u8,
) -> ProjectRootShareV1 {
    refresh_share_from_pair_v1_spec(
        project_root_share_v1_spec(root, slope, left_id),
        project_root_share_v1_spec(root, slope, right_id),
        new_slope,
        refreshed_id,
    )
}

pub open spec fn project_root_share_wire_from_share_v1_spec(
    share: ProjectRootShareV1,
) -> ProjectRootShareWireV1Spec {
    ProjectRootShareWireV1Spec {
        share_id: share.id,
        scalar: share.value,
    }
}

pub open spec fn decode_project_root_share_wire_v1_spec(
    wire_len: nat,
    wire: ProjectRootShareWireV1Spec,
) -> Option<ProjectRootShareV1> {
    if wire_len == project_root_share_wire_width_bytes_v1_spec()
        && is_valid_share_id_v1_spec(wire.share_id)
        && is_valid_project_root_share_scalar_v1_spec(wire.scalar)
    {
        Some(ProjectRootShareV1 {
            id: wire.share_id,
            value: wire.scalar,
        })
    } else {
        None
    }
}

pub uninterp spec fn partial_context_tag_v1_spec(context: PrfContextV1) -> Bytes32;

pub open spec fn output_derivation_input_v1_spec(
    context: PrfContextV1,
    point_coeff: u8,
) -> PrfOutputDerivationInputV1 {
    PrfOutputDerivationInputV1 {
        suite_id: context.suite_id,
        purpose_id: context.purpose_id,
        context_id: context.context_id,
        point_coeff,
    }
}

pub uninterp spec fn prf_output_hash_from_input_v1_spec(
    input: PrfOutputDerivationInputV1,
) -> Bytes32;

pub open spec fn prf_output_hash_v1_spec(context: PrfContextV1, point_coeff: u8) -> Bytes32 {
    prf_output_hash_from_input_v1_spec(output_derivation_input_v1_spec(context, point_coeff))
}

pub uninterp spec fn compressed_point_from_coeff_v1_spec(point_coeff: u8) -> Bytes32;

pub uninterp spec fn decompress_point_coeff_v1_spec(compressed_point: Bytes32) -> u8;

pub uninterp spec fn is_valid_compressed_point_v1_spec(compressed_point: Bytes32) -> bool;

pub open spec fn evaluate_direct_reference_v1_spec(
    root: u8,
    context: PrfContextV1,
) -> Bytes32 {
    prf_output_hash_v1_spec(context, root)
}

pub open spec fn evaluate_partial_v1_spec(
    share: ProjectRootShareV1,
    context: PrfContextV1,
) -> PrfPartialV1 {
    PrfPartialV1 {
        id: share.id,
        context_tag: partial_context_tag_v1_spec(context),
        point_coeff: share.value,
    }
}

pub open spec fn partial_context_matches_v1_spec(
    partial: PrfPartialV1,
    context: PrfContextV1,
) -> bool {
    partial.context_tag == partial_context_tag_v1_spec(context)
}

pub open spec fn combine_partial_point_coeffs_v1_spec(
    left: PrfPartialV1,
    right: PrfPartialV1,
) -> u8 {
    reconstruct_from_share_values_v1_spec(left.id, left.point_coeff, right.id, right.point_coeff)
}

pub open spec fn combine_partials_v1_spec(
    left: PrfPartialV1,
    right: PrfPartialV1,
    context: PrfContextV1,
) -> Option<Bytes32> {
    if is_valid_share_pair_v1_spec(left.id, right.id)
        && partial_context_matches_v1_spec(left, context)
        && partial_context_matches_v1_spec(right, context)
    {
        Some(prf_output_hash_v1_spec(
            context,
            combine_partial_point_coeffs_v1_spec(left, right),
        ))
    } else {
        None
    }
}

pub open spec fn option_a_output_v1_spec(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    context: PrfContextV1,
) -> Option<Bytes32> {
    combine_partials_v1_spec(
        evaluate_partial_v1_spec(project_root_share_v1_spec(root, slope, left_id), context),
        evaluate_partial_v1_spec(project_root_share_v1_spec(root, slope, right_id), context),
        context,
    )
}

pub open spec fn option_a_output_from_share_wires_v1_spec(
    left_wire_len: nat,
    left_wire: ProjectRootShareWireV1Spec,
    right_wire_len: nat,
    right_wire: ProjectRootShareWireV1Spec,
    context: PrfContextV1,
) -> Option<Bytes32> {
    match (
        decode_project_root_share_wire_v1_spec(left_wire_len, left_wire),
        decode_project_root_share_wire_v1_spec(right_wire_len, right_wire),
    ) {
        (Some(left_share), Some(right_share)) => combine_partials_v1_spec(
            evaluate_partial_v1_spec(left_share, context),
            evaluate_partial_v1_spec(right_share, context),
            context,
        ),
        _ => None,
    }
}

pub open spec fn partial_wire_from_partial_v1_spec(partial: PrfPartialV1) -> PrfPartialWireV1 {
    PrfPartialWireV1 {
        share_id: partial.id,
        context_tag: partial.context_tag,
        compressed_point: compressed_point_from_coeff_v1_spec(partial.point_coeff),
    }
}

pub open spec fn decode_partial_wire_with_context_v1_spec(
    wire: PrfPartialWireV1,
    context: PrfContextV1,
) -> Option<PrfPartialV1> {
    if is_valid_share_id_v1_spec(wire.share_id)
        && wire.context_tag == partial_context_tag_v1_spec(context)
        && is_valid_compressed_point_v1_spec(wire.compressed_point)
    {
        Some(PrfPartialV1 {
            id: wire.share_id,
            context_tag: wire.context_tag,
            point_coeff: decompress_point_coeff_v1_spec(wire.compressed_point),
        })
    } else {
        None
    }
}

pub open spec fn commitment_from_share_v1_spec(
    share: ProjectRootShareV1,
) -> ProjectRootShareCommitmentV1Spec {
    ProjectRootShareCommitmentV1Spec {
        id: share.id,
        point_coeff: share.value,
    }
}

pub open spec fn dleq_challenge_input_v1_spec(
    context: PrfContextV1,
    context_tag: Bytes32,
    share_id: u8,
    commitment_point_coeff: u8,
    partial_point_coeff: u8,
    nonce_g_coeff: u8,
    nonce_p_coeff: u8,
) -> DleqChallengeInputV1Spec {
    DleqChallengeInputV1Spec {
        suite_id: context.suite_id,
        purpose_id: context.purpose_id,
        context_tag,
        share_id,
        basepoint_id: 1u8,
        input_point_id: context.context_id,
        commitment_point_coeff,
        partial_point_coeff,
        nonce_g_coeff,
        nonce_p_coeff,
    }
}

pub uninterp spec fn dleq_challenge_v1_spec(input: DleqChallengeInputV1Spec) -> u8;

pub open spec fn generated_dleq_proof_for_partial_v1_spec(
    share: ProjectRootShareV1,
    partial: PrfPartialV1,
    context: PrfContextV1,
    nonce: u8,
) -> PrfDleqProofV1Spec {
    let commitment = commitment_from_share_v1_spec(share);
    let challenge = dleq_challenge_v1_spec(dleq_challenge_input_v1_spec(
        context,
        partial.context_tag,
        partial.id,
        commitment.point_coeff,
        partial.point_coeff,
        nonce,
        nonce,
    ));
    PrfDleqProofV1Spec {
        challenge,
        response: field_add_v1_spec(nonce, field_mul_v1_spec(challenge, share.value)),
    }
}

pub open spec fn generate_dleq_proof_for_partial_v1_spec(
    share: ProjectRootShareV1,
    partial: PrfPartialV1,
    context: PrfContextV1,
    nonce: u8,
) -> Option<PrfDleqProofV1Spec> {
    if is_valid_dleq_nonce_v1_spec(nonce) {
        Some(generated_dleq_proof_for_partial_v1_spec(share, partial, context, nonce))
    } else {
        None
    }
}

pub open spec fn generated_dleq_bundle_for_share_v1_spec(
    share: ProjectRootShareV1,
    context: PrfContextV1,
    nonce: u8,
) -> PrfPartialProofBundleV1Spec {
    let partial = evaluate_partial_v1_spec(share, context);
    PrfPartialProofBundleV1Spec {
        partial,
        commitment: commitment_from_share_v1_spec(share),
        proof: generated_dleq_proof_for_partial_v1_spec(share, partial, context, nonce),
    }
}

pub open spec fn verify_dleq_proof_v1_spec(
    commitment: ProjectRootShareCommitmentV1Spec,
    partial: PrfPartialV1,
    context: PrfContextV1,
    proof: PrfDleqProofV1Spec,
) -> bool {
    if is_valid_share_id_v1_spec(commitment.id)
        && commitment.id == partial.id
        && partial_context_matches_v1_spec(partial, context)
    {
        let nonce_g = field_sub_v1_spec(
            proof.response,
            field_mul_v1_spec(proof.challenge, commitment.point_coeff),
        );
        let nonce_p = field_sub_v1_spec(
            proof.response,
            field_mul_v1_spec(proof.challenge, partial.point_coeff),
        );
        proof.challenge == dleq_challenge_v1_spec(dleq_challenge_input_v1_spec(
            context,
            partial.context_tag,
            partial.id,
            commitment.point_coeff,
            partial.point_coeff,
            nonce_g,
            nonce_p,
        ))
    } else {
        false
    }
}

pub open spec fn combine_verified_partials_v1_spec(
    left: PrfPartialProofBundleV1Spec,
    right: PrfPartialProofBundleV1Spec,
    context: PrfContextV1,
) -> Option<Bytes32> {
    if left.partial.id == right.partial.id {
        None
    } else if verify_dleq_proof_v1_spec(left.commitment, left.partial, context, left.proof)
        && verify_dleq_proof_v1_spec(right.commitment, right.partial, context, right.proof)
    {
        combine_partials_v1_spec(left.partial, right.partial, context)
    } else {
        None
    }
}

pub open spec fn option_b_output_v1_spec(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    context: PrfContextV1,
) -> Option<Bytes32> {
    let left_partial =
        evaluate_partial_v1_spec(project_root_share_v1_spec(root, slope, left_id), context);
    let right_partial =
        evaluate_partial_v1_spec(project_root_share_v1_spec(root, slope, right_id), context);
    let left_wire = partial_wire_from_partial_v1_spec(left_partial);
    let right_wire = partial_wire_from_partial_v1_spec(right_partial);
    match (
        decode_partial_wire_with_context_v1_spec(left_wire, context),
        decode_partial_wire_with_context_v1_spec(right_wire, context),
    ) {
        (Some(decoded_left), Some(decoded_right)) => {
            combine_partials_v1_spec(decoded_left, decoded_right, context)
        },
        _ => None,
    }
}

pub broadcast axiom fn axiom_field_add_outputs_field_v1(left: u8, right: u8)
    requires
        is_field_element_v1_spec(left),
        is_field_element_v1_spec(right),
    ensures
        #![trigger field_add_v1_spec(left, right)]
        is_field_element_v1_spec(field_add_v1_spec(left, right)),
;

pub broadcast axiom fn axiom_field_mul_outputs_field_v1(left: u8, right: u8)
    requires
        is_field_element_v1_spec(left),
        is_field_element_v1_spec(right),
    ensures
        #![trigger field_mul_v1_spec(left, right)]
        is_field_element_v1_spec(field_mul_v1_spec(left, right)),
;

pub broadcast axiom fn axiom_field_sub_cancel_right_v1(nonce: u8, right: u8)
    requires
        is_field_element_v1_spec(nonce),
        is_field_element_v1_spec(right),
    ensures
        #![trigger field_sub_v1_spec(field_add_v1_spec(nonce, right), right)]
        field_sub_v1_spec(field_add_v1_spec(nonce, right), right) == nonce,
;

pub broadcast axiom fn axiom_dleq_challenge_outputs_field_v1(input: DleqChallengeInputV1Spec)
    ensures
        #![trigger dleq_challenge_v1_spec(input)]
        is_field_element_v1_spec(dleq_challenge_v1_spec(input)),
;

pub broadcast axiom fn axiom_lagrange_reconstructs_generated_root_v1(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_pair_v1_spec(left_id, right_id),
    ensures
        #![trigger reconstruct_generated_root_v1_spec(root, slope, left_id, right_id)]
        reconstruct_generated_root_v1_spec(root, slope, left_id, right_id) == root,
;

pub broadcast axiom fn axiom_generated_compressed_point_round_trips_v1(point_coeff: u8)
    requires
        is_valid_project_root_share_scalar_v1_spec(point_coeff),
    ensures
        #![trigger compressed_point_from_coeff_v1_spec(point_coeff)]
        is_valid_compressed_point_v1_spec(compressed_point_from_coeff_v1_spec(point_coeff)),
        decompress_point_coeff_v1_spec(compressed_point_from_coeff_v1_spec(point_coeff))
            == point_coeff,
;

pub proof fn scalar_and_wire_widths_are_fixed_v1()
    ensures
        scalar_width_bytes_v1_spec() == 32nat,
        project_root_share_wire_width_bytes_v1_spec() == 33nat,
        prf_output_width_bytes_v1_spec() == 32nat,
        partial_context_tag_width_bytes_v1_spec() == 32nat,
        compressed_point_width_bytes_v1_spec() == 32nat,
        partial_wire_width_bytes_v1_spec() == 65nat,
        share_commitment_wire_width_bytes_v1_spec() == 33nat,
        dleq_proof_wire_width_bytes_v1_spec() == 64nat,
{
}

pub proof fn zero_root_scalar_is_rejected_v1()
    ensures
        !is_valid_project_root_scalar_v1_spec(0u8),
{
}

pub proof fn zero_share_scalar_is_accepted_v1()
    ensures
        is_valid_project_root_share_scalar_v1_spec(0u8),
{
}

pub proof fn malformed_root_scalar_encoding_is_rejected_v1(encoded: u8)
    requires
        !is_field_element_v1_spec(encoded),
    ensures
        parse_project_root_scalar_encoding_v1_spec(encoded) == None::<u8>,
{
}

pub proof fn malformed_share_scalar_encoding_is_rejected_v1(encoded: u8)
    requires
        !is_field_element_v1_spec(encoded),
    ensures
        parse_project_root_share_scalar_encoding_v1_spec(encoded) == None::<u8>,
{
}

pub proof fn zero_root_scalar_encoding_is_rejected_by_parser_v1()
    ensures
        parse_project_root_scalar_encoding_v1_spec(0u8) == None::<u8>,
{
}

pub proof fn zero_share_scalar_encoding_is_accepted_by_parser_v1()
    ensures
        parse_project_root_share_scalar_encoding_v1_spec(0u8) == Some(0u8),
{
}

pub proof fn project_root_share_wire_rejects_wrong_length_v1(
    wire_len: nat,
    wire: ProjectRootShareWireV1Spec,
)
    requires
        wire_len != project_root_share_wire_width_bytes_v1_spec(),
    ensures
        decode_project_root_share_wire_v1_spec(wire_len, wire) == None::<ProjectRootShareV1>,
{
}

pub proof fn project_root_share_wire_rejects_invalid_share_id_v1(
    wire: ProjectRootShareWireV1Spec,
)
    requires
        !is_valid_share_id_v1_spec(wire.share_id),
    ensures
        decode_project_root_share_wire_v1_spec(
            project_root_share_wire_width_bytes_v1_spec(),
            wire,
        ) == None::<ProjectRootShareV1>,
{
}

pub proof fn project_root_share_wire_rejects_invalid_scalar_v1(
    wire: ProjectRootShareWireV1Spec,
)
    requires
        !is_valid_project_root_share_scalar_v1_spec(wire.scalar),
    ensures
        decode_project_root_share_wire_v1_spec(
            project_root_share_wire_width_bytes_v1_spec(),
            wire,
        ) == None::<ProjectRootShareV1>,
{
}

pub proof fn project_root_share_wire_accepts_zero_share_scalar_v1(id: u8)
    requires
        is_valid_share_id_v1_spec(id),
    ensures
        decode_project_root_share_wire_v1_spec(
            project_root_share_wire_width_bytes_v1_spec(),
            ProjectRootShareWireV1Spec {
                share_id: id,
                scalar: 0u8,
            },
        ) == Some(ProjectRootShareV1 { id, value: 0u8 }),
{
}

pub proof fn generated_project_root_share_wire_round_trips_v1(
    root: u8,
    slope: u8,
    id: u8,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_id_v1_spec(id),
    ensures
        decode_project_root_share_wire_v1_spec(
            project_root_share_wire_width_bytes_v1_spec(),
            project_root_share_wire_from_share_v1_spec(project_root_share_v1_spec(root, slope, id)),
        ) == Some(project_root_share_v1_spec(root, slope, id)),
{
    generated_share_value_is_canonical_v1(root, slope, id);
}

pub proof fn supported_share_ids_are_exactly_one_two_three_v1(id: u8)
    ensures
        is_valid_share_id_v1_spec(id) == (id == 1u8 || id == 2u8 || id == 3u8),
{
}

pub proof fn duplicate_share_ids_are_rejected_v1(id: u8)
    requires
        is_valid_share_id_v1_spec(id),
    ensures
        !is_valid_share_pair_v1_spec(id, id),
        !validate_two_share_subset_v1_spec(2nat, id, id),
{
}

pub proof fn insufficient_share_subset_is_rejected_v1(left: u8, right: u8)
    ensures
        !validate_two_share_subset_v1_spec(1nat, left, right),
{
}

pub proof fn oversized_share_subset_is_rejected_v1(left: u8, right: u8)
    ensures
        !validate_two_share_subset_v1_spec(3nat, left, right),
{
}

pub proof fn generated_share_value_is_canonical_v1(root: u8, slope: u8, id: u8)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_id_v1_spec(id),
    ensures
        is_valid_project_root_share_scalar_v1_spec(shamir_share_value_v1_spec(root, slope, id)),
{
    broadcast use axiom_field_add_outputs_field_v1;
    broadcast use axiom_field_mul_outputs_field_v1;
}

pub proof fn every_valid_pair_reconstructs_root_v1(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_pair_v1_spec(left_id, right_id),
    ensures
        reconstruct_generated_root_v1_spec(root, slope, left_id, right_id) == root,
{
    broadcast use axiom_lagrange_reconstructs_generated_root_v1;
    assert(reconstruct_generated_root_v1_spec(root, slope, left_id, right_id) == root);
}

pub proof fn refreshed_valid_pair_reconstructs_original_root_v1(
    root: u8,
    slope: u8,
    old_left_id: u8,
    old_right_id: u8,
    new_slope: u8,
    refreshed_left_id: u8,
    refreshed_right_id: u8,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_project_root_scalar_v1_spec(new_slope),
        is_valid_share_pair_v1_spec(old_left_id, old_right_id),
        is_valid_share_pair_v1_spec(refreshed_left_id, refreshed_right_id),
    ensures
        reconstruct_from_share_values_v1_spec(
            refreshed_left_id,
            refresh_generated_share_v1_spec(
                root,
                slope,
                old_left_id,
                old_right_id,
                new_slope,
                refreshed_left_id,
            ).value,
            refreshed_right_id,
            refresh_generated_share_v1_spec(
                root,
                slope,
                old_left_id,
                old_right_id,
                new_slope,
                refreshed_right_id,
            ).value,
        ) == root,
{
    broadcast use axiom_lagrange_reconstructs_generated_root_v1;

    let reconstructed = reconstruct_generated_root_v1_spec(root, slope, old_left_id, old_right_id);
    assert(reconstructed == root);
    assert(is_valid_project_root_scalar_v1_spec(reconstructed));

    let refreshed_left = refresh_generated_share_v1_spec(
        root,
        slope,
        old_left_id,
        old_right_id,
        new_slope,
        refreshed_left_id,
    );
    let refreshed_right = refresh_generated_share_v1_spec(
        root,
        slope,
        old_left_id,
        old_right_id,
        new_slope,
        refreshed_right_id,
    );

    assert(refreshed_left == project_root_share_v1_spec(reconstructed, new_slope, refreshed_left_id));
    assert(refreshed_right == project_root_share_v1_spec(reconstructed, new_slope, refreshed_right_id));
    assert(reconstruct_generated_root_v1_spec(
        reconstructed,
        new_slope,
        refreshed_left_id,
        refreshed_right_id,
    ) == reconstructed);
}

pub proof fn direct_and_option_a_outputs_match_v1(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    context: PrfContextV1,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_pair_v1_spec(left_id, right_id),
    ensures
        option_a_output_v1_spec(root, slope, left_id, right_id, context)
            == Some(evaluate_direct_reference_v1_spec(root, context)),
{
    broadcast use axiom_lagrange_reconstructs_generated_root_v1;
    let left_share = project_root_share_v1_spec(root, slope, left_id);
    let right_share = project_root_share_v1_spec(root, slope, right_id);
    let left_partial = evaluate_partial_v1_spec(left_share, context);
    let right_partial = evaluate_partial_v1_spec(right_share, context);
    assert(combine_partial_point_coeffs_v1_spec(left_partial, right_partial)
        == reconstruct_generated_root_v1_spec(root, slope, left_id, right_id));
    assert(reconstruct_generated_root_v1_spec(root, slope, left_id, right_id) == root);
}

pub proof fn generated_share_wire_option_a_output_matches_direct_reference_v1(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    context: PrfContextV1,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_pair_v1_spec(left_id, right_id),
    ensures
        option_a_output_from_share_wires_v1_spec(
            project_root_share_wire_width_bytes_v1_spec(),
            project_root_share_wire_from_share_v1_spec(project_root_share_v1_spec(root, slope, left_id)),
            project_root_share_wire_width_bytes_v1_spec(),
            project_root_share_wire_from_share_v1_spec(project_root_share_v1_spec(root, slope, right_id)),
            context,
        ) == Some(evaluate_direct_reference_v1_spec(root, context)),
{
    generated_project_root_share_wire_round_trips_v1(root, slope, left_id);
    generated_project_root_share_wire_round_trips_v1(root, slope, right_id);
    direct_and_option_a_outputs_match_v1(root, slope, left_id, right_id, context);
}

pub proof fn output_derivation_input_includes_context_tuple_v1(
    context: PrfContextV1,
    point_coeff: u8,
)
    ensures
        output_derivation_input_v1_spec(context, point_coeff).suite_id == context.suite_id,
        output_derivation_input_v1_spec(context, point_coeff).purpose_id == context.purpose_id,
        output_derivation_input_v1_spec(context, point_coeff).context_id == context.context_id,
        output_derivation_input_v1_spec(context, point_coeff).point_coeff == point_coeff,
{
}

pub proof fn generated_dleq_proof_verifies_for_valid_partial_v1(
    share: ProjectRootShareV1,
    context: PrfContextV1,
    nonce: u8,
)
    requires
        is_valid_share_id_v1_spec(share.id),
        is_valid_project_root_share_scalar_v1_spec(share.value),
        is_valid_dleq_nonce_v1_spec(nonce),
    ensures
        generate_dleq_proof_for_partial_v1_spec(
            share,
            evaluate_partial_v1_spec(share, context),
            context,
            nonce,
        )
            == Some(generated_dleq_proof_for_partial_v1_spec(
                share,
                evaluate_partial_v1_spec(share, context),
                context,
                nonce,
            )),
        verify_dleq_proof_v1_spec(
            commitment_from_share_v1_spec(share),
            evaluate_partial_v1_spec(share, context),
            context,
            generated_dleq_proof_for_partial_v1_spec(
                share,
                evaluate_partial_v1_spec(share, context),
                context,
                nonce,
            ),
        ),
{
    broadcast use axiom_dleq_challenge_outputs_field_v1;
    broadcast use axiom_field_mul_outputs_field_v1;
    broadcast use axiom_field_sub_cancel_right_v1;

    let partial = evaluate_partial_v1_spec(share, context);
    let commitment = commitment_from_share_v1_spec(share);
    let input = dleq_challenge_input_v1_spec(
        context,
        partial.context_tag,
        partial.id,
        commitment.point_coeff,
        partial.point_coeff,
        nonce,
        nonce,
    );
    let challenge = dleq_challenge_v1_spec(input);
    let challenge_share = field_mul_v1_spec(challenge, share.value);
    assert(is_field_element_v1_spec(challenge));
    assert(is_field_element_v1_spec(challenge_share));
    assert(field_sub_v1_spec(field_add_v1_spec(nonce, challenge_share), challenge_share) == nonce);
}

pub proof fn generated_dleq_bundle_verifies_v1(
    share: ProjectRootShareV1,
    context: PrfContextV1,
    nonce: u8,
)
    requires
        is_valid_share_id_v1_spec(share.id),
        is_valid_project_root_share_scalar_v1_spec(share.value),
        is_valid_dleq_nonce_v1_spec(nonce),
    ensures
        verify_dleq_proof_v1_spec(
            generated_dleq_bundle_for_share_v1_spec(share, context, nonce).commitment,
            generated_dleq_bundle_for_share_v1_spec(share, context, nonce).partial,
            context,
            generated_dleq_bundle_for_share_v1_spec(share, context, nonce).proof,
        ),
{
    generated_dleq_proof_verifies_for_valid_partial_v1(share, context, nonce);
}

pub proof fn zero_dleq_nonce_is_rejected_v1(
    share: ProjectRootShareV1,
    partial: PrfPartialV1,
    context: PrfContextV1,
)
    ensures
        generate_dleq_proof_for_partial_v1_spec(share, partial, context, 0u8)
            == None::<PrfDleqProofV1Spec>,
{
}

pub proof fn dleq_rejects_commitment_partial_id_mismatch_v1(
    commitment: ProjectRootShareCommitmentV1Spec,
    partial: PrfPartialV1,
    context: PrfContextV1,
    proof: PrfDleqProofV1Spec,
)
    requires
        commitment.id != partial.id,
    ensures
        !verify_dleq_proof_v1_spec(commitment, partial, context, proof),
{
}

pub proof fn dleq_rejects_wrong_context_tag_v1(
    commitment: ProjectRootShareCommitmentV1Spec,
    partial: PrfPartialV1,
    context: PrfContextV1,
    proof: PrfDleqProofV1Spec,
)
    requires
        partial.context_tag != partial_context_tag_v1_spec(context),
    ensures
        !verify_dleq_proof_v1_spec(commitment, partial, context, proof),
{
}

pub proof fn combine_verified_partials_rejects_duplicate_partial_ids_v1(
    left: PrfPartialProofBundleV1Spec,
    right: PrfPartialProofBundleV1Spec,
    context: PrfContextV1,
)
    requires
        left.partial.id == right.partial.id,
    ensures
        combine_verified_partials_v1_spec(left, right, context) == None::<Bytes32>,
{
}

pub proof fn combine_verified_partials_rejects_unverified_left_bundle_v1(
    left: PrfPartialProofBundleV1Spec,
    right: PrfPartialProofBundleV1Spec,
    context: PrfContextV1,
)
    requires
        left.partial.id != right.partial.id,
        !verify_dleq_proof_v1_spec(left.commitment, left.partial, context, left.proof),
    ensures
        combine_verified_partials_v1_spec(left, right, context) == None::<Bytes32>,
{
}

pub proof fn combine_verified_partials_rejects_unverified_right_bundle_v1(
    left: PrfPartialProofBundleV1Spec,
    right: PrfPartialProofBundleV1Spec,
    context: PrfContextV1,
)
    requires
        left.partial.id != right.partial.id,
        !verify_dleq_proof_v1_spec(right.commitment, right.partial, context, right.proof),
    ensures
        combine_verified_partials_v1_spec(left, right, context) == None::<Bytes32>,
{
}

pub proof fn generated_partial_wire_preserves_fields_v1(partial: PrfPartialV1)
    ensures
        partial_wire_from_partial_v1_spec(partial).share_id == partial.id,
        partial_wire_from_partial_v1_spec(partial).context_tag == partial.context_tag,
        partial_wire_from_partial_v1_spec(partial).compressed_point
            == compressed_point_from_coeff_v1_spec(partial.point_coeff),
{
}

pub proof fn wrong_context_tag_wire_is_rejected_v1(
    wire: PrfPartialWireV1,
    context: PrfContextV1,
)
    requires
        wire.context_tag != partial_context_tag_v1_spec(context),
    ensures
        decode_partial_wire_with_context_v1_spec(wire, context) == None::<PrfPartialV1>,
{
}

pub proof fn generated_partial_wire_round_trips_v1(partial: PrfPartialV1, context: PrfContextV1)
    requires
        is_valid_share_id_v1_spec(partial.id),
        is_valid_project_root_share_scalar_v1_spec(partial.point_coeff),
        partial.context_tag == partial_context_tag_v1_spec(context),
    ensures
        decode_partial_wire_with_context_v1_spec(partial_wire_from_partial_v1_spec(partial), context)
            == Some(partial),
{
    broadcast use axiom_generated_compressed_point_round_trips_v1;
}

pub proof fn option_b_placement_matches_option_a_v1(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    context: PrfContextV1,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_pair_v1_spec(left_id, right_id),
    ensures
        option_b_output_v1_spec(root, slope, left_id, right_id, context)
            == option_a_output_v1_spec(root, slope, left_id, right_id, context),
{
    broadcast use axiom_field_add_outputs_field_v1;
    broadcast use axiom_field_mul_outputs_field_v1;
    broadcast use axiom_generated_compressed_point_round_trips_v1;

    let left_share = project_root_share_v1_spec(root, slope, left_id);
    let right_share = project_root_share_v1_spec(root, slope, right_id);
    generated_share_value_is_canonical_v1(root, slope, left_id);
    generated_share_value_is_canonical_v1(root, slope, right_id);
    generated_partial_wire_round_trips_v1(evaluate_partial_v1_spec(left_share, context), context);
    generated_partial_wire_round_trips_v1(evaluate_partial_v1_spec(right_share, context), context);
}

pub proof fn direct_option_a_and_option_b_outputs_match_v1(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    context: PrfContextV1,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_pair_v1_spec(left_id, right_id),
    ensures
        option_a_output_v1_spec(root, slope, left_id, right_id, context)
            == Some(evaluate_direct_reference_v1_spec(root, context)),
        option_b_output_v1_spec(root, slope, left_id, right_id, context)
            == Some(evaluate_direct_reference_v1_spec(root, context)),
{
    direct_and_option_a_outputs_match_v1(root, slope, left_id, right_id, context);
    option_b_placement_matches_option_a_v1(root, slope, left_id, right_id, context);
}

pub proof fn generated_verified_option_b_output_matches_direct_reference_v1(
    root: u8,
    slope: u8,
    left_id: u8,
    right_id: u8,
    context: PrfContextV1,
    left_nonce: u8,
    right_nonce: u8,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_share_pair_v1_spec(left_id, right_id),
        is_valid_dleq_nonce_v1_spec(left_nonce),
        is_valid_dleq_nonce_v1_spec(right_nonce),
    ensures
        combine_verified_partials_v1_spec(
            generated_dleq_bundle_for_share_v1_spec(
                project_root_share_v1_spec(root, slope, left_id),
                context,
                left_nonce,
            ),
            generated_dleq_bundle_for_share_v1_spec(
                project_root_share_v1_spec(root, slope, right_id),
                context,
                right_nonce,
            ),
            context,
        ) == Some(evaluate_direct_reference_v1_spec(root, context)),
{
    let left_share = project_root_share_v1_spec(root, slope, left_id);
    let right_share = project_root_share_v1_spec(root, slope, right_id);
    generated_share_value_is_canonical_v1(root, slope, left_id);
    generated_share_value_is_canonical_v1(root, slope, right_id);
    generated_dleq_bundle_verifies_v1(left_share, context, left_nonce);
    generated_dleq_bundle_verifies_v1(right_share, context, right_nonce);
    direct_and_option_a_outputs_match_v1(root, slope, left_id, right_id, context);
}

pub proof fn refreshed_option_a_output_matches_direct_reference_v1(
    root: u8,
    slope: u8,
    old_left_id: u8,
    old_right_id: u8,
    new_slope: u8,
    refreshed_left_id: u8,
    refreshed_right_id: u8,
    context: PrfContextV1,
)
    requires
        is_valid_project_root_scalar_v1_spec(root),
        is_valid_project_root_scalar_v1_spec(slope),
        is_valid_project_root_scalar_v1_spec(new_slope),
        is_valid_share_pair_v1_spec(old_left_id, old_right_id),
        is_valid_share_pair_v1_spec(refreshed_left_id, refreshed_right_id),
    ensures
        combine_partials_v1_spec(
            evaluate_partial_v1_spec(refresh_generated_share_v1_spec(
                root,
                slope,
                old_left_id,
                old_right_id,
                new_slope,
                refreshed_left_id,
            ), context),
            evaluate_partial_v1_spec(refresh_generated_share_v1_spec(
                root,
                slope,
                old_left_id,
                old_right_id,
                new_slope,
                refreshed_right_id,
            ), context),
            context,
        ) == Some(evaluate_direct_reference_v1_spec(root, context)),
{
    refreshed_valid_pair_reconstructs_original_root_v1(
        root,
        slope,
        old_left_id,
        old_right_id,
        new_slope,
        refreshed_left_id,
        refreshed_right_id,
    );
    broadcast use axiom_lagrange_reconstructs_generated_root_v1;

    let refreshed_left = refresh_generated_share_v1_spec(
        root,
        slope,
        old_left_id,
        old_right_id,
        new_slope,
        refreshed_left_id,
    );
    let refreshed_right = refresh_generated_share_v1_spec(
        root,
        slope,
        old_left_id,
        old_right_id,
        new_slope,
        refreshed_right_id,
    );
    let left_partial = evaluate_partial_v1_spec(refreshed_left, context);
    let right_partial = evaluate_partial_v1_spec(refreshed_right, context);
    assert(combine_partial_point_coeffs_v1_spec(left_partial, right_partial) == root);
}

}
