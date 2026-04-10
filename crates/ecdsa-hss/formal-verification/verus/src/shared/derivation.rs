//! Verification entrypoint for canonical `x` and additive-share derivation.
//!
//! Planned proof targets:
//! - deterministic canonical `x`
//! - valid non-zero secp256k1 scalar range
//! - additive-share reconstruction
//! - deterministic retry-counter rule

use vstd::prelude::*;

use super::context::CanonicalContextV1;

verus! {

pub type Bytes32 = [u8; 32];
pub type Bytes64 = [u8; 64];

#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalXInputV1 {
    pub context: CanonicalContextV1,
    pub y_client_le_bytes: Bytes32,
    pub y_relayer_le_bytes: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalXOutputV1 {
    pub m_le_bytes: Bytes32,
    pub d_le_bytes: Bytes32,
    pub x_be_bytes: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdditiveShareDerivationOutputV1 {
    pub x_client_be_bytes: Bytes32,
    pub x_relayer_be_bytes: Bytes32,
    pub retry_counter: u32,
}

pub open spec fn secp256k1_scalar_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn secp256k1_order_v1_spec() -> int {
    115792089237316195423570985008687907852837564279074904382605163141518161494337int
}

pub uninterp spec fn bytes32_as_int_v1_spec(bytes: Bytes32) -> int;

pub open spec fn is_valid_nonzero_scalar_v1_spec(bytes: Bytes32) -> bool {
    0 < bytes32_as_int_v1_spec(bytes) < secp256k1_order_v1_spec()
}

pub uninterp spec fn add_le_bytes_mod_2_256_v1_spec(left: Bytes32, right: Bytes32) -> Bytes32;

pub uninterp spec fn canonical_x_hash_v1_spec(
    context: CanonicalContextV1,
    d_le_bytes: Bytes32,
) -> Bytes64;

pub uninterp spec fn reduce_hash_to_valid_scalar_v1_spec(hash: Bytes64) -> Bytes32;

pub uninterp spec fn scalar_int_to_bytes32_v1_spec(value: int) -> Bytes32;

pub broadcast axiom fn axiom_reduce_hash_to_valid_scalar_is_valid_v1(hash: Bytes64)
    ensures
        #![trigger reduce_hash_to_valid_scalar_v1_spec(hash)]
        is_valid_nonzero_scalar_v1_spec(reduce_hash_to_valid_scalar_v1_spec(hash)),
;

pub broadcast axiom fn axiom_scalar_int_encoding_matches_value_v1(value: int)
    requires
        0 < value < secp256k1_order_v1_spec(),
    ensures
        #![trigger scalar_int_to_bytes32_v1_spec(value)]
        is_valid_nonzero_scalar_v1_spec(scalar_int_to_bytes32_v1_spec(value)),
        bytes32_as_int_v1_spec(scalar_int_to_bytes32_v1_spec(value)) == value,
;

pub broadcast axiom fn axiom_valid_scalar_bytes_are_injective_v1(left: Bytes32, right: Bytes32)
    requires
        is_valid_nonzero_scalar_v1_spec(left),
        is_valid_nonzero_scalar_v1_spec(right),
    ensures
        #![trigger bytes32_as_int_v1_spec(left), bytes32_as_int_v1_spec(right)]
        bytes32_as_int_v1_spec(left) == bytes32_as_int_v1_spec(right) <==> left == right,
;

pub open spec fn derive_m_le_bytes_v1_spec(input: CanonicalXInputV1) -> Bytes32 {
    add_le_bytes_mod_2_256_v1_spec(input.y_client_le_bytes, input.y_relayer_le_bytes)
}

pub open spec fn derive_d_le_bytes_v1_spec(input: CanonicalXInputV1) -> Bytes32 {
    derive_m_le_bytes_v1_spec(input)
}

pub open spec fn derive_canonical_x_v1_spec(input: CanonicalXInputV1) -> CanonicalXOutputV1 {
    let m_le_bytes = derive_m_le_bytes_v1_spec(input);
    let d_le_bytes = derive_d_le_bytes_v1_spec(input);
    let hash = canonical_x_hash_v1_spec(input.context, d_le_bytes);
    let x_be_bytes = reduce_hash_to_valid_scalar_v1_spec(hash);
    CanonicalXOutputV1 {
        m_le_bytes,
        d_le_bytes,
        x_be_bytes,
    }
}

pub open spec fn canonical_x_is_in_scalar_domain_v1_spec(input: CanonicalXInputV1) -> bool {
    is_valid_nonzero_scalar_v1_spec(derive_canonical_x_v1_spec(input).x_be_bytes)
}

pub uninterp spec fn additive_client_share_hash_v1_spec(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
    retry_counter: u32,
) -> Bytes64;

pub open spec fn candidate_client_share_v1_spec(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
    retry_counter: u32,
) -> Bytes32 {
    reduce_hash_to_valid_scalar_v1_spec(
        additive_client_share_hash_v1_spec(x_be_bytes, context, retry_counter),
    )
}

pub uninterp spec fn retry_counter_v1_spec(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
) -> u32;

pub open spec fn client_share_is_distinct_from_canonical_v1_spec(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
    retry_counter: u32,
) -> bool {
    candidate_client_share_v1_spec(x_be_bytes, context, retry_counter) != x_be_bytes
}

pub open spec fn relayer_share_int_from_x_and_client_share_v1_spec(
    x_be_bytes: Bytes32,
    x_client_be_bytes: Bytes32,
) -> int {
    let x = bytes32_as_int_v1_spec(x_be_bytes);
    let x_client = bytes32_as_int_v1_spec(x_client_be_bytes);
    if x >= x_client {
        x - x_client
    } else {
        x + secp256k1_order_v1_spec() - x_client
    }
}

pub open spec fn relayer_share_from_x_and_client_share_v1_spec(
    x_be_bytes: Bytes32,
    x_client_be_bytes: Bytes32,
) -> Bytes32 {
    scalar_int_to_bytes32_v1_spec(
        relayer_share_int_from_x_and_client_share_v1_spec(x_be_bytes, x_client_be_bytes),
    )
}

pub broadcast axiom fn axiom_retry_counter_selects_first_distinct_client_share_v1(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
)
    requires
        is_valid_nonzero_scalar_v1_spec(x_be_bytes),
    ensures
        #![trigger retry_counter_v1_spec(x_be_bytes, context)]
        client_share_is_distinct_from_canonical_v1_spec(
            x_be_bytes,
            context,
            retry_counter_v1_spec(x_be_bytes, context),
        ),
        forall|earlier: u32|
            earlier < retry_counter_v1_spec(x_be_bytes, context) ==>
                !client_share_is_distinct_from_canonical_v1_spec(x_be_bytes, context, earlier),
;

pub open spec fn derive_additive_shares_v1_spec(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
) -> AdditiveShareDerivationOutputV1 {
    let retry_counter = retry_counter_v1_spec(x_be_bytes, context);
    let x_client_be_bytes = candidate_client_share_v1_spec(x_be_bytes, context, retry_counter);
    let x_relayer_be_bytes =
        relayer_share_from_x_and_client_share_v1_spec(x_be_bytes, x_client_be_bytes);
    AdditiveShareDerivationOutputV1 {
        x_client_be_bytes,
        x_relayer_be_bytes,
        retry_counter,
    }
}

pub open spec fn additive_shares_are_in_scalar_domain_v1_spec(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
) -> bool {
    &&& is_valid_nonzero_scalar_v1_spec(
        derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes,
    )
    &&& is_valid_nonzero_scalar_v1_spec(
        derive_additive_shares_v1_spec(x_be_bytes, context).x_relayer_be_bytes,
    )
}

pub open spec fn additive_shares_reconstruct_x_v1_spec(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
) -> bool {
    (
        bytes32_as_int_v1_spec(derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes)
            + bytes32_as_int_v1_spec(
                derive_additive_shares_v1_spec(x_be_bytes, context).x_relayer_be_bytes,
            )
    ) % secp256k1_order_v1_spec() == bytes32_as_int_v1_spec(x_be_bytes)
}

pub proof fn canonical_x_derivation_preserves_d_equals_m(input: CanonicalXInputV1)
    ensures
        derive_canonical_x_v1_spec(input).d_le_bytes
            == derive_canonical_x_v1_spec(input).m_le_bytes,
{
}

pub proof fn canonical_x_derivation_is_deterministic(
    left: CanonicalXInputV1,
    right: CanonicalXInputV1,
)
    requires
        left == right,
    ensures
        derive_canonical_x_v1_spec(left) == derive_canonical_x_v1_spec(right),
{
}

pub proof fn canonical_x_scalar_domain_goal_matches_reduction_output(
    input: CanonicalXInputV1,
)
    ensures
        canonical_x_is_in_scalar_domain_v1_spec(input)
            == is_valid_nonzero_scalar_v1_spec(
                reduce_hash_to_valid_scalar_v1_spec(
                    canonical_x_hash_v1_spec(input.context, derive_d_le_bytes_v1_spec(input)),
                ),
            ),
{
}

pub proof fn canonical_x_is_always_a_valid_nonzero_scalar(
    input: CanonicalXInputV1,
)
    ensures
        canonical_x_is_in_scalar_domain_v1_spec(input),
{
    broadcast use axiom_reduce_hash_to_valid_scalar_is_valid_v1;
}

pub proof fn additive_share_derivation_uses_retry_counter_output(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
)
    ensures
        derive_additive_shares_v1_spec(x_be_bytes, context).retry_counter
            == retry_counter_v1_spec(x_be_bytes, context),
{
}

pub proof fn additive_share_derivation_is_deterministic(
    left_x_be_bytes: Bytes32,
    left_context: CanonicalContextV1,
    right_x_be_bytes: Bytes32,
    right_context: CanonicalContextV1,
)
    requires
        left_x_be_bytes == right_x_be_bytes,
        left_context == right_context,
    ensures
        derive_additive_shares_v1_spec(left_x_be_bytes, left_context)
            == derive_additive_shares_v1_spec(right_x_be_bytes, right_context),
{
}

pub proof fn additive_share_domain_goals_match_derived_outputs(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
)
    ensures
        additive_shares_are_in_scalar_domain_v1_spec(x_be_bytes, context)
            == (
                is_valid_nonzero_scalar_v1_spec(
                    derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes,
                )
                    && is_valid_nonzero_scalar_v1_spec(
                        derive_additive_shares_v1_spec(x_be_bytes, context).x_relayer_be_bytes,
                    )
            ),
{
}

pub proof fn relayer_share_int_is_valid_nonzero_scalar_v1(
    x_be_bytes: Bytes32,
    x_client_be_bytes: Bytes32,
)
    requires
        is_valid_nonzero_scalar_v1_spec(x_be_bytes),
        is_valid_nonzero_scalar_v1_spec(x_client_be_bytes),
        x_client_be_bytes != x_be_bytes,
    ensures
        0 < relayer_share_int_from_x_and_client_share_v1_spec(x_be_bytes, x_client_be_bytes)
            < secp256k1_order_v1_spec(),
{
    let x = bytes32_as_int_v1_spec(x_be_bytes);
    let x_client = bytes32_as_int_v1_spec(x_client_be_bytes);
    broadcast use axiom_valid_scalar_bytes_are_injective_v1;
    if x >= x_client {
        assert(x != x_client);
        assert(relayer_share_int_from_x_and_client_share_v1_spec(x_be_bytes, x_client_be_bytes) == x - x_client);
        assert(x - x_client > 0);
        assert(x - x_client < secp256k1_order_v1_spec());
    } else {
        assert(relayer_share_int_from_x_and_client_share_v1_spec(x_be_bytes, x_client_be_bytes)
            == x + secp256k1_order_v1_spec() - x_client);
        assert(x + secp256k1_order_v1_spec() - x_client > 0);
        assert(x + secp256k1_order_v1_spec() - x_client < secp256k1_order_v1_spec());
    }
}

pub proof fn relayer_share_reconstructs_canonical_scalar_v1(
    x_be_bytes: Bytes32,
    x_client_be_bytes: Bytes32,
)
    requires
        is_valid_nonzero_scalar_v1_spec(x_be_bytes),
        is_valid_nonzero_scalar_v1_spec(x_client_be_bytes),
        x_client_be_bytes != x_be_bytes,
    ensures
        (
            bytes32_as_int_v1_spec(x_client_be_bytes)
                + relayer_share_int_from_x_and_client_share_v1_spec(
                    x_be_bytes,
                    x_client_be_bytes,
                )
        ) % secp256k1_order_v1_spec() == bytes32_as_int_v1_spec(x_be_bytes),
{
    let x = bytes32_as_int_v1_spec(x_be_bytes);
    let x_client = bytes32_as_int_v1_spec(x_client_be_bytes);
    if x >= x_client {
        assert(relayer_share_int_from_x_and_client_share_v1_spec(x_be_bytes, x_client_be_bytes) == x - x_client);
        assert((x_client + (x - x_client)) % secp256k1_order_v1_spec() == x);
    } else {
        assert(relayer_share_int_from_x_and_client_share_v1_spec(x_be_bytes, x_client_be_bytes)
            == x + secp256k1_order_v1_spec() - x_client);
        assert((x_client + (x + secp256k1_order_v1_spec() - x_client))
            % secp256k1_order_v1_spec() == x);
    }
}

pub proof fn additive_share_reconstruction_goal_matches_derived_outputs(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
)
    ensures
        additive_shares_reconstruct_x_v1_spec(x_be_bytes, context)
            == (
                (
                    bytes32_as_int_v1_spec(
                        derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes,
                    ) + bytes32_as_int_v1_spec(
                        derive_additive_shares_v1_spec(x_be_bytes, context).x_relayer_be_bytes,
                    )
                ) % secp256k1_order_v1_spec() == bytes32_as_int_v1_spec(x_be_bytes)
            ),
{
}

pub proof fn additive_share_outputs_are_valid_nonzero_scalars(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
)
    requires
        is_valid_nonzero_scalar_v1_spec(x_be_bytes),
    ensures
        additive_shares_are_in_scalar_domain_v1_spec(x_be_bytes, context),
{
    broadcast use axiom_reduce_hash_to_valid_scalar_is_valid_v1;
    broadcast use axiom_retry_counter_selects_first_distinct_client_share_v1;
    broadcast use axiom_scalar_int_encoding_matches_value_v1;
    broadcast use axiom_valid_scalar_bytes_are_injective_v1;
    relayer_share_int_is_valid_nonzero_scalar_v1(
        x_be_bytes,
        derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes,
    );
}

pub proof fn additive_shares_reconstruct_the_canonical_scalar(
    x_be_bytes: Bytes32,
    context: CanonicalContextV1,
)
    requires
        is_valid_nonzero_scalar_v1_spec(x_be_bytes),
    ensures
        additive_shares_reconstruct_x_v1_spec(x_be_bytes, context),
{
    broadcast use axiom_reduce_hash_to_valid_scalar_is_valid_v1;
    broadcast use axiom_retry_counter_selects_first_distinct_client_share_v1;
    broadcast use axiom_scalar_int_encoding_matches_value_v1;
    broadcast use axiom_valid_scalar_bytes_are_injective_v1;
    relayer_share_reconstructs_canonical_scalar_v1(
        x_be_bytes,
        derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes,
    );
    relayer_share_int_is_valid_nonzero_scalar_v1(
        x_be_bytes,
        derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes,
    );
    assert(
        bytes32_as_int_v1_spec(
            derive_additive_shares_v1_spec(x_be_bytes, context).x_relayer_be_bytes,
        ) == relayer_share_int_from_x_and_client_share_v1_spec(
            x_be_bytes,
            derive_additive_shares_v1_spec(x_be_bytes, context).x_client_be_bytes,
        )
    );
}

pub proof fn retry_counter_is_deterministic_for_fixed_inputs(
    left_x_be_bytes: Bytes32,
    left_context: CanonicalContextV1,
    right_x_be_bytes: Bytes32,
    right_context: CanonicalContextV1,
)
    requires
        left_x_be_bytes == right_x_be_bytes,
        left_context == right_context,
    ensures
        derive_additive_shares_v1_spec(left_x_be_bytes, left_context).retry_counter
            == derive_additive_shares_v1_spec(right_x_be_bytes, right_context).retry_counter,
        retry_counter_v1_spec(left_x_be_bytes, left_context)
            == retry_counter_v1_spec(right_x_be_bytes, right_context),
{
}

pub proof fn secp256k1_scalar_width_is_fixed_v1()
    ensures
        secp256k1_scalar_width_bytes_v1_spec() == 32,
{
}

}
