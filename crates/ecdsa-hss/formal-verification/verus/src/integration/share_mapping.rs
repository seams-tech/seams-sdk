//! Verification entrypoint for the current backend seam.
//!
//! Planned proof targets:
//! - fixed participant-ID mapping for `{1, 2}`
//! - mapped-share acceptance by the current backend domain rules
//! - same-key preservation through the mapping layer

use vstd::prelude::*;

use crate::shared::derivation::Bytes32;

verus! {

pub type Bytes33 = [u8; 33];
pub type Bytes20 = [u8; 20];

pub open spec fn client_participant_id_v1_spec() -> u16 {
    1u16
}

pub open spec fn relayer_participant_id_v1_spec() -> u16 {
    2u16
}

#[derive(Debug, PartialEq, Eq)]
pub struct BackendMappedShareV1 {
    pub participant_id: u16,
    pub mapped_scalar_be_bytes: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BackendSharePairV1 {
    pub client_share: BackendMappedShareV1,
    pub relayer_share: BackendMappedShareV1,
}

pub open spec fn client_lambda_v1_spec() -> int {
    3int
}

pub open spec fn relayer_lambda_v1_spec() -> int {
    crate::shared::derivation::secp256k1_order_v1_spec() - 2int
}

pub open spec fn is_supported_2p_participant_id_v1_spec(participant_id: u16) -> bool {
    participant_id == client_participant_id_v1_spec()
        || participant_id == relayer_participant_id_v1_spec()
}

pub open spec fn lambda_for_participant_v1_spec(participant_id: u16) -> int {
    if participant_id == client_participant_id_v1_spec() {
        client_lambda_v1_spec()
    } else if participant_id == relayer_participant_id_v1_spec() {
        relayer_lambda_v1_spec()
    } else {
        0int
    }
}

pub uninterp spec fn map_additive_share_scalar_to_backend_v1_spec(
    additive_share_be_bytes: Bytes32,
    participant_id: u16,
) -> Bytes32;

pub broadcast axiom fn axiom_backend_mapping_preserves_additive_share_for_supported_ids_v1(
    additive_share_be_bytes: Bytes32,
    participant_id: u16,
)
    requires
        is_supported_2p_participant_id_v1_spec(participant_id),
        crate::shared::derivation::is_valid_nonzero_scalar_v1_spec(additive_share_be_bytes),
    ensures
        #![trigger map_additive_share_scalar_to_backend_v1_spec(
            additive_share_be_bytes,
            participant_id,
        )]
        crate::shared::derivation::is_valid_nonzero_scalar_v1_spec(
            map_additive_share_scalar_to_backend_v1_spec(additive_share_be_bytes, participant_id),
        ),
        (
            lambda_for_participant_v1_spec(participant_id)
                * crate::shared::derivation::bytes32_as_int_v1_spec(
                    map_additive_share_scalar_to_backend_v1_spec(
                    additive_share_be_bytes,
                    participant_id,
                ))
        ) % crate::shared::derivation::secp256k1_order_v1_spec()
            == crate::shared::derivation::bytes32_as_int_v1_spec(additive_share_be_bytes),
;

pub open spec fn backend_share_is_accepted_by_domain_v1_spec(
    share: BackendMappedShareV1,
) -> bool {
    &&& is_supported_2p_participant_id_v1_spec(share.participant_id)
    &&& crate::shared::derivation::is_valid_nonzero_scalar_v1_spec(share.mapped_scalar_be_bytes)
}

pub open spec fn map_additive_shares_to_backend_v1_spec(
    x_client_be_bytes: Bytes32,
    x_relayer_be_bytes: Bytes32,
) -> BackendSharePairV1 {
    BackendSharePairV1 {
        client_share: BackendMappedShareV1 {
            participant_id: client_participant_id_v1_spec(),
            mapped_scalar_be_bytes: map_additive_share_scalar_to_backend_v1_spec(
                x_client_be_bytes,
                client_participant_id_v1_spec(),
            ),
        },
        relayer_share: BackendMappedShareV1 {
            participant_id: relayer_participant_id_v1_spec(),
            mapped_scalar_be_bytes: map_additive_share_scalar_to_backend_v1_spec(
                x_relayer_be_bytes,
                relayer_participant_id_v1_spec(),
            ),
        },
    }
}

pub open spec fn map_derived_additive_shares_to_backend_v1_spec(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContextV1,
) -> BackendSharePairV1 {
    let derived = crate::shared::derivation::derive_additive_shares_v1_spec(x_be_bytes, context);
    map_additive_shares_to_backend_v1_spec(derived.x_client_be_bytes, derived.x_relayer_be_bytes)
}

pub open spec fn effective_group_secret_from_backend_pair_v1_spec(
    pair: BackendSharePairV1,
) -> int {
    (
        lambda_for_participant_v1_spec(pair.client_share.participant_id)
            * crate::shared::derivation::bytes32_as_int_v1_spec(
                pair.client_share.mapped_scalar_be_bytes,
            )
            + lambda_for_participant_v1_spec(pair.relayer_share.participant_id)
                * crate::shared::derivation::bytes32_as_int_v1_spec(
                    pair.relayer_share.mapped_scalar_be_bytes,
                )
    ) % crate::shared::derivation::secp256k1_order_v1_spec()
}

pub uninterp spec fn public_key_from_scalar_v1_spec(
    scalar_be_bytes: Bytes32,
) -> Bytes33;

pub uninterp spec fn threshold_public_key_from_backend_pair_v1_spec(
    pair: BackendSharePairV1,
) -> Bytes33;

pub uninterp spec fn ethereum_address_from_public_key_v1_spec(
    public_key33: Bytes33,
) -> Bytes20;

pub open spec fn canonical_public_key_from_x_v1_spec(
    x_be_bytes: Bytes32,
) -> Bytes33 {
    public_key_from_scalar_v1_spec(x_be_bytes)
}

pub open spec fn threshold_public_key_from_x_via_backend_v1_spec(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContextV1,
) -> Bytes33 {
    threshold_public_key_from_backend_pair_v1_spec(
        map_derived_additive_shares_to_backend_v1_spec(x_be_bytes, context),
    )
}

pub open spec fn canonical_address_from_x_v1_spec(
    x_be_bytes: Bytes32,
) -> Bytes20 {
    ethereum_address_from_public_key_v1_spec(canonical_public_key_from_x_v1_spec(x_be_bytes))
}

pub open spec fn threshold_address_from_x_via_backend_v1_spec(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContextV1,
) -> Bytes20 {
    ethereum_address_from_public_key_v1_spec(
        threshold_public_key_from_x_via_backend_v1_spec(x_be_bytes, context),
    )
}

pub broadcast axiom fn axiom_threshold_public_key_matches_effective_group_secret_v1(
    pair: BackendSharePairV1,
    x_be_bytes: Bytes32,
)
    requires
        backend_share_is_accepted_by_domain_v1_spec(pair.client_share),
        backend_share_is_accepted_by_domain_v1_spec(pair.relayer_share),
        crate::shared::derivation::is_valid_nonzero_scalar_v1_spec(x_be_bytes),
        effective_group_secret_from_backend_pair_v1_spec(pair)
            == crate::shared::derivation::bytes32_as_int_v1_spec(x_be_bytes),
    ensures
        #![trigger threshold_public_key_from_backend_pair_v1_spec(pair), public_key_from_scalar_v1_spec(x_be_bytes)]
        threshold_public_key_from_backend_pair_v1_spec(pair)
            == public_key_from_scalar_v1_spec(x_be_bytes),
;

pub proof fn backend_mapping_uses_fixed_participant_ids_v1(
    x_client_be_bytes: Bytes32,
    x_relayer_be_bytes: Bytes32,
)
    ensures
        map_additive_shares_to_backend_v1_spec(x_client_be_bytes, x_relayer_be_bytes)
            .client_share.participant_id == 1u16,
        map_additive_shares_to_backend_v1_spec(x_client_be_bytes, x_relayer_be_bytes)
            .relayer_share.participant_id == 2u16,
{
}

pub proof fn mapped_backend_shares_are_accepted_by_domain_v1(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContextV1,
)
    requires
        crate::shared::derivation::additive_shares_are_in_scalar_domain_v1_spec(x_be_bytes, context),
    ensures
        backend_share_is_accepted_by_domain_v1_spec(
            map_derived_additive_shares_to_backend_v1_spec(x_be_bytes, context).client_share,
        ),
        backend_share_is_accepted_by_domain_v1_spec(
            map_derived_additive_shares_to_backend_v1_spec(x_be_bytes, context).relayer_share,
        ),
{
    broadcast use axiom_backend_mapping_preserves_additive_share_for_supported_ids_v1;
}

pub proof fn mapped_backend_shares_preserve_effective_group_secret_v1(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContextV1,
)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_v1_spec(x_be_bytes),
        crate::shared::derivation::additive_shares_are_in_scalar_domain_v1_spec(x_be_bytes, context),
        crate::shared::derivation::additive_shares_reconstruct_x_v1_spec(x_be_bytes, context),
    ensures
        effective_group_secret_from_backend_pair_v1_spec(
            map_derived_additive_shares_to_backend_v1_spec(x_be_bytes, context),
        ) == crate::shared::derivation::bytes32_as_int_v1_spec(x_be_bytes),
{
    broadcast use axiom_backend_mapping_preserves_additive_share_for_supported_ids_v1;
}

pub proof fn threshold_public_key_equals_x_times_g_v1(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContextV1,
)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_v1_spec(x_be_bytes),
        crate::shared::derivation::additive_shares_are_in_scalar_domain_v1_spec(x_be_bytes, context),
        crate::shared::derivation::additive_shares_reconstruct_x_v1_spec(x_be_bytes, context),
    ensures
        threshold_public_key_from_x_via_backend_v1_spec(x_be_bytes, context)
            == canonical_public_key_from_x_v1_spec(x_be_bytes),
{
    mapped_backend_shares_are_accepted_by_domain_v1(x_be_bytes, context);
    mapped_backend_shares_preserve_effective_group_secret_v1(x_be_bytes, context);
    broadcast use axiom_threshold_public_key_matches_effective_group_secret_v1;
}

pub proof fn threshold_signing_address_equals_addr_x_times_g_v1(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContextV1,
)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_v1_spec(x_be_bytes),
        crate::shared::derivation::additive_shares_are_in_scalar_domain_v1_spec(x_be_bytes, context),
        crate::shared::derivation::additive_shares_reconstruct_x_v1_spec(x_be_bytes, context),
    ensures
        threshold_address_from_x_via_backend_v1_spec(x_be_bytes, context)
            == canonical_address_from_x_v1_spec(x_be_bytes),
{
    threshold_public_key_equals_x_times_g_v1(x_be_bytes, context);
}

}
