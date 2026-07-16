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

pub open spec fn client_participant_id_spec() -> u16 {
    1u16
}

pub open spec fn relayer_participant_id_spec() -> u16 {
    2u16
}

#[derive(Debug, PartialEq, Eq)]
pub struct BackendMappedShare {
    pub participant_id: u16,
    pub mapped_scalar_be_bytes: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BackendSharePair {
    pub client_share: BackendMappedShare,
    pub relayer_share: BackendMappedShare,
}

pub open spec fn client_lambda_spec() -> int {
    3int
}

pub open spec fn relayer_lambda_spec() -> int {
    crate::shared::derivation::secp256k1_order_spec() - 2int
}

pub open spec fn is_supported_2p_participant_id_spec(participant_id: u16) -> bool {
    participant_id == client_participant_id_spec()
        || participant_id == relayer_participant_id_spec()
}

pub open spec fn lambda_for_participant_spec(participant_id: u16) -> int {
    if participant_id == client_participant_id_spec() {
        client_lambda_spec()
    } else if participant_id == relayer_participant_id_spec() {
        relayer_lambda_spec()
    } else {
        0int
    }
}

pub open spec fn client_lambda_inverse_spec() -> int {
    77194726158210796949047323339125271901891709519383269588403442094345440996225int
}

pub open spec fn relayer_lambda_inverse_spec() -> int {
    57896044618658097711785492504343953926418782139537452191302581570759080747168int
}

pub open spec fn lambda_inverse_for_participant_spec(participant_id: u16) -> int {
    if participant_id == client_participant_id_spec() {
        client_lambda_inverse_spec()
    } else if participant_id == relayer_participant_id_spec() {
        relayer_lambda_inverse_spec()
    } else {
        0int
    }
}

pub open spec fn mapped_backend_scalar_int_spec(
    additive_share_be_bytes: Bytes32,
    participant_id: u16,
) -> int {
    (
        crate::shared::derivation::bytes32_as_int_spec(additive_share_be_bytes)
            * lambda_inverse_for_participant_spec(participant_id)
    ) % crate::shared::derivation::secp256k1_order_spec()
}

pub open spec fn map_additive_share_scalar_to_backend_spec(
    additive_share_be_bytes: Bytes32,
    participant_id: u16,
) -> Bytes32 {
    crate::shared::derivation::scalar_int_to_bytes32_spec(
        mapped_backend_scalar_int_spec(additive_share_be_bytes, participant_id),
    )
}

pub open spec fn backend_share_is_accepted_by_domain_spec(
    share: BackendMappedShare,
) -> bool {
    &&& is_supported_2p_participant_id_spec(share.participant_id)
    &&& crate::shared::derivation::is_valid_nonzero_scalar_spec(share.mapped_scalar_be_bytes)
}

pub open spec fn map_additive_shares_to_backend_spec(
    x_client_be_bytes: Bytes32,
    x_relayer_be_bytes: Bytes32,
) -> BackendSharePair {
    BackendSharePair {
        client_share: BackendMappedShare {
            participant_id: client_participant_id_spec(),
            mapped_scalar_be_bytes: map_additive_share_scalar_to_backend_spec(
                x_client_be_bytes,
                client_participant_id_spec(),
            ),
        },
        relayer_share: BackendMappedShare {
            participant_id: relayer_participant_id_spec(),
            mapped_scalar_be_bytes: map_additive_share_scalar_to_backend_spec(
                x_relayer_be_bytes,
                relayer_participant_id_spec(),
            ),
        },
    }
}

pub open spec fn map_derived_additive_shares_to_backend_spec(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContext,
) -> BackendSharePair {
    let derived = crate::shared::derivation::derive_additive_shares_spec(x_be_bytes, context);
    map_additive_shares_to_backend_spec(derived.x_client_be_bytes, derived.x_relayer_be_bytes)
}

pub open spec fn effective_group_secret_from_backend_pair_spec(
    pair: BackendSharePair,
) -> int {
    (
        lambda_for_participant_spec(pair.client_share.participant_id)
            * crate::shared::derivation::bytes32_as_int_spec(
                pair.client_share.mapped_scalar_be_bytes,
            )
            + lambda_for_participant_spec(pair.relayer_share.participant_id)
                * crate::shared::derivation::bytes32_as_int_spec(
                    pair.relayer_share.mapped_scalar_be_bytes,
                )
    ) % crate::shared::derivation::secp256k1_order_spec()
}

pub uninterp spec fn public_key_from_scalar_spec(
    scalar_be_bytes: Bytes32,
) -> Bytes33;

pub uninterp spec fn threshold_public_key_from_backend_pair_spec(
    pair: BackendSharePair,
) -> Bytes33;

pub uninterp spec fn ethereum_address_from_public_key_spec(
    public_key33: Bytes33,
) -> Bytes20;

pub open spec fn canonical_public_key_from_x_spec(
    x_be_bytes: Bytes32,
) -> Bytes33 {
    public_key_from_scalar_spec(x_be_bytes)
}

pub open spec fn threshold_public_key_from_x_via_backend_spec(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContext,
) -> Bytes33 {
    threshold_public_key_from_backend_pair_spec(
        map_derived_additive_shares_to_backend_spec(x_be_bytes, context),
    )
}

pub open spec fn canonical_address_from_x_spec(
    x_be_bytes: Bytes32,
) -> Bytes20 {
    ethereum_address_from_public_key_spec(canonical_public_key_from_x_spec(x_be_bytes))
}

pub open spec fn threshold_address_from_x_via_backend_spec(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContext,
) -> Bytes20 {
    ethereum_address_from_public_key_spec(
        threshold_public_key_from_x_via_backend_spec(x_be_bytes, context),
    )
}

pub broadcast axiom fn axiom_threshold_public_key_matches_effective_group_secret(
    pair: BackendSharePair,
    x_be_bytes: Bytes32,
)
    requires
        backend_share_is_accepted_by_domain_spec(pair.client_share),
        backend_share_is_accepted_by_domain_spec(pair.relayer_share),
        crate::shared::derivation::is_valid_nonzero_scalar_spec(x_be_bytes),
        effective_group_secret_from_backend_pair_spec(pair)
            == crate::shared::derivation::bytes32_as_int_spec(x_be_bytes),
    ensures
        #![trigger threshold_public_key_from_backend_pair_spec(pair), public_key_from_scalar_spec(x_be_bytes)]
        threshold_public_key_from_backend_pair_spec(pair)
            == public_key_from_scalar_spec(x_be_bytes),
;

pub proof fn client_lambda_inverse_is_correct()
    ensures
        (client_lambda_spec() * client_lambda_inverse_spec())
            % crate::shared::derivation::secp256k1_order_spec() == 1int,
{
}

pub proof fn relayer_lambda_inverse_is_correct()
    ensures
        (relayer_lambda_spec() * relayer_lambda_inverse_spec())
            % crate::shared::derivation::secp256k1_order_spec() == 1int,
{
}

pub proof fn mapped_backend_scalar_is_valid(
    additive_share_be_bytes: Bytes32,
    participant_id: u16,
)
    requires
        is_supported_2p_participant_id_spec(participant_id),
        crate::shared::derivation::is_valid_nonzero_scalar_spec(additive_share_be_bytes),
    ensures
        crate::shared::derivation::is_valid_nonzero_scalar_spec(
            map_additive_share_scalar_to_backend_spec(additive_share_be_bytes, participant_id),
        ),
{
    let mapped_value = mapped_backend_scalar_int_spec(additive_share_be_bytes, participant_id);
    if participant_id == client_participant_id_spec() {
        mapped_client_scalar_preserves_share_int(additive_share_be_bytes);
    } else {
        mapped_relayer_scalar_preserves_share_int(additive_share_be_bytes);
    }
    assert(mapped_value != 0);
    assert(0 < mapped_value);
    assert(mapped_value < crate::shared::derivation::secp256k1_order_spec());
    crate::shared::derivation::axiom_scalar_int_encoding_matches_value(mapped_value);
}

pub proof fn mapped_client_scalar_preserves_share_int(additive_share_be_bytes: Bytes32)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_spec(additive_share_be_bytes),
    ensures
        (
            client_lambda_spec()
                * mapped_backend_scalar_int_spec(
                    additive_share_be_bytes,
                    client_participant_id_spec(),
                )
        ) % crate::shared::derivation::secp256k1_order_spec()
            == crate::shared::derivation::bytes32_as_int_spec(additive_share_be_bytes),
{
    let n = crate::shared::derivation::secp256k1_order_spec();
    let a = crate::shared::derivation::bytes32_as_int_spec(additive_share_be_bytes);
    let inv = client_lambda_inverse_spec();
    let mapped = mapped_backend_scalar_int_spec(additive_share_be_bytes, client_participant_id_spec());
    client_lambda_inverse_is_correct();
    assert(mapped == (a * inv) % n);
    assert(((client_lambda_spec() * mapped) % n) == ((client_lambda_spec() * (a * inv)) % n));
    assert(client_lambda_spec() * (a * inv) == (client_lambda_spec() * inv) * a) by (nonlinear_arith);
    assert((client_lambda_spec() * (a * inv)) % n == ((client_lambda_spec() * inv) * a) % n);
    assert(((client_lambda_spec() * inv) * a) % n == a);
}

pub proof fn mapped_relayer_scalar_preserves_share_int(additive_share_be_bytes: Bytes32)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_spec(additive_share_be_bytes),
    ensures
        (
            relayer_lambda_spec()
                * mapped_backend_scalar_int_spec(
                    additive_share_be_bytes,
                    relayer_participant_id_spec(),
                )
        ) % crate::shared::derivation::secp256k1_order_spec()
            == crate::shared::derivation::bytes32_as_int_spec(additive_share_be_bytes),
{
    let n = crate::shared::derivation::secp256k1_order_spec();
    let a = crate::shared::derivation::bytes32_as_int_spec(additive_share_be_bytes);
    let inv = relayer_lambda_inverse_spec();
    let mapped = mapped_backend_scalar_int_spec(additive_share_be_bytes, relayer_participant_id_spec());
    relayer_lambda_inverse_is_correct();
    assert(mapped == (a * inv) % n);
    assert(((relayer_lambda_spec() * mapped) % n) == ((relayer_lambda_spec() * (a * inv)) % n));
    assert(relayer_lambda_spec() * (a * inv) == (relayer_lambda_spec() * inv) * a) by (nonlinear_arith);
    assert((relayer_lambda_spec() * (a * inv)) % n == ((relayer_lambda_spec() * inv) * a) % n);
    assert(((relayer_lambda_spec() * inv) * a) % n == a);
}

pub proof fn mapped_backend_scalar_preserves_additive_share(
    additive_share_be_bytes: Bytes32,
    participant_id: u16,
)
    requires
        is_supported_2p_participant_id_spec(participant_id),
        crate::shared::derivation::is_valid_nonzero_scalar_spec(additive_share_be_bytes),
    ensures
        (
            lambda_for_participant_spec(participant_id)
                * crate::shared::derivation::bytes32_as_int_spec(
                    map_additive_share_scalar_to_backend_spec(
                        additive_share_be_bytes,
                        participant_id,
                    ),
                )
        ) % crate::shared::derivation::secp256k1_order_spec()
            == crate::shared::derivation::bytes32_as_int_spec(additive_share_be_bytes),
{
    mapped_backend_scalar_is_valid(additive_share_be_bytes, participant_id);
    if participant_id == client_participant_id_spec() {
        mapped_client_scalar_preserves_share_int(additive_share_be_bytes);
    } else {
        mapped_relayer_scalar_preserves_share_int(additive_share_be_bytes);
    }
    crate::shared::derivation::axiom_scalar_int_encoding_matches_value(
        mapped_backend_scalar_int_spec(additive_share_be_bytes, participant_id),
    );
    assert(
        crate::shared::derivation::bytes32_as_int_spec(
            map_additive_share_scalar_to_backend_spec(additive_share_be_bytes, participant_id),
        ) == mapped_backend_scalar_int_spec(additive_share_be_bytes, participant_id)
    );
}

pub proof fn backend_mapping_uses_fixed_participant_ids(
    x_client_be_bytes: Bytes32,
    x_relayer_be_bytes: Bytes32,
)
    ensures
        map_additive_shares_to_backend_spec(x_client_be_bytes, x_relayer_be_bytes)
            .client_share.participant_id == 1u16,
        map_additive_shares_to_backend_spec(x_client_be_bytes, x_relayer_be_bytes)
            .relayer_share.participant_id == 2u16,
{
}

pub proof fn mapped_backend_shares_are_accepted_by_domain(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContext,
)
    requires
        crate::shared::derivation::additive_shares_are_in_scalar_domain_spec(x_be_bytes, context),
    ensures
        backend_share_is_accepted_by_domain_spec(
            map_derived_additive_shares_to_backend_spec(x_be_bytes, context).client_share,
        ),
        backend_share_is_accepted_by_domain_spec(
            map_derived_additive_shares_to_backend_spec(x_be_bytes, context).relayer_share,
        ),
{
    mapped_backend_scalar_is_valid(
        crate::shared::derivation::derive_additive_shares_spec(x_be_bytes, context).x_client_be_bytes,
        client_participant_id_spec(),
    );
    mapped_backend_scalar_is_valid(
        crate::shared::derivation::derive_additive_shares_spec(x_be_bytes, context).x_relayer_be_bytes,
        relayer_participant_id_spec(),
    );
}

pub proof fn mapped_backend_shares_preserve_effective_group_secret(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContext,
)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_spec(x_be_bytes),
        crate::shared::derivation::additive_shares_are_in_scalar_domain_spec(x_be_bytes, context),
        crate::shared::derivation::additive_shares_reconstruct_x_spec(x_be_bytes, context),
    ensures
        effective_group_secret_from_backend_pair_spec(
            map_derived_additive_shares_to_backend_spec(x_be_bytes, context),
        ) == crate::shared::derivation::bytes32_as_int_spec(x_be_bytes),
{
    mapped_backend_scalar_preserves_additive_share(
        crate::shared::derivation::derive_additive_shares_spec(x_be_bytes, context).x_client_be_bytes,
        client_participant_id_spec(),
    );
    mapped_backend_scalar_preserves_additive_share(
        crate::shared::derivation::derive_additive_shares_spec(x_be_bytes, context).x_relayer_be_bytes,
        relayer_participant_id_spec(),
    );
}

pub proof fn threshold_public_key_equals_x_times_g(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContext,
)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_spec(x_be_bytes),
        crate::shared::derivation::additive_shares_are_in_scalar_domain_spec(x_be_bytes, context),
        crate::shared::derivation::additive_shares_reconstruct_x_spec(x_be_bytes, context),
    ensures
        threshold_public_key_from_x_via_backend_spec(x_be_bytes, context)
            == canonical_public_key_from_x_spec(x_be_bytes),
{
    mapped_backend_shares_are_accepted_by_domain(x_be_bytes, context);
    mapped_backend_shares_preserve_effective_group_secret(x_be_bytes, context);
    broadcast use axiom_threshold_public_key_matches_effective_group_secret;
}

pub proof fn threshold_signing_address_equals_addr_x_times_g(
    x_be_bytes: Bytes32,
    context: crate::shared::context::CanonicalContext,
)
    requires
        crate::shared::derivation::is_valid_nonzero_scalar_spec(x_be_bytes),
        crate::shared::derivation::additive_shares_are_in_scalar_domain_spec(x_be_bytes, context),
        crate::shared::derivation::additive_shares_reconstruct_x_spec(x_be_bytes, context),
    ensures
        threshold_address_from_x_via_backend_spec(x_be_bytes, context)
            == canonical_address_from_x_spec(x_be_bytes),
{
    threshold_public_key_equals_x_times_g(x_be_bytes, context);
}

}
