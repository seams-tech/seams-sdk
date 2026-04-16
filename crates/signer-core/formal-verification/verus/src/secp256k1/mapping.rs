//! Verus model for `map_additive_share_to_threshold_signatures_share_2p`.

use vstd::prelude::*;

use super::scalar::Bytes32;

verus! {

#[derive(Debug, PartialEq, Eq)]
pub struct BackendMappedShareV1 {
    pub participant_id: u32,
    pub mapped_scalar_be_bytes: Bytes32,
}

pub uninterp spec fn scalar_int_to_bytes32_v1_spec(value: int) -> Bytes32;

pub broadcast axiom fn axiom_scalar_int_encoding_matches_value_v1(value: int)
    requires
        0 < value < crate::secp256k1::scalar::secp256k1_order_v1_spec(),
    ensures
        #![trigger scalar_int_to_bytes32_v1_spec(value)]
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(
            scalar_int_to_bytes32_v1_spec(value),
        ),
        crate::secp256k1::scalar::bytes32_as_int_v1_spec(
            scalar_int_to_bytes32_v1_spec(value),
        ) == value,
;

pub open spec fn client_participant_id_v1_spec() -> u32 {
    1u32
}

pub open spec fn relayer_participant_id_v1_spec() -> u32 {
    2u32
}

pub open spec fn is_supported_2p_participant_id_v1_spec(participant_id: u32) -> bool {
    participant_id == client_participant_id_v1_spec()
        || participant_id == relayer_participant_id_v1_spec()
}

pub open spec fn client_lambda_v1_spec() -> int {
    3int
}

pub open spec fn relayer_lambda_v1_spec() -> int {
    crate::secp256k1::scalar::secp256k1_order_v1_spec() - 2int
}

pub open spec fn lambda_for_participant_v1_spec(participant_id: u32) -> int {
    if participant_id == client_participant_id_v1_spec() {
        client_lambda_v1_spec()
    } else if participant_id == relayer_participant_id_v1_spec() {
        relayer_lambda_v1_spec()
    } else {
        0int
    }
}

pub open spec fn client_lambda_inverse_v1_spec() -> int {
    77194726158210796949047323339125271901891709519383269588403442094345440996225int
}

pub open spec fn relayer_lambda_inverse_v1_spec() -> int {
    57896044618658097711785492504343953926418782139537452191302581570759080747168int
}

pub open spec fn lambda_inverse_for_participant_v1_spec(participant_id: u32) -> int {
    if participant_id == client_participant_id_v1_spec() {
        client_lambda_inverse_v1_spec()
    } else if participant_id == relayer_participant_id_v1_spec() {
        relayer_lambda_inverse_v1_spec()
    } else {
        0int
    }
}

pub open spec fn mapped_backend_scalar_int_v1_spec(
    additive_share32: Bytes32,
    participant_id: u32,
) -> int {
    (
        crate::secp256k1::scalar::bytes32_as_int_v1_spec(additive_share32)
            * lambda_inverse_for_participant_v1_spec(participant_id)
    ) % crate::secp256k1::scalar::secp256k1_order_v1_spec()
}

pub open spec fn map_supported_additive_share_to_backend_v1_spec(
    additive_share32: Bytes32,
    participant_id: u32,
) -> BackendMappedShareV1 {
    BackendMappedShareV1 {
        participant_id,
        mapped_scalar_be_bytes: scalar_int_to_bytes32_v1_spec(
            mapped_backend_scalar_int_v1_spec(additive_share32, participant_id),
        ),
    }
}

pub open spec fn map_additive_share_to_threshold_signatures_share_2p_v1_spec(
    additive_share32: Bytes32,
    participant_id: u32,
) -> Option<BackendMappedShareV1> {
    if is_supported_2p_participant_id_v1_spec(participant_id) {
        Some(map_supported_additive_share_to_backend_v1_spec(additive_share32, participant_id))
    } else {
        None
    }
}

pub proof fn unsupported_participant_ids_are_rejected_v1(
    additive_share32: Bytes32,
    participant_id: u32,
)
    requires
        !is_supported_2p_participant_id_v1_spec(participant_id),
    ensures
        map_additive_share_to_threshold_signatures_share_2p_v1_spec(
            additive_share32,
            participant_id,
        ).is_none(),
{
}

pub proof fn client_lambda_inverse_is_correct_v1()
    ensures
        (client_lambda_v1_spec() * client_lambda_inverse_v1_spec())
            % crate::secp256k1::scalar::secp256k1_order_v1_spec() == 1int,
{
}

pub proof fn relayer_lambda_inverse_is_correct_v1()
    ensures
        (relayer_lambda_v1_spec() * relayer_lambda_inverse_v1_spec())
            % crate::secp256k1::scalar::secp256k1_order_v1_spec() == 1int,
{
}

pub proof fn mapped_client_scalar_preserves_share_int_v1(additive_share32: Bytes32)
    requires
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(additive_share32),
    ensures
        (
            client_lambda_v1_spec()
                * mapped_backend_scalar_int_v1_spec(
                    additive_share32,
                    client_participant_id_v1_spec(),
                )
        ) % crate::secp256k1::scalar::secp256k1_order_v1_spec()
            == crate::secp256k1::scalar::bytes32_as_int_v1_spec(additive_share32),
{
    let n = crate::secp256k1::scalar::secp256k1_order_v1_spec();
    let a = crate::secp256k1::scalar::bytes32_as_int_v1_spec(additive_share32);
    let inv = client_lambda_inverse_v1_spec();
    let mapped = mapped_backend_scalar_int_v1_spec(additive_share32, client_participant_id_v1_spec());
    client_lambda_inverse_is_correct_v1();
    assert(mapped == (a * inv) % n);
    assert(((client_lambda_v1_spec() * mapped) % n) == ((client_lambda_v1_spec() * (a * inv)) % n));
    assert(client_lambda_v1_spec() * (a * inv) == (client_lambda_v1_spec() * inv) * a) by (nonlinear_arith);
    assert((client_lambda_v1_spec() * (a * inv)) % n == ((client_lambda_v1_spec() * inv) * a) % n);
    assert(((client_lambda_v1_spec() * inv) * a) % n == a);
}

pub proof fn mapped_relayer_scalar_preserves_share_int_v1(additive_share32: Bytes32)
    requires
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(additive_share32),
    ensures
        (
            relayer_lambda_v1_spec()
                * mapped_backend_scalar_int_v1_spec(
                    additive_share32,
                    relayer_participant_id_v1_spec(),
                )
        ) % crate::secp256k1::scalar::secp256k1_order_v1_spec()
            == crate::secp256k1::scalar::bytes32_as_int_v1_spec(additive_share32),
{
    let n = crate::secp256k1::scalar::secp256k1_order_v1_spec();
    let a = crate::secp256k1::scalar::bytes32_as_int_v1_spec(additive_share32);
    let inv = relayer_lambda_inverse_v1_spec();
    let mapped = mapped_backend_scalar_int_v1_spec(additive_share32, relayer_participant_id_v1_spec());
    relayer_lambda_inverse_is_correct_v1();
    assert(mapped == (a * inv) % n);
    assert(((relayer_lambda_v1_spec() * mapped) % n) == ((relayer_lambda_v1_spec() * (a * inv)) % n));
    assert(relayer_lambda_v1_spec() * (a * inv) == (relayer_lambda_v1_spec() * inv) * a) by (nonlinear_arith);
    assert((relayer_lambda_v1_spec() * (a * inv)) % n == ((relayer_lambda_v1_spec() * inv) * a) % n);
    assert(((relayer_lambda_v1_spec() * inv) * a) % n == a);
}

pub proof fn mapped_backend_scalar_is_valid_v1(
    additive_share32: Bytes32,
    participant_id: u32,
)
    requires
        is_supported_2p_participant_id_v1_spec(participant_id),
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(additive_share32),
    ensures
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(
            map_supported_additive_share_to_backend_v1_spec(
                additive_share32,
                participant_id,
            ).mapped_scalar_be_bytes,
        ),
{
    let mapped_value = mapped_backend_scalar_int_v1_spec(additive_share32, participant_id);
    if participant_id == client_participant_id_v1_spec() {
        mapped_client_scalar_preserves_share_int_v1(additive_share32);
    } else {
        mapped_relayer_scalar_preserves_share_int_v1(additive_share32);
    }
    assert(mapped_value != 0);
    assert(0 < mapped_value);
    assert(mapped_value < crate::secp256k1::scalar::secp256k1_order_v1_spec());
    axiom_scalar_int_encoding_matches_value_v1(mapped_value);
}

pub proof fn mapped_backend_scalar_preserves_additive_share_v1(
    additive_share32: Bytes32,
    participant_id: u32,
)
    requires
        is_supported_2p_participant_id_v1_spec(participant_id),
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(additive_share32),
    ensures
        (
            lambda_for_participant_v1_spec(participant_id)
                * crate::secp256k1::scalar::bytes32_as_int_v1_spec(
                    map_supported_additive_share_to_backend_v1_spec(
                        additive_share32,
                        participant_id,
                    ).mapped_scalar_be_bytes,
                )
        ) % crate::secp256k1::scalar::secp256k1_order_v1_spec()
            == crate::secp256k1::scalar::bytes32_as_int_v1_spec(additive_share32),
{
    mapped_backend_scalar_is_valid_v1(additive_share32, participant_id);
    if participant_id == client_participant_id_v1_spec() {
        mapped_client_scalar_preserves_share_int_v1(additive_share32);
    } else {
        mapped_relayer_scalar_preserves_share_int_v1(additive_share32);
    }
    axiom_scalar_int_encoding_matches_value_v1(
        mapped_backend_scalar_int_v1_spec(additive_share32, participant_id),
    );
    assert(
        crate::secp256k1::scalar::bytes32_as_int_v1_spec(
            map_supported_additive_share_to_backend_v1_spec(
                additive_share32,
                participant_id,
            ).mapped_scalar_be_bytes,
        ) == mapped_backend_scalar_int_v1_spec(additive_share32, participant_id)
    );
}

}
