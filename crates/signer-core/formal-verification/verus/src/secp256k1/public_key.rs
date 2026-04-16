//! Verus model for `signer_core::secp256k1` public-key helper output shapes.

use vstd::prelude::*;

#[allow(unused_imports)]
use super::scalar::{Bytes20, Bytes32, Bytes33};

verus! {

pub uninterp spec fn is_valid_compressed_public_key_v1_spec(public_key33: Bytes33) -> bool;

pub uninterp spec fn compressed_public_key_sum_v1_spec(
    left33: Bytes33,
    right33: Bytes33,
) -> Bytes33;

pub broadcast axiom fn axiom_public_key_from_valid_scalar_is_valid_v1(scalar32: Bytes32)
    requires
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(scalar32),
    ensures
        #![trigger crate::secp256k1::scalar::compressed_public_key_from_scalar_v1_spec(scalar32)]
        is_valid_compressed_public_key_v1_spec(
            crate::secp256k1::scalar::compressed_public_key_from_scalar_v1_spec(scalar32),
        ),
;

pub broadcast axiom fn axiom_sum_of_valid_public_keys_is_valid_v1(
    left33: Bytes33,
    right33: Bytes33,
)
    requires
        is_valid_compressed_public_key_v1_spec(left33),
        is_valid_compressed_public_key_v1_spec(right33),
    ensures
        #![trigger compressed_public_key_sum_v1_spec(left33, right33)]
        is_valid_compressed_public_key_v1_spec(
            compressed_public_key_sum_v1_spec(left33, right33),
        ),
;

pub open spec fn validate_secp256k1_public_key_33_v1_spec(public_key33: Bytes33) -> Option<Bytes33> {
    if is_valid_compressed_public_key_v1_spec(public_key33) {
        Some(public_key33)
    } else {
        None
    }
}

pub open spec fn secp256k1_private_key_32_to_public_key_33_v1_spec(
    private_key32: Bytes32,
) -> Option<Bytes33> {
    if crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(private_key32) {
        Some(crate::secp256k1::scalar::compressed_public_key_from_scalar_v1_spec(
            private_key32,
        ))
    } else {
        None
    }
}

pub open spec fn secp256k1_public_key_33_to_ethereum_address_20_v1_spec(
    public_key33: Bytes33,
) -> Option<Bytes20> {
    if is_valid_compressed_public_key_v1_spec(public_key33) {
        Some(crate::secp256k1::scalar::ethereum_address_from_public_key_v1_spec(
            public_key33,
        ))
    } else {
        None
    }
}

pub open spec fn add_secp256k1_public_keys_33_v1_spec(
    left33: Bytes33,
    right33: Bytes33,
) -> Option<Bytes33> {
    if is_valid_compressed_public_key_v1_spec(left33)
        && is_valid_compressed_public_key_v1_spec(right33)
    {
        Some(compressed_public_key_sum_v1_spec(left33, right33))
    } else {
        None
    }
}

pub proof fn invalid_public_key_validation_is_rejected_v1(public_key33: Bytes33)
    requires
        !is_valid_compressed_public_key_v1_spec(public_key33),
    ensures
        validate_secp256k1_public_key_33_v1_spec(public_key33).is_none(),
{
}

pub proof fn valid_public_key_validation_preserves_bytes_v1(public_key33: Bytes33)
    requires
        is_valid_compressed_public_key_v1_spec(public_key33),
    ensures
        validate_secp256k1_public_key_33_v1_spec(public_key33) == Some(public_key33),
        public_key33@.len()
            == crate::secp256k1::scalar::secp256k1_compressed_public_key_width_bytes_v1_spec(),
{
}

pub proof fn private_key_to_public_key_output_is_compressed_v1(private_key32: Bytes32)
    requires
        crate::secp256k1::scalar::is_valid_nonzero_scalar_v1_spec(private_key32),
    ensures
        secp256k1_private_key_32_to_public_key_33_v1_spec(private_key32)
            == Some(crate::secp256k1::scalar::compressed_public_key_from_scalar_v1_spec(
                private_key32,
            )),
        crate::secp256k1::scalar::compressed_public_key_from_scalar_v1_spec(private_key32)@.len()
            == crate::secp256k1::scalar::secp256k1_compressed_public_key_width_bytes_v1_spec(),
        is_valid_compressed_public_key_v1_spec(
            crate::secp256k1::scalar::compressed_public_key_from_scalar_v1_spec(private_key32),
        ),
{
    broadcast use axiom_public_key_from_valid_scalar_is_valid_v1;
}

pub proof fn public_key_to_ethereum_address_output_shape_is_fixed_v1(public_key33: Bytes33)
    requires
        is_valid_compressed_public_key_v1_spec(public_key33),
    ensures
        secp256k1_public_key_33_to_ethereum_address_20_v1_spec(public_key33)
            == Some(crate::secp256k1::scalar::ethereum_address_from_public_key_v1_spec(
                public_key33,
            )),
        crate::secp256k1::scalar::ethereum_address_from_public_key_v1_spec(public_key33)@.len()
            == crate::secp256k1::scalar::ethereum_address_width_bytes_v1_spec(),
{
}

pub proof fn public_key_addition_output_is_compressed_v1(left33: Bytes33, right33: Bytes33)
    requires
        is_valid_compressed_public_key_v1_spec(left33),
        is_valid_compressed_public_key_v1_spec(right33),
    ensures
        add_secp256k1_public_keys_33_v1_spec(left33, right33)
            == Some(compressed_public_key_sum_v1_spec(left33, right33)),
        compressed_public_key_sum_v1_spec(left33, right33)@.len()
            == crate::secp256k1::scalar::secp256k1_compressed_public_key_width_bytes_v1_spec(),
        is_valid_compressed_public_key_v1_spec(compressed_public_key_sum_v1_spec(left33, right33)),
{
    broadcast use axiom_sum_of_valid_public_keys_is_valid_v1;
}

}
