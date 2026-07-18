//! Verus model for `signer_core::secp256k1` scalar derivation helpers.

use vstd::prelude::*;

verus! {

pub type Bytes20 = [u8; 20];
pub type Bytes32 = [u8; 32];
pub type Bytes33 = [u8; 33];
pub type Bytes64 = [u8; 64];

#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalKeypairOutputV1 {
    pub private_key32: Bytes32,
    pub public_key33: Bytes33,
    pub ethereum_address20: Bytes20,
}

pub open spec fn secp256k1_order_v1_spec() -> int {
    115792089237316195423570985008687907852837564279074904382605163141518161494337int
}

pub open spec fn secp256k1_scalar_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn secp256k1_compressed_public_key_width_bytes_v1_spec() -> nat {
    33nat
}

pub open spec fn ethereum_address_width_bytes_v1_spec() -> nat {
    20nat
}

pub uninterp spec fn bytes32_as_int_v1_spec(bytes: Bytes32) -> int;

pub open spec fn is_valid_nonzero_scalar_v1_spec(bytes: Bytes32) -> bool {
    0 < bytes32_as_int_v1_spec(bytes) < secp256k1_order_v1_spec()
}

pub uninterp spec fn reduce_hkdf_output_to_nonzero_scalar_v1_spec(okm64: Bytes64) -> Bytes32;

pub uninterp spec fn compressed_public_key_from_scalar_v1_spec(scalar32: Bytes32) -> Bytes33;

pub uninterp spec fn ethereum_address_from_public_key_v1_spec(public_key33: Bytes33) -> Bytes20;

pub uninterp spec fn prf_second_hkdf_output_v1_spec(
    prf_second: Seq<u8>,
    near_account_id: Seq<u8>,
) -> Bytes64;

pub broadcast axiom fn axiom_reduced_hkdf_output_is_valid_nonzero_scalar_v1(okm64: Bytes64)
    ensures
        #![trigger reduce_hkdf_output_to_nonzero_scalar_v1_spec(okm64)]
        is_valid_nonzero_scalar_v1_spec(reduce_hkdf_output_to_nonzero_scalar_v1_spec(okm64)),
;

pub open spec fn derive_secp256k1_keypair_from_prf_second_v1_spec(
    prf_second: Seq<u8>,
    near_account_id: Seq<u8>,
) -> CanonicalKeypairOutputV1 {
    let private_key32 = reduce_hkdf_output_to_nonzero_scalar_v1_spec(
        prf_second_hkdf_output_v1_spec(prf_second, near_account_id),
    );
    let public_key33 = compressed_public_key_from_scalar_v1_spec(private_key32);
    CanonicalKeypairOutputV1 {
        private_key32,
        public_key33,
        ethereum_address20: ethereum_address_from_public_key_v1_spec(public_key33),
    }
}

pub proof fn hkdf_output_reduction_is_deterministic_v1(left: Bytes64, right: Bytes64)
    requires
        left == right,
    ensures
        reduce_hkdf_output_to_nonzero_scalar_v1_spec(left)
            == reduce_hkdf_output_to_nonzero_scalar_v1_spec(right),
{
}

pub proof fn hkdf_output_reduction_is_valid_nonzero_scalar_v1(okm64: Bytes64)
    ensures
        is_valid_nonzero_scalar_v1_spec(reduce_hkdf_output_to_nonzero_scalar_v1_spec(okm64)),
{
    broadcast use axiom_reduced_hkdf_output_is_valid_nonzero_scalar_v1;
}

pub proof fn canonical_keypair_derivation_is_deterministic_v1(
    left_prf_second: Seq<u8>,
    left_near_account_id: Seq<u8>,
    right_prf_second: Seq<u8>,
    right_near_account_id: Seq<u8>,
)
    requires
        left_prf_second == right_prf_second,
        left_near_account_id == right_near_account_id,
    ensures
        derive_secp256k1_keypair_from_prf_second_v1_spec(
            left_prf_second,
            left_near_account_id,
        ) == derive_secp256k1_keypair_from_prf_second_v1_spec(
            right_prf_second,
            right_near_account_id,
        ),
{
}

pub proof fn canonical_private_key_is_valid_nonzero_scalar_v1(
    prf_second: Seq<u8>,
    near_account_id: Seq<u8>,
)
    ensures
        is_valid_nonzero_scalar_v1_spec(
            derive_secp256k1_keypair_from_prf_second_v1_spec(
                prf_second,
                near_account_id,
            ).private_key32,
        ),
{
    broadcast use axiom_reduced_hkdf_output_is_valid_nonzero_scalar_v1;
}

pub proof fn canonical_keypair_output_layout_is_fixed_v1(
    prf_second: Seq<u8>,
    near_account_id: Seq<u8>,
)
    ensures
        derive_secp256k1_keypair_from_prf_second_v1_spec(
            prf_second,
            near_account_id,
        ).private_key32@.len() == secp256k1_scalar_width_bytes_v1_spec(),
        derive_secp256k1_keypair_from_prf_second_v1_spec(
            prf_second,
            near_account_id,
        ).public_key33@.len() == secp256k1_compressed_public_key_width_bytes_v1_spec(),
        derive_secp256k1_keypair_from_prf_second_v1_spec(
            prf_second,
            near_account_id,
        ).ethereum_address20@.len() == ethereum_address_width_bytes_v1_spec(),
{
}

}
