//! Verus model for threshold Ed25519 client-share derivation.

use vstd::prelude::*;

verus! {

pub type Bytes32 = [u8; 32];
pub type Bytes64 = [u8; 64];

#[derive(Debug, PartialEq, Eq)]
pub struct ClientThresholdShareOutputV1 {
    pub signing_share32: Bytes32,
    pub verifying_share32: Bytes32,
}

pub open spec fn ed25519_scalar_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn ed25519_compressed_public_key_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn threshold_client_share_derivation_path_v1_spec() -> u32 {
    0u32
}

pub uninterp spec fn threshold_client_share_hkdf_info_v1_spec(
    near_account_id: Seq<u8>,
    derivation_path: u32,
) -> Seq<u8>;

pub uninterp spec fn threshold_client_share_hkdf_output_v1_spec(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
) -> Bytes64;

pub uninterp spec fn reduce_ed25519_wide_to_nonzero_scalar_v1_spec(okm64: Bytes64) -> Bytes32;

pub uninterp spec fn is_nonzero_ed25519_scalar_v1_spec(signing_share32: Bytes32) -> bool;

pub uninterp spec fn verifying_share_from_signing_share_v1_spec(
    signing_share32: Bytes32,
) -> Bytes32;

pub broadcast axiom fn axiom_reduced_ed25519_wide_output_is_nonzero_v1(okm64: Bytes64)
    ensures
        #![trigger reduce_ed25519_wide_to_nonzero_scalar_v1_spec(okm64)]
        is_nonzero_ed25519_scalar_v1_spec(reduce_ed25519_wide_to_nonzero_scalar_v1_spec(okm64)),
;

pub open spec fn derive_threshold_client_signing_share_v1_spec(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
) -> Bytes32 {
    reduce_ed25519_wide_to_nonzero_scalar_v1_spec(
        threshold_client_share_hkdf_output_v1_spec(wrap_key_seed32, near_account_id),
    )
}

pub open spec fn derive_threshold_client_verifying_share_v1_spec(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
) -> Bytes32 {
    verifying_share_from_signing_share_v1_spec(
        derive_threshold_client_signing_share_v1_spec(wrap_key_seed32, near_account_id),
    )
}

pub open spec fn derive_threshold_client_share_output_v1_spec(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
) -> ClientThresholdShareOutputV1 {
    let signing_share32 = derive_threshold_client_signing_share_v1_spec(
        wrap_key_seed32,
        near_account_id,
    );
    ClientThresholdShareOutputV1 {
        signing_share32,
        verifying_share32: verifying_share_from_signing_share_v1_spec(signing_share32),
    }
}

pub proof fn threshold_client_hkdf_info_uses_fixed_derivation_path_v1(
    near_account_id: Seq<u8>,
)
    ensures
        threshold_client_share_hkdf_info_v1_spec(
            near_account_id,
            threshold_client_share_derivation_path_v1_spec(),
        ) == threshold_client_share_hkdf_info_v1_spec(near_account_id, 0u32),
{
}

pub proof fn threshold_client_signing_share_derivation_is_deterministic_v1(
    left_wrap_key_seed32: Bytes32,
    left_near_account_id: Seq<u8>,
    right_wrap_key_seed32: Bytes32,
    right_near_account_id: Seq<u8>,
)
    requires
        left_wrap_key_seed32 == right_wrap_key_seed32,
        left_near_account_id == right_near_account_id,
    ensures
        derive_threshold_client_signing_share_v1_spec(
            left_wrap_key_seed32,
            left_near_account_id,
        ) == derive_threshold_client_signing_share_v1_spec(
            right_wrap_key_seed32,
            right_near_account_id,
        ),
{
}

pub proof fn threshold_client_signing_share_is_nonzero_v1(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
)
    ensures
        is_nonzero_ed25519_scalar_v1_spec(
            derive_threshold_client_signing_share_v1_spec(wrap_key_seed32, near_account_id),
        ),
{
    broadcast use axiom_reduced_ed25519_wide_output_is_nonzero_v1;
}

pub proof fn threshold_client_verifying_share_matches_signing_share_v1(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
)
    ensures
        derive_threshold_client_verifying_share_v1_spec(wrap_key_seed32, near_account_id)
            == verifying_share_from_signing_share_v1_spec(
                derive_threshold_client_signing_share_v1_spec(wrap_key_seed32, near_account_id),
            ),
        derive_threshold_client_share_output_v1_spec(
            wrap_key_seed32,
            near_account_id,
        ).verifying_share32 == verifying_share_from_signing_share_v1_spec(
            derive_threshold_client_share_output_v1_spec(
                wrap_key_seed32,
                near_account_id,
            ).signing_share32,
        ),
{
}

pub proof fn threshold_client_share_output_layout_is_fixed_v1(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
)
    ensures
        derive_threshold_client_share_output_v1_spec(
            wrap_key_seed32,
            near_account_id,
        ).signing_share32@.len() == ed25519_scalar_width_bytes_v1_spec(),
        derive_threshold_client_share_output_v1_spec(
            wrap_key_seed32,
            near_account_id,
        ).verifying_share32@.len() == ed25519_compressed_public_key_width_bytes_v1_spec(),
{
}

}
