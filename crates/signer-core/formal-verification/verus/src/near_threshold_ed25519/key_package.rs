//! Verus model for threshold Ed25519 key-package construction shape.

use vstd::prelude::*;

use super::derivation::Bytes32;

verus! {

#[derive(Debug, PartialEq, Eq)]
pub struct KeyPackageShapeV1 {
    pub identifier: u16,
    pub signing_share32: Bytes32,
    pub verifying_share32: Bytes32,
    pub group_public_key32: Bytes32,
    pub min_signers: u16,
}

pub open spec fn threshold_ed25519_2p_min_signers_v1_spec() -> u16 {
    2u16
}

pub open spec fn key_package_from_signing_share_bytes_v1_spec(
    signing_share32: Bytes32,
    group_public_key32: Bytes32,
    identifier: u16,
) -> KeyPackageShapeV1 {
    KeyPackageShapeV1 {
        identifier,
        signing_share32,
        verifying_share32: crate::near_threshold_ed25519::derivation::verifying_share_from_signing_share_v1_spec(
            signing_share32,
        ),
        group_public_key32,
        min_signers: threshold_ed25519_2p_min_signers_v1_spec(),
    }
}

pub open spec fn derive_client_key_package_from_wrap_key_seed_v1_spec(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
    group_public_key32: Bytes32,
    identifier: u16,
) -> KeyPackageShapeV1 {
    key_package_from_signing_share_bytes_v1_spec(
        crate::near_threshold_ed25519::derivation::derive_threshold_client_signing_share_v1_spec(
            wrap_key_seed32,
            near_account_id,
        ),
        group_public_key32,
        identifier,
    )
}

pub proof fn key_package_preserves_identifier_and_group_key_v1(
    signing_share32: Bytes32,
    group_public_key32: Bytes32,
    identifier: u16,
)
    ensures
        key_package_from_signing_share_bytes_v1_spec(
            signing_share32,
            group_public_key32,
            identifier,
        ).identifier == identifier,
        key_package_from_signing_share_bytes_v1_spec(
            signing_share32,
            group_public_key32,
            identifier,
        ).group_public_key32 == group_public_key32,
{
}

pub proof fn key_package_preserves_signing_share_v1(
    signing_share32: Bytes32,
    group_public_key32: Bytes32,
    identifier: u16,
)
    ensures
        key_package_from_signing_share_bytes_v1_spec(
            signing_share32,
            group_public_key32,
            identifier,
        ).signing_share32 == signing_share32,
{
}

pub proof fn key_package_verifying_share_matches_signing_share_v1(
    signing_share32: Bytes32,
    group_public_key32: Bytes32,
    identifier: u16,
)
    ensures
        key_package_from_signing_share_bytes_v1_spec(
            signing_share32,
            group_public_key32,
            identifier,
        ).verifying_share32 == crate::near_threshold_ed25519::derivation::verifying_share_from_signing_share_v1_spec(
            signing_share32,
        ),
{
}

pub proof fn key_package_uses_fixed_2p_min_signers_v1(
    signing_share32: Bytes32,
    group_public_key32: Bytes32,
    identifier: u16,
)
    ensures
        key_package_from_signing_share_bytes_v1_spec(
            signing_share32,
            group_public_key32,
            identifier,
        ).min_signers == 2u16,
{
}

pub proof fn derived_key_package_preserves_derived_signing_and_verifying_shares_v1(
    wrap_key_seed32: Bytes32,
    near_account_id: Seq<u8>,
    group_public_key32: Bytes32,
    identifier: u16,
)
    ensures
        derive_client_key_package_from_wrap_key_seed_v1_spec(
            wrap_key_seed32,
            near_account_id,
            group_public_key32,
            identifier,
        ).signing_share32 == crate::near_threshold_ed25519::derivation::derive_threshold_client_signing_share_v1_spec(
            wrap_key_seed32,
            near_account_id,
        ),
        derive_client_key_package_from_wrap_key_seed_v1_spec(
            wrap_key_seed32,
            near_account_id,
            group_public_key32,
            identifier,
        ).verifying_share32 == crate::near_threshold_ed25519::derivation::derive_threshold_client_verifying_share_v1_spec(
            wrap_key_seed32,
            near_account_id,
        ),
{
}

}
