use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::subtle::ConstantTimeEq;
use k256::{FieldBytes, NonZeroScalar, SecretKey, WideBytes};
use sha2::{Digest, Sha512};
use signer_core::error::{CoreResult, SignerCoreError};
use signer_core::secp256k1::{
    add_secp256k1_public_keys_33, map_additive_share_to_threshold_signatures_share_2p,
    secp256k1_private_key_32_to_public_key_33, secp256k1_public_key_33_to_ethereum_address_20,
    THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID, THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::shared::context::{encode_context_v1, EcdsaHssStableKeyContextV1};
use crate::wire::RootShareInputsV1;

const CANONICAL_X_DOMAIN_TAG: &[u8] = b"ecdsa-hss:v1:canonical-x";
const ADDITIVE_CLIENT_DOMAIN_TAG: &[u8] = b"ecdsa-hss:v1:additive-share:client";

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CanonicalSecretMaterialV1 {
    pub context_bytes: Vec<u8>,
    pub d32: [u8; 32],
    pub x32: [u8; 32],
    pub public_key33: [u8; 33],
    pub ethereum_address20: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AdditiveShareMaterialV1 {
    pub retry_counter: u32,
    pub x_client32: [u8; 32],
    pub x_relayer32: [u8; 32],
    pub client_public_key33: [u8; 33],
    pub relayer_public_key33: [u8; 33],
    pub mapped_client_share32: [u8; 32],
    pub mapped_relayer_share32: [u8; 32],
    pub threshold_public_key33: [u8; 33],
    pub threshold_ethereum_address20: [u8; 20],
}

pub fn verify_single_key_invariant_v1(
    canonical: &CanonicalSecretMaterialV1,
    additive_shares: &AdditiveShareMaterialV1,
) -> CoreResult<()> {
    if canonical.public_key33 != additive_shares.threshold_public_key33 {
        return Err(SignerCoreError::invalid_input(
            "threshold public key does not match canonical public key",
        ));
    }
    if canonical.ethereum_address20 != additive_shares.threshold_ethereum_address20 {
        return Err(SignerCoreError::invalid_input(
            "threshold ethereum address does not match canonical ethereum address",
        ));
    }
    Ok(())
}

pub fn derive_canonical_secret_v1(
    root_shares: &RootShareInputsV1,
    context: &EcdsaHssStableKeyContextV1,
) -> CoreResult<CanonicalSecretMaterialV1> {
    let y_client32_le = root_shares.y_client32_le;
    let y_relayer32_le = root_shares.y_relayer32_le;
    let context_bytes = encode_context_v1(context)?;

    let d32 = wrapping_add_le_32(&y_client32_le, &y_relayer32_le);

    let mut hasher = Sha512::new();
    hasher.update(CANONICAL_X_DOMAIN_TAG);
    hasher.update(&context_bytes);
    hasher.update(d32);
    let mut h_x: [u8; 64] = hasher.finalize().into();
    let x_scalar = reduce_sha512_digest_to_nonzero_scalar(&h_x);
    h_x.zeroize();
    let x32 = nonzero_scalar_to_32_be(&x_scalar);

    let public_key33 = vec_to_fixed_33(
        secp256k1_private_key_32_to_public_key_33(&x32)?,
        "canonical public key",
    )?;
    let ethereum_address20 = vec_to_fixed_20(
        secp256k1_public_key_33_to_ethereum_address_20(&public_key33)?,
        "canonical ethereum address",
    )?;

    Ok(CanonicalSecretMaterialV1 {
        context_bytes,
        d32,
        x32,
        public_key33,
        ethereum_address20,
    })
}

pub fn derive_additive_shares_v1(
    x32_be: &[u8],
    context: &EcdsaHssStableKeyContextV1,
) -> CoreResult<AdditiveShareMaterialV1> {
    let x_scalar = parse_nonzero_scalar_32_be(x32_be, "x32_be")?;
    let x32_be = nonzero_scalar_to_32_be(&x_scalar);
    let context_bytes = encode_context_v1(context)?;

    let mut retry_counter: u32 = 0;
    loop {
        let mut hasher = Sha512::new();
        hasher.update(ADDITIVE_CLIENT_DOMAIN_TAG);
        hasher.update(&context_bytes);
        hasher.update(retry_counter.to_be_bytes());
        hasher.update(x32_be);
        let mut h_share: [u8; 64] = hasher.finalize().into();
        let x_client = reduce_sha512_digest_to_nonzero_scalar(&h_share);
        h_share.zeroize();
        let x_client32 = nonzero_scalar_to_32_be(&x_client);

        if bool::from(x_client.ct_eq(&x_scalar)) {
            retry_counter = retry_counter.checked_add(1).ok_or_else(|| {
                SignerCoreError::internal("retry counter overflow in additive-share derivation")
            })?;
            continue;
        }

        let x_relayer = Option::<NonZeroScalar>::from(NonZeroScalar::new(
            *x_scalar.as_ref() - *x_client.as_ref(),
        ))
        .ok_or_else(|| {
            SignerCoreError::internal(
                "derived relayer share is zero after additive-share derivation",
            )
        })?;
        let x_relayer32 = nonzero_scalar_to_32_be(&x_relayer);

        let client_public_key33 = vec_to_fixed_33(
            secp256k1_private_key_32_to_public_key_33(&x_client32)?,
            "client additive-share public key",
        )?;
        let relayer_public_key33 = vec_to_fixed_33(
            secp256k1_private_key_32_to_public_key_33(&x_relayer32)?,
            "relayer additive-share public key",
        )?;
        let mapped_client_share32 = vec_to_fixed_32(
            map_additive_share_to_threshold_signatures_share_2p(
                &x_client32,
                THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
            )?,
            "mapped client share",
        )?;
        let mapped_relayer_share32 = vec_to_fixed_32(
            map_additive_share_to_threshold_signatures_share_2p(
                &x_relayer32,
                THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
            )?,
            "mapped relayer share",
        )?;
        let threshold_public_key33 = vec_to_fixed_33(
            add_secp256k1_public_keys_33(&client_public_key33, &relayer_public_key33)?,
            "threshold public key",
        )?;
        let threshold_ethereum_address20 = vec_to_fixed_20(
            secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33)?,
            "threshold ethereum address",
        )?;

        return Ok(AdditiveShareMaterialV1 {
            retry_counter,
            x_client32,
            x_relayer32,
            client_public_key33,
            relayer_public_key33,
            mapped_client_share32,
            mapped_relayer_share32,
            threshold_public_key33,
            threshold_ethereum_address20,
        });
    }
}

fn parse_nonzero_scalar_32_be(bytes: &[u8], field_name: &str) -> CoreResult<NonZeroScalar> {
    if bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    SecretKey::from_slice(bytes)
        .map(|secret_key| secret_key.to_nonzero_scalar())
        .map_err(|_| SignerCoreError::invalid_input(format!("{field_name} must be in (0, n)")))
}

fn reduce_sha512_digest_to_nonzero_scalar(digest64: &[u8; 64]) -> NonZeroScalar {
    let mut wide = WideBytes::default();
    wide.copy_from_slice(digest64);
    <NonZeroScalar as Reduce<U512>>::reduce_bytes(&wide)
}

fn nonzero_scalar_to_32_be(scalar: &NonZeroScalar) -> [u8; 32] {
    field_bytes_to_array32(&FieldBytes::from(scalar))
}

fn field_bytes_to_array32(bytes: &FieldBytes) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    out
}

fn wrapping_add_le_32(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for idx in 0..32 {
        let sum = left[idx] as u16 + right[idx] as u16 + carry;
        out[idx] = sum as u8;
        carry = sum >> 8;
    }
    out
}

fn vec_to_fixed_20(bytes: Vec<u8>, field_name: &str) -> CoreResult<[u8; 20]> {
    if bytes.len() != 20 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 20 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must be exactly 20 bytes"))
    })
}

fn vec_to_fixed_32(bytes: Vec<u8>, field_name: &str) -> CoreResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must be exactly 32 bytes"))
    })
}

fn vec_to_fixed_33(bytes: Vec<u8>, field_name: &str) -> CoreResult<[u8; 33]> {
    if bytes.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 33 bytes (got {})",
            bytes.len()
        )));
    }
    bytes.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must be exactly 33 bytes"))
    })
}
