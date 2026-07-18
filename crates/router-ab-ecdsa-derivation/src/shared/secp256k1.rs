use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, SecretKey};
use sha3::{Digest, Keccak256};

use crate::error::{RouterAbEcdsaDerivationError, RouterAbEcdsaDerivationResult};

pub fn validate_secp256k1_public_key_33(
    public_key33: &[u8],
) -> RouterAbEcdsaDerivationResult<Vec<u8>> {
    if public_key33.len() != 33 {
        return Err(RouterAbEcdsaDerivationError::invalid_length(format!(
            "public_key33 must be 33 bytes (got {})",
            public_key33.len()
        )));
    }
    let key = PublicKey::from_sec1_bytes(public_key33).map_err(|_| {
        RouterAbEcdsaDerivationError::decode_error("invalid compressed secp256k1 public key")
    })?;
    let encoded = key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes != public_key33 {
        return Err(RouterAbEcdsaDerivationError::decode_error(
            "compressed secp256k1 public key must use canonical SEC1 encoding",
        ));
    }
    Ok(bytes.to_vec())
}

pub fn secp256k1_private_key_32_to_public_key_33(
    private_key32: &[u8],
) -> RouterAbEcdsaDerivationResult<Vec<u8>> {
    if private_key32.len() != 32 {
        return Err(RouterAbEcdsaDerivationError::invalid_length(format!(
            "private_key32 must be 32 bytes (got {})",
            private_key32.len()
        )));
    }
    let secret_key = SecretKey::from_slice(private_key32)
        .map_err(|_| RouterAbEcdsaDerivationError::crypto_error("invalid secp256k1 private key"))?;
    Ok(secret_key
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec())
}

pub fn add_secp256k1_public_keys_33(
    left33: &[u8],
    right33: &[u8],
) -> RouterAbEcdsaDerivationResult<Vec<u8>> {
    let left = PublicKey::from_sec1_bytes(left33).map_err(|_| {
        RouterAbEcdsaDerivationError::decode_error(
            "left33 is not a valid compressed secp256k1 public key",
        )
    })?;
    let right = PublicKey::from_sec1_bytes(right33).map_err(|_| {
        RouterAbEcdsaDerivationError::decode_error(
            "right33 is not a valid compressed secp256k1 public key",
        )
    })?;

    let sum = (ProjectivePoint::from(*left.as_affine())
        + ProjectivePoint::from(*right.as_affine()))
    .to_affine();
    Ok(sum.to_encoded_point(true).as_bytes().to_vec())
}

pub fn secp256k1_public_key_33_to_ethereum_address_20(
    public_key33: &[u8],
) -> RouterAbEcdsaDerivationResult<Vec<u8>> {
    let public_key = PublicKey::from_sec1_bytes(public_key33).map_err(|_| {
        RouterAbEcdsaDerivationError::decode_error("invalid compressed secp256k1 public key")
    })?;
    let encoded = public_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(RouterAbEcdsaDerivationError::invalid_length(
            "uncompressed secp256k1 public key must be 65 bytes with 0x04 prefix",
        ));
    }
    let mut hasher = Keccak256::new();
    hasher.update(&bytes[1..]);
    let digest = hasher.finalize();
    Ok(digest[digest.len() - 20..].to_vec())
}
