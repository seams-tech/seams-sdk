use k256::elliptic_curve::ops::Invert;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey};
use sha3::{Digest, Keccak256};

use crate::error::{EcdsaHssError, EcdsaHssResult};

pub const THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID: u32 = 1;
pub const THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID: u32 = 2;

pub fn map_additive_share_to_threshold_signatures_share_2p(
    additive_share32: &[u8],
    participant_id: u32,
) -> EcdsaHssResult<Vec<u8>> {
    let additive = parse_nonzero_scalar_32(additive_share32, "additive_share32")?;
    let lambda = match participant_id {
        THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID => nonzero_scalar_from_u32(3)?,
        THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID => {
            nonzero_scalar_from_scalar(-Scalar::from(2u32), "relayer mapping coefficient")?
        }
        _ => {
            return Err(EcdsaHssError::invalid_input(format!(
                "unsupported participant_id for 2P mapping: {}",
                participant_id
            )))
        }
    };
    let mapped = additive * lambda.invert();
    Ok(field_bytes_to_array32(&FieldBytes::from(mapped)).to_vec())
}

pub fn validate_secp256k1_public_key_33(public_key33: &[u8]) -> EcdsaHssResult<Vec<u8>> {
    if public_key33.len() != 33 {
        return Err(EcdsaHssError::invalid_length(format!(
            "public_key33 must be 33 bytes (got {})",
            public_key33.len()
        )));
    }
    let key = PublicKey::from_sec1_bytes(public_key33)
        .map_err(|_| EcdsaHssError::decode_error("invalid compressed secp256k1 public key"))?;
    let encoded = key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes != public_key33 {
        return Err(EcdsaHssError::decode_error(
            "compressed secp256k1 public key must use canonical SEC1 encoding",
        ));
    }
    Ok(bytes.to_vec())
}

pub fn secp256k1_private_key_32_to_public_key_33(private_key32: &[u8]) -> EcdsaHssResult<Vec<u8>> {
    if private_key32.len() != 32 {
        return Err(EcdsaHssError::invalid_length(format!(
            "private_key32 must be 32 bytes (got {})",
            private_key32.len()
        )));
    }
    let secret_key = SecretKey::from_slice(private_key32)
        .map_err(|_| EcdsaHssError::crypto_error("invalid secp256k1 private key"))?;
    Ok(secret_key
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec())
}

pub fn add_secp256k1_public_keys_33(left33: &[u8], right33: &[u8]) -> EcdsaHssResult<Vec<u8>> {
    let left = PublicKey::from_sec1_bytes(left33).map_err(|_| {
        EcdsaHssError::decode_error("left33 is not a valid compressed secp256k1 public key")
    })?;
    let right = PublicKey::from_sec1_bytes(right33).map_err(|_| {
        EcdsaHssError::decode_error("right33 is not a valid compressed secp256k1 public key")
    })?;

    let sum = (ProjectivePoint::from(*left.as_affine())
        + ProjectivePoint::from(*right.as_affine()))
    .to_affine();
    Ok(sum.to_encoded_point(true).as_bytes().to_vec())
}

pub fn secp256k1_public_key_33_to_ethereum_address_20(
    public_key33: &[u8],
) -> EcdsaHssResult<Vec<u8>> {
    let public_key = PublicKey::from_sec1_bytes(public_key33)
        .map_err(|_| EcdsaHssError::decode_error("invalid compressed secp256k1 public key"))?;
    let encoded = public_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(EcdsaHssError::invalid_length(
            "uncompressed secp256k1 public key must be 65 bytes with 0x04 prefix",
        ));
    }
    let mut hasher = Keccak256::new();
    hasher.update(&bytes[1..]);
    let digest = hasher.finalize();
    Ok(digest[digest.len() - 20..].to_vec())
}

fn parse_nonzero_scalar_32(bytes: &[u8], field_name: &str) -> EcdsaHssResult<NonZeroScalar> {
    if bytes.len() != 32 {
        return Err(EcdsaHssError::invalid_length(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    SecretKey::from_slice(bytes)
        .map(|secret_key| secret_key.to_nonzero_scalar())
        .map_err(|_| EcdsaHssError::invalid_input(format!("{field_name} must be in (0, n)")))
}

fn nonzero_scalar_from_u32(value: u32) -> EcdsaHssResult<NonZeroScalar> {
    nonzero_scalar_from_scalar(Scalar::from(value), "mapping coefficient")
}

fn nonzero_scalar_from_scalar(scalar: Scalar, field_name: &str) -> EcdsaHssResult<NonZeroScalar> {
    Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar)).ok_or_else(|| {
        EcdsaHssError::internal(format!("{field_name} unexpectedly reduced to zero"))
    })
}

fn field_bytes_to_array32(bytes: &FieldBytes) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    out
}
