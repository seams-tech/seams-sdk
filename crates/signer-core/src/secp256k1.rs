use hkdf::Hkdf;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, SecretKey, WideBytes};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::error::{CoreResult, SignerCoreError};

const EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1: &[u8] = b"secp256k1-signing-key-dual-prf-v1";
const EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1: &str = "evm-key-derivation:";

fn reduce_hkdf_output_to_nonzero_secp256k1_scalar(okm64: &[u8]) -> CoreResult<[u8; 32]> {
    if okm64.len() != 64 {
        return Err(SignerCoreError::invalid_length(format!(
            "HKDF output must be 64 bytes before secp256k1 reduction (got {})",
            okm64.len()
        )));
    }

    let mut wide = WideBytes::default();
    wide.copy_from_slice(okm64);
    Ok(field_bytes_to_array32(&FieldBytes::from(
        <NonZeroScalar as Reduce<U512>>::reduce_bytes(&wide),
    )))
}

pub fn derive_secp256k1_keypair_from_prf_second(
    prf_second: &[u8],
    near_account_id: &str,
) -> CoreResult<Vec<u8>> {
    if prf_second.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "prf_second must be non-empty",
        ));
    }

    let near_account_id = near_account_id.trim();
    if near_account_id.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "near_account_id must be non-empty",
        ));
    }

    let mut hkdf_salt =
        Vec::with_capacity(EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.len() + near_account_id.len());
    hkdf_salt.extend_from_slice(EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.as_bytes());
    hkdf_salt.extend_from_slice(near_account_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), prf_second);
    let mut okm64 = Zeroizing::new([0u8; 64]);
    hk.expand(EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1, &mut *okm64)
        .map_err(|_| {
            SignerCoreError::hkdf_error(
                "HKDF expand failed for secp256k1 PRF.second key derivation",
            )
        })?;

    let private_key32 = reduce_hkdf_output_to_nonzero_secp256k1_scalar(&okm64[..])?;
    let secret_key = SecretKey::from_slice(&private_key32)
        .map_err(|_| SignerCoreError::crypto_error("derived secp256k1 private key is invalid"))?;

    let public_key_compressed = secret_key.public_key().to_encoded_point(true);
    let public_key_compressed = public_key_compressed.as_bytes();
    if public_key_compressed.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "derived compressed secp256k1 public key must be 33 bytes (got {})",
            public_key_compressed.len()
        )));
    }

    let public_key_uncompressed = secret_key.public_key().to_encoded_point(false);
    let public_key_uncompressed = public_key_uncompressed.as_bytes();
    if public_key_uncompressed.len() != 65 || public_key_uncompressed[0] != 0x04 {
        return Err(SignerCoreError::invalid_length(format!(
            "derived uncompressed secp256k1 public key must be 65 bytes with 0x04 prefix (got {})",
            public_key_uncompressed.len()
        )));
    }

    let mut hasher = Keccak256::new();
    hasher.update(&public_key_uncompressed[1..]);
    let digest = hasher.finalize();
    let address20 = &digest[digest.len() - 20..];

    let mut out = Vec::with_capacity(85);
    out.extend_from_slice(&private_key32);
    out.extend_from_slice(public_key_compressed);
    out.extend_from_slice(address20);
    Ok(out)
}

fn field_bytes_to_array32(bytes: &FieldBytes) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    out
}

pub fn validate_secp256k1_public_key_33(public_key33: &[u8]) -> CoreResult<Vec<u8>> {
    if public_key33.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "public_key33 must be 33 bytes (got {})",
            public_key33.len()
        )));
    }
    let key = PublicKey::from_sec1_bytes(public_key33)
        .map_err(|_| SignerCoreError::decode_error("invalid compressed secp256k1 public key"))?;
    let encoded = key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "compressed secp256k1 public key must encode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    if bytes != public_key33 {
        return Err(SignerCoreError::decode_error(
            "compressed secp256k1 public key must use canonical SEC1 encoding",
        ));
    }
    Ok(bytes.to_vec())
}

pub fn add_secp256k1_public_keys_33(left33: &[u8], right33: &[u8]) -> CoreResult<Vec<u8>> {
    let left = PublicKey::from_sec1_bytes(left33).map_err(|_| {
        SignerCoreError::decode_error("left33 is not a valid compressed secp256k1 public key")
    })?;
    let right = PublicKey::from_sec1_bytes(right33).map_err(|_| {
        SignerCoreError::decode_error("right33 is not a valid compressed secp256k1 public key")
    })?;

    let sum = (ProjectivePoint::from(*left.as_affine())
        + ProjectivePoint::from(*right.as_affine()))
    .to_affine();
    let encoded = sum.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "sum of secp256k1 public keys must encode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

pub fn secp256k1_private_key_32_to_public_key_33(private_key32: &[u8]) -> CoreResult<Vec<u8>> {
    if private_key32.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "private_key32 must be 32 bytes (got {})",
            private_key32.len()
        )));
    }
    let secret_key = SecretKey::from_slice(private_key32)
        .map_err(|_| SignerCoreError::crypto_error("invalid secp256k1 private key"))?;
    let encoded = secret_key.public_key().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "compressed secp256k1 public key must encode to 33 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

pub fn secp256k1_public_key_33_to_ethereum_address_20(public_key33: &[u8]) -> CoreResult<Vec<u8>> {
    if public_key33.len() != 33 {
        return Err(SignerCoreError::invalid_length(format!(
            "public_key33 must be 33 bytes (got {})",
            public_key33.len()
        )));
    }
    let key = PublicKey::from_sec1_bytes(public_key33)
        .map_err(|_| SignerCoreError::decode_error("invalid compressed secp256k1 public key"))?;
    let uncompressed = key.to_encoded_point(false);
    let uncompressed = uncompressed.as_bytes();
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return Err(SignerCoreError::invalid_length(format!(
            "uncompressed secp256k1 public key must be 65 bytes with 0x04 prefix (got {})",
            uncompressed.len()
        )));
    }

    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..]);
    let digest = hasher.finalize();
    Ok(digest[digest.len() - 20..].to_vec())
}

pub fn sign_secp256k1_recoverable(digest32: &[u8], private_key32: &[u8]) -> CoreResult<Vec<u8>> {
    if digest32.len() != 32 {
        return Err(SignerCoreError::invalid_length("digest32 must be 32 bytes"));
    }
    if private_key32.len() != 32 {
        return Err(SignerCoreError::invalid_length(
            "privateKey must be 32 bytes",
        ));
    }

    let sk = SecretKey::from_slice(private_key32)
        .map_err(|_| SignerCoreError::crypto_error("invalid secp256k1 private key"))?;
    let signing_key: SigningKey = sk.into();
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest32)
        .map_err(|_| SignerCoreError::crypto_error("secp256k1 signing failed"))?;

    // Ethereum requires low-s normalized signatures (EIP-2).
    // When normalizing s -> n-s, the recovery id flips parity.
    let (sig, recid) = match sig.normalize_s() {
        Some(normalized) => {
            let flipped = RecoveryId::from_byte(recid.to_byte() ^ 1)
                .ok_or_else(|| SignerCoreError::internal("invalid recovery id"))?;
            (normalized, flipped)
        }
        None => (sig, recid),
    };

    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);
    out.push(recid.to_byte());
    Ok(out)
}

pub fn verify_secp256k1_recoverable_signature_against_public_key_33(
    digest32: &[u8],
    signature65: &[u8],
    public_key33: &[u8],
) -> CoreResult<Vec<u8>> {
    if digest32.len() != 32 {
        return Err(SignerCoreError::invalid_length("digest32 must be 32 bytes"));
    }
    if signature65.len() != 65 {
        return Err(SignerCoreError::invalid_length(
            "signature65 must be 65 bytes",
        ));
    }

    let expected_vk = VerifyingKey::from_sec1_bytes(public_key33)
        .map_err(|_| SignerCoreError::decode_error("invalid compressed secp256k1 public key"))?;
    let signature = Signature::from_slice(&signature65[0..64])
        .map_err(|_| SignerCoreError::decode_error("invalid secp256k1 signature scalars"))?;
    let recid = RecoveryId::from_byte(signature65[64])
        .ok_or_else(|| SignerCoreError::decode_error("invalid secp256k1 recovery id"))?;
    let recovered = VerifyingKey::recover_from_prehash(digest32, &signature, recid)
        .map_err(|_| SignerCoreError::crypto_error("secp256k1 signature recovery failed"))?;

    let recovered_bytes = recovered.to_encoded_point(true);
    let expected_bytes = expected_vk.to_encoded_point(true);
    if recovered_bytes.as_bytes() != expected_bytes.as_bytes() {
        return Err(SignerCoreError::crypto_error(
            "recovered secp256k1 public key did not match expected key",
        ));
    }
    Ok(recovered_bytes.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{Signature, VerifyingKey};

    #[test]
    fn add_secp256k1_public_keys_matches_scalar_sum() {
        let mut sk1_bytes = [0u8; 32];
        sk1_bytes[31] = 1;
        let mut sk2_bytes = [0u8; 32];
        sk2_bytes[31] = 2;
        let mut sk3_bytes = [0u8; 32];
        sk3_bytes[31] = 3;

        let sk1 = SecretKey::from_slice(&sk1_bytes).expect("sk1");
        let sk2 = SecretKey::from_slice(&sk2_bytes).expect("sk2");
        let sk3 = SecretKey::from_slice(&sk3_bytes).expect("sk3");

        let pk1 = sk1.public_key().to_encoded_point(true).as_bytes().to_vec();
        let pk2 = sk2.public_key().to_encoded_point(true).as_bytes().to_vec();
        let expected = sk3.public_key().to_encoded_point(true).as_bytes().to_vec();

        let summed = add_secp256k1_public_keys_33(&pk1, &pk2).expect("sum");
        assert_eq!(summed, expected);

        let validated = validate_secp256k1_public_key_33(&pk1).expect("validate");
        assert_eq!(validated.len(), 33);
    }

    #[test]
    fn private_key_32_to_public_key_33_matches_secret_key_derivation() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;

        let expected = SecretKey::from_slice(&sk_bytes)
            .expect("secret key")
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let derived =
            secp256k1_private_key_32_to_public_key_33(&sk_bytes).expect("derive public key");
        assert_eq!(derived, expected);
    }

    #[test]
    fn sign_secp256k1_recoverable_produces_low_s_and_valid_recovery_id() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;
        let mut digest = [0u8; 32];
        digest[31] = 9;

        let out = sign_secp256k1_recoverable(digest.as_slice(), sk_bytes.as_slice()).expect("sign");
        assert_eq!(out.len(), 65);

        let sig = Signature::from_slice(&out[..64])
            .expect("signature bytes must decode into secp256k1 sig");
        let recid = RecoveryId::from_byte(out[64]).expect("recovery id");
        assert!(
            sig.normalize_s().is_none(),
            "signature should already be low-s normalized",
        );

        let recovered =
            VerifyingKey::recover_from_prehash(&digest, &sig, recid).expect("recover key from sig");
        let expected = SecretKey::from_slice(&sk_bytes)
            .expect("sk")
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        assert_eq!(
            recovered.to_encoded_point(true).as_bytes().to_vec(),
            expected,
            "recovered key must match signer key",
        );
    }

    #[test]
    fn verify_recoverable_signature_against_public_key_33_roundtrips() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 7;
        let mut digest = [0u8; 32];
        digest[0] = 1;
        digest[31] = 9;

        let signature65 =
            sign_secp256k1_recoverable(digest.as_slice(), sk_bytes.as_slice()).expect("sign");
        let public_key33 =
            secp256k1_private_key_32_to_public_key_33(&sk_bytes).expect("derive public key");

        let verified = verify_secp256k1_recoverable_signature_against_public_key_33(
            digest.as_slice(),
            signature65.as_slice(),
            public_key33.as_slice(),
        )
        .expect("verify");
        assert_eq!(verified, public_key33);
    }

    #[test]
    fn public_key_33_to_ethereum_address_matches_prf_second_derivation() {
        let prf_second = vec![0x22; 32];
        let near_account_id = "alice.testnet";

        let out = derive_secp256k1_keypair_from_prf_second(prf_second.as_slice(), near_account_id)
            .expect("derive keypair");
        assert_eq!(out.len(), 85);
        let public_key33 = &out[32..65];
        let expected_address = &out[65..85];

        let address = secp256k1_public_key_33_to_ethereum_address_20(public_key33)
            .expect("address derivation");
        assert_eq!(address.len(), 20);
        assert_eq!(address.as_slice(), expected_address);
    }
}
