use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CoreResult, SignerCoreError};

pub const NEAR_ED25519_SEED_EXPORT_ARTIFACT_KIND_V1: &str = "near-ed25519-seed-v1";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExpandedEd25519SeedMaterial {
    pub seed: [u8; 32],
    pub signing_scalar_bytes: [u8; 32],
    pub nonce_prefix: [u8; 32],
    pub public_key_bytes: [u8; 32],
}

impl core::fmt::Debug for ExpandedEd25519SeedMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ExpandedEd25519SeedMaterial([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearEd25519SeedExportArtifactV1 {
    pub artifact_kind: String,
    pub public_key: String,
    pub private_key: String,
}

fn require_nonempty<'a>(label: &str, value: &'a str) -> CoreResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must be non-empty"
        )));
    }
    Ok(trimmed)
}

pub fn expand_ed25519_seed(seed: [u8; 32]) -> ExpandedEd25519SeedMaterial {
    let hash = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(seed)));
    let mut signing_scalar_bytes = [0u8; 32];
    signing_scalar_bytes.copy_from_slice(&hash[..32]);
    signing_scalar_bytes[0] &= 248;
    signing_scalar_bytes[31] &= 63;
    signing_scalar_bytes[31] |= 64;
    let mut nonce_prefix = [0u8; 32];
    nonce_prefix.copy_from_slice(&hash[32..64]);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    ExpandedEd25519SeedMaterial {
        seed,
        signing_scalar_bytes,
        nonce_prefix,
        public_key_bytes: signing_key.verifying_key().to_bytes(),
    }
}

pub fn encode_near_ed25519_private_key_from_seed(seed: [u8; 32]) -> String {
    let material = expand_ed25519_seed(seed);
    let mut encoded = Zeroizing::new([0u8; 64]);
    encoded[..32].copy_from_slice(&material.seed);
    encoded[32..].copy_from_slice(&material.public_key_bytes);
    format!("ed25519:{}", bs58::encode(encoded.as_slice()).into_string())
}

pub fn encode_near_ed25519_public_key_from_seed(seed: [u8; 32]) -> String {
    let material = expand_ed25519_seed(seed);
    format!(
        "ed25519:{}",
        bs58::encode(material.public_key_bytes).into_string()
    )
}

pub fn verify_near_ed25519_seed_matches_public_key(
    seed: [u8; 32],
    expected_public_key: &str,
) -> CoreResult<String> {
    let expected_public_key = require_nonempty("expectedPublicKey", expected_public_key)?;
    let derived_public_key = encode_near_ed25519_public_key_from_seed(seed);
    if derived_public_key != expected_public_key {
        return Err(SignerCoreError::crypto_error(
            "canonical seed does not match the expected public key",
        ));
    }
    Ok(derived_public_key)
}

pub fn build_near_ed25519_seed_export_artifact_v1(
    seed: [u8; 32],
    expected_public_key: &str,
) -> CoreResult<NearEd25519SeedExportArtifactV1> {
    let public_key = verify_near_ed25519_seed_matches_public_key(seed, expected_public_key)?;
    Ok(NearEd25519SeedExportArtifactV1 {
        artifact_kind: NEAR_ED25519_SEED_EXPORT_ARTIFACT_KIND_V1.to_string(),
        public_key,
        private_key: encode_near_ed25519_private_key_from_seed(seed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SignerCoreErrorCode;

    #[test]
    fn encode_near_private_key_from_seed_round_trips_public_key() {
        let seed = [7u8; 32];
        let encoded = encode_near_ed25519_private_key_from_seed(seed);
        let decoded = bs58::decode(encoded.trim_start_matches("ed25519:"))
            .into_vec()
            .expect("base58");
        assert_eq!(&decoded[..32], &seed);
        let material = expand_ed25519_seed(seed);
        assert_eq!(&decoded[32..], &material.public_key_bytes);
    }

    #[test]
    fn near_ed25519_seed_export_artifact_requires_matching_public_key() {
        let seed = [51u8; 32];
        let expected_public_key = encode_near_ed25519_public_key_from_seed(seed);
        let artifact = build_near_ed25519_seed_export_artifact_v1(seed, &expected_public_key)
            .expect("seed export artifact");
        assert_eq!(
            artifact.artifact_kind,
            NEAR_ED25519_SEED_EXPORT_ARTIFACT_KIND_V1
        );
        assert_eq!(artifact.public_key, expected_public_key);
        assert_eq!(
            artifact.private_key,
            encode_near_ed25519_private_key_from_seed(seed)
        );
        let serialized = serde_json::to_value(&artifact).expect("serialize export artifact");
        let serialized = serialized.as_object().expect("artifact object");
        assert_eq!(serialized.len(), 3);
        assert!(serialized.contains_key("artifactKind"));
        assert!(serialized.contains_key("publicKey"));
        assert!(serialized.contains_key("privateKey"));
        assert!(!serialized.contains_key("seedB64u"));
        let encoded_private_key = artifact
            .private_key
            .strip_prefix("ed25519:")
            .expect("canonical NEAR private-key prefix");
        let decoded_private_key = bs58::decode(encoded_private_key)
            .into_vec()
            .expect("canonical NEAR private-key encoding");
        assert_eq!(&decoded_private_key[..32], &seed);
    }

    #[test]
    fn near_ed25519_seed_export_artifact_fails_closed_on_public_key_mismatch() {
        let seed = [52u8; 32];
        let error = build_near_ed25519_seed_export_artifact_v1(seed, "ed25519:wrong")
            .expect_err("public key mismatch");
        assert_eq!(error.code, SignerCoreErrorCode::CryptoError);
        assert!(error.message.contains("expected public key"));
    }
}
