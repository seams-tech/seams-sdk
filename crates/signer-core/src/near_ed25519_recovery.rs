use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{CoreResult, SignerCoreError};

pub const ED25519_HSS_CLIENT_ROOT_SHARE_SALT_V1: &[u8] = b"ed25519/root-share/client:v1";
pub const ED25519_HSS_CLIENT_TAU_SHARE_SALT_V1: &[u8] = b"ed25519/tau/client:v1";
pub const ED25519_HSS_SERVER_ROOT_SHARE_SALT_V1: &[u8] = b"ed25519/root-share/server:v1";
pub const ED25519_HSS_SERVER_TAU_SHARE_SALT_V1: &[u8] = b"ed25519/tau/server:v1";
pub const ED25519_HSS_CONTEXT_BINDING_DOMAIN_V1: &[u8] =
    b"succinct-garbling-proto/context-binding/v1";
pub const NEAR_ED25519_SEED_EXPORT_ARTIFACT_KIND_V1: &str = "near-ed25519-seed-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedEd25519SeedMaterial {
    pub seed: [u8; 32],
    pub signing_scalar_bytes: [u8; 32],
    pub nonce_prefix: [u8; 32],
    pub public_key_bytes: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed25519HssCanonicalContextV1 {
    pub org_id: String,
    pub account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub participant_ids: Vec<u16>,
    pub derivation_version: u32,
}

impl Ed25519HssCanonicalContextV1 {
    pub fn normalized(&self) -> CoreResult<Self> {
        validate_nonempty_exact("orgId", &self.org_id)?;
        validate_nonempty_exact("accountId", &self.account_id)?;
        validate_nonempty_exact("keyPurpose", &self.key_purpose)?;
        validate_nonempty_exact("keyVersion", &self.key_version)?;

        let mut participant_ids: Vec<u16> = self
            .participant_ids
            .iter()
            .copied()
            .filter(|value| *value > 0)
            .collect();
        participant_ids.sort_unstable();
        participant_ids.dedup();

        if participant_ids.len() < 2 {
            return Err(SignerCoreError::invalid_input(
                "participantIds must contain at least two non-zero identifiers",
            ));
        }

        Ok(Self {
            org_id: self.org_id.clone(),
            account_id: self.account_id.clone(),
            key_purpose: self.key_purpose.clone(),
            key_version: self.key_version.clone(),
            participant_ids,
            derivation_version: self.derivation_version,
        })
    }

    pub fn binding_digest(&self) -> CoreResult<[u8; 32]> {
        let normalized = self.normalized()?;
        let mut hasher = Sha256::new();

        hasher.update(ED25519_HSS_CONTEXT_BINDING_DOMAIN_V1);
        update_len_prefixed(&mut hasher, &normalized.org_id);
        update_len_prefixed(&mut hasher, &normalized.account_id);
        update_len_prefixed(&mut hasher, &normalized.key_purpose);
        update_len_prefixed(&mut hasher, &normalized.key_version);
        hasher.update((normalized.participant_ids.len() as u32).to_be_bytes());
        for participant_id in normalized.participant_ids {
            hasher.update(participant_id.to_be_bytes());
        }
        hasher.update(normalized.derivation_version.to_be_bytes());

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed25519HssClientInputsV1 {
    pub context: Ed25519HssCanonicalContextV1,
    pub context_binding: [u8; 32],
    pub y_client: [u8; 32],
    pub tau_client: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ed25519HssServerInputsV1 {
    pub context: Ed25519HssCanonicalContextV1,
    pub context_binding: [u8; 32],
    pub y_server: [u8; 32],
    pub tau_server: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearEd25519SeedExportArtifactV1 {
    pub artifact_kind: String,
    pub seed_b64u: String,
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

fn validate_nonempty_exact(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must be non-empty"
        )));
    }
    if value.trim() != value {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must not contain leading or trailing whitespace"
        )));
    }
    Ok(())
}

fn update_len_prefixed(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value.as_bytes());
}

pub fn expand_ed25519_seed(seed: [u8; 32]) -> ExpandedEd25519SeedMaterial {
    let hash = Sha512::digest(seed);

    let mut signing_scalar_bytes = [0u8; 32];
    signing_scalar_bytes.copy_from_slice(&hash[..32]);
    signing_scalar_bytes[0] &= 248;
    signing_scalar_bytes[31] &= 63;
    signing_scalar_bytes[31] |= 64;

    let mut nonce_prefix = [0u8; 32];
    nonce_prefix.copy_from_slice(&hash[32..64]);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key_bytes = signing_key.verifying_key().to_bytes();

    ExpandedEd25519SeedMaterial {
        seed,
        signing_scalar_bytes,
        nonce_prefix,
        public_key_bytes,
    }
}

pub fn encode_near_ed25519_private_key_from_seed(seed: [u8; 32]) -> String {
    let material = expand_ed25519_seed(seed);
    let mut encoded = [0u8; 64];
    encoded[..32].copy_from_slice(&material.seed);
    encoded[32..].copy_from_slice(&material.public_key_bytes);
    format!("ed25519:{}", bs58::encode(encoded).into_string())
}

fn derive_hkdf_bytes(salt: &[u8], prf_first: &[u8], info: &[u8], out: &mut [u8]) -> CoreResult<()> {
    if prf_first.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "prf.first must be non-empty",
        ));
    }
    Hkdf::<Sha256>::new(Some(salt), prf_first)
        .expand(info, out)
        .map_err(|_| SignerCoreError::hkdf_error("HKDF expand failed"))
}

pub fn derive_ed25519_hss_client_inputs_v1(
    prf_first: &[u8],
    context: &Ed25519HssCanonicalContextV1,
) -> CoreResult<Ed25519HssClientInputsV1> {
    let context = context.normalized()?;
    let context_binding = context.binding_digest()?;

    let mut y_client = [0u8; 32];
    derive_hkdf_bytes(
        ED25519_HSS_CLIENT_ROOT_SHARE_SALT_V1,
        prf_first,
        &context_binding,
        &mut y_client,
    )?;

    let mut tau_wide = [0u8; 64];
    derive_hkdf_bytes(
        ED25519_HSS_CLIENT_TAU_SHARE_SALT_V1,
        prf_first,
        &context_binding,
        &mut tau_wide,
    )?;
    let tau_client =
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&tau_wide).to_bytes();

    Ok(Ed25519HssClientInputsV1 {
        context,
        context_binding,
        y_client,
        tau_client,
    })
}

pub fn derive_ed25519_hss_server_inputs_v1(
    master_secret: &[u8],
    context: &Ed25519HssCanonicalContextV1,
) -> CoreResult<Ed25519HssServerInputsV1> {
    let context = context.normalized()?;
    let context_binding = context.binding_digest()?;

    let mut y_server = [0u8; 32];
    derive_hkdf_bytes(
        ED25519_HSS_SERVER_ROOT_SHARE_SALT_V1,
        master_secret,
        &context_binding,
        &mut y_server,
    )?;

    let mut tau_wide = [0u8; 64];
    derive_hkdf_bytes(
        ED25519_HSS_SERVER_TAU_SHARE_SALT_V1,
        master_secret,
        &context_binding,
        &mut tau_wide,
    )?;
    let tau_server =
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&tau_wide).to_bytes();

    Ok(Ed25519HssServerInputsV1 {
        context,
        context_binding,
        y_server,
        tau_server,
    })
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
        seed_b64u: Base64UrlUnpadded::encode_string(&seed),
        public_key,
        private_key: encode_near_ed25519_private_key_from_seed(seed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SignerCoreErrorCode;
    use base64ct::{Base64UrlUnpadded, Encoding};

    fn sample_hss_context() -> Ed25519HssCanonicalContextV1 {
        Ed25519HssCanonicalContextV1 {
            org_id: "org_123".to_string(),
            account_id: "alice.near".to_string(),
            key_purpose: "near-ed25519".to_string(),
            key_version: "single-key-hss-v1".to_string(),
            participant_ids: vec![2, 1, 2],
            derivation_version: 1,
        }
    }

    fn decode_b64u_32(input: &str) -> [u8; 32] {
        let bytes = Base64UrlUnpadded::decode_vec(input).expect("valid base64url");
        bytes
            .as_slice()
            .try_into()
            .expect("fixture must be 32 bytes")
    }

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
    fn hss_context_binding_normalizes_participant_ids() {
        let left = sample_hss_context();
        let right = Ed25519HssCanonicalContextV1 {
            participant_ids: vec![1, 2],
            ..sample_hss_context()
        };

        assert_eq!(
            left.binding_digest().expect("left binding digest"),
            right.binding_digest().expect("right binding digest"),
        );
    }

    #[test]
    fn hss_client_inputs_are_deterministic_and_domain_separated() {
        let prf_first = [13u8; 32];
        let base = sample_hss_context();
        let same = derive_ed25519_hss_client_inputs_v1(&prf_first, &base).expect("base inputs");
        let repeat =
            derive_ed25519_hss_client_inputs_v1(&prf_first, &sample_hss_context()).expect("repeat");
        assert_eq!(same, repeat);

        let different_account = derive_ed25519_hss_client_inputs_v1(
            &prf_first,
            &Ed25519HssCanonicalContextV1 {
                account_id: "bob.near".to_string(),
                ..sample_hss_context()
            },
        )
        .expect("different account");
        let different_purpose = derive_ed25519_hss_client_inputs_v1(
            &prf_first,
            &Ed25519HssCanonicalContextV1 {
                key_purpose: "near-ed25519-export".to_string(),
                ..sample_hss_context()
            },
        )
        .expect("different purpose");

        assert_ne!(same.context_binding, different_account.context_binding);
        assert_ne!(same.y_client, different_account.y_client);
        assert_ne!(same.tau_client, different_account.tau_client);
        assert_ne!(same.context_binding, different_purpose.context_binding);
    }

    #[test]
    fn hss_client_inputs_require_two_non_zero_participants() {
        let error = derive_ed25519_hss_client_inputs_v1(
            &[17u8; 32],
            &Ed25519HssCanonicalContextV1 {
                participant_ids: vec![1, 0],
                ..sample_hss_context()
            },
        )
        .expect_err("invalid participants");
        assert_eq!(error.code, SignerCoreErrorCode::InvalidInput);
        assert!(error.message.contains("participantIds"));
    }

    #[test]
    fn hss_server_inputs_are_deterministic_and_domain_separated() {
        let master_secret = [21u8; 32];
        let base = sample_hss_context();
        let same = derive_ed25519_hss_server_inputs_v1(&master_secret, &base).expect("base inputs");
        let repeat = derive_ed25519_hss_server_inputs_v1(&master_secret, &sample_hss_context())
            .expect("repeat");
        assert_eq!(same, repeat);

        let different_version = derive_ed25519_hss_server_inputs_v1(
            &master_secret,
            &Ed25519HssCanonicalContextV1 {
                key_version: "single-key-hss-v2".to_string(),
                ..sample_hss_context()
            },
        )
        .expect("different version");

        assert_ne!(same.context_binding, different_version.context_binding);
        assert_ne!(same.y_server, different_version.y_server);
        assert_ne!(same.tau_server, different_version.tau_server);
    }

    #[test]
    fn hss_client_and_server_inputs_share_the_same_context_binding() {
        let context = sample_hss_context();
        let client =
            derive_ed25519_hss_client_inputs_v1(&[7u8; 32], &context).expect("client inputs");
        let server =
            derive_ed25519_hss_server_inputs_v1(&[9u8; 32], &context).expect("server inputs");

        assert_eq!(client.context_binding, server.context_binding);
        assert_eq!(client.context, server.context);
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
        assert_eq!(decode_b64u_32(&artifact.seed_b64u), seed);
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
