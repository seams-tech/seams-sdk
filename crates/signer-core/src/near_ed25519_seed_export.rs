use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{CoreResult, SignerCoreError};
use crate::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;

pub const SEED_BACKED_CLIENT_PARTICIPANT_ID_V1: u16 = 1;
pub const SEED_BACKED_RELAYER_PARTICIPANT_ID_V1: u16 = 2;
pub const SEED_BACKED_DERIVATION_PATH_V1: u32 = 0;
pub const SEED_BACKED_MAX_COUNTER_TRIES_V1: u32 = 1024;
pub const SEED_BACKED_CLIENT_SIGNING_SHARE_SALT_V2: &[u8] =
    b"tatchi/lite/threshold-ed25519/client-signing-share:v2";
pub const SEED_BACKED_CLIENT_EXPORT_SHARE_SALT_V1: &[u8] =
    b"tatchi/lite/threshold-ed25519/client-export-share:v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedEd25519SeedMaterial {
    pub seed: [u8; 32],
    pub signing_scalar_bytes: [u8; 32],
    pub nonce_prefix: [u8; 32],
    pub public_key_bytes: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedBackedThresholdShareBundleV1 {
    pub seed_material: ExpandedEd25519SeedMaterial,
    pub x_client: [u8; 32],
    pub x_relayer: [u8; 32],
    pub y_client: [u8; 32],
    pub y_relayer: [u8; 32],
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

pub fn build_seed_backed_derivation_info_v1(
    near_account_id: &str,
    key_version: &str,
    counter: u32,
) -> CoreResult<Vec<u8>> {
    let near_account_id = require_nonempty("nearAccountId", near_account_id)?;
    let key_version = require_nonempty("keyVersion", key_version)?;

    let mut info = Vec::with_capacity(near_account_id.len() + key_version.len() + 14);
    info.extend_from_slice(near_account_id.as_bytes());
    info.push(0);
    info.extend_from_slice(key_version.as_bytes());
    info.push(0);
    info.extend_from_slice(&SEED_BACKED_CLIENT_PARTICIPANT_ID_V1.to_be_bytes());
    info.extend_from_slice(&SEED_BACKED_RELAYER_PARTICIPANT_ID_V1.to_be_bytes());
    info.extend_from_slice(&SEED_BACKED_DERIVATION_PATH_V1.to_be_bytes());
    info.extend_from_slice(&counter.to_be_bytes());
    Ok(info)
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

pub fn derive_seed_backed_client_signing_share_v2(
    prf_first: &[u8],
    near_account_id: &str,
    key_version: &str,
) -> CoreResult<[u8; 32]> {
    let mut okm = [0u8; 64];
    for counter in 0..SEED_BACKED_MAX_COUNTER_TRIES_V1 {
        let info = build_seed_backed_derivation_info_v1(near_account_id, key_version, counter)?;
        derive_hkdf_bytes(
            SEED_BACKED_CLIENT_SIGNING_SHARE_SALT_V2,
            prf_first,
            &info,
            &mut okm,
        )?;
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&okm);
        if scalar != curve25519_dalek::scalar::Scalar::ZERO {
            return Ok(scalar.to_bytes());
        }
    }
    Err(SignerCoreError::crypto_error(
        "client signing share derivation exhausted counter retries",
    ))
}

pub fn derive_seed_backed_client_export_share_v1(
    prf_first: &[u8],
    near_account_id: &str,
    key_version: &str,
) -> CoreResult<[u8; 32]> {
    let info = build_seed_backed_derivation_info_v1(near_account_id, key_version, 0)?;
    let mut okm = [0u8; 32];
    derive_hkdf_bytes(
        SEED_BACKED_CLIENT_EXPORT_SHARE_SALT_V1,
        prf_first,
        &info,
        &mut okm,
    )?;
    Ok(okm)
}

pub fn derive_seed_backed_relayer_signing_share_2p_v1(
    signing_scalar_bytes: [u8; 32],
    x_client: [u8; 32],
) -> [u8; 32] {
    let a = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(signing_scalar_bytes);
    let x_client = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(x_client);
    (x_client + x_client - a).to_bytes()
}

pub fn derive_seed_backed_relayer_export_share_2p_v1(
    seed: [u8; 32],
    y_client: [u8; 32],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: u16 = 0;
    for idx in 0..32 {
        let lhs = seed[idx] as u16;
        let rhs = y_client[idx] as u16 + borrow;
        if lhs >= rhs {
            out[idx] = (lhs - rhs) as u8;
            borrow = 0;
        } else {
            out[idx] = ((lhs + 256) - rhs) as u8;
            borrow = 1;
        }
    }
    out
}

pub fn derive_seed_backed_verifying_share_2p_v1(signing_share_bytes: [u8; 32]) -> [u8; 32] {
    let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(signing_share_bytes);
    (curve25519_dalek::constants::ED25519_BASEPOINT_POINT * scalar)
        .compress()
        .to_bytes()
}

pub fn derive_seed_backed_threshold_public_key_2p_v1(
    x_client: [u8; 32],
    x_relayer: [u8; 32],
) -> CoreResult<[u8; 32]> {
    let client_verifying_share = derive_seed_backed_verifying_share_2p_v1(x_client);
    let relayer_verifying_share = derive_seed_backed_verifying_share_2p_v1(x_relayer);
    compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &client_verifying_share,
        &relayer_verifying_share,
        SEED_BACKED_CLIENT_PARTICIPANT_ID_V1,
        SEED_BACKED_RELAYER_PARTICIPANT_ID_V1,
    )
}

pub fn combine_seed_backed_export_shares_2p_v1(
    y_client: [u8; 32],
    y_relayer: [u8; 32],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for idx in 0..32 {
        let sum = y_client[idx] as u16 + y_relayer[idx] as u16 + carry;
        out[idx] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

pub fn validate_seed_backed_threshold_share_bundle_v1(
    bundle: &SeedBackedThresholdShareBundleV1,
) -> CoreResult<()> {
    let derived_group_public_key =
        derive_seed_backed_threshold_public_key_2p_v1(bundle.x_client, bundle.x_relayer)?;
    if derived_group_public_key != bundle.seed_material.public_key_bytes {
        return Err(SignerCoreError::crypto_error(
            "seed-backed share bundle does not match seed-derived public key",
        ));
    }
    if combine_seed_backed_export_shares_2p_v1(bundle.y_client, bundle.y_relayer)
        != bundle.seed_material.seed
    {
        return Err(SignerCoreError::crypto_error(
            "seed-backed export shares do not recombine to the original seed",
        ));
    }
    Ok(())
}

pub fn derive_seed_backed_threshold_share_bundle_v1(
    seed: [u8; 32],
    prf_first: &[u8],
    near_account_id: &str,
    key_version: &str,
) -> CoreResult<SeedBackedThresholdShareBundleV1> {
    let seed_material = expand_ed25519_seed(seed);
    let x_client =
        derive_seed_backed_client_signing_share_v2(prf_first, near_account_id, key_version)?;
    let y_client =
        derive_seed_backed_client_export_share_v1(prf_first, near_account_id, key_version)?;
    let x_relayer = derive_seed_backed_relayer_signing_share_2p_v1(
        seed_material.signing_scalar_bytes,
        x_client,
    );
    let y_relayer = derive_seed_backed_relayer_export_share_2p_v1(seed_material.seed, y_client);
    let bundle = SeedBackedThresholdShareBundleV1 {
        seed_material,
        x_client,
        x_relayer,
        y_client,
        y_relayer,
    };
    validate_seed_backed_threshold_share_bundle_v1(&bundle)?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SeedExportFixtureV1 {
        near_account_id: String,
        key_version: String,
        client_participant_id: u16,
        relayer_participant_id: u16,
        prf_first_b64u: String,
        seed_b64u: String,
        signing_scalar_b64u: String,
        nonce_prefix_b64u: String,
        public_key: String,
        near_private_key: String,
        x_client_b64u: String,
        x_relayer_b64u: String,
        y_client_b64u: String,
        y_relayer_b64u: String,
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
    fn seed_backed_signing_and_export_domains_are_distinct() {
        let prf_first = [11u8; 32];
        let x_client = derive_seed_backed_client_signing_share_v2(&prf_first, "alice.near", "v1")
            .expect("x_client");
        let y_client = derive_seed_backed_client_export_share_v1(&prf_first, "alice.near", "v1")
            .expect("y_client");
        assert_ne!(x_client, y_client);
    }

    #[test]
    fn relayer_shares_recombine_to_seed_and_signing_scalar() {
        let seed = [23u8; 32];
        let prf_first = [19u8; 32];
        let bundle =
            derive_seed_backed_threshold_share_bundle_v1(seed, &prf_first, "alice.near", "v1")
                .expect("bundle");

        let a = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
            bundle.seed_material.signing_scalar_bytes,
        );
        let x_client = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(bundle.x_client);
        let x_relayer = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(bundle.x_relayer);
        assert_eq!(x_client + x_client - x_relayer, a);

        assert_eq!(
            combine_seed_backed_export_shares_2p_v1(bundle.y_client, bundle.y_relayer),
            bundle.seed_material.seed,
        );
        validate_seed_backed_threshold_share_bundle_v1(&bundle).expect("bundle validation");
    }

    #[test]
    fn published_seed_export_fixture_matches_derived_outputs() {
        let fixture: SeedExportFixtureV1 =
            serde_json::from_str(include_str!("../fixtures/ed25519-export-seed-v1/v1.json"))
                .expect("fixture json");

        assert_eq!(
            fixture.client_participant_id,
            SEED_BACKED_CLIENT_PARTICIPANT_ID_V1
        );
        assert_eq!(
            fixture.relayer_participant_id,
            SEED_BACKED_RELAYER_PARTICIPANT_ID_V1
        );

        let seed = decode_b64u_32(&fixture.seed_b64u);
        let prf_first = Base64UrlUnpadded::decode_vec(&fixture.prf_first_b64u).expect("prf_first");
        let bundle = derive_seed_backed_threshold_share_bundle_v1(
            seed,
            &prf_first,
            &fixture.near_account_id,
            &fixture.key_version,
        )
        .expect("fixture bundle");

        assert_eq!(
            Base64UrlUnpadded::encode_string(&bundle.seed_material.signing_scalar_bytes),
            fixture.signing_scalar_b64u,
        );
        assert_eq!(
            Base64UrlUnpadded::encode_string(&bundle.seed_material.nonce_prefix),
            fixture.nonce_prefix_b64u,
        );
        assert_eq!(
            format!(
                "ed25519:{}",
                bs58::encode(bundle.seed_material.public_key_bytes).into_string()
            ),
            fixture.public_key,
        );
        assert_eq!(
            encode_near_ed25519_private_key_from_seed(bundle.seed_material.seed),
            fixture.near_private_key,
        );
        assert_eq!(
            Base64UrlUnpadded::encode_string(&bundle.x_client),
            fixture.x_client_b64u,
        );
        assert_eq!(
            Base64UrlUnpadded::encode_string(&bundle.x_relayer),
            fixture.x_relayer_b64u,
        );
        assert_eq!(
            Base64UrlUnpadded::encode_string(&bundle.y_client),
            fixture.y_client_b64u,
        );
        assert_eq!(
            Base64UrlUnpadded::encode_string(&bundle.y_relayer),
            fixture.y_relayer_b64u,
        );
        validate_seed_backed_threshold_share_bundle_v1(&bundle).expect("fixture validation");
    }
}
