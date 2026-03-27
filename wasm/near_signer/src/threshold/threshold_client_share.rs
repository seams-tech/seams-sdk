use crate::crypto::WrapKey;
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(test)]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
#[cfg(test)]
use curve25519_dalek::scalar::Scalar as CurveScalar;
use frost_ed25519::keys::{KeyPackage, SigningShare, VerifyingShare};

#[cfg(test)]
pub(crate) fn derive_threshold_client_signing_share_bytes_v1(
    wrap_key: &WrapKey,
    near_account_id: &str,
) -> Result<[u8; 32], String> {
    signer_platform_web::near_threshold_ed25519::derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
        &wrap_key.wrap_key_seed,
        near_account_id,
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn derive_threshold_client_verifying_share_b64u_v1(
    wrap_key: &WrapKey,
    near_account_id: &str,
) -> Result<String, String> {
    signer_platform_web::near_threshold_ed25519::derive_threshold_client_verifying_share_b64u_v1_from_wrap_key_seed_b64u(
        &wrap_key.wrap_key_seed,
        near_account_id,
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn derive_option_b_client_signing_share_bytes_v1(
    prf_first_b64u: &str,
    near_account_id: &str,
    key_version: &str,
) -> Result<[u8; 32], String> {
    let prf_first =
        Base64UrlUnpadded::decode_vec(prf_first_b64u).map_err(|e| format!("Invalid prfFirstB64u: {e}"))?;
    signer_platform_web::near_ed25519_recovery::derive_bootstrap_client_signing_share_v2(
        prf_first.as_slice(),
        near_account_id,
        key_version,
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn derive_option_b_client_verifying_share_b64u_v1(
    prf_first_b64u: &str,
    near_account_id: &str,
    key_version: &str,
) -> Result<String, String> {
    let signing_share =
        derive_option_b_client_signing_share_bytes_v1(prf_first_b64u, near_account_id, key_version)?;
    Ok(Base64UrlUnpadded::encode_string(
        &signer_platform_web::near_ed25519_recovery::derive_bootstrap_verifying_share_2p_v1(
            signing_share,
        ),
    ))
}

pub(crate) fn derive_option_b_client_key_package_v1(
    prf_first_b64u: &str,
    near_account_id: &str,
    key_version: &str,
    near_public_key_bytes: &[u8; 32],
    client_identifier: frost_ed25519::Identifier,
) -> Result<KeyPackage, String> {
    let signing_share_bytes =
        derive_option_b_client_signing_share_bytes_v1(prf_first_b64u, near_account_id, key_version)?;
    let signing_share = SigningShare::deserialize(&signing_share_bytes)
        .map_err(|e| format!("threshold-signer: invalid Option B signing share: {e}"))?;
    let verifying_share_bytes =
        signer_platform_web::near_ed25519_recovery::derive_bootstrap_verifying_share_2p_v1(
            signing_share_bytes,
        );
    let verifying_share = VerifyingShare::deserialize(&verifying_share_bytes)
        .map_err(|e| format!("threshold-signer: invalid Option B verifying share: {e}"))?;
    let verifying_key = frost_ed25519::VerifyingKey::deserialize(near_public_key_bytes)
        .map_err(|e| format!("threshold-signer: invalid group public key: {e}"))?;
    Ok(KeyPackage::new(
        client_identifier,
        signing_share,
        verifying_share,
        verifying_key,
        2,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::WrapKey;
    use crate::encoders::base64_url_encode;

    #[test]
    fn derive_client_share_is_deterministic_and_matches_verifying_share() {
        let wrap_key = WrapKey {
            wrap_key_seed: base64_url_encode(&[7u8; 32]),
            wrap_key_salt: base64_url_encode(&[9u8; 32]),
        };

        let s1 = derive_threshold_client_signing_share_bytes_v1(&wrap_key, "alice.near")
            .expect("signing share should derive");
        let s2 = derive_threshold_client_signing_share_bytes_v1(&wrap_key, "alice.near")
            .expect("signing share should derive");
        assert_eq!(s1, s2);

        let v1 = signer_platform_web::near_threshold_ed25519::derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed_b64u(
            &wrap_key.wrap_key_seed,
            "alice.near",
        )
            .expect("verifying share should derive");
        let scalar = CurveScalar::from_bytes_mod_order(s1);
        let expected = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
        assert_eq!(v1, expected);

        let different_account =
            derive_threshold_client_signing_share_bytes_v1(&wrap_key, "bob.near")
                .expect("signing share should derive");
        assert_ne!(s1, different_account);
    }

    #[test]
    fn derive_client_share_rejects_invalid_seed_length() {
        let wrap_key = WrapKey {
            wrap_key_seed: base64_url_encode(&[1u8; 31]),
            wrap_key_salt: base64_url_encode(&[2u8; 32]),
        };

        let err =
            derive_threshold_client_signing_share_bytes_v1(&wrap_key, "alice.near").unwrap_err();
        assert!(err.contains("expected 32 bytes"), "unexpected error: {err}");
    }
}
