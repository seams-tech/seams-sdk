use crate::crypto::WrapKey;
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(test)]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
#[cfg(test)]
use curve25519_dalek::scalar::Scalar as CurveScalar;
use frost_ed25519::keys::KeyPackage;

#[cfg(test)]
pub(crate) fn derive_threshold_client_signing_share_bytes_v1(
    wrap_key: &WrapKey,
    near_account_id: &str,
) -> Result<[u8; 32], String> {
    signer_wasm_core::near_threshold_ed25519::derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed_b64u(
        &wrap_key.wrap_key_seed,
        near_account_id,
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn derive_threshold_client_verifying_share_b64u_v1(
    wrap_key: &WrapKey,
    near_account_id: &str,
) -> Result<String, String> {
    signer_wasm_core::near_threshold_ed25519::derive_threshold_client_verifying_share_b64u_v1_from_wrap_key_seed_b64u(
        &wrap_key.wrap_key_seed,
        near_account_id,
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn key_package_from_client_base_b64u(
    x_client_base_b64u: &str,
    near_public_key_bytes: &[u8; 32],
    client_identifier: frost_ed25519::Identifier,
) -> Result<KeyPackage, String> {
    let decoded = Base64UrlUnpadded::decode_vec(x_client_base_b64u)
        .map_err(|e| format!("Invalid xClientBaseB64u: {e}"))?;
    let signing_share_bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        format!(
            "xClientBaseB64u must decode to 32 bytes, got {}",
            decoded.len()
        )
    })?;
    signer_wasm_core::near_threshold_ed25519::key_package_from_signing_share_bytes(
        &signing_share_bytes,
        near_public_key_bytes,
        client_identifier,
    )
    .map_err(|e| e.to_string())
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

        let v1 = signer_wasm_core::near_threshold_ed25519::derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed_b64u(
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

    #[test]
    fn key_package_from_client_base_matches_generic_constructor() {
        let signing_share_bytes = [7u8; 32];
        let near_public_key_bytes = (ED25519_BASEPOINT_POINT * CurveScalar::from(11u64))
            .compress()
            .to_bytes();
        let client_identifier: frost_ed25519::Identifier =
            1u16.try_into().expect("valid identifier");

        let from_b64u = key_package_from_client_base_b64u(
            &base64_url_encode(&signing_share_bytes),
            &near_public_key_bytes,
            client_identifier,
        )
        .expect("client base should decode");
        let direct =
            signer_wasm_core::near_threshold_ed25519::key_package_from_signing_share_bytes(
                &signing_share_bytes,
                &near_public_key_bytes,
                client_identifier,
            )
            .expect("generic constructor should succeed");

        assert_eq!(from_b64u.identifier(), direct.identifier());
        assert_eq!(from_b64u.signing_share(), direct.signing_share());
        assert_eq!(from_b64u.verifying_share(), direct.verifying_share());
        assert_eq!(from_b64u.verifying_key(), direct.verifying_key());
    }
}
