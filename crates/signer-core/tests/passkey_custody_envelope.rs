#![cfg(feature = "passkey-custody")]

//! Boundary tests for passkey custody sealing.
//!
//! These own the crypto invariants of Refactor 100 Phase 1: AAD substitution
//! across every binding field, ciphertext tampering, cross-credential and
//! cross-curve key separation, and the digest checks a browser cache must pass.

use signer_core::passkey_custody::{
    derive_passkey_custody_kek_v1, encode_passkey_custody_aad_v1, open_passkey_custody_secret_v1,
    open_verified_passkey_custody_secret_v1, seal_passkey_custody_secret_v1, sha256_digest,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodyLaneScopeV1, PasskeyCustodySecretBindingV1,
    WalletCustodyEnvelopeFactorV1, EMAIL_OTP_FACTOR_KEK_VERSION_V1, PASSKEY_CUSTODY_KEK_VERSION_V1,
    WALLET_SEED_DERIVATION_SCHEME_V1,
};

const PRF_FIRST: [u8; 32] = [7u8; 32];
const OTHER_PRF_FIRST: [u8; 32] = [9u8; 32];
const NONCE: [u8; 12] = [3u8; 12];
const CUSTODY_SECRET: [u8; 32] = [42u8; 32];

fn digest_b64u(seed: u8) -> String {
    base64_url(&[seed; 32])
}

fn base64_url(bytes: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
}

fn ed25519_lane() -> PasskeyCustodyLaneScopeV1 {
    PasskeyCustodyLaneScopeV1 {
        wallet_key_id: "wallet-key:ed25519:alice.testnet:root-1:v1".into(),
        lane_id: "lane:owner:ed25519:1".into(),
        lane_share_epoch: "lane-share-epoch-1".into(),
    }
}

fn evm_lane() -> PasskeyCustodyLaneScopeV1 {
    PasskeyCustodyLaneScopeV1 {
        wallet_key_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
        lane_id: "lane:owner:evm-family:1".into(),
        lane_share_epoch: "lane-share-epoch-1".into(),
    }
}

fn wallet_seed_binding() -> PasskeyCustodySecretBindingV1 {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    PasskeyCustodySecretBindingV1::WalletCustodySeed {
        derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.into(),
        key_manifest_digest_b64u: digest_b64u(1),
        near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
        registered_public_key_b64u: digest_b64u(5),
        evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
        client_root_public_key33_b64u: base64_url(&compressed),
    }
}

fn passkey_factor() -> WalletCustodyEnvelopeFactorV1 {
    WalletCustodyEnvelopeFactorV1::Passkey {
        rp_id: "wallet.example.localhost".into(),
        credential_id_b64u: "Y3JlZGVudGlhbC0x".into(),
        kek_version: PASSKEY_CUSTODY_KEK_VERSION_V1.into(),
    }
}

fn email_otp_factor() -> WalletCustodyEnvelopeFactorV1 {
    WalletCustodyEnvelopeFactorV1::EmailOtp {
        enrollment_id: "enrollment-1".into(),
        enrollment_seal_key_version: "seal-v1".into(),
        kek_version: EMAIL_OTP_FACTOR_KEK_VERSION_V1.into(),
    }
}

fn ecdsa_lane_binding() -> PasskeyCustodySecretBindingV1 {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x03;
    PasskeyCustodySecretBindingV1::EcdsaLaneHolderShare {
        lane: evm_lane(),
        evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
        threshold_session_id: "threshold-ecdsa-session-1".into(),
        threshold_public_key33_b64u: base64_url(&compressed),
    }
}

fn envelope(binding: PasskeyCustodySecretBindingV1) -> PasskeyCustodyEnvelopeBindingV1 {
    PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: "alice.testnet".into(),
        envelope_id: "wallet-custody-envelope-1".into(),
        factor: passkey_factor(),
        envelope_revision: 1,
        binding,
    }
}

#[test]
fn seals_and_opens_every_custody_branch() {
    let mut threshold_key = [0u8; 33];
    threshold_key[0] = 0x03;
    let _ = threshold_key;
    let branches = vec![
        wallet_seed_binding(),
        PasskeyCustodySecretBindingV1::Ed25519LaneHolderShare {
            lane: ed25519_lane(),
            near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
            registered_public_key_b64u: digest_b64u(5),
            participant_binding_digest_b64u: digest_b64u(6),
        },
        ecdsa_lane_binding(),
    ];

    for branch in branches {
        let binding = envelope(branch);
        let sealed =
            seal_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();
        let opened =
            open_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &sealed.ciphertext)
                .unwrap();
        assert_eq!(opened.as_slice(), CUSTODY_SECRET);
        assert_eq!(sealed.ciphertext_digest, sha256_digest(&sealed.ciphertext));
    }
}

#[test]
fn substituting_any_bound_field_prevents_opening() {
    let binding = envelope(wallet_seed_binding());
    let sealed =
        seal_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();

    let mut substitutions: Vec<PasskeyCustodyEnvelopeBindingV1> = Vec::new();

    let mut wrong_wallet = binding.clone();
    wrong_wallet.wallet_id = "mallory.testnet".into();
    substitutions.push(wrong_wallet);

    let mut wrong_envelope = binding.clone();
    wrong_envelope.envelope_id = "wallet-custody-envelope-2".into();
    substitutions.push(wrong_envelope);

    let mut wrong_revision = binding.clone();
    wrong_revision.envelope_revision = 2;
    substitutions.push(wrong_revision);

    let mut wrong_rp = binding.clone();
    wrong_rp.factor = WalletCustodyEnvelopeFactorV1::Passkey {
        rp_id: "evil.example".into(),
        credential_id_b64u: "Y3JlZGVudGlhbC0x".into(),
        kek_version: PASSKEY_CUSTODY_KEK_VERSION_V1.into(),
    };
    substitutions.push(wrong_rp);

    let mut wrong_credential = binding.clone();
    wrong_credential.factor = WalletCustodyEnvelopeFactorV1::Passkey {
        rp_id: "wallet.example.localhost".into(),
        credential_id_b64u: "Y3JlZGVudGlhbC0y".into(),
        kek_version: PASSKEY_CUSTODY_KEK_VERSION_V1.into(),
    };
    substitutions.push(wrong_credential);

    // A different factor kind is the case that matters most for the single-seed
    // model: two factors wrap the same seed, so they must never share a KEK.
    let mut other_factor = binding.clone();
    other_factor.factor = email_otp_factor();
    substitutions.push(other_factor);

    let mut wrong_manifest = binding.clone();
    wrong_manifest.binding = PasskeyCustodySecretBindingV1::WalletCustodySeed {
        derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.into(),
        key_manifest_digest_b64u: digest_b64u(99),
        near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
        registered_public_key_b64u: digest_b64u(5),
        evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
        client_root_public_key33_b64u: {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            base64_url(&compressed)
        },
    };
    substitutions.push(wrong_manifest);

    let mut wrong_signing_key = binding.clone();
    wrong_signing_key.binding = PasskeyCustodySecretBindingV1::WalletCustodySeed {
        derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.into(),
        key_manifest_digest_b64u: digest_b64u(1),
        near_ed25519_signing_key_id: "near-ed25519-key-2".into(),
        registered_public_key_b64u: digest_b64u(5),
        evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
        client_root_public_key33_b64u: {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            base64_url(&compressed)
        },
    };
    substitutions.push(wrong_signing_key);

    for substitution in substitutions {
        assert!(
            open_passkey_custody_secret_v1(&PRF_FIRST, &substitution, &NONCE, &sealed.ciphertext)
                .is_err(),
            "a substituted binding must not open the envelope"
        );
    }
}

#[test]
fn a_different_custody_branch_cannot_open_the_same_ciphertext() {
    let ed25519 = envelope(wallet_seed_binding());
    let sealed =
        seal_passkey_custody_secret_v1(&PRF_FIRST, &ed25519, &NONCE, &CUSTODY_SECRET).unwrap();

    let mut ecdsa = envelope(ecdsa_lane_binding());
    ecdsa.envelope_id = ed25519.envelope_id.clone();
    assert!(
        open_passkey_custody_secret_v1(&PRF_FIRST, &ecdsa, &NONCE, &sealed.ciphertext).is_err()
    );

    // The KEKs differ too, not just the AAD: purpose is part of the HKDF info.
    let ed25519_kek = derive_passkey_custody_kek_v1(&PRF_FIRST, &ed25519).unwrap();
    let ecdsa_kek = derive_passkey_custody_kek_v1(&PRF_FIRST, &ecdsa).unwrap();
    assert_ne!(ed25519_kek.as_slice(), ecdsa_kek.as_slice());
}

#[test]
fn a_different_prf_result_cannot_open_the_envelope() {
    let binding = envelope(wallet_seed_binding());
    let sealed =
        seal_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();
    assert!(
        open_passkey_custody_secret_v1(&OTHER_PRF_FIRST, &binding, &NONCE, &sealed.ciphertext)
            .is_err()
    );
}

#[test]
fn tampered_ciphertext_and_nonce_fail_to_open() {
    let binding = envelope(wallet_seed_binding());
    let sealed =
        seal_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();

    for index in [0usize, 5, sealed.ciphertext.len() - 1] {
        let mut tampered = sealed.ciphertext.clone();
        tampered[index] ^= 0x01;
        assert!(
            open_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &tampered).is_err(),
            "flipping ciphertext byte {index} must fail authentication"
        );
    }

    let mut wrong_nonce = NONCE;
    wrong_nonce[0] ^= 0x01;
    assert!(
        open_passkey_custody_secret_v1(&PRF_FIRST, &binding, &wrong_nonce, &sealed.ciphertext)
            .is_err()
    );

    let truncated = &sealed.ciphertext[..sealed.ciphertext.len() - 1];
    assert!(open_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, truncated).is_err());
}

#[test]
fn digest_verification_rejects_a_drifted_cache_row() {
    let binding = envelope(wallet_seed_binding());
    let sealed =
        seal_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();

    let opened = open_verified_passkey_custody_secret_v1(
        &PRF_FIRST,
        &binding,
        &NONCE,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
    .unwrap();
    assert_eq!(opened.as_slice(), CUSTODY_SECRET);

    let wrong_digest = [0u8; 32];
    assert!(open_verified_passkey_custody_secret_v1(
        &PRF_FIRST,
        &binding,
        &NONCE,
        &sealed.ciphertext,
        &wrong_digest,
        &sealed.ciphertext_digest,
    )
    .is_err());
    assert!(open_verified_passkey_custody_secret_v1(
        &PRF_FIRST,
        &binding,
        &NONCE,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &wrong_digest,
    )
    .is_err());
}

#[test]
fn aad_is_unambiguous_across_field_boundaries() {
    // Length-delimited labeled fields mean a value cannot be shifted into the
    // neighbouring field to forge an equal encoding.
    let mut left = envelope(wallet_seed_binding());
    left.wallet_id = "alice".into();
    left.envelope_id = "envelope-1".into();

    let mut right = envelope(wallet_seed_binding());
    right.wallet_id = "aliceenvelope".into();
    right.envelope_id = "-1".into();

    assert_ne!(
        encode_passkey_custody_aad_v1(&left).unwrap(),
        encode_passkey_custody_aad_v1(&right).unwrap()
    );
}

#[test]
fn malformed_binding_fields_are_rejected_before_any_crypto() {
    let mut empty_wallet = envelope(wallet_seed_binding());
    empty_wallet.wallet_id = String::new();
    assert!(encode_passkey_custody_aad_v1(&empty_wallet).is_err());

    fn seed_with(
        derivation_scheme: &str,
        key_manifest_digest_b64u: String,
        client_root_public_key33_b64u: String,
    ) -> PasskeyCustodySecretBindingV1 {
        PasskeyCustodySecretBindingV1::WalletCustodySeed {
            derivation_scheme: derivation_scheme.into(),
            key_manifest_digest_b64u,
            near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
            registered_public_key_b64u: digest_b64u(5),
            evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
            client_root_public_key33_b64u,
        }
    }

    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    let valid_client_root = base64_url(&compressed);

    let mut bad_digest = envelope(wallet_seed_binding());
    bad_digest.binding = seed_with(
        WALLET_SEED_DERIVATION_SCHEME_V1,
        "not-32-bytes".into(),
        valid_client_root.clone(),
    );
    assert!(encode_passkey_custody_aad_v1(&bad_digest).is_err());

    // A 32-byte digest is not a 33-byte compressed point.
    let mut bad_client_root = envelope(wallet_seed_binding());
    bad_client_root.binding = seed_with(
        WALLET_SEED_DERIVATION_SCHEME_V1,
        digest_b64u(1),
        digest_b64u(3),
    );
    assert!(encode_passkey_custody_aad_v1(&bad_client_root).is_err());

    // An unknown derivation scheme is refused rather than treated as default.
    let mut bad_scheme = envelope(wallet_seed_binding());
    bad_scheme.binding = seed_with(
        "wallet_seed_chained_v0",
        digest_b64u(1),
        valid_client_root.clone(),
    );
    assert!(encode_passkey_custody_aad_v1(&bad_scheme).is_err());

    // A factor declaring the other kind's KEK version is refused, so the two
    // factors can never be coaxed into deriving from the same context.
    let mut crossed_kek = envelope(wallet_seed_binding());
    crossed_kek.factor = WalletCustodyEnvelopeFactorV1::Passkey {
        rp_id: "wallet.example.localhost".into(),
        credential_id_b64u: "Y3JlZGVudGlhbC0x".into(),
        kek_version: EMAIL_OTP_FACTOR_KEK_VERSION_V1.into(),
    };
    assert!(encode_passkey_custody_aad_v1(&crossed_kek).is_err());

    let binding = envelope(wallet_seed_binding());
    assert!(seal_passkey_custody_secret_v1(&[0u8; 16], &binding, &NONCE, &CUSTODY_SECRET).is_err());
    assert!(
        seal_passkey_custody_secret_v1(&PRF_FIRST, &binding, &[0u8; 24], &CUSTODY_SECRET).is_err()
    );
    assert!(seal_passkey_custody_secret_v1(&PRF_FIRST, &binding, &NONCE, &[]).is_err());
}

#[test]
fn cross_branch_fields_fail_to_deserialize() {
    // The Rust boundary mirrors the TypeScript parser: a wallet-scoped seed
    // record carrying lane identity is rejected, not narrowed.
    let json = r#"{
        "kind": "wallet_custody_seed_v1",
        "derivationScheme": "wallet_seed_parallel_hkdf_sha256_v1",
        "keyManifestDigestB64u": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
        "nearEd25519SigningKeyId": "near-ed25519-key-1",
        "registeredPublicKeyB64u": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
        "evmFamilySigningKeySlotId": "wallet-key:evm-family:alice.testnet:root-1:v1",
        "clientRootPublicKey33B64u": "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "laneId": "lane:owner:ed25519:1"
    }"#;
    assert!(serde_json::from_str::<PasskeyCustodySecretBindingV1>(json).is_err());
}

#[test]
fn a_valid_branch_round_trips_through_json() {
    let json = r#"{
        "kind": "ecdsa_lane_holder_share_v1",
        "walletKeyId": "wallet-key:evm-family:alice.testnet:root-1:v1",
        "laneId": "lane:owner:evm-family:1",
        "laneShareEpoch": "lane-share-epoch-1",
        "evmFamilySigningKeySlotId": "wallet-key:evm-family:alice.testnet:root-1:v1",
        "thresholdSessionId": "threshold-ecdsa-session-1",
        "thresholdPublicKey33B64u": "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }"#;
    let parsed = serde_json::from_str::<PasskeyCustodySecretBindingV1>(json).unwrap();
    assert_eq!(parsed.kind().as_str(), "ecdsa_lane_holder_share_v1");
    assert_eq!(parsed.lane().unwrap().lane_id, "lane:owner:evm-family:1");
    assert!(encode_passkey_custody_aad_v1(&envelope(parsed)).is_ok());
}

#[test]
fn a_wallet_scoped_seed_and_a_lane_share_never_encode_alike() {
    // The seed encodes an explicit `scope=wallet` marker rather than omitting
    // lane fields, so its AAD can never be a prefix of a lane AAD.
    let seed = encode_passkey_custody_aad_v1(&envelope(wallet_seed_binding())).unwrap();
    let lane = encode_passkey_custody_aad_v1(&envelope(ecdsa_lane_binding())).unwrap();
    assert_ne!(seed, lane);
    assert!(!lane.starts_with(&seed));
    assert!(!seed.starts_with(&lane));
}

#[test]
fn interchangeable_factors_derive_different_keks_for_one_seed() {
    // Passkey and Email OTP wrap the same custody seed. They must still derive
    // separate KEKs, or compromising one factor's key would open the other's
    // envelope directly.
    let passkey = envelope(wallet_seed_binding());
    let mut email_otp = envelope(wallet_seed_binding());
    email_otp.factor = email_otp_factor();

    let passkey_kek = derive_passkey_custody_kek_v1(&PRF_FIRST, &passkey).unwrap();
    let otp_kek = derive_passkey_custody_kek_v1(&PRF_FIRST, &email_otp).unwrap();
    assert_ne!(passkey_kek.as_slice(), otp_kek.as_slice());

    let sealed =
        seal_passkey_custody_secret_v1(&PRF_FIRST, &passkey, &NONCE, &CUSTODY_SECRET).unwrap();
    assert!(
        open_passkey_custody_secret_v1(&PRF_FIRST, &email_otp, &NONCE, &sealed.ciphertext).is_err()
    );
}
