#![cfg(feature = "passkey-custody")]

//! Boundary tests for passkey custody sealing.
//!
//! These own the crypto invariants of Refactor 100 Phase 1: AAD substitution
//! across every binding field, ciphertext tampering, cross-credential and
//! cross-curve key separation, and the digest checks a browser cache must pass.

use signer_core::error::CoreResult;
use signer_core::passkey_custody::{
    derive_passkey_custody_kek_v1, encode_passkey_custody_aad_v1, open_passkey_custody_secret_v1,
    open_verified_passkey_custody_secret_v1, open_wallet_custody_seed_envelope_v1,
    reseal_wallet_custody_seed_under_new_factor_v1, seal_passkey_custody_secret_v1,
    seal_wallet_custody_seed_envelope_v1, sha256_digest, PasskeyCustodyEnvelopeBindingV1,
    PasskeyCustodyLaneScopeV1, PasskeyCustodySecretBindingV1, SealedPasskeyCustodyEnvelopeV1,
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
    PasskeyCustodySecretBindingV1::WalletCustodySeed {
        derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.into(),
    }
}

/// Seals through whichever entry point the binding's branch requires: a wallet
/// custody seed through its own path, a lane holder share through the general
/// one. Tests below exercise crypto invariants that hold for both.
fn seal_for_test(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    custody_secret: &[u8],
) -> CoreResult<SealedPasskeyCustodyEnvelopeV1> {
    match &binding.binding {
        PasskeyCustodySecretBindingV1::WalletCustodySeed { .. } => {
            seal_wallet_custody_seed_envelope_v1(prf_first, binding, nonce, custody_secret)
        }
        _ => seal_passkey_custody_secret_v1(prf_first, binding, nonce, custody_secret),
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
        let sealed = seal_for_test(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();
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
    let sealed = seal_for_test(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();

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
    let sealed = seal_for_test(&PRF_FIRST, &ed25519, &NONCE, &CUSTODY_SECRET).unwrap();

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
    let sealed = seal_for_test(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();
    assert!(
        open_passkey_custody_secret_v1(&OTHER_PRF_FIRST, &binding, &NONCE, &sealed.ciphertext)
            .is_err()
    );
}

#[test]
fn tampered_ciphertext_and_nonce_fail_to_open() {
    let binding = envelope(wallet_seed_binding());
    let sealed = seal_for_test(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();

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
    let sealed = seal_for_test(&PRF_FIRST, &binding, &NONCE, &CUSTODY_SECRET).unwrap();

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

    // The seed binding carries only its derivation scheme now, so that is the
    // one field an envelope can get wrong.
    let mut wrong_scheme = envelope(wallet_seed_binding());
    wrong_scheme.binding = PasskeyCustodySecretBindingV1::WalletCustodySeed {
        derivation_scheme: "wallet_seed_chained_v0".into(),
    };
    assert!(encode_passkey_custody_aad_v1(&wrong_scheme).is_err());
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

    let sealed = seal_for_test(&PRF_FIRST, &passkey, &NONCE, &CUSTODY_SECRET).unwrap();
    assert!(
        open_passkey_custody_secret_v1(&PRF_FIRST, &email_otp, &NONCE, &sealed.ciphertext).is_err()
    );
}

/// The other factor for the same wallet: a passkey envelope alongside the
/// Email OTP one, or vice versa.
fn second_factor_envelope() -> PasskeyCustodyEnvelopeBindingV1 {
    let mut binding = envelope(wallet_seed_binding());
    binding.factor = email_otp_factor();
    binding.envelope_id = "wallet-custody-envelope-2".into();
    binding
}

fn open_admitted() -> (
    Vec<u8>,
    signer_core::passkey_custody::WalletCustodySeedFromSealedEnvelopeV1,
) {
    let first = envelope(wallet_seed_binding());
    let sealed =
        seal_wallet_custody_seed_envelope_v1(&PRF_FIRST, &first, &NONCE, &CUSTODY_SECRET).unwrap();
    let (seed, admitted) = open_wallet_custody_seed_envelope_v1(
        &PRF_FIRST,
        &first,
        &NONCE,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
    .unwrap();
    (seed.to_vec(), admitted)
}

#[test]
fn a_second_factor_opens_the_same_seed_without_rederiving_anything() {
    let (seed, admitted) = open_admitted();
    assert_eq!(seed, CUSTODY_SECRET);
    assert_eq!(admitted.wallet_id(), "alice.testnet");

    let second = second_factor_envelope();
    let resealed = reseal_wallet_custody_seed_under_new_factor_v1(
        &OTHER_PRF_FIRST,
        &second,
        &admitted,
        &NONCE,
        &seed,
    )
    .unwrap();

    // Both factors now reach one seed, and each opens only its own envelope.
    assert_eq!(
        open_passkey_custody_secret_v1(&OTHER_PRF_FIRST, &second, &NONCE, &resealed.ciphertext)
            .unwrap()
            .as_slice(),
        CUSTODY_SECRET
    );
    assert!(
        open_passkey_custody_secret_v1(&PRF_FIRST, &second, &NONCE, &resealed.ciphertext).is_err(),
        "the first factor's key must not open the second factor's envelope"
    );
}

#[test]
fn a_reseal_may_change_only_the_factor_and_the_envelope_id() {
    let (seed, admitted) = open_admitted();

    let mut other_wallet = second_factor_envelope();
    other_wallet.wallet_id = "mallory.testnet".into();

    let mut other_keys = second_factor_envelope();
    other_keys.binding = ecdsa_lane_binding();

    for rejected in [other_wallet, other_keys] {
        assert!(
            reseal_wallet_custody_seed_under_new_factor_v1(
                &OTHER_PRF_FIRST,
                &rejected,
                &admitted,
                &NONCE,
                &seed
            )
            .is_err(),
            "a reseal must not change the wallet or the custody secret it carries"
        );
    }
}

#[test]
fn a_lane_share_cannot_mint_a_seed_admission() {
    let lane = envelope(ecdsa_lane_binding());
    let sealed =
        seal_passkey_custody_secret_v1(&PRF_FIRST, &lane, &NONCE, &CUSTODY_SECRET).unwrap();
    assert!(open_wallet_custody_seed_envelope_v1(
        &PRF_FIRST,
        &lane,
        &NONCE,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest
    )
    .is_err());
}

#[test]
fn a_drifted_envelope_row_mints_no_admission() {
    let first = envelope(wallet_seed_binding());
    let sealed =
        seal_wallet_custody_seed_envelope_v1(&PRF_FIRST, &first, &NONCE, &CUSTODY_SECRET).unwrap();

    // A stored digest that no longer matches the ciphertext must fail before a
    // seed — and therefore an admission — exists.
    assert!(open_wallet_custody_seed_envelope_v1(
        &PRF_FIRST,
        &first,
        &NONCE,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &[0u8; 32]
    )
    .is_err());
    assert!(open_wallet_custody_seed_envelope_v1(
        &PRF_FIRST,
        &first,
        &NONCE,
        &sealed.ciphertext,
        &[0u8; 32],
        &sealed.ciphertext_digest
    )
    .is_err());
}
