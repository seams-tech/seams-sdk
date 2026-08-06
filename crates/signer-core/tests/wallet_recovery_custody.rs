#![cfg(feature = "passkey-custody")]

//! Boundary tests for the two-level wallet recovery wrap.
//!
//! These own the invariants that make manifest-KEK wrapping safe: every code
//! opens the same set, per-entry AAD survives the shared manifest KEK, rotating
//! codes leaves entry ciphertexts untouched, and a wrap cannot be moved onto a
//! different wallet, code, key manifest, or entry.

use signer_core::passkey_custody::{PasskeyCustodyLaneScopeV1, PasskeyCustodySecretKind};
use signer_core::wallet_recovery_custody::{
    derive_wallet_recovery_entry_kek_v1, encode_recovery_entry_aad_v1,
    open_wallet_recovery_entry_v1, open_wallet_recovery_manifest_kek_v1,
    seal_wallet_recovery_entry_v1, seal_wallet_recovery_manifest_kek_v1, WalletRecoveryCodeScopeV1,
    WalletRecoveryEntryScopeV1, WALLET_RECOVERY_CODE_COUNT,
};

const MANIFEST_KEK: [u8; 32] = [11u8; 32];
const NONCE: [u8; 12] = [5u8; 12];
const ED25519_SECRET: [u8; 32] = [21u8; 32];
const ECDSA_SECRET: [u8; 32] = [22u8; 32];
const KEY_MANIFEST_DIGEST: [u8; 32] = [77u8; 32];

fn recovery_code(index: usize) -> Vec<u8> {
    vec![index as u8 + 1; 20]
}

fn code_scope(index: usize) -> WalletRecoveryCodeScopeV1 {
    WalletRecoveryCodeScopeV1 {
        wallet_id: "alice.testnet".into(),
        recovery_key_id: format!("email-otp-rkid-v1-code-{index}"),
        key_manifest_digest: KEY_MANIFEST_DIGEST,
    }
}

fn ed25519_entry_scope() -> WalletRecoveryEntryScopeV1 {
    WalletRecoveryEntryScopeV1 {
        wallet_id: "alice.testnet".into(),
        lane: PasskeyCustodyLaneScopeV1 {
            wallet_key_id: "wallet-key:ed25519:alice.testnet:root-1:v1".into(),
            lane_id: "lane:owner:ed25519:1".into(),
            lane_share_epoch: "lane-share-epoch-1".into(),
        },
        custody_secret_kind: PasskeyCustodySecretKind::Ed25519YaoClientRoot,
        key_manifest_digest: KEY_MANIFEST_DIGEST,
    }
}

fn ecdsa_entry_scope() -> WalletRecoveryEntryScopeV1 {
    WalletRecoveryEntryScopeV1 {
        wallet_id: "alice.testnet".into(),
        lane: PasskeyCustodyLaneScopeV1 {
            wallet_key_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
            lane_id: "lane:owner:evm-family:1".into(),
            lane_share_epoch: "lane-share-epoch-1".into(),
        },
        custody_secret_kind: PasskeyCustodySecretKind::EcdsaClientRootShare,
        key_manifest_digest: KEY_MANIFEST_DIGEST,
    }
}

#[test]
fn any_of_the_ten_codes_opens_the_same_manifest_kek() {
    let wraps: Vec<_> = (0..WALLET_RECOVERY_CODE_COUNT)
        .map(|index| {
            let mut nonce = NONCE;
            nonce[0] = index as u8;
            (
                index,
                nonce,
                seal_wallet_recovery_manifest_kek_v1(
                    &recovery_code(index),
                    &code_scope(index),
                    &nonce,
                    &MANIFEST_KEK,
                )
                .unwrap(),
            )
        })
        .collect();

    for (index, nonce, wrap) in &wraps {
        let opened = open_wallet_recovery_manifest_kek_v1(
            &recovery_code(*index),
            &code_scope(*index),
            nonce,
            &wrap.ciphertext,
        )
        .unwrap();
        assert_eq!(opened.as_slice(), MANIFEST_KEK);
    }
}

#[test]
fn a_recovery_code_opens_every_entry_in_the_mixed_wallet_set() {
    let wrap = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        &code_scope(0),
        &NONCE,
        &MANIFEST_KEK,
    )
    .unwrap();

    let ed25519 = seal_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ed25519_entry_scope(),
        &NONCE,
        &ED25519_SECRET,
    )
    .unwrap();
    let ecdsa =
        seal_wallet_recovery_entry_v1(&MANIFEST_KEK, &ecdsa_entry_scope(), &NONCE, &ECDSA_SECRET)
            .unwrap();

    let manifest_kek = open_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        &code_scope(0),
        &NONCE,
        &wrap.ciphertext,
    )
    .unwrap();

    assert_eq!(
        open_wallet_recovery_entry_v1(
            &manifest_kek[..],
            &ed25519_entry_scope(),
            &NONCE,
            &ed25519.ciphertext
        )
        .unwrap()
        .as_slice(),
        ED25519_SECRET
    );
    assert_eq!(
        open_wallet_recovery_entry_v1(
            &manifest_kek[..],
            &ecdsa_entry_scope(),
            &NONCE,
            &ecdsa.ciphertext
        )
        .unwrap()
        .as_slice(),
        ECDSA_SECRET
    );
}

#[test]
fn per_entry_aad_survives_the_shared_manifest_kek() {
    let ed25519 = seal_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ed25519_entry_scope(),
        &NONCE,
        &ED25519_SECRET,
    )
    .unwrap();

    // The Ed25519 entry ciphertext must not open under the ECDSA entry scope,
    // even though both entries share one manifest KEK.
    assert!(open_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ecdsa_entry_scope(),
        &NONCE,
        &ed25519.ciphertext
    )
    .is_err());

    let ed25519_kek =
        derive_wallet_recovery_entry_kek_v1(&MANIFEST_KEK, &ed25519_entry_scope()).unwrap();
    let ecdsa_kek =
        derive_wallet_recovery_entry_kek_v1(&MANIFEST_KEK, &ecdsa_entry_scope()).unwrap();
    assert_ne!(ed25519_kek.as_slice(), ecdsa_kek.as_slice());
}

#[test]
fn substituting_entry_scope_fields_prevents_opening() {
    let sealed = seal_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ed25519_entry_scope(),
        &NONCE,
        &ED25519_SECRET,
    )
    .unwrap();

    let mut wrong_wallet = ed25519_entry_scope();
    wrong_wallet.wallet_id = "mallory.testnet".into();

    let mut wrong_lane = ed25519_entry_scope();
    wrong_lane.lane.lane_id = "lane:linked-device:ed25519:2".into();

    let mut wrong_epoch = ed25519_entry_scope();
    wrong_epoch.lane.lane_share_epoch = "lane-share-epoch-2".into();

    let mut wrong_kind = ed25519_entry_scope();
    wrong_kind.custody_secret_kind = PasskeyCustodySecretKind::Ed25519LaneHolderShare;

    let mut wrong_manifest = ed25519_entry_scope();
    wrong_manifest.key_manifest_digest = [0u8; 32];

    for scope in [
        wrong_wallet,
        wrong_lane,
        wrong_epoch,
        wrong_kind,
        wrong_manifest,
    ] {
        assert!(
            open_wallet_recovery_entry_v1(&MANIFEST_KEK, &scope, &NONCE, &sealed.ciphertext)
                .is_err(),
            "a substituted entry scope must not open the wrap"
        );
    }
}

#[test]
fn substituting_code_scope_fields_prevents_opening() {
    let wrap = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        &code_scope(0),
        &NONCE,
        &MANIFEST_KEK,
    )
    .unwrap();

    // A different code cannot open another code's wrap.
    assert!(open_wallet_recovery_manifest_kek_v1(
        &recovery_code(1),
        &code_scope(0),
        &NONCE,
        &wrap.ciphertext
    )
    .is_err());

    let mut wrong_wallet = code_scope(0);
    wrong_wallet.wallet_id = "mallory.testnet".into();

    let mut wrong_key_id = code_scope(0);
    wrong_key_id.recovery_key_id = "email-otp-rkid-v1-code-9".into();

    let mut wrong_manifest = code_scope(0);
    wrong_manifest.key_manifest_digest = [0u8; 32];

    for scope in [wrong_wallet, wrong_key_id, wrong_manifest] {
        assert!(
            open_wallet_recovery_manifest_kek_v1(
                &recovery_code(0),
                &scope,
                &NONCE,
                &wrap.ciphertext
            )
            .is_err(),
            "a substituted code scope must not open the manifest KEK"
        );
    }
}

#[test]
fn rotating_codes_leaves_entry_ciphertexts_untouched() {
    let entry = seal_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ed25519_entry_scope(),
        &NONCE,
        &ED25519_SECRET,
    )
    .unwrap();
    let original = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        &code_scope(0),
        &NONCE,
        &MANIFEST_KEK,
    )
    .unwrap();

    // Rotation rewraps the same manifest KEK under fresh codes. No custody
    // secret is opened, so the entry ciphertext is byte-identical afterwards.
    let rotated = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(5),
        &code_scope(5),
        &NONCE,
        &MANIFEST_KEK,
    )
    .unwrap();
    assert_ne!(original.ciphertext, rotated.ciphertext);

    let manifest_kek = open_wallet_recovery_manifest_kek_v1(
        &recovery_code(5),
        &code_scope(5),
        &NONCE,
        &rotated.ciphertext,
    )
    .unwrap();
    assert_eq!(
        open_wallet_recovery_entry_v1(
            &manifest_kek[..],
            &ed25519_entry_scope(),
            &NONCE,
            &entry.ciphertext
        )
        .unwrap()
        .as_slice(),
        ED25519_SECRET
    );
}

#[test]
fn tampered_recovery_ciphertext_fails_to_open() {
    let sealed = seal_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ed25519_entry_scope(),
        &NONCE,
        &ED25519_SECRET,
    )
    .unwrap();

    for index in [0usize, 4, sealed.ciphertext.len() - 1] {
        let mut tampered = sealed.ciphertext.clone();
        tampered[index] ^= 0x01;
        assert!(open_wallet_recovery_entry_v1(
            &MANIFEST_KEK,
            &ed25519_entry_scope(),
            &NONCE,
            &tampered
        )
        .is_err());
    }

    let truncated = &sealed.ciphertext[..sealed.ciphertext.len() - 1];
    assert!(open_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ed25519_entry_scope(),
        &NONCE,
        truncated
    )
    .is_err());
}

#[test]
fn malformed_recovery_inputs_are_rejected() {
    assert!(seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        &code_scope(0),
        &NONCE,
        &[0u8; 16]
    )
    .is_err());
    assert!(
        seal_wallet_recovery_manifest_kek_v1(&[], &code_scope(0), &NONCE, &MANIFEST_KEK).is_err()
    );
    assert!(seal_wallet_recovery_entry_v1(
        &[0u8; 16],
        &ed25519_entry_scope(),
        &NONCE,
        &ED25519_SECRET
    )
    .is_err());
    assert!(seal_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &ed25519_entry_scope(),
        &[0u8; 24],
        &ED25519_SECRET
    )
    .is_err());
    assert!(
        seal_wallet_recovery_entry_v1(&MANIFEST_KEK, &ed25519_entry_scope(), &NONCE, &[]).is_err()
    );

    let mut empty_wallet = ed25519_entry_scope();
    empty_wallet.wallet_id = String::new();
    assert!(encode_recovery_entry_aad_v1(&empty_wallet).is_err());
}
