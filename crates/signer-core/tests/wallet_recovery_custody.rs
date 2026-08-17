#![cfg(feature = "passkey-custody")]

//! Boundary tests for the two-level wallet recovery wrap.
//!
//! These own the invariants that make manifest-KEK wrapping safe: every code
//! opens the same set, per-entry AAD survives the shared manifest KEK, rotating
//! codes leaves entry ciphertexts untouched, and a wrap cannot be moved onto a
//! different wallet, code, or key manifest.
//!
//! Sealing here always starts from a verified manifest, because that is the
//! only way to obtain the proof the sealing functions require. Two wallets
//! stand in for "a different key manifest": each has its own verified proof, so
//! a cross-wallet substitution is a substitution of real verified scopes rather
//! than of hand-written digests.

use signer_core::wallet_recovery_custody::{
    derive_wallet_recovery_entry_kek_v1, encode_recovery_entry_aad_v1,
    open_wallet_recovery_entry_v1, open_wallet_recovery_manifest_kek_v1,
    seal_wallet_recovery_entry_v1, seal_wallet_recovery_manifest_kek_v1, WalletRecoveryCodeScopeV1,
    WalletRecoveryEntryScopeV1, WALLET_RECOVERY_CODE_COUNT,
};

const MANIFEST_KEK: [u8; 32] = [11u8; 32];
const NONCE: [u8; 12] = [5u8; 12];
const ALICE_SEED: [u8; 32] = [21u8; 32];
const BOB_SEED: [u8; 32] = [22u8; 32];
const ALICE: &str = "alice.testnet";
const BOB: &str = "bob.testnet";

fn recovery_code(index: usize) -> Vec<u8> {
    vec![index as u8 + 1; 20]
}

fn recovery_key_id(index: usize) -> String {
    format!("wallet-rkid-v1-code-{index}")
}

/// The scope an open reconstructs from the stored record. Opening takes a scope
/// directly: recovery must open the seed before it can derive anything to
/// verify against.
fn code_scope(index: usize) -> WalletRecoveryCodeScopeV1 {
    WalletRecoveryCodeScopeV1 {
        wallet_id: ALICE.into(),
        recovery_key_id: recovery_key_id(index),
    }
}

/// The one entry a recovery set carries: the wallet-scoped owner seed.
fn alice_entry_scope() -> WalletRecoveryEntryScopeV1 {
    WalletRecoveryEntryScopeV1 {
        wallet_id: ALICE.into(),
    }
}

/// A second wallet's entry, used to prove wallet and manifest binding.
fn bob_entry_scope() -> WalletRecoveryEntryScopeV1 {
    WalletRecoveryEntryScopeV1 {
        wallet_id: BOB.into(),
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
                    ALICE,
                    &recovery_key_id(index),
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
fn a_recovery_code_opens_the_seed_entry_its_manifest_kek_covers() {
    let wrap = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        ALICE,
        &recovery_key_id(0),
        &NONCE,
        &MANIFEST_KEK,
    )
    .unwrap();

    let alice_entry =
        seal_wallet_recovery_entry_v1(&MANIFEST_KEK, ALICE, &NONCE, &ALICE_SEED).unwrap();
    let bob_entry = seal_wallet_recovery_entry_v1(&MANIFEST_KEK, BOB, &NONCE, &BOB_SEED).unwrap();

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
            &alice_entry_scope(),
            &NONCE,
            &alice_entry.ciphertext
        )
        .unwrap()
        .as_slice(),
        ALICE_SEED
    );
    assert_eq!(
        open_wallet_recovery_entry_v1(
            &manifest_kek[..],
            &bob_entry_scope(),
            &NONCE,
            &bob_entry.ciphertext
        )
        .unwrap()
        .as_slice(),
        BOB_SEED
    );
}

#[test]
fn per_entry_aad_survives_the_shared_manifest_kek() {
    let alice_entry =
        seal_wallet_recovery_entry_v1(&MANIFEST_KEK, ALICE, &NONCE, &ALICE_SEED).unwrap();

    // One wallet's entry ciphertext must not open under another's entry scope,
    // even though both entries share one manifest KEK.
    assert!(open_wallet_recovery_entry_v1(
        &MANIFEST_KEK,
        &bob_entry_scope(),
        &NONCE,
        &alice_entry.ciphertext
    )
    .is_err());

    let alice_kek =
        derive_wallet_recovery_entry_kek_v1(&MANIFEST_KEK, &alice_entry_scope()).unwrap();
    let bob_kek = derive_wallet_recovery_entry_kek_v1(&MANIFEST_KEK, &bob_entry_scope()).unwrap();
    assert_ne!(alice_kek.as_slice(), bob_kek.as_slice());
}

#[test]
fn substituting_entry_scope_fields_prevents_opening() {
    let sealed = seal_wallet_recovery_entry_v1(&MANIFEST_KEK, ALICE, &NONCE, &ALICE_SEED).unwrap();

    let mut wrong_wallet = alice_entry_scope();
    wrong_wallet.wallet_id = "mallory.testnet".into();

    // Wallet id is the entry scope now, so it is the one substitution left.
    assert!(
        open_wallet_recovery_entry_v1(&MANIFEST_KEK, &wrong_wallet, &NONCE, &sealed.ciphertext)
            .is_err(),
        "a substituted entry scope must not open the wrap"
    );
}

#[test]
fn substituting_code_scope_fields_prevents_opening() {
    let wrap = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        ALICE,
        &recovery_key_id(0),
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
    wrong_key_id.recovery_key_id = recovery_key_id(9);

    for scope in [wrong_wallet, wrong_key_id] {
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
    let entry = seal_wallet_recovery_entry_v1(&MANIFEST_KEK, ALICE, &NONCE, &ALICE_SEED).unwrap();
    let original = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        ALICE,
        &recovery_key_id(0),
        &NONCE,
        &MANIFEST_KEK,
    )
    .unwrap();

    // Rotation rewraps the same manifest KEK under fresh codes. No custody
    // secret is opened, so the entry ciphertext is byte-identical afterwards.
    let rotated = seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(5),
        ALICE,
        &recovery_key_id(5),
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
            &alice_entry_scope(),
            &NONCE,
            &entry.ciphertext
        )
        .unwrap()
        .as_slice(),
        ALICE_SEED
    );
}

#[test]
fn tampered_recovery_ciphertext_fails_to_open() {
    let sealed = seal_wallet_recovery_entry_v1(&MANIFEST_KEK, ALICE, &NONCE, &ALICE_SEED).unwrap();

    for index in [0usize, 4, sealed.ciphertext.len() - 1] {
        let mut tampered = sealed.ciphertext.clone();
        tampered[index] ^= 0x01;
        assert!(open_wallet_recovery_entry_v1(
            &MANIFEST_KEK,
            &alice_entry_scope(),
            &NONCE,
            &tampered
        )
        .is_err());
    }

    let truncated = &sealed.ciphertext[..sealed.ciphertext.len() - 1];
    assert!(
        open_wallet_recovery_entry_v1(&MANIFEST_KEK, &alice_entry_scope(), &NONCE, truncated)
            .is_err()
    );
}

#[test]
fn malformed_recovery_inputs_are_rejected() {
    assert!(seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        ALICE,
        &recovery_key_id(0),
        &NONCE,
        &[0u8; 16]
    )
    .is_err());
    assert!(seal_wallet_recovery_manifest_kek_v1(
        &[],
        ALICE,
        &recovery_key_id(0),
        &NONCE,
        &MANIFEST_KEK
    )
    .is_err());
    // An empty wallet id or recovery key id fails inside the AAD encoder, so a
    // scope built from a proof is still checked for well-formedness.
    assert!(seal_wallet_recovery_manifest_kek_v1(
        &recovery_code(0),
        "",
        &recovery_key_id(0),
        &NONCE,
        &MANIFEST_KEK
    )
    .is_err());
    assert!(seal_wallet_recovery_entry_v1(&[0u8; 16], ALICE, &NONCE, &ALICE_SEED).is_err());
    assert!(seal_wallet_recovery_entry_v1(&MANIFEST_KEK, ALICE, &[0u8; 24], &ALICE_SEED).is_err());
    assert!(seal_wallet_recovery_entry_v1(&MANIFEST_KEK, ALICE, &NONCE, &[]).is_err());

    let mut empty_wallet = alice_entry_scope();
    empty_wallet.wallet_id = String::new();
    assert!(encode_recovery_entry_aad_v1(&empty_wallet).is_err());

    // Two wallets' seed entries never encode alike, and neither is a prefix
    // of the other.
    let one = encode_recovery_entry_aad_v1(&alice_entry_scope()).unwrap();
    let other = encode_recovery_entry_aad_v1(&bob_entry_scope()).unwrap();
    assert_ne!(one, other);
    assert!(!other.starts_with(&one));
    assert!(!one.starts_with(&other));
}
