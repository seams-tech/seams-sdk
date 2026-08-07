#![cfg(feature = "passkey-custody")]

//! Owner root derivation from the wallet custody seed.
//!
//! These own the key-separation property the Email OTP defect violated: no
//! signing root may be a function of another, and the manifest check must fail
//! closed so an opened seed cannot publish a capability it does not reproduce.

use signer_core::wallet_seed_derivation::{
    compute_wallet_key_manifest_digest_v1, derive_ecdsa_client_root_share_from_seed_v1,
    derive_ed25519_yao_client_root_from_seed_v1, verify_wallet_key_manifest_v1,
    WalletKeyManifestV1,
};

const SEED: [u8; 32] = [7u8; 32];
const WALLET_ID: &str = "alice.testnet";
const APPLICATION_BINDING_DIGEST: [u8; 32] = [3u8; 32];
const SLOT_ID: &str = "wallet-key:evm-family:alice.testnet:root-1:v1";
const PATH: &str = "evm-signing";

fn ed25519_root() -> Vec<u8> {
    derive_ed25519_yao_client_root_from_seed_v1(&SEED, &APPLICATION_BINDING_DIGEST)
        .expect("ed25519 root")
        .to_vec()
}

fn ecdsa_share() -> Vec<u8> {
    derive_ecdsa_client_root_share_from_seed_v1(&SEED, WALLET_ID, SLOT_ID, PATH)
        .expect("ecdsa share")
        .to_vec()
}

fn manifest() -> WalletKeyManifestV1 {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    WalletKeyManifestV1 {
        wallet_id: WALLET_ID.into(),
        near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
        registered_public_key: [9u8; 32],
        evm_family_signing_key_slot_id: SLOT_ID.into(),
        client_root_public_key33: compressed,
    }
}

#[test]
fn roots_are_deterministic_and_domain_separated() {
    assert_eq!(ed25519_root(), ed25519_root());
    assert_eq!(ecdsa_share(), ecdsa_share());
    assert_ne!(ed25519_root(), ecdsa_share());
    assert_eq!(ed25519_root().len(), 32);
    assert_eq!(ecdsa_share().len(), 32);
}

/// The defect this scheme exists to prevent: in the retired Email OTP scheme
/// the ECDSA share was HKDF-derived from the Ed25519 root plus public context,
/// so holding that root yielded the share. Neither root may be recoverable
/// from the other under any label this scheme uses.
#[test]
fn neither_root_is_derivable_from_the_other() {
    let ed25519 = ed25519_root();
    let ecdsa = ecdsa_share();

    for salt in [
        "seams/wallet-custody/seed/ed25519-yao-client-root/v1",
        "seams/wallet-custody/seed/ecdsa-client-root-share/v1",
    ] {
        // Treat each root as if it were the seed and re-run both derivations.
        for parent in [&ed25519, &ecdsa] {
            let as_seed: [u8; 32] = parent.as_slice().try_into().unwrap();
            let chained_ed =
                derive_ed25519_yao_client_root_from_seed_v1(&as_seed, &APPLICATION_BINDING_DIGEST)
                    .unwrap();
            let chained_ecdsa =
                derive_ecdsa_client_root_share_from_seed_v1(&as_seed, WALLET_ID, SLOT_ID, PATH)
                    .unwrap();
            assert_ne!(chained_ed.to_vec(), ed25519, "salt {salt}");
            assert_ne!(chained_ed.to_vec(), ecdsa, "salt {salt}");
            assert_ne!(chained_ecdsa.to_vec(), ed25519, "salt {salt}");
            assert_ne!(chained_ecdsa.to_vec(), ecdsa, "salt {salt}");
        }
    }
}

#[test]
fn every_bound_input_changes_the_derived_root() {
    assert_ne!(
        ed25519_root(),
        derive_ed25519_yao_client_root_from_seed_v1(&[8u8; 32], &APPLICATION_BINDING_DIGEST)
            .unwrap()
            .to_vec()
    );
    // A different application binding is a different key: wallet, signing key,
    // signing root and signer slot all live inside this digest.
    assert_ne!(
        ed25519_root(),
        derive_ed25519_yao_client_root_from_seed_v1(&SEED, &[4u8; 32])
            .unwrap()
            .to_vec()
    );
    assert_ne!(
        ecdsa_share(),
        derive_ecdsa_client_root_share_from_seed_v1(
            &SEED,
            WALLET_ID,
            "wallet-key:evm-family:alice.testnet:root-2:v1",
            PATH
        )
        .unwrap()
        .to_vec()
    );
    assert_ne!(
        ecdsa_share(),
        derive_ecdsa_client_root_share_from_seed_v1(&SEED, WALLET_ID, SLOT_ID, "evm-signing/2")
            .unwrap()
            .to_vec()
    );
}

#[test]
fn malformed_derivation_inputs_are_rejected() {
    assert!(
        derive_ed25519_yao_client_root_from_seed_v1(&[0u8; 16], &APPLICATION_BINDING_DIGEST)
            .is_err()
    );
    assert!(
        derive_ecdsa_client_root_share_from_seed_v1(&[0u8; 16], WALLET_ID, SLOT_ID, PATH).is_err()
    );
    assert!(derive_ecdsa_client_root_share_from_seed_v1(&SEED, "", SLOT_ID, PATH).is_err());
    assert!(derive_ecdsa_client_root_share_from_seed_v1(&SEED, WALLET_ID, "  ", PATH).is_err());
    assert!(derive_ecdsa_client_root_share_from_seed_v1(&SEED, WALLET_ID, SLOT_ID, "").is_err());
}

#[test]
fn the_manifest_check_fails_closed_on_every_field() {
    let expected = compute_wallet_key_manifest_digest_v1(&manifest()).unwrap();
    assert!(verify_wallet_key_manifest_v1(&manifest(), &expected).is_ok());

    let mut wrong_wallet = manifest();
    wrong_wallet.wallet_id = "mallory.testnet".into();

    let mut wrong_signing_key = manifest();
    wrong_signing_key.near_ed25519_signing_key_id = "near-ed25519-key-2".into();

    let mut wrong_public_key = manifest();
    wrong_public_key.registered_public_key = [1u8; 32];

    let mut wrong_slot = manifest();
    wrong_slot.evm_family_signing_key_slot_id =
        "wallet-key:evm-family:alice.testnet:root-2:v1".into();

    let mut wrong_client_root = manifest();
    wrong_client_root.client_root_public_key33[1] ^= 0x01;

    for candidate in [
        wrong_wallet,
        wrong_signing_key,
        wrong_public_key,
        wrong_slot,
        wrong_client_root,
    ] {
        assert!(
            verify_wallet_key_manifest_v1(&candidate, &expected).is_err(),
            "a manifest differing in any bound field must not verify"
        );
    }

    // A truncated or empty expectation must not pass either.
    assert!(verify_wallet_key_manifest_v1(&manifest(), &expected[..31]).is_err());
    assert!(verify_wallet_key_manifest_v1(&manifest(), &[]).is_err());
}

#[test]
fn manifest_fields_cannot_be_shifted_across_boundaries() {
    // Length-delimited labeled fields: moving characters between adjacent
    // fields must not produce an equal digest.
    let mut left = manifest();
    left.wallet_id = "alice".into();
    left.near_ed25519_signing_key_id = "key-1".into();

    let mut right = manifest();
    right.wallet_id = "alicekey".into();
    right.near_ed25519_signing_key_id = "-1".into();

    assert_ne!(
        compute_wallet_key_manifest_digest_v1(&left).unwrap(),
        compute_wallet_key_manifest_digest_v1(&right).unwrap()
    );
}

#[test]
fn a_manifest_with_a_non_compressed_client_root_is_rejected() {
    let mut uncompressed = manifest();
    uncompressed.client_root_public_key33[0] = 0x04;
    assert!(compute_wallet_key_manifest_digest_v1(&uncompressed).is_err());
}
