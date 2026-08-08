#![cfg(feature = "passkey-custody")]

//! Owner root derivation from the wallet custody seed.
//!
//! These own the key-separation property the Email OTP defect violated: no
//! signing root may be a function of another, and the manifest check must fail
//! closed so an opened seed cannot publish a capability it does not reproduce.

use signer_core::wallet_seed_derivation::{
    compute_wallet_key_set_manifest_digest_v1, derive_ecdsa_client_root_share_from_seed_v1,
    derive_ed25519_local_material_cache_key_from_seed_v1,
    derive_ed25519_yao_client_root_from_seed_v1, derive_wallet_seed_owner_roots_v1,
    establish_wallet_key_set_manifest_v1, verify_registered_wallet_key_set_manifest_v1,
    verify_wallet_key_set_manifest_v1, wallet_key_manifest_digest_b64u, WalletKeySetKindV1,
    WalletKeySetManifestV1,
};

const SEED: [u8; 32] = [7u8; 32];
const WALLET_ID: &str = "alice.testnet";
const APPLICATION_BINDING_DIGEST: [u8; 32] = [3u8; 32];
const SLOT_ID: &str = "wallet-key:evm-family:alice.testnet:root-1:v1";
const ECDSA_BINDING_DIGEST: [u8; 32] = [5u8; 32];

fn ed25519_root() -> Vec<u8> {
    derive_ed25519_yao_client_root_from_seed_v1(&SEED, &APPLICATION_BINDING_DIGEST)
        .expect("ed25519 root")
        .to_vec()
}

fn ecdsa_share() -> Vec<u8> {
    derive_ecdsa_client_root_share_from_seed_v1(&SEED, &ECDSA_BINDING_DIGEST)
        .expect("ecdsa share")
        .to_vec()
}

fn local_material_cache_key() -> Vec<u8> {
    derive_ed25519_local_material_cache_key_from_seed_v1(&SEED, &APPLICATION_BINDING_DIGEST)
        .expect("cache key")
        .to_vec()
}

fn manifest() -> WalletKeySetManifestV1 {
    WalletKeySetManifestV1::NearEd25519 {
        wallet_id: WALLET_ID.into(),
        near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
        registered_public_key: [9u8; 32],
    }
}

fn evm_manifest() -> WalletKeySetManifestV1 {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    WalletKeySetManifestV1::EvmFamilyEcdsa {
        wallet_id: WALLET_ID.into(),
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
                derive_ecdsa_client_root_share_from_seed_v1(&as_seed, &ECDSA_BINDING_DIGEST)
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
        derive_ecdsa_client_root_share_from_seed_v1(&SEED, &[6u8; 32])
            .unwrap()
            .to_vec()
    );
    // The two curves share a seed; an identical binding digest must still not
    // collapse them onto one secret, because their salts differ.
    assert_ne!(
        derive_ed25519_yao_client_root_from_seed_v1(&SEED, &ECDSA_BINDING_DIGEST)
            .unwrap()
            .to_vec(),
        ecdsa_share()
    );
}

#[test]
fn malformed_derivation_inputs_are_rejected() {
    assert!(
        derive_ed25519_yao_client_root_from_seed_v1(&[0u8; 16], &APPLICATION_BINDING_DIGEST)
            .is_err()
    );
    assert!(
        derive_ecdsa_client_root_share_from_seed_v1(&[0u8; 16], &ECDSA_BINDING_DIGEST).is_err()
    );
}

#[test]
fn the_manifest_check_fails_closed_on_every_field() {
    let expected = compute_wallet_key_set_manifest_digest_v1(&manifest()).unwrap();
    assert!(verify_wallet_key_set_manifest_v1(&manifest(), &expected).is_ok());

    let candidates = [
        WalletKeySetManifestV1::NearEd25519 {
            wallet_id: "mallory.testnet".into(),
            near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
            registered_public_key: [9u8; 32],
        },
        WalletKeySetManifestV1::NearEd25519 {
            wallet_id: WALLET_ID.into(),
            near_ed25519_signing_key_id: "near-ed25519-key-2".into(),
            registered_public_key: [9u8; 32],
        },
        WalletKeySetManifestV1::NearEd25519 {
            wallet_id: WALLET_ID.into(),
            near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
            registered_public_key: [1u8; 32],
        },
        // The other key set never satisfies this one's digest: the two encode
        // under different contexts.
        evm_manifest(),
    ];
    for candidate in candidates {
        assert!(
            verify_wallet_key_set_manifest_v1(&candidate, &expected).is_err(),
            "a manifest differing in any bound field must not verify"
        );
    }

    // A truncated or empty expectation must not pass either.
    assert!(verify_wallet_key_set_manifest_v1(&manifest(), &expected[..31]).is_err());
    assert!(verify_wallet_key_set_manifest_v1(&manifest(), &[]).is_err());

    // And the EVM key set verifies against its own digest, independently.
    let evm_expected = compute_wallet_key_set_manifest_digest_v1(&evm_manifest()).unwrap();
    assert!(verify_wallet_key_set_manifest_v1(&evm_manifest(), &evm_expected).is_ok());
    assert_ne!(expected, evm_expected);
}

#[test]
fn manifest_fields_cannot_be_shifted_across_boundaries() {
    // Length-delimited labeled fields: moving characters between adjacent
    // fields must not produce an equal digest.
    let left = WalletKeySetManifestV1::NearEd25519 {
        wallet_id: "alice".into(),
        near_ed25519_signing_key_id: "key-1".into(),
        registered_public_key: [9u8; 32],
    };
    let right = WalletKeySetManifestV1::NearEd25519 {
        wallet_id: "alicekey".into(),
        near_ed25519_signing_key_id: "-1".into(),
        registered_public_key: [9u8; 32],
    };
    assert_ne!(
        compute_wallet_key_set_manifest_digest_v1(&left).unwrap(),
        compute_wallet_key_set_manifest_digest_v1(&right).unwrap()
    );
}

#[test]
fn a_manifest_with_a_non_compressed_client_root_is_rejected() {
    let uncompressed = WalletKeySetManifestV1::EvmFamilyEcdsa {
        wallet_id: WALLET_ID.into(),
        evm_family_signing_key_slot_id: SLOT_ID.into(),
        client_root_public_key33: [0x04; 33],
    };
    assert!(compute_wallet_key_set_manifest_digest_v1(&uncompressed).is_err());
}

#[cfg(feature = "ecdsa-role-local-client")]
mod ecdsa_bootstrap_integration {
    use super::*;
    use router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext;
    use signer_core::ecdsa_role_local_client::command::{
        prepare_ecdsa_client_bootstrap, PrepareEcdsaClientBootstrapCommand,
    };

    fn bootstrap_with(seed: [u8; 32], digest: [u8; 32]) -> [u8; 33] {
        let share = derive_ecdsa_client_root_share_from_seed_v1(&seed, &digest)
            .expect("seed-derived client root share");
        let output = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
            context: RouterAbEcdsaDerivationStableKeyContext::new(digest),
            client_root_share32: *share,
        })
        .expect("ecdsa client bootstrap");
        output.client_bootstrap.derivation_client_share_public_key33
    }

    /// The seam already accepts a root share, so the seed path needed no new
    /// entry point — but it still has to produce a usable share end to end.
    #[test]
    fn a_seed_derived_share_bootstraps_a_stable_client_public_key() {
        let first = bootstrap_with(SEED, ECDSA_BINDING_DIGEST);
        let again = bootstrap_with(SEED, ECDSA_BINDING_DIGEST);
        assert_eq!(first, again);
        assert!(first[0] == 0x02 || first[0] == 0x03);
    }

    #[test]
    fn a_different_seed_or_binding_bootstraps_a_different_public_key() {
        let baseline = bootstrap_with(SEED, ECDSA_BINDING_DIGEST);
        assert_ne!(baseline, bootstrap_with([9u8; 32], ECDSA_BINDING_DIGEST));
        assert_ne!(baseline, bootstrap_with(SEED, [6u8; 32]));
    }
}

#[test]
fn paired_derivation_produces_both_owner_roots_from_one_seed() {
    let roots = derive_wallet_seed_owner_roots_v1(
        &SEED,
        &APPLICATION_BINDING_DIGEST,
        &ECDSA_BINDING_DIGEST,
    )
    .expect("owner roots");
    assert_eq!(roots.ed25519_yao_client_root().to_vec(), ed25519_root());
    assert_eq!(roots.ecdsa_client_root_share().to_vec(), ecdsa_share());
    assert_ne!(
        roots.ed25519_yao_client_root(),
        roots.ecdsa_client_root_share()
    );
}

#[test]
fn paired_derivation_rejects_a_shared_binding_digest() {
    // Equal digests mean at least one was not the protocol's own, which is the
    // divergence this signature exists to prevent.
    assert!(derive_wallet_seed_owner_roots_v1(
        &SEED,
        &APPLICATION_BINDING_DIGEST,
        &APPLICATION_BINDING_DIGEST
    )
    .is_err());
    assert!(derive_wallet_seed_owner_roots_v1(
        &[0u8; 16],
        &APPLICATION_BINDING_DIGEST,
        &ECDSA_BINDING_DIGEST
    )
    .is_err());
}

#[test]
fn the_registration_gate_returns_a_proof_only_when_the_manifest_matches() {
    let expected = compute_wallet_key_set_manifest_digest_v1(&manifest()).unwrap();
    let verified = verify_registered_wallet_key_set_manifest_v1(&manifest(), &expected).unwrap();
    assert_eq!(verified.digest(), &expected);
    assert_eq!(verified.key_set(), WalletKeySetKindV1::NearEd25519);
    assert_eq!(
        verified.digest_b64u(),
        wallet_key_manifest_digest_b64u(&expected)
    );

    // No proof for a key set the seed does not reproduce, so a caller cannot
    // reach a record writer by ignoring the error.
    let drifted = WalletKeySetManifestV1::NearEd25519 {
        wallet_id: WALLET_ID.into(),
        near_ed25519_signing_key_id: "near-ed25519-key-1".into(),
        registered_public_key: [1u8; 32],
    };
    assert!(verify_registered_wallet_key_set_manifest_v1(&drifted, &expected).is_err());
}

#[test]
fn establishing_and_verifying_are_separate_paths_to_the_same_proof() {
    // Provisioning mints the digest; there is no prior record to reproduce.
    let established = establish_wallet_key_set_manifest_v1(&evm_manifest()).unwrap();
    let expected = compute_wallet_key_set_manifest_digest_v1(&evm_manifest()).unwrap();
    assert_eq!(established.digest(), &expected);
    assert_eq!(established.key_set(), WalletKeySetKindV1::EvmFamilyEcdsa);

    // Recovery must reproduce an existing one, so it compares and can fail.
    let drifted = WalletKeySetManifestV1::EvmFamilyEcdsa {
        wallet_id: WALLET_ID.into(),
        evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-2:v1".into(),
        client_root_public_key33: {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed
        },
    };
    assert!(verify_registered_wallet_key_set_manifest_v1(&drifted, &expected).is_err());

    // The establishing constructor still refuses a malformed manifest.
    let uncompressed = WalletKeySetManifestV1::EvmFamilyEcdsa {
        wallet_id: WALLET_ID.into(),
        evm_family_signing_key_slot_id: SLOT_ID.into(),
        client_root_public_key33: [0x04; 33],
    };
    assert!(establish_wallet_key_set_manifest_v1(&uncompressed).is_err());
}

/// The continuity cache key is a third domain, not a reuse of either root.
///
/// It wraps a local record that re-opens material the protocol already
/// activated; it must never be usable as, or derivable from, key material a
/// protocol signs with. Sharing bytes with either root would mean a stolen
/// cache key yields signing capability, which is the whole reason it gets its
/// own salt.
#[test]
fn the_local_material_cache_key_is_neither_signing_root() {
    let cache_key = local_material_cache_key();

    assert_eq!(cache_key, local_material_cache_key());
    assert_eq!(cache_key.len(), 32);
    // Same seed, same binding digest as the Ed25519 root: only the salt differs,
    // so this is the comparison that proves the salt is load-bearing.
    assert_ne!(cache_key, ed25519_root());
    assert_ne!(cache_key, ecdsa_share());
    assert_ne!(cache_key, SEED.to_vec());
}

/// One key set's cache key cannot open another's record.
#[test]
fn the_cache_key_is_bound_to_its_key_set() {
    let other = derive_ed25519_local_material_cache_key_from_seed_v1(&SEED, &[4u8; 32])
        .expect("cache key")
        .to_vec();
    assert_ne!(local_material_cache_key(), other);
}

/// A different seed is a different cache, so a wallet cannot open another's.
#[test]
fn the_cache_key_follows_the_seed() {
    let other = derive_ed25519_local_material_cache_key_from_seed_v1(
        &[8u8; 32],
        &APPLICATION_BINDING_DIGEST,
    )
    .expect("cache key")
    .to_vec();
    assert_ne!(local_material_cache_key(), other);
}

#[test]
fn the_cache_key_rejects_a_seed_of_the_wrong_length() {
    assert!(derive_ed25519_local_material_cache_key_from_seed_v1(
        &[7u8; 31],
        &APPLICATION_BINDING_DIGEST
    )
    .is_err());
}
