#![cfg(all(feature = "ecdsa-role-local-client", feature = "passkey-custody"))]

//! Does a seed-derived EVM key set actually register?
//!
//! Refactor 100 replaces the strict Router A/B derivation rounds for the
//! EVM-family key set: instead of the client receiving `xClientBase` from the
//! two Derivers, it derives its own root share from the wallet custody seed.
//! Everything downstream of that substitution is plumbing — but only if the two
//! sides still agree on a threshold key.
//!
//! These prove the agreement in-process, with no relayer and no Router. The
//! server half is the real production function the SigningWorker uses
//! (`derive_relayer_share_for_client_public`, reached in the Worker through
//! `cloudflare_router_ab_ecdsa_derivation_public_identity_from_material_parts_v1`),
//! and the client half is the real `prepare`/`finalize` bootstrap pair the
//! custody ceremony calls. Nothing here is a stub.
//!
//! What makes this worth having before the wire work: it is the one property
//! that, if false, makes the entire seed-root EVM path unbuildable. The
//! composition is a pure function of the stable key context, the SigningWorker's
//! own output material, and the client's public key — it consumes nothing the
//! Deriver rounds produce, which is exactly why the rounds can be dropped.

use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_ecdsa_derivation::{
    derive_relayer_share_for_client_public, RouterAbEcdsaDerivationStableKeyContext,
};
use signer_core::ecdsa_role_local_client::command::{
    finalize_ecdsa_client_bootstrap, prepare_ecdsa_client_bootstrap,
    FinalizeEcdsaClientBootstrapCommand, PrepareEcdsaClientBootstrapCommand,
    RelayerPublicIdentityInput,
};
use signer_core::wallet_seed_derivation::derive_ecdsa_client_root_share_from_seed_v1;

/// The ECDSA application binding digest. In production it comes from the
/// registration facts and is computed locally before any network leg.
const APPLICATION_BINDING_DIGEST: [u8; 32] = [0x41; 32];
/// The SigningWorker's own output material — its `y_relayer32`. Server-side
/// this is the sealed per-wallet material record, never the client's business.
const SIGNING_WORKER_MATERIAL: [u8; 32] = [0x9c; 32];
const RELAYER_KEY_ID: &str = "relayer-key-1";

fn context() -> RouterAbEcdsaDerivationStableKeyContext {
    RouterAbEcdsaDerivationStableKeyContext::new(APPLICATION_BINDING_DIGEST)
}

fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// One whole seed-root registration: the client derives from the seed, the
/// server answers from its own material, the client finalizes.
struct SeedRootRegistration {
    client_share_public_key33: [u8; 33],
    threshold_public_key33: [u8; 33],
    ethereum_address20: [u8; 20],
    /// What the client itself computed at finalize, independently of the
    /// server's claim.
    client_finalized_threshold_public_key33: [u8; 33],
    client_finalized_ethereum_address20: [u8; 20],
    ready_state_blob: Vec<u8>,
}

fn register_from_seed(seed: &[u8; 32], signing_worker_material: [u8; 32]) -> SeedRootRegistration {
    // Client: seed -> HKDF -> root share -> bootstrap prepare. This is the
    // substitution the refactor makes; in the strict path `client_root_share32`
    // was `xClientBase` from the Deriver rounds instead.
    let root_share = derive_ecdsa_client_root_share_from_seed_v1(seed, &APPLICATION_BINDING_DIGEST)
        .expect("seed-derived ECDSA client root share");
    let prepared = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
        context: context(),
        client_root_share32: *root_share,
    })
    .expect("client bootstrap prepare");
    let client_share_public_key33 = prepared.public_facts.derivation_client_share_public_key33;

    // Server: the SigningWorker derives its relayer share against the client's
    // public key and composes the identity. No Deriver round contributes here.
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &context(),
        signing_worker_material,
        &client_share_public_key33,
        prepared.public_facts.client_share_retry_counter,
    )
    .expect("relayer share for the client public key");

    // Client: finalize against what the server returned. This re-composes the
    // identity locally and refuses a group key that is not the sum of the two
    // shares, so a passing finalize is the client's own agreement, not trust.
    let finalized = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
        pending_state_blob: prepared.pending_state_blob.clone(),
        relayer_public_identity: RelayerPublicIdentityInput {
            relayer_key_id: RELAYER_KEY_ID.to_string(),
            relayer_public_key33: identity.relayer_public_key33,
            group_public_key33: identity.threshold_public_key33,
            ethereum_address20: identity.threshold_ethereum_address20,
            relayer_share_retry_counter: identity.relayer_share_retry_counter,
        },
    })
    .expect("client bootstrap finalize");

    SeedRootRegistration {
        client_share_public_key33,
        threshold_public_key33: identity.threshold_public_key33,
        ethereum_address20: identity.threshold_ethereum_address20,
        client_finalized_threshold_public_key33: finalized.public_facts.group_public_key33,
        client_finalized_ethereum_address20: finalized.public_facts.ethereum_address20,
        ready_state_blob: finalized.ready_state_blob.state_blob.clone(),
    }
}

#[test]
fn a_seed_derived_client_share_and_the_signing_worker_agree_on_one_wallet() {
    let registration = register_from_seed(&[0x13; 32], SIGNING_WORKER_MATERIAL);

    // The whole point: both sides land on the same threshold key and address.
    assert_eq!(
        registration.client_finalized_threshold_public_key33, registration.threshold_public_key33,
        "the client and the SigningWorker composed different threshold keys"
    );
    assert_eq!(
        registration.client_finalized_ethereum_address20, registration.ethereum_address20,
        "the client and the SigningWorker composed different addresses"
    );
    assert!(!registration.ready_state_blob.is_empty());

    // A compressed point, and not the client's own share.
    assert!(matches!(
        registration.threshold_public_key33[0],
        0x02 | 0x03
    ));
    assert_ne!(
        registration.threshold_public_key33,
        registration.client_share_public_key33
    );
}

#[test]
fn the_same_seed_re_registers_the_same_wallet() {
    // The recovery property. A wallet recovered from its custody seed must
    // reach the identical EVM address, given the same SigningWorker material —
    // otherwise the recovered wallet is a different wallet.
    let first = register_from_seed(&[0x13; 32], SIGNING_WORKER_MATERIAL);
    let second = register_from_seed(&[0x13; 32], SIGNING_WORKER_MATERIAL);

    assert_eq!(
        first.client_share_public_key33,
        second.client_share_public_key33
    );
    assert_eq!(first.threshold_public_key33, second.threshold_public_key33);
    assert_eq!(first.ethereum_address20, second.ethereum_address20);
}

#[test]
fn a_different_seed_is_a_different_wallet() {
    let first = register_from_seed(&[0x13; 32], SIGNING_WORKER_MATERIAL);
    let other = register_from_seed(&[0x14; 32], SIGNING_WORKER_MATERIAL);

    assert_ne!(
        first.client_share_public_key33,
        other.client_share_public_key33
    );
    assert_ne!(first.threshold_public_key33, other.threshold_public_key33);
    assert_ne!(first.ethereum_address20, other.ethereum_address20);
}

#[test]
fn the_client_share_is_bound_to_the_application_binding_digest() {
    // The seed alone does not determine the share: the digest is mixed in, so
    // one seed cannot be replayed into another application's key set. This is
    // the isolation property behind keeping the digest in the derivation.
    let seed = [0x13u8; 32];
    let bound = derive_ecdsa_client_root_share_from_seed_v1(&seed, &APPLICATION_BINDING_DIGEST)
        .expect("share under the registration digest");
    let elsewhere = derive_ecdsa_client_root_share_from_seed_v1(&seed, &[0x42u8; 32])
        .expect("share under another digest");
    assert_ne!(*bound, *elsewhere);
}

#[test]
fn a_relayer_identity_the_client_did_not_agree_to_is_refused() {
    let seed = [0x13u8; 32];
    let root_share =
        derive_ecdsa_client_root_share_from_seed_v1(&seed, &APPLICATION_BINDING_DIGEST)
            .expect("seed-derived root share");
    let prepared = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
        context: context(),
        client_root_share32: *root_share,
    })
    .expect("prepare");
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &context(),
        SIGNING_WORKER_MATERIAL,
        &prepared.public_facts.derivation_client_share_public_key33,
        prepared.public_facts.client_share_retry_counter,
    )
    .expect("relayer share");

    // A group key that is not the sum of the two shares would bind the wallet
    // to a threshold key the seed-derived share does not participate in. The
    // client must refuse it rather than store a key it cannot sign under.
    let refused = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
        pending_state_blob: prepared.pending_state_blob.clone(),
        relayer_public_identity: RelayerPublicIdentityInput {
            relayer_key_id: RELAYER_KEY_ID.to_string(),
            relayer_public_key33: identity.relayer_public_key33,
            // The relayer's own key, standing in for the group key.
            group_public_key33: identity.relayer_public_key33,
            ethereum_address20: identity.threshold_ethereum_address20,
            relayer_share_retry_counter: identity.relayer_share_retry_counter,
        },
    });
    assert!(refused.is_err(), "a mismatched group key must not finalize");
}

#[test]
fn a_different_signing_worker_cannot_reproduce_the_wallet() {
    // The seed is not the whole wallet: the SigningWorker's material is the
    // other half. A different SigningWorker answering the same client produces
    // a different threshold key, which is what makes the pair a 2-of-2.
    let first = register_from_seed(&[0x13; 32], SIGNING_WORKER_MATERIAL);
    let other = register_from_seed(&[0x13; 32], [0x5e; 32]);

    assert_eq!(
        first.client_share_public_key33, other.client_share_public_key33,
        "the client half depends only on the seed and the digest"
    );
    assert_ne!(first.threshold_public_key33, other.threshold_public_key33);
    assert_ne!(first.ethereum_address20, other.ethereum_address20);
}

#[test]
fn the_registered_identity_is_reported_in_wire_form_without_loss() {
    // What the activate leg carries back is base64url of these exact bytes, so
    // a wire round-trip must not change the wallet.
    let registration = register_from_seed(&[0x13; 32], SIGNING_WORKER_MATERIAL);
    let encoded = b64u(&registration.threshold_public_key33);
    let decoded = Base64UrlUnpadded::decode_vec(&encoded).expect("threshold key round-trips");
    assert_eq!(decoded.as_slice(), &registration.threshold_public_key33[..]);
    assert_eq!(
        b64u(&registration.ethereum_address20).len(),
        27,
        "20 bytes encode to 27 unpadded base64url characters"
    );
}
