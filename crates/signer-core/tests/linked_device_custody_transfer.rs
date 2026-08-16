#![cfg(feature = "linked-device-custody-transfer")]

//! Crypto invariants for the Refactor 103 Phase 8 cross-device seed transfer.
//!
//! Device linking is the one custody flow where the secret that opens the
//! existing envelope and the secret that seals the new one live on different
//! machines. These own what that split must not weaken: the transfer opens for
//! exactly one recipient key and exactly one enrollment, it cannot relabel the
//! seed on the way across, and the envelope Device 2 writes makes the same
//! claim Device 1's envelope made.

use signer_core::error::CoreResult;
use signer_core::linked_device_custody_transfer::{
    open_wallet_custody_seed_from_linked_device_v1, reseal_transferred_wallet_custody_seed_v1,
    seal_wallet_custody_seed_for_linked_device_v1, LinkedDeviceCustodyTransferBindingV1,
    LinkedDeviceCustodyTransferRecipientV1, SealedLinkedDeviceCustodyTransferV1,
};
use signer_core::passkey_custody::{
    open_wallet_custody_seed_envelope_v1, seal_wallet_custody_seed_envelope_v1,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodyLaneScopeV1, PasskeyCustodySecretBindingV1,
    WalletCustodyEnvelopeFactorV1, WalletCustodySeedFromSealedEnvelopeV1,
    PASSKEY_CUSTODY_KEK_VERSION_V1, WALLET_SEED_DERIVATION_SCHEME_V1,
};
use zeroize::Zeroizing;

const WALLET_ID: &str = "alice.testnet";
const ENROLLMENT_ID: &str = "enrollment:device-2";
const DEVICE_ID: &str = "device:2";
const OWNER_PRF: [u8; 32] = [7u8; 32];
const DEVICE_2_PRF: [u8; 32] = [11u8; 32];
const RECIPIENT_SECRET: [u8; 32] = [21u8; 32];
const OTHER_RECIPIENT_SECRET: [u8; 32] = [22u8; 32];
const EPHEMERAL_SECRET: [u8; 32] = [31u8; 32];
const ENVELOPE_NONCE: [u8; 12] = [3u8; 12];
const TRANSFER_NONCE: [u8; 12] = [4u8; 12];
const RESEAL_NONCE: [u8; 12] = [5u8; 12];
const CUSTODY_SEED: [u8; 32] = [42u8; 32];

fn wallet_seed_binding() -> PasskeyCustodySecretBindingV1 {
    PasskeyCustodySecretBindingV1::WalletCustodySeed {
        derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.into(),
    }
}

fn owner_envelope_binding() -> PasskeyCustodyEnvelopeBindingV1 {
    PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: WALLET_ID.into(),
        envelope_id: "envelope:owner".into(),
        factor: WalletCustodyEnvelopeFactorV1::Passkey {
            rp_id: "wallet.example.localhost".into(),
            credential_id_b64u: "credential-device-1".into(),
            kek_version: PASSKEY_CUSTODY_KEK_VERSION_V1.into(),
        },
        envelope_revision: 1,
        binding: wallet_seed_binding(),
    }
}

fn device_2_envelope_binding() -> PasskeyCustodyEnvelopeBindingV1 {
    PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: WALLET_ID.into(),
        envelope_id: "envelope:device-2".into(),
        factor: WalletCustodyEnvelopeFactorV1::Passkey {
            rp_id: "wallet.example.localhost".into(),
            credential_id_b64u: "credential-device-2".into(),
            kek_version: PASSKEY_CUSTODY_KEK_VERSION_V1.into(),
        },
        envelope_revision: 1,
        binding: wallet_seed_binding(),
    }
}

/// Device 1: opens its own envelope and mints the admission a transfer needs.
fn admitted_owner_seed() -> CoreResult<(Zeroizing<Vec<u8>>, WalletCustodySeedFromSealedEnvelopeV1)>
{
    let binding = owner_envelope_binding();
    let sealed =
        seal_wallet_custody_seed_envelope_v1(&OWNER_PRF, &binding, &ENVELOPE_NONCE, &CUSTODY_SEED)?;
    open_wallet_custody_seed_envelope_v1(
        &OWNER_PRF,
        &binding,
        &ENVELOPE_NONCE,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
}

fn transfer_binding(recipient_public_key_b64u: String) -> LinkedDeviceCustodyTransferBindingV1 {
    LinkedDeviceCustodyTransferBindingV1 {
        wallet_id: WALLET_ID.into(),
        enrollment_id: ENROLLMENT_ID.into(),
        device_id: DEVICE_ID.into(),
        recipient_public_key_b64u,
        binding: wallet_seed_binding(),
    }
}

fn recipient() -> LinkedDeviceCustodyTransferRecipientV1 {
    LinkedDeviceCustodyTransferRecipientV1::from_secret_bytes(&RECIPIENT_SECRET).expect("recipient")
}

fn seal_for_recipient(
    recipient: &LinkedDeviceCustodyTransferRecipientV1,
) -> CoreResult<(
    LinkedDeviceCustodyTransferBindingV1,
    SealedLinkedDeviceCustodyTransferV1,
)> {
    let (seed, admitted) = admitted_owner_seed()?;
    let transfer = transfer_binding(recipient.public_key_b64u());
    let sealed = seal_wallet_custody_seed_for_linked_device_v1(
        &admitted,
        &seed[..],
        &transfer,
        &EPHEMERAL_SECRET,
        &TRANSFER_NONCE,
    )?;
    Ok((transfer, sealed))
}

fn open_for_recipient(
    recipient: &LinkedDeviceCustodyTransferRecipientV1,
    transfer: &LinkedDeviceCustodyTransferBindingV1,
    sealed: &SealedLinkedDeviceCustodyTransferV1,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    let (seed, _admitted) = open_wallet_custody_seed_from_linked_device_v1(
        recipient,
        transfer,
        &sealed.ephemeral_public_key,
        &sealed.nonce,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )?;
    Ok(seed)
}

#[test]
fn transfers_the_exact_seed_to_the_addressed_recipient() {
    let recipient = recipient();
    let (transfer, sealed) = seal_for_recipient(&recipient).expect("seal");
    let seed = open_for_recipient(&recipient, &transfer, &sealed).expect("open");
    assert_eq!(&seed[..], &CUSTODY_SEED[..]);
    // The seed itself never appears in what crosses the wire.
    assert_ne!(sealed.ciphertext.as_slice(), &CUSTODY_SEED[..]);
}

#[test]
fn a_transfer_does_not_open_for_another_recipient_key() {
    let recipient = recipient();
    let (transfer, sealed) = seal_for_recipient(&recipient).expect("seal");
    let other = LinkedDeviceCustodyTransferRecipientV1::from_secret_bytes(&OTHER_RECIPIENT_SECRET)
        .expect("other recipient");

    // Addressed to the original key: the mismatch is caught before decryption.
    let wrong_holder = open_wallet_custody_seed_from_linked_device_v1(
        &other,
        &transfer,
        &sealed.ephemeral_public_key,
        &sealed.nonce,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    );
    assert!(wrong_holder.is_err());

    // Rewriting the binding to name the other key changes the AAD, so the
    // recorded aad hash no longer matches and the AEAD would fail regardless.
    let substituted = transfer_binding(other.public_key_b64u());
    let substituted_open = open_wallet_custody_seed_from_linked_device_v1(
        &other,
        &substituted,
        &sealed.ephemeral_public_key,
        &sealed.nonce,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    );
    assert!(substituted_open.is_err());
}

#[test]
fn a_transfer_is_bound_to_its_exact_enrollment_wallet_and_device() {
    let recipient = recipient();
    let (transfer, sealed) = seal_for_recipient(&recipient).expect("seal");

    for substituted in [
        LinkedDeviceCustodyTransferBindingV1 {
            enrollment_id: "enrollment:other".into(),
            ..transfer.clone()
        },
        LinkedDeviceCustodyTransferBindingV1 {
            device_id: "device:3".into(),
            ..transfer.clone()
        },
        LinkedDeviceCustodyTransferBindingV1 {
            wallet_id: "bob.testnet".into(),
            ..transfer.clone()
        },
    ] {
        let opened = open_wallet_custody_seed_from_linked_device_v1(
            &recipient,
            &substituted,
            &sealed.ephemeral_public_key,
            &sealed.nonce,
            &sealed.ciphertext,
            &sealed.aad_hash,
            &sealed.ciphertext_digest,
        );
        assert!(
            opened.is_err(),
            "substituted transfer binding must not open"
        );
    }
}

#[test]
fn a_tampered_package_does_not_open() {
    let recipient = recipient();
    let (transfer, sealed) = seal_for_recipient(&recipient).expect("seal");

    let mut flipped_ciphertext = sealed.ciphertext.clone();
    flipped_ciphertext[0] ^= 0x01;
    assert!(open_wallet_custody_seed_from_linked_device_v1(
        &recipient,
        &transfer,
        &sealed.ephemeral_public_key,
        &sealed.nonce,
        &flipped_ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
    .is_err());

    let mut flipped_ephemeral = sealed.ephemeral_public_key;
    flipped_ephemeral[0] ^= 0x01;
    assert!(open_wallet_custody_seed_from_linked_device_v1(
        &recipient,
        &transfer,
        &flipped_ephemeral,
        &sealed.nonce,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
    .is_err());

    let mut wrong_nonce = sealed.nonce;
    wrong_nonce[0] ^= 0x01;
    assert!(open_wallet_custody_seed_from_linked_device_v1(
        &recipient,
        &transfer,
        &sealed.ephemeral_public_key,
        &wrong_nonce,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
    .is_err());
}

#[test]
fn a_transfer_requires_an_admitted_seed_from_the_same_wallet() {
    let recipient = recipient();
    let (seed, admitted) = admitted_owner_seed().expect("admitted");
    let cross_wallet = LinkedDeviceCustodyTransferBindingV1 {
        wallet_id: "bob.testnet".into(),
        ..transfer_binding(recipient.public_key_b64u())
    };
    let sealed = seal_wallet_custody_seed_for_linked_device_v1(
        &admitted,
        &seed[..],
        &cross_wallet,
        &EPHEMERAL_SECRET,
        &TRANSFER_NONCE,
    );
    assert!(sealed.is_err());
}

#[test]
fn a_transfer_carries_only_wallet_custody_seeds() {
    let recipient = recipient();
    let (seed, admitted) = admitted_owner_seed().expect("admitted");
    let lane_scoped = LinkedDeviceCustodyTransferBindingV1 {
        binding: PasskeyCustodySecretBindingV1::Ed25519LaneHolderShare {
            lane: PasskeyCustodyLaneScopeV1 {
                wallet_key_id: "wallet-key:ed25519:alice.testnet:root-1:v1".into(),
                lane_id: "lane:owner:ed25519:1".into(),
                lane_share_epoch: "lane-share-epoch-1".into(),
            },
            near_ed25519_signing_key_id: "near-key:1".into(),
            registered_public_key_b64u: base64_url(&[1u8; 32]),
            participant_binding_digest_b64u: base64_url(&[2u8; 32]),
        },
        ..transfer_binding(recipient.public_key_b64u())
    };
    assert!(seal_wallet_custody_seed_for_linked_device_v1(
        &admitted,
        &seed[..],
        &lane_scoped,
        &EPHEMERAL_SECRET,
        &TRANSFER_NONCE,
    )
    .is_err());
}

#[test]
fn the_linked_reseal_preserves_the_wallet_and_custody_claim() {
    let recipient = recipient();
    let (transfer, sealed) = seal_for_recipient(&recipient).expect("seal");
    let (seed, admitted) = open_wallet_custody_seed_from_linked_device_v1(
        &recipient,
        &transfer,
        &sealed.ephemeral_public_key,
        &sealed.nonce,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
    .expect("open");
    assert_eq!(admitted.wallet_id(), WALLET_ID);
    assert_eq!(admitted.enrollment_id(), ENROLLMENT_ID);
    assert_eq!(admitted.device_id(), DEVICE_ID);

    // Only the factor and the envelope id may differ.
    let device_2 = reseal_transferred_wallet_custody_seed_v1(
        &DEVICE_2_PRF,
        &device_2_envelope_binding(),
        &admitted,
        &RESEAL_NONCE,
        &seed[..],
    )
    .expect("reseal");

    // Device 2's envelope opens under Device 2's own factor and yields the same
    // seed the wallet already had. No new wallet, no rotated material.
    let (reopened, _) = open_wallet_custody_seed_envelope_v1(
        &DEVICE_2_PRF,
        &device_2_envelope_binding(),
        &RESEAL_NONCE,
        &device_2.ciphertext,
        &device_2.aad_hash,
        &device_2.ciphertext_digest,
    )
    .expect("reopen");
    assert_eq!(&reopened[..], &CUSTODY_SEED[..]);

    // Device 1's factor cannot open Device 2's envelope.
    assert!(open_wallet_custody_seed_envelope_v1(
        &OWNER_PRF,
        &device_2_envelope_binding(),
        &RESEAL_NONCE,
        &device_2.ciphertext,
        &device_2.aad_hash,
        &device_2.ciphertext_digest,
    )
    .is_err());
}

#[test]
fn the_linked_reseal_cannot_move_or_relabel_the_seed() {
    let recipient = recipient();
    let (transfer, sealed) = seal_for_recipient(&recipient).expect("seal");
    let (seed, admitted) = open_wallet_custody_seed_from_linked_device_v1(
        &recipient,
        &transfer,
        &sealed.ephemeral_public_key,
        &sealed.nonce,
        &sealed.ciphertext,
        &sealed.aad_hash,
        &sealed.ciphertext_digest,
    )
    .expect("open");

    let cross_wallet = PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: "bob.testnet".into(),
        ..device_2_envelope_binding()
    };
    assert!(reseal_transferred_wallet_custody_seed_v1(
        &DEVICE_2_PRF,
        &cross_wallet,
        &admitted,
        &RESEAL_NONCE,
        &seed[..],
    )
    .is_err());

    let relabelled = PasskeyCustodyEnvelopeBindingV1 {
        binding: PasskeyCustodySecretBindingV1::EcdsaLaneHolderShare {
            lane: PasskeyCustodyLaneScopeV1 {
                wallet_key_id: "wallet-key:evm-family:alice.testnet:root-1:v1".into(),
                lane_id: "lane:owner:evm-family:1".into(),
                lane_share_epoch: "lane-share-epoch-1".into(),
            },
            evm_family_signing_key_slot_id: "slot:1".into(),
            threshold_session_id: "session:1".into(),
            threshold_public_key33_b64u: base64_url(&[3u8; 33]),
        },
        ..device_2_envelope_binding()
    };
    assert!(reseal_transferred_wallet_custody_seed_v1(
        &DEVICE_2_PRF,
        &relabelled,
        &admitted,
        &RESEAL_NONCE,
        &seed[..],
    )
    .is_err());
}

#[test]
fn a_recipient_key_is_deterministic_in_its_secret_and_distinct_across_secrets() {
    let first = recipient();
    let repeat = recipient();
    let other = LinkedDeviceCustodyTransferRecipientV1::from_secret_bytes(&OTHER_RECIPIENT_SECRET)
        .expect("other recipient");
    assert_eq!(first.public_key_b64u(), repeat.public_key_b64u());
    assert_ne!(first.public_key_b64u(), other.public_key_b64u());
    assert!(LinkedDeviceCustodyTransferRecipientV1::from_secret_bytes(&[0u8; 31]).is_err());
}

fn base64_url(bytes: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
}
