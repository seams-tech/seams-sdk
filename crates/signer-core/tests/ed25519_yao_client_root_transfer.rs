#![cfg(feature = "ed25519-yao-client-root-transfer")]

use base64ct::{Base64UrlUnpadded, Encoding};
use signer_core::ed25519_yao_client_root_transfer::{
    open_ed25519_yao_client_root_from_linked_device_v1,
    open_ed25519_yao_client_root_under_factor_v1,
    seal_ed25519_yao_client_root_for_linked_device_v1,
    seal_ed25519_yao_client_root_under_factor_v1, Ed25519YaoClientRootFromLinkedDeviceTransferV1,
    Ed25519YaoClientRootTransferBindingV1, Ed25519YaoClientRootTransferRecipientV1,
    SealedEd25519YaoClientRootTransferV1,
};
use signer_core::ed25519_yao_derivation::Ed25519YaoClientRootV1;
use signer_core::passkey_custody::{
    open_wallet_custody_seed_envelope_v1, seal_wallet_custody_seed_envelope_v1,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodySecretBindingV1, PasskeyCustodyTargetFactorV1,
    WalletCustodyEnvelopeFactorV1, WALLET_SEED_DERIVATION_SCHEME_V1,
};
use signer_core::wallet_seed_derivation::derive_ed25519_yao_client_root_from_seed_v1;

const CUSTODY_SEED: [u8; 32] = [42; 32];
const PASSKEY_PRF: [u8; 32] = [7; 32];
const FACTOR_SECRET: [u8; 32] = [8; 32];
const RECIPIENT_SECRET: [u8; 32] = [21; 32];
const EPHEMERAL_SECRET: [u8; 32] = [31; 32];
const SEED_ENVELOPE_NONCE: [u8; 12] = [3; 12];
const ROOT_ENVELOPE_NONCE: [u8; 12] = [4; 12];
const APPLICATION_BINDING_DIGEST: [u8; 32] = [9; 32];
const REGISTERED_PUBLIC_KEY: [u8; 32] = [10; 32];

fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn passkey_factor() -> WalletCustodyEnvelopeFactorV1 {
    WalletCustodyEnvelopeFactorV1::Passkey {
        rp_id: "wallet.example".into(),
        credential_id_b64u: b64u(b"credential-1"),
        kek_version: "passkey_prf_kek_hkdf_sha256_v1".into(),
    }
}

fn seed_envelope_binding() -> PasskeyCustodyEnvelopeBindingV1 {
    PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: "wallet-1".into(),
        envelope_id: "seed-envelope-1".into(),
        factor: passkey_factor(),
        envelope_revision: 1,
        binding: PasskeyCustodySecretBindingV1::WalletCustodySeed {
            derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.into(),
        },
    }
}

fn transfer_binding(
    recipient: &Ed25519YaoClientRootTransferRecipientV1,
) -> Ed25519YaoClientRootTransferBindingV1 {
    Ed25519YaoClientRootTransferBindingV1 {
        link_session_id: "link-session-1".into(),
        wallet_id: "wallet-1".into(),
        wallet_key_id: "wallet-key-ed25519-1".into(),
        target_factor: PasskeyCustodyTargetFactorV1::PasskeyPrf,
        enrollment_id: "enrollment-1".into(),
        device_id: "device-2".into(),
        revocation_epoch: 4,
        application_binding_digest_b64u: b64u(&APPLICATION_BINDING_DIGEST),
        registered_public_key_b64u: b64u(&REGISTERED_PUBLIC_KEY),
        recipient_public_key_b64u: recipient.public_key_b64u(),
    }
}

fn root_envelope_binding() -> PasskeyCustodyEnvelopeBindingV1 {
    PasskeyCustodyEnvelopeBindingV1 {
        wallet_id: "wallet-1".into(),
        envelope_id: "root-envelope-1".into(),
        factor: passkey_factor(),
        envelope_revision: 1,
        binding: PasskeyCustodySecretBindingV1::Ed25519YaoClientRoot {
            link_session_id: "link-session-1".into(),
            wallet_key_id: "wallet-key-ed25519-1".into(),
            target_factor: PasskeyCustodyTargetFactorV1::PasskeyPrf,
            application_binding_digest_b64u: b64u(&APPLICATION_BINDING_DIGEST),
            registered_public_key_b64u: b64u(&REGISTERED_PUBLIC_KEY),
            enrollment_id: "enrollment-1".into(),
            device_id: "device-2".into(),
            revocation_epoch: 4,
        },
    }
}

fn open_transfer(
    transfer: &Ed25519YaoClientRootTransferBindingV1,
    sealed_transfer: &SealedEd25519YaoClientRootTransferV1,
) -> (
    Ed25519YaoClientRootV1,
    Ed25519YaoClientRootFromLinkedDeviceTransferV1,
) {
    let recipient =
        Ed25519YaoClientRootTransferRecipientV1::from_secret_bytes(&RECIPIENT_SECRET).unwrap();
    open_ed25519_yao_client_root_from_linked_device_v1(
        recipient,
        transfer,
        &sealed_transfer.ephemeral_public_key,
        &sealed_transfer.nonce,
        &sealed_transfer.ciphertext,
        &sealed_transfer.binding_digest,
        &sealed_transfer.ciphertext_digest,
    )
    .unwrap()
}

#[test]
fn transfer_derives_only_the_application_bound_root_and_factor_seals_it() {
    let seed_binding = seed_envelope_binding();
    let sealed_seed = seal_wallet_custody_seed_envelope_v1(
        &PASSKEY_PRF,
        &seed_binding,
        &SEED_ENVELOPE_NONCE,
        &CUSTODY_SEED,
    )
    .unwrap();
    let (opened_seed, seed_admission) = open_wallet_custody_seed_envelope_v1(
        &PASSKEY_PRF,
        &seed_binding,
        &SEED_ENVELOPE_NONCE,
        &sealed_seed.ciphertext,
        &sealed_seed.aad_hash,
        &sealed_seed.ciphertext_digest,
    )
    .unwrap();

    let recipient =
        Ed25519YaoClientRootTransferRecipientV1::from_secret_bytes(&RECIPIENT_SECRET).unwrap();
    let transfer = transfer_binding(&recipient);
    let transfer_json = serde_json::to_string(&transfer).unwrap();
    let decoded_transfer: Ed25519YaoClientRootTransferBindingV1 =
        serde_json::from_str(&transfer_json).unwrap();
    assert_eq!(decoded_transfer, transfer);
    let sealed_transfer = seal_ed25519_yao_client_root_for_linked_device_v1(
        &seed_admission,
        &opened_seed,
        &transfer,
        &EPHEMERAL_SECRET,
        &SEED_ENVELOPE_NONCE,
    )
    .unwrap();
    assert_eq!(sealed_transfer.ciphertext.len(), 32 + 16);
    assert_ne!(&sealed_transfer.ciphertext[..32], &CUSTODY_SEED);

    let (opened_root, root_admission) = open_ed25519_yao_client_root_from_linked_device_v1(
        recipient,
        &transfer,
        &sealed_transfer.ephemeral_public_key,
        &sealed_transfer.nonce,
        &sealed_transfer.ciphertext,
        &sealed_transfer.binding_digest,
        &sealed_transfer.ciphertext_digest,
    )
    .unwrap();
    let expected_root =
        derive_ed25519_yao_client_root_from_seed_v1(&CUSTODY_SEED, &APPLICATION_BINDING_DIGEST)
            .unwrap();
    assert_eq!(opened_root.into_bytes(), *expected_root);
    assert_eq!(root_admission.wallet_id(), "wallet-1");
    assert_eq!(root_admission.wallet_key_id(), "wallet-key-ed25519-1");
    assert_eq!(root_admission.revocation_epoch(), 4);
    assert_eq!(root_admission.link_session_id(), "link-session-1");

    let root = Ed25519YaoClientRootV1::from_secret_bytes(*expected_root);
    let root_binding = root_envelope_binding();
    let sealed_root = seal_ed25519_yao_client_root_under_factor_v1(
        &FACTOR_SECRET,
        &root_binding,
        root_admission,
        &root,
        &ROOT_ENVELOPE_NONCE,
    )
    .unwrap();
    let opened_factor_root = open_ed25519_yao_client_root_under_factor_v1(
        &FACTOR_SECRET,
        &root_binding,
        &ROOT_ENVELOPE_NONCE,
        &sealed_root.ciphertext,
        &sealed_root.aad_hash,
        &sealed_root.ciphertext_digest,
    )
    .unwrap();
    assert_eq!(opened_factor_root.into_bytes(), *expected_root);
}

#[test]
fn transfer_and_root_reseal_reject_scope_substitution() {
    let seed_binding = seed_envelope_binding();
    let sealed_seed = seal_wallet_custody_seed_envelope_v1(
        &PASSKEY_PRF,
        &seed_binding,
        &SEED_ENVELOPE_NONCE,
        &CUSTODY_SEED,
    )
    .unwrap();
    let (opened_seed, seed_admission) = open_wallet_custody_seed_envelope_v1(
        &PASSKEY_PRF,
        &seed_binding,
        &SEED_ENVELOPE_NONCE,
        &sealed_seed.ciphertext,
        &sealed_seed.aad_hash,
        &sealed_seed.ciphertext_digest,
    )
    .unwrap();
    let recipient =
        Ed25519YaoClientRootTransferRecipientV1::from_secret_bytes(&RECIPIENT_SECRET).unwrap();
    let transfer = transfer_binding(&recipient);
    let sealed_transfer = seal_ed25519_yao_client_root_for_linked_device_v1(
        &seed_admission,
        &opened_seed,
        &transfer,
        &EPHEMERAL_SECRET,
        &SEED_ENVELOPE_NONCE,
    )
    .unwrap();

    let mut wrong_transfer = transfer.clone();
    wrong_transfer.target_factor = PasskeyCustodyTargetFactorV1::EmailOtp;
    let wrong_recipient =
        Ed25519YaoClientRootTransferRecipientV1::from_secret_bytes(&RECIPIENT_SECRET).unwrap();
    assert!(open_ed25519_yao_client_root_from_linked_device_v1(
        wrong_recipient,
        &wrong_transfer,
        &sealed_transfer.ephemeral_public_key,
        &sealed_transfer.nonce,
        &sealed_transfer.ciphertext,
        &sealed_transfer.binding_digest,
        &sealed_transfer.ciphertext_digest,
    )
    .is_err());

    let mut stale_transfer = transfer.clone();
    stale_transfer.revocation_epoch += 1;
    let stale_recipient =
        Ed25519YaoClientRootTransferRecipientV1::from_secret_bytes(&RECIPIENT_SECRET).unwrap();
    assert!(open_ed25519_yao_client_root_from_linked_device_v1(
        stale_recipient,
        &stale_transfer,
        &sealed_transfer.ephemeral_public_key,
        &sealed_transfer.nonce,
        &sealed_transfer.ciphertext,
        &sealed_transfer.binding_digest,
        &sealed_transfer.ciphertext_digest,
    )
    .is_err());

    let (_, root_admission) = open_transfer(&transfer, &sealed_transfer);
    let root = Ed25519YaoClientRootV1::from_secret_bytes(
        *derive_ed25519_yao_client_root_from_seed_v1(&CUSTODY_SEED, &APPLICATION_BINDING_DIGEST)
            .unwrap(),
    );
    let mut wrong_root_binding = root_envelope_binding();
    if let PasskeyCustodySecretBindingV1::Ed25519YaoClientRoot { wallet_key_id, .. } =
        &mut wrong_root_binding.binding
    {
        *wallet_key_id = "wallet-key-ed25519-sibling".into();
    }
    assert!(seal_ed25519_yao_client_root_under_factor_v1(
        &FACTOR_SECRET,
        &wrong_root_binding,
        root_admission,
        &root,
        &ROOT_ENVELOPE_NONCE,
    )
    .is_err());

    let (_, stale_root_admission) = open_transfer(&transfer, &sealed_transfer);
    let stale_root = Ed25519YaoClientRootV1::from_secret_bytes(
        *derive_ed25519_yao_client_root_from_seed_v1(&CUSTODY_SEED, &APPLICATION_BINDING_DIGEST)
            .unwrap(),
    );
    let mut stale_root_binding = root_envelope_binding();
    if let PasskeyCustodySecretBindingV1::Ed25519YaoClientRoot {
        revocation_epoch, ..
    } = &mut stale_root_binding.binding
    {
        *revocation_epoch += 1;
    }
    assert!(seal_ed25519_yao_client_root_under_factor_v1(
        &FACTOR_SECRET,
        &stale_root_binding,
        stale_root_admission,
        &stale_root,
        &ROOT_ENVELOPE_NONCE,
    )
    .is_err());

    let (_, wrong_factor_admission) = open_transfer(&transfer, &sealed_transfer);
    let wrong_factor_root = Ed25519YaoClientRootV1::from_secret_bytes(
        *derive_ed25519_yao_client_root_from_seed_v1(&CUSTODY_SEED, &APPLICATION_BINDING_DIGEST)
            .unwrap(),
    );
    let mut wrong_factor_binding = root_envelope_binding();
    if let PasskeyCustodySecretBindingV1::Ed25519YaoClientRoot { target_factor, .. } =
        &mut wrong_factor_binding.binding
    {
        *target_factor = PasskeyCustodyTargetFactorV1::EmailOtp;
    }
    assert!(seal_ed25519_yao_client_root_under_factor_v1(
        &FACTOR_SECRET,
        &wrong_factor_binding,
        wrong_factor_admission,
        &wrong_factor_root,
        &ROOT_ENVELOPE_NONCE,
    )
    .is_err());
}
