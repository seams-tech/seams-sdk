use rand_chacha_09::ChaCha20Rng;
use rand_core_09::SeedableRng;
use router_ab_core::{
    confirm_tenant_root_recovery_recipient_proof_v1,
    decode_tenant_root_recovery_recipient_proof_v1, open_tenant_root_recovery_recipient_proof_v1,
    seal_tenant_root_recovery_recipient_proof_v1, verify_tenant_root_recovery_recipient_proof_v1,
    RouterAbDerivationErrorCode, TenantRootCustodyLineageId, TenantRootIdentityV1,
    TenantRootRecoveryRecipientKeypairV1, TenantRootRecoveryRecipientProofBindingV1,
    TenantRootRecoveryRecipientProofConfirmationV1, TenantRootRecoveryRecipientProofEnvelopeV1,
    TenantRootRecoveryRecipientProofSecretV1, TenantRootRecoveryRecipientPublicKeyV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{ThresholdShareId, TwoPartyDeriverRole};

fn identity_digest() -> router_ab_core::TenantRootIdentityDigestV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .unwrap()
        .digest()
        .unwrap()
}

fn keypair(seed: u8) -> TenantRootRecoveryRecipientKeypairV1 {
    TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([seed; 32]).unwrap()
}

fn hpke_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn binding(
    public_key: TenantRootRecoveryRecipientPublicKeyV1,
) -> TenantRootRecoveryRecipientProofBindingV1 {
    TenantRootRecoveryRecipientProofBindingV1::new(
        [0x11; 16],
        identity_digest(),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
        TwoPartyDeriverRole::DeriverA,
        ThresholdShareId::from_u16(1).unwrap(),
        public_key.fingerprint(),
        "owner-1",
        7,
        1_700_000_000_000,
        1_700_000_600_000,
    )
    .unwrap()
}

fn envelope() -> TenantRootRecoveryRecipientProofEnvelopeV1 {
    let recipient = keypair(0x41);
    seal_tenant_root_recovery_recipient_proof_v1(
        binding(recipient.public_key()),
        recipient.public_key(),
        [0x33; 32],
        &mut hpke_rng(0x44),
    )
    .unwrap()
}

#[test]
fn key_and_fingerprint_are_canonical() {
    let recipient = keypair(0x41);
    assert_eq!(
        hex::encode(recipient.public_key().as_bytes()),
        "fd2c4dd1c8a6b88fe1fc59ce441398f5ea83a9296e210997ac63bed970b86028",
    );
    assert_eq!(
        hex::encode(recipient.public_key().fingerprint().as_bytes()),
        "dcb8a4bed838d7ff810d96b0d1a7febe565675a3d464f8ee30722215654a15ae",
    );

    assert!(TenantRootRecoveryRecipientPublicKeyV1::from_bytes([0; 32]).is_err());
    let mut high_bit_alias = *recipient.public_key().as_bytes();
    high_bit_alias[31] |= 0x80;
    assert!(TenantRootRecoveryRecipientPublicKeyV1::from_bytes(high_bit_alias).is_err());
    let mut reduced_alias = [0xff; 32];
    reduced_alias[0] = 0xf6;
    reduced_alias[31] = 0x7f;
    assert!(TenantRootRecoveryRecipientPublicKeyV1::from_bytes(reduced_alias).is_err());
    assert!(TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([0; 32]).is_err());
}

#[test]
fn challenge_roundtrip_confirmation_and_binary_golden() {
    let recipient = keypair(0x41);
    let envelope = seal_tenant_root_recovery_recipient_proof_v1(
        binding(recipient.public_key()),
        recipient.public_key(),
        [0x33; 32],
        &mut hpke_rng(0x44),
    )
    .unwrap();
    let encoded = envelope.to_bytes().unwrap();
    assert!(encoded.starts_with(b"SEAMRCP1"));
    assert_eq!(
        hex::encode(envelope.binding().canonical_aad_bytes().unwrap()),
        "000000317365616d732f74656e616e742d726f6f742d7265636f766572792d726563697069656e742d70726f6f662f6161642f76310000001011111111111111111111111111111111000000209c5d583ae4693793ce3b51590c788651ba0df4c2339b25b84676665fce44aa8b000000102222222222222222222222222222222200000009646572697665725f6100000002000100000020dcb8a4bed838d7ff810d96b0d1a7febe565675a3d464f8ee30722215654a15ae000000076f776e65722d31000000080000000000000007000000080000018bcfe56800000000080000018bcfee8fc0",
    );
    assert_eq!(
        hex::encode(envelope.binding().canonical_confirmation_bytes().unwrap()),
        "0000003a7365616d732f74656e616e742d726f6f742d7265636f766572792d726563697069656e742d70726f6f662f636f6e6669726d6174696f6e2f76310000001011111111111111111111111111111111000000209c5d583ae4693793ce3b51590c788651ba0df4c2339b25b84676665fce44aa8b000000102222222222222222222222222222222200000009646572697665725f6100000002000100000020dcb8a4bed838d7ff810d96b0d1a7febe565675a3d464f8ee30722215654a15ae000000076f776e65722d31000000080000000000000007000000080000018bcfe56800000000080000018bcfee8fc0",
    );
    assert_eq!(encoded.len(), 327);
    assert_eq!(
        hex::encode(Sha256::digest(&encoded)),
        "56d6c6f645b4284cb1c213c2362c9b6486bdc3977759460ded9a03377e62f8fb",
    );

    let decoded = decode_tenant_root_recovery_recipient_proof_v1(&encoded).unwrap();
    assert_eq!(decoded, envelope);
    let opened = open_tenant_root_recovery_recipient_proof_v1(&decoded, &recipient).unwrap();
    assert_eq!(opened.as_bytes(), &[0x33; 32]);
    let confirmation =
        confirm_tenant_root_recovery_recipient_proof_v1(decoded.binding(), opened.as_bytes())
            .unwrap();
    assert_eq!(
        hex::encode(confirmation.as_bytes()),
        "d18d73244a5b795356fb8f79cdd0d5746a9a14b83e5ff6612089da3a6baad0f4",
    );
    verify_tenant_root_recovery_recipient_proof_v1(
        decoded.binding(),
        opened.as_bytes(),
        &confirmation,
    )
    .unwrap();
}

#[test]
fn substitutions_fail_closed_and_confirmation_is_constant_time_checked() {
    let recipient = keypair(0x41);
    let wrong_recipient = keypair(0x42);
    let envelope = envelope();
    assert_eq!(
        open_tenant_root_recovery_recipient_proof_v1(&envelope, &wrong_recipient)
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::RecipientMismatch,
    );

    let opened = envelope.open(&recipient).unwrap();
    let mut wrong_secret = *opened.as_bytes();
    wrong_secret[0] ^= 1;
    let confirmation =
        confirm_tenant_root_recovery_recipient_proof_v1(envelope.binding(), opened.as_bytes())
            .unwrap();
    assert_eq!(
        verify_tenant_root_recovery_recipient_proof_v1(
            envelope.binding(),
            &wrong_secret,
            &confirmation,
        )
        .unwrap_err()
        .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed,
    );

    let changed_binding = TenantRootRecoveryRecipientProofBindingV1::new(
        *envelope.binding().challenge_id(),
        envelope.binding().tenant_identity_digest(),
        envelope.binding().custody_lineage(),
        envelope.binding().role(),
        envelope.binding().share_id(),
        envelope.binding().recipient_fingerprint(),
        "owner-2",
        envelope.binding().lifecycle_revision().get(),
        envelope.binding().issued_at_ms(),
        envelope.binding().expires_at_ms(),
    )
    .unwrap();
    let changed_confirmation =
        confirm_tenant_root_recovery_recipient_proof_v1(&changed_binding, opened.as_bytes())
            .unwrap();
    assert_ne!(confirmation, changed_confirmation);
}

#[test]
fn malformed_binding_and_envelope_bytes_are_rejected() {
    let recipient = keypair(0x41);
    assert!(TenantRootRecoveryRecipientProofBindingV1::new(
        [0; 16],
        identity_digest(),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
        TwoPartyDeriverRole::DeriverA,
        ThresholdShareId::from_u16(1).unwrap(),
        recipient.public_key().fingerprint(),
        "owner-1",
        7,
        1_700_000_000_000,
        1_700_000_600_000,
    )
    .is_err());
    assert!(TenantRootRecoveryRecipientProofBindingV1::new(
        [0x11; 16],
        identity_digest(),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
        TwoPartyDeriverRole::DeriverA,
        ThresholdShareId::from_u16(2).unwrap(),
        recipient.public_key().fingerprint(),
        "owner-1",
        7,
        1_700_000_000_000,
        1_700_000_600_000,
    )
    .is_err());
    assert!(TenantRootRecoveryRecipientProofBindingV1::new(
        [0x11; 16],
        identity_digest(),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
        TwoPartyDeriverRole::DeriverA,
        ThresholdShareId::from_u16(1).unwrap(),
        recipient.public_key().fingerprint(),
        "owner-1",
        0,
        1_700_000_000_000,
        1_700_000_600_000,
    )
    .is_err());

    let encoded = envelope().to_bytes().unwrap();
    let mut bad_magic = encoded.clone();
    bad_magic[0] ^= 1;
    assert!(decode_tenant_root_recovery_recipient_proof_v1(&bad_magic).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_tenant_root_recovery_recipient_proof_v1(&trailing).is_err());
    assert!(decode_tenant_root_recovery_recipient_proof_v1(&encoded[..encoded.len() - 1]).is_err());

    let mut bad_encapsulation = encoded;
    let binding_len = u32::from_be_bytes(bad_encapsulation[8..12].try_into().unwrap()) as usize;
    let encapsulated_offset = 12 + binding_len;
    bad_encapsulation[encapsulated_offset + 31] |= 0x80;
    assert!(decode_tenant_root_recovery_recipient_proof_v1(&bad_encapsulation).is_err());
}

#[test]
fn confirmation_wire_shape_is_exact() {
    let confirmation = TenantRootRecoveryRecipientProofConfirmationV1::from_bytes([0x55; 32]);
    assert_eq!(confirmation.as_bytes(), &[0x55; 32]);
    assert!(!format!("{confirmation:?}").contains("5555"));
    let secret = TenantRootRecoveryRecipientProofSecretV1::from_bytes([0x66; 32]).unwrap();
    assert_eq!(secret.as_bytes(), &[0x66; 32]);
    assert!(TenantRootRecoveryRecipientProofSecretV1::from_bytes([0; 32]).is_err());
    let _ = router_ab_core::TenantRootRecoveryRecipientFingerprintV1::from_bytes([0x77; 32]);
}
