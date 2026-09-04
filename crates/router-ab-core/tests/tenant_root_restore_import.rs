use ed25519_dalek::SigningKey;
use rand_chacha_09::ChaCha20Rng;
use rand_core_09::SeedableRng;
use router_ab_core::{
    seal_tenant_root_recovery_package_v1, sign_tenant_root_recovery_manifest_v1,
    verify_and_open_tenant_root_recovery_role_package_v1, ExpectedTenantRootRestoreImportV1,
    TenantRootCustodyLineageId, TenantRootRecoveryTrustedVerifyingKeysV1,
    TenantRootRestoreDestinationFingerprintV1, TenantRootRestoreImportEnvelopeV1,
    TenantRootRestoreImportKeypairV1, TenantRootRestoreImportPublicKeyV1,
    TenantRootRestoreSessionIdV1, VerifiedTenantRootRecoveryRoleShareV1,
};
use threshold_prf::{SigningRootShareCommitment, TwoPartyDeriverRole};

mod support;

use support::verified_recovery_artifact_fixture;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hpke_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn verified_source_share() -> VerifiedTenantRootRecoveryRoleShareV1 {
    let fixture = verified_recovery_artifact_fixture();
    let descriptor = fixture.descriptor;
    let control = signing_key(0x91);
    let package_a = seal_tenant_root_recovery_package_v1(
        &descriptor,
        &fixture.verified_a,
        &mut hpke_rng(0x71),
        &fixture.signing_a.to_bytes(),
    )
    .unwrap();
    let package_b = seal_tenant_root_recovery_package_v1(
        &descriptor,
        &fixture.verified_b,
        &mut hpke_rng(0x81),
        &fixture.signing_b.to_bytes(),
    )
    .unwrap();
    let manifest = sign_tenant_root_recovery_manifest_v1(
        descriptor,
        &package_a,
        &package_b,
        vec!["deriver-a-cert".into()],
        vec!["deriver-b-cert".into()],
        vec!["control-plane-cert".into()],
        &control.to_bytes(),
    )
    .unwrap();
    verify_and_open_tenant_root_recovery_role_package_v1(
        &manifest,
        &package_a,
        &fixture.recipient_a,
        &TenantRootRecoveryTrustedVerifyingKeysV1 {
            deriver_a: fixture.signing_a.verifying_key().to_bytes(),
            deriver_b: fixture.signing_b.verifying_key().to_bytes(),
            control_plane: control.verifying_key().to_bytes(),
        },
    )
    .unwrap()
}

fn expected_import(
    source: &VerifiedTenantRootRecoveryRoleShareV1,
    import_keypair: &TenantRootRestoreImportKeypairV1,
) -> ExpectedTenantRootRestoreImportV1 {
    ExpectedTenantRootRestoreImportV1::from_verified_source(
        source,
        TenantRootRestoreDestinationFingerprintV1::from_bytes([0xd1; 32]).unwrap(),
        TenantRootCustodyLineageId::from_bytes([0xd2; 16]).unwrap(),
        TenantRootRestoreSessionIdV1::from_bytes([0xd3; 16]).unwrap(),
        "destination-a-import-key-1",
        import_keypair.public_key(),
        1_787_971_200_000,
        1_787_972_100_000,
    )
    .unwrap()
}

#[test]
fn verified_source_share_reseals_and_opens_at_the_destination_role() {
    let source = verified_source_share();
    let import_keypair = TenantRootRestoreImportKeypairV1::derive_from_ikm([0xe1; 32]).unwrap();
    let envelope = TenantRootRestoreImportEnvelopeV1::seal(
        &source,
        &expected_import(&source, &import_keypair),
        &mut hpke_rng(0xe2),
    )
    .unwrap();
    let bytes = envelope.to_bytes().unwrap();
    assert_eq!(&bytes[..8], b"SEAMSRI1");
    assert_eq!(
        hex::encode(envelope.digest().unwrap()),
        "dacf4cac52eb2617a3b5c72438f946c193291c02312389bc399725290dde342b"
    );
    let decoded = TenantRootRestoreImportEnvelopeV1::decode(&bytes).unwrap();
    assert_eq!(decoded, envelope);
    let expected = expected_import(&source, &import_keypair);
    let imported = decoded.open(&expected, &import_keypair).unwrap();
    assert_eq!(imported.binding().role(), TwoPartyDeriverRole::DeriverA);
    let share_wire = imported.into_share_wire();
    let share = share_wire.to_share().unwrap();
    assert_eq!(share.id(), TwoPartyDeriverRole::DeriverA.share_id());
    assert_eq!(
        SigningRootShareCommitment::from_share(&share),
        source.recovery_share_commitment()
    );
}

#[test]
fn import_envelope_rejects_wrong_recipient_mutation_and_noncanonical_keys() {
    let source = verified_source_share();
    let import_keypair = TenantRootRestoreImportKeypairV1::derive_from_ikm([0xe1; 32]).unwrap();
    let envelope = TenantRootRestoreImportEnvelopeV1::seal(
        &source,
        &expected_import(&source, &import_keypair),
        &mut hpke_rng(0xe2),
    )
    .unwrap();
    let wrong_keypair = TenantRootRestoreImportKeypairV1::derive_from_ikm([0xe3; 32]).unwrap();
    let expected = expected_import(&source, &import_keypair);
    assert!(envelope.open(&expected, &wrong_keypair).is_err());

    let wrong_expected = ExpectedTenantRootRestoreImportV1::from_verified_source(
        &source,
        TenantRootRestoreDestinationFingerprintV1::from_bytes([0xd1; 32]).unwrap(),
        TenantRootCustodyLineageId::from_bytes([0xd4; 16]).unwrap(),
        TenantRootRestoreSessionIdV1::from_bytes([0xd3; 16]).unwrap(),
        "destination-a-import-key-1",
        import_keypair.public_key(),
        1_787_971_200_000,
        1_787_972_100_000,
    )
    .unwrap();
    assert_eq!(
        envelope
            .open(&wrong_expected, &import_keypair)
            .unwrap_err()
            .code(),
        router_ab_core::RouterAbDerivationErrorCode::ReplayMismatch,
    );

    let mut mutated = envelope.to_bytes().unwrap();
    let last = mutated.len() - 1;
    mutated[last] ^= 1;
    let mutated = TenantRootRestoreImportEnvelopeV1::decode(&mutated).unwrap();
    assert!(mutated.open(&expected, &import_keypair).is_err());

    let mut trailing = envelope.to_bytes().unwrap();
    trailing.push(0);
    assert!(TenantRootRestoreImportEnvelopeV1::decode(&trailing).is_err());

    assert!(TenantRootRestoreImportPublicKeyV1::from_bytes([0; 32]).is_err());
    let mut high_bit_alias = *import_keypair.public_key().as_bytes();
    high_bit_alias[31] |= 0x80;
    assert!(TenantRootRestoreImportPublicKeyV1::from_bytes(high_bit_alias).is_err());
    let mut reduced_alias = [0xff; 32];
    reduced_alias[0] = 0xf6;
    reduced_alias[31] = 0x7f;
    assert!(TenantRootRestoreImportPublicKeyV1::from_bytes(reduced_alias).is_err());
}

#[test]
fn import_decode_rejects_noncanonical_encapsulated_keys() {
    let share = verified_source_share();
    let keypair = TenantRootRestoreImportKeypairV1::derive_from_ikm([0xe1; 32]).unwrap();
    let envelope = TenantRootRestoreImportEnvelopeV1::seal(
        &share,
        &expected_import(&share, &keypair),
        &mut hpke_rng(0xe2),
    )
    .unwrap();
    let mut bytes = envelope.to_bytes().unwrap();
    let binding_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let encapsulated_key_start = 12 + binding_len;
    bytes[encapsulated_key_start + 31] |= 0x80;
    assert!(TenantRootRestoreImportEnvelopeV1::decode(&bytes).is_err());
}
