use ed25519_dalek::SigningKey;
use rand_chacha_09::ChaCha20Rng;
use rand_core_09::SeedableRng;
use router_ab_core::{
    decode_tenant_root_recovery_manifest_v1, decode_tenant_root_recovery_package_v1,
    seal_tenant_root_recovery_package_v1, sign_tenant_root_recovery_manifest_v1,
    verify_and_open_tenant_root_recovery_role_package_v1, TenantRootRecoveryDescriptorV1,
    TenantRootRecoveryManifestV1, TenantRootRecoveryPackageV1,
    TenantRootRecoveryRecipientKeypairV1, TenantRootRecoveryRecipientPublicKeyV1,
    TenantRootRecoverySetId, TenantRootRecoveryTrustedVerifyingKeysV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{SigningRootShareWire, TwoPartyDeriverRole};

mod support;

use support::verified_recovery_artifact_fixture;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hpke_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn descriptor() -> TenantRootRecoveryDescriptorV1 {
    verified_recovery_artifact_fixture().descriptor
}

fn packages() -> (
    TenantRootRecoveryDescriptorV1,
    TenantRootRecoveryPackageV1,
    TenantRootRecoveryPackageV1,
    TenantRootRecoveryRecipientKeypairV1,
    TenantRootRecoveryRecipientKeypairV1,
    SigningKey,
    SigningKey,
) {
    let fixture = verified_recovery_artifact_fixture();
    let descriptor = fixture.descriptor;
    let package_a = seal_tenant_root_recovery_package_v1(
        &descriptor,
        &fixture.verified_a,
        &mut hpke_rng(0x71),
        &fixture.signing_a.to_bytes(),
    )
    .expect("package A");
    let package_b = seal_tenant_root_recovery_package_v1(
        &descriptor,
        &fixture.verified_b,
        &mut hpke_rng(0x81),
        &fixture.signing_b.to_bytes(),
    )
    .expect("package B");
    (
        descriptor,
        package_a,
        package_b,
        fixture.recipient_a,
        fixture.recipient_b,
        fixture.signing_a,
        fixture.signing_b,
    )
}

#[test]
fn recovery_set_id_and_recipient_fingerprint_are_canonical() {
    let id = TenantRootRecoverySetId::from_bytes([0xa5; 16]).expect("set id");
    assert_eq!(id.to_base64url(), "paWlpaWlpaWlpaWlpaWlpQ");
    assert_eq!(
        TenantRootRecoverySetId::from_base64url(&id.to_base64url()).unwrap(),
        id
    );
    assert!(TenantRootRecoverySetId::from_base64url("paWlpaWlpaWlpaWlpaWlpQ=").is_err());
    assert!(TenantRootRecoverySetId::from_bytes([0; 16]).is_err());

    let keypair = TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([0xa1; 32]).unwrap();
    let public_key = keypair.public_key();
    let expected_fingerprint: [u8; 32] = Sha256::digest(public_key.as_bytes()).into();
    assert_eq!(public_key.fingerprint().as_bytes(), &expected_fingerprint);
    assert!(TenantRootRecoveryRecipientPublicKeyV1::from_bytes([0; 32]).is_err());
    let mut reduced_alias = [0xff; 32];
    reduced_alias[0] = 0xf6;
    reduced_alias[31] = 0x7f;
    assert!(TenantRootRecoveryRecipientPublicKeyV1::from_bytes(reduced_alias).is_err());
    let mut non_canonical_alias = *public_key.as_bytes();
    non_canonical_alias[31] |= 0x80;
    assert!(TenantRootRecoveryRecipientPublicKeyV1::from_bytes(non_canonical_alias).is_err());
    assert!(TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([0; 32]).is_err());
}

#[test]
fn descriptor_canonical_json_round_trips_and_binds_commitments() {
    let descriptor = descriptor();
    let canonical = descriptor.canonical_json().expect("canonical descriptor");
    assert_eq!(canonical.first(), Some(&b'{'));
    assert!(canonical.windows(2).all(|window| window != b"\n"));
    assert_eq!(
        TenantRootRecoveryDescriptorV1::from_canonical_json(&canonical).unwrap(),
        descriptor
    );
    assert_eq!(
        hex::encode(descriptor.digest().unwrap().into_bytes()),
        hex::encode(Sha256::digest(&canonical)),
    );
    assert_eq!(
        hex::encode(descriptor.digest().unwrap().into_bytes()),
        "58f5870bfa350a66c84606b748e942de68832b8bd952663a553d680e53e293cb",
    );

    let mut unknown = canonical.clone();
    unknown.pop();
    unknown.extend_from_slice(b",\"unknown\":1}");
    assert!(TenantRootRecoveryDescriptorV1::from_canonical_json(&unknown).is_err());

    let duplicate = canonical
        .strip_suffix(b"}")
        .expect("object")
        .iter()
        .copied()
        .chain(
            b",\"formatVersion\":\"tenant_root_recovery_descriptor_v1\"}"
                .iter()
                .copied(),
        )
        .collect::<Vec<_>>();
    assert!(TenantRootRecoveryDescriptorV1::from_canonical_json(&duplicate).is_err());
}

#[test]
fn role_packages_are_deterministic_signed_encrypted_and_recipient_bound() {
    let (descriptor, package_a, package_b, recipient_a, recipient_b, signing_a, signing_b) =
        packages();
    let package_a_bytes = package_a.to_bytes().unwrap();
    assert_eq!(
        hex::encode(package_a.digest().unwrap().into_bytes()),
        "02297cf527c929e185917658ed20af1232c676a60aa6dcf420023a57274aa118",
    );
    assert_eq!(
        hex::encode(package_b.digest().unwrap().into_bytes()),
        "5061ecafc86d8058b206ae8da00c8219cb0053c9dd2068a919546f41a21a10fb",
    );
    assert_eq!(&package_a_bytes[..8], b"SEAMSRB1");
    assert_eq!(package_a.ciphertext_len(), SigningRootShareWire::LEN + 16);
    assert_ne!(package_a.digest().unwrap(), package_b.digest().unwrap());

    let decoded_a = decode_tenant_root_recovery_package_v1(&package_a_bytes).unwrap();
    assert_eq!(decoded_a, package_a);
    let control_plane = signing_key(0x91);
    let manifest = sign_tenant_root_recovery_manifest_v1(
        descriptor,
        &package_a,
        &package_b,
        vec!["deriver-a-cert".to_owned()],
        vec!["deriver-b-cert".to_owned()],
        vec!["control-plane-cert".to_owned()],
        &control_plane.to_bytes(),
    )
    .unwrap();
    let trusted_keys = TenantRootRecoveryTrustedVerifyingKeysV1 {
        deriver_a: signing_a.verifying_key().to_bytes(),
        deriver_b: signing_b.verifying_key().to_bytes(),
        control_plane: control_plane.verifying_key().to_bytes(),
    };
    let opened_a = verify_and_open_tenant_root_recovery_role_package_v1(
        &manifest,
        &decoded_a,
        &recipient_a,
        &trusted_keys,
    )
    .unwrap();
    assert_eq!(opened_a.role(), TwoPartyDeriverRole::DeriverA);

    let opened_b = verify_and_open_tenant_root_recovery_role_package_v1(
        &manifest,
        &package_b,
        &recipient_b,
        &trusted_keys,
    )
    .unwrap();
    assert_eq!(opened_b.role(), TwoPartyDeriverRole::DeriverB);
    assert!(verify_and_open_tenant_root_recovery_role_package_v1(
        &manifest,
        &package_a,
        &recipient_b,
        &trusted_keys,
    )
    .is_err());

    let mut mutated = package_a_bytes.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 1;
    assert!(decode_tenant_root_recovery_package_v1(&mutated).is_ok());
    let mutated = decode_tenant_root_recovery_package_v1(&mutated).unwrap();
    assert!(manifest
        .verify_role_package(&mutated, &trusted_keys)
        .is_err());
}

#[test]
fn strict_binary_bounds_fail_closed() {
    let (_, package_a, _, _, _, _, _) = packages();
    let mut truncated = package_a.to_bytes().unwrap();
    truncated.pop();
    assert!(decode_tenant_root_recovery_package_v1(&truncated).is_err());

    let mut trailing = package_a.to_bytes().unwrap();
    trailing.push(0);
    assert!(decode_tenant_root_recovery_package_v1(&trailing).is_err());

    let oversized = vec![0_u8; 16 * 1024 + 1];
    assert!(decode_tenant_root_recovery_package_v1(&oversized).is_err());
}

#[test]
fn signed_manifest_binds_both_packages_and_requires_external_trust() {
    let (descriptor, package_a, package_b, _, _, signing_a, signing_b) = packages();
    let control_plane = signing_key(0x91);
    let manifest = sign_tenant_root_recovery_manifest_v1(
        descriptor.clone(),
        &package_a,
        &package_b,
        vec!["deriver-a-cert".to_owned()],
        vec!["deriver-b-cert".to_owned()],
        vec!["control-plane-cert".to_owned()],
        &control_plane.to_bytes(),
    )
    .expect("manifest");
    manifest
        .verify(control_plane.verifying_key().as_bytes())
        .unwrap();
    manifest
        .verify_packages(
            &package_a,
            &package_b,
            &router_ab_core::TenantRootRecoveryTrustedVerifyingKeysV1 {
                deriver_a: signing_a.verifying_key().to_bytes(),
                deriver_b: signing_b.verifying_key().to_bytes(),
                control_plane: control_plane.verifying_key().to_bytes(),
            },
        )
        .unwrap();

    let canonical = manifest.canonical_json().unwrap();
    assert_eq!(
        hex::encode(manifest.digest().unwrap()),
        "6a2d4119db1eb6973c9a524947357e0697aeb3038de759c156f555aec3735da3",
    );
    let decoded = decode_tenant_root_recovery_manifest_v1(&canonical).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(
        TenantRootRecoveryManifestV1::from_canonical_json(&canonical)
            .unwrap()
            .digest()
            .unwrap(),
        manifest.digest().unwrap()
    );
    assert!(manifest
        .verify(signing_key(0x92).verifying_key().as_bytes())
        .is_err());

    let mut trailing = canonical.clone();
    trailing.push(b' ');
    assert!(decode_tenant_root_recovery_manifest_v1(&trailing).is_err());

    let mut duplicate = canonical.strip_suffix(b"}").expect("object").to_vec();
    duplicate.extend_from_slice(b",\"formatVersion\":\"tenant_root_recovery_manifest_v1\"}");
    assert!(decode_tenant_root_recovery_manifest_v1(&duplicate).is_err());
}
