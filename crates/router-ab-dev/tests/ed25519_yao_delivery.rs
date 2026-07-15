use router_ab_dev::{
    derive_local_ed25519_yao_recipient_key_pair_v1,
    generate_local_ed25519_yao_recipient_key_pair_v1, open_local_ed25519_yao_client_package_v1,
    open_local_ed25519_yao_signing_worker_package_v1, seal_local_ed25519_yao_package_v1,
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoPackageKindV1,
};

fn tamper_ciphertext(package: &Ed25519YaoEncryptedPackageV1) -> Ed25519YaoEncryptedPackageV1 {
    let mut ciphertext = package.ciphertext().to_vec();
    ciphertext[0] ^= 1;
    Ed25519YaoEncryptedPackageV1::new(
        package.kind(),
        package.deriver(),
        package.session(),
        package.transcript(),
        *package.encapsulated_key(),
        ciphertext,
    )
    .expect("structurally valid tampered package")
}

#[test]
fn hpke_recipient_packages_open_only_at_the_intended_recipient() {
    let client = generate_local_ed25519_yao_recipient_key_pair_v1().expect("client key pair");
    let signing_worker =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("SigningWorker key pair");
    let plaintext = vec![0x42; 216];
    let client_envelope = seal_local_ed25519_yao_package_v1(
        Ed25519YaoPackageKindV1::ActivationClient,
        Ed25519YaoDeriverRoleV1::DeriverA,
        [0x51; 32],
        [0x61; 32],
        client.public_key,
        &plaintext,
    )
    .expect("Client HPKE seal");
    let worker_envelope = seal_local_ed25519_yao_package_v1(
        Ed25519YaoPackageKindV1::ActivationSigningWorker,
        Ed25519YaoDeriverRoleV1::DeriverA,
        [0x51; 32],
        [0x61; 32],
        signing_worker.public_key,
        &plaintext,
    )
    .expect("SigningWorker HPKE seal");

    assert_eq!(
        *open_local_ed25519_yao_client_package_v1(&client_envelope, &client.private_key)
            .expect("Client opens package"),
        plaintext
    );
    assert!(open_local_ed25519_yao_signing_worker_package_v1(
        &client_envelope,
        &signing_worker.private_key
    )
    .is_err());
    assert_eq!(
        *open_local_ed25519_yao_signing_worker_package_v1(
            &worker_envelope,
            &signing_worker.private_key,
        )
        .expect("SigningWorker opens package"),
        plaintext
    );
    assert!(
        open_local_ed25519_yao_client_package_v1(&worker_envelope, &client.private_key).is_err()
    );

    let tampered = tamper_ciphertext(&client_envelope);
    assert!(open_local_ed25519_yao_client_package_v1(&tampered, &client.private_key).is_err());
}

#[test]
fn deterministic_local_key_material_produces_one_stable_x25519_key_pair() {
    let first =
        derive_local_ed25519_yao_recipient_key_pair_v1(&[0x71; 32]).expect("first key pair");
    let second =
        derive_local_ed25519_yao_recipient_key_pair_v1(&[0x71; 32]).expect("second key pair");
    assert_eq!(first.public_key, second.public_key);
    assert_eq!(first.private_key.as_bytes(), second.private_key.as_bytes());
}
