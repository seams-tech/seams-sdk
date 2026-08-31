use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use router_ab_core::{
    MpcPrfShareCommitmentWireV1, MpcPrfSigningRootShareWireV1, TenantRootCustodyLineageId,
    TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedBackupBindingV1,
    TenantRootManagedBackupSealRequestV1, TenantRootManagedRestoreRoleV1, TenantRootShareEpoch,
    TenantRootSignedManagedBackupV1,
};
use threshold_prf::{
    SigningRootShare, SigningRootShareCommitment, SigningRootShareWire, ThresholdShareId,
};

fn share_and_commitment(
    share_id: u16,
    scalar: u64,
) -> (MpcPrfSigningRootShareWireV1, MpcPrfShareCommitmentWireV1) {
    let share = SigningRootShare::from_canonical_bytes(
        ThresholdShareId::from_u16(share_id).unwrap(),
        Scalar::from(scalar).to_bytes(),
    )
    .unwrap();
    (
        MpcPrfSigningRootShareWireV1::new(
            SigningRootShareWire::from_share(&share).to_bytes().to_vec(),
        )
        .unwrap(),
        MpcPrfShareCommitmentWireV1::new(
            SigningRootShareCommitment::from_share(&share)
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
    )
}

fn identity_digest(root_id: &str) -> router_ab_core::TenantRootIdentityDigestV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", root_id, "v3")
        .unwrap()
        .digest()
        .unwrap()
}

fn receipt(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).unwrap()
}

fn binding(
    identity: router_ab_core::TenantRootIdentityDigestV1,
    epoch: u64,
    commitment: MpcPrfShareCommitmentWireV1,
) -> TenantRootManagedBackupBindingV1 {
    TenantRootManagedBackupBindingV1::new(
        identity,
        TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap(),
        TenantRootManagedRestoreRoleV1::DeriverA,
        TenantRootShareEpoch::new(epoch).unwrap(),
        commitment,
        receipt(0x44),
        "kms-a/tenant-7/backup-epoch-8",
        "deriver-a-signing-key-7",
        1_000_000,
    )
    .unwrap()
}

#[test]
fn managed_backup_aad_receipt_and_restore_vector_is_frozen() {
    let (share, commitment) = share_and_commitment(1, 12);
    let binding = binding(identity_digest("root-main"), 8, commitment);
    let signing_key = SigningKey::from_bytes(&[0x51; 32]);
    let seal_request = TenantRootManagedBackupSealRequestV1::new(binding.clone(), share).unwrap();

    assert_eq!(
        seal_request.aad().unwrap(),
        binding.canonical_bytes().unwrap()
    );
    assert!(format!("{seal_request:?}").contains("[redacted]"));

    let artifact = TenantRootSignedManagedBackupV1::sign(
        seal_request,
        vec![0xa5; 96],
        &signing_key.to_bytes(),
    )
    .unwrap();
    let vector = format!(
        "{}:{}:{}",
        hex::encode(binding.digest().unwrap().as_bytes()),
        hex::encode(artifact.ciphertext_digest()),
        hex::encode(artifact.lifecycle_receipt_digest().unwrap().as_bytes()),
    );
    assert_eq!(
        vector,
        "c6293904d5ffb21b620016cac6a73c40728a61214b67b0d2776a679869d3cba1:\
         2ed3c3dd51931178fe1c751b6d6d158ce537da2e472ab3ce1f06391d8552e629:\
         72566c796c1bf4ca81ab241696a122908ba92af0227ceb4d126623bb047bceb5"
    );

    let verified = artifact
        .verify(&binding, signing_key.verifying_key().as_bytes())
        .unwrap();
    assert_eq!(verified.aad().unwrap(), binding.canonical_bytes().unwrap());
    assert_eq!(verified.ciphertext(), vec![0xa5; 96]);

    let (opened_share, _) = share_and_commitment(1, 12);
    let restored = verified.verify_opened_share(opened_share).unwrap();
    assert_eq!(restored.role(), TenantRootManagedRestoreRoleV1::DeriverA);
    assert_eq!(restored.share().share_id(), 1);
    assert_eq!(
        restored.receipt_digest(),
        artifact.lifecycle_receipt_digest().unwrap(),
    );
}

#[test]
fn managed_backup_rejects_role_binding_and_signature_substitution() {
    let (share, commitment) = share_and_commitment(1, 12);
    assert!(TenantRootManagedBackupBindingV1::new(
        identity_digest("root-main"),
        TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap(),
        TenantRootManagedRestoreRoleV1::DeriverB,
        TenantRootShareEpoch::new(8).unwrap(),
        commitment.clone(),
        receipt(0x44),
        "kms-b/tenant-7/backup-epoch-8",
        "deriver-b-signing-key-9",
        1_000_000,
    )
    .is_err());

    let original_binding = binding(identity_digest("root-main"), 8, commitment.clone());
    let signing_key = SigningKey::from_bytes(&[0x51; 32]);
    let artifact = TenantRootSignedManagedBackupV1::sign(
        TenantRootManagedBackupSealRequestV1::new(original_binding.clone(), share).unwrap(),
        vec![0xa5; 96],
        &signing_key.to_bytes(),
    )
    .unwrap();
    let wrong_binding = binding(identity_digest("root-other"), 8, commitment.clone());
    let wrong_epoch = binding(identity_digest("root-main"), 9, commitment);
    let wrong_key = SigningKey::from_bytes(&[0x52; 32]);

    assert!(artifact
        .verify(&wrong_binding, signing_key.verifying_key().as_bytes())
        .is_err());
    assert!(artifact
        .verify(&wrong_epoch, signing_key.verifying_key().as_bytes())
        .is_err());
    assert!(artifact
        .verify(&original_binding, wrong_key.verifying_key().as_bytes())
        .is_err());

    let (share, _) = share_and_commitment(1, 12);
    let request = TenantRootManagedBackupSealRequestV1::new(original_binding, share).unwrap();
    assert!(
        TenantRootSignedManagedBackupV1::sign(request, Vec::new(), &signing_key.to_bytes())
            .is_err()
    );
}

#[test]
fn managed_backup_open_rejects_wrong_share_after_valid_provider_decryption() {
    let (share, commitment) = share_and_commitment(1, 12);
    let binding = binding(identity_digest("root-main"), 8, commitment);
    let signing_key = SigningKey::from_bytes(&[0x51; 32]);
    let artifact = TenantRootSignedManagedBackupV1::sign(
        TenantRootManagedBackupSealRequestV1::new(binding.clone(), share).unwrap(),
        vec![0xa5; 96],
        &signing_key.to_bytes(),
    )
    .unwrap();
    let verified = artifact
        .verify(&binding, signing_key.verifying_key().as_bytes())
        .unwrap();
    let (wrong_share, _) = share_and_commitment(1, 13);

    assert!(verified.verify_opened_share(wrong_share).is_err());
}
