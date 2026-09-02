use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    MpcPrfShareCommitmentWireV1, MpcPrfSigningRootShareWireV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCustodyLineageId, TenantRootIdentityV1, TenantRootManagedBackupBindingV1,
    TenantRootManagedBackupSealRequestV1, TenantRootManagedRestoreRoleV1, TenantRootShareEpoch,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedManagedBackupV1, TenantRootSignedShareInstallationEvidenceV1,
};
use threshold_prf::{
    prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment, SigningRootShareWire,
    TwoPartyDeriverRole,
};

const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;
const BACKUP_PROVIDER_ID: &str = "kms-provider-a";
const BACKUP_KEY_VERSION: &str = "kms-a/tenant-7/backup-epoch-8";
const ROLE_SIGNING_KEY_ID: &str = "deriver-a-signing-key-7";

fn identity(root_id: &str) -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", root_id, "v3").unwrap()
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).unwrap()
}

fn context(
    identity: &TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    epochs: TenantRootCeremonyEpochsV1,
    session_seed: u8,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity.digest().unwrap(),
        custody_lineage,
        epochs,
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap()
}

fn fixed_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .unwrap()
}

fn role_signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    SigningKey::from_bytes(
        &[match role {
            TwoPartyDeriverRole::DeriverA => 0x51,
            TwoPartyDeriverRole::DeriverB => 0x61,
        }; 32],
    )
}

#[allow(clippy::too_many_arguments)]
fn verified_evidence(
    identity: &TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    epochs: TenantRootCeremonyEpochsV1,
    role: TwoPartyDeriverRole,
    share_scalar: u64,
    peer_scalar: u64,
    session_seed: u8,
    proof_seed: u8,
) -> (
    router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    MpcPrfSigningRootShareWireV1,
    MpcPrfShareCommitmentWireV1,
) {
    let share = fixed_share(role, share_scalar);
    let peer = fixed_share(role.peer(), peer_scalar);
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context(identity, custody_lineage, epochs, session_seed),
        role,
        SigningRootShareCommitment::from_share(&share),
        SigningRootShareCommitment::from_share(&peer),
    )
    .unwrap();
    let proof = prove_root_share_knowledge(
        &share,
        &transcript.canonical_bytes().unwrap(),
        &mut ChaCha20Rng::from_seed([proof_seed; 32]),
    )
    .unwrap();
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap();
    let signing_key = role_signing_key(role);
    let signed =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes())
            .unwrap();
    let wire = signed.canonical_bytes().unwrap();
    let verified = TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &wire,
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap();
    (
        verified,
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

fn binding(
    evidence: &router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    backup_provider_id: &str,
    backup_key_version: &str,
    role_signing_key_id: &str,
    created_at_ms: u64,
) -> TenantRootManagedBackupBindingV1 {
    TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
        evidence,
        backup_provider_id,
        backup_key_version,
        role_signing_key_id,
        created_at_ms,
    )
    .unwrap()
}

#[test]
fn managed_backup_aad_receipt_and_restore_vector_is_frozen() {
    let tenant_identity = identity("root-main");
    let custody_lineage = lineage(0x31);
    let (evidence, share, commitment) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(7).unwrap(),
            TenantRootShareEpoch::new(8).unwrap(),
        )
        .unwrap(),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x21,
        0x33,
    );
    let binding = binding(
        &evidence,
        BACKUP_PROVIDER_ID,
        BACKUP_KEY_VERSION,
        ROLE_SIGNING_KEY_ID,
        ISSUED_AT_MS,
    );
    let source_digest = evidence.lifecycle_receipt_digest().unwrap();

    assert_eq!(binding.identity_digest(), tenant_identity.digest().unwrap());
    assert_eq!(binding.custody_lineage(), custody_lineage);
    assert_eq!(binding.role(), TenantRootManagedRestoreRoleV1::DeriverA);
    assert_eq!(binding.epoch(), TenantRootShareEpoch::new(8).unwrap());
    assert_eq!(binding.share_commitment(), &commitment);
    assert_eq!(binding.installation_receipt_digest(), source_digest);
    assert_eq!(binding.backup_provider_id(), BACKUP_PROVIDER_ID);
    assert_eq!(binding.backup_key_version(), BACKUP_KEY_VERSION);
    assert_eq!(binding.role_signing_key_id(), ROLE_SIGNING_KEY_ID);
    assert_eq!(binding.created_at_ms(), ISSUED_AT_MS);

    let opened_share = share.clone();
    let seal_request = TenantRootManagedBackupSealRequestV1::new(binding.clone(), share).unwrap();
    assert_eq!(
        seal_request.aad().unwrap(),
        binding.canonical_bytes().unwrap()
    );
    assert!(format!("{seal_request:?}").contains("[redacted]"));

    let signing_key = role_signing_key(TwoPartyDeriverRole::DeriverA);
    let artifact = TenantRootSignedManagedBackupV1::sign(
        seal_request,
        vec![0xa5; 96],
        &signing_key.to_bytes(),
    )
    .unwrap();
    let artifact_wire = artifact.canonical_bytes().unwrap();
    let decoded_artifact =
        TenantRootSignedManagedBackupV1::decode_canonical_bytes(&artifact_wire).unwrap();
    assert_eq!(decoded_artifact.canonical_bytes().unwrap(), artifact_wire);
    let mut noncanonical_artifact = artifact_wire.clone();
    noncanonical_artifact.push(0);
    assert!(
        TenantRootSignedManagedBackupV1::decode_canonical_bytes(&noncanonical_artifact).is_err()
    );
    let vector = format!(
        "{}:{}:{}",
        hex::encode(binding.digest().unwrap().as_bytes()),
        hex::encode(artifact.ciphertext_digest()),
        hex::encode(artifact.lifecycle_receipt_digest().unwrap().as_bytes()),
    );
    assert_eq!(
        vector,
        "f0e6d7f80a7b1d9abadbd305ce2c380fa0a5ae8c4652c0258fd7590c8d696129:\
         2ed3c3dd51931178fe1c751b6d6d158ce537da2e472ab3ce1f06391d8552e629:\
         91ffc40ac4508f2edafccc10f96d320846e4c7005ff91133feb602c0c342fb2e"
    );

    let verified = TenantRootSignedManagedBackupV1::decode_and_verify_canonical_bytes(
        &artifact_wire,
        &binding,
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap();
    assert_eq!(verified.binding(), &binding);
    assert_eq!(verified.installation_receipt_digest(), source_digest);
    assert_eq!(verified.canonical_bytes(), artifact_wire.as_slice());
    assert_eq!(verified.aad().unwrap(), binding.canonical_bytes().unwrap());
    assert_eq!(verified.ciphertext(), vec![0xa5; 96]);

    let restored = verified.verify_opened_share(opened_share).unwrap();
    assert_eq!(restored.binding(), &binding);
    assert_eq!(restored.role(), TenantRootManagedRestoreRoleV1::DeriverA);
    assert_eq!(restored.share().share_id(), 1);
    assert_eq!(restored.installation_receipt_digest(), source_digest);
    assert_eq!(
        restored.receipt_digest(),
        artifact.lifecycle_receipt_digest().unwrap(),
    );
}

#[test]
fn managed_backup_requires_strict_boundary_identifiers() {
    let tenant_identity = identity("root-main");
    let (evidence, _, _) = verified_evidence(
        &tenant_identity,
        lineage(0x31),
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(7).unwrap(),
            TenantRootShareEpoch::new(8).unwrap(),
        )
        .unwrap(),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x21,
        0x33,
    );

    assert!(
        TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
            &evidence,
            " provider-a",
            BACKUP_KEY_VERSION,
            ROLE_SIGNING_KEY_ID,
            ISSUED_AT_MS,
        )
        .is_err()
    );
    assert!(
        TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
            &evidence,
            BACKUP_PROVIDER_ID,
            "backup-key-v1\n",
            ROLE_SIGNING_KEY_ID,
            ISSUED_AT_MS,
        )
        .is_err()
    );
    assert!(
        TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
            &evidence,
            BACKUP_PROVIDER_ID,
            BACKUP_KEY_VERSION,
            "backup-signing-key\t",
            ISSUED_AT_MS,
        )
        .is_err()
    );
    let too_long = "x".repeat(257);
    assert!(
        TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
            &evidence,
            too_long,
            BACKUP_KEY_VERSION,
            ROLE_SIGNING_KEY_ID,
            ISSUED_AT_MS,
        )
        .is_err()
    );
}

#[test]
fn managed_backup_rejects_source_identity_lineage_role_epoch_commitment_and_digest_substitution() {
    let tenant_identity = identity("root-main");
    let custody_lineage = lineage(0x31);
    let epochs = TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(7).unwrap(),
        TenantRootShareEpoch::new(8).unwrap(),
    )
    .unwrap();
    let (evidence, share, _) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        epochs,
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x21,
        0x33,
    );
    let original_binding = binding(
        &evidence,
        BACKUP_PROVIDER_ID,
        BACKUP_KEY_VERSION,
        ROLE_SIGNING_KEY_ID,
        ISSUED_AT_MS,
    );
    let empty_ciphertext_share = share.clone();
    let signing_key = role_signing_key(TwoPartyDeriverRole::DeriverA);
    let artifact = TenantRootSignedManagedBackupV1::sign(
        TenantRootManagedBackupSealRequestV1::new(original_binding.clone(), share).unwrap(),
        vec![0xa5; 96],
        &signing_key.to_bytes(),
    )
    .unwrap();

    let (wrong_identity, _, _) = verified_evidence(
        &identity("root-other"),
        custody_lineage,
        epochs,
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x21,
        0x34,
    );
    let (wrong_lineage, _, _) = verified_evidence(
        &tenant_identity,
        lineage(0x32),
        epochs,
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x21,
        0x35,
    );
    let wrong_epochs = TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(8).unwrap(),
        TenantRootShareEpoch::new(9).unwrap(),
    )
    .unwrap();
    let (wrong_epoch, _, _) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        wrong_epochs,
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x22,
        0x36,
    );
    let (wrong_role, _, _) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        epochs,
        TwoPartyDeriverRole::DeriverB,
        19,
        12,
        0x23,
        0x37,
    );
    let (wrong_commitment, _, _) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        epochs,
        TwoPartyDeriverRole::DeriverA,
        13,
        19,
        0x24,
        0x38,
    );
    let (wrong_digest, _, _) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        epochs,
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x21,
        0x39,
    );
    let wrong_digest_binding = binding(
        &wrong_digest,
        BACKUP_PROVIDER_ID,
        BACKUP_KEY_VERSION,
        ROLE_SIGNING_KEY_ID,
        ISSUED_AT_MS,
    );
    assert_eq!(
        wrong_digest_binding.identity_digest(),
        original_binding.identity_digest()
    );
    assert_eq!(
        wrong_digest_binding.custody_lineage(),
        original_binding.custody_lineage()
    );
    assert_eq!(wrong_digest_binding.role(), original_binding.role());
    assert_eq!(wrong_digest_binding.epoch(), original_binding.epoch());
    assert_eq!(
        wrong_digest_binding.share_commitment(),
        original_binding.share_commitment()
    );
    assert_ne!(
        wrong_digest_binding.installation_receipt_digest(),
        original_binding.installation_receipt_digest(),
    );

    assert!(artifact
        .verify(
            &binding(
                &wrong_identity,
                BACKUP_PROVIDER_ID,
                BACKUP_KEY_VERSION,
                ROLE_SIGNING_KEY_ID,
                ISSUED_AT_MS,
            ),
            signing_key.verifying_key().as_bytes(),
        )
        .is_err());
    assert!(artifact
        .verify(
            &binding(
                &wrong_lineage,
                BACKUP_PROVIDER_ID,
                BACKUP_KEY_VERSION,
                ROLE_SIGNING_KEY_ID,
                ISSUED_AT_MS,
            ),
            signing_key.verifying_key().as_bytes(),
        )
        .is_err());
    assert!(artifact
        .verify(
            &binding(
                &wrong_epoch,
                BACKUP_PROVIDER_ID,
                BACKUP_KEY_VERSION,
                ROLE_SIGNING_KEY_ID,
                ISSUED_AT_MS,
            ),
            signing_key.verifying_key().as_bytes(),
        )
        .is_err());
    assert!(artifact
        .verify(
            &binding(
                &wrong_role,
                "kms-provider-b",
                "kms-b/tenant-7/backup-epoch-8",
                "deriver-b-signing-key-9",
                ISSUED_AT_MS,
            ),
            signing_key.verifying_key().as_bytes(),
        )
        .is_err());
    assert!(artifact
        .verify(
            &binding(
                &wrong_commitment,
                BACKUP_PROVIDER_ID,
                BACKUP_KEY_VERSION,
                ROLE_SIGNING_KEY_ID,
                ISSUED_AT_MS,
            ),
            signing_key.verifying_key().as_bytes(),
        )
        .is_err());
    assert!(artifact
        .verify(
            &wrong_digest_binding,
            signing_key.verifying_key().as_bytes(),
        )
        .is_err());

    let request =
        TenantRootManagedBackupSealRequestV1::new(original_binding, empty_ciphertext_share)
            .unwrap();
    assert!(
        TenantRootSignedManagedBackupV1::sign(request, Vec::new(), &signing_key.to_bytes())
            .is_err()
    );
}

#[test]
fn managed_backup_open_rejects_wrong_share_after_valid_provider_decryption() {
    let tenant_identity = identity("root-main");
    let custody_lineage = lineage(0x31);
    let epochs = TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(7).unwrap(),
        TenantRootShareEpoch::new(8).unwrap(),
    )
    .unwrap();
    let (evidence, share, _) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        epochs,
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x21,
        0x33,
    );
    let binding = binding(
        &evidence,
        BACKUP_PROVIDER_ID,
        BACKUP_KEY_VERSION,
        ROLE_SIGNING_KEY_ID,
        ISSUED_AT_MS,
    );
    let signing_key = role_signing_key(TwoPartyDeriverRole::DeriverA);
    let artifact = TenantRootSignedManagedBackupV1::sign(
        TenantRootManagedBackupSealRequestV1::new(binding.clone(), share).unwrap(),
        vec![0xa5; 96],
        &signing_key.to_bytes(),
    )
    .unwrap();
    let verified = artifact
        .verify(&binding, signing_key.verifying_key().as_bytes())
        .unwrap();
    assert_eq!(
        verified.installation_receipt_digest(),
        evidence.lifecycle_receipt_digest().unwrap(),
    );
    let (_, wrong_share, _) = verified_evidence(
        &tenant_identity,
        custody_lineage,
        epochs,
        TwoPartyDeriverRole::DeriverA,
        13,
        19,
        0x25,
        0x3a,
    );

    assert!(verified.verify_opened_share(wrong_share).is_err());
}
