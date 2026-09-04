use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    TenantRootAcceptedPermanentLossAuthorizationBindingV1, TenantRootActivationReceiptTransitionV1,
    TenantRootBackupPolicyV1, TenantRootCanaryCurveFamilyV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootManagedBackupBindingV1, TenantRootManagedBackupSealRequestV1,
    TenantRootProtocolDigestV1, TenantRootProviderCanaryReceiptBindingV1,
    TenantRootRoleInstallationReceiptsV1, TenantRootShareEpoch,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1, TenantRootSignedManagedBackupV1,
    TenantRootSignedProviderCanaryReceiptV1, TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
};
use threshold_prf::{
    prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment, SigningRootShareWire,
    TwoPartyDeriverRole,
};

const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;
const CANARY_SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];
const FIRST_AUTHORITY_KEY_BYTES: [u8; 32] = [0x41; 32];
const SECOND_AUTHORITY_KEY_BYTES: [u8; 32] = [0x42; 32];

fn identity() -> TenantRootIdentityDigestV1 {
    TenantRootIdentityDigestV1::from_bytes([0x11; 32])
}

fn lineage() -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage")
}

fn context(epochs: TenantRootCeremonyEpochsV1) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity(),
        lineage(),
        epochs,
        TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).expect("session"),
        TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("context")
}

fn role_signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    SigningKey::from_bytes(
        &[match role {
            TwoPartyDeriverRole::DeriverA => 0x51,
            TwoPartyDeriverRole::DeriverB => 0x61,
        }; 32],
    )
}

fn role_signing_key_id(role: TwoPartyDeriverRole) -> &'static str {
    match role {
        TwoPartyDeriverRole::DeriverA => "deriver-a-signing-key-7",
        TwoPartyDeriverRole::DeriverB => "deriver-b-signing-key-9",
    }
}

fn share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .expect("share")
}

fn commitments(a_scalar: u64, b_scalar: u64) -> TenantRootEpochCommitmentsV1 {
    TenantRootEpochCommitmentsV1::new(
        commitment(TwoPartyDeriverRole::DeriverA, a_scalar),
        commitment(TwoPartyDeriverRole::DeriverB, b_scalar),
    )
    .expect("commitments")
}

fn commitment(
    role: TwoPartyDeriverRole,
    scalar: u64,
) -> router_ab_core::MpcPrfShareCommitmentWireV1 {
    let share = share(role, scalar);
    router_ab_core::MpcPrfShareCommitmentWireV1::new(
        SigningRootShareCommitment::from_share(&share)
            .to_bytes()
            .to_vec(),
    )
    .expect("commitment")
}

fn installation(
    epochs: TenantRootCeremonyEpochsV1,
    role: TwoPartyDeriverRole,
    scalar: u64,
    peer_scalar: u64,
    proof_seed: u8,
) -> (
    router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    router_ab_core::MpcPrfSigningRootShareWireV1,
) {
    let signing_share = share(role, scalar);
    let peer = share(role.peer(), peer_scalar);
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context(epochs),
        role,
        SigningRootShareCommitment::from_share(&signing_share),
        SigningRootShareCommitment::from_share(&peer),
    )
    .expect("installation transcript");
    let proof = prove_root_share_knowledge(
        &signing_share,
        &transcript.canonical_bytes().expect("transcript bytes"),
        &mut ChaCha20Rng::from_seed([proof_seed; 32]),
    )
    .expect("knowledge proof");
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof)
        .expect("installation evidence");
    let signing_key = role_signing_key(role);
    let signed =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes())
            .expect("signed installation evidence");
    let bytes = signed.canonical_bytes().expect("installation bytes");
    let verified = TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &bytes,
        signing_key.verifying_key().as_bytes(),
    )
    .expect("verified installation evidence");
    let share_wire = router_ab_core::MpcPrfSigningRootShareWireV1::new(
        SigningRootShareWire::from_share(&signing_share)
            .to_bytes()
            .to_vec(),
    )
    .expect("share wire");
    (verified, share_wire)
}

fn managed_backup(
    installation: &router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    share: &router_ab_core::MpcPrfSigningRootShareWireV1,
    role: TwoPartyDeriverRole,
) -> router_ab_core::VerifiedTenantRootManagedBackupV1 {
    let binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
        installation,
        format!("kms/{}/epoch", role_signing_key_id(role)),
        format!("kms-key/{}/v1", role_signing_key_id(role)),
        role_signing_key_id(role),
        ISSUED_AT_MS,
    )
    .expect("backup binding");
    let request = TenantRootManagedBackupSealRequestV1::new(binding.clone(), share.clone())
        .expect("backup seal request");
    let signing_key = role_signing_key(role);
    let signed =
        TenantRootSignedManagedBackupV1::sign(request, vec![0xa5; 96], &signing_key.to_bytes())
            .expect("signed backup");
    signed
        .verify(&binding, signing_key.verifying_key().as_bytes())
        .expect("verified backup")
}

fn canary(
    epochs: TenantRootCeremonyEpochsV1,
    commitments: &TenantRootEpochCommitmentsV1,
    family: TenantRootCanaryCurveFamilyV1,
) -> router_ab_core::VerifiedTenantRootProviderCanaryReceiptV1 {
    let (transition, target_epoch) = match epochs {
        TenantRootCeremonyEpochsV1::Create { next } => (
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            next,
        ),
        TenantRootCeremonyEpochsV1::Refresh { next, .. } => {
            (TenantRootActivationReceiptTransitionV1::RefreshSwap, next)
        }
    };
    let binding = TenantRootProviderCanaryReceiptBindingV1::new(
        identity(),
        lineage(),
        transition,
        target_epoch,
        commitments.clone(),
        family,
        "kms/tenant-11/epoch",
        ISSUED_AT_MS + 10,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        "control-plane-canary-v1",
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
    )
    .expect("canary binding");
    let signed =
        TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &CANARY_SIGNING_KEY_BYTES)
            .expect("signed canary");
    signed
        .verify(
            &binding,
            &SigningKey::from_bytes(&CANARY_SIGNING_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        )
        .expect("verified canary")
}

fn accepted_loss(
    epochs: TenantRootCeremonyEpochsV1,
    target_commitments: &TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> router_ab_core::VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
    accepted_loss_with_scope(
        epochs,
        target_commitments,
        installation_receipts,
        context(epochs).digest().expect("context digest"),
        expected_control_plane_revision,
        result_control_plane_revision,
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
    )
}

fn accepted_loss_with_scope(
    epochs: TenantRootCeremonyEpochsV1,
    target_commitments: &TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    context_digest: TenantRootProtocolDigestV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> router_ab_core::VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
    let (transition, target_epoch) = match epochs {
        TenantRootCeremonyEpochsV1::Create { next } => (
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            next,
        ),
        TenantRootCeremonyEpochsV1::Refresh { next, .. } => {
            (TenantRootActivationReceiptTransitionV1::RefreshSwap, next)
        }
    };
    let binding = TenantRootAcceptedPermanentLossAuthorizationBindingV1::new(
        identity(),
        lineage(),
        transition,
        target_epoch,
        context_digest,
        target_commitments.clone(),
        installation_receipts,
        expected_control_plane_revision,
        result_control_plane_revision,
        "policy-accept-loss-001",
        "incident-2026-0001",
        "both managed backups are unavailable",
        issued_at_ms,
        expires_at_ms,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        "operator-a-v1",
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x72; 32]),
        "operator-b-v1",
    )
    .expect("accepted-loss binding");
    let signed = TenantRootSignedAcceptedPermanentLossAuthorizationV1::sign(
        binding.clone(),
        &FIRST_AUTHORITY_KEY_BYTES,
        &SECOND_AUTHORITY_KEY_BYTES,
    )
    .expect("signed accepted-loss authorization");
    signed
        .verify(
            &binding,
            &SigningKey::from_bytes(&FIRST_AUTHORITY_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
            &SigningKey::from_bytes(&SECOND_AUTHORITY_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        )
        .expect("verified accepted-loss authorization")
}

fn refresh_epochs() -> TenantRootCeremonyEpochsV1 {
    TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(7).expect("current epoch"),
        TenantRootShareEpoch::new(8).expect("next epoch"),
    )
    .expect("refresh epochs")
}

fn refresh_installation_receipts() -> TenantRootRoleInstallationReceiptsV1 {
    let epochs = refresh_epochs();
    let (installation_a, _) = installation(epochs, TwoPartyDeriverRole::DeriverA, 19, 33, 0x71);
    let (installation_b, _) = installation(epochs, TwoPartyDeriverRole::DeriverB, 33, 19, 0x81);
    TenantRootRoleInstallationReceiptsV1::new(
        installation_a
            .lifecycle_receipt_digest()
            .expect("installation receipt A"),
        installation_b
            .lifecycle_receipt_digest()
            .expect("installation receipt B"),
    )
    .expect("installation receipts")
}

fn refresh_bundle_with_authorization(
    authorization: router_ab_core::VerifiedTenantRootAcceptedPermanentLossAuthorizationV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> router_ab_core::RouterAbDerivationResult<VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1>
{
    let current = commitments(12, 19);
    let epochs = refresh_epochs();
    let next = commitments(19, 33);
    let (installation_a, _) = installation(epochs, TwoPartyDeriverRole::DeriverA, 19, 33, 0x71);
    let (installation_b, _) = installation(epochs, TwoPartyDeriverRole::DeriverB, 33, 19, 0x81);
    let ecdsa = canary(epochs, &next, TenantRootCanaryCurveFamilyV1::Ecdsa);
    let ed25519 = canary(epochs, &next, TenantRootCanaryCurveFamilyV1::Ed25519);
    VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_accepted_loss(
        &current,
        installation_a,
        installation_b,
        authorization,
        ecdsa,
        ed25519,
        expected_control_plane_revision,
        result_control_plane_revision,
    )
}

#[test]
fn initial_creation_bundle_derives_strict_projections_and_consumes_installation_wires() {
    let epochs = TenantRootCeremonyEpochsV1::create();
    let expected_commitments = commitments(12, 19);
    let (installation_a, share_a) =
        installation(epochs, TwoPartyDeriverRole::DeriverA, 12, 19, 0x51);
    let (installation_b, share_b) =
        installation(epochs, TwoPartyDeriverRole::DeriverB, 19, 12, 0x61);
    let installation_a_bytes = installation_a.canonical_bytes().to_vec();
    let installation_b_bytes = installation_b.canonical_bytes().to_vec();
    let backup_a = managed_backup(&installation_a, &share_a, TwoPartyDeriverRole::DeriverA);
    let backup_b = managed_backup(&installation_b, &share_b, TwoPartyDeriverRole::DeriverB);
    let backup_a_receipt = backup_a.receipt_digest();
    let backup_b_receipt = backup_b.receipt_digest();
    let ecdsa = canary(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
    );
    let ed25519 = canary(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ed25519,
    );

    let bundle =
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            ecdsa,
            ed25519,
            2,
            3,
        )
        .expect("initial activation evidence bundle");

    assert_eq!(
        bundle.transition(),
        TenantRootActivationReceiptTransitionV1::InitialCreation
    );
    assert_eq!(bundle.epochs(), epochs);
    assert_eq!(bundle.epoch(), TenantRootShareEpoch::INITIAL);
    assert_eq!(bundle.identity_digest(), identity());
    assert_eq!(bundle.custody_lineage(), lineage());
    assert_eq!(
        bundle.context_digest(),
        context(epochs).digest().expect("context digest")
    );
    assert_eq!(bundle.commitments(), &expected_commitments);
    assert_eq!(
        bundle.root_commitment(),
        expected_commitments.root_commitment()
    );
    assert_eq!(
        bundle.backup_policy(),
        TenantRootBackupPolicyV1::CurrentRoleBackups(
            router_ab_core::TenantRootRoleBackupReceiptsV1::new(backup_a_receipt, backup_b_receipt)
                .expect("backup receipts"),
        )
    );
    assert_eq!(
        *bundle.canary_receipts().ecdsa().as_bytes(),
        ecdsa_digest(&bundle)
    );
    bundle
        .require_fresh(ISSUED_AT_MS + 10)
        .expect("fresh bundle");

    let (actual_a_bytes, actual_b_bytes) = bundle.into_installation_evidence_bytes();
    assert_eq!(actual_a_bytes, installation_a_bytes);
    assert_eq!(actual_b_bytes, installation_b_bytes);
}

#[test]
fn refresh_bundle_derives_root_continuity_and_accepted_loss_projection() {
    let current = commitments(12, 19);
    let epochs = TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(7).expect("current epoch"),
        TenantRootShareEpoch::new(8).expect("next epoch"),
    )
    .expect("refresh epochs");
    let next = commitments(19, 33);
    let (installation_a, _) = installation(epochs, TwoPartyDeriverRole::DeriverA, 19, 33, 0x71);
    let (installation_b, _) = installation(epochs, TwoPartyDeriverRole::DeriverB, 33, 19, 0x81);
    let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
        installation_a
            .lifecycle_receipt_digest()
            .expect("installation receipt A"),
        installation_b
            .lifecycle_receipt_digest()
            .expect("installation receipt B"),
    )
    .expect("installation receipts");
    let authorization = accepted_loss(epochs, &next, installation_receipts, 11, 12);
    let authorization_bytes = authorization.canonical_bytes().to_vec();
    let authorization_digest = authorization.digest();
    let ecdsa = canary(epochs, &next, TenantRootCanaryCurveFamilyV1::Ecdsa);
    let ed25519 = canary(epochs, &next, TenantRootCanaryCurveFamilyV1::Ed25519);

    let bundle =
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_accepted_loss(
            &current,
            installation_a,
            installation_b,
            authorization,
            ecdsa,
            ed25519,
            11,
            12,
        )
        .expect("refresh activation evidence bundle");

    assert_eq!(
        bundle.transition(),
        TenantRootActivationReceiptTransitionV1::RefreshSwap
    );
    assert_eq!(
        bundle.current_epoch(),
        TenantRootShareEpoch::new(7).expect("current epoch")
    );
    assert_eq!(
        bundle.next_epoch(),
        TenantRootShareEpoch::new(8).expect("next epoch")
    );
    assert_eq!(bundle.current_commitments(), &current);
    assert_eq!(bundle.next_commitments(), &next);
    assert_eq!(bundle.root_commitment(), current.root_commitment());
    assert_eq!(
        bundle.context_digest(),
        context(epochs).digest().expect("context digest")
    );
    let TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(receipt) = bundle.backup_policy()
    else {
        panic!("expected accepted-loss backup policy");
    };
    assert_eq!(
        receipt.authorization_bytes(),
        authorization_bytes.as_slice()
    );
    assert_eq!(receipt.authorization_digest(), &authorization_digest);
    assert!(matches!(
        bundle.availability(),
        router_ab_core::TenantRootActivationAvailabilityEvidenceViewV1::AcceptedPermanentDerivationLoss {
            ..
        }
    ));
    bundle
        .require_fresh(ISSUED_AT_MS + 10)
        .expect("fresh bundle");
}

#[test]
fn accepted_loss_bundle_rejects_scope_replays() {
    let epochs = refresh_epochs();
    let next = commitments(19, 33);
    let installation_receipts = refresh_installation_receipts();
    let cases = [
        (
            "context",
            accepted_loss_with_scope(
                epochs,
                &next,
                installation_receipts,
                TenantRootProtocolDigestV1::from_bytes([0x56; 32]).expect("context digest"),
                11,
                12,
                ISSUED_AT_MS,
                EXPIRES_AT_MS,
            ),
        ),
        (
            "deriver A commitment",
            accepted_loss_with_scope(
                epochs,
                &commitments(20, 33),
                installation_receipts,
                context(epochs).digest().expect("context digest"),
                11,
                12,
                ISSUED_AT_MS,
                EXPIRES_AT_MS,
            ),
        ),
        (
            "deriver B commitment",
            accepted_loss_with_scope(
                epochs,
                &commitments(19, 34),
                installation_receipts,
                context(epochs).digest().expect("context digest"),
                11,
                12,
                ISSUED_AT_MS,
                EXPIRES_AT_MS,
            ),
        ),
        (
            "deriver A installation receipt",
            accepted_loss_with_scope(
                epochs,
                &next,
                TenantRootRoleInstallationReceiptsV1::new(
                    TenantRootLifecycleReceiptDigestV1::from_bytes([0x91; 32]).expect("receipt A"),
                    installation_receipts.deriver_b(),
                )
                .expect("installation receipts"),
                context(epochs).digest().expect("context digest"),
                11,
                12,
                ISSUED_AT_MS,
                EXPIRES_AT_MS,
            ),
        ),
        (
            "deriver B installation receipt",
            accepted_loss_with_scope(
                epochs,
                &next,
                TenantRootRoleInstallationReceiptsV1::new(
                    installation_receipts.deriver_a(),
                    TenantRootLifecycleReceiptDigestV1::from_bytes([0x92; 32]).expect("receipt B"),
                )
                .expect("installation receipts"),
                context(epochs).digest().expect("context digest"),
                11,
                12,
                ISSUED_AT_MS,
                EXPIRES_AT_MS,
            ),
        ),
        (
            "authorization revisions",
            accepted_loss_with_scope(
                epochs,
                &next,
                installation_receipts,
                context(epochs).digest().expect("context digest"),
                12,
                13,
                ISSUED_AT_MS,
                EXPIRES_AT_MS,
            ),
        ),
        (
            "authorization issue time",
            accepted_loss_with_scope(
                epochs,
                &next,
                installation_receipts,
                context(epochs).digest().expect("context digest"),
                11,
                12,
                ISSUED_AT_MS + 1,
                EXPIRES_AT_MS + 1,
            ),
        ),
        (
            "authorization expiry time",
            accepted_loss_with_scope(
                epochs,
                &next,
                installation_receipts,
                context(epochs).digest().expect("context digest"),
                11,
                12,
                ISSUED_AT_MS,
                EXPIRES_AT_MS - 1,
            ),
        ),
    ];
    for (label, authorization) in cases {
        assert!(
            refresh_bundle_with_authorization(authorization, 11, 12).is_err(),
            "{label} must remain bound to the exact refresh ceremony"
        );
    }

    assert!(
        refresh_bundle_with_authorization(
            accepted_loss(epochs, &next, installation_receipts, 11, 12,),
            10,
            11,
        )
        .is_err(),
        "the expected lifecycle revision must be part of the activation claim"
    );
    assert!(
        refresh_bundle_with_authorization(
            accepted_loss(epochs, &next, installation_receipts, 11, 12,),
            11,
            13,
        )
        .is_err(),
        "the result lifecycle revision must be part of the activation claim"
    );
}

#[test]
fn bundle_rejects_installation_source_digest_and_canary_family_substitution() {
    let epochs = TenantRootCeremonyEpochsV1::create();
    let expected_commitments = commitments(12, 19);
    let (original_a, share_a) = installation(epochs, TwoPartyDeriverRole::DeriverA, 12, 19, 0x91);
    let (installation_b, share_b) =
        installation(epochs, TwoPartyDeriverRole::DeriverB, 19, 12, 0xa1);
    let backup_a = managed_backup(&original_a, &share_a, TwoPartyDeriverRole::DeriverA);
    let backup_b = managed_backup(&installation_b, &share_b, TwoPartyDeriverRole::DeriverB);
    let ecdsa = canary(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
    );
    let ed25519 = canary(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ed25519,
    );
    let (substituted_a, _) = installation(epochs, TwoPartyDeriverRole::DeriverA, 12, 19, 0xb1);

    assert!(
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            substituted_a,
            installation_b,
            backup_a,
            backup_b,
            ecdsa,
            ed25519,
            2,
            3,
        )
        .is_err(),
        "backup provenance must follow the exact installation wire digest"
    );

    let (installation_a, share_a) =
        installation(epochs, TwoPartyDeriverRole::DeriverA, 12, 19, 0xc1);
    let (installation_b, share_b) =
        installation(epochs, TwoPartyDeriverRole::DeriverB, 19, 12, 0xd1);
    let backup_a = managed_backup(&installation_a, &share_a, TwoPartyDeriverRole::DeriverA);
    let backup_b = managed_backup(&installation_b, &share_b, TwoPartyDeriverRole::DeriverB);
    let ecdsa = canary(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
    );
    let wrong_family = canary(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
    );
    assert!(
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            ecdsa,
            wrong_family,
            2,
            3,
        )
        .is_err(),
        "the second provider canary must be Ed25519"
    );
}

fn ecdsa_digest(bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1) -> [u8; 32] {
    match bundle.availability() {
        router_ab_core::TenantRootActivationAvailabilityEvidenceViewV1::CurrentRoleBackups {
            ..
        } => *bundle.canary_receipts().ecdsa().as_bytes(),
        router_ab_core::TenantRootActivationAvailabilityEvidenceViewV1::AcceptedPermanentDerivationLoss {
            ..
        } => unreachable!("initial test uses managed backups"),
    }
}
