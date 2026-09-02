use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    MpcPrfShareCommitmentWireV1, MpcPrfSigningRootShareWireV1, RouterAbDerivationErrorCode,
    TenantRootAcceptedPermanentLossAuthorizationBindingV1,
    TenantRootActivationReceiptAvailabilityV1, TenantRootActivationReceiptTransitionV1,
    TenantRootCanaryCurveFamilyV1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootControlPlaneAuthorityIdV1,
    TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1,
    TenantRootManagedBackupBindingV1, TenantRootManagedBackupSealRequestV1,
    TenantRootProtocolDigestV1, TenantRootProviderCanaryReceiptBindingV1,
    TenantRootRoleInstallationReceiptsV1, TenantRootShareEpoch,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1, TenantRootSignedActivationReceiptV1,
    TenantRootSignedManagedBackupV1, TenantRootSignedProviderCanaryReceiptV1,
    TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1,
    TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1,
    TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{
    prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment, SigningRootShareWire,
    TwoPartyDeriverRole,
};

const ISSUER_KEY_BYTES: [u8; 32] = [0x41; 32];
const ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const ISSUE_TIME_MS: u64 = 1_000_000;
const ACTIVATION_TIME_MS: u64 = 1_000_010;
const EXPIRY_TIME_MS: u64 = 1_030_000;
const CANARY_SIGNING_KEY_BYTES: [u8; 32] = [0x51; 32];
const FIRST_AUTHORITY_KEY_BYTES: [u8; 32] = [0x61; 32];
const SECOND_AUTHORITY_KEY_BYTES: [u8; 32] = [0x62; 32];

fn identity() -> TenantRootIdentityDigestV1 {
    identity_with(0x11)
}

fn lineage() -> TenantRootCustodyLineageId {
    lineage_with(0x22)
}

fn identity_with(value: u8) -> TenantRootIdentityDigestV1 {
    TenantRootIdentityDigestV1::from_bytes([value; 32])
}

fn lineage_with(value: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([value; 16]).expect("lineage")
}

fn context_with(
    epochs: TenantRootCeremonyEpochsV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    session_byte: u8,
    nonce_byte: u8,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity_digest,
        custody_lineage,
        epochs,
        TenantRootCeremonySessionIdV1::from_bytes([session_byte; 16]).expect("session"),
        TenantRootCeremonyNonceV1::from_bytes([nonce_byte; 32]).expect("nonce"),
        ISSUE_TIME_MS,
        EXPIRY_TIME_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("context")
}

fn share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .expect("share")
}

fn commitment(role: TwoPartyDeriverRole, scalar: u64) -> MpcPrfShareCommitmentWireV1 {
    MpcPrfShareCommitmentWireV1::new(
        SigningRootShareCommitment::from_share(&share(role, scalar))
            .to_bytes()
            .to_vec(),
    )
    .expect("commitment")
}

fn commitments(a_scalar: u64, b_scalar: u64) -> TenantRootEpochCommitmentsV1 {
    TenantRootEpochCommitmentsV1::new(
        commitment(TwoPartyDeriverRole::DeriverA, a_scalar),
        commitment(TwoPartyDeriverRole::DeriverB, b_scalar),
    )
    .expect("commitments")
}

fn role_signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    SigningKey::from_bytes(
        &[match role {
            TwoPartyDeriverRole::DeriverA => 0x71,
            TwoPartyDeriverRole::DeriverB => 0x72,
        }; 32],
    )
}

fn role_signing_key_id(role: TwoPartyDeriverRole) -> &'static str {
    match role {
        TwoPartyDeriverRole::DeriverA => "deriver-a-signing-key-7",
        TwoPartyDeriverRole::DeriverB => "deriver-b-signing-key-9",
    }
}

fn installation(
    epochs: TenantRootCeremonyEpochsV1,
    role: TwoPartyDeriverRole,
    scalar: u64,
    peer_scalar: u64,
    proof_seed: u8,
) -> (
    router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    MpcPrfSigningRootShareWireV1,
) {
    installation_with_scope(
        epochs,
        role,
        scalar,
        peer_scalar,
        proof_seed,
        identity(),
        lineage(),
        0x33,
        0x44,
    )
}

fn installation_with_scope(
    epochs: TenantRootCeremonyEpochsV1,
    role: TwoPartyDeriverRole,
    scalar: u64,
    peer_scalar: u64,
    proof_seed: u8,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    session_byte: u8,
    nonce_byte: u8,
) -> (
    router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    MpcPrfSigningRootShareWireV1,
) {
    let signing_share = share(role, scalar);
    let peer = share(role.peer(), peer_scalar);
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context_with(
            epochs,
            identity_digest,
            custody_lineage,
            session_byte,
            nonce_byte,
        ),
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
    let share_wire = MpcPrfSigningRootShareWireV1::new(
        SigningRootShareWire::from_share(&signing_share)
            .to_bytes()
            .to_vec(),
    )
    .expect("share wire");
    (verified, share_wire)
}

fn managed_backup(
    installation: &router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    share: &MpcPrfSigningRootShareWireV1,
    role: TwoPartyDeriverRole,
) -> router_ab_core::VerifiedTenantRootManagedBackupV1 {
    managed_backup_with_fields(
        installation,
        share,
        role,
        &format!("backup-provider-{}", role_signing_key_id(role)),
        &format!("kms/{}/epoch", role_signing_key_id(role)),
        role_signing_key_id(role),
    )
}

fn managed_backup_with_fields(
    installation: &router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    share: &MpcPrfSigningRootShareWireV1,
    role: TwoPartyDeriverRole,
    backup_provider_id: &str,
    backup_key_version: &str,
    role_signing_key_id: &str,
) -> router_ab_core::VerifiedTenantRootManagedBackupV1 {
    let binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
        installation,
        backup_provider_id,
        backup_key_version,
        role_signing_key_id,
        ISSUE_TIME_MS,
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
    canary_with_scope(epochs, commitments, family, identity(), lineage())
}

fn canary_with_scope(
    epochs: TenantRootCeremonyEpochsV1,
    commitments: &TenantRootEpochCommitmentsV1,
    family: TenantRootCanaryCurveFamilyV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
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
        identity_digest,
        custody_lineage,
        transition,
        target_epoch,
        commitments.clone(),
        family,
        "kms/tenant-11/epoch",
        ISSUE_TIME_MS + 10,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        "control-plane-canary-v1",
        ISSUE_TIME_MS,
        EXPIRY_TIME_MS,
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

fn accepted_loss_for_scope(
    epochs: TenantRootCeremonyEpochsV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    context_digest: TenantRootProtocolDigestV1,
    commitments: &TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
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
        identity_digest,
        custody_lineage,
        transition,
        target_epoch,
        context_digest,
        commitments.clone(),
        installation_receipts,
        expected_control_plane_revision,
        result_control_plane_revision,
        "policy-accept-loss-001",
        "incident-2026-0001",
        "both managed backups are unavailable",
        ISSUE_TIME_MS,
        EXPIRY_TIME_MS,
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

fn creation_bundle(
    accepted_loss_branch: bool,
) -> VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
    creation_bundle_with_scope(
        accepted_loss_branch,
        identity(),
        lineage(),
        0x33,
        0x44,
        0x51,
        0x61,
    )
}

fn creation_bundle_with_revisions(
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
    creation_bundle_with_scope_and_commitments(
        false,
        identity(),
        lineage(),
        0x33,
        0x44,
        0x51,
        0x61,
        12,
        19,
        expected_control_plane_revision,
        result_control_plane_revision,
    )
}

fn creation_bundle_with_scope(
    accepted_loss_branch: bool,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    session_byte: u8,
    nonce_byte: u8,
    deriver_a_proof_seed: u8,
    deriver_b_proof_seed: u8,
) -> VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
    creation_bundle_with_scope_and_commitments(
        accepted_loss_branch,
        identity_digest,
        custody_lineage,
        session_byte,
        nonce_byte,
        deriver_a_proof_seed,
        deriver_b_proof_seed,
        12,
        19,
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1,
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1,
    )
}

fn creation_bundle_with_scope_and_commitments(
    accepted_loss_branch: bool,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    session_byte: u8,
    nonce_byte: u8,
    deriver_a_proof_seed: u8,
    deriver_b_proof_seed: u8,
    deriver_a_scalar: u64,
    deriver_b_scalar: u64,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
    let epochs = TenantRootCeremonyEpochsV1::create();
    let expected_commitments = commitments(deriver_a_scalar, deriver_b_scalar);
    let (installation_a, share_a) = installation_with_scope(
        epochs,
        TwoPartyDeriverRole::DeriverA,
        deriver_a_scalar,
        deriver_b_scalar,
        deriver_a_proof_seed,
        identity_digest,
        custody_lineage,
        session_byte,
        nonce_byte,
    );
    let (installation_b, share_b) = installation_with_scope(
        epochs,
        TwoPartyDeriverRole::DeriverB,
        deriver_b_scalar,
        deriver_a_scalar,
        deriver_b_proof_seed,
        identity_digest,
        custody_lineage,
        session_byte,
        nonce_byte,
    );
    let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
        installation_a
            .lifecycle_receipt_digest()
            .expect("deriver A installation receipt"),
        installation_b
            .lifecycle_receipt_digest()
            .expect("deriver B installation receipt"),
    )
    .expect("installation receipts");
    let context_digest = installation_a
        .evidence()
        .transcript()
        .context()
        .digest()
        .expect("context digest");
    let backup_a = managed_backup(&installation_a, &share_a, TwoPartyDeriverRole::DeriverA);
    let backup_b = managed_backup(&installation_b, &share_b, TwoPartyDeriverRole::DeriverB);
    let ecdsa = canary_with_scope(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
        identity_digest,
        custody_lineage,
    );
    let ed25519 = canary_with_scope(
        epochs,
        &expected_commitments,
        TenantRootCanaryCurveFamilyV1::Ed25519,
        identity_digest,
        custody_lineage,
    );
    if accepted_loss_branch {
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_accepted_loss(
            installation_a,
            installation_b,
            accepted_loss_for_scope(
                epochs,
                identity_digest,
                custody_lineage,
                context_digest,
                &expected_commitments,
                installation_receipts,
                expected_control_plane_revision,
                result_control_plane_revision,
            ),
            ecdsa,
            ed25519,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
        .expect("initial accepted-loss evidence bundle")
    } else {
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            ecdsa,
            ed25519,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
        .expect("initial managed-backup evidence bundle")
    }
}

fn creation_bundle_with_shared_backup_key_version() -> router_ab_core::RouterAbDerivationResult<
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
> {
    creation_bundle_with_backup_fields(
        "backup-provider-a",
        "backup-provider-b",
        "kms/shared-version",
        "kms/shared-version",
        role_signing_key_id(TwoPartyDeriverRole::DeriverA),
        role_signing_key_id(TwoPartyDeriverRole::DeriverB),
    )
}

fn creation_bundle_with_shared_backup_provider() -> router_ab_core::RouterAbDerivationResult<
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
> {
    creation_bundle_with_backup_fields(
        "backup-provider-shared",
        "backup-provider-shared",
        "kms/deriver-a-epoch",
        "kms/deriver-b-epoch",
        role_signing_key_id(TwoPartyDeriverRole::DeriverA),
        role_signing_key_id(TwoPartyDeriverRole::DeriverB),
    )
}

fn creation_bundle_with_shared_backup_authority() -> router_ab_core::RouterAbDerivationResult<
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
> {
    creation_bundle_with_backup_fields(
        "backup-provider-a",
        "backup-provider-b",
        "kms/deriver-a-epoch",
        "kms/deriver-b-epoch",
        "shared-role-signing-key",
        "shared-role-signing-key",
    )
}

fn creation_bundle_with_backup_fields(
    backup_provider_a: &str,
    backup_provider_b: &str,
    backup_key_version_a: &str,
    backup_key_version_b: &str,
    role_signing_key_id_a: &str,
    role_signing_key_id_b: &str,
) -> router_ab_core::RouterAbDerivationResult<
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
> {
    let epochs = TenantRootCeremonyEpochsV1::create();
    let expected_commitments = commitments(12, 19);
    let (installation_a, share_a) =
        installation(epochs, TwoPartyDeriverRole::DeriverA, 12, 19, 0x51);
    let (installation_b, share_b) =
        installation(epochs, TwoPartyDeriverRole::DeriverB, 19, 12, 0x61);
    let backup_a = managed_backup_with_fields(
        &installation_a,
        &share_a,
        TwoPartyDeriverRole::DeriverA,
        backup_provider_a,
        backup_key_version_a,
        role_signing_key_id_a,
    );
    let backup_b = managed_backup_with_fields(
        &installation_b,
        &share_b,
        TwoPartyDeriverRole::DeriverB,
        backup_provider_b,
        backup_key_version_b,
        role_signing_key_id_b,
    );
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
        installation_a,
        installation_b,
        backup_a,
        backup_b,
        canary(
            epochs,
            &expected_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
        ),
        canary(
            epochs,
            &expected_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
        ),
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1,
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1,
    )
}

fn refresh_bundle(
    accepted_loss_branch: bool,
) -> VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1 {
    refresh_bundle_with_revisions(accepted_loss_branch, 5, 6).expect("refresh evidence bundle")
}

fn refresh_bundle_with_revisions(
    accepted_loss_branch: bool,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
) -> router_ab_core::RouterAbDerivationResult<VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1>
{
    let current = commitments(12, 19);
    let epochs = TenantRootCeremonyEpochsV1::refresh(
        TenantRootShareEpoch::new(7).expect("current epoch"),
        TenantRootShareEpoch::new(8).expect("next epoch"),
    )
    .expect("refresh epochs");
    let next = commitments(19, 33);
    let (installation_a, share_a) =
        installation(epochs, TwoPartyDeriverRole::DeriverA, 19, 33, 0x71);
    let (installation_b, share_b) =
        installation(epochs, TwoPartyDeriverRole::DeriverB, 33, 19, 0x81);
    let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
        installation_a
            .lifecycle_receipt_digest()
            .expect("deriver A installation receipt"),
        installation_b
            .lifecycle_receipt_digest()
            .expect("deriver B installation receipt"),
    )
    .expect("installation receipts");
    let context_digest = installation_a
        .evidence()
        .transcript()
        .context()
        .digest()
        .expect("context digest");
    let ecdsa = canary(epochs, &next, TenantRootCanaryCurveFamilyV1::Ecdsa);
    let ed25519 = canary(epochs, &next, TenantRootCanaryCurveFamilyV1::Ed25519);
    if accepted_loss_branch {
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_accepted_loss(
            &current,
            installation_a,
            installation_b,
            accepted_loss_for_scope(
                epochs,
                identity(),
                lineage(),
                context_digest,
                &next,
                installation_receipts,
                expected_control_plane_revision,
                result_control_plane_revision,
            ),
            ecdsa,
            ed25519,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
    } else {
        let backup_a = managed_backup(&installation_a, &share_a, TwoPartyDeriverRole::DeriverA);
        let backup_b = managed_backup(&installation_b, &share_b, TwoPartyDeriverRole::DeriverB);
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_managed_backups(
            &current,
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            ecdsa,
            ed25519,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
    }
}

fn verifying_key_bytes() -> [u8; 32] {
    SigningKey::from_bytes(&ISSUER_KEY_BYTES)
        .verifying_key()
        .to_bytes()
}

fn sign_creation(
    bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
) -> TenantRootSignedActivationReceiptV1 {
    TenantRootSignedActivationReceiptV1::sign_initial_creation(
        bundle,
        ACTIVATION_TIME_MS,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .expect("signed initial activation receipt")
}

fn sign_refresh(
    bundle: &VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
) -> TenantRootSignedActivationReceiptV1 {
    TenantRootSignedActivationReceiptV1::sign_refresh_swap(
        bundle,
        ACTIVATION_TIME_MS,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .expect("signed refresh activation receipt")
}

fn verify_creation(
    receipt: TenantRootSignedActivationReceiptV1,
    bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    activated_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issuer_key_id: &str,
) -> router_ab_core::RouterAbDerivationResult<
    router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
> {
    receipt.verify_initial_creation(
        bundle,
        activated_at_ms,
        authority_id,
        issuer_key_id,
        &verifying_key_bytes(),
    )
}

fn verify_refresh(
    receipt: TenantRootSignedActivationReceiptV1,
    bundle: &VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    activated_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issuer_key_id: &str,
) -> router_ab_core::RouterAbDerivationResult<
    router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
> {
    receipt.verify_refresh_swap(
        bundle,
        activated_at_ms,
        authority_id,
        issuer_key_id,
        &verifying_key_bytes(),
    )
}

fn read_field(bytes: &[u8], offset: usize) -> (usize, usize, usize) {
    let length_end = offset + 4;
    let length =
        u32::from_be_bytes(bytes[offset..length_end].try_into().expect("field length")) as usize;
    let value_start = length_end;
    let value_end = value_start + length;
    (value_start, value_end, value_end)
}

fn replace_accepted_loss_authorization_byte(bytes: &[u8]) -> Vec<u8> {
    let mut replaced = bytes.to_vec();
    let mut offset = 0;
    let mut found = false;
    for _ in 0..32 {
        let (value_start, value_end, next_offset) = read_field(&replaced, offset);
        if &replaced[value_start..value_end] == b"accepted_permanent_derivation_loss" {
            let (authorization_start, authorization_end, _) = read_field(&replaced, next_offset);
            replaced[authorization_end - 1] ^= 1;
            let digest = Sha256::digest(&replaced[authorization_start..authorization_end]);
            let (digest_start, digest_end, _) = read_field(&replaced, authorization_end);
            assert_eq!(digest_end - digest_start, 32);
            replaced[digest_start..digest_end].copy_from_slice(&digest);
            found = true;
            break;
        }
        offset = next_offset;
    }
    assert!(found, "accepted-loss branch must be present");
    replaced
}

#[test]
fn initial_creation_receipt_is_bundle_bound_and_canonical() {
    let bundle = creation_bundle(false);
    let receipt = sign_creation(&bundle);
    let bytes = receipt.canonical_bytes().expect("canonical receipt");
    assert!(bytes.len() < TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1);
    assert!(bytes
        .windows(b"current_role_backups".len())
        .any(|window| window == b"current_role_backups"));
    let decoded = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&bytes)
        .expect("decode canonical receipt");
    assert_eq!(decoded, receipt);
    assert_eq!(
        decoded.transition(),
        TenantRootActivationReceiptTransitionV1::InitialCreation
    );
    assert_eq!(
        decoded.expected_control_plane_revision(),
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1
    );
    assert_eq!(
        decoded.result_control_plane_revision(),
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1
    );
    assert_eq!(decoded.issued_at_ms(), bundle.context().issued_at_ms());
    assert_eq!(decoded.expires_at_ms(), bundle.context().expires_at_ms());
    match decoded.availability() {
        TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups { receipts } => {
            let expected = match bundle.availability() {
                router_ab_core::TenantRootActivationAvailabilityEvidenceViewV1::CurrentRoleBackups {
                    deriver_a,
                    deriver_b,
                } => router_ab_core::TenantRootRoleBackupReceiptsV1::new(
                    deriver_a.receipt_digest(),
                    deriver_b.receipt_digest(),
                )
                .expect("backup receipts"),
                router_ab_core::TenantRootActivationAvailabilityEvidenceViewV1::AcceptedPermanentDerivationLoss {
                    ..
                } => panic!("managed-backup fixture must use current-role branch"),
            };
            assert_eq!(*receipts, expected);
        }
        TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss { .. } => {
            panic!("managed-backup fixture must use current-role branch")
        }
    }
    let receipt_digest = receipt.digest().expect("receipt digest");
    let verified = decoded
        .verify_initial_creation(
            &bundle,
            ACTIVATION_TIME_MS,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
            ISSUER_KEY_ID,
            &verifying_key_bytes(),
        )
        .expect("verify exact initial activation receipt");
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(verified.digest(), receipt_digest);
    verified
        .require_fresh(ISSUE_TIME_MS)
        .expect("issue boundary");
    verified
        .require_fresh(EXPIRY_TIME_MS)
        .expect("expiry boundary");
    assert!(verified.require_fresh(EXPIRY_TIME_MS + 1).is_err());
}

#[test]
fn current_role_backup_evidence_requires_independent_key_versions() {
    let error = creation_bundle_with_shared_backup_key_version()
        .expect_err("A/B managed backups must not share a key version");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);
}

#[test]
fn current_role_backup_evidence_requires_independent_providers() {
    let error = creation_bundle_with_shared_backup_provider()
        .expect_err("A/B managed backups must not share a provider");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);
}

#[test]
fn current_role_backup_evidence_requires_independent_authorities() {
    let error = creation_bundle_with_shared_backup_authority()
        .expect_err("A/B managed backups must not share a role authority");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);
}

#[test]
fn refresh_receipt_preserves_root_continuity_and_revision_advance() {
    let bundle = refresh_bundle(false);
    let receipt = sign_refresh(&bundle);
    let bytes = receipt.canonical_bytes().expect("canonical receipt");
    let decoded = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&bytes)
        .expect("decode canonical refresh receipt");
    let verified = decoded
        .verify_refresh_swap(
            &bundle,
            ACTIVATION_TIME_MS,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
            ISSUER_KEY_ID,
            &verifying_key_bytes(),
        )
        .expect("verify exact refresh activation receipt");
    assert_eq!(verified.expected_control_plane_revision(), 5);
    assert_eq!(verified.result_control_plane_revision(), 6);
    assert_eq!(verified.issued_at_ms(), bundle.context().issued_at_ms());
    assert_eq!(verified.expires_at_ms(), bundle.context().expires_at_ms());
    assert_eq!(verified.identity_digest(), identity());
    assert_eq!(verified.custody_lineage(), lineage());
    assert_eq!(verified.context_digest(), bundle.context_digest());
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
}

#[test]
fn availability_branch_substitution_fails_before_signature_acceptance() {
    let current_bundle = creation_bundle(false);
    let receipt = sign_creation(&current_bundle);
    let accepted_loss_bundle = creation_bundle(true);
    let error = receipt
        .verify_initial_creation(
            &accepted_loss_bundle,
            ACTIVATION_TIME_MS,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
            ISSUER_KEY_ID,
            &verifying_key_bytes(),
        )
        .expect_err("availability branch substitution must fail");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);
}

#[test]
fn accepted_loss_scope_rejects_context_root_and_installation_replay() {
    let bundle = creation_bundle(true);
    let receipt = sign_creation(&bundle);
    let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]);

    let context_variant =
        creation_bundle_with_scope(true, identity(), lineage(), 0x34, 0x44, 0x51, 0x61);
    let context_error = verify_creation(
        receipt.clone(),
        &context_variant,
        ACTIVATION_TIME_MS,
        authority_id,
        ISSUER_KEY_ID,
    )
    .expect_err("accepted-loss context replay must fail");
    assert_eq!(
        context_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let root_variant =
        creation_bundle_with_scope(true, identity_with(0x12), lineage(), 0x33, 0x44, 0x51, 0x61);
    let root_error = verify_creation(
        receipt.clone(),
        &root_variant,
        ACTIVATION_TIME_MS,
        authority_id,
        ISSUER_KEY_ID,
    )
    .expect_err("accepted-loss root replay must fail");
    assert_eq!(
        root_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let commitment_variant = creation_bundle_with_scope_and_commitments(
        true,
        identity(),
        lineage(),
        0x33,
        0x44,
        0x51,
        0x61,
        13,
        20,
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1,
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1,
    );
    let commitment_error = verify_creation(
        receipt.clone(),
        &commitment_variant,
        ACTIVATION_TIME_MS,
        authority_id,
        ISSUER_KEY_ID,
    )
    .expect_err("accepted-loss root commitment replay must fail");
    assert_eq!(
        commitment_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let installation_variant =
        creation_bundle_with_scope(true, identity(), lineage(), 0x33, 0x44, 0x52, 0x61);
    let installation_error = verify_creation(
        receipt.clone(),
        &installation_variant,
        ACTIVATION_TIME_MS,
        authority_id,
        ISSUER_KEY_ID,
    )
    .expect_err("accepted-loss installation replay must fail");
    assert_eq!(
        installation_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let issuer_error = verify_creation(
        receipt,
        &bundle,
        ACTIVATION_TIME_MS,
        authority_id,
        "different-issuer-key",
    )
    .expect_err("accepted-loss issuer scope replay must fail");
    assert_eq!(
        issuer_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn accepted_loss_revision_scope_rejects_refresh_replay() {
    let bundle = refresh_bundle(true);
    let receipt = sign_refresh(&bundle);
    let different_revision_bundle =
        refresh_bundle_with_revisions(true, 6, 7).expect("different authoritative revision bundle");
    let error = verify_refresh(
        receipt,
        &different_revision_bundle,
        ACTIVATION_TIME_MS,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        ISSUER_KEY_ID,
    )
    .expect_err("accepted-loss revision replay must fail");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);
}

#[test]
fn accepted_loss_receipt_carries_exact_authorization_bytes_and_digest() {
    let bundle = creation_bundle(true);
    let receipt = sign_creation(&bundle);
    let authorization_bytes = match bundle.availability() {
        router_ab_core::TenantRootActivationAvailabilityEvidenceViewV1::AcceptedPermanentDerivationLoss {
            authorization,
        } => authorization.canonical_bytes().to_vec(),
        router_ab_core::TenantRootActivationAvailabilityEvidenceViewV1::CurrentRoleBackups {
            ..
        } => panic!("accepted-loss fixture must use accepted-loss branch"),
    };
    match receipt.availability() {
        TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss {
            authorization_bytes: receipt_bytes,
            authorization_digest,
        } => {
            let expected_digest: [u8; 32] = Sha256::digest(&authorization_bytes).into();
            assert_eq!(receipt_bytes, &authorization_bytes);
            assert_eq!(authorization_digest.as_bytes(), &expected_digest);
        }
        TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups { .. } => {
            panic!("accepted-loss fixture must use accepted-loss branch")
        }
    }
    let bytes = receipt
        .canonical_bytes()
        .expect("canonical accepted-loss receipt");
    let tampered = replace_accepted_loss_authorization_byte(&bytes);
    let decoded = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&tampered)
        .expect("tampered authorization remains structurally canonical");
    let error = decoded
        .verify_initial_creation(
            &bundle,
            ACTIVATION_TIME_MS,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
            ISSUER_KEY_ID,
            &verifying_key_bytes(),
        )
        .expect_err("tampered authorization bytes must fail exact bundle verification");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);
}

#[test]
fn result_revision_and_metadata_are_authoritative() {
    let creation = creation_bundle_with_revisions(
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_EXPECTED_REVISION_V1 + 1,
        TENANT_ROOT_INITIAL_CREATION_ACTIVATION_RESULT_REVISION_V1 + 1,
    );
    let initial_error = TenantRootSignedActivationReceiptV1::sign_initial_creation(
        &creation,
        ACTIVATION_TIME_MS,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        ISSUER_KEY_ID,
        &ISSUER_KEY_BYTES,
    )
    .expect_err("initial activation revision is fixed");
    assert_eq!(
        initial_error.code(),
        RouterAbDerivationErrorCode::MalformedInput
    );

    let invalid_refresh = refresh_bundle_with_revisions(false, 5, 7)
        .expect_err("refresh result revision must advance exactly one");
    assert_eq!(
        invalid_refresh.code(),
        RouterAbDerivationErrorCode::MalformedInput
    );

    let overflow_refresh = refresh_bundle_with_revisions(false, u64::MAX, u64::MAX)
        .expect_err("refresh revision advancement must reject overflow");
    assert_eq!(
        overflow_refresh.code(),
        RouterAbDerivationErrorCode::MalformedInput
    );
}

#[test]
fn canonical_decoder_rejects_truncation_trailing_and_tampering() {
    let bundle = creation_bundle(false);
    let receipt = sign_creation(&bundle);
    let bytes = receipt.canonical_bytes().expect("canonical receipt");
    for malformed in [
        bytes[..bytes.len() - 1].to_vec(),
        {
            let mut value = bytes.clone();
            value.push(0);
            value
        },
        {
            let mut value = bytes.clone();
            value[3] = value[3].saturating_add(1);
            value
        },
    ] {
        let error = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&malformed)
            .expect_err("non-canonical activation receipt must fail");
        assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
    }
    let mut tampered_signature = bytes.clone();
    let last_byte = tampered_signature
        .last_mut()
        .expect("canonical receipt has a signature");
    *last_byte ^= 1;
    let tampered = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&tampered_signature)
        .expect("nonzero tampered signature remains structurally canonical");
    let signature_error = tampered
        .verify_initial_creation(
            &bundle,
            ACTIVATION_TIME_MS,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
            ISSUER_KEY_ID,
            &verifying_key_bytes(),
        )
        .expect_err("tampered issuer signature must fail closed");
    assert_eq!(
        signature_error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn issuer_signature_verification_retains_exact_wire_and_rejects_substitution() {
    let bundle = creation_bundle(false);
    let receipt = sign_creation(&bundle);
    let bytes = receipt.canonical_bytes().expect("canonical receipt");
    let decoded = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&bytes)
        .expect("decoded receipt");
    let verified = decoded
        .verify_issuer_signature(&verifying_key_bytes())
        .expect("issuer signature");
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(verified.digest(), receipt.digest().expect("receipt digest"));

    let mut tampered = bytes;
    let last_byte = tampered.len() - 1;
    tampered[last_byte] ^= 1;
    let decoded = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&tampered)
        .expect("substituted signature remains structurally canonical");
    let error = decoded
        .verify_issuer_signature(&verifying_key_bytes())
        .expect_err("substituted signature must fail");
    assert_eq!(
        error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}
