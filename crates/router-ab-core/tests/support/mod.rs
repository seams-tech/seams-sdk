#![allow(dead_code)]

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_chacha_09::ChaCha20Rng as ChaCha20Rng09;
use rand_core::SeedableRng;
use rand_core_09::SeedableRng as SeedableRng09;
use router_ab_core::{
    PendingTenantRootRecoveryShareV1, TenantRootActivationReceiptTransitionV1,
    TenantRootBackupPolicyV1, TenantRootCanaryCurveFamilyV1, TenantRootCanaryReceiptsV1,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId,
    TenantRootEmptyCreationV1, TenantRootEpochCommitmentsV1, TenantRootIdentityV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedBackupBindingV1,
    TenantRootManagedBackupSealRequestV1, TenantRootProviderCanaryReceiptBindingV1,
    TenantRootRecoveryDescriptorV1, TenantRootRecoveryRecipientKeypairV1,
    TenantRootRecoveryReshareContextV1, TenantRootRecoveryReshareHpkeKeypairV1,
    TenantRootRecoverySetId, TenantRootRoleBackupReceiptsV1, TenantRootRoleInstallationReceiptsV1,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedActivationReceiptV1, TenantRootSignedManagedBackupV1,
    TenantRootSignedProviderCanaryReceiptV1, TenantRootSignedRecoveryReshareCommitmentV1,
    TenantRootSignedRecoveryReshareContributionV1,
    TenantRootSignedRecoveryShareInstallationEvidenceV1,
    TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1, VerifiedTenantRootManagedBackupV1,
    VerifiedTenantRootProviderCanaryReceiptV1, VerifiedTenantRootRecoveryResharePairV1,
    VerifiedTenantRootRecoveryShareV1, VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    VerifiedTenantRootShareInstallationEvidenceV1, VerifiedTenantRootSignedActivationReceiptV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};
use threshold_prf::{
    prove_root_share_knowledge, RootShareRefreshCoefficient, SigningRootShare,
    SigningRootShareCommitment, SigningRootShareWire, TwoPartyDeriverRole,
};

pub const ISSUED_AT_MS: u64 = 1_000_000;
pub const EXPIRES_AT_MS: u64 = 1_030_000;

const ACTIVATION_ISSUER_KEY_BYTES: [u8; 32] = [0x41; 32];
const ACTIVATION_ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const CANARY_SIGNING_KEY_BYTES: [u8; 32] = [0x71; 32];
const CANARY_AUTHORITY_BYTES: [u8; 32] = [0x72; 32];
const CANARY_SIGNING_KEY_ID: &str = "control-plane-canary-v1";

pub struct InitialActivationEvidenceFixture {
    pub bundle: VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    pub evidence_a: VerifiedTenantRootShareInstallationEvidenceV1,
    pub evidence_b: VerifiedTenantRootShareInstallationEvidenceV1,
    pub installation_receipts: TenantRootRoleInstallationReceiptsV1,
    pub backup_policy: TenantRootBackupPolicyV1,
    pub canary_receipts: TenantRootCanaryReceiptsV1,
}

pub struct RefreshActivationEvidenceFixture {
    pub bundle: VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    pub evidence_a: VerifiedTenantRootShareInstallationEvidenceV1,
    pub evidence_b: VerifiedTenantRootShareInstallationEvidenceV1,
    pub installation_receipts: TenantRootRoleInstallationReceiptsV1,
    pub backup_policy: TenantRootBackupPolicyV1,
    pub canary_receipts: TenantRootCanaryReceiptsV1,
}

pub fn initial_activation_receipt(
    bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    activated_at_ms: u64,
) -> VerifiedTenantRootSignedActivationReceiptV1 {
    let signed = TenantRootSignedActivationReceiptV1::sign_initial_creation(
        bundle,
        activated_at_ms,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        ACTIVATION_ISSUER_KEY_ID,
        &ACTIVATION_ISSUER_KEY_BYTES,
    )
    .unwrap();
    signed
        .verify_initial_creation(
            bundle,
            activated_at_ms,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ACTIVATION_ISSUER_KEY_ID,
            &SigningKey::from_bytes(&ACTIVATION_ISSUER_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
}

pub fn refresh_activation_receipt(
    bundle: &VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    activated_at_ms: u64,
) -> VerifiedTenantRootSignedActivationReceiptV1 {
    let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]);
    let signed = TenantRootSignedActivationReceiptV1::sign_refresh_swap(
        bundle,
        activated_at_ms,
        authority_id,
        ACTIVATION_ISSUER_KEY_ID,
        &ACTIVATION_ISSUER_KEY_BYTES,
    )
    .unwrap();
    signed
        .verify_refresh_swap(
            bundle,
            activated_at_ms,
            authority_id,
            ACTIVATION_ISSUER_KEY_ID,
            &SigningKey::from_bytes(&ACTIVATION_ISSUER_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
}

pub fn initial_activation_evidence_fixture(
    context: TenantRootCeremonyContextV1,
    share_a: &SigningRootShare,
    share_b: &SigningRootShare,
    proof_seed_a: u8,
    proof_seed_b: u8,
) -> InitialActivationEvidenceFixture {
    let commitments = epoch_commitments(share_a, share_b);
    let installation_a = signed_installation_wire(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        share_a,
        share_b,
        proof_seed_a,
    );
    let installation_b = signed_installation_wire(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        share_b,
        share_a,
        proof_seed_b,
    );
    let evidence_a = installation_a.evidence().clone();
    let evidence_b = installation_b.evidence().clone();
    let share_wire_a = share_wire(share_a);
    let share_wire_b = share_wire(share_b);
    let backup_a = managed_backup(
        &installation_a,
        &share_wire_a,
        context.signing_key_id(TwoPartyDeriverRole::DeriverA),
    );
    let backup_b = managed_backup(
        &installation_b,
        &share_wire_b,
        context.signing_key_id(TwoPartyDeriverRole::DeriverB),
    );
    let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
        installation_a.lifecycle_receipt_digest().unwrap(),
        installation_b.lifecycle_receipt_digest().unwrap(),
    )
    .unwrap();
    let backup_policy = TenantRootBackupPolicyV1::CurrentRoleBackups(
        TenantRootRoleBackupReceiptsV1::new(backup_a.receipt_digest(), backup_b.receipt_digest())
            .unwrap(),
    );
    let canary_a = provider_canary(
        &context,
        &commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
        "kms/tenant-root/ecdsa-canary-v1",
    );
    let canary_b = provider_canary(
        &context,
        &commitments,
        TenantRootCanaryCurveFamilyV1::Ed25519,
        "kms/tenant-root/ed25519-canary-v1",
    );
    let canary_receipts = TenantRootCanaryReceiptsV1::new(
        lifecycle_digest_from_provider_canary(canary_a.digest()),
        lifecycle_digest_from_provider_canary(canary_b.digest()),
    )
    .unwrap();
    let bundle =
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            canary_a,
            canary_b,
            2,
            3,
        )
        .unwrap();
    InitialActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    }
}

pub fn refresh_activation_evidence_fixture(
    context: TenantRootCeremonyContextV1,
    current_commitments: &TenantRootEpochCommitmentsV1,
    share_a: &SigningRootShare,
    share_b: &SigningRootShare,
    proof_seed_a: u8,
    proof_seed_b: u8,
    expected_control_plane_revision: u64,
) -> RefreshActivationEvidenceFixture {
    let commitments = epoch_commitments(share_a, share_b);
    let installation_a = signed_installation_wire(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        share_a,
        share_b,
        proof_seed_a,
    );
    let installation_b = signed_installation_wire(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        share_b,
        share_a,
        proof_seed_b,
    );
    let evidence_a = installation_a.evidence().clone();
    let evidence_b = installation_b.evidence().clone();
    let share_wire_a = share_wire(share_a);
    let share_wire_b = share_wire(share_b);
    let backup_a = managed_backup(
        &installation_a,
        &share_wire_a,
        context.signing_key_id(TwoPartyDeriverRole::DeriverA),
    );
    let backup_b = managed_backup(
        &installation_b,
        &share_wire_b,
        context.signing_key_id(TwoPartyDeriverRole::DeriverB),
    );
    let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
        installation_a.lifecycle_receipt_digest().unwrap(),
        installation_b.lifecycle_receipt_digest().unwrap(),
    )
    .unwrap();
    let backup_policy = TenantRootBackupPolicyV1::CurrentRoleBackups(
        TenantRootRoleBackupReceiptsV1::new(backup_a.receipt_digest(), backup_b.receipt_digest())
            .unwrap(),
    );
    let canary_a = provider_canary(
        &context,
        &commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
        "kms/tenant-root/ecdsa-canary-v1",
    );
    let canary_b = provider_canary(
        &context,
        &commitments,
        TenantRootCanaryCurveFamilyV1::Ed25519,
        "kms/tenant-root/ed25519-canary-v1",
    );
    let canary_receipts = TenantRootCanaryReceiptsV1::new(
        lifecycle_digest_from_provider_canary(canary_a.digest()),
        lifecycle_digest_from_provider_canary(canary_b.digest()),
    )
    .unwrap();
    let bundle =
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_managed_backups(
            current_commitments,
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            canary_a,
            canary_b,
            expected_control_plane_revision,
            expected_control_plane_revision.checked_add(1).unwrap(),
        )
        .unwrap();
    RefreshActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    }
}

fn epoch_commitments(
    share_a: &SigningRootShare,
    share_b: &SigningRootShare,
) -> TenantRootEpochCommitmentsV1 {
    TenantRootEpochCommitmentsV1::new(
        router_ab_core::MpcPrfShareCommitmentWireV1::new(
            SigningRootShareCommitment::from_share(share_a)
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
        router_ab_core::MpcPrfShareCommitmentWireV1::new(
            SigningRootShareCommitment::from_share(share_b)
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn share_wire(share: &SigningRootShare) -> router_ab_core::MpcPrfSigningRootShareWireV1 {
    router_ab_core::MpcPrfSigningRootShareWireV1::new(
        SigningRootShareWire::from_share(share).to_bytes().to_vec(),
    )
    .unwrap()
}

fn signed_installation_wire(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share: &SigningRootShare,
    peer: &SigningRootShare,
    proof_seed: u8,
) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context,
        role,
        SigningRootShareCommitment::from_share(share),
        SigningRootShareCommitment::from_share(peer),
    )
    .unwrap();
    let proof = prove_root_share_knowledge(
        share,
        &transcript.canonical_bytes().unwrap(),
        &mut rng06(proof_seed),
    )
    .unwrap();
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap();
    let signing_key = signing_key(role);
    let signed =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes())
            .unwrap();
    let bytes = signed.canonical_bytes().unwrap();
    TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &bytes,
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap()
}

fn managed_backup(
    installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    share: &router_ab_core::MpcPrfSigningRootShareWireV1,
    role_signing_key_id: &str,
) -> VerifiedTenantRootManagedBackupV1 {
    let role = installation.evidence().transcript().role();
    let epoch = match installation.evidence().transcript().context().epochs() {
        TenantRootCeremonyEpochsV1::Create { next }
        | TenantRootCeremonyEpochsV1::Refresh { next, .. } => next,
    };
    let provider_id = match role {
        TwoPartyDeriverRole::DeriverA => "backup-provider-deriver-a-v1",
        TwoPartyDeriverRole::DeriverB => "backup-provider-deriver-b-v1",
    };
    let key_version = match role {
        TwoPartyDeriverRole::DeriverA => {
            format!("kms/tenant-root/deriver-a/epoch-{}/v1", epoch.get().get())
        }
        TwoPartyDeriverRole::DeriverB => {
            format!("kms/tenant-root/deriver-b/epoch-{}/v1", epoch.get().get())
        }
    };
    let binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
        installation,
        provider_id,
        key_version,
        role_signing_key_id,
        installation
            .evidence()
            .transcript()
            .context()
            .issued_at_ms(),
    )
    .unwrap();
    let request =
        TenantRootManagedBackupSealRequestV1::new(binding.clone(), share.clone()).unwrap();
    let signing_key = signing_key(role);
    let ciphertext = match role {
        TwoPartyDeriverRole::DeriverA => vec![0xa5; 96],
        TwoPartyDeriverRole::DeriverB => vec![0xb5; 96],
    };
    let signed =
        TenantRootSignedManagedBackupV1::sign(request, ciphertext, &signing_key.to_bytes())
            .unwrap();
    let bytes = signed.canonical_bytes().unwrap();
    TenantRootSignedManagedBackupV1::decode_and_verify_canonical_bytes(
        &bytes,
        &binding,
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap()
}

fn provider_canary(
    context: &TenantRootCeremonyContextV1,
    commitments: &TenantRootEpochCommitmentsV1,
    family: TenantRootCanaryCurveFamilyV1,
    provider_key_version_ref: &str,
) -> VerifiedTenantRootProviderCanaryReceiptV1 {
    let (transition, target_epoch) = match context.epochs() {
        TenantRootCeremonyEpochsV1::Create { next } => (
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            next,
        ),
        TenantRootCeremonyEpochsV1::Refresh { next, .. } => {
            (TenantRootActivationReceiptTransitionV1::RefreshSwap, next)
        }
    };
    let binding = TenantRootProviderCanaryReceiptBindingV1::new(
        context.identity_digest(),
        context.custody_lineage(),
        transition,
        target_epoch,
        commitments.clone(),
        family,
        provider_key_version_ref,
        context.issued_at_ms(),
        TenantRootControlPlaneAuthorityIdV1::from_bytes(CANARY_AUTHORITY_BYTES),
        CANARY_SIGNING_KEY_ID,
        context.issued_at_ms(),
        context.expires_at_ms(),
    )
    .unwrap();
    let signed =
        TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &CANARY_SIGNING_KEY_BYTES)
            .unwrap();
    signed
        .verify(
            &binding,
            &SigningKey::from_bytes(&CANARY_SIGNING_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
}

fn lifecycle_digest_from_provider_canary(
    digest: router_ab_core::TenantRootProviderCanaryReceiptDigestV1,
) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes(*digest.as_bytes()).unwrap()
}

pub struct RecoveryReshareFixture {
    pub context: TenantRootRecoveryReshareContextV1,
    pub active_a: SigningRootShare,
    pub active_b: SigningRootShare,
    pub coefficient_a: RootShareRefreshCoefficient,
    pub coefficient_b: RootShareRefreshCoefficient,
    pub signed_commitment_a: TenantRootSignedRecoveryReshareCommitmentV1,
    pub signed_commitment_b: TenantRootSignedRecoveryReshareCommitmentV1,
    pub signing_a: SigningKey,
    pub signing_b: SigningKey,
}

pub struct VerifiedRecoveryArtifactFixture {
    pub descriptor: TenantRootRecoveryDescriptorV1,
    pub verified_a: VerifiedTenantRootRecoveryShareV1,
    pub verified_b: VerifiedTenantRootRecoveryShareV1,
    pub recipient_a: TenantRootRecoveryRecipientKeypairV1,
    pub recipient_b: TenantRootRecoveryRecipientKeypairV1,
    pub signing_a: SigningKey,
    pub signing_b: SigningKey,
}

pub fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3").unwrap()
}

pub fn lineage() -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap()
}

pub fn rng06(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

pub fn rng09(seed: u8) -> ChaCha20Rng09 {
    <ChaCha20Rng09 as SeedableRng09>::from_seed([seed; 32])
}

pub fn fixed_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .unwrap()
}

pub fn signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    SigningKey::from_bytes(
        &[match role {
            TwoPartyDeriverRole::DeriverA => 0x51,
            TwoPartyDeriverRole::DeriverB => 0x61,
        }; 32],
    )
}

pub fn recovery_reshare_fixture() -> RecoveryReshareFixture {
    let (active, active_a, active_b) = active_root();
    let recipient_a = TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([0xa1; 32])
        .unwrap()
        .public_key();
    let recipient_b = TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([0xb1; 32])
        .unwrap()
        .public_key();
    let context = TenantRootRecoveryReshareContextV1::from_active(
        &active,
        TenantRootRecoverySetId::from_bytes([0x41; 16]).unwrap(),
        recipient_a,
        recipient_b,
        TenantRootCeremonySessionIdV1::from_bytes([0x42; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x43; 32]).unwrap(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap();
    let coefficient_a = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverA,
        Scalar::from(7_u64).to_bytes(),
    )
    .unwrap();
    let coefficient_b = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverB,
        Scalar::from(11_u64).to_bytes(),
    )
    .unwrap();
    let signing_a = signing_key(TwoPartyDeriverRole::DeriverA);
    let signing_b = signing_key(TwoPartyDeriverRole::DeriverB);
    let signed_commitment_a = TenantRootSignedRecoveryReshareCommitmentV1::sign(
        &context,
        &coefficient_a,
        &signing_a.to_bytes(),
    )
    .unwrap();
    let signed_commitment_b = TenantRootSignedRecoveryReshareCommitmentV1::sign(
        &context,
        &coefficient_b,
        &signing_b.to_bytes(),
    )
    .unwrap();
    RecoveryReshareFixture {
        context,
        active_a,
        active_b,
        coefficient_a,
        coefficient_b,
        signed_commitment_a,
        signed_commitment_b,
        signing_a,
        signing_b,
    }
}

pub fn verified_recovery_artifact_fixture() -> VerifiedRecoveryArtifactFixture {
    let fixture = recovery_reshare_fixture();
    let verified_commitment_a = fixture
        .signed_commitment_a
        .verify(
            &fixture.context,
            fixture.signing_a.verifying_key().as_bytes(),
        )
        .unwrap();
    let verified_commitment_b = fixture
        .signed_commitment_b
        .verify(
            &fixture.context,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .unwrap();
    let hpke_a = TenantRootRecoveryReshareHpkeKeypairV1::derive_from_ikm([0x71; 32]).unwrap();
    let hpke_b = TenantRootRecoveryReshareHpkeKeypairV1::derive_from_ikm([0x81; 32]).unwrap();
    let contribution_a_to_b = TenantRootSignedRecoveryReshareContributionV1::seal(
        &fixture.context,
        &fixture.coefficient_a,
        &verified_commitment_a,
        "recovery-reshare-hpke-b-1",
        hpke_b.public_key(),
        &mut rng09(0x91),
        &fixture.signing_a.to_bytes(),
    )
    .unwrap();
    let contribution_b_to_a = TenantRootSignedRecoveryReshareContributionV1::seal(
        &fixture.context,
        &fixture.coefficient_b,
        &verified_commitment_b,
        "recovery-reshare-hpke-a-1",
        hpke_a.public_key(),
        &mut rng09(0xa1),
        &fixture.signing_b.to_bytes(),
    )
    .unwrap();
    let verified_b_for_a = contribution_b_to_a
        .verify_and_open(
            &fixture.context,
            &verified_commitment_b,
            "recovery-reshare-hpke-a-1",
            &hpke_a,
            fixture.signing_b.verifying_key().as_bytes(),
        )
        .unwrap();
    let verified_a_for_b = contribution_a_to_b
        .verify_and_open(
            &fixture.context,
            &verified_commitment_a,
            "recovery-reshare-hpke-b-1",
            &hpke_b,
            fixture.signing_a.verifying_key().as_bytes(),
        )
        .unwrap();
    let pending_a = PendingTenantRootRecoveryShareV1::derive(
        &fixture.context,
        &fixture.active_a,
        &fixture.coefficient_a,
        &verified_commitment_a,
        verified_b_for_a,
    )
    .unwrap();
    let pending_b = PendingTenantRootRecoveryShareV1::derive(
        &fixture.context,
        &fixture.active_b,
        &fixture.coefficient_b,
        &verified_commitment_b,
        verified_a_for_b,
    )
    .unwrap();
    let evidence_a = pending_a
        .prove(&fixture.context, pending_b.commitment(), &mut rng06(0xb1))
        .unwrap();
    let evidence_b = pending_b
        .prove(&fixture.context, pending_a.commitment(), &mut rng06(0xc1))
        .unwrap();
    let signed_evidence_a = TenantRootSignedRecoveryShareInstallationEvidenceV1::sign(
        &fixture.context,
        evidence_a,
        &fixture.signing_a.to_bytes(),
    )
    .unwrap();
    let signed_evidence_b = TenantRootSignedRecoveryShareInstallationEvidenceV1::sign(
        &fixture.context,
        evidence_b,
        &fixture.signing_b.to_bytes(),
    )
    .unwrap();
    let verified_pair = VerifiedTenantRootRecoveryResharePairV1::verify(
        &fixture.context,
        &signed_evidence_a,
        &signed_evidence_b,
        fixture.signing_a.verifying_key().as_bytes(),
        fixture.signing_b.verifying_key().as_bytes(),
    )
    .unwrap();
    let descriptor = TenantRootRecoveryDescriptorV1::from_verified_reshare(
        &verified_pair,
        "2026-08-29T10:20:30.123Z",
    )
    .unwrap();
    let verified_a = pending_a.finalize(&verified_pair).unwrap();
    let verified_b = pending_b.finalize(&verified_pair).unwrap();
    VerifiedRecoveryArtifactFixture {
        descriptor,
        verified_a,
        verified_b,
        recipient_a: TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([0xa1; 32]).unwrap(),
        recipient_b: TenantRootRecoveryRecipientKeypairV1::derive_from_ikm([0xb1; 32]).unwrap(),
        signing_a: fixture.signing_a,
        signing_b: fixture.signing_b,
    }
}

fn active_root() -> (
    router_ab_core::TenantRootActiveRefreshV1,
    SigningRootShare,
    SigningRootShare,
) {
    let active_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let active_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let context = TenantRootCeremonyContextV1::new(
        identity().digest().unwrap(),
        lineage(),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x21; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x22; 32]).unwrap(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap();
    let fixture = initial_activation_evidence_fixture(context, &active_a, &active_b, 0x23, 0x24);
    let verified = TenantRootEmptyCreationV1::new(identity(), lineage())
        .start(fixture.bundle.context())
        .unwrap()
        .verify(
            &fixture.evidence_a,
            &fixture.evidence_b,
            fixture.installation_receipts,
            fixture.backup_policy,
            fixture.canary_receipts,
            1_010_000,
        )
        .unwrap();
    let activation = initial_activation_receipt(&fixture.bundle, 1_020_000);
    let active = verified.activate(activation).unwrap().into_refresh_state();
    (active, active_a, active_b)
}

fn lifecycle_digest(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).unwrap()
}
