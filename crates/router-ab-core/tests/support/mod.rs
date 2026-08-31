#![allow(dead_code)]

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_chacha_09::ChaCha20Rng as ChaCha20Rng09;
use rand_core::SeedableRng;
use rand_core_09::SeedableRng as SeedableRng09;
use router_ab_core::{
    PendingTenantRootRecoveryShareV1, TenantRootActivationReceiptV1, TenantRootBackupPolicyV1,
    TenantRootCanaryReceiptsV1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId,
    TenantRootEmptyCreationV1, TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootRecoveryDescriptorV1, TenantRootRecoveryRecipientKeypairV1,
    TenantRootRecoveryReshareContextV1, TenantRootRecoveryReshareHpkeKeypairV1,
    TenantRootRecoverySetId, TenantRootRoleBackupReceiptsV1, TenantRootRoleInstallationReceiptsV1,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedRecoveryReshareCommitmentV1, TenantRootSignedRecoveryReshareContributionV1,
    TenantRootSignedRecoveryShareInstallationEvidenceV1,
    TenantRootSignedShareInstallationEvidenceV1, VerifiedTenantRootRecoveryResharePairV1,
    VerifiedTenantRootRecoveryShareV1,
};
use threshold_prf::{
    prove_root_share_knowledge, RootShareRefreshCoefficient, SigningRootShare,
    SigningRootShareCommitment, TwoPartyDeriverRole,
};

pub const ISSUED_AT_MS: u64 = 1_000_000;
pub const EXPIRES_AT_MS: u64 = 1_030_000;

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
    let evidence_a = creation_evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        &active_a,
        &active_b,
        0x23,
    );
    let evidence_b = creation_evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        &active_b,
        &active_a,
        0x24,
    );
    let active = TenantRootEmptyCreationV1::new(identity(), lineage())
        .start(&context)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            TenantRootRoleInstallationReceiptsV1::new(lifecycle_digest(1), lifecycle_digest(2))
                .unwrap(),
            TenantRootBackupPolicyV1::CurrentRoleBackups(
                TenantRootRoleBackupReceiptsV1::new(lifecycle_digest(3), lifecycle_digest(4))
                    .unwrap(),
            ),
            TenantRootCanaryReceiptsV1::new(lifecycle_digest(5), lifecycle_digest(6)).unwrap(),
            1_010_000,
        )
        .unwrap()
        .activate(TenantRootActivationReceiptV1::new(lifecycle_digest(7), 1_020_000).unwrap())
        .unwrap()
        .into_refresh_state();
    (active, active_a, active_b)
}

fn creation_evidence(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share: &SigningRootShare,
    peer: &SigningRootShare,
    proof_seed: u8,
) -> router_ab_core::VerifiedTenantRootShareInstallationEvidenceV1 {
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
    TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes())
        .unwrap()
        .verify(signing_key.verifying_key().as_bytes())
        .unwrap()
}

fn lifecycle_digest(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).unwrap()
}
