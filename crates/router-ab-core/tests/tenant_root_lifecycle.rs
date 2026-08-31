use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    combine_mpc_prf_stable_proof_bundles_with_threshold_backend_v2,
    evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2,
    plan_mpc_prf_stable_purpose_binding_v2,
    verify_mpc_prf_stable_partial_with_threshold_backend_v2, ActiveTenantRootEpochV1,
    MpcPrfSigningRootShareWireV1, MpcPrfStableThresholdCombineInputV2,
    MpcPrfStableThresholdSignerInputV2, Role, StableTenantDerivationContextV2,
    TenantRootAcceptedLossReceiptV1, TenantRootActivationReceiptV1, TenantRootBackupPolicyV1,
    TenantRootCanaryReceiptsV1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCleanupIncompleteCreationV1, TenantRootCreationFailureV1,
    TenantRootCreationRecoveryActionV1, TenantRootCreationStateV1, TenantRootCustodyBindingV1,
    TenantRootCustodyLineageId, TenantRootDeletedReceiptV1, TenantRootDeletionActiveV1,
    TenantRootDeletionAuthorizationV1, TenantRootDeletionDrainReceiptV1,
    TenantRootDeletionEvidenceV1, TenantRootDeletionFenceReceiptV1, TenantRootDeletionStateV1,
    TenantRootDerivationNonceV1, TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1, TenantRootDeriverIdentitiesV1, TenantRootDestructionCommandV1,
    TenantRootDestructionFailureV1, TenantRootDestructionProfileV1,
    TenantRootDestructionProgressReceiptV1, TenantRootEmptyCreationV1,
    TenantRootFailedBeforeActivationCreationV1, TenantRootIdentityV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreAvailableV1,
    TenantRootManagedRestoreCapabilityV1, TenantRootManagedRestoreCleanupFailureV1,
    TenantRootManagedRestoreCleanupReceiptV1, TenantRootManagedRestoreFailureV1,
    TenantRootManagedRestoreInstallationReceiptV1, TenantRootManagedRestoreInstallingV1,
    TenantRootManagedRestorePeerVerificationReceiptV1, TenantRootManagedRestoreRoleV1,
    TenantRootManagedRestoreStateV1, TenantRootManagedRoleDestructionReceiptV1,
    TenantRootManagedRoleDestructionReceiptsV1, TenantRootOperationalErasureClaimV1,
    TenantRootOperationalRoleRemovalReceiptV1, TenantRootOperationalRoleRemovalReceiptsV1,
    TenantRootPendingCleanupFailureV1, TenantRootPendingCleanupReceiptV1,
    TenantRootProtocolDigestV1, TenantRootRefreshFailureV1, TenantRootRefreshRecoveryActionV1,
    TenantRootRefreshStateV1, TenantRootRoleBackupReceiptsV1, TenantRootRoleInstallationReceiptsV1,
    TenantRootRoleRetirementReceiptsV1, TenantRootRoleUnavailableReceiptV1,
    TenantRootServiceCleanupReceiptV1, TenantRootShareEpoch, TenantRootShareInstallationEvidenceV1,
    TenantRootShareInstallationTranscriptV1, TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootShareInstallationEvidenceV1,
};
use threshold_prf::{
    apply_two_party_root_share_refresh, prove_root_share_knowledge, PrfPurpose,
    RootShareRefreshCoefficient, SigningRootShare, SigningRootShareCommitment,
    SigningRootShareWire, TwoPartyDeriverRole, TwoPartyRootShareCommitments,
};

const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3").unwrap()
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).unwrap()
}

fn context(lineage: TenantRootCustodyLineageId, session_seed: u8) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity().digest().unwrap(),
        lineage,
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap()
}

fn refresh_context(
    lineage: TenantRootCustodyLineageId,
    current: u64,
    next: u64,
    session_seed: u8,
) -> TenantRootCeremonyContextV1 {
    refresh_context_at(
        lineage,
        current,
        next,
        session_seed,
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
    )
}

fn refresh_context_at(
    lineage: TenantRootCustodyLineageId,
    current: u64,
    next: u64,
    session_seed: u8,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity().digest().unwrap(),
        lineage,
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(current).unwrap(),
            TenantRootShareEpoch::new(next).unwrap(),
        )
        .unwrap(),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x42; 32]).unwrap(),
        issued_at_ms,
        expires_at_ms,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap()
}

fn managed_restore_capability(
    active: &router_ab_core::TenantRootActiveRefreshV1,
    role: TenantRootManagedRestoreRoleV1,
    digest_seed: u8,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> TenantRootManagedRestoreCapabilityV1 {
    TenantRootManagedRestoreCapabilityV1::new(
        digest(digest_seed),
        active.identity().digest().unwrap(),
        active.custody_lineage(),
        role,
        active.current().epoch(),
        active.current().activation().digest(),
        issued_at_ms,
        expires_at_ms,
    )
    .unwrap()
}

fn managed_restore_installation(
    active: &router_ab_core::TenantRootActiveRefreshV1,
    capability: &TenantRootManagedRestoreCapabilityV1,
    receipt_seed: u8,
    installed_at_ms: u64,
) -> TenantRootManagedRestoreInstallationReceiptV1 {
    let commitment = match capability.role() {
        TenantRootManagedRestoreRoleV1::DeriverA => {
            active.current().verified().commitments().deriver_a()
        }
        TenantRootManagedRestoreRoleV1::DeriverB => {
            active.current().verified().commitments().deriver_b()
        }
    };
    TenantRootManagedRestoreInstallationReceiptV1::new(
        digest(receipt_seed),
        capability.digest(),
        active.identity().digest().unwrap(),
        active.custody_lineage(),
        capability.role(),
        active.current().epoch(),
        active.current().activation().digest(),
        commitment.clone(),
        installed_at_ms,
    )
    .unwrap()
}

fn managed_restore_peer_receipt(
    active: &router_ab_core::TenantRootActiveRefreshV1,
    restored_role: TenantRootManagedRestoreRoleV1,
    receipt_seed: u8,
    verified_at_ms: u64,
) -> TenantRootManagedRestorePeerVerificationReceiptV1 {
    let role = restored_role.peer();
    let commitment = match role {
        TenantRootManagedRestoreRoleV1::DeriverA => {
            active.current().verified().commitments().deriver_a()
        }
        TenantRootManagedRestoreRoleV1::DeriverB => {
            active.current().verified().commitments().deriver_b()
        }
    };
    TenantRootManagedRestorePeerVerificationReceiptV1::new(
        digest(receipt_seed),
        active.identity().digest().unwrap(),
        active.custody_lineage(),
        role,
        active.current().epoch(),
        active.current().activation().digest(),
        commitment.clone(),
        verified_at_ms,
    )
    .unwrap()
}

fn managed_deletion_evidence(
    digest_seed: u8,
    completed_at_ms: u64,
) -> TenantRootDeletionEvidenceV1 {
    let deriver_a = TenantRootManagedRoleDestructionReceiptV1::new(
        TenantRootManagedRestoreRoleV1::DeriverA,
        digest(digest_seed),
        digest(digest_seed + 1),
        digest(digest_seed + 2),
        completed_at_ms - 2,
        completed_at_ms - 1,
    )
    .unwrap();
    let deriver_b = TenantRootManagedRoleDestructionReceiptV1::new(
        TenantRootManagedRestoreRoleV1::DeriverB,
        digest(digest_seed + 3),
        digest(digest_seed + 4),
        digest(digest_seed + 5),
        completed_at_ms - 2,
        completed_at_ms,
    )
    .unwrap();
    TenantRootDeletionEvidenceV1::ManagedHealing {
        roles: TenantRootManagedRoleDestructionReceiptsV1::new(deriver_a, deriver_b).unwrap(),
        service_cleanup: service_cleanup(digest_seed + 6, completed_at_ms),
    }
}

fn operational_deletion_evidence(
    digest_seed: u8,
    completed_at_ms: u64,
) -> TenantRootDeletionEvidenceV1 {
    let deriver_a = TenantRootOperationalRoleRemovalReceiptV1::new(
        TenantRootManagedRestoreRoleV1::DeriverA,
        digest(digest_seed),
        digest(digest_seed + 1),
        completed_at_ms - 1,
    )
    .unwrap();
    let deriver_b = TenantRootOperationalRoleRemovalReceiptV1::new(
        TenantRootManagedRestoreRoleV1::DeriverB,
        digest(digest_seed + 2),
        digest(digest_seed + 3),
        completed_at_ms,
    )
    .unwrap();
    TenantRootDeletionEvidenceV1::OperationalRotation {
        roles: TenantRootOperationalRoleRemovalReceiptsV1::new(deriver_a, deriver_b).unwrap(),
        service_cleanup: service_cleanup(digest_seed + 4, completed_at_ms),
        erasure_claim: TenantRootOperationalErasureClaimV1::CryptographicErasureUnverified,
    }
}

fn service_cleanup(digest_seed: u8, completed_at_ms: u64) -> TenantRootServiceCleanupReceiptV1 {
    TenantRootServiceCleanupReceiptV1::new(
        digest(digest_seed),
        digest(digest_seed + 1),
        digest(digest_seed + 2),
        digest(digest_seed + 3),
        digest(digest_seed + 4),
        completed_at_ms,
    )
    .unwrap()
}

fn fixed_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .unwrap()
}

fn backend_share_wire(share: &SigningRootShare) -> MpcPrfSigningRootShareWireV1 {
    MpcPrfSigningRootShareWireV1::new(SigningRootShareWire::from_share(share).to_bytes().to_vec())
        .unwrap()
}

fn signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    SigningKey::from_bytes(
        &[match role {
            TwoPartyDeriverRole::DeriverA => 0x51,
            TwoPartyDeriverRole::DeriverB => 0x61,
        }; 32],
    )
}

fn authenticated_evidence(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share: &SigningRootShare,
    peer: &SigningRootShare,
    proof_seed: u8,
) -> VerifiedTenantRootShareInstallationEvidenceV1 {
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
        &mut seeded_rng(proof_seed),
    )
    .unwrap();
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap();
    let key = signing_key(role);
    TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &key.to_bytes())
        .unwrap()
        .verify(key.verifying_key().as_bytes())
        .unwrap()
}

fn evidence_pair(
    context: &TenantRootCeremonyContextV1,
) -> (
    VerifiedTenantRootShareInstallationEvidenceV1,
    VerifiedTenantRootShareInstallationEvidenceV1,
    TwoPartyRootShareCommitments,
) {
    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    evidence_pair_for_shares(context, &share_a, &share_b, 1, 2)
}

fn evidence_pair_for_shares(
    context: &TenantRootCeremonyContextV1,
    share_a: &SigningRootShare,
    share_b: &SigningRootShare,
    proof_seed_a: u8,
    proof_seed_b: u8,
) -> (
    VerifiedTenantRootShareInstallationEvidenceV1,
    VerifiedTenantRootShareInstallationEvidenceV1,
    TwoPartyRootShareCommitments,
) {
    let commitments = TwoPartyRootShareCommitments::from_shares(&share_a, &share_b).unwrap();
    (
        authenticated_evidence(
            context.clone(),
            TwoPartyDeriverRole::DeriverA,
            &share_a,
            &share_b,
            proof_seed_a,
        ),
        authenticated_evidence(
            context.clone(),
            TwoPartyDeriverRole::DeriverB,
            &share_b,
            &share_a,
            proof_seed_b,
        ),
        commitments,
    )
}

fn refreshed_share(
    current: &SigningRootShare,
    recipient: TwoPartyDeriverRole,
    coefficient_a: &RootShareRefreshCoefficient,
    coefficient_b: &RootShareRefreshCoefficient,
) -> SigningRootShare {
    let contribution_a = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(recipient))
        .unwrap();
    let contribution_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(recipient))
        .unwrap();
    apply_two_party_root_share_refresh(current, contribution_a, contribution_b).unwrap()
}

fn active_refresh_state(
    lineage: TenantRootCustodyLineageId,
) -> (
    router_ab_core::TenantRootActiveRefreshV1,
    SigningRootShare,
    SigningRootShare,
) {
    active_refresh_state_with_policy(lineage, managed_backups())
}

fn active_refresh_state_with_policy(
    lineage: TenantRootCustodyLineageId,
    backup_policy: TenantRootBackupPolicyV1,
) -> (
    router_ab_core::TenantRootActiveRefreshV1,
    SigningRootShare,
    SigningRootShare,
) {
    let creation_context = context(lineage, 0x71);
    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let (evidence_a, evidence_b, _) =
        evidence_pair_for_shares(&creation_context, &share_a, &share_b, 21, 22);
    let active = TenantRootEmptyCreationV1::new(identity(), lineage)
        .start(&creation_context)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            backup_policy,
            canaries(),
            1_010_000,
        )
        .unwrap()
        .activate(TenantRootActivationReceiptV1::new(digest(30), 1_020_000).unwrap())
        .unwrap()
        .into_refresh_state();
    (active, share_a, share_b)
}

fn advance_active_refresh(
    active: router_ab_core::TenantRootActiveRefreshV1,
    current_a: &SigningRootShare,
    current_b: &SigningRootShare,
) -> (
    router_ab_core::TenantRootActiveRefreshV1,
    SigningRootShare,
    SigningRootShare,
) {
    let lineage = active.custody_lineage();
    let current_epoch = active.current().epoch();
    let next_epoch = current_epoch.next().unwrap();
    let refresh_context = refresh_context(
        lineage,
        current_epoch.get().get(),
        next_epoch.get().get(),
        0x7a,
    );
    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(71));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(72));
    let next_a = refreshed_share(
        current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    );
    let next_b = refreshed_share(
        current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    );
    let (evidence_a, evidence_b, _) =
        evidence_pair_for_shares(&refresh_context, &next_a, &next_b, 73, 74);
    let active = active
        .start(&refresh_context)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .unwrap()
        .activate(TenantRootActivationReceiptV1::new(digest(75), 1_020_000).unwrap())
        .unwrap()
        .finish_retirement(
            TenantRootRoleRetirementReceiptsV1::new(digest(76), digest(77), 1_021_000).unwrap(),
        )
        .unwrap();
    (active, next_a, next_b)
}

fn stable_context_digest(
    stable_context: &StableTenantDerivationContextV2,
) -> TenantRootProtocolDigestV1 {
    stable_context.digest()
}

fn custody_binding(
    active: &router_ab_core::TenantRootActiveRefreshV1,
    stable_context: &StableTenantDerivationContextV2,
) -> TenantRootCustodyBindingV1 {
    TenantRootCustodyBindingV1::from_active(
        active,
        TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9").unwrap(),
        TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
        TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
        TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        stable_context,
        TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
    )
    .unwrap()
}

fn digest(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).unwrap()
}

fn installation_receipts() -> TenantRootRoleInstallationReceiptsV1 {
    TenantRootRoleInstallationReceiptsV1::new(digest(1), digest(2)).unwrap()
}

fn managed_backups() -> TenantRootBackupPolicyV1 {
    TenantRootBackupPolicyV1::CurrentRoleBackups(
        TenantRootRoleBackupReceiptsV1::new(digest(3), digest(4)).unwrap(),
    )
}

fn canaries() -> TenantRootCanaryReceiptsV1 {
    TenantRootCanaryReceiptsV1::new(digest(5), digest(6)).unwrap()
}

fn assert_state_kind(state: impl Into<TenantRootCreationStateV1>, expected: &str) {
    let state = state.into();
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["kind"], expected);
}

#[test]
fn creation_restart_projects_one_forward_recovery_action_from_every_state() {
    let custody_lineage = lineage(0x30);
    let creation_context = context(custody_lineage, 0x20);
    let ceremony_digest = creation_context.digest().unwrap();
    let (evidence_a, evidence_b, _) = evidence_pair(&creation_context);
    let empty = TenantRootEmptyCreationV1::new(identity(), custody_lineage);
    let empty_plan = TenantRootCreationStateV1::from(empty.clone())
        .recovery_plan()
        .unwrap();
    assert_eq!(empty_plan.identity_digest(), identity().digest().unwrap());
    assert_eq!(empty_plan.custody_lineage(), custody_lineage);
    assert_eq!(empty_plan.revision(), 0);
    assert_eq!(
        empty_plan.action(),
        TenantRootCreationRecoveryActionV1::StartFreshCeremony
    );

    let preparing = empty.start(&creation_context).unwrap();
    let preparing_plan = TenantRootCreationStateV1::from(preparing.clone())
        .recovery_plan()
        .unwrap();
    assert_eq!(
        preparing_plan.action(),
        TenantRootCreationRecoveryActionV1::AbortPendingEpoch {
            pending_epoch: TenantRootShareEpoch::INITIAL,
            ceremony_digest,
        }
    );

    let verified = preparing
        .clone()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .unwrap();
    assert_eq!(
        TenantRootCreationStateV1::from(verified.clone())
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootCreationRecoveryActionV1::AbortPendingEpoch {
            pending_epoch: TenantRootShareEpoch::INITIAL,
            ceremony_digest,
        }
    );

    let activation_digest = digest(0x29);
    let active = verified
        .activate(TenantRootActivationReceiptV1::new(activation_digest, 1_020_000).unwrap())
        .unwrap();
    assert_eq!(
        TenantRootCreationStateV1::from(active)
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootCreationRecoveryActionV1::KeepActive {
            active_epoch: TenantRootShareEpoch::INITIAL,
            activation_receipt_digest: activation_digest,
        }
    );

    let failed = preparing
        .clone()
        .fail_with_cleanup(
            TenantRootCreationFailureV1::new(digest(0x2a), 1_005_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(0x2b), digest(0x2c), 1_006_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        TenantRootCreationStateV1::from(failed)
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootCreationRecoveryActionV1::StartFreshCeremonyAfterCleanup {
            failed_epoch: TenantRootShareEpoch::INITIAL,
            failed_ceremony_digest: ceremony_digest,
        }
    );

    let cleanup_incomplete = preparing
        .fail_with_incomplete_cleanup(
            TenantRootCreationFailureV1::new(digest(0x2d), 1_005_000).unwrap(),
            TenantRootPendingCleanupFailureV1::deriver_b_incomplete(
                digest(0x2e),
                digest(0x2f),
                1_006_000,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        TenantRootCreationStateV1::from(cleanup_incomplete)
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootCreationRecoveryActionV1::ResumePendingCleanup {
            pending_epoch: TenantRootShareEpoch::INITIAL,
            ceremony_digest,
        }
    );
}

#[test]
fn refresh_restart_projects_abort_or_forward_recovery_from_every_state() {
    let custody_lineage = lineage(0x40);
    let (active, current_a, current_b) = active_refresh_state(custody_lineage);
    let active_epoch = TenantRootShareEpoch::INITIAL;
    assert_eq!(
        TenantRootRefreshStateV1::from(active.clone())
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootRefreshRecoveryActionV1::KeepActive { active_epoch }
    );

    let ceremony = refresh_context(custody_lineage, 1, 2, 0x70);
    let ceremony_digest = ceremony.digest().unwrap();
    let pending_epoch = TenantRootShareEpoch::new(2).unwrap();
    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(0x31));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(0x32));
    let next_a = refreshed_share(
        &current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    );
    let next_b = refreshed_share(
        &current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    );
    let (evidence_a, evidence_b, _) =
        evidence_pair_for_shares(&ceremony, &next_a, &next_b, 0x33, 0x34);
    let preparing = active.start(&ceremony).unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(preparing.clone())
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootRefreshRecoveryActionV1::AbortPendingEpoch {
            active_epoch,
            pending_epoch,
            ceremony_digest,
        }
    );

    let verified = preparing
        .clone()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(verified.clone())
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootRefreshRecoveryActionV1::AbortPendingEpoch {
            active_epoch,
            pending_epoch,
            ceremony_digest,
        }
    );

    let activation_digest = digest(0x35);
    let retiring = verified
        .activate(TenantRootActivationReceiptV1::new(activation_digest, 1_020_000).unwrap())
        .unwrap();
    let retiring_plan = TenantRootRefreshStateV1::from(retiring)
        .recovery_plan()
        .unwrap();
    assert_eq!(
        retiring_plan.identity_digest(),
        identity().digest().unwrap()
    );
    assert_eq!(retiring_plan.custody_lineage(), custody_lineage);
    assert_eq!(retiring_plan.revision(), 6);
    assert_eq!(
        retiring_plan.action(),
        TenantRootRefreshRecoveryActionV1::ResumeRetirement {
            active_epoch: pending_epoch,
            retiring_epoch: active_epoch,
            activation_receipt_digest: activation_digest,
        }
    );

    let failed = preparing
        .clone()
        .fail_with_cleanup(
            TenantRootRefreshFailureV1::new(digest(0x36), 1_005_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(0x37), digest(0x38), 1_006_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(failed)
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootRefreshRecoveryActionV1::StartFreshRefreshAfterCleanup {
            active_epoch,
            failed_epoch: pending_epoch,
            failed_ceremony_digest: ceremony_digest,
        }
    );

    let cleanup_incomplete = preparing
        .fail_with_incomplete_cleanup(
            TenantRootRefreshFailureV1::new(digest(0x39), 1_005_000).unwrap(),
            TenantRootPendingCleanupFailureV1::deriver_a_incomplete(
                digest(0x3a),
                digest(0x3b),
                1_006_000,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(cleanup_incomplete)
            .recovery_plan()
            .unwrap()
            .action(),
        TenantRootRefreshRecoveryActionV1::ResumePendingCleanup {
            active_epoch,
            pending_epoch,
            ceremony_digest,
        }
    );
}

#[test]
fn creation_moves_only_empty_to_preparing_to_verified_to_active() {
    let lineage = lineage(0x31);
    let context = context(lineage, 0x21);
    let (evidence_a, evidence_b, expected_commitments) = evidence_pair(&context);
    let empty = TenantRootEmptyCreationV1::new(identity(), lineage);
    assert_eq!(TenantRootCreationStateV1::from(empty.clone()).revision(), 0);

    let preparing = empty.start(&context).unwrap();
    assert_eq!(
        TenantRootCreationStateV1::from(preparing.clone()).revision(),
        1
    );
    let verified = preparing
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .unwrap();
    assert_eq!(
        TenantRootCreationStateV1::from(verified.clone()).revision(),
        2
    );
    let active = verified
        .activate(TenantRootActivationReceiptV1::new(digest(7), 1_020_000).unwrap())
        .unwrap();

    assert_eq!(active.revision(), 3);
    assert_eq!(
        active.current().verified().commitments().root_commitment(),
        &expected_commitments.root().to_bytes(),
    );
    assert_eq!(active.current().verified().pending().epoch().get().get(), 1);
    assert!(matches!(
        active.current().verified().backup_policy(),
        TenantRootBackupPolicyV1::CurrentRoleBackups(_)
    ));
    assert_state_kind(active, "active");
}

#[test]
fn explicit_accepted_loss_is_the_only_backup_free_activation_branch() {
    let lineage = lineage(0x32);
    let context = context(lineage, 0x22);
    let (evidence_a, evidence_b, _) = evidence_pair(&context);
    let verified = TenantRootEmptyCreationV1::new(identity(), lineage)
        .start(&context)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(
                TenantRootAcceptedLossReceiptV1::new(digest(8)),
            ),
            canaries(),
            1_010_000,
        )
        .unwrap();

    assert!(matches!(
        verified
            .activate(TenantRootActivationReceiptV1::new(digest(9), 1_020_000).unwrap())
            .unwrap()
            .current(),
        ActiveTenantRootEpochV1 { .. }
    ));
    assert!(TenantRootLifecycleReceiptDigestV1::from_bytes([0; 32]).is_err());
    assert!(TenantRootRoleBackupReceiptsV1::new(digest(3), digest(3)).is_err());
    assert!(TenantRootRoleInstallationReceiptsV1::new(digest(1), digest(1)).is_err());
    assert!(TenantRootCanaryReceiptsV1::new(digest(5), digest(5)).is_err());
}

#[test]
fn creation_rejects_identity_lineage_and_ceremony_substitution() {
    let expected_lineage = lineage(0x33);
    let other_lineage = lineage(0x34);
    let other_context = context(other_lineage, 0x23);
    assert!(TenantRootEmptyCreationV1::new(identity(), expected_lineage)
        .start(&other_context)
        .is_err());

    let expected_context = context(expected_lineage, 0x24);
    let preparing = TenantRootEmptyCreationV1::new(identity(), expected_lineage)
        .start(&expected_context)
        .unwrap();
    let substituted_context = context(expected_lineage, 0x25);
    let (evidence_a, evidence_b, _) = evidence_pair(&substituted_context);
    assert!(preparing
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .is_err());
}

#[test]
fn pre_activation_failures_distinguish_complete_and_incomplete_cleanup() {
    let lineage = lineage(0x35);
    let creation_context = context(lineage, 0x26);
    let preparing = TenantRootEmptyCreationV1::new(identity(), lineage)
        .start(&creation_context)
        .unwrap();
    let complete: TenantRootFailedBeforeActivationCreationV1 = preparing
        .clone()
        .fail_with_cleanup(
            TenantRootCreationFailureV1::new(digest(10), 1_005_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(11), digest(12), 1_006_000).unwrap(),
        )
        .unwrap();
    assert_state_kind(complete, "failed_before_activation");

    let incomplete: TenantRootCleanupIncompleteCreationV1 = preparing
        .clone()
        .fail_with_incomplete_cleanup(
            TenantRootCreationFailureV1::new(digest(13), 1_005_000).unwrap(),
            TenantRootPendingCleanupFailureV1::deriver_a_incomplete(
                digest(14),
                digest(15),
                1_006_000,
            )
            .unwrap(),
        )
        .unwrap();
    assert_state_kind(incomplete.clone(), "cleanup_incomplete");
    let cleaned = incomplete
        .complete_cleanup(
            TenantRootPendingCleanupReceiptV1::new(digest(23), digest(24), 1_007_000).unwrap(),
        )
        .unwrap();
    assert!(cleaned.clone().retry(&creation_context).is_err());
    let fresh_context = context(lineage, 0x66);
    assert_eq!(
        TenantRootCreationStateV1::from(cleaned.retry(&fresh_context).unwrap()).revision(),
        4
    );

    assert!(preparing
        .clone()
        .fail_with_cleanup(
            TenantRootCreationFailureV1::new(digest(16), ISSUED_AT_MS - 1).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(17), digest(18), 1_006_000).unwrap(),
        )
        .is_err());
    assert!(preparing
        .fail_with_cleanup(
            TenantRootCreationFailureV1::new(digest(19), 1_007_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(20), digest(21), 1_006_000).unwrap(),
        )
        .is_err());
}

#[test]
fn verification_and_activation_cannot_cross_the_ceremony_expiry() {
    let lineage = lineage(0x36);
    let context = context(lineage, 0x27);
    let (evidence_a, evidence_b, _) = evidence_pair(&context);
    let preparing = TenantRootEmptyCreationV1::new(identity(), lineage)
        .start(&context)
        .unwrap();
    assert!(preparing
        .clone()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            EXPIRES_AT_MS + 1,
        )
        .is_err());

    let verified = preparing
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .unwrap();
    assert!(verified
        .activate(TenantRootActivationReceiptV1::new(digest(22), EXPIRES_AT_MS + 1).unwrap())
        .is_err());
}

#[test]
fn refresh_is_forward_only_and_returns_to_active_after_both_retirements() {
    let lineage = lineage(0x41);
    let (active, current_a, current_b) = active_refresh_state(lineage);
    let stable_root = *active.current().verified().commitments().root_commitment();
    let refresh_context = refresh_context(lineage, 1, 2, 0x72);
    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(31));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(32));
    let next_a = refreshed_share(
        &current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    );
    let next_b = refreshed_share(
        &current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    );
    let (evidence_a, evidence_b, _) =
        evidence_pair_for_shares(&refresh_context, &next_a, &next_b, 33, 34);

    let preparing = active.start(&refresh_context).unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(preparing.clone()).revision(),
        4
    );
    let verified = preparing
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(verified.clone()).revision(),
        5
    );
    let retiring = verified
        .activate(TenantRootActivationReceiptV1::new(digest(31), 1_020_000).unwrap())
        .unwrap();
    assert_eq!(retiring.current().epoch().get().get(), 2);
    assert_eq!(retiring.previous().active().epoch().get().get(), 1);
    assert_eq!(
        retiring
            .current()
            .verified()
            .commitments()
            .root_commitment(),
        &stable_root
    );
    assert_eq!(
        TenantRootRefreshStateV1::from(retiring.clone()).revision(),
        6
    );

    let active = retiring
        .finish_retirement(
            TenantRootRoleRetirementReceiptsV1::new(digest(32), digest(33), 1_021_000).unwrap(),
        )
        .unwrap();
    assert_eq!(active.current().epoch().get().get(), 2);
    assert_eq!(active.revision(), 7);
    let refresh_json = serde_json::to_value(TenantRootRefreshStateV1::from(active)).unwrap();
    assert_eq!(refresh_json["kind"], "active");
}

#[test]
fn refresh_rejects_epoch_root_and_ceremony_substitution() {
    let lineage = lineage(0x43);
    let (active, current_a, current_b) = active_refresh_state(lineage);
    assert!(active
        .clone()
        .start(&refresh_context(lineage, 2, 3, 0x73))
        .is_err());

    let expected_context = refresh_context(lineage, 1, 2, 0x74);
    let preparing = active.start(&expected_context).unwrap();
    let unrelated_a = fixed_share(TwoPartyDeriverRole::DeriverA, 51);
    let unrelated_b = fixed_share(TwoPartyDeriverRole::DeriverB, 83);
    let (unrelated_evidence_a, unrelated_evidence_b, _) =
        evidence_pair_for_shares(&expected_context, &unrelated_a, &unrelated_b, 35, 36);
    assert!(preparing
        .clone()
        .verify(
            &unrelated_evidence_a,
            &unrelated_evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .is_err());

    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(37));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(38));
    let next_a = refreshed_share(
        &current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    );
    let next_b = refreshed_share(
        &current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    );
    let other_context = refresh_context(lineage, 1, 2, 0x75);
    let (other_evidence_a, other_evidence_b, _) =
        evidence_pair_for_shares(&other_context, &next_a, &next_b, 39, 40);
    assert!(preparing
        .verify(
            &other_evidence_a,
            &other_evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .is_err());
}

#[test]
fn refresh_failure_keeps_the_old_epoch_and_retirement_cannot_roll_back() {
    let lineage = lineage(0x44);
    let (active, current_a, current_b) = active_refresh_state(lineage);
    let ceremony = refresh_context(lineage, 1, 2, 0x76);
    let preparing = active.clone().start(&ceremony).unwrap();
    let failed = preparing
        .clone()
        .fail_with_cleanup(
            TenantRootRefreshFailureV1::new(digest(40), 1_005_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(41), digest(42), 1_006_000).unwrap(),
        )
        .unwrap();
    let failed_json = serde_json::to_value(TenantRootRefreshStateV1::from(failed.clone())).unwrap();
    assert_eq!(failed_json["kind"], "failed_before_activation");
    assert_eq!(
        failed_json["state"]["current"]["verified"]["pending"]["epoch"],
        1
    );
    assert!(failed.clone().retry(&ceremony).is_err());
    let retry_context = refresh_context(lineage, 1, 2, 0x77);
    assert_eq!(
        TenantRootRefreshStateV1::from(failed.retry(&retry_context).unwrap()).revision(),
        6
    );

    let incomplete = preparing
        .fail_with_incomplete_cleanup(
            TenantRootRefreshFailureV1::new(digest(43), 1_005_000).unwrap(),
            TenantRootPendingCleanupFailureV1::both_roles_incomplete(digest(44), 1_006_000)
                .unwrap(),
        )
        .unwrap();
    let incomplete_json =
        serde_json::to_value(TenantRootRefreshStateV1::from(incomplete.clone())).unwrap();
    assert_eq!(incomplete_json["kind"], "cleanup_incomplete");
    let cleaned = incomplete
        .complete_cleanup(
            TenantRootPendingCleanupReceiptV1::new(digest(48), digest(49), 1_007_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(
            cleaned
                .retry(&refresh_context(lineage, 1, 2, 0x78))
                .unwrap()
        )
        .revision(),
        7
    );

    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(41));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(42));
    let next_a = refreshed_share(
        &current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    );
    let next_b = refreshed_share(
        &current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    );
    let (evidence_a, evidence_b, _) = evidence_pair_for_shares(&ceremony, &next_a, &next_b, 43, 44);
    let retiring = active
        .start(&ceremony)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_010_000,
        )
        .unwrap()
        .activate(TenantRootActivationReceiptV1::new(digest(45), 1_020_000).unwrap())
        .unwrap();
    assert!(retiring
        .finish_retirement(
            TenantRootRoleRetirementReceiptsV1::new(digest(46), digest(47), 1_019_999).unwrap()
        )
        .is_err());
}

#[test]
fn managed_restore_requires_commitment_verification_and_forward_refresh() {
    let lineage = lineage(0x51);
    let (active, current_a, current_b) = active_refresh_state(lineage);
    let stable_root = *active.current().verified().commitments().root_commitment();
    let available = TenantRootManagedRestoreAvailableV1::new(active.clone()).unwrap();
    let unavailable = available
        .mark_role_unavailable(
            TenantRootRoleUnavailableReceiptV1::new(
                digest(60),
                TenantRootManagedRestoreRoleV1::DeriverA,
                1_021_000,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(unavailable.revision(), 4);

    let capability = managed_restore_capability(
        &active,
        TenantRootManagedRestoreRoleV1::DeriverA,
        61,
        1_022_000,
        1_050_000,
    );
    let restoring = match unavailable
        .start_restore(capability.clone(), 1_023_000)
        .unwrap()
    {
        TenantRootManagedRestoreInstallingV1::RestoringA(state) => state,
        TenantRootManagedRestoreInstallingV1::RestoringB(_) => {
            panic!("Deriver A outage selected the wrong restore branch")
        }
    };
    let verifying = restoring
        .accept_installation(managed_restore_installation(
            &active,
            &capability,
            62,
            1_024_000,
        ))
        .unwrap();
    let forward_context = refresh_context_at(lineage, 1, 2, 0x81, 1_026_000, 1_049_000);
    let forward = verifying
        .begin_forward_refresh(
            managed_restore_peer_receipt(
                &active,
                TenantRootManagedRestoreRoleV1::DeriverA,
                63,
                1_025_000,
            ),
            &forward_context,
        )
        .unwrap();
    let forward_json =
        serde_json::to_value(TenantRootManagedRestoreStateV1::from(forward.clone())).unwrap();
    assert_eq!(forward_json["kind"], "forward_refreshing");
    assert_eq!(forward_json["state"]["phase"], "preparing");
    assert_eq!(
        TenantRootManagedRestoreStateV1::from(forward.clone()).revision(),
        7
    );

    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(51));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(52));
    let next_a = refreshed_share(
        &current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    );
    let next_b = refreshed_share(
        &current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    );
    let (evidence_a, evidence_b, _) =
        evidence_pair_for_shares(&forward_context, &next_a, &next_b, 53, 54);
    let retiring = forward
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts(),
            managed_backups(),
            canaries(),
            1_030_000,
        )
        .unwrap()
        .activate(TenantRootActivationReceiptV1::new(digest(64), 1_040_000).unwrap())
        .unwrap();
    let available = retiring
        .finish_retirement(
            TenantRootRoleRetirementReceiptsV1::new(digest(65), digest(66), 1_041_000).unwrap(),
        )
        .unwrap();

    assert_eq!(available.active().current().epoch().get().get(), 2);
    assert_eq!(available.revision(), 10);
    assert_eq!(
        available
            .active()
            .current()
            .verified()
            .commitments()
            .root_commitment(),
        &stable_root
    );
    let available_json =
        serde_json::to_value(TenantRootManagedRestoreStateV1::from(available)).unwrap();
    assert_eq!(available_json["kind"], "available");
}

#[test]
fn accepted_permanent_loss_policy_cannot_enter_managed_restore() {
    let (active, _, _) = active_refresh_state_with_policy(
        lineage(0x57),
        TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(
            TenantRootAcceptedLossReceiptV1::new(digest(107)),
        ),
    );

    assert!(TenantRootManagedRestoreAvailableV1::new(active).is_err());
}

#[test]
fn managed_restore_has_exact_role_branches_and_rejects_dual_loss() {
    for (lineage_seed, role, expected_kind) in [
        (
            0x52,
            TenantRootManagedRestoreRoleV1::DeriverA,
            "restoring_a",
        ),
        (
            0x53,
            TenantRootManagedRestoreRoleV1::DeriverB,
            "restoring_b",
        ),
    ] {
        let lineage = lineage(lineage_seed);
        let (active, _, _) = active_refresh_state(lineage);
        let unavailable = TenantRootManagedRestoreAvailableV1::new(active.clone())
            .unwrap()
            .mark_role_unavailable(
                TenantRootRoleUnavailableReceiptV1::new(digest(70), role, 1_021_000).unwrap(),
            )
            .unwrap();

        let wrong_role = managed_restore_capability(&active, role.peer(), 71, 1_022_000, 1_050_000);
        let error = unavailable
            .clone()
            .start_restore(wrong_role, 1_023_000)
            .unwrap_err();
        assert!(error
            .message()
            .contains("dual-role loss requires tenant recovery"));

        let capability = managed_restore_capability(&active, role, 72, 1_022_000, 1_050_000);
        let installing = unavailable
            .start_restore(capability.clone(), 1_023_000)
            .unwrap();
        let state_json =
            serde_json::to_value(TenantRootManagedRestoreStateV1::from(installing.clone()))
                .unwrap();
        assert_eq!(state_json["kind"], expected_kind);

        let verifying = match installing {
            TenantRootManagedRestoreInstallingV1::RestoringA(state) => state
                .accept_installation(managed_restore_installation(
                    &active,
                    &capability,
                    73,
                    1_024_000,
                ))
                .unwrap(),
            TenantRootManagedRestoreInstallingV1::RestoringB(state) => state
                .accept_installation(managed_restore_installation(
                    &active,
                    &capability,
                    73,
                    1_024_000,
                ))
                .unwrap(),
        };
        let verifying_json =
            serde_json::to_value(TenantRootManagedRestoreStateV1::from(verifying)).unwrap();
        assert_eq!(verifying_json["kind"], "verifying");
    }
}

#[test]
fn managed_restore_rejects_identity_epoch_commitment_and_peer_substitution() {
    let lineage = lineage(0x54);
    let (active, _, _) = active_refresh_state(lineage);
    let unavailable = TenantRootManagedRestoreAvailableV1::new(active.clone())
        .unwrap()
        .mark_role_unavailable(
            TenantRootRoleUnavailableReceiptV1::new(
                digest(80),
                TenantRootManagedRestoreRoleV1::DeriverA,
                1_021_000,
            )
            .unwrap(),
        )
        .unwrap();

    let wrong_identity = TenantRootManagedRestoreCapabilityV1::new(
        digest(81),
        TenantRootIdentityV1::new("other-org", "project-2", "production", "root-main", "v3")
            .unwrap()
            .digest()
            .unwrap(),
        lineage,
        TenantRootManagedRestoreRoleV1::DeriverA,
        active.current().epoch(),
        active.current().activation().digest(),
        1_022_000,
        1_050_000,
    )
    .unwrap();
    assert!(unavailable
        .clone()
        .start_restore(wrong_identity, 1_023_000)
        .is_err());

    let wrong_epoch = TenantRootManagedRestoreCapabilityV1::new(
        digest(82),
        active.identity().digest().unwrap(),
        lineage,
        TenantRootManagedRestoreRoleV1::DeriverA,
        TenantRootShareEpoch::new(2).unwrap(),
        active.current().activation().digest(),
        1_022_000,
        1_050_000,
    )
    .unwrap();
    assert!(unavailable
        .clone()
        .start_restore(wrong_epoch, 1_023_000)
        .is_err());

    let capability = managed_restore_capability(
        &active,
        TenantRootManagedRestoreRoleV1::DeriverA,
        83,
        1_022_000,
        1_050_000,
    );
    let restoring = match unavailable
        .start_restore(capability.clone(), 1_023_000)
        .unwrap()
    {
        TenantRootManagedRestoreInstallingV1::RestoringA(state) => state,
        TenantRootManagedRestoreInstallingV1::RestoringB(_) => unreachable!(),
    };
    let wrong_commitment = TenantRootManagedRestoreInstallationReceiptV1::new(
        digest(84),
        capability.digest(),
        active.identity().digest().unwrap(),
        lineage,
        TenantRootManagedRestoreRoleV1::DeriverA,
        active.current().epoch(),
        active.current().activation().digest(),
        active
            .current()
            .verified()
            .commitments()
            .deriver_b()
            .clone(),
        1_024_000,
    )
    .unwrap();
    assert!(restoring
        .clone()
        .accept_installation(wrong_commitment)
        .is_err());

    let verifying = restoring
        .accept_installation(managed_restore_installation(
            &active,
            &capability,
            85,
            1_024_000,
        ))
        .unwrap();
    let wrong_peer = TenantRootManagedRestorePeerVerificationReceiptV1::new(
        digest(86),
        active.identity().digest().unwrap(),
        lineage,
        TenantRootManagedRestoreRoleV1::DeriverA,
        active.current().epoch(),
        active.current().activation().digest(),
        active
            .current()
            .verified()
            .commitments()
            .deriver_a()
            .clone(),
        1_025_000,
    )
    .unwrap();
    assert!(verifying
        .begin_forward_refresh(
            wrong_peer,
            &refresh_context_at(lineage, 1, 2, 0x82, 1_026_000, 1_049_000),
        )
        .is_err());
}

#[test]
fn managed_restore_cleanup_blocks_replay_until_complete_and_requires_fresh_capability() {
    let lineage = lineage(0x55);
    let (active, _, _) = active_refresh_state(lineage);
    let unavailable = TenantRootManagedRestoreAvailableV1::new(active.clone())
        .unwrap()
        .mark_role_unavailable(
            TenantRootRoleUnavailableReceiptV1::new(
                digest(90),
                TenantRootManagedRestoreRoleV1::DeriverA,
                1_021_000,
            )
            .unwrap(),
        )
        .unwrap();
    let capability = managed_restore_capability(
        &active,
        TenantRootManagedRestoreRoleV1::DeriverA,
        91,
        1_022_000,
        1_050_000,
    );
    let restoring = match unavailable
        .start_restore(capability.clone(), 1_023_000)
        .unwrap()
    {
        TenantRootManagedRestoreInstallingV1::RestoringA(state) => state,
        TenantRootManagedRestoreInstallingV1::RestoringB(_) => unreachable!(),
    };
    let incomplete = restoring
        .fail_with_incomplete_cleanup(
            TenantRootManagedRestoreFailureV1::new(digest(92), 1_024_000).unwrap(),
            TenantRootManagedRestoreCleanupFailureV1::new(
                digest(93),
                TenantRootManagedRestoreRoleV1::DeriverA,
                1_025_000,
            )
            .unwrap(),
        )
        .unwrap();
    let incomplete_json =
        serde_json::to_value(TenantRootManagedRestoreStateV1::from(incomplete.clone())).unwrap();
    assert_eq!(incomplete_json["kind"], "cleanup_incomplete");
    assert!(incomplete
        .clone()
        .complete_cleanup(
            TenantRootManagedRestoreCleanupReceiptV1::new(
                digest(94),
                TenantRootManagedRestoreRoleV1::DeriverB,
                1_026_000,
            )
            .unwrap(),
        )
        .is_err());

    let unavailable = incomplete
        .complete_cleanup(
            TenantRootManagedRestoreCleanupReceiptV1::new(
                digest(95),
                TenantRootManagedRestoreRoleV1::DeriverA,
                1_026_000,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(unavailable
        .clone()
        .start_restore(capability, 1_027_000)
        .is_err());

    let fresh = managed_restore_capability(
        &active,
        TenantRootManagedRestoreRoleV1::DeriverA,
        96,
        1_027_000,
        1_055_000,
    );
    let retry = unavailable.start_restore(fresh, 1_028_000).unwrap();
    assert_eq!(TenantRootManagedRestoreStateV1::from(retry).revision(), 8);
}

#[test]
fn managed_restore_forward_refresh_failure_cannot_unfence_the_old_epoch() {
    let lineage = lineage(0x56);
    let (active, _, _) = active_refresh_state(lineage);
    let capability = managed_restore_capability(
        &active,
        TenantRootManagedRestoreRoleV1::DeriverB,
        101,
        1_022_000,
        1_060_000,
    );
    let restoring = TenantRootManagedRestoreAvailableV1::new(active.clone())
        .unwrap()
        .mark_role_unavailable(
            TenantRootRoleUnavailableReceiptV1::new(
                digest(100),
                TenantRootManagedRestoreRoleV1::DeriverB,
                1_021_000,
            )
            .unwrap(),
        )
        .unwrap()
        .start_restore(capability.clone(), 1_023_000)
        .unwrap();
    let restoring = match restoring {
        TenantRootManagedRestoreInstallingV1::RestoringB(state) => state,
        TenantRootManagedRestoreInstallingV1::RestoringA(_) => unreachable!(),
    };
    let verifying = restoring
        .accept_installation(managed_restore_installation(
            &active,
            &capability,
            102,
            1_024_000,
        ))
        .unwrap();
    let ceremony = refresh_context_at(lineage, 1, 2, 0x83, 1_026_000, 1_055_000);
    let forward = verifying
        .begin_forward_refresh(
            managed_restore_peer_receipt(
                &active,
                TenantRootManagedRestoreRoleV1::DeriverB,
                103,
                1_025_000,
            ),
            &ceremony,
        )
        .unwrap();
    let failed = forward
        .fail_with_cleanup(
            TenantRootRefreshFailureV1::new(digest(104), 1_027_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(105), digest(106), 1_028_000).unwrap(),
        )
        .unwrap();
    let failed_json =
        serde_json::to_value(TenantRootManagedRestoreStateV1::from(failed.clone())).unwrap();
    assert_eq!(failed_json["kind"], "forward_refreshing");
    assert_eq!(failed_json["state"]["phase"], "failed_before_activation");
    assert!(failed.clone().retry(&ceremony).is_err());

    let fresh = refresh_context_at(lineage, 1, 2, 0x84, 1_029_000, 1_059_000);
    let retry = failed.retry(&fresh).unwrap();
    let retry_json = serde_json::to_value(TenantRootManagedRestoreStateV1::from(retry)).unwrap();
    assert_eq!(retry_json["kind"], "forward_refreshing");
    assert_eq!(retry_json["state"]["phase"], "preparing");
}

#[test]
fn managed_root_deletion_is_forward_only_and_requires_permanent_destruction_evidence() {
    let (active, _, _) = active_refresh_state(lineage(0x61));
    let stable_root = *active.current().verified().commitments().root_commitment();
    let deletion = TenantRootDeletionActiveV1::new(
        active.clone(),
        TenantRootDestructionProfileV1::ManagedHealing,
    )
    .unwrap();
    let fenced = deletion
        .fence(
            TenantRootDeletionAuthorizationV1::new(digest(110), digest(111), 1_021_000).unwrap(),
            TenantRootDeletionFenceReceiptV1::new(digest(112), 1_022_000).unwrap(),
        )
        .unwrap();
    assert_eq!(
        TenantRootDeletionStateV1::from(fenced.clone()).revision(),
        4
    );
    let destroying = fenced
        .begin_destruction(
            TenantRootDeletionDrainReceiptV1::new(digest(113), active.current().epoch(), 1_023_000)
                .unwrap(),
            TenantRootDestructionCommandV1::new(digest(114), 1_024_000).unwrap(),
        )
        .unwrap();
    let destroying_json =
        serde_json::to_value(TenantRootDeletionStateV1::from(destroying.clone())).unwrap();
    assert_eq!(destroying_json["kind"], "destroying");
    assert_eq!(
        destroying
            .clone()
            .complete(
                operational_deletion_evidence(120, 1_028_000),
                TenantRootDeletedReceiptV1::new(digest(130), 1_029_000).unwrap(),
            )
            .unwrap_err()
            .message(),
        "tenant-root deletion evidence does not match the deployment profile"
    );

    let deleted = destroying
        .complete(
            managed_deletion_evidence(131, 1_028_000),
            TenantRootDeletedReceiptV1::new(digest(150), 1_029_000).unwrap(),
        )
        .unwrap();
    assert_eq!(deleted.revision(), 6);
    assert_eq!(deleted.root_commitment(), &stable_root);
    let deleted_json = serde_json::to_value(TenantRootDeletionStateV1::from(deleted)).unwrap();
    assert_eq!(deleted_json["kind"], "deleted");
    assert_eq!(deleted_json["state"]["profile"], "managed_healing_v1");
    assert_eq!(
        deleted_json["state"]["evidence"]["profile"],
        "managed_healing_v1"
    );
    assert_eq!(
        deleted_json["state"]["tenantCopies"],
        "outside_service_control"
    );
}

#[test]
fn root_deletion_rejects_undrained_or_wrong_epoch_and_preserves_partial_failure() {
    let (active, _, _) = active_refresh_state(lineage(0x62));
    let fenced = TenantRootDeletionActiveV1::new(
        active.clone(),
        TenantRootDestructionProfileV1::OperationalRotation,
    )
    .unwrap()
    .fence(
        TenantRootDeletionAuthorizationV1::new(digest(151), digest(152), 1_021_000).unwrap(),
        TenantRootDeletionFenceReceiptV1::new(digest(153), 1_022_000).unwrap(),
    )
    .unwrap();
    assert!(fenced
        .clone()
        .begin_destruction(
            TenantRootDeletionDrainReceiptV1::new(
                digest(154),
                TenantRootShareEpoch::new(2).unwrap(),
                1_023_000,
            )
            .unwrap(),
            TenantRootDestructionCommandV1::new(digest(155), 1_024_000).unwrap(),
        )
        .is_err());
    assert!(
        fenced
            .clone()
            .begin_destruction(
                TenantRootDeletionDrainReceiptV1::new(
                    digest(156),
                    active.current().epoch(),
                    1_021_999,
                )
                .unwrap(),
                TenantRootDestructionCommandV1::new(digest(157), 1_024_000).unwrap(),
            )
            .is_err()
    );

    let destroying = fenced
        .begin_destruction(
            TenantRootDeletionDrainReceiptV1::new(digest(158), active.current().epoch(), 1_023_000)
                .unwrap(),
            TenantRootDestructionCommandV1::new(digest(159), 1_024_000).unwrap(),
        )
        .unwrap();
    let incomplete = destroying
        .record_incomplete(
            TenantRootDestructionFailureV1::new(digest(160), 1_025_000).unwrap(),
            TenantRootDestructionProgressReceiptV1::new(digest(161), 1_026_000).unwrap(),
        )
        .unwrap();
    let incomplete_json =
        serde_json::to_value(TenantRootDeletionStateV1::from(incomplete.clone())).unwrap();
    assert_eq!(incomplete_json["kind"], "destruction_incomplete");

    let deleted = incomplete
        .complete(
            operational_deletion_evidence(162, 1_030_000),
            TenantRootDeletedReceiptV1::new(digest(180), 1_031_000).unwrap(),
        )
        .unwrap();
    assert_eq!(deleted.revision(), 7);
    let deleted_json = serde_json::to_value(TenantRootDeletionStateV1::from(deleted)).unwrap();
    assert_eq!(
        deleted_json["state"]["completionPath"]["kind"],
        "after_incomplete"
    );
    assert_eq!(
        deleted_json["state"]["evidence"]["evidence"]["erasureClaim"],
        "cryptographic_erasure_unverified"
    );
}

#[test]
fn accepted_loss_roots_can_only_use_operational_deletion_claims() {
    let (active, _, _) = active_refresh_state_with_policy(
        lineage(0x63),
        TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(
            TenantRootAcceptedLossReceiptV1::new(digest(181)),
        ),
    );

    assert!(TenantRootDeletionActiveV1::new(
        active.clone(),
        TenantRootDestructionProfileV1::ManagedHealing,
    )
    .is_err());
    let operational = TenantRootDeletionActiveV1::new(
        active,
        TenantRootDestructionProfileV1::OperationalRotation,
    )
    .unwrap();
    let json = serde_json::to_value(TenantRootDeletionStateV1::from(operational)).unwrap();
    assert_eq!(json["state"]["profile"], "operational_rotation_v1");
}

#[test]
fn custody_binding_changes_with_the_active_epoch_while_stable_context_remains_exact() {
    let lineage = lineage(0x71);
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let stable_bytes = stable_context.canonical_context_bytes();
    let stable_digest = stable_context_digest(&stable_context);
    let (epoch_one, share_a, share_b) = active_refresh_state(lineage);
    let root_commitment = *epoch_one
        .current()
        .verified()
        .commitments()
        .root_commitment();
    let binding_one = custody_binding(&epoch_one, &stable_context);

    let (epoch_two, refreshed_share_a, refreshed_share_b) =
        advance_active_refresh(epoch_one, &share_a, &share_b);
    let binding_two = custody_binding(&epoch_two, &stable_context);

    assert_eq!(binding_one.epoch().get().get(), 1);
    assert_eq!(binding_two.epoch().get().get(), 2);
    assert_eq!(binding_one.stable_context_digest(), stable_digest);
    assert_eq!(binding_two.stable_context_digest(), stable_digest);
    assert_eq!(stable_context.canonical_context_bytes(), stable_bytes);
    assert_eq!(
        epoch_two
            .current()
            .verified()
            .commitments()
            .root_commitment(),
        &root_commitment,
    );
    assert_ne!(
        binding_one.canonical_bytes().unwrap(),
        binding_two.canonical_bytes().unwrap()
    );
    assert_ne!(binding_one.digest().unwrap(), binding_two.digest().unwrap());

    let plan_one = plan_mpc_prf_stable_purpose_binding_v2(
        &stable_context,
        &binding_one,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();
    let plan_two = plan_mpc_prf_stable_purpose_binding_v2(
        &stable_context,
        &binding_two,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();
    assert_eq!(
        plan_one.threshold_prf_context_bytes(),
        stable_bytes.as_slice()
    );
    assert_eq!(
        plan_one.threshold_prf_context_bytes(),
        plan_two.threshold_prf_context_bytes()
    );
    assert_eq!(
        plan_one.stable_context_digest(),
        plan_two.stable_context_digest()
    );
    assert_ne!(
        plan_one.custody_binding_digest(),
        plan_two.custody_binding_digest()
    );

    let epoch_one_a = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        MpcPrfStableThresholdSignerInputV2 {
            purpose_plan: plan_one.clone(),
            signer_role: Role::SignerA,
            signing_root_share_wire: backend_share_wire(&share_a),
        },
        &mut seeded_rng(91),
    )
    .unwrap();
    let epoch_one_b = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        MpcPrfStableThresholdSignerInputV2 {
            purpose_plan: plan_one.clone(),
            signer_role: Role::SignerB,
            signing_root_share_wire: backend_share_wire(&share_b),
        },
        &mut seeded_rng(92),
    )
    .unwrap();
    let epoch_two_a = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        MpcPrfStableThresholdSignerInputV2 {
            purpose_plan: plan_two.clone(),
            signer_role: Role::SignerA,
            signing_root_share_wire: backend_share_wire(&refreshed_share_a),
        },
        &mut seeded_rng(91),
    )
    .unwrap();
    let epoch_two_b = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        MpcPrfStableThresholdSignerInputV2 {
            purpose_plan: plan_two.clone(),
            signer_role: Role::SignerB,
            signing_root_share_wire: backend_share_wire(&refreshed_share_b),
        },
        &mut seeded_rng(92),
    )
    .unwrap();
    assert_ne!(epoch_one_a.proof_wire, epoch_two_a.proof_wire);
    assert!(
        verify_mpc_prf_stable_partial_with_threshold_backend_v2(&plan_two, &epoch_one_a,).is_err()
    );
    let mut substituted_custody_binding = epoch_one_a.clone();
    substituted_custody_binding.purpose_plan = plan_two.clone();
    assert!(verify_mpc_prf_stable_partial_with_threshold_backend_v2(
        &plan_two,
        &substituted_custody_binding,
    )
    .is_err());

    let epoch_one_output = combine_mpc_prf_stable_proof_bundles_with_threshold_backend_v2(
        MpcPrfStableThresholdCombineInputV2 {
            purpose_plan: plan_one,
            left: epoch_one_a,
            right: epoch_one_b,
        },
    )
    .unwrap();
    let epoch_two_output = combine_mpc_prf_stable_proof_bundles_with_threshold_backend_v2(
        MpcPrfStableThresholdCombineInputV2 {
            purpose_plan: plan_two,
            left: epoch_two_a,
            right: epoch_two_b,
        },
    )
    .unwrap();
    assert_eq!(
        epoch_one_output.stable_context_digest,
        epoch_two_output.stable_context_digest
    );
    assert_ne!(
        epoch_one_output.custody_binding_digest,
        epoch_two_output.custody_binding_digest
    );
    assert_eq!(
        epoch_one_output.output_material,
        epoch_two_output.output_material
    );

    let alternate_context = StableTenantDerivationContextV2::new([0x43; 32]);
    assert!(plan_mpc_prf_stable_purpose_binding_v2(
        &alternate_context,
        &binding_one,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .is_err());
}

#[test]
fn custody_binding_identifiers_and_lifetime_are_strict() {
    let operation_id = TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap();
    let session_id = TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap();
    let nonce = TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap();
    let serialized_operation = serde_json::to_value(operation_id).unwrap();
    assert!(serde_json::from_value::<TenantRootDerivationOperationIdV1>(
        serialized_operation.clone()
    )
    .is_ok());
    assert!(serde_json::from_value::<TenantRootDerivationOperationIdV1>(
        serde_json::Value::String(format!("{}=", serialized_operation.as_str().unwrap()))
    )
    .is_err());
    assert!(serde_json::from_value::<TenantRootDerivationOperationIdV1>(
        serde_json::Value::String("AQ".to_owned())
    )
    .is_err());
    let serialized_session = serde_json::to_value(session_id).unwrap();
    assert!(
        serde_json::from_value::<TenantRootDerivationSessionIdV1>(serialized_session.clone())
            .is_ok()
    );
    assert!(
        serde_json::from_value::<TenantRootDerivationSessionIdV1>(serde_json::Value::String(
            format!("{}=", serialized_session.as_str().unwrap())
        ))
        .is_err()
    );
    assert!(
        serde_json::from_value::<TenantRootDerivationSessionIdV1>(serde_json::Value::String(
            "AQ".to_owned()
        ))
        .is_err()
    );
    let serialized_nonce = serde_json::to_value(nonce).unwrap();
    assert!(
        serde_json::from_value::<TenantRootDerivationNonceV1>(serialized_nonce.clone()).is_ok()
    );
    assert!(
        serde_json::from_value::<TenantRootDerivationNonceV1>(serde_json::Value::String(format!(
            "{}=",
            serialized_nonce.as_str().unwrap()
        ),))
        .is_err()
    );
    assert!(TenantRootDerivationOperationIdV1::from_bytes([0; 16]).is_err());
    assert!(TenantRootDerivationSessionIdV1::from_bytes([0; 16]).is_err());
    assert!(TenantRootDerivationNonceV1::from_bytes([0; 32]).is_err());
    assert!(TenantRootDeriverIdentitiesV1::new("", "deriver-b").is_err());
    assert!(TenantRootDeriverIdentitiesV1::new("same", "same").is_err());

    let (active, _, _) = active_refresh_state(lineage(0x72));
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let binding = custody_binding(&active, &stable_context);
    assert!(binding.validate_at(ISSUED_AT_MS - 60_000).is_ok());
    assert!(binding.validate_at(ISSUED_AT_MS - 60_001).is_err());
    assert!(binding.validate_at(EXPIRES_AT_MS + 60_000).is_ok());
    assert!(binding.validate_at(EXPIRES_AT_MS + 60_001).is_err());

    assert!(TenantRootCustodyBindingV1::from_active(
        &active,
        TenantRootDeriverIdentitiesV1::new("deriver-a", "deriver-b").unwrap(),
        operation_id,
        session_id,
        nonce,
        0,
        EXPIRES_AT_MS,
        &stable_context,
        TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
    )
    .is_err());
    assert!(TenantRootCustodyBindingV1::from_active(
        &active,
        TenantRootDeriverIdentitiesV1::new("deriver-a", "deriver-b").unwrap(),
        operation_id,
        session_id,
        nonce,
        ISSUED_AT_MS,
        ISSUED_AT_MS,
        &stable_context,
        TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
    )
    .is_err());
}

#[test]
fn custody_binding_digest_rejects_public_field_substitution() {
    let (active, _, _) = active_refresh_state(lineage(0x73));
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let alternate_context = StableTenantDerivationContextV2::new([0x43; 32]);
    let base = custody_binding(&active, &stable_context).digest().unwrap();
    let substituted = [
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-8", "deriver-b-runtime-9")
                .unwrap(),
            TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
            TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
            TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            &stable_context,
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
        )
        .unwrap(),
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9")
                .unwrap(),
            TenantRootDerivationOperationIdV1::from_bytes([0x85; 16]).unwrap(),
            TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
            TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            &stable_context,
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
        )
        .unwrap(),
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9")
                .unwrap(),
            TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
            TenantRootDerivationSessionIdV1::from_bytes([0x86; 16]).unwrap(),
            TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            &stable_context,
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
        )
        .unwrap(),
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9")
                .unwrap(),
            TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
            TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
            TenantRootDerivationNonceV1::from_bytes([0x87; 32]).unwrap(),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            &stable_context,
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
        )
        .unwrap(),
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9")
                .unwrap(),
            TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
            TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
            TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            &alternate_context,
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]),
        )
        .unwrap(),
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9")
                .unwrap(),
            TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
            TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
            TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            &stable_context,
            TenantRootProtocolDigestV1::from_bytes([0x89; 32]),
        )
        .unwrap(),
    ];

    for binding in substituted {
        assert_ne!(binding.digest().unwrap(), base);
    }
}

#[test]
fn custody_binding_canonical_digest_is_frozen() {
    let (active, _, _) = active_refresh_state(lineage(0x74));
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let binding = custody_binding(&active, &stable_context);

    assert_eq!(
        hex::encode(binding.digest().unwrap().into_bytes()),
        "d9815df6f9ad6cb3b1c4406969ec33877077af61df69e3b8b1e38e35ee6899c7",
    );
}
