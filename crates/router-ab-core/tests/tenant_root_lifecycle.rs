use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    combine_mpc_prf_stable_proof_bundles_with_threshold_backend_v2,
    evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2,
    plan_mpc_prf_stable_purpose_binding_v2, resolve_active_tenant_root_pair_binding_v1,
    resolve_authoritative_active_tenant_root_pair_binding_v1,
    verify_mpc_prf_stable_partial_with_threshold_backend_v2, MpcPrfSigningRootShareWireV1,
    MpcPrfStablePurposeBindingPlanV2, MpcPrfStableThresholdCombineInputV2,
    MpcPrfStableThresholdSignerInputV2, Role, StableTenantDerivationContextV2,
    TenantRootAcceptedLossReceiptV1, TenantRootAcceptedPermanentLossAuthorizationBindingV1,
    TenantRootActivationReceiptTransitionV1, TenantRootActivePairMismatchV1,
    TenantRootActivePairResolutionV1, TenantRootActiveRoleBindingV1,
    TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1, TenantRootActiveRootPairV1,
    TenantRootBackupPolicyV1, TenantRootCanaryCurveFamilyV1, TenantRootCanaryReceiptsV1,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCleanupIncompleteCreationV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCreationFailureV1,
    TenantRootCreationRecoveryActionV1, TenantRootCreationStateV1, TenantRootCustodyBindingV1,
    TenantRootCustodyLineageId, TenantRootDeletedReceiptV1, TenantRootDeletionActiveV1,
    TenantRootDeletionAuthorizationV1, TenantRootDeletionDrainReceiptV1,
    TenantRootDeletionEvidenceV1, TenantRootDeletionFenceReceiptV1, TenantRootDeletionStateV1,
    TenantRootDerivationNonceV1, TenantRootDerivationOperationIdV1,
    TenantRootDerivationSessionIdV1, TenantRootDeriverIdentitiesV1, TenantRootDestructionCommandV1,
    TenantRootDestructionFailureV1, TenantRootDestructionProfileV1,
    TenantRootDestructionProgressReceiptV1, TenantRootEmptyCreationV1,
    TenantRootEpochCommitmentsV1, TenantRootFailedBeforeActivationCreationV1,
    TenantRootIdentityDigestV1, TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootManagedRestoreAvailableV1, TenantRootManagedRestoreCapabilityV1,
    TenantRootManagedRestoreCleanupFailureV1, TenantRootManagedRestoreCleanupReceiptV1,
    TenantRootManagedRestoreFailureV1, TenantRootManagedRestoreInstallationReceiptV1,
    TenantRootManagedRestoreInstallingV1, TenantRootManagedRestorePeerVerificationReceiptV1,
    TenantRootManagedRestoreRoleV1, TenantRootManagedRestoreStateV1,
    TenantRootManagedRoleDestructionReceiptV1, TenantRootManagedRoleDestructionReceiptsV1,
    TenantRootOperationalErasureClaimV1, TenantRootOperationalRoleRemovalReceiptV1,
    TenantRootOperationalRoleRemovalReceiptsV1, TenantRootPendingCleanupFailureV1,
    TenantRootPendingCleanupReceiptV1, TenantRootProtocolDigestV1,
    TenantRootProviderCanaryReceiptBindingV1, TenantRootRefreshFailureV1,
    TenantRootRefreshRecoveryActionV1, TenantRootRefreshStateV1, TenantRootRoleBackupReceiptsV1,
    TenantRootRoleInstallationReceiptsV1, TenantRootRoleRetirementReceiptsV1,
    TenantRootRoleUnavailableReceiptV1, TenantRootServiceCleanupReceiptV1, TenantRootShareEpoch,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1, TenantRootSignedProviderCanaryReceiptV1,
    TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    VerifiedTenantRootProviderCanaryReceiptV1, VerifiedTenantRootShareInstallationEvidenceV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};
use threshold_prf::{
    apply_two_party_root_share_refresh, prove_root_share_knowledge, PrfPurpose,
    RootShareRefreshCoefficient, SigningRootShare, SigningRootShareCommitment,
    SigningRootShareWire, TwoPartyDeriverRole, TwoPartyRootShareCommitments,
};

mod support;

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
    authenticated_installation_wire(context, role, share, peer, proof_seed)
        .evidence()
        .clone()
}

fn authenticated_installation_wire(
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
        &mut seeded_rng(proof_seed),
    )
    .unwrap();
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap();
    let key = signing_key(role);
    let signed = TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &key.to_bytes())
        .unwrap()
        .canonical_bytes()
        .unwrap();
    TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &signed,
        key.verifying_key().as_bytes(),
    )
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
    let creation_context = context(lineage, 0x71);
    let (verified, bundle) =
        verified_creation_with_managed_bundle(lineage, creation_context, 21, 22);
    let activation = support::initial_activation_receipt(&bundle, 1_020_000);
    let active = verified.activate(activation).unwrap().into_refresh_state();
    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    (active, share_a, share_b)
}

fn verified_creation_with_managed_bundle(
    lineage: TenantRootCustodyLineageId,
    creation_context: TenantRootCeremonyContextV1,
    proof_seed_a: u8,
    proof_seed_b: u8,
) -> (
    router_ab_core::TenantRootVerifiedCreationV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
) {
    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let fixture = support::initial_activation_evidence_fixture(
        creation_context.clone(),
        &share_a,
        &share_b,
        proof_seed_a,
        proof_seed_b,
    );
    let support::InitialActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let verified = TenantRootEmptyCreationV1::new(identity(), lineage)
        .start(&creation_context)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();
    (verified, bundle)
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
    let fixture = support::refresh_activation_evidence_fixture(
        refresh_context.clone(),
        active.current().verified().commitments(),
        &next_a,
        &next_b,
        73,
        74,
        5,
    );
    let support::RefreshActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let verified = active
        .start(&refresh_context)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();
    let activation = support::refresh_activation_receipt(&bundle, 1_020_000);
    let active = verified
        .activate(activation)
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
    stable_context.digest().expect("stable context digest")
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
        TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
    )
    .unwrap()
}

fn active_role_binding(
    active: &router_ab_core::TenantRootActiveRefreshV1,
    role: TenantRootManagedRestoreRoleV1,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
) -> TenantRootActiveRoleBindingV1 {
    let share_commitment = match role {
        TenantRootManagedRestoreRoleV1::DeriverA => active
            .current()
            .verified()
            .commitments()
            .deriver_a()
            .clone(),
        TenantRootManagedRestoreRoleV1::DeriverB => active
            .current()
            .verified()
            .commitments()
            .deriver_b()
            .clone(),
    };
    TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            active.identity().digest().unwrap(),
            active.custody_lineage(),
            active.current().epoch(),
            role,
        ),
        share_commitment,
        activation_receipt_digest,
    )
    .unwrap()
}

fn active_role_resolution(
    active: &router_ab_core::TenantRootActiveRefreshV1,
    role: TenantRootManagedRestoreRoleV1,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
) -> TenantRootActiveRoleResolutionV1 {
    TenantRootActiveRoleResolutionV1::Active(active_role_binding(
        active,
        role,
        activation_receipt_digest,
    ))
}

fn active_pair(
    active: &router_ab_core::TenantRootActiveRefreshV1,
    custody_binding: &TenantRootCustodyBindingV1,
) -> TenantRootActiveRootPairV1 {
    let activation_receipt_digest = custody_binding.activation_receipt_digest();
    resolve_authoritative_active_tenant_root_pair_binding_v1(
        active.identity().digest().unwrap(),
        custody_binding,
        &active_role_resolution(
            active,
            TenantRootManagedRestoreRoleV1::DeriverA,
            activation_receipt_digest,
        ),
        &active_role_resolution(
            active,
            TenantRootManagedRestoreRoleV1::DeriverB,
            activation_receipt_digest,
        ),
    )
    .unwrap()
    .require_active()
    .unwrap()
    .clone()
}

fn stable_signer_input(
    purpose_plan: MpcPrfStablePurposeBindingPlanV2,
    custody_binding: &TenantRootCustodyBindingV1,
    active_pair: &TenantRootActiveRootPairV1,
    signer_role: Role,
    share: &SigningRootShare,
    now_ms: u64,
) -> MpcPrfStableThresholdSignerInputV2 {
    MpcPrfStableThresholdSignerInputV2::new(
        purpose_plan,
        custody_binding,
        active_pair,
        signer_role,
        backend_share_wire(share),
        now_ms,
    )
    .expect("stable signer input")
}

fn digest(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).unwrap()
}

fn accepted_loss_authorization(
    identity: &TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    context_digest: TenantRootProtocolDigestV1,
    commitments: TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
) -> router_ab_core::VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
    let binding = TenantRootAcceptedPermanentLossAuthorizationBindingV1::new(
        identity.digest().unwrap(),
        custody_lineage,
        TenantRootActivationReceiptTransitionV1::InitialCreation,
        TenantRootShareEpoch::INITIAL,
        context_digest,
        commitments,
        installation_receipts,
        2,
        3,
        "policy-accept-loss-001",
        "incident-2026-0001",
        "both managed backups are unavailable",
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
        "operator-a-v1",
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x72; 32]),
        "operator-b-v1",
    )
    .unwrap();
    let first_key = SigningKey::from_bytes(&[0x61; 32]);
    let second_key = SigningKey::from_bytes(&[0x62; 32]);
    let signed = TenantRootSignedAcceptedPermanentLossAuthorizationV1::sign(
        binding.clone(),
        &first_key.to_bytes(),
        &second_key.to_bytes(),
    )
    .unwrap();
    signed
        .verify(
            &binding,
            first_key.verifying_key().as_bytes(),
            second_key.verifying_key().as_bytes(),
        )
        .unwrap()
}

fn accepted_loss_policy(
    identity: &TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    context_digest: TenantRootProtocolDigestV1,
    commitments: TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
) -> TenantRootBackupPolicyV1 {
    TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(
        TenantRootAcceptedLossReceiptV1::from_verified(accepted_loss_authorization(
            identity,
            custody_lineage,
            context_digest,
            commitments,
            installation_receipts,
        )),
    )
}

struct AcceptedInitialActivationFixture {
    bundle: VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    evidence_a: VerifiedTenantRootShareInstallationEvidenceV1,
    evidence_b: VerifiedTenantRootShareInstallationEvidenceV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    backup_policy: TenantRootBackupPolicyV1,
    canary_receipts: TenantRootCanaryReceiptsV1,
}

fn accepted_initial_activation_fixture(
    context: TenantRootCeremonyContextV1,
    proof_seed_a: u8,
    proof_seed_b: u8,
) -> AcceptedInitialActivationFixture {
    let share_a = fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let installation_a = authenticated_installation_wire(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        &share_a,
        &share_b,
        proof_seed_a,
    );
    let installation_b = authenticated_installation_wire(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        &share_b,
        &share_a,
        proof_seed_b,
    );
    let evidence_a = installation_a.evidence().clone();
    let evidence_b = installation_b.evidence().clone();
    let commitments = TenantRootEpochCommitmentsV1::from_verified(
        TwoPartyRootShareCommitments::from_shares(&share_a, &share_b).unwrap(),
    )
    .unwrap();
    let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
        installation_a.lifecycle_receipt_digest().unwrap(),
        installation_b.lifecycle_receipt_digest().unwrap(),
    )
    .unwrap();
    let ecdsa_canary =
        activation_canary(&context, &commitments, TenantRootCanaryCurveFamilyV1::Ecdsa);
    let ed25519_canary = activation_canary(
        &context,
        &commitments,
        TenantRootCanaryCurveFamilyV1::Ed25519,
    );
    let canary_receipts = TenantRootCanaryReceiptsV1::new(
        TenantRootLifecycleReceiptDigestV1::from_bytes(*ecdsa_canary.digest().as_bytes()).unwrap(),
        TenantRootLifecycleReceiptDigestV1::from_bytes(*ed25519_canary.digest().as_bytes())
            .unwrap(),
    )
    .unwrap();
    let backup_policy = accepted_loss_policy(
        &identity(),
        context.custody_lineage(),
        context.digest().unwrap(),
        commitments.clone(),
        installation_receipts.clone(),
    );
    let authorization = accepted_loss_authorization(
        &identity(),
        context.custody_lineage(),
        context.digest().unwrap(),
        commitments,
        installation_receipts.clone(),
    );
    let bundle =
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_accepted_loss(
            installation_a,
            installation_b,
            authorization,
            ecdsa_canary,
            ed25519_canary,
            2,
            3,
        )
        .unwrap();
    AcceptedInitialActivationFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    }
}

fn activation_canary(
    context: &TenantRootCeremonyContextV1,
    commitments: &TenantRootEpochCommitmentsV1,
    family: TenantRootCanaryCurveFamilyV1,
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
    let provider_key_version_ref = match family {
        TenantRootCanaryCurveFamilyV1::Ecdsa => "kms/tenant-root/ecdsa-canary-v1",
        TenantRootCanaryCurveFamilyV1::Ed25519 => "kms/tenant-root/ed25519-canary-v1",
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
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x72; 32]),
        "control-plane-canary-v1",
        context.issued_at_ms(),
        context.expires_at_ms(),
    )
    .unwrap();
    let signing_key = [0x71; 32];
    let signed =
        TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &signing_key).unwrap();
    signed
        .verify(
            &binding,
            SigningKey::from_bytes(&signing_key)
                .verifying_key()
                .as_bytes(),
        )
        .unwrap()
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

fn assert_creation_recovery_metadata(
    plan: &router_ab_core::TenantRootCreationRecoveryPlanV1,
    custody_lineage: TenantRootCustodyLineageId,
    revision: u64,
) {
    assert_eq!(plan.identity_digest(), identity().digest().unwrap());
    assert_eq!(plan.custody_lineage(), custody_lineage);
    assert_eq!(plan.revision(), revision);
}

fn assert_refresh_recovery_metadata(
    plan: &router_ab_core::TenantRootRefreshRecoveryPlanV1,
    custody_lineage: TenantRootCustodyLineageId,
    revision: u64,
) {
    assert_eq!(plan.identity_digest(), identity().digest().unwrap());
    assert_eq!(plan.custody_lineage(), custody_lineage);
    assert_eq!(plan.revision(), revision);
}

#[test]
fn creation_restart_projects_one_forward_recovery_action_from_every_state() {
    let custody_lineage = lineage(0x30);
    let creation_context = context(custody_lineage, 0x20);
    let ceremony_digest = creation_context.digest().unwrap();
    let fixture = support::initial_activation_evidence_fixture(
        creation_context.clone(),
        &fixed_share(TwoPartyDeriverRole::DeriverA, 12),
        &fixed_share(TwoPartyDeriverRole::DeriverB, 19),
        1,
        2,
    );
    let support::InitialActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let empty = TenantRootEmptyCreationV1::new(identity(), custody_lineage);
    let empty_plan = TenantRootCreationStateV1::from(empty.clone())
        .recovery_plan()
        .unwrap();
    assert_creation_recovery_metadata(&empty_plan, custody_lineage, 0);
    assert_eq!(
        empty_plan.action(),
        TenantRootCreationRecoveryActionV1::StartFreshCeremony
    );

    let preparing = empty.start(&creation_context).unwrap();
    let preparing_plan = TenantRootCreationStateV1::from(preparing.clone())
        .recovery_plan()
        .unwrap();
    assert_creation_recovery_metadata(&preparing_plan, custody_lineage, 1);
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
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();
    let verified_plan = TenantRootCreationStateV1::from(verified.clone())
        .recovery_plan()
        .unwrap();
    assert_creation_recovery_metadata(&verified_plan, custody_lineage, 2);
    assert_eq!(
        verified_plan.action(),
        TenantRootCreationRecoveryActionV1::AbortPendingEpoch {
            pending_epoch: TenantRootShareEpoch::INITIAL,
            ceremony_digest,
        }
    );

    let activation = support::initial_activation_receipt(&bundle, 1_020_000);
    let activation_digest = activation.digest();
    let active = verified.clone().activate(activation).unwrap();
    let active_plan = TenantRootCreationStateV1::from(active)
        .recovery_plan()
        .unwrap();
    assert_creation_recovery_metadata(&active_plan, custody_lineage, 3);
    assert_eq!(
        active_plan.action(),
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
    let failed_plan = TenantRootCreationStateV1::from(failed.clone())
        .recovery_plan()
        .unwrap();
    assert_creation_recovery_metadata(&failed_plan, custody_lineage, 2);
    assert_eq!(
        failed_plan.action(),
        TenantRootCreationRecoveryActionV1::StartFreshCeremonyAfterCleanup {
            failed_epoch: TenantRootShareEpoch::INITIAL,
            failed_ceremony_digest: ceremony_digest,
        }
    );

    let cleanup_incomplete = preparing
        .clone()
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
    let cleanup_incomplete_plan = TenantRootCreationStateV1::from(cleanup_incomplete.clone())
        .recovery_plan()
        .unwrap();
    assert_creation_recovery_metadata(&cleanup_incomplete_plan, custody_lineage, 2);
    assert_eq!(
        cleanup_incomplete_plan.action(),
        TenantRootCreationRecoveryActionV1::ResumePendingCleanup {
            pending_epoch: TenantRootShareEpoch::INITIAL,
            ceremony_digest,
        }
    );

    let failed_after_verification = verified
        .clone()
        .fail_with_cleanup(
            TenantRootCreationFailureV1::new(digest(0x30), 1_015_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(0x31), digest(0x32), 1_016_000).unwrap(),
        )
        .unwrap();
    let failed_after_verification_plan =
        TenantRootCreationStateV1::from(failed_after_verification.clone())
            .recovery_plan()
            .unwrap();
    assert_creation_recovery_metadata(&failed_after_verification_plan, custody_lineage, 3);
    assert_eq!(
        failed_after_verification_plan.action(),
        TenantRootCreationRecoveryActionV1::StartFreshCeremonyAfterCleanup {
            failed_epoch: TenantRootShareEpoch::INITIAL,
            failed_ceremony_digest: ceremony_digest,
        }
    );
    assert!(failed_after_verification
        .retry(&context(lineage(0x31), 0x21))
        .is_err());

    let cleanup_incomplete_after_verification = verified
        .fail_with_incomplete_cleanup(
            TenantRootCreationFailureV1::new(digest(0x33), 1_015_000).unwrap(),
            TenantRootPendingCleanupFailureV1::deriver_a_incomplete(
                digest(0x34),
                digest(0x35),
                1_016_000,
            )
            .unwrap(),
        )
        .unwrap();
    let cleanup_incomplete_after_verification_plan =
        TenantRootCreationStateV1::from(cleanup_incomplete_after_verification)
            .recovery_plan()
            .unwrap();
    assert_creation_recovery_metadata(
        &cleanup_incomplete_after_verification_plan,
        custody_lineage,
        3,
    );
    assert_eq!(
        cleanup_incomplete_after_verification_plan.action(),
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
    let active_plan = TenantRootRefreshStateV1::from(active.clone())
        .recovery_plan()
        .unwrap();
    assert_refresh_recovery_metadata(&active_plan, custody_lineage, 3);
    assert_eq!(
        active_plan.action(),
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
    let fixture = support::refresh_activation_evidence_fixture(
        ceremony.clone(),
        active.current().verified().commitments(),
        &next_a,
        &next_b,
        0x33,
        0x34,
        5,
    );
    let support::RefreshActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let preparing = active.start(&ceremony).unwrap();
    let preparing_plan = TenantRootRefreshStateV1::from(preparing.clone())
        .recovery_plan()
        .unwrap();
    assert_refresh_recovery_metadata(&preparing_plan, custody_lineage, 4);
    assert_eq!(
        preparing_plan.action(),
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
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();
    let verified_plan = TenantRootRefreshStateV1::from(verified.clone())
        .recovery_plan()
        .unwrap();
    assert_refresh_recovery_metadata(&verified_plan, custody_lineage, 5);
    assert_eq!(
        verified_plan.action(),
        TenantRootRefreshRecoveryActionV1::AbortPendingEpoch {
            active_epoch,
            pending_epoch,
            ceremony_digest,
        }
    );

    let activation = support::refresh_activation_receipt(&bundle, 1_020_000);
    let activation_digest = activation.digest();
    let retiring = verified.clone().activate(activation).unwrap();
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
    let failed_plan = TenantRootRefreshStateV1::from(failed.clone())
        .recovery_plan()
        .unwrap();
    assert_refresh_recovery_metadata(&failed_plan, custody_lineage, 5);
    assert_eq!(
        failed_plan.action(),
        TenantRootRefreshRecoveryActionV1::StartFreshRefreshAfterCleanup {
            active_epoch,
            failed_epoch: pending_epoch,
            failed_ceremony_digest: ceremony_digest,
        }
    );

    let cleanup_incomplete = preparing
        .clone()
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
    let cleanup_incomplete_plan = TenantRootRefreshStateV1::from(cleanup_incomplete.clone())
        .recovery_plan()
        .unwrap();
    assert_refresh_recovery_metadata(&cleanup_incomplete_plan, custody_lineage, 5);
    assert_eq!(
        cleanup_incomplete_plan.action(),
        TenantRootRefreshRecoveryActionV1::ResumePendingCleanup {
            active_epoch,
            pending_epoch,
            ceremony_digest,
        }
    );

    let failed_after_verification = verified
        .clone()
        .fail_with_cleanup(
            TenantRootRefreshFailureV1::new(digest(0x3c), 1_015_000).unwrap(),
            TenantRootPendingCleanupReceiptV1::new(digest(0x3d), digest(0x3e), 1_016_000).unwrap(),
        )
        .unwrap();
    let failed_after_verification_plan =
        TenantRootRefreshStateV1::from(failed_after_verification.clone())
            .recovery_plan()
            .unwrap();
    assert_refresh_recovery_metadata(&failed_after_verification_plan, custody_lineage, 6);
    assert_eq!(
        failed_after_verification_plan.action(),
        TenantRootRefreshRecoveryActionV1::StartFreshRefreshAfterCleanup {
            active_epoch,
            failed_epoch: pending_epoch,
            failed_ceremony_digest: ceremony_digest,
        }
    );
    assert!(failed_after_verification
        .retry(&refresh_context(lineage(0x41), 2, 3, 0x79))
        .is_err());

    let cleanup_incomplete_after_verification = verified
        .fail_with_incomplete_cleanup(
            TenantRootRefreshFailureV1::new(digest(0x3f), 1_015_000).unwrap(),
            TenantRootPendingCleanupFailureV1::deriver_b_incomplete(
                digest(0x40),
                digest(0x41),
                1_016_000,
            )
            .unwrap(),
        )
        .unwrap();
    let cleanup_incomplete_after_verification_plan =
        TenantRootRefreshStateV1::from(cleanup_incomplete_after_verification)
            .recovery_plan()
            .unwrap();
    assert_refresh_recovery_metadata(
        &cleanup_incomplete_after_verification_plan,
        custody_lineage,
        6,
    );
    assert_eq!(
        cleanup_incomplete_after_verification_plan.action(),
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
    let fixture = support::initial_activation_evidence_fixture(
        context.clone(),
        &fixed_share(TwoPartyDeriverRole::DeriverA, 12),
        &fixed_share(TwoPartyDeriverRole::DeriverB, 19),
        1,
        2,
    );
    let expected_root = *fixture.bundle.root_commitment();
    let support::InitialActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
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
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();
    assert_eq!(
        TenantRootCreationStateV1::from(verified.clone()).revision(),
        2
    );
    let activation = support::initial_activation_receipt(&bundle, 1_020_000);
    let activation_bytes = activation.canonical_bytes().to_vec();
    let activation_digest = activation.digest();
    let activation_time = activation.activated_at_ms();
    let active = verified.activate(activation).unwrap();

    assert_eq!(active.revision(), 3);
    assert_eq!(
        active.current().activation_receipt_bytes(),
        activation_bytes
    );
    assert_eq!(
        active.current().activation_receipt_digest(),
        activation_digest
    );
    assert_eq!(active.current().activation_time_ms(), activation_time);
    assert_eq!(
        active.current().verified().commitments().root_commitment(),
        &expected_root,
    );
    assert_eq!(active.current().verified().pending().epoch().get().get(), 1);
    assert!(matches!(
        active.current().verified().backup_policy(),
        TenantRootBackupPolicyV1::CurrentRoleBackups(_)
    ));
    assert_state_kind(active, "active");
}

#[test]
fn accepted_loss_activation_requires_the_exact_verified_authorization() {
    let lineage = lineage(0x32);
    let context = context(lineage, 0x22);
    let fixture = accepted_initial_activation_fixture(context.clone(), 1, 2);
    let AcceptedInitialActivationFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let verified = TenantRootEmptyCreationV1::new(identity(), lineage)
        .start(&context)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();

    let activation = support::initial_activation_receipt(&bundle, 1_020_000);
    let active = verified.activate(activation).unwrap();
    assert_eq!(active.revision(), 3);
    assert!(matches!(
        active.current().verified().backup_policy(),
        TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(_)
    ));
    assert!(TenantRootLifecycleReceiptDigestV1::from_bytes([0; 32]).is_err());
    assert!(
        serde_json::from_value::<TenantRootLifecycleReceiptDigestV1>(
            serde_json::to_value([0_u8; 32]).unwrap(),
        )
        .is_err()
    );
    let encoded_digest = serde_json::to_value(digest(10)).unwrap();
    assert_eq!(
        serde_json::from_value::<TenantRootLifecycleReceiptDigestV1>(encoded_digest).unwrap(),
        digest(10),
    );
    assert!(TenantRootRoleBackupReceiptsV1::new(digest(3), digest(3)).is_err());
    assert!(TenantRootRoleInstallationReceiptsV1::new(digest(1), digest(1)).is_err());
    assert!(TenantRootCanaryReceiptsV1::new(digest(5), digest(5)).is_err());
}

#[test]
fn accepted_loss_activation_rejects_cross_scope_receipt_replay() {
    let first_lineage = lineage(0x32);
    let second_lineage = lineage(0x39);
    let first_context = context(first_lineage, 0x22);
    let second_context = context(second_lineage, 0x29);
    let first_fixture = accepted_initial_activation_fixture(first_context.clone(), 1, 2);
    let second_fixture = accepted_initial_activation_fixture(second_context.clone(), 1, 2);
    let AcceptedInitialActivationFixture {
        bundle: _,
        evidence_a: first_evidence_a,
        evidence_b: first_evidence_b,
        installation_receipts: first_installation_receipts,
        backup_policy: first_backup_policy,
        canary_receipts: first_canary_receipts,
    } = first_fixture;
    let AcceptedInitialActivationFixture {
        bundle: second_bundle,
        evidence_a: second_evidence_a,
        evidence_b: second_evidence_b,
        installation_receipts: second_installation_receipts,
        backup_policy: second_backup_policy,
        canary_receipts: second_canary_receipts,
    } = second_fixture;
    let first_verified = TenantRootEmptyCreationV1::new(identity(), first_lineage)
        .start(&first_context)
        .unwrap()
        .verify(
            &first_evidence_a,
            &first_evidence_b,
            first_installation_receipts,
            first_backup_policy,
            first_canary_receipts,
            1_010_000,
        )
        .unwrap();
    let _second_verified = TenantRootEmptyCreationV1::new(identity(), second_lineage)
        .start(&second_context)
        .unwrap()
        .verify(
            &second_evidence_a,
            &second_evidence_b,
            second_installation_receipts,
            second_backup_policy,
            second_canary_receipts,
            1_010_000,
        )
        .unwrap();
    let replayed_activation = support::initial_activation_receipt(&second_bundle, 1_020_000);
    assert!(first_verified.activate(replayed_activation).is_err());
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
    assert_state_kind(complete.clone(), "failed_before_activation");
    assert!(complete
        .clone()
        .retry(&context(
            TenantRootCustodyLineageId::from_bytes([0x36; 16]).unwrap(),
            0x67,
        ))
        .is_err());

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
    assert!(incomplete
        .clone()
        .complete_cleanup(
            TenantRootPendingCleanupReceiptV1::new(digest(0x22), digest(0x23), 1_005_999).unwrap(),
        )
        .is_err());
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
    let fixture = support::refresh_activation_evidence_fixture(
        refresh_context.clone(),
        active.current().verified().commitments(),
        &next_a,
        &next_b,
        33,
        34,
        5,
    );
    let support::RefreshActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;

    let preparing = active.start(&refresh_context).unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(preparing.clone()).revision(),
        4
    );
    let verified = preparing
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();
    assert_eq!(
        TenantRootRefreshStateV1::from(verified.clone()).revision(),
        5
    );
    let activation = support::refresh_activation_receipt(&bundle, 1_020_000);
    let activation_bytes = activation.canonical_bytes().to_vec();
    let activation_digest = activation.digest();
    let activation_time = activation.activated_at_ms();
    let retiring = verified.activate(activation).unwrap();
    assert_eq!(
        retiring.current().activation_receipt_bytes(),
        activation_bytes
    );
    assert_eq!(
        retiring.current().activation_receipt_digest(),
        activation_digest
    );
    assert_eq!(retiring.current().activation_time_ms(), activation_time);
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
    assert_eq!(active.activation_receipt_bytes(), activation_bytes);
    assert_eq!(active.activation_receipt_digest(), activation_digest);
    assert_eq!(active.activation_time_ms(), activation_time);
    let refresh_json = serde_json::to_value(TenantRootRefreshStateV1::from(active)).unwrap();
    assert_eq!(refresh_json["kind"], "active");
}

#[test]
fn refresh_rejects_epoch_lineage_root_and_ceremony_substitution() {
    let lineage = lineage(0x43);
    let (active, current_a, current_b) = active_refresh_state(lineage);
    assert!(active
        .clone()
        .start(&refresh_context(
            TenantRootCustodyLineageId::from_bytes([0x42; 16]).unwrap(),
            1,
            2,
            0x72,
        ))
        .is_err());
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
    assert!(failed
        .clone()
        .retry(&refresh_context(
            TenantRootCustodyLineageId::from_bytes([0x45; 16]).unwrap(),
            1,
            2,
            0x79,
        ))
        .is_err());
    assert!(failed
        .clone()
        .retry(&refresh_context(lineage, 2, 3, 0x7a))
        .is_err());
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
    assert!(incomplete
        .clone()
        .complete_cleanup(
            TenantRootPendingCleanupReceiptV1::new(digest(50), digest(51), 1_005_999).unwrap(),
        )
        .is_err());
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
    let fixture = support::refresh_activation_evidence_fixture(
        ceremony.clone(),
        active.current().verified().commitments(),
        &next_a,
        &next_b,
        43,
        44,
        5,
    );
    let support::RefreshActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let verified = active
        .start(&ceremony)
        .unwrap()
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_010_000,
        )
        .unwrap();
    let activation = support::refresh_activation_receipt(&bundle, 1_020_000);
    let retiring = verified.activate(activation).unwrap();
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
    let fixture = support::refresh_activation_evidence_fixture(
        forward_context.clone(),
        active.current().verified().commitments(),
        &next_a,
        &next_b,
        53,
        54,
        8,
    );
    let support::RefreshActivationEvidenceFixture {
        bundle,
        evidence_a,
        evidence_b,
        installation_receipts,
        backup_policy,
        canary_receipts,
    } = fixture;
    let verified = forward
        .verify(
            &evidence_a,
            &evidence_b,
            installation_receipts,
            backup_policy,
            canary_receipts,
            1_030_000,
        )
        .unwrap();
    let activation = support::refresh_activation_receipt(&bundle, 1_040_000);
    let retiring = verified.activate(activation).unwrap();
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

    let wrong_lineage = TenantRootManagedRestoreCapabilityV1::new(
        digest(87),
        active.identity().digest().unwrap(),
        TenantRootCustodyLineageId::from_bytes([0x53; 16]).unwrap(),
        TenantRootManagedRestoreRoleV1::DeriverA,
        active.current().epoch(),
        active.current().activation().digest(),
        1_022_000,
        1_050_000,
    )
    .unwrap();
    assert!(unavailable
        .clone()
        .start_restore(wrong_lineage, 1_023_000)
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
    let pair_one = active_pair(&epoch_one, &binding_one);

    let (epoch_two, refreshed_share_a, refreshed_share_b) =
        advance_active_refresh(epoch_one, &share_a, &share_b);
    let binding_two = custody_binding(&epoch_two, &stable_context);
    let pair_two = active_pair(&epoch_two, &binding_two);

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
        stable_signer_input(
            plan_one.clone(),
            &binding_one,
            &pair_one,
            Role::SignerA,
            &share_a,
            ISSUED_AT_MS,
        ),
        &mut seeded_rng(91),
    )
    .unwrap();
    let epoch_one_b = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        stable_signer_input(
            plan_one.clone(),
            &binding_one,
            &pair_one,
            Role::SignerB,
            &share_b,
            ISSUED_AT_MS,
        ),
        &mut seeded_rng(92),
    )
    .unwrap();
    let epoch_two_a = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        stable_signer_input(
            plan_two.clone(),
            &binding_two,
            &pair_two,
            Role::SignerA,
            &refreshed_share_a,
            ISSUED_AT_MS,
        ),
        &mut seeded_rng(91),
    )
    .unwrap();
    let epoch_two_b = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        stable_signer_input(
            plan_two.clone(),
            &binding_two,
            &pair_two,
            Role::SignerB,
            &refreshed_share_b,
            ISSUED_AT_MS,
        ),
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
fn stable_signer_input_rejects_a_substituted_share() {
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let (active, _, _) = active_refresh_state(lineage(0x7a));
    let custody_binding = custody_binding(&active, &stable_context);
    let active_pair = active_pair(&active, &custody_binding);
    let plan = plan_mpc_prf_stable_purpose_binding_v2(
        &stable_context,
        &custody_binding,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();
    let substituted_share = fixed_share(TwoPartyDeriverRole::DeriverA, 31);

    let error = MpcPrfStableThresholdSignerInputV2::new(
        plan,
        &custody_binding,
        &active_pair,
        Role::SignerA,
        backend_share_wire(&substituted_share),
        ISSUED_AT_MS,
    )
    .unwrap_err();
    assert_eq!(
        error.code(),
        router_ab_core::RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn stable_signer_input_rejects_a_stale_custody_binding() {
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let (active, share_a, _) = active_refresh_state(lineage(0x7b));
    let custody_binding = custody_binding(&active, &stable_context);
    let active_pair = active_pair(&active, &custody_binding);
    let plan = plan_mpc_prf_stable_purpose_binding_v2(
        &stable_context,
        &custody_binding,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();

    let error = MpcPrfStableThresholdSignerInputV2::new(
        plan,
        &custody_binding,
        &active_pair,
        Role::SignerA,
        backend_share_wire(&share_a),
        EXPIRES_AT_MS + 60_001,
    )
    .unwrap_err();
    assert_eq!(
        error.code(),
        router_ab_core::RouterAbDerivationErrorCode::MalformedInput
    );
}

#[test]
fn stable_signer_input_rejects_a_pair_from_another_custody_binding() {
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let (active, share_a, _) = active_refresh_state(lineage(0x7c));
    let binding_one = custody_binding(&active, &stable_context);
    let pair_one = active_pair(&active, &binding_one);
    let (foreign_active, _, _) = active_refresh_state(lineage(0x7d));
    let foreign_binding = custody_binding(&foreign_active, &stable_context);
    let foreign_pair = active_pair(&foreign_active, &foreign_binding);
    let plan = plan_mpc_prf_stable_purpose_binding_v2(
        &stable_context,
        &binding_one,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();

    let error = MpcPrfStableThresholdSignerInputV2::new(
        plan,
        &binding_one,
        &foreign_pair,
        Role::SignerA,
        backend_share_wire(&share_a),
        ISSUED_AT_MS,
    )
    .unwrap_err();
    assert_eq!(
        error.code(),
        router_ab_core::RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair
    );
    assert_ne!(pair_one, foreign_pair);
}

#[test]
fn stable_signer_input_rejects_a_plan_or_receipt_substitution() {
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let (active, share_a, _) = active_refresh_state(lineage(0x7f));
    let binding_one = custody_binding(&active, &stable_context);
    let active_pair = active_pair(&active, &binding_one);

    let alternate_binding =
        custody_binding(&active, &StableTenantDerivationContextV2::new([0x43; 32]));
    let alternate_plan = plan_mpc_prf_stable_purpose_binding_v2(
        &StableTenantDerivationContextV2::new([0x43; 32]),
        &alternate_binding,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();
    let plan_error = MpcPrfStableThresholdSignerInputV2::new(
        alternate_plan,
        &binding_one,
        &active_pair,
        Role::SignerA,
        backend_share_wire(&share_a),
        ISSUED_AT_MS,
    )
    .unwrap_err();
    assert_eq!(
        plan_error.code(),
        router_ab_core::RouterAbDerivationErrorCode::TranscriptMismatch
    );

    let expected_receipt = binding_one.activation_receipt_digest();
    let substituted_receipt = digest(0x9a);
    let substituted_receipt_resolution = resolve_active_tenant_root_pair_binding_v1(
        active.identity().digest().unwrap(),
        &active_role_resolution(
            &active,
            TenantRootManagedRestoreRoleV1::DeriverA,
            expected_receipt,
        ),
        &active_role_resolution(
            &active,
            TenantRootManagedRestoreRoleV1::DeriverB,
            substituted_receipt,
        ),
    )
    .unwrap();
    assert_eq!(
        substituted_receipt_resolution,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ActivationReceiptDigests {
                deriver_a: expected_receipt,
                deriver_b: substituted_receipt,
            }
        )
    );
    assert_eq!(
        substituted_receipt_resolution
            .require_active()
            .unwrap_err()
            .code(),
        router_ab_core::RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair
    );
}

#[test]
fn stable_signer_input_rejects_an_invalid_or_mismatched_role() {
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let (active, share_a, _) = active_refresh_state(lineage(0x7e));
    let custody_binding = custody_binding(&active, &stable_context);
    let active_pair = active_pair(&active, &custody_binding);
    let plan = plan_mpc_prf_stable_purpose_binding_v2(
        &stable_context,
        &custody_binding,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();

    let invalid_role = MpcPrfStableThresholdSignerInputV2::new(
        plan.clone(),
        &custody_binding,
        &active_pair,
        Role::Server,
        backend_share_wire(&share_a),
        ISSUED_AT_MS,
    )
    .unwrap_err();
    assert_eq!(
        invalid_role.code(),
        router_ab_core::RouterAbDerivationErrorCode::SignerIdentityMismatch
    );

    let mismatched_role = MpcPrfStableThresholdSignerInputV2::new(
        plan,
        &custody_binding,
        &active_pair,
        Role::SignerB,
        backend_share_wire(&share_a),
        ISSUED_AT_MS,
    )
    .unwrap_err();
    assert_eq!(
        mismatched_role.code(),
        router_ab_core::RouterAbDerivationErrorCode::SignerIdentityMismatch
    );
}

#[test]
fn authoritative_pair_requires_exact_custody_facts_and_activation_receipt() {
    let (active, _, _) = active_refresh_state(lineage(0x75));
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let custody_binding = custody_binding(&active, &stable_context);
    let activation_receipt_digest = active.current().activation().digest();
    let deriver_a = active_role_resolution(
        &active,
        TenantRootManagedRestoreRoleV1::DeriverA,
        activation_receipt_digest,
    );
    let deriver_b = active_role_resolution(
        &active,
        TenantRootManagedRestoreRoleV1::DeriverB,
        activation_receipt_digest,
    );

    let resolution = resolve_authoritative_active_tenant_root_pair_binding_v1(
        active.identity().digest().unwrap(),
        &custody_binding,
        &deriver_a,
        &deriver_b,
    )
    .unwrap();
    let pair = resolution.require_active().unwrap();
    assert_eq!(pair.identity_digest(), custody_binding.identity_digest());
    assert_eq!(pair.custody_lineage(), custody_binding.custody_lineage());
    assert_eq!(pair.epoch(), custody_binding.epoch());
    assert_eq!(pair.commitments(), custody_binding.commitments());
    assert_eq!(pair.root_commitment(), custody_binding.root_commitment());
    assert_eq!(
        pair.activation_receipt_digest(),
        custody_binding.activation_receipt_digest(),
    );
}

#[test]
fn authoritative_pair_rejects_stale_lineage_epoch_or_commitments() {
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let (epoch_one, share_a, share_b) = active_refresh_state(lineage(0x76));
    let custody_binding = custody_binding(&epoch_one, &stable_context);

    let (epoch_two, _, _) = advance_active_refresh(epoch_one, &share_a, &share_b);
    assert_ne!(epoch_two.current().epoch(), custody_binding.epoch());
    assert_ne!(
        epoch_two.current().verified().commitments(),
        custody_binding.commitments()
    );
    let refreshed_receipt = epoch_two.current().activation().digest();
    let refreshed = resolve_authoritative_active_tenant_root_pair_binding_v1(
        epoch_two.identity().digest().unwrap(),
        &custody_binding,
        &active_role_resolution(
            &epoch_two,
            TenantRootManagedRestoreRoleV1::DeriverA,
            refreshed_receipt,
        ),
        &active_role_resolution(
            &epoch_two,
            TenantRootManagedRestoreRoleV1::DeriverB,
            refreshed_receipt,
        ),
    )
    .unwrap();
    assert_eq!(
        refreshed,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::CustodyBinding
        )
    );

    let (other_lineage, _, _) = active_refresh_state(lineage(0x77));
    let other_lineage_receipt = other_lineage.current().activation().digest();
    let other_lineage_result = resolve_authoritative_active_tenant_root_pair_binding_v1(
        other_lineage.identity().digest().unwrap(),
        &custody_binding,
        &active_role_resolution(
            &other_lineage,
            TenantRootManagedRestoreRoleV1::DeriverA,
            other_lineage_receipt,
        ),
        &active_role_resolution(
            &other_lineage,
            TenantRootManagedRestoreRoleV1::DeriverB,
            other_lineage_receipt,
        ),
    )
    .unwrap();
    assert_eq!(
        other_lineage_result,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::CustodyBinding
        )
    );
}

#[test]
fn authoritative_pair_rejects_an_activation_receipt_substitution() {
    let (active, _, _) = active_refresh_state(lineage(0x78));
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let custody_binding = custody_binding(&active, &stable_context);
    let expected = custody_binding.activation_receipt_digest();
    let substituted = digest(0x99);
    let resolution = resolve_authoritative_active_tenant_root_pair_binding_v1(
        active.identity().digest().unwrap(),
        &custody_binding,
        &active_role_resolution(&active, TenantRootManagedRestoreRoleV1::DeriverA, expected),
        &active_role_resolution(
            &active,
            TenantRootManagedRestoreRoleV1::DeriverB,
            substituted,
        ),
    )
    .unwrap();
    assert_eq!(
        resolution,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ActivationReceiptDigest {
                expected,
                deriver_a: expected,
                deriver_b: substituted,
            }
        )
    );
}

#[test]
fn authoritative_pair_rejects_a_foreign_custody_identity() {
    let (active, _, _) = active_refresh_state(lineage(0x79));
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let custody_binding = custody_binding(&active, &stable_context);
    let receipt = custody_binding.activation_receipt_digest();
    let deriver_a =
        active_role_resolution(&active, TenantRootManagedRestoreRoleV1::DeriverA, receipt);
    let deriver_b =
        active_role_resolution(&active, TenantRootManagedRestoreRoleV1::DeriverB, receipt);

    let error = resolve_authoritative_active_tenant_root_pair_binding_v1(
        TenantRootIdentityDigestV1::from_bytes([0x99; 32]),
        &custody_binding,
        &deriver_a,
        &deriver_b,
    )
    .unwrap_err();
    assert_eq!(
        error.code(),
        router_ab_core::RouterAbDerivationErrorCode::MalformedInput
    );
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
        TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
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
        TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
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
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
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
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
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
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
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
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
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
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
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
            TenantRootProtocolDigestV1::from_bytes([0x89; 32]).expect("non-zero protocol digest"),
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
        "8e32299705e9c1aa1f87805b882df95f6fdc1dadfb2955585a777b37194170f6",
    );
}

#[test]
fn custody_binding_lifetime_and_identities_use_the_frozen_boundary_rules() {
    let (active, _, _) = active_refresh_state(lineage(0x74));
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let build = |issued_at_ms: u64, expires_at_ms: u64, deriver_a: &str, deriver_b: &str| {
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new(deriver_a, deriver_b)?,
            TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
            TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
            TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
            issued_at_ms,
            expires_at_ms,
            &stable_context,
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("non-zero protocol digest"),
        )
    };

    let issued = ISSUED_AT_MS;
    assert!(build(
        issued,
        issued + TENANT_ROOT_MAX_LIFETIME_MS_V1,
        "deriver-a-runtime-7",
        "deriver-b-runtime-9",
    )
    .is_ok());
    assert!(build(
        issued,
        issued + TENANT_ROOT_MAX_LIFETIME_MS_V1 + 1,
        "deriver-a-runtime-7",
        "deriver-b-runtime-9",
    )
    .is_err());

    for rejected in [
        "",
        " deriver-a-runtime-7",
        "deriver-a-runtime-7 ",
        "deriver-a\u{0000}runtime-7",
        "deriver-a\nruntime-7",
    ] {
        assert!(
            build(issued, EXPIRES_AT_MS, rejected, "deriver-b-runtime-9").is_err(),
            "expected rejection for {rejected:?}"
        );
    }
    let longest = "d".repeat(256);
    assert!(build(issued, EXPIRES_AT_MS, &longest, "deriver-b-runtime-9").is_ok());
    let too_long = "d".repeat(257);
    assert!(build(issued, EXPIRES_AT_MS, &too_long, "deriver-b-runtime-9").is_err());
}
