use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use router_ab_core::{
    evaluate_tenant_root_refresh_commitment_checkpoint_v1,
    resolve_active_tenant_root_pair_binding_v1,
    verify_tenant_root_refresh_installation_transition_v1, MpcPrfShareCommitmentWireV1,
    RouterAbDerivationErrorCode, TenantRootActiveRefreshV1, TenantRootActiveRoleBindingV1,
    TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1, TenantRootActiveRootPairV1,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId,
    TenantRootEmptyCreationV1, TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1,
    TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootPendingCleanupReceiptV1, TenantRootRefreshCommitmentCheckpointActiveBindingV1,
    TenantRootRefreshCommitmentCheckpointEvaluationV1,
    TenantRootRefreshCommitmentCheckpointOutcomeV1, TenantRootRefreshCommitmentCheckpointStateV1,
    TenantRootRefreshCommitmentTranscriptV1, TenantRootRefreshFailureV1,
    TenantRootRoleRefreshCommandV1, TenantRootRoleRetirementReceiptsV1, TenantRootShareEpoch,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootRefreshCommitmentPairV1, VerifiedTenantRootRefreshCommitmentV1,
    VerifiedTenantRootRoleRefreshCommandV1, VerifiedTenantRootSignedActivationReceiptV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};
use threshold_prf::{
    apply_two_party_root_share_refresh, RootShareRefreshCoefficient, SigningRootShare,
    SigningRootShareCommitment, TwoPartyDeriverRole,
};

mod support;

const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;
const ACTIVE_EPOCH: u64 = 1;
const NEXT_EPOCH: u64 = 2;
const EXPECTED_REVISION: u64 = 3;
const ACTIVATION_TIME_MS: u64 = 1_000_020;
const ISSUER_KEY_ID: &str = "control-plane-issuer-v1";
const ISSUER_SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];

fn identity() -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
        .expect("identity")
}

fn identity_digest() -> TenantRootIdentityDigestV1 {
    identity().digest().expect("identity digest")
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("lineage")
}

fn authority(seed: u8) -> TenantRootControlPlaneAuthorityIdV1 {
    TenantRootControlPlaneAuthorityIdV1::from_bytes([seed; 32])
}

fn lifecycle_digest(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).expect("lifecycle digest")
}

fn context(session_seed: u8) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity_digest(),
        lineage(0x31),
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(ACTIVE_EPOCH).expect("active epoch"),
            TenantRootShareEpoch::new(NEXT_EPOCH).expect("next epoch"),
        )
        .expect("refresh epochs"),
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).expect("session id"),
        TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("refresh context")
}

fn creation_context() -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity_digest(),
        lineage(0x31),
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x10; 16]).expect("session id"),
        TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce"),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .expect("creation context")
}

fn signing_root_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
    SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
        .expect("signing root share")
}

fn active_share_commitment(role: TwoPartyDeriverRole, scalar: u64) -> MpcPrfShareCommitmentWireV1 {
    MpcPrfShareCommitmentWireV1::new(
        SigningRootShareCommitment::from_share(&signing_root_share(role, scalar))
            .to_bytes()
            .to_vec(),
    )
    .expect("active share commitment")
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
        .expect("Deriver A refresh contribution");
    let contribution_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(recipient))
        .expect("Deriver B refresh contribution");
    apply_two_party_root_share_refresh(current, contribution_a, contribution_b)
        .expect("refreshed share")
}

struct ActiveStateFixture {
    state: TenantRootActiveRefreshV1,
    bundle: router_ab_core::VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
}

fn active_state_fixture() -> ActiveStateFixture {
    let share_a = signing_root_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = signing_root_share(TwoPartyDeriverRole::DeriverB, 19);
    let fixture = support::initial_activation_evidence_fixture(
        creation_context(),
        &share_a,
        &share_b,
        0x21,
        0x22,
    );
    let verified = TenantRootEmptyCreationV1::new(identity(), lineage(0x31))
        .start(fixture.bundle.context())
        .expect("creation start")
        .verify(
            &fixture.evidence_a,
            &fixture.evidence_b,
            fixture.installation_receipts,
            fixture.backup_policy,
            fixture.canary_receipts,
            ISSUED_AT_MS + 10,
        )
        .expect("creation verification");
    let activation_receipt =
        support::initial_activation_receipt(&fixture.bundle, ACTIVATION_TIME_MS);
    let state = verified
        .activate(support::initial_activation_receipt(
            &fixture.bundle,
            ACTIVATION_TIME_MS,
        ))
        .expect("creation activation")
        .into_refresh_state();
    ActiveStateFixture {
        state,
        bundle: fixture.bundle,
        activation_receipt,
    }
}

fn active_pair_with(
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: TenantRootShareEpoch,
    deriver_a_scalar: u64,
    deriver_b_scalar: u64,
    receipt: TenantRootLifecycleReceiptDigestV1,
) -> TenantRootActiveRootPairV1 {
    let deriver_a = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            epoch,
            TenantRootManagedRestoreRoleV1::DeriverA,
        ),
        active_share_commitment(TwoPartyDeriverRole::DeriverA, deriver_a_scalar),
        receipt,
    )
    .expect("Deriver A active binding");
    let deriver_b = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            epoch,
            TenantRootManagedRestoreRoleV1::DeriverB,
        ),
        active_share_commitment(TwoPartyDeriverRole::DeriverB, deriver_b_scalar),
        receipt,
    )
    .expect("Deriver B active binding");
    resolve_active_tenant_root_pair_binding_v1(
        identity_digest,
        &TenantRootActiveRoleResolutionV1::Active(deriver_a),
        &TenantRootActiveRoleResolutionV1::Active(deriver_b),
    )
    .expect("active pair resolution")
    .require_active()
    .expect("active pair")
    .clone()
}

fn active_pair(
    active_state: &TenantRootActiveRefreshV1,
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
) -> TenantRootActiveRootPairV1 {
    let identity_digest = active_state
        .identity()
        .digest()
        .expect("active identity digest");
    let custody_lineage = active_state.custody_lineage();
    let epoch = active_state.current().epoch();
    let commitments = active_state.current().verified().commitments();
    let receipt = activation_receipt.digest();
    let deriver_a = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            epoch,
            TenantRootManagedRestoreRoleV1::DeriverA,
        ),
        commitments.deriver_a().clone(),
        receipt,
    )
    .expect("Deriver A active binding");
    let deriver_b = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            epoch,
            TenantRootManagedRestoreRoleV1::DeriverB,
        ),
        commitments.deriver_b().clone(),
        receipt,
    )
    .expect("Deriver B active binding");
    resolve_active_tenant_root_pair_binding_v1(
        identity_digest,
        &TenantRootActiveRoleResolutionV1::Active(deriver_a),
        &TenantRootActiveRoleResolutionV1::Active(deriver_b),
    )
    .expect("active pair resolution")
    .require_active()
    .expect("active pair")
    .clone()
}

fn command(
    active_pair: &TenantRootActiveRootPairV1,
    context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
) -> TenantRootRoleRefreshCommandV1 {
    TenantRootRoleRefreshCommandV1::sign(
        active_pair,
        context,
        role,
        EXPECTED_REVISION,
        authority_id,
        ISSUED_AT_MS + 1,
        EXPIRES_AT_MS - 1,
        ISSUER_KEY_ID,
        &ISSUER_SIGNING_KEY_BYTES,
    )
    .expect("refresh command")
}

fn verified_command(
    command: &TenantRootRoleRefreshCommandV1,
    active_pair: &TenantRootActiveRootPairV1,
    context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
) -> VerifiedTenantRootRoleRefreshCommandV1 {
    command
        .verify(
            active_pair,
            context,
            role,
            EXPECTED_REVISION,
            authority_id,
            ISSUER_KEY_ID,
            SigningKey::from_bytes(&ISSUER_SIGNING_KEY_BYTES)
                .verifying_key()
                .as_bytes(),
        )
        .expect("verified refresh command")
}

fn signed_commitment(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    scalar: u64,
) -> TenantRootSignedRefreshCommitmentV1 {
    let coefficient =
        RootShareRefreshCoefficient::from_canonical_bytes(role, Scalar::from(scalar).to_bytes())
            .expect("refresh coefficient");
    let transcript =
        TenantRootRefreshCommitmentTranscriptV1::new(context, coefficient.commitment())
            .expect("refresh commitment transcript");
    let signing_key = match role {
        TwoPartyDeriverRole::DeriverA => SigningKey::from_bytes(&[0x51; 32]),
        TwoPartyDeriverRole::DeriverB => SigningKey::from_bytes(&[0x61; 32]),
    };
    TenantRootSignedRefreshCommitmentV1::sign(transcript, &signing_key.to_bytes())
        .expect("signed refresh commitment")
}

fn verified_commitment(
    signed: &TenantRootSignedRefreshCommitmentV1,
    context: &TenantRootCeremonyContextV1,
) -> VerifiedTenantRootRefreshCommitmentV1 {
    let verifying_key = match signed.role() {
        TwoPartyDeriverRole::DeriverA => SigningKey::from_bytes(&[0x51; 32]),
        TwoPartyDeriverRole::DeriverB => SigningKey::from_bytes(&[0x61; 32]),
    };
    signed
        .verify_strict(
            context,
            signed.role(),
            context.signing_key_id(signed.role()),
            verifying_key.verifying_key().as_bytes(),
        )
        .expect("verified refresh commitment")
}

fn installation_wires(
    context: &TenantRootCeremonyContextV1,
    current_commitments: &TenantRootEpochCommitmentsV1,
    share_a: &SigningRootShare,
    share_b: &SigningRootShare,
    proof_seed_a: u8,
    proof_seed_b: u8,
) -> (
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) {
    let fixture = support::refresh_activation_evidence_fixture(
        context.clone(),
        current_commitments,
        share_a,
        share_b,
        proof_seed_a,
        proof_seed_b,
        EXPECTED_REVISION,
    );
    let (wire_a, wire_b) = fixture.bundle.into_installation_evidence_bytes();
    let key_a = SigningKey::from_bytes(&[0x51; 32]);
    let key_b = SigningKey::from_bytes(&[0x61; 32]);
    (
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &wire_a,
            key_a.verifying_key().as_bytes(),
        )
        .expect("verified Deriver A installation wire"),
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &wire_b,
            key_b.verifying_key().as_bytes(),
        )
        .expect("verified Deriver B installation wire"),
    )
}

fn active_binding(
    active_pair: &TenantRootActiveRootPairV1,
    activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
) -> TenantRootRefreshCommitmentCheckpointActiveBindingV1 {
    TenantRootRefreshCommitmentCheckpointActiveBindingV1::from_verified_activation_receipt(
        activation_receipt,
        active_pair,
        EXPECTED_REVISION,
    )
    .expect("active checkpoint binding")
}

#[test]
fn active_binding_requires_exact_signed_activation_provenance() {
    let active_fixture = active_state_fixture();
    let active_state = &active_fixture.state;
    let active_pair = active_pair(active_state, &active_fixture.activation_receipt);
    let binding = active_binding(&active_pair, active_fixture.activation_receipt);
    assert_eq!(binding.expected_control_plane_revision(), EXPECTED_REVISION);
    assert_eq!(
        binding.active_activation_receipt_digest(),
        active_pair.activation_receipt_digest()
    );
    let error =
        TenantRootRefreshCommitmentCheckpointActiveBindingV1::from_verified_activation_receipt(
            support::initial_activation_receipt(&active_fixture.bundle, ACTIVATION_TIME_MS + 1),
            &active_pair,
            EXPECTED_REVISION,
        )
        .expect_err("active pair must retain the exact activation receipt");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);

    let substitutions = [
        (
            "identity",
            active_pair_with(
                TenantRootIdentityDigestV1::from_bytes([0x12; 32]),
                lineage(0x31),
                TenantRootShareEpoch::new(ACTIVE_EPOCH).expect("active epoch"),
                12,
                19,
                active_pair.activation_receipt_digest(),
            ),
        ),
        (
            "lineage",
            active_pair_with(
                identity_digest(),
                lineage(0x32),
                TenantRootShareEpoch::new(ACTIVE_EPOCH).expect("active epoch"),
                12,
                19,
                active_pair.activation_receipt_digest(),
            ),
        ),
        (
            "epoch",
            active_pair_with(
                identity_digest(),
                lineage(0x31),
                TenantRootShareEpoch::new(ACTIVE_EPOCH + 1).expect("substituted epoch"),
                12,
                19,
                active_pair.activation_receipt_digest(),
            ),
        ),
        (
            "commitments and root",
            active_pair_with(
                identity_digest(),
                lineage(0x31),
                TenantRootShareEpoch::new(ACTIVE_EPOCH).expect("active epoch"),
                13,
                20,
                active_pair.activation_receipt_digest(),
            ),
        ),
        (
            "role receipt digests",
            active_pair_with(
                identity_digest(),
                lineage(0x31),
                TenantRootShareEpoch::new(ACTIVE_EPOCH).expect("active epoch"),
                12,
                19,
                lifecycle_digest(0x72),
            ),
        ),
    ];
    for (substitution, substituted_pair) in substitutions {
        let error =
            TenantRootRefreshCommitmentCheckpointActiveBindingV1::from_verified_activation_receipt(
                support::initial_activation_receipt(&active_fixture.bundle, ACTIVATION_TIME_MS),
                &substituted_pair,
                EXPECTED_REVISION,
            )
            .expect_err("active-pair substitution must fail closed");
        assert_eq!(
            error.code(),
            RouterAbDerivationErrorCode::ReplayMismatch,
            "unexpected error for {substitution} substitution"
        );
    }
}

struct RetriedActiveStateFixture {
    state: TenantRootActiveRefreshV1,
    bundle: router_ab_core::VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
}

fn active_state_after_failed_retry() -> RetriedActiveStateFixture {
    let current_a = signing_root_share(TwoPartyDeriverRole::DeriverA, 12);
    let current_b = signing_root_share(TwoPartyDeriverRole::DeriverB, 19);
    let initial = active_state_fixture();
    let current_commitments = initial.bundle.commitments().clone();
    let failed = initial
        .state
        .start(&context(0x11))
        .expect("failed refresh start")
        .fail_with_cleanup(
            TenantRootRefreshFailureV1::new(lifecycle_digest(0x71), ISSUED_AT_MS + 2)
                .expect("refresh failure"),
            TenantRootPendingCleanupReceiptV1::new(
                lifecycle_digest(0x72),
                lifecycle_digest(0x73),
                ISSUED_AT_MS + 3,
            )
            .expect("pending cleanup"),
        )
        .expect("failed refresh cleanup");
    let retry_context = context(0x12);
    let coefficient_a = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverA,
        Scalar::from(23_u64).to_bytes(),
    )
    .expect("Deriver A refresh coefficient");
    let coefficient_b = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverB,
        Scalar::from(31_u64).to_bytes(),
    )
    .expect("Deriver B refresh coefficient");
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
    let preparing = failed.retry(&retry_context).expect("refresh retry");
    let expected_revision = preparing
        .revision()
        .checked_add(1)
        .expect("refresh verification revision");
    let fixture = support::refresh_activation_evidence_fixture(
        retry_context,
        &current_commitments,
        &next_a,
        &next_b,
        0x31,
        0x32,
        expected_revision,
    );
    let verified = preparing
        .verify(
            &fixture.evidence_a,
            &fixture.evidence_b,
            fixture.installation_receipts,
            fixture.backup_policy,
            fixture.canary_receipts,
            ISSUED_AT_MS + 10,
        )
        .expect("refresh retry verification");
    let activation_time_ms = ACTIVATION_TIME_MS + 20;
    let receipt_for_binding =
        support::refresh_activation_receipt(&fixture.bundle, activation_time_ms);
    let active = verified
        .activate(support::refresh_activation_receipt(
            &fixture.bundle,
            activation_time_ms,
        ))
        .expect("refresh retry activation")
        .finish_retirement(
            TenantRootRoleRetirementReceiptsV1::new(
                lifecycle_digest(0x81),
                lifecycle_digest(0x82),
                activation_time_ms + 1,
            )
            .expect("retirement receipts"),
        )
        .expect("refresh retry retirement");
    RetriedActiveStateFixture {
        state: active,
        bundle: fixture.bundle,
        activation_receipt: receipt_for_binding,
    }
}

#[test]
fn active_binding_uses_revision_after_failed_attempt_and_retry() {
    let active_fixture = active_state_after_failed_retry();
    let active_state = &active_fixture.state;
    let active_pair = active_pair(active_state, &active_fixture.activation_receipt);
    assert_eq!(active_fixture.bundle.expected_control_plane_revision(), 7);
    assert_eq!(
        active_fixture
            .activation_receipt
            .result_control_plane_revision(),
        8
    );
    assert_eq!(active_state.revision(), 9);
    assert!(
        active_state.revision()
            >= active_fixture
                .activation_receipt
                .result_control_plane_revision()
    );

    let binding =
        TenantRootRefreshCommitmentCheckpointActiveBindingV1::from_verified_activation_receipt(
            active_fixture.activation_receipt,
            &active_pair,
            active_state.revision(),
        )
        .expect("active checkpoint binding after retry");
    assert_eq!(binding.expected_control_plane_revision(), 9);
}

fn evaluate(
    existing: Option<router_ab_core::TenantRootRefreshCommitmentCheckpointV1>,
    candidate: VerifiedTenantRootRefreshCommitmentV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    active_binding: &TenantRootRefreshCommitmentCheckpointActiveBindingV1,
    context: &TenantRootCeremonyContextV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    now_ms: u64,
) -> TenantRootRefreshCommitmentCheckpointEvaluationV1 {
    let key_a = SigningKey::from_bytes(&[0x51; 32]);
    let key_b = SigningKey::from_bytes(&[0x61; 32]);
    evaluate_tenant_root_refresh_commitment_checkpoint_v1(
        existing,
        candidate,
        command,
        active_binding,
        context,
        authority_id,
        key_a.verifying_key().as_bytes(),
        key_b.verifying_key().as_bytes(),
        now_ms,
    )
    .expect("checkpoint evaluation")
}

#[test]
fn checkpoint_retains_exact_wires_and_replays_after_expiry() {
    let active_fixture = active_state_fixture();
    let active_state = &active_fixture.state;
    let active_pair = active_pair(active_state, &active_fixture.activation_receipt);
    let active_binding = active_binding(&active_pair, active_fixture.activation_receipt);
    let context = context(0x11);
    let authority_id = authority(0x44);
    let command_a = command(
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverA,
        authority_id,
    );
    let command_b = command(
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverB,
        authority_id,
    );
    let verified_command_a = verified_command(
        &command_a,
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverA,
        authority_id,
    );
    let verified_command_b = verified_command(
        &command_b,
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverB,
        authority_id,
    );
    let signed_a = signed_commitment(context.clone(), TwoPartyDeriverRole::DeriverA, 17);
    let signed_b = signed_commitment(context.clone(), TwoPartyDeriverRole::DeriverB, 29);
    let signed_a_bytes = signed_a.canonical_bytes().expect("A wire");
    let signed_b_bytes = signed_b.canonical_bytes().expect("B wire");

    let first = evaluate(
        None,
        verified_commitment(&signed_a, &context),
        &verified_command_a,
        &active_binding,
        &context,
        authority_id,
        ISSUED_AT_MS + 1,
    );
    let checkpoint = match first {
        TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit {
            checkpoint,
            outcome:
                TenantRootRefreshCommitmentCheckpointOutcomeV1::WaitingForPeer {
                    role: TwoPartyDeriverRole::DeriverA,
                },
        } => checkpoint,
        other => panic!("unexpected first evaluation: {other:?}"),
    };
    match checkpoint.state() {
        TenantRootRefreshCommitmentCheckpointStateV1::OneRoleCommitted {
            role,
            command_digest,
            signed_commitment,
        } => {
            assert_eq!(*role, TwoPartyDeriverRole::DeriverA);
            assert_eq!(*command_digest, verified_command_a.digest());
            assert_eq!(signed_commitment, &signed_a_bytes);
        }
        other => panic!("unexpected first checkpoint state: {other:?}"),
    }
    let checkpoint_wire = checkpoint.canonical_bytes().expect("checkpoint wire");
    let decoded = router_ab_core::TenantRootRefreshCommitmentCheckpointV1::decode_canonical_bytes(
        &checkpoint_wire,
    )
    .expect("decoded checkpoint");
    assert_eq!(
        decoded.canonical_bytes().expect("re-encoded checkpoint"),
        checkpoint_wire
    );

    let replay = evaluate(
        Some(checkpoint.clone()),
        verified_commitment(&signed_a, &context),
        &verified_command_a,
        &active_binding,
        &context,
        authority_id,
        EXPIRES_AT_MS + 1,
    );
    assert!(matches!(
        replay,
        TenantRootRefreshCommitmentCheckpointEvaluationV1::Replay(
            TenantRootRefreshCommitmentCheckpointOutcomeV1::WaitingForPeer {
                role: TwoPartyDeriverRole::DeriverA
            }
        )
    ));

    let complete = evaluate(
        Some(checkpoint),
        verified_commitment(&signed_b, &context),
        &verified_command_b,
        &active_binding,
        &context,
        authority_id,
        EXPIRES_AT_MS - 1,
    );
    let complete_checkpoint = match complete {
        TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit {
            checkpoint,
            outcome: TenantRootRefreshCommitmentCheckpointOutcomeV1::BothRolesCommitted { pair },
        } => {
            assert_eq!(pair.context(), &context);
            checkpoint
        }
        other => panic!("unexpected completion evaluation: {other:?}"),
    };
    match complete_checkpoint.state() {
        TenantRootRefreshCommitmentCheckpointStateV1::BothRolesCommitted {
            deriver_a_signed_commitment,
            deriver_b_signed_commitment,
            ..
        } => {
            assert_eq!(deriver_a_signed_commitment, &signed_a_bytes);
            assert_eq!(deriver_b_signed_commitment, &signed_b_bytes);
        }
        other => panic!("unexpected completed checkpoint state: {other:?}"),
    }

    let completed_replay = evaluate(
        Some(complete_checkpoint),
        verified_commitment(&signed_b, &context),
        &verified_command_b,
        &active_binding,
        &context,
        authority_id,
        EXPIRES_AT_MS + 1,
    );
    assert!(matches!(
        completed_replay,
        TenantRootRefreshCommitmentCheckpointEvaluationV1::Replay(
            TenantRootRefreshCommitmentCheckpointOutcomeV1::BothRolesCommitted { .. }
        )
    ));
}

#[test]
fn refresh_installation_transition_matches_active_and_accepted_coefficients() {
    let active_fixture = active_state_fixture();
    let active_pair = active_pair(&active_fixture.state, &active_fixture.activation_receipt);
    let active_commitments = active_pair.commitments().clone();
    let context = context(0x11);
    let coefficient_a = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverA,
        Scalar::from(7_u64).to_bytes(),
    )
    .expect("Deriver A refresh coefficient");
    let coefficient_b = RootShareRefreshCoefficient::from_canonical_bytes(
        TwoPartyDeriverRole::DeriverB,
        Scalar::from(11_u64).to_bytes(),
    )
    .expect("Deriver B refresh coefficient");
    let accepted_commitments = VerifiedTenantRootRefreshCommitmentPairV1::new(
        verified_commitment(
            &signed_commitment(context.clone(), TwoPartyDeriverRole::DeriverA, 7),
            &context,
        ),
        verified_commitment(
            &signed_commitment(context.clone(), TwoPartyDeriverRole::DeriverB, 11),
            &context,
        ),
    )
    .expect("accepted refresh commitment pair");
    let current_a = signing_root_share(TwoPartyDeriverRole::DeriverA, 12);
    let current_b = signing_root_share(TwoPartyDeriverRole::DeriverB, 19);
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
    let (installation_a, installation_b) =
        installation_wires(&context, &active_commitments, &next_a, &next_b, 0x71, 0x72);

    let next_commitments = verify_tenant_root_refresh_installation_transition_v1(
        &active_commitments,
        &accepted_commitments,
        &installation_a,
        &installation_b,
    )
    .expect("exact active plus coefficient transition");
    assert_eq!(
        next_commitments.root_commitment(),
        active_commitments.root_commitment()
    );
    let next_a_commitment = SigningRootShareCommitment::from_share(&next_a).to_bytes();
    let next_b_commitment = SigningRootShareCommitment::from_share(&next_b).to_bytes();
    assert_eq!(
        next_commitments.deriver_a().as_bytes(),
        next_a_commitment.as_slice()
    );
    assert_eq!(
        next_commitments.deriver_b().as_bytes(),
        next_b_commitment.as_slice()
    );

    for (substituted_a, substituted_b, proof_seed) in
        [(31_u64, 57_u64, 0x73_u8), (29_u64, 53_u64, 0x75_u8)]
    {
        let substituted_a_share = signing_root_share(TwoPartyDeriverRole::DeriverA, substituted_a);
        let substituted_b_share = signing_root_share(TwoPartyDeriverRole::DeriverB, substituted_b);
        let (substituted_a_installation, substituted_b_installation) = installation_wires(
            &context,
            &active_commitments,
            &substituted_a_share,
            &substituted_b_share,
            proof_seed,
            proof_seed.wrapping_add(1),
        );
        let error = verify_tenant_root_refresh_installation_transition_v1(
            &active_commitments,
            &accepted_commitments,
            &substituted_a_installation,
            &substituted_b_installation,
        )
        .expect_err("root-preserving local/peer substitution must fail");
        assert_eq!(
            error.code(),
            RouterAbDerivationErrorCode::OutputVerificationFailed
        );
    }

    let coefficient_current = TenantRootEpochCommitmentsV1::new(
        active_share_commitment(TwoPartyDeriverRole::DeriverA, 12),
        active_share_commitment(TwoPartyDeriverRole::DeriverB, 21),
    )
    .expect("coefficient substitution active commitments");
    let coefficient_share_a = signing_root_share(TwoPartyDeriverRole::DeriverA, 7);
    let coefficient_share_b = signing_root_share(TwoPartyDeriverRole::DeriverB, 11);
    let (coefficient_installation_a, coefficient_installation_b) = installation_wires(
        &context,
        &coefficient_current,
        &coefficient_share_a,
        &coefficient_share_b,
        0x77,
        0x78,
    );
    let error = verify_tenant_root_refresh_installation_transition_v1(
        &coefficient_current,
        &accepted_commitments,
        &coefficient_installation_a,
        &coefficient_installation_b,
    )
    .expect_err("coefficient commitments must not be accepted as installed shares");
    assert_eq!(
        error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn checkpoint_rejects_changed_scope_role_or_commitment() {
    let active_fixture = active_state_fixture();
    let active_state = &active_fixture.state;
    let active_pair = active_pair(active_state, &active_fixture.activation_receipt);
    let active_binding = active_binding(&active_pair, active_fixture.activation_receipt);
    let context = context(0x11);
    let authority_id = authority(0x44);
    let command_a = command(
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverA,
        authority_id,
    );
    let verified_command_a = verified_command(
        &command_a,
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverA,
        authority_id,
    );
    let signed_a = signed_commitment(context.clone(), TwoPartyDeriverRole::DeriverA, 17);

    let checkpoint = match evaluate(
        None,
        verified_commitment(&signed_a, &context),
        &verified_command_a,
        &active_binding,
        &context,
        authority_id,
        ISSUED_AT_MS + 1,
    ) {
        TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit { checkpoint, .. } => checkpoint,
        other => panic!("unexpected first evaluation: {other:?}"),
    };

    let changed_commitment = signed_commitment(context.clone(), TwoPartyDeriverRole::DeriverA, 18);
    let error = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
        Some(checkpoint.clone()),
        verified_commitment(&changed_commitment, &context),
        &verified_command_a,
        &active_binding,
        &context,
        authority_id,
        SigningKey::from_bytes(&[0x51; 32])
            .verifying_key()
            .as_bytes(),
        SigningKey::from_bytes(&[0x61; 32])
            .verifying_key()
            .as_bytes(),
        EXPIRES_AT_MS + 1,
    )
    .expect_err("changed commitment must conflict");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);

    let signed_b = signed_commitment(context.clone(), TwoPartyDeriverRole::DeriverB, 29);
    let error = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
        Some(checkpoint.clone()),
        verified_commitment(&signed_b, &context),
        &verified_command_a,
        &active_binding,
        &context,
        authority_id,
        SigningKey::from_bytes(&[0x51; 32])
            .verifying_key()
            .as_bytes(),
        SigningKey::from_bytes(&[0x61; 32])
            .verifying_key()
            .as_bytes(),
        ISSUED_AT_MS + 1,
    )
    .expect_err("role-swapped candidate must conflict");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);

    let changed_authority = authority(0x45);
    let changed_command = command(
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverA,
        changed_authority,
    );
    let verified_changed_command = verified_command(
        &changed_command,
        &active_pair,
        &context,
        TwoPartyDeriverRole::DeriverA,
        changed_authority,
    );
    let error = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
        Some(checkpoint.clone()),
        verified_commitment(&signed_a, &context),
        &verified_changed_command,
        &active_binding,
        &context,
        authority_id,
        SigningKey::from_bytes(&[0x51; 32])
            .verifying_key()
            .as_bytes(),
        SigningKey::from_bytes(&[0x61; 32])
            .verifying_key()
            .as_bytes(),
        EXPIRES_AT_MS + 1,
    )
    .expect_err("authority substitution must conflict");
    assert_eq!(error.code(), RouterAbDerivationErrorCode::ReplayMismatch);

    let checkpoint_wire = checkpoint.canonical_bytes().expect("checkpoint wire");
    let mut trailing = checkpoint_wire.clone();
    trailing.push(0);
    assert!(
        router_ab_core::TenantRootRefreshCommitmentCheckpointV1::decode_canonical_bytes(&trailing)
            .is_err()
    );
}
