use router_ab_cloudflare::{
    TenantRootCutoverAttemptIdV1, TenantRootCutoverCanaryCurveV1, TenantRootCutoverCanaryReceiptV1,
    TenantRootCutoverDrainReceiptV1, TenantRootCutoverFenceReceiptV1, TenantRootCutoverOpenV1,
    TenantRootCutoverPrerequisitesV1, TenantRootCutoverProfileActivationReceiptV1,
    TenantRootCutoverReceiptDigestV1, TenantRootCutoverRecoveryActionV1,
    TenantRootCutoverRevisionVerificationReceiptV1, TenantRootCutoverRollbackReceiptV1,
    TenantRootCutoverStateV1, TenantRootCutoverUnfenceReceiptV1, TenantRootDerivationProfileV1,
    TenantRootParticipantStorageRevisionV1, TenantRootProtocolVersionV1,
    TenantRootRevisionManifestV1, TenantRootRevisionParticipantInputV1,
    TenantRootRevisionParticipantRoleV1, TenantRootRevisionParticipantV1,
    TenantRootYaoArtifactDigestSetV1,
};

const GIT_COMMIT: &str = "1111111111111111111111111111111111111111";
const B4_B5_COMMIT: &str = "2222222222222222222222222222222222222222";

fn receipt(seed: u8) -> TenantRootCutoverReceiptDigestV1 {
    TenantRootCutoverReceiptDigestV1::from_bytes([seed; 32]).expect("receipt")
}

fn attempt(seed: u8) -> TenantRootCutoverAttemptIdV1 {
    TenantRootCutoverAttemptIdV1::from_bytes([seed; 16]).expect("attempt")
}

fn attempt_id() -> TenantRootCutoverAttemptIdV1 {
    attempt(0x55)
}

/// The verifier-committed Phase 0 `approval_payload_sha256` the manifest names.
const PHASE0_SELECTION_RECORD: [u8; 32] = [0x40; 32];

fn prerequisites() -> TenantRootCutoverPrerequisitesV1 {
    prerequisites_for(PHASE0_SELECTION_RECORD)
}

fn prerequisites_for(record_digest: [u8; 32]) -> TenantRootCutoverPrerequisitesV1 {
    TenantRootCutoverPrerequisitesV1::new(receipt(1), receipt(2), receipt(3), record_digest)
        .expect("prerequisites")
}

fn manifest() -> TenantRootRevisionManifestV1 {
    let artifacts = TenantRootYaoArtifactDigestSetV1::new(
        [0x10; 32], [0x11; 32], [0x12; 32], [0x13; 32], [0x14; 32], [0x15; 32],
    )
    .expect("artifacts");
    TenantRootRevisionManifestV1::new(
        B4_B5_COMMIT,
        PHASE0_SELECTION_RECORD,
        participant(TenantRootRevisionParticipantRoleV1::WalletServer, artifacts),
        participant(TenantRootRevisionParticipantRoleV1::Router, artifacts),
        participant(TenantRootRevisionParticipantRoleV1::DeriverA, artifacts),
        participant(TenantRootRevisionParticipantRoleV1::DeriverB, artifacts),
        participant(
            TenantRootRevisionParticipantRoleV1::SigningWorker,
            artifacts,
        ),
    )
    .expect("manifest")
}

fn participant(
    role: TenantRootRevisionParticipantRoleV1,
    artifacts: TenantRootYaoArtifactDigestSetV1,
) -> TenantRootRevisionParticipantV1 {
    let role_name = match role {
        TenantRootRevisionParticipantRoleV1::WalletServer => "wallet-server",
        TenantRootRevisionParticipantRoleV1::Router => "router",
        TenantRootRevisionParticipantRoleV1::DeriverA => "deriver-a",
        TenantRootRevisionParticipantRoleV1::DeriverB => "deriver-b",
        TenantRootRevisionParticipantRoleV1::SigningWorker => "signing-worker",
    };
    let configuration_seed = match role {
        TenantRootRevisionParticipantRoleV1::WalletServer => 0x31,
        TenantRootRevisionParticipantRoleV1::Router => 0x32,
        TenantRootRevisionParticipantRoleV1::DeriverA => 0x33,
        TenantRootRevisionParticipantRoleV1::DeriverB => 0x34,
        TenantRootRevisionParticipantRoleV1::SigningWorker => 0x35,
    };
    let storage = match role {
        TenantRootRevisionParticipantRoleV1::DeriverA
        | TenantRootRevisionParticipantRoleV1::DeriverB => {
            TenantRootParticipantStorageRevisionV1::RolePrivateD1 {
                migration_head: "0003_tenant_root_command_replays".to_owned(),
            }
        }
        TenantRootRevisionParticipantRoleV1::WalletServer
        | TenantRootRevisionParticipantRoleV1::Router
        | TenantRootRevisionParticipantRoleV1::SigningWorker => {
            TenantRootParticipantStorageRevisionV1::Stateless
        }
    };
    TenantRootRevisionParticipantV1::new(TenantRootRevisionParticipantInputV1 {
        role,
        release_id: "release-120-1".to_owned(),
        git_commit: GIT_COMMIT.to_owned(),
        deployed_script_identity: format!("seams-{role_name}"),
        deployment_id: format!("deployment-{role_name}"),
        source_build_digest: [0x30; 32],
        configuration_digest: [configuration_seed; 32],
        protocol_version: TenantRootProtocolVersionV1::R120V1,
        profile: TenantRootDerivationProfileV1::RoleTargetedThresholdPrfV1,
        yao_artifacts: artifacts,
        storage,
    })
    .expect("participant")
}

fn fence_receipt(seed: u8, at_ms: u64) -> TenantRootCutoverFenceReceiptV1 {
    TenantRootCutoverFenceReceiptV1::new(attempt_id(), receipt(seed), at_ms).expect("fence receipt")
}

fn drain_receipt(
    zero_in_flight_seed: u8,
    delayed_commit_seed: u8,
    at_ms: u64,
) -> TenantRootCutoverDrainReceiptV1 {
    TenantRootCutoverDrainReceiptV1::new(
        attempt_id(),
        receipt(zero_in_flight_seed),
        receipt(delayed_commit_seed),
        at_ms,
    )
    .expect("drain receipt")
}

fn revision_receipt(
    ecdsa_seed: u8,
    ed25519_seed: u8,
    mixed_revision_seed: u8,
    at_ms: u64,
) -> TenantRootCutoverRevisionVerificationReceiptV1 {
    TenantRootCutoverRevisionVerificationReceiptV1::new(
        attempt_id(),
        &manifest(),
        receipt(ecdsa_seed),
        receipt(ed25519_seed),
        receipt(mixed_revision_seed),
        at_ms,
    )
    .expect("revision receipt")
}

fn activation_receipt(seed: u8, at_ms: u64) -> TenantRootCutoverProfileActivationReceiptV1 {
    TenantRootCutoverProfileActivationReceiptV1::new(attempt_id(), receipt(seed), at_ms)
        .expect("activation receipt")
}

fn rollback_receipt(seed: u8, at_ms: u64) -> TenantRootCutoverRollbackReceiptV1 {
    TenantRootCutoverRollbackReceiptV1::new(attempt_id(), receipt(seed), at_ms)
        .expect("rollback receipt")
}

fn unfence_receipt(seed: u8, at_ms: u64) -> TenantRootCutoverUnfenceReceiptV1 {
    TenantRootCutoverUnfenceReceiptV1::new(attempt_id(), receipt(seed), at_ms)
        .expect("unfence receipt")
}

fn open() -> TenantRootCutoverOpenV1 {
    TenantRootCutoverOpenV1::new(attempt_id(), prerequisites())
}

#[test]
fn successful_cutover_is_exact_and_monotonic() {
    let open = open();
    let open_state = TenantRootCutoverStateV1::from(open.clone());
    assert_eq!(open_state.revision(), 0);
    assert_eq!(
        open_state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::CloseFence
    );
    let fenced = open.fence(fence_receipt(4, 100)).expect("fenced");
    let fenced_state = TenantRootCutoverStateV1::from(fenced.clone());
    assert_eq!(fenced_state.revision(), 1);
    assert_eq!(
        fenced_state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::ResumeDrainOrRollback
    );
    let drained = fenced.drain(drain_receipt(5, 6, 200)).expect("drained");
    let drained_state = TenantRootCutoverStateV1::from(drained.clone());
    assert_eq!(drained_state.revision(), 2);
    assert_eq!(
        drained_state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::ResumeRevisionVerificationOrRollback
    );
    let verified = drained
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .expect("verified");
    let verified_state = TenantRootCutoverStateV1::from(verified.clone());
    assert_eq!(verified_state.revision(), 3);
    assert_eq!(
        verified_state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::ResumeProfileActivationOrRollback
    );
    let activated = verified
        .activate_profile(activation_receipt(10, 400))
        .expect("activated");
    let activated_state = TenantRootCutoverStateV1::from(activated.clone());
    assert_eq!(activated_state.revision(), 4);
    assert_eq!(
        activated_state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::ResumeFirstDerivationOrRollback
    );
    let committed = activated
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                500,
            )
            .expect("ECDSA canary"),
        )
        .expect("committed");
    let committed_state = TenantRootCutoverStateV1::from(committed.clone());
    assert_eq!(committed_state.revision(), 5);
    assert_eq!(
        committed_state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::ResumeForwardOnlyOtherCurve
    );
    let ready = committed
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(12),
                600,
            )
            .expect("Ed25519 canary"),
        )
        .expect("ready");
    let ready_state = TenantRootCutoverStateV1::from(ready.clone());
    assert_eq!(ready_state.revision(), 6);
    assert_eq!(
        ready_state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::ResumeUnfence
    );
    let complete = ready.unfence(unfence_receipt(13, 700)).expect("complete");
    let state = TenantRootCutoverStateV1::from(complete);
    assert_eq!(state.revision(), 7);
    assert_eq!(
        state.recovery_action(),
        TenantRootCutoverRecoveryActionV1::Complete
    );
    assert_eq!(
        serde_json::to_value(state).expect("json")["kind"],
        "complete"
    );
}

#[test]
fn rollback_is_available_only_before_first_profile_derivation() {
    let fenced = open().fence(fence_receipt(4, 100)).expect("fenced");
    let rolled_back = fenced
        .rollback(rollback_receipt(20, 200))
        .expect("rollback");
    let rolled_back = TenantRootCutoverStateV1::from(rolled_back);
    assert_eq!(rolled_back.revision(), 9);
    assert_eq!(
        rolled_back.recovery_action(),
        TenantRootCutoverRecoveryActionV1::StartFreshAttempt
    );

    let drained = open()
        .fence(fence_receipt(4, 100))
        .expect("fenced")
        .drain(drain_receipt(5, 6, 200))
        .expect("drained");
    let verified = drained
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .expect("verified");
    let activated = verified
        .activate_profile(activation_receipt(10, 400))
        .expect("activated");
    let rolled_back = activated
        .rollback(rollback_receipt(20, 500))
        .expect("rollback");
    assert_eq!(rolled_back.attempt_id(), attempt_id());
    assert_eq!(TenantRootCutoverStateV1::from(rolled_back).revision(), 12);

    let committed = open()
        .fence(fence_receipt(4, 100))
        .expect("fenced")
        .drain(drain_receipt(5, 6, 200))
        .expect("drained")
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .expect("verified")
        .activate_profile(activation_receipt(10, 400))
        .expect("activated")
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                500,
            )
            .expect("canary"),
        )
        .expect("committed");
    let committed = TenantRootCutoverStateV1::from(committed);
    assert_eq!(committed.revision(), 5);
    assert_eq!(
        committed.recovery_action(),
        TenantRootCutoverRecoveryActionV1::ResumeForwardOnlyOtherCurve
    );
}

#[test]
fn duplicate_receipts_curve_reuse_and_time_replay_fail_closed() {
    assert!(TenantRootCutoverPrerequisitesV1::new(
        receipt(1),
        receipt(1),
        receipt(3),
        PHASE0_SELECTION_RECORD
    )
    .is_err());
    assert!(
        TenantRootCutoverDrainReceiptV1::new(attempt_id(), receipt(5), receipt(5), 200).is_err()
    );

    let activated = open()
        .fence(fence_receipt(4, 100))
        .expect("fenced")
        .drain(drain_receipt(5, 6, 200))
        .expect("drained")
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .expect("verified")
        .activate_profile(activation_receipt(10, 400))
        .expect("activated");
    assert!(activated
        .clone()
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(7),
                500,
            )
            .expect("replayed pre-activation canary"),
        )
        .is_err());
    let committed = activated
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                500,
            )
            .expect("canary"),
        )
        .expect("committed");
    assert!(committed
        .clone()
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(8),
                600,
            )
            .expect("replayed pre-activation canary"),
        )
        .is_err());
    assert!(committed
        .clone()
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(11),
                600,
            )
            .expect("repeated canary receipt"),
        )
        .is_err());
    assert!(committed
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(12),
                600,
            )
            .expect("canary"),
        )
        .is_err());

    assert!(TenantRootCutoverFenceReceiptV1::new(attempt_id(), receipt(4), 0).is_err());
    assert!(TenantRootCutoverFenceReceiptV1::new(attempt_id(), receipt(4), u64::MAX).is_err());
    assert!(TenantRootCutoverAttemptIdV1::from_bytes([0; 16]).is_err());
}

#[test]
fn cross_attempt_receipts_fail_closed_at_every_stage() {
    let other_attempt = attempt(0x56);
    assert!(open()
        .fence(
            TenantRootCutoverFenceReceiptV1::new(other_attempt, receipt(4), 100)
                .expect("other-attempt fence"),
        )
        .is_err());

    let fenced = open().fence(fence_receipt(4, 100)).expect("fenced");
    assert!(fenced
        .clone()
        .drain(
            TenantRootCutoverDrainReceiptV1::new(other_attempt, receipt(5), receipt(6), 200,)
                .expect("other-attempt drain"),
        )
        .is_err());
    assert!(fenced
        .clone()
        .rollback(
            TenantRootCutoverRollbackReceiptV1::new(other_attempt, receipt(20), 200)
                .expect("other-attempt rollback"),
        )
        .is_err());

    let drained = fenced.drain(drain_receipt(5, 6, 200)).expect("drained");
    assert!(drained
        .clone()
        .verify_revisions(
            TenantRootCutoverRevisionVerificationReceiptV1::new(
                other_attempt,
                &manifest(),
                receipt(7),
                receipt(8),
                receipt(9),
                300,
            )
            .expect("other-attempt revision receipt"),
        )
        .is_err());

    let verified = drained
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .expect("verified");
    assert!(verified
        .clone()
        .activate_profile(
            TenantRootCutoverProfileActivationReceiptV1::new(other_attempt, receipt(10), 400,)
                .expect("other-attempt activation"),
        )
        .is_err());

    let activated = verified
        .activate_profile(activation_receipt(10, 400))
        .expect("activated");
    assert!(activated
        .clone()
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                other_attempt,
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                500,
            )
            .expect("other-attempt first canary"),
        )
        .is_err());

    let committed = activated
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                500,
            )
            .expect("first canary"),
        )
        .expect("committed");
    assert!(committed
        .clone()
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                other_attempt,
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(12),
                600,
            )
            .expect("other-attempt second canary"),
        )
        .is_err());

    let ready = committed
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(12),
                600,
            )
            .expect("second canary"),
        )
        .expect("ready");
    assert!(ready
        .unfence(
            TenantRootCutoverUnfenceReceiptV1::new(other_attempt, receipt(13), 700)
                .expect("other-attempt unfence"),
        )
        .is_err());
}

#[test]
fn revision_verification_binds_the_fenced_phase0_selection_record() {
    // Matching record digests: the fenced approval names the deployed manifest.
    assert!(TenantRootCutoverOpenV1::new(attempt_id(), prerequisites())
        .fence(fence_receipt(4, 100))
        .expect("fenced")
        .drain(drain_receipt(5, 6, 200))
        .expect("drained")
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .is_ok());

    // A different Phase 0 record is rejected even though the attempt id and every
    // timestamp are otherwise valid and monotonic.
    let mismatched = TenantRootCutoverOpenV1::new(attempt_id(), prerequisites_for([0x41; 32]))
        .fence(fence_receipt(4, 100))
        .expect("fenced")
        .drain(drain_receipt(5, 6, 200))
        .expect("drained")
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .unwrap_err();
    assert_eq!(
        mismatched.message(),
        "R120 revision manifest names another Phase 0 selection record"
    );

    // The receipt digests are never compared against the record digest: reusing the
    // signed-selection receipt bytes as a record digest still fails closed.
    assert!(
        TenantRootCutoverOpenV1::new(attempt_id(), prerequisites_for(*receipt(3).as_bytes()))
            .fence(fence_receipt(4, 100))
            .expect("fenced")
            .drain(drain_receipt(5, 6, 200))
            .expect("drained")
            .verify_revisions(revision_receipt(7, 8, 9, 300))
            .is_err()
    );
}

#[test]
fn prerequisites_reject_a_zero_phase0_selection_record() {
    assert!(
        TenantRootCutoverPrerequisitesV1::new(receipt(1), receipt(2), receipt(3), [0; 32]).is_err()
    );
}

#[test]
fn lifecycle_rejects_non_monotonic_transition_timestamps() {
    let fenced = open().fence(fence_receipt(4, 100)).expect("fenced");
    assert!(fenced.clone().drain(drain_receipt(5, 6, 100)).is_err());
    assert!(fenced.clone().drain(drain_receipt(5, 6, 99)).is_err());
    assert!(fenced.clone().rollback(rollback_receipt(20, 100)).is_err());
    assert!(fenced.clone().rollback(rollback_receipt(20, 99)).is_err());

    let drained = fenced.drain(drain_receipt(5, 6, 200)).expect("drained");
    assert!(drained
        .clone()
        .verify_revisions(revision_receipt(7, 8, 9, 200))
        .is_err());
    assert!(drained.clone().rollback(rollback_receipt(21, 200)).is_err());

    let verified = drained
        .verify_revisions(revision_receipt(7, 8, 9, 300))
        .expect("verified");
    assert!(verified
        .clone()
        .activate_profile(activation_receipt(10, 300))
        .is_err());
    assert!(verified
        .clone()
        .rollback(rollback_receipt(22, 300))
        .is_err());

    let activated = verified
        .activate_profile(activation_receipt(10, 400))
        .expect("activated");
    assert!(activated
        .clone()
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                400,
            )
            .expect("same-time first canary"),
        )
        .is_err());
    assert!(activated
        .clone()
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                399,
            )
            .expect("earlier first canary"),
        )
        .is_err());
    assert!(activated
        .clone()
        .rollback(rollback_receipt(23, 400))
        .is_err());

    let committed = activated
        .admit_first_derivation(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ecdsa,
                receipt(11),
                500,
            )
            .expect("first canary"),
        )
        .expect("committed");
    assert!(committed
        .clone()
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(12),
                500,
            )
            .expect("same-time second canary"),
        )
        .is_err());
    assert!(committed
        .clone()
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(12),
                499,
            )
            .expect("earlier second canary"),
        )
        .is_err());

    let ready = committed
        .complete_other_curve(
            TenantRootCutoverCanaryReceiptV1::new(
                attempt_id(),
                TenantRootCutoverCanaryCurveV1::Ed25519,
                receipt(12),
                600,
            )
            .expect("second canary"),
        )
        .expect("ready");
    assert!(ready.clone().unfence(unfence_receipt(13, 600)).is_err());
    assert!(ready.unfence(unfence_receipt(13, 599)).is_err());
}
