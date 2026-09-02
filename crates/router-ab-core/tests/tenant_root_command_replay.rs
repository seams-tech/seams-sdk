use router_ab_core::{
    reserve_tenant_root_command_v1, RouterAbDerivationErrorCode, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCommandOperationV1, TenantRootCommandReplayDecisionV1,
    TenantRootCommandReplayKeyV1, TenantRootCommandReplayRecordV1, TenantRootCommandScopeV1,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootProtocolDigestV1,
    TenantRootShareEpoch,
};
use threshold_prf::TwoPartyDeriverRole;

fn key(nonce: u8) -> TenantRootCommandReplayKeyV1 {
    key_with(0x11, 0x22, 0x33, nonce, TwoPartyDeriverRole::DeriverA)
}

fn key_with(
    identity: u8,
    lineage: u8,
    session: u8,
    nonce: u8,
    role: TwoPartyDeriverRole,
) -> TenantRootCommandReplayKeyV1 {
    TenantRootCommandReplayKeyV1::new(
        TenantRootIdentityDigestV1::from_bytes([identity; 32]),
        TenantRootCustodyLineageId::from_bytes([lineage; 16]).unwrap(),
        TenantRootCeremonySessionIdV1::from_bytes([session; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([nonce; 32]).unwrap(),
        role,
    )
}

fn scope(
    key: TenantRootCommandReplayKeyV1,
    epoch: u64,
    expected_control_plane_revision: u64,
) -> TenantRootCommandScopeV1 {
    TenantRootCommandScopeV1::new(
        key,
        TenantRootShareEpoch::new(epoch).unwrap(),
        expected_control_plane_revision,
    )
    .expect("valid command scope")
}

fn digest(marker: u8) -> TenantRootProtocolDigestV1 {
    TenantRootProtocolDigestV1::from_bytes([marker; 32]).expect("non-zero protocol digest")
}

fn reservation() -> router_ab_core::ReservedTenantRootCommandV1 {
    let TenantRootCommandReplayDecisionV1::Execute(reserved) =
        reserve_tenant_root_command_v1(None, key(0x44), digest(0x55), 10).unwrap()
    else {
        panic!("fresh command must execute");
    };
    reserved
}

#[test]
fn command_scope_requires_a_positive_control_plane_revision() {
    assert!(
        TenantRootCommandScopeV1::new(key(0x44), TenantRootShareEpoch::new(1).unwrap(), 0,)
            .is_err()
    );
    let scope = scope(key(0x44), 1, 1);
    assert_eq!(scope.key(), &key(0x44));
    assert_eq!(scope.epoch(), TenantRootShareEpoch::new(1).unwrap());
    assert_eq!(scope.expected_control_plane_revision(), 1);
}

#[test]
fn role_command_digest_has_a_frozen_vector() {
    let scope = scope(key(0x44), 1, 1);
    let operation = TenantRootCommandOperationV1::insert_pending(digest(0x66));
    assert_eq!(
        hex::encode(scope.command_digest(operation).unwrap().as_bytes()),
        "02842b98a156f0d9910b6bec0e396587d0b676ca97ce5615db148dddfcdadbca",
    );
}

#[test]
fn role_command_digest_changes_for_every_authenticated_field() {
    let base_scope = scope(key(0x44), 1, 1);
    let base_operation = TenantRootCommandOperationV1::insert_pending(digest(0x66));
    let base_digest = base_scope.command_digest(base_operation).unwrap();
    let substitutions = [
        (
            "operation",
            base_scope,
            TenantRootCommandOperationV1::activate_initial(digest(0x66)),
        ),
        (
            "identity",
            scope(
                key_with(0x12, 0x22, 0x33, 0x44, TwoPartyDeriverRole::DeriverA),
                1,
                1,
            ),
            base_operation,
        ),
        (
            "lineage",
            scope(
                key_with(0x11, 0x23, 0x33, 0x44, TwoPartyDeriverRole::DeriverA),
                1,
                1,
            ),
            base_operation,
        ),
        (
            "role",
            scope(
                key_with(0x11, 0x22, 0x33, 0x44, TwoPartyDeriverRole::DeriverB),
                1,
                1,
            ),
            base_operation,
        ),
        ("epoch", scope(key(0x44), 2, 1), base_operation),
        ("expected revision", scope(key(0x44), 1, 2), base_operation),
        (
            "session",
            scope(
                key_with(0x11, 0x22, 0x34, 0x44, TwoPartyDeriverRole::DeriverA),
                1,
                1,
            ),
            base_operation,
        ),
        (
            "nonce",
            scope(
                key_with(0x11, 0x22, 0x33, 0x45, TwoPartyDeriverRole::DeriverA),
                1,
                1,
            ),
            base_operation,
        ),
        (
            "operation payload",
            base_scope,
            TenantRootCommandOperationV1::insert_pending(digest(0x67)),
        ),
    ];

    for (field, candidate_scope, candidate_operation) in substitutions {
        let candidate_digest = candidate_scope.command_digest(candidate_operation).unwrap();
        assert_ne!(
            base_digest, candidate_digest,
            "{field} substitution must change the role command digest"
        );
    }
}

#[test]
fn exact_retry_is_in_progress_then_replays_the_terminal_receipt() {
    let record = TenantRootCommandReplayRecordV1::Reserved(reservation());
    assert_eq!(
        reserve_tenant_root_command_v1(Some(&record), key(0x44), digest(0x55), 11).unwrap(),
        TenantRootCommandReplayDecisionV1::InProgress
    );

    let completed = reservation()
        .checkpoint_executed(11)
        .unwrap()
        .complete(digest(0x66), 12)
        .unwrap();
    assert_eq!(
        reserve_tenant_root_command_v1(Some(&completed), key(0x44), digest(0x55), 13).unwrap(),
        TenantRootCommandReplayDecisionV1::ReplayCompleted {
            receipt_digest: digest(0x66)
        }
    );
}

#[test]
fn reserved_checkpoint_can_only_complete_after_execution() {
    let executed = reservation().checkpoint_executed(11).unwrap();
    assert_eq!(executed.key(), &key(0x44));
    assert_eq!(executed.command_digest(), digest(0x55));
    assert_eq!(executed.reserved_at_ms(), 10);
    assert_eq!(executed.executed_at_ms(), 11);

    let completed = executed.complete(digest(0x66), 12).unwrap();
    assert!(matches!(
        completed,
        TenantRootCommandReplayRecordV1::Completed(_)
    ));
}

#[test]
fn executed_checkpoint_is_in_progress_and_cannot_fail() {
    let executed = reservation().checkpoint_executed(11).unwrap();
    let record = TenantRootCommandReplayRecordV1::Executed(executed);

    assert_eq!(
        reserve_tenant_root_command_v1(Some(&record), key(0x44), digest(0x55), 12).unwrap(),
        TenantRootCommandReplayDecisionV1::InProgress
    );
    assert_eq!(
        reserve_tenant_root_command_v1(Some(&record), key(0x44), digest(0x56), 12)
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
    assert_eq!(
        reserve_tenant_root_command_v1(Some(&record), key(0x45), digest(0x55), 12)
            .unwrap_err()
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn reused_session_rejects_nonce_payload_and_role_substitution() {
    let record = TenantRootCommandReplayRecordV1::Reserved(reservation());
    let nonce_error =
        reserve_tenant_root_command_v1(Some(&record), key(0x45), digest(0x55), 11).unwrap_err();
    assert_eq!(
        nonce_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let payload_error =
        reserve_tenant_root_command_v1(Some(&record), key(0x44), digest(0x56), 11).unwrap_err();
    assert_eq!(
        payload_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let other_role = TenantRootCommandReplayKeyV1::new(
        TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
        TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).unwrap(),
        TwoPartyDeriverRole::DeriverB,
    );
    let role_error =
        reserve_tenant_root_command_v1(Some(&record), other_role, digest(0x55), 11).unwrap_err();
    assert_eq!(
        role_error.code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn failed_command_consumes_the_session_and_replays_its_failure_receipt() {
    let failed = reservation().fail(digest(0x77), 12).unwrap();
    assert_eq!(
        reserve_tenant_root_command_v1(Some(&failed), key(0x44), digest(0x55), 13).unwrap(),
        TenantRootCommandReplayDecisionV1::ReplayFailed {
            failure_receipt_digest: digest(0x77)
        }
    );
}

#[test]
fn timestamps_and_storage_key_are_strict_and_stable() {
    assert!(reserve_tenant_root_command_v1(None, key(0x44), digest(0x55), 0).is_err());
    assert!(reservation().checkpoint_executed(9).is_err());
    assert!(reservation().fail(digest(0x77), 9).is_err());
    let executed = reservation().checkpoint_executed(11).unwrap();
    assert!(executed.complete(digest(0x66), 10).is_err());
    assert_eq!(
        key(0x44).storage_key_digest().expect("storage key digest"),
        key(0x45).storage_key_digest().expect("storage key digest")
    );
    assert_eq!(
        hex::encode(
            key(0x44)
                .storage_key_digest()
                .expect("storage key digest")
                .as_bytes()
        ),
        "933a0980c47235dbb05eccd1d5f9974180c7de313bb6b71898f685b1f67c9037"
    );
    assert_ne!(
        key(0x44).storage_key_digest().expect("storage key digest"),
        TenantRootCommandReplayKeyV1::new(
            TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
            TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).unwrap(),
            TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).unwrap(),
            TwoPartyDeriverRole::DeriverB,
        )
        .storage_key_digest()
        .expect("storage key digest")
    );
}
