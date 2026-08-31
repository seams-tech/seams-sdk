use router_ab_core::{
    reserve_tenant_root_command_v1, RouterAbDerivationErrorCode, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCommandReplayDecisionV1, TenantRootCommandReplayKeyV1,
    TenantRootCommandReplayRecordV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootProtocolDigestV1,
};
use threshold_prf::TwoPartyDeriverRole;

fn key(nonce: u8) -> TenantRootCommandReplayKeyV1 {
    TenantRootCommandReplayKeyV1::new(
        TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
        TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([nonce; 32]).unwrap(),
        TwoPartyDeriverRole::DeriverA,
    )
}

fn digest(marker: u8) -> TenantRootProtocolDigestV1 {
    TenantRootProtocolDigestV1::from_bytes([marker; 32])
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
fn exact_retry_is_in_progress_then_replays_the_terminal_receipt() {
    let reserved = reservation();
    let record = TenantRootCommandReplayRecordV1::Reserved(reserved);
    assert_eq!(
        reserve_tenant_root_command_v1(Some(&record), key(0x44), digest(0x55), 11).unwrap(),
        TenantRootCommandReplayDecisionV1::InProgress
    );

    let completed = reserved.complete(digest(0x66), 12).unwrap();
    assert_eq!(
        reserve_tenant_root_command_v1(Some(&completed), key(0x44), digest(0x55), 13).unwrap(),
        TenantRootCommandReplayDecisionV1::ReplayCompleted {
            receipt_digest: digest(0x66)
        }
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
    assert!(reservation().complete(digest(0x66), 9).is_err());
    assert_eq!(
        key(0x44).storage_key_digest(),
        key(0x45).storage_key_digest()
    );
    assert_eq!(
        hex::encode(key(0x44).storage_key_digest().as_bytes()),
        "933a0980c47235dbb05eccd1d5f9974180c7de313bb6b71898f685b1f67c9037"
    );
    assert_ne!(
        key(0x44).storage_key_digest(),
        TenantRootCommandReplayKeyV1::new(
            TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).unwrap(),
            TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).unwrap(),
            TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).unwrap(),
            TwoPartyDeriverRole::DeriverB,
        )
        .storage_key_digest()
    );
}
