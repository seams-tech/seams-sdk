use router_ab_core::{
    ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1, ExpensiveWorkKindV1,
    GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1, RegistrationPrepareHandleV1,
    RouterAbProtocolErrorCode,
};
use router_ab_core::{PublicDigest32, RequestKind};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

#[test]
fn work_kind_maps_to_router_ab_request_kind() {
    assert_eq!(
        ExpensiveWorkKindV1::RegistrationPrepare.primitive_request_kind(),
        RequestKind::Registration
    );
    assert_eq!(
        ExpensiveWorkKindV1::KeyExport.primitive_request_kind(),
        RequestKind::Export
    );
    assert_eq!(
        ExpensiveWorkKindV1::Recovery.primitive_request_kind(),
        RequestKind::Recovery
    );
    assert_eq!(
        ExpensiveWorkKindV1::ServerShareRefresh.primitive_request_kind(),
        RequestKind::Refresh
    );
}

#[test]
fn gate_context_requires_server_derived_boundary_fields() {
    let principal =
        GatePrincipalV1::authenticated_session("user-1", "session-1").expect("principal");

    let context = ExpensiveWorkGateContextV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
        "org-1",
        "project-1",
        "local",
        "wallet-1",
        principal,
        digest(0x01),
    )
    .expect("gate context");

    assert_eq!(context.work_kind, ExpensiveWorkKindV1::RegistrationPrepare);
    assert_eq!(context.resource_id, "wallet-1");
}

#[test]
fn gate_context_rejects_empty_resource_id() {
    let principal = GatePrincipalV1::pre_auth_session("pre-auth-1").expect("principal");
    let err = ExpensiveWorkGateContextV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
        "org-1",
        "project-1",
        "local",
        "",
        principal,
        digest(0x01),
    )
    .expect_err("empty resource id must be rejected");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn gate_principal_rejects_empty_branch_identity() {
    let err = GatePrincipalV1::authenticated_session("user-1", "")
        .expect_err("empty session id must be rejected");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn gate_decisions_validate_branch_specific_fields() {
    let accepted = ExpensiveWorkGateDecisionV1::accepted("request-1").expect("accepted");
    assert!(matches!(
        accepted,
        ExpensiveWorkGateDecisionV1::Accepted { .. }
    ));

    let reuse =
        ExpensiveWorkGateDecisionV1::reuse_existing("request-2", "lifecycle-1").expect("reuse");
    assert!(matches!(
        reuse,
        ExpensiveWorkGateDecisionV1::ReuseExisting { .. }
    ));

    let defer = ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::SignerQueueSaturated);
    assert!(matches!(defer, ExpensiveWorkGateDecisionV1::Defer { .. }));

    let rejected = ExpensiveWorkGateDecisionV1::rejected(GateRejectReasonV1::RateLimited, 1000)
        .expect("rejected");
    assert!(matches!(
        rejected,
        ExpensiveWorkGateDecisionV1::Rejected { .. }
    ));
}

#[test]
fn gate_decision_rejects_invalid_branch_data() {
    let err =
        ExpensiveWorkGateDecisionV1::accepted("").expect_err("empty request id must be rejected");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);

    let err = ExpensiveWorkGateDecisionV1::rejected(GateRejectReasonV1::AbusePolicy, 0)
        .expect_err("zero retry-after must be rejected");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn registration_prepare_handle_binds_scope_and_expiry() {
    let handle = RegistrationPrepareHandleV1::new(
        "prepare-1",
        "email_otp",
        "wallet-1",
        "example.com",
        "router_ab_v1",
        digest(0x10),
        digest(0x11),
        digest(0x12),
        1000,
        6000,
    )
    .expect("prepare handle");

    assert_eq!(handle.handle_id, "prepare-1");
    assert_eq!(handle.expires_at_ms, 6000);
}

#[test]
fn registration_prepare_handle_rejects_expired_range() {
    let err = RegistrationPrepareHandleV1::new(
        "prepare-1",
        "email_otp",
        "wallet-1",
        "example.com",
        "router_ab_v1",
        digest(0x10),
        digest(0x11),
        digest(0x12),
        6000,
        6000,
    )
    .expect_err("expired handle must be rejected");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidTimeRange);
}
