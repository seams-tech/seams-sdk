use router_ab_core::{
    AccountScope, DerivationContext, RequestKind, RootShareEpoch, RouterAbDerivationErrorCode,
};

#[test]
fn root_share_epoch_is_required() {
    let err = RootShareEpoch::new("").expect_err("empty epoch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::EmptyField);
}

#[test]
fn refresh_context_requires_ceremony_id() {
    let err = DerivationContext::new(
        RequestKind::Refresh,
        AccountScope::new(
            "near-testnet",
            "alice.testnet",
            "ed25519:11111111111111111111111111111111",
        )
        .expect("account scope"),
        RootShareEpoch::new("epoch-2").expect("epoch"),
        "",
    )
    .expect_err("empty ceremony id should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::EmptyField);
}
