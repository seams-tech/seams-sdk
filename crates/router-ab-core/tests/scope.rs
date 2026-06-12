use router_ab_core::{AccountScope, RefreshScope, RootShareEpoch, RouterAbDerivationErrorCode};

fn account_scope() -> AccountScope {
    AccountScope::new(
        "near-testnet",
        "alice.testnet",
        "ed25519:11111111111111111111111111111111",
    )
    .expect("account scope")
}

#[test]
fn refresh_scope_rejects_same_old_and_new_epoch() {
    let err = RefreshScope {
        old_root_share_epoch: RootShareEpoch::new("epoch-1").expect("old epoch"),
        new_root_share_epoch: RootShareEpoch::new("epoch-1").expect("new epoch"),
        refresh_id: "refresh-1".to_owned(),
        account_scope: account_scope(),
        old_signer_set_id: "signer-set-old".to_owned(),
        new_signer_set_id: "signer-set-new".to_owned(),
        expected_router_id: "role:router:local:sha256-r".to_owned(),
        expected_client_id: "role:client:local:sha256-c".to_owned(),
        expected_relayer_id: "role:relayer:local:sha256-relayer".to_owned(),
        address_verification_requirement: "required".to_owned(),
    }
    .validate()
    .expect_err("same old and new epoch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RootEpochMismatch);
}

#[test]
fn refresh_scope_accepts_distinct_old_and_new_epochs() {
    RefreshScope {
        old_root_share_epoch: RootShareEpoch::new("epoch-1").expect("old epoch"),
        new_root_share_epoch: RootShareEpoch::new("epoch-2").expect("new epoch"),
        refresh_id: "refresh-1".to_owned(),
        account_scope: account_scope(),
        old_signer_set_id: "signer-set-old".to_owned(),
        new_signer_set_id: "signer-set-new".to_owned(),
        expected_router_id: "role:router:local:sha256-r".to_owned(),
        expected_client_id: "role:client:local:sha256-c".to_owned(),
        expected_relayer_id: "role:relayer:local:sha256-relayer".to_owned(),
        address_verification_requirement: "required".to_owned(),
    }
    .validate()
    .expect("distinct old and new epochs should pass");
}
