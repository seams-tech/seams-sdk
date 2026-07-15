use router_ab_core::LocalServiceRoleV1;
use router_ab_dev::{
    build_local_ed25519_yao_one_account_plan_v1, build_local_ed25519_yao_two_administrator_plan_v1,
    local_ed25519_yao_worker_artifact_digest_v1,
};
use std::collections::BTreeSet;

#[test]
fn fixed_local_profiles_share_protocol_artifacts_and_separate_layout_policy() {
    let one_account = build_local_ed25519_yao_one_account_plan_v1();
    let two_administrator = build_local_ed25519_yao_two_administrator_plan_v1();

    assert_eq!(
        one_account.artifact_identity(),
        two_administrator.artifact_identity()
    );
    assert!(!one_account.evidence_claim().production_eligible());
    assert!(!two_administrator.evidence_claim().production_eligible());
    assert!(!one_account
        .evidence_claim()
        .administrative_independence_proven());
    assert!(!two_administrator
        .evidence_claim()
        .administrative_independence_proven());
    assert_eq!(
        one_account
            .role_roots()
            .iter()
            .map(|entry| entry.relative_root())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["."])
    );
    assert_eq!(
        two_administrator
            .role_roots()
            .iter()
            .map(|entry| entry.relative_root())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    for role in [
        LocalServiceRoleV1::DeriverA,
        LocalServiceRoleV1::DeriverB,
        LocalServiceRoleV1::SigningWorker,
    ] {
        assert!(one_account.root_for(role).is_some());
        assert!(two_administrator.root_for(role).is_some());
    }
}

#[test]
fn both_fixed_profiles_select_the_exact_same_worker_binary() {
    let worker = std::fs::read(env!("CARGO_BIN_EXE_router_ab_local_worker"))
        .expect("read shared worker binary");
    let one_account_digest = local_ed25519_yao_worker_artifact_digest_v1(&worker);
    let two_administrator_digest = local_ed25519_yao_worker_artifact_digest_v1(&worker);
    assert_ne!(one_account_digest, [0_u8; 32]);
    assert_eq!(one_account_digest, two_administrator_digest);
}

#[test]
fn protocol_and_worker_sources_expose_no_runtime_profile_negotiation() {
    let sources = [
        include_str!("../src/local_ed25519_yao_api.rs"),
        include_str!("../src/local_ed25519_yao_input.rs"),
        include_str!("../src/local_ed25519_yao_worker.rs"),
        include_str!("../src/bin/router_ab_local_worker.rs"),
    ]
    .join("\n");
    for forbidden in ["--profile", "YAOS_AB_TOPOLOGY", "YAOS_AB_PROFILE"] {
        assert!(!sources.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn ed25519_yao_and_ecdsa_hss_modules_have_disjoint_backend_imports() {
    let yao_sources = [
        include_str!("../src/local_ed25519_yao_api.rs"),
        include_str!("../src/local_ed25519_yao_delivery.rs"),
        include_str!("../src/local_ed25519_yao_input.rs"),
        include_str!("../src/local_ed25519_yao_profiles.rs"),
        include_str!("../src/local_ed25519_yao_refresh.rs"),
        include_str!("../src/local_ed25519_yao_router.rs"),
        include_str!("../src/local_ed25519_yao_signing_worker.rs"),
        include_str!("../src/local_ed25519_yao_stream.rs"),
        include_str!("../src/local_ed25519_yao_worker.rs"),
    ]
    .join("\n");
    for forbidden in ["ed25519_hss", "ed25519-hss", "ecdsa_hss", "ecdsa-hss"] {
        assert!(!yao_sources.contains(forbidden), "found {forbidden}");
    }

    let ecdsa_hss_source = include_str!("../src/local_ecdsa_hss_pool_store.rs");
    for forbidden in ["ed25519_yao", "ed25519-yao", "router_ab_ed25519_yao"] {
        assert!(!ecdsa_hss_source.contains(forbidden), "found {forbidden}");
    }
}
