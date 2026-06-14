use router_ab_core::{
    LocalHttpPathV1, LocalServiceRoleV1, NormalSigningScopeV1, OpenedShareKind, Role,
    RouterAbProtocolErrorCode,
};
use router_ab_dev::{
    derive_committed_ed25519_hss_split_relayer_role_shares_v1,
    evaluate_committed_ed25519_hss_role_scoped_derivation_v1,
    handle_local_deriver_peer_message_json_v1, handle_local_router_setup_smoke_request_json_v1,
    handle_local_router_setup_smoke_request_v1, handle_local_signing_worker_activation_json_v1,
    local_http_service_binding_endpoint_v1, run_example_local_router_ab_hss_dev_ceremony_v1,
    run_example_local_router_ab_hss_dev_http_ceremony_v1,
    verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1,
    verify_committed_ed25519_hss_split_relayer_fixture_v1,
    verify_committed_ed25519_hss_split_relayer_fixtures_v1,
    verify_committed_ed25519_hss_split_relayer_role_shares_v1, LocalRouterSetupSmokeRequestV1,
    LOCAL_DERIVER_A_PEER_PATH_V1, LOCAL_DERIVER_A_PRIVATE_PATH_V1, LOCAL_DERIVER_B_PEER_PATH_V1,
    LOCAL_DERIVER_B_PRIVATE_PATH_V1, LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
};
use std::{fs, path::Path};

#[test]
fn dev_adapter_verifies_committed_ed25519_hss_split_relayer_fixture() {
    let report = verify_committed_ed25519_hss_split_relayer_fixture_v1("derived-gamma")
        .expect("committed split-relayer HSS fixture verifies");

    assert_eq!(report.fixture_name, "derived-gamma");
    assert_eq!(report.split_epoch, "split-epoch-1");
    assert_eq!(report.context_binding_hex.len(), 64);
    assert_eq!(report.public_key_hex.len(), 64);
    assert!(report.near_public_key.starts_with("ed25519:"));
    let near_key_bytes = bs58::decode(
        report
            .near_public_key
            .strip_prefix("ed25519:")
            .expect("near key prefix"),
    )
    .into_vec()
    .expect("near key base58 decodes");
    assert_eq!(near_key_bytes.len(), 32);
    assert_eq!(hex::encode(near_key_bytes), report.public_key_hex);
    assert_eq!(report.x_client_base_commitment_hex.len(), 64);
    assert_eq!(report.x_relayer_base_commitment_hex.len(), 64);
    assert_eq!(report.deriver_a.role, Role::SignerA);
    assert_eq!(report.deriver_b.role, Role::SignerB);
    assert_ne!(
        report.deriver_a.y_relayer_share_commitment_hex,
        report.deriver_b.y_relayer_share_commitment_hex
    );
    assert_ne!(
        report.deriver_a.tau_relayer_share_commitment_hex,
        report.deriver_b.tau_relayer_share_commitment_hex
    );
}

#[test]
fn dev_adapter_returns_recipient_scoped_hss_base_share_outputs() {
    let (deriver_a, deriver_b) =
        derive_committed_ed25519_hss_split_relayer_role_shares_v1("derived-gamma", "split-epoch-1")
            .expect("derive role-scoped shares");
    let output = evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
        "derived-gamma",
        deriver_a,
        deriver_b,
    )
    .expect("role-scoped HSS derivation evaluates");
    let client_commitment = output.client_output.commitment();
    let signing_worker_commitment = output.signing_worker_output.commitment();

    assert_eq!(output.fixture_name, "derived-gamma");
    assert_eq!(output.client_output.recipient_role(), Role::Client);
    assert_eq!(
        output.client_output.opened_share_kind(),
        OpenedShareKind::XClientBase
    );
    assert_eq!(output.signing_worker_output.recipient_role(), Role::Relayer);
    assert_eq!(
        output.signing_worker_output.opened_share_kind(),
        OpenedShareKind::XRelayerBase
    );
    assert_eq!(client_commitment.base_share_commitment_hex.len(), 64);
    assert_eq!(
        signing_worker_commitment.base_share_commitment_hex.len(),
        64
    );
    assert_ne!(
        client_commitment.base_share_commitment_hex,
        signing_worker_commitment.base_share_commitment_hex
    );
    assert!(format!("{:?}", output.client_output).contains("[redacted]"));
    assert!(format!("{output:?}").contains("[redacted]"));
    assert!(output.near_public_key.starts_with("ed25519:"));
}

#[test]
fn dev_adapter_runs_local_router_ab_ceremony_with_hss_role_scoped_outputs() {
    let result = run_example_local_router_ab_hss_dev_ceremony_v1("derived-gamma", "split-epoch-1")
        .expect("local Router/A/B ceremony and HSS parity run");

    assert_eq!(
        result.router_request.lifecycle.account_id,
        "gamma.test.near"
    );
    assert_eq!(
        result.router_request.account_public_key,
        result.hss_derivation.near_public_key
    );
    assert_eq!(
        result.hss_parity.near_public_key,
        result.hss_derivation.near_public_key
    );
    assert_eq!(
        result.hss_parity.public_key_hex,
        result.hss_derivation.public_key_hex
    );
    assert_eq!(
        result.hss_derivation.client_output.recipient_role(),
        Role::Client
    );
    assert_eq!(
        result.hss_derivation.client_output.opened_share_kind(),
        OpenedShareKind::XClientBase
    );
    assert_eq!(
        result.hss_derivation.signing_worker_output.recipient_role(),
        Role::Relayer
    );
    assert_eq!(
        result
            .hss_derivation
            .signing_worker_output
            .opened_share_kind(),
        OpenedShareKind::XRelayerBase
    );

    result
        .core_ceremony
        .router_response
        .validate()
        .expect("router proof-bundle response validates");
    result
        .core_ceremony
        .signing_worker_activation
        .validate()
        .expect("SigningWorker proof-bundle activation validates");
    let normal_scope = NormalSigningScopeV1::new(
        "sign-request-1",
        "gamma.test.near",
        "session-1",
        "relayer-a",
    )
    .expect("normal signing scope");
    result
        .core_ceremony
        .signing_worker_activation_receipt
        .active_signing_worker_state
        .validate_for_scope(&normal_scope)
        .expect("active SigningWorker state matches HSS fixture account scope");
    assert!(format!("{result:?}").contains("[redacted]"));
}

#[test]
fn dev_adapter_http_ceremony_maps_checked_paths_to_production_style_routes() {
    let result =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")
            .expect("typed HTTP ceremony runs");

    assert_eq!(
        result.deriver_a_request.path,
        LocalHttpPathV1::RouterToSignerA
    );
    assert_eq!(
        result.deriver_b_request.path,
        LocalHttpPathV1::RouterToSignerB
    );
    assert_eq!(
        result.core_http_ceremony.deriver_a_peer_request.path,
        LocalHttpPathV1::SignerAToSignerB
    );
    assert_eq!(
        result.core_http_ceremony.deriver_b_peer_request.path,
        LocalHttpPathV1::SignerBToSignerA
    );

    let router_to_a = local_http_service_binding_endpoint_v1(
        "http://127.0.0.1:8788",
        result.deriver_a_request.path,
    )
    .expect("Router to Deriver A endpoint");
    let router_to_b = local_http_service_binding_endpoint_v1(
        "http://127.0.0.1:8789",
        result.deriver_b_request.path,
    )
    .expect("Router to Deriver B endpoint");
    let a_to_b = local_http_service_binding_endpoint_v1(
        "http://127.0.0.1:8789",
        result.core_http_ceremony.deriver_a_peer_request.path,
    )
    .expect("Deriver A to Deriver B endpoint");
    let b_to_a = local_http_service_binding_endpoint_v1(
        "http://127.0.0.1:8788",
        result.core_http_ceremony.deriver_b_peer_request.path,
    )
    .expect("Deriver B to Deriver A endpoint");

    assert_eq!(router_to_a.owner, LocalServiceRoleV1::DeriverA);
    assert_eq!(router_to_a.path, LOCAL_DERIVER_A_PRIVATE_PATH_V1);
    assert_eq!(router_to_b.owner, LocalServiceRoleV1::DeriverB);
    assert_eq!(router_to_b.path, LOCAL_DERIVER_B_PRIVATE_PATH_V1);
    assert_eq!(a_to_b.owner, LocalServiceRoleV1::DeriverB);
    assert_eq!(a_to_b.path, LOCAL_DERIVER_B_PEER_PATH_V1);
    assert_eq!(b_to_a.owner, LocalServiceRoleV1::DeriverA);
    assert_eq!(b_to_a.path, LOCAL_DERIVER_A_PEER_PATH_V1);

    result
        .core_http_ceremony
        .router_response
        .validate()
        .expect("Router response validates");
    result
        .core_http_ceremony
        .signing_worker_activation
        .validate()
        .expect("SigningWorker activation validates");
}

#[test]
fn dev_adapter_setup_smoke_response_returns_only_client_facing_router_output() {
    let response = handle_local_router_setup_smoke_request_v1(
        LocalRouterSetupSmokeRequestV1::new("derived-gamma", "split-epoch-1")
            .expect("setup-smoke request"),
    )
    .expect("setup-smoke response");

    assert_eq!(response.fixture_name, "derived-gamma");
    assert_eq!(response.split_epoch, "split-epoch-1");
    assert!(response.near_public_key.starts_with("ed25519:"));
    assert_eq!(response.signing_worker_activation_digest_hex.len(), 64);
    assert_eq!(response.signing_worker_activation_status, "activated");
    response
        .router_response
        .validate()
        .expect("client-facing Router response validates");

    let json = handle_local_router_setup_smoke_request_json_v1(
        br#"{"fixture_name":"derived-gamma","split_epoch":"split-epoch-1"}"#,
    )
    .expect("setup-smoke JSON response");
    assert!(json.contains("deriver_a_client_bundle"));
    assert!(json.contains("deriver_b_client_bundle"));
    assert!(!json.contains("signing_worker_bundle"));
    assert!(!json.contains("relayer_bundle"));
    assert!(!json.contains("signing_worker_material_handle"));
}

#[test]
fn dev_adapter_deriver_peer_receipts_validate_direct_ab_messages() {
    let result =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")
            .expect("typed HTTP ceremony runs");

    let a_to_b_body = serde_json::to_vec(
        &result
            .core_http_ceremony
            .deriver_a_peer_request
            .envelope
            .message,
    )
    .expect("A to B peer JSON");
    let b_to_a_body = serde_json::to_vec(
        &result
            .core_http_ceremony
            .deriver_b_peer_request
            .envelope
            .message,
    )
    .expect("B to A peer JSON");

    let b_receipt = handle_local_deriver_peer_message_json_v1(
        LocalServiceRoleV1::DeriverB,
        LOCAL_DERIVER_B_PEER_PATH_V1,
        &a_to_b_body,
    )
    .expect("Deriver B accepts A peer message");
    let a_receipt = handle_local_deriver_peer_message_json_v1(
        LocalServiceRoleV1::DeriverA,
        LOCAL_DERIVER_A_PEER_PATH_V1,
        &b_to_a_body,
    )
    .expect("Deriver A accepts B peer message");

    let b: serde_json::Value = serde_json::from_str(&b_receipt).expect("B receipt JSON");
    let a: serde_json::Value = serde_json::from_str(&a_receipt).expect("A receipt JSON");
    assert_eq!(b["receiver_role"], "deriver_b");
    assert_eq!(b["accepted_from_role"], "signer_a");
    assert_eq!(b["peer_message_kind"], "signer_a_to_signer_b");
    assert_eq!(b["proof_bundle_count"], 2);
    assert_eq!(a["receiver_role"], "deriver_a");
    assert_eq!(a["accepted_from_role"], "signer_b");
    assert_eq!(a["peer_message_kind"], "signer_b_to_signer_a");
    assert_eq!(a["proof_bundle_count"], 2);
    assert!(!b_receipt.contains("proof_bundles"));
    assert!(!a_receipt.contains("proof_bundles"));
}

#[test]
fn dev_adapter_signing_worker_activation_accepts_only_x_relayer_base_bundles() {
    let result =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")
            .expect("typed HTTP ceremony runs");
    let activation_body = serde_json::to_vec(&result.core_http_ceremony.signing_worker_activation)
        .expect("activation JSON");

    let receipt = handle_local_signing_worker_activation_json_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
        &activation_body,
    )
    .expect("SigningWorker accepts relayer-output activation");
    let receipt_value: serde_json::Value =
        serde_json::from_str(&receipt).expect("activation receipt JSON");
    assert_eq!(receipt_value["receiver_role"], "signing_worker");
    assert_eq!(
        receipt_value["accepted_opened_share_kind"],
        "x_relayer_base"
    );
    assert_eq!(receipt_value["accepted_recipient_role"], "relayer");
    assert_eq!(receipt_value["status"], "accepted");
    assert_eq!(
        receipt_value["deriver_a_bundle_digest_hex"]
            .as_str()
            .expect("Deriver A bundle digest")
            .len(),
        64
    );
    assert!(!receipt.contains("signing_worker_material_handle"));
    assert!(!receipt.contains("x_client_base"));

    let client_bundle_activation = serde_json::json!({
        "deriver_a_signing_worker_bundle": result.core_http_ceremony.router_response.deriver_a_client_bundle,
        "deriver_b_signing_worker_bundle": result.core_http_ceremony.router_response.deriver_b_client_bundle,
    });
    let err = handle_local_signing_worker_activation_json_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
        client_bundle_activation.to_string().as_bytes(),
    )
    .expect_err("SigningWorker must reject client-output bundles");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn dev_adapter_local_route_diagnostics_stay_redacted() {
    let ceremony =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")
            .expect("typed HTTP ceremony runs");
    let router_response = handle_local_router_setup_smoke_request_json_v1(
        br#"{"fixture_name":"derived-gamma","split_epoch":"split-epoch-1"}"#,
    )
    .expect("setup-smoke response JSON");
    let peer_response = handle_local_deriver_peer_message_json_v1(
        LocalServiceRoleV1::DeriverB,
        LOCAL_DERIVER_B_PEER_PATH_V1,
        &serde_json::to_vec(
            &ceremony
                .core_http_ceremony
                .deriver_a_peer_request
                .envelope
                .message,
        )
        .expect("peer JSON"),
    )
    .expect("peer receipt JSON");
    let activation_response = handle_local_signing_worker_activation_json_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
        &serde_json::to_vec(&ceremony.core_http_ceremony.signing_worker_activation)
            .expect("activation JSON"),
    )
    .expect("activation receipt JSON");
    let joined = format!("{router_response}\n{peer_response}\n{activation_response}");

    for forbidden in [
        "proof_bundles",
        "signing_worker_material_handle",
        "local-dev-sealed-root-share",
        "root_share_wire",
        "PRIVATE",
        "SECRET",
        "y_relayer_share",
        "tau_relayer_share",
        "base_share",
    ] {
        assert!(
            !joined.contains(forbidden),
            "local route diagnostics leaked {forbidden}"
        );
    }
}

#[test]
fn dev_adapter_verifies_explicit_role_scoped_hss_relayer_shares() {
    let (deriver_a, deriver_b) =
        derive_committed_ed25519_hss_split_relayer_role_shares_v1("derived-gamma", "split-epoch-1")
            .expect("derive role-scoped shares");

    assert_eq!(deriver_a.role(), Role::SignerA);
    assert_eq!(deriver_b.role(), Role::SignerB);
    assert_eq!(deriver_a.split_epoch(), "split-epoch-1");
    assert_eq!(deriver_b.split_epoch(), "split-epoch-1");
    assert!(format!("{deriver_a:?}").contains("[redacted]"));

    let report = verify_committed_ed25519_hss_split_relayer_role_shares_v1(
        "derived-gamma",
        deriver_a,
        deriver_b,
    )
    .expect("explicit role-scoped shares verify");

    assert_eq!(report.fixture_name, "derived-gamma");
    assert!(report.near_public_key.starts_with("ed25519:"));
}

#[test]
fn dev_adapter_hss_role_share_type_stays_redacted_and_non_serializable() {
    let source = read_dev_src("lib.rs");
    let share_block = extract_struct_block(&source, "LocalEd25519HssRelayerInputShareV1");

    assert!(share_block.contains("role: Role"));
    assert!(share_block.contains("split_epoch: String"));
    assert!(share_block.contains("y_relayer_share: [u8; 32]"));
    assert!(share_block.contains("tau_relayer_share: [u8; 32]"));
    assert!(!share_block.contains("pub y_relayer_share"));
    assert!(!share_block.contains("pub tau_relayer_share"));
    assert!(!share_block.contains("Serialize"));
    assert!(!share_block.contains("Deserialize"));
    assert!(source.contains("impl fmt::Debug for LocalEd25519HssRelayerInputShareV1"));
    assert!(source.contains(".field(\"y_relayer_share\", &\"[redacted]\")"));
    assert!(source.contains(".field(\"tau_relayer_share\", &\"[redacted]\")"));
}

#[test]
fn dev_adapter_rejects_mixed_split_epoch_hss_relayer_shares() {
    let (deriver_a, _) =
        derive_committed_ed25519_hss_split_relayer_role_shares_v1("derived-gamma", "split-epoch-1")
            .expect("derive first epoch shares");
    let (_, deriver_b) =
        derive_committed_ed25519_hss_split_relayer_role_shares_v1("derived-gamma", "split-epoch-2")
            .expect("derive second epoch shares");
    let err = verify_committed_ed25519_hss_split_relayer_role_shares_v1(
        "derived-gamma",
        deriver_a,
        deriver_b,
    )
    .expect_err("mixed split epochs must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn dev_adapter_refreshes_split_relayer_shares_without_changing_wallet_identity() {
    let before = verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1(
        "derived-gamma",
        "split-epoch-1",
    )
    .expect("first split epoch verifies");
    let after = verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1(
        "derived-gamma",
        "split-epoch-2",
    )
    .expect("second split epoch verifies");

    assert_eq!(before.fixture_name, after.fixture_name);
    assert_eq!(before.context_binding_hex, after.context_binding_hex);
    assert_eq!(before.public_key_hex, after.public_key_hex);
    assert_eq!(before.near_public_key, after.near_public_key);
    assert_ne!(
        before.deriver_a.y_relayer_share_commitment_hex,
        after.deriver_a.y_relayer_share_commitment_hex
    );
    assert_ne!(
        before.deriver_a.tau_relayer_share_commitment_hex,
        after.deriver_a.tau_relayer_share_commitment_hex
    );
    assert_ne!(
        before.deriver_b.y_relayer_share_commitment_hex,
        after.deriver_b.y_relayer_share_commitment_hex
    );
    assert_ne!(
        before.deriver_b.tau_relayer_share_commitment_hex,
        after.deriver_b.tau_relayer_share_commitment_hex
    );
}

#[test]
fn dev_adapter_verifies_all_committed_ed25519_hss_split_relayer_fixtures() {
    let reports = verify_committed_ed25519_hss_split_relayer_fixtures_v1()
        .expect("committed split-relayer HSS fixture corpus verifies");

    assert!(reports.len() >= 3);
    assert!(reports
        .iter()
        .any(|report| report.fixture_name == "derived-gamma"));
}

#[test]
fn dev_adapter_rejects_unknown_ed25519_hss_fixture() {
    let err = verify_committed_ed25519_hss_split_relayer_fixture_v1("missing-fixture")
        .expect_err("unknown fixture must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

fn read_dev_src(file_name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(file_name);
    fs::read_to_string(path).expect("dev source file should read")
}

fn extract_struct_block(source: &str, struct_name: &str) -> String {
    let marker = format!("pub struct {struct_name}");
    let start = source.find(&marker).expect("struct marker should exist");
    let before = source[..start].rfind("#[").unwrap_or(start);
    let after = source[start..]
        .find("}")
        .map(|offset| start + offset + 1)
        .expect("struct block should end");
    source[before..after].to_owned()
}
