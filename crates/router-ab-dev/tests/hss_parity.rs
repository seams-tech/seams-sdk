use router_ab_core::{NormalSigningScopeV1, OpenedShareKind, Role, RouterAbProtocolErrorCode};
use router_ab_dev::{
    derive_committed_ed25519_hss_split_relayer_role_shares_v1,
    evaluate_committed_ed25519_hss_role_scoped_derivation_v1,
    run_example_local_router_ab_hss_dev_ceremony_v1,
    verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1,
    verify_committed_ed25519_hss_split_relayer_fixture_v1,
    verify_committed_ed25519_hss_split_relayer_fixtures_v1,
    verify_committed_ed25519_hss_split_relayer_role_shares_v1,
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
