use ed25519_dalek::{Signer, SigningKey, Verifier};
use router_ab_core::{
    Ed25519YaoEpochTransitionV1, Ed25519YaoRefreshBindingV1, Ed25519YaoRefreshEpochsV1,
    Ed25519YaoSessionIdV1, Ed25519YaoStateEpochV1, LocalHttpPathV1, LocalServiceRoleV1,
    RootShareEpoch,
};
use router_ab_dev::{
    admit_local_ed25519_yao_export_v1, admit_local_ed25519_yao_registration_v1,
    build_local_ed25519_yao_one_account_plan_v1, build_local_ed25519_yao_two_administrator_plan_v1,
    generate_local_ed25519_yao_recipient_key_pair_v1, local_ed25519_yao_refresh_binding_digest_v1,
    local_env_materialization_plan_v1, open_local_ed25519_yao_client_package_v1,
    run_example_local_router_ab_dev_http_ceremony_v1,
    seal_local_ed25519_yao_activation_deriver_a_input_v1,
    seal_local_ed25519_yao_activation_deriver_b_input_v1,
    seal_local_ed25519_yao_export_deriver_a_input_v1,
    seal_local_ed25519_yao_export_deriver_b_input_v1,
    seal_local_ed25519_yao_refresh_deriver_a_input_v1,
    seal_local_ed25519_yao_refresh_deriver_b_input_v1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoPackageKindV1, LocalDeriverPeerMessageReceiptV1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoClientContributionV1,
    LocalEd25519YaoExportDeriverARequestV1, LocalEd25519YaoExportDeriverBRequestV1,
    LocalEd25519YaoExportRecipientV1, LocalEd25519YaoRecipientKeyPairV1,
    LocalEd25519YaoRecoveryCredentialBindingV1, LocalEd25519YaoRefreshActiveEpochsV1,
    LocalEd25519YaoRefreshDeriverARequestV1, LocalEd25519YaoRefreshDeriverBRequestV1,
    LocalEd25519YaoRefreshPromotionRequestV1, LocalEd25519YaoRoleCompletionV1,
    LocalEd25519YaoRouterExportAdmissionRequestV1, LocalEd25519YaoRouterRecoveryAdmissionRequestV1,
    LocalEd25519YaoRouterRecoveryStateV1, LocalEd25519YaoRouterRefreshAdmissionRequestV1,
    LocalEd25519YaoRouterRefreshStateV1, LocalEd25519YaoSigningWorkerActivationReceiptV1,
    LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    LocalEd25519YaoSigningWorkerPackagePairDeliveryV1,
    LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
    LocalEd25519YaoSigningWorkerRefreshReceiptV1, LocalHttpServiceBindingClientV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoLifecycleScopeV1,
    RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_EXPORT_START_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_EXPORT_RESULT_PATH, LOCAL_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH, LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_RESULT_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
    LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH,
};
use router_ab_ed25519_yao::recipient::client::{
    combine_client_activation_packages, combine_export_packages,
};
use router_ab_ed25519_yao::relay::{
    derive_registration_receipt, ActivationDeriverAClientPackage, ActivationDeriverBClientPackage,
    ActivationPublicCommitments, ActivationPublicReceipt, ExportDeriverAClientPackage,
    ExportDeriverBClientPackage,
};
use router_ab_ed25519_yao::{
    Ed25519YaoActivationRoleExecutionV1, Ed25519YaoExportRoleExecutionV1, Ed25519YaoRoleExecutionV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientDerivationRootV1,
    Ed25519YaoStableKeyDerivationContextV1,
};
use signer_core::near_ed25519_recovery::expand_ed25519_seed;
use signer_core::near_threshold_ed25519::verifying_share_bytes_from_signing_share_bytes;
use signer_core::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, MutexGuard, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

fn router_ab_dev_source() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("router-ab-dev source should be readable")
}

fn router_ab_dev_local_service_http_source() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/local_service_http.rs"))
        .expect("router-ab-dev local service HTTP source should be readable")
}

fn router_ab_dev_local_dev_http_source() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/local_dev_http.rs"))
        .expect("router-ab-dev local dev HTTP source should be readable")
}

fn router_ab_dev_local_router_ab_ecdsa_derivation_pool_store_source() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/local_router_ab_ecdsa_derivation_pool_store.rs"),
    )
    .expect("router-ab-dev local Router A/B ECDSA derivation pool store source should be readable")
}

fn router_ab_dev_local_worker_topology_source() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/local_worker_topology.rs"))
        .expect("router-ab-dev local worker topology source should be readable")
}

fn router_ab_dev_bin_source(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/bin")
            .join(name),
    )
    .unwrap_or_else(|error| panic!("{name} should be readable: {error}"))
}

#[test]
fn local_dev_http_request_boundary_lives_outside_monolith() {
    let lib_source = router_ab_dev_source();
    let helper_source = router_ab_dev_local_dev_http_source();
    for expected in [
        "pub struct LocalDevHttpRequestPartsV1",
        "pub fn read_local_dev_http_request_v1",
        "pub fn write_local_dev_http_response_v1",
        "pub fn local_dev_http_error_body_v1",
    ] {
        assert!(
            helper_source.contains(expected),
            "local dev HTTP module should own {expected}"
        );
        assert!(
            !lib_source.contains(expected),
            "router-ab-dev lib.rs should not own {expected}"
        );
    }
}

#[test]
fn local_dev_http_dispatch_lives_outside_monolith() {
    let lib_source = router_ab_dev_source();
    let helper_source = router_ab_dev_local_dev_http_source();
    for expected in [
        "pub enum LocalDevHttpTopologyV1",
        "pub fn local_dev_http_handle_request_v1",
        "fn local_dev_signing_worker_private_route_v1",
        "fn local_dev_protocol_response_v1",
    ] {
        assert!(
            helper_source.contains(expected),
            "local dev HTTP module should own {expected}"
        );
        assert!(
            !lib_source.contains(expected),
            "router-ab-dev lib.rs should not own {expected}"
        );
    }
}

#[test]
fn local_worker_bins_delegate_to_shared_route_dispatcher() {
    for name in ["router_ab_local_worker.rs"] {
        let source = router_ab_dev_bin_source(name);
        assert!(
            source.contains("local_dev_http_handle_request_v1"),
            "{name} should delegate requests to the shared local dev dispatcher"
        );
        for forbidden in [
            "LOCAL_ROUTER_NORMAL_SIGNING",
            "LOCAL_ROUTER_AB_ECDSA_DERIVATION",
            "LOCAL_SIGNING_WORKER_NORMAL_SIGNING",
            "LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION",
            "match request.path",
            "if request.path",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} should not carry route-dispatch logic: found {forbidden}"
            );
        }
    }
}

#[test]
fn local_signing_worker_private_http_helper_lives_outside_monolith() {
    let lib_source = router_ab_dev_source();
    let helper_source = router_ab_dev_local_service_http_source();
    for expected in [
        "pub struct LocalHttpServiceBindingClientV1",
        "pub struct LocalHttpServiceBindingEndpointV1",
        "pub fn local_http_service_binding_endpoint_v1",
    ] {
        assert!(
            helper_source.contains(expected),
            "local service HTTP module should own {expected}"
        );
        assert!(
            !lib_source.contains(expected),
            "router-ab-dev lib.rs should not own {expected}"
        );
    }
}

#[test]
fn local_worker_topology_helpers_live_outside_monolith() {
    let lib_source = router_ab_dev_source();
    let helper_source = router_ab_dev_local_worker_topology_source();
    for expected in [
        "pub struct LocalWorkerHealthResponseV1",
        "pub fn local_worker_bind_addr_v1",
        "pub fn local_worker_owned_paths_v1",
        "pub fn local_worker_health_response_v1",
    ] {
        assert!(
            helper_source.contains(expected),
            "local worker topology module should own {expected}"
        );
        assert!(
            !lib_source.contains(expected),
            "router-ab-dev lib.rs should not own {expected}"
        );
    }
}

#[test]
fn local_router_ab_ecdsa_derivation_pool_lifecycle_store_lives_outside_monolith() {
    let lib_source = router_ab_dev_source();
    let helper_source = router_ab_dev_local_router_ab_ecdsa_derivation_pool_store_source();
    for expected in [
        "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1",
        "pub(crate) fn local_signing_worker_ecdsa_pool_mutate_v1",
        "apply_cloudflare_signing_worker_ecdsa_pool_command_v1",
    ] {
        assert!(
            helper_source.contains(expected),
            "local Router A/B ECDSA derivation pool-store module should own {expected}"
        );
    }
    for helper_only in [
        "pub(crate) fn local_signing_worker_ecdsa_pool_mutate_v1",
        "apply_cloudflare_signing_worker_ecdsa_pool_command_v1",
    ] {
        assert!(
            !lib_source.contains(helper_only),
            "router-ab-dev lib.rs should not own {helper_only}"
        );
    }
    for obsolete in [
        "LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolLifecycleV1",
        "local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_put_v1",
        "local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_store_take_v1",
    ] {
        assert!(
            !lib_source.contains(obsolete) && !helper_source.contains(obsolete),
            "obsolete delete-based local ECDSA pool symbol must remain deleted: {obsolete}"
        );
    }
}

#[test]
fn local_workers_accept_direct_deriver_peer_messages_over_http(
) -> Result<(), Box<dyn std::error::Error>> {
    let _process_guard = local_worker_process_test_guard();
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let temp = temp_dir("peer-http")?;
    let deriver_a_url = format!("http://127.0.0.1:{}", free_port()?);
    let deriver_b_url = format!("http://127.0.0.1:{}", free_port()?);
    write_deriver_envs(&temp, &deriver_a_url, &deriver_b_url)?;

    let mut deriver_a = ChildGuard::spawn(
        binary,
        "deriver-a",
        temp.join(".env.router-ab.deriver-a.local"),
    )?;
    let mut deriver_b = ChildGuard::spawn(
        binary,
        "deriver-b",
        temp.join(".env.router-ab.deriver-b.local"),
    )?;
    wait_for_health(&deriver_a_url, deriver_a.child_mut())?;
    wait_for_health(&deriver_b_url, deriver_b.child_mut())?;

    let ceremony = run_example_local_router_ab_dev_http_ceremony_v1()?;
    let client = LocalHttpServiceBindingClientV1::default();

    let b_receipt: LocalDeriverPeerMessageReceiptV1 = client.post_json_v1(
        &deriver_b_url,
        LocalHttpPathV1::SignerAToSignerB,
        &ceremony
            .core_http_ceremony
            .deriver_a_peer_request
            .envelope
            .message,
    )?;
    let a_receipt: LocalDeriverPeerMessageReceiptV1 = client.post_json_v1(
        &deriver_a_url,
        LocalHttpPathV1::SignerBToSignerA,
        &ceremony
            .core_http_ceremony
            .deriver_b_peer_request
            .envelope
            .message,
    )?;

    assert_eq!(b_receipt.receiver_role, LocalServiceRoleV1::DeriverB);
    assert_eq!(b_receipt.status, "accepted");
    assert_eq!(b_receipt.proof_bundle_count, 2);
    assert_eq!(a_receipt.receiver_role, LocalServiceRoleV1::DeriverA);
    assert_eq!(a_receipt.status, "accepted");
    assert_eq!(a_receipt.proof_bundle_count, 2);
    drop(deriver_a);
    drop(deriver_b);
    let _ = fs::remove_dir_all(temp);
    Ok(())
}

#[test]
fn local_worker_rejects_public_router_role() -> Result<(), Box<dyn std::error::Error>> {
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let output = Command::new(binary).arg("--role").arg("router").output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no longer exposes a public router role"));
    Ok(())
}

#[test]
fn local_worker_survives_malformed_http_probe() -> Result<(), Box<dyn std::error::Error>> {
    let _process_guard = local_worker_process_test_guard();
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let temp = temp_dir("malformed-probe")?;
    let deriver_a_url = format!("http://127.0.0.1:{}", free_port()?);
    let deriver_b_url = format!("http://127.0.0.1:{}", free_port()?);
    write_deriver_envs(&temp, &deriver_a_url, &deriver_b_url)?;

    let mut deriver_a = ChildGuard::spawn(
        binary,
        "deriver-a",
        temp.join(".env.router-ab.deriver-a.local"),
    )?;
    wait_for_health(&deriver_a_url, deriver_a.child_mut())?;

    send_incomplete_http_probe(&deriver_a_url)?;
    thread::sleep(Duration::from_millis(100));
    assert!(
        deriver_a.child_mut().try_wait()?.is_none(),
        "malformed HTTP probe should not stop the local worker"
    );
    get_health(&deriver_a_url)?;

    drop(deriver_a);
    let _ = fs::remove_dir_all(temp);
    Ok(())
}

struct LocalActivationProcessContext<'a> {
    deriver_a_url: &'a str,
    deriver_b_url: &'a str,
    signing_worker_url: &'a str,
    request_a: &'a LocalEd25519YaoActivationDeriverARequestV1,
    request_b: &'a LocalEd25519YaoActivationDeriverBRequestV1,
    deriver_a_input_recipient: &'a LocalEd25519YaoRecipientKeyPairV1,
    deriver_b_input_recipient: &'a LocalEd25519YaoRecipientKeyPairV1,
    client_recipient: &'a LocalEd25519YaoRecipientKeyPairV1,
    mode: LocalLifecycleRunModeV1,
}

struct LocalActivationProcessOutcome {
    client_scalar: Zeroizing<[u8; 32]>,
    signing_worker_verifying_share: [u8; 32],
    public_receipt: ActivationPublicReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalLifecycleRunModeV1 {
    Validation,
    Measurement,
}

impl LocalLifecycleRunModeV1 {
    fn from_environment() -> Self {
        match std::env::var("SEAMS_YAOS_AB_LOCAL_MEASUREMENT") {
            Ok(value) if value == "1" => Self::Measurement,
            _ => Self::Validation,
        }
    }

    const fn exercises_faults(self) -> bool {
        matches!(self, Self::Validation)
    }

    const fn emits_sample(self) -> bool {
        matches!(self, Self::Measurement)
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalEd25519YaoLifecycleLatencySampleV1<'a> {
    schema: &'static str,
    profile: &'a str,
    registration_microseconds: u64,
    recovery_microseconds: u64,
    refresh_microseconds: u64,
    export_microseconds: u64,
    activation_deriver_a_to_b_bytes: u64,
    activation_deriver_b_to_a_bytes: u64,
    activation_total_ab_bytes: u64,
    export_deriver_a_to_b_bytes: u64,
    export_deriver_b_to_a_bytes: u64,
    export_total_ab_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Phase9CLocalLifecycleEvidenceV1<'a> {
    schema: &'static str,
    profile: &'a str,
    lifecycle_vectors: [&'static str; 5],
    registered_public_key_sha256: String,
    exported_public_key_sha256: String,
    export_public_key_matches_registered: bool,
    export_standard_signature_verified: bool,
    recovery_preserved_identity: bool,
    refresh_preserved_identity: bool,
}

fn write_phase9c_local_lifecycle_evidence(
    profile: &str,
    registered_public_key: &[u8; 32],
    exported_public_key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(evidence_dir) = std::env::var_os("SEAMS_YAOS_AB_PHASE9C_EVIDENCE_DIR") else {
        return Ok(());
    };
    let evidence = Phase9CLocalLifecycleEvidenceV1 {
        schema: "seams-ed25519-yao-phase9c-lifecycle-evidence-v1",
        profile,
        lifecycle_vectors: [
            "registration",
            "activation",
            "recovery",
            "refresh",
            "exact_export",
        ],
        registered_public_key_sha256: hex::encode(Sha256::digest(registered_public_key)),
        exported_public_key_sha256: hex::encode(Sha256::digest(exported_public_key)),
        export_public_key_matches_registered: true,
        export_standard_signature_verified: true,
        recovery_preserved_identity: true,
        refresh_preserved_identity: true,
    };
    let evidence_path = PathBuf::from(evidence_dir).join(format!("{profile}.json"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence_path)?;
    serde_json::to_writer_pretty(&mut file, &evidence)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn elapsed_microseconds(started: Instant) -> u64 {
    started
        .elapsed()
        .as_micros()
        .try_into()
        .expect("local lifecycle latency fits u64")
}

fn conflicting_session_id(session: [u8; 32]) -> Ed25519YaoSessionIdV1 {
    let mut conflicting = session;
    conflicting[0] ^= 1;
    if conflicting.iter().all(|byte| *byte == 0) {
        conflicting[0] = 1;
    }
    Ed25519YaoSessionIdV1::new(conflicting).expect("conflicting session")
}

fn package_with_session(
    package: &Ed25519YaoEncryptedPackageV1,
    session: [u8; 32],
) -> Ed25519YaoEncryptedPackageV1 {
    Ed25519YaoEncryptedPackageV1::new(
        package.kind(),
        package.deriver(),
        session,
        package.transcript(),
        *package.encapsulated_key(),
        package.ciphertext().to_vec(),
    )
    .expect("package with replacement session")
}

fn package_with_deriver(
    package: &Ed25519YaoEncryptedPackageV1,
    deriver: Ed25519YaoDeriverRoleV1,
) -> Ed25519YaoEncryptedPackageV1 {
    Ed25519YaoEncryptedPackageV1::new(
        package.kind(),
        deriver,
        package.session(),
        package.transcript(),
        *package.encapsulated_key(),
        package.ciphertext().to_vec(),
    )
    .expect("package with replacement Deriver")
}

fn package_with_kind(
    package: &Ed25519YaoEncryptedPackageV1,
    kind: Ed25519YaoPackageKindV1,
) -> Ed25519YaoEncryptedPackageV1 {
    Ed25519YaoEncryptedPackageV1::new(
        kind,
        package.deriver(),
        package.session(),
        package.transcript(),
        *package.encapsulated_key(),
        package.ciphertext().to_vec(),
    )
    .expect("package with replacement kind")
}

fn package_with_tampered_ciphertext(
    package: &Ed25519YaoEncryptedPackageV1,
) -> Ed25519YaoEncryptedPackageV1 {
    let mut ciphertext = package.ciphertext().to_vec();
    ciphertext[0] ^= 1;
    Ed25519YaoEncryptedPackageV1::new(
        package.kind(),
        package.deriver(),
        package.session(),
        package.transcript(),
        *package.encapsulated_key(),
        ciphertext,
    )
    .expect("structurally valid ciphertext tamper")
}

fn yao_application() -> RouterAbEd25519YaoApplicationBindingFactsV1 {
    RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-process",
        "ed25519ks_process",
        "project:local",
        1,
    )
    .expect("application binding")
}

fn yao_scope(lifecycle_id: &str, wallet_session_id: &str) -> RouterAbEd25519YaoLifecycleScopeV1 {
    RouterAbEd25519YaoLifecycleScopeV1::new(
        lifecycle_id,
        RootShareEpoch::new("epoch-1").expect("root share epoch"),
        "account-1",
        wallet_session_id,
        "signer-set-1",
        "local-signing-worker",
    )
    .expect("lifecycle scope")
}

fn yao_registration_request(
    lifecycle_id: &str,
    wallet_session_id: &str,
    application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
) -> RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
    RouterAbEd25519YaoRegistrationAdmissionRequestV1::new(
        yao_scope(lifecycle_id, wallet_session_id),
        application_binding,
        [1, 2],
    )
    .expect("registration admission request")
}

fn conflicting_activation_delivery(
    delivery: &LocalEd25519YaoSigningWorkerPackageDeliveryV1,
) -> LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
    let mut conflicting = delivery.clone();
    let session = conflicting_session_id(delivery.binding.session_id.into_bytes());
    conflicting.binding.session_id = session;
    conflicting.package = package_with_session(&delivery.package, session.into_bytes());
    conflicting
}

fn conflicting_refresh_delivery(
    delivery: &LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
) -> LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1 {
    let mut conflicting = delivery.clone();
    let mut ceremony = delivery.binding.ceremony().clone();
    let session = conflicting_session_id(ceremony.session_id.into_bytes());
    ceremony.session_id = session;
    conflicting.binding = Ed25519YaoRefreshBindingV1::new(
        ceremony,
        *delivery.binding.registered_public_key(),
        *delivery.binding.epochs(),
    )
    .expect("conflicting refresh binding");
    conflicting.package = package_with_session(&delivery.package, session.into_bytes());
    conflicting
}

fn run_local_activation_process_v1(
    context: LocalActivationProcessContext<'_>,
) -> Result<LocalActivationProcessOutcome, Box<dyn std::error::Error>> {
    let auth_headers = [(
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    )];
    let request_b_envelope = seal_local_ed25519_yao_activation_deriver_b_input_v1(
        context.request_b,
        context.deriver_b_input_recipient.public_key,
    )?;
    let request_a_envelope = seal_local_ed25519_yao_activation_deriver_a_input_v1(
        context.request_a,
        context.deriver_a_input_recipient.public_key,
    )?;
    let (stage_status, _) = post_json_to_path_with_headers(
        context.deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
        &request_b_envelope,
        &auth_headers,
    )?;
    assert_eq!(stage_status, 200);
    if context.mode.exercises_faults() {
        let result_request = serde_json::json!({
            "family": "activation",
            "session_id": context.request_b.binding.session_id.into_bytes(),
        });
        assert_eq!(
            post_json_to_path_with_headers(
                context.deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
                &result_request,
                &auth_headers,
            )?
            .0,
            400
        );
    }
    let (a_status, a_body) = post_json_to_path_with_headers(
        context.deriver_a_url,
        LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH,
        &request_a_envelope,
        &auth_headers,
    )?;
    assert_eq!(a_status, 200);
    let result_request = serde_json::json!({
        "family": "activation",
        "session_id": context.request_b.binding.session_id.into_bytes(),
    });
    let (b_status, b_body) = post_json_to_path_with_headers(
        context.deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
        &result_request,
        &auth_headers,
    )?;
    assert_eq!(b_status, 200);
    let a_execution = activation_execution_from_json(&a_body, Ed25519YaoDeriverRoleV1::DeriverA)?;
    let b_execution = activation_execution_from_json(&b_body, Ed25519YaoDeriverRoleV1::DeriverB)?;
    assert_eq!(a_execution.binding, context.request_a.binding);
    assert_eq!(b_execution.binding, context.request_b.binding);
    assert_eq!(a_execution.transcript, b_execution.transcript);
    let a_client_envelope = a_execution.client_package.clone();
    let b_client_envelope = b_execution.client_package.clone();
    let a_worker_envelope = a_execution.signing_worker_package.clone();
    let b_worker_envelope = b_execution.signing_worker_package.clone();
    if context.mode.exercises_faults() {
        assert!(open_local_ed25519_yao_client_package_v1(
            &a_client_envelope,
            &context.deriver_a_input_recipient.private_key,
        )
        .is_err());
        assert!(open_local_ed25519_yao_client_package_v1(
            &a_worker_envelope,
            &context.client_recipient.private_key,
        )
        .is_err());
        assert_eq!(
            b_body,
            post_json_to_path_with_headers(
                context.deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
                &result_request,
                &auth_headers,
            )?
            .1
        );
    }
    let activation_session = context.request_a.binding.session_id.into_bytes();
    let activation_transcript = a_execution.transcript;
    let mut a_client_plaintext = open_local_ed25519_yao_client_package_v1(
        &a_client_envelope,
        &context.client_recipient.private_key,
    )?;
    let mut b_client_plaintext = open_local_ed25519_yao_client_package_v1(
        &b_client_envelope,
        &context.client_recipient.private_key,
    )?;
    let a_client_package =
        ActivationDeriverAClientPackage::from_bytes(std::mem::take(&mut *a_client_plaintext))?;
    let b_client_package =
        ActivationDeriverBClientPackage::from_bytes(std::mem::take(&mut *b_client_plaintext))?;
    let client_scalar = Zeroizing::new(
        combine_client_activation_packages(
            activation_session,
            activation_transcript,
            a_client_package,
            b_client_package,
        )?
        .into_bytes(),
    );
    let a_delivery = LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
        binding: context.request_a.binding.clone(),
        client_commitment: a_execution.client_commitment,
        signing_worker_commitment: a_execution.signing_worker_commitment,
        package: a_worker_envelope,
    };
    let b_delivery = LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
        binding: context.request_b.binding.clone(),
        client_commitment: b_execution.client_commitment,
        signing_worker_commitment: b_execution.signing_worker_commitment,
        package: b_worker_envelope,
    };
    if context.mode.exercises_faults() {
        let conflicting_a_pair = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
            deriver_a: conflicting_activation_delivery(&a_delivery),
            deriver_b: b_delivery.clone(),
        };
        let (conflicting_a_status, _) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
            &conflicting_a_pair,
            &auth_headers,
        )?;
        assert_eq!(conflicting_a_status, 400);
        let mut wrong_role_delivery = b_delivery.clone();
        wrong_role_delivery.package =
            package_with_deriver(&b_delivery.package, Ed25519YaoDeriverRoleV1::DeriverA);
        let wrong_role_pair = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
            deriver_a: a_delivery.clone(),
            deriver_b: wrong_role_delivery,
        };
        let (wrong_role_status, _) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
            &wrong_role_pair,
            &auth_headers,
        )?;
        assert_eq!(wrong_role_status, 400);
        let mut wrong_family_delivery = b_delivery.clone();
        wrong_family_delivery.package =
            package_with_kind(&b_delivery.package, Ed25519YaoPackageKindV1::ExportClient);
        let wrong_family_pair = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
            deriver_a: a_delivery.clone(),
            deriver_b: wrong_family_delivery,
        };
        let (wrong_family_status, _) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
            &wrong_family_pair,
            &auth_headers,
        )?;
        assert_eq!(wrong_family_status, 400);
        let mut malformed_delivery = b_delivery.clone();
        malformed_delivery.package = package_with_tampered_ciphertext(&b_delivery.package);
        let malformed_pair = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
            deriver_a: a_delivery.clone(),
            deriver_b: malformed_delivery,
        };
        let (malformed_status, _) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
            &malformed_pair,
            &auth_headers,
        )?;
        assert_eq!(malformed_status, 400);
        let conflicting_b_pair = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
            deriver_a: a_delivery.clone(),
            deriver_b: conflicting_activation_delivery(&b_delivery),
        };
        let (conflicting_b_status, _) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
            &conflicting_b_pair,
            &auth_headers,
        )?;
        assert_eq!(conflicting_b_status, 400);
    }
    let delivery = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
        deriver_a: a_delivery,
        deriver_b: b_delivery,
    };
    let (delivery_status, delivery_body) = post_json_to_path_with_headers(
        context.signing_worker_url,
        LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
        &delivery,
        &auth_headers,
    )?;
    assert_eq!(delivery_status, 200);
    let activation_receipt =
        serde_json::from_str::<LocalEd25519YaoSigningWorkerActivationReceiptV1>(&delivery_body)?;
    let (worker_public_key, signing_worker_verifying_share, recovery_promotion) =
        match activation_receipt {
            LocalEd25519YaoSigningWorkerActivationReceiptV1::Active {
                registered_public_key,
                signing_worker_verifying_share,
                ..
            } => (registered_public_key, signing_worker_verifying_share, None),
            LocalEd25519YaoSigningWorkerActivationReceiptV1::Staged { promotion } => (
                promotion.registered_public_key,
                promotion.signing_worker_verifying_share,
                Some(promotion),
            ),
        };
    let commitments = ActivationPublicCommitments::new(
        a_execution.client_commitment,
        b_execution.client_commitment,
        a_execution.signing_worker_commitment,
        b_execution.signing_worker_commitment,
    );
    let public_receipt = derive_registration_receipt(commitments)?;
    let derived_public_key = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &verifying_share_bytes_from_signing_share_bytes(&client_scalar),
        &signing_worker_verifying_share,
        1,
        2,
    )?;
    assert_eq!(&derived_public_key, public_receipt.registered_public_key());
    assert_eq!(&worker_public_key, public_receipt.registered_public_key());

    if let Some(promotion) = recovery_promotion {
        let (promotion_status, promotion_body) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
            &promotion,
            &auth_headers,
        )?;
        assert_eq!(promotion_status, 200, "{promotion_body}");
        let promoted_receipt = serde_json::from_str::<
            LocalEd25519YaoSigningWorkerActivationReceiptV1,
        >(&promotion_body)?;
        let LocalEd25519YaoSigningWorkerActivationReceiptV1::Active {
            registered_public_key: promoted_public_key,
            signing_worker_verifying_share: promoted_verifying_share,
            ..
        } = promoted_receipt
        else {
            return Err("SigningWorker did not promote the verified recovery candidate".into());
        };
        assert_eq!(promoted_public_key, worker_public_key);
        assert_eq!(promoted_verifying_share, signing_worker_verifying_share);
    }

    Ok(LocalActivationProcessOutcome {
        client_scalar,
        signing_worker_verifying_share,
        public_receipt,
    })
}

struct LocalRefreshProcessContext<'a> {
    deriver_a_url: &'a str,
    deriver_b_url: &'a str,
    signing_worker_url: &'a str,
    request_a: &'a LocalEd25519YaoRefreshDeriverARequestV1,
    request_b: &'a LocalEd25519YaoRefreshDeriverBRequestV1,
    deriver_a_input_recipient: &'a LocalEd25519YaoRecipientKeyPairV1,
    deriver_b_input_recipient: &'a LocalEd25519YaoRecipientKeyPairV1,
    client_recipient: &'a LocalEd25519YaoRecipientKeyPairV1,
    mode: LocalLifecycleRunModeV1,
}

fn run_local_refresh_process_v1(
    context: LocalRefreshProcessContext<'_>,
) -> Result<LocalActivationProcessOutcome, Box<dyn std::error::Error>> {
    let auth_headers = [(
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    )];
    let request_b_envelope = seal_local_ed25519_yao_refresh_deriver_b_input_v1(
        context.request_b,
        context.deriver_b_input_recipient.public_key,
    )?;
    let request_a_envelope = seal_local_ed25519_yao_refresh_deriver_a_input_v1(
        context.request_a,
        context.deriver_a_input_recipient.public_key,
    )?;
    let (stage_status, _) = post_json_to_path_with_headers(
        context.deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH,
        &request_b_envelope,
        &auth_headers,
    )?;
    assert_eq!(stage_status, 200);
    if context.mode.exercises_faults() {
        assert_eq!(
            get_path_with_headers(
                context.deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_REFRESH_RESULT_PATH,
                &auth_headers,
            )?
            .0,
            400
        );
        assert_eq!(
            get_path_with_headers(
                context.deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
                &auth_headers,
            )?
            .0,
            400
        );
    }
    let (a_status, a_body) = post_json_to_path_with_headers(
        context.deriver_a_url,
        LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH,
        &request_a_envelope,
        &auth_headers,
    )?;
    assert_eq!(a_status, 200, "{a_body}");
    let (b_status, b_body) = get_path_with_headers(
        context.deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_RESULT_PATH,
        &auth_headers,
    )?;
    assert_eq!(b_status, 200);
    assert_typed_completion_pair(&a_body, &b_body)?;
    let a_receipt: serde_json::Value = serde_json::from_str(&a_body)?;
    let b_receipt: serde_json::Value = serde_json::from_str(&b_body)?;
    assert_eq!(a_receipt["family"], "activation");
    assert_eq!(a_receipt["frame_count"], 17);
    assert_eq!(a_receipt["transcript_hex"], b_receipt["transcript_hex"]);
    assert_exact_wire_ledger(&a_receipt, &b_receipt, 2_185_420, 37_164, 2_222_584);

    let a_client_envelope = get_encrypted_package(
        context.deriver_a_url,
        LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
        &auth_headers,
    )?;
    let b_client_envelope = get_encrypted_package(
        context.deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
        &auth_headers,
    )?;
    let a_worker_envelope = get_encrypted_package(
        context.deriver_a_url,
        LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
        &auth_headers,
    )?;
    let b_worker_envelope = get_encrypted_package(
        context.deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
        &auth_headers,
    )?;
    if context.mode.exercises_faults() {
        assert!(open_local_ed25519_yao_client_package_v1(
            &a_client_envelope,
            &context.deriver_a_input_recipient.private_key,
        )
        .is_err());
        assert!(open_local_ed25519_yao_client_package_v1(
            &a_worker_envelope,
            &context.client_recipient.private_key,
        )
        .is_err());
        assert_eq!(
            b_worker_envelope,
            get_encrypted_package(
                context.deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
                &auth_headers,
            )?
        );
    }
    let session = context.request_a.binding.ceremony().session_id.into_bytes();
    let transcript = json_hex_32(&a_receipt, "transcript_hex")?;
    let mut a_client_plaintext = open_local_ed25519_yao_client_package_v1(
        &a_client_envelope,
        &context.client_recipient.private_key,
    )?;
    let mut b_client_plaintext = open_local_ed25519_yao_client_package_v1(
        &b_client_envelope,
        &context.client_recipient.private_key,
    )?;
    let a_client_package =
        ActivationDeriverAClientPackage::from_bytes(std::mem::take(&mut *a_client_plaintext))?;
    let b_client_package =
        ActivationDeriverBClientPackage::from_bytes(std::mem::take(&mut *b_client_plaintext))?;
    let client_scalar = Zeroizing::new(
        combine_client_activation_packages(
            session,
            transcript,
            a_client_package,
            b_client_package,
        )?
        .into_bytes(),
    );
    let a_delivery = LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1 {
        binding: context.request_a.binding.clone(),
        client_commitment: json_hex_32(&a_receipt, "client_commitment_hex")?,
        signing_worker_commitment: json_hex_32(&a_receipt, "signing_worker_commitment_hex")?,
        package: a_worker_envelope,
    };
    let b_delivery = LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1 {
        binding: context.request_b.binding.clone(),
        client_commitment: json_hex_32(&b_receipt, "client_commitment_hex")?,
        signing_worker_commitment: json_hex_32(&b_receipt, "signing_worker_commitment_hex")?,
        package: b_worker_envelope,
    };
    let (delivery_status, delivery_body) = post_json_to_path_with_headers(
        context.signing_worker_url,
        LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH,
        &a_delivery,
        &auth_headers,
    )?;
    assert_eq!(delivery_status, 200);
    assert!(matches!(
        serde_json::from_str::<LocalEd25519YaoSigningWorkerRefreshReceiptV1>(&delivery_body)?,
        LocalEd25519YaoSigningWorkerRefreshReceiptV1::Pending { .. }
    ));
    if context.mode.exercises_faults() {
        let conflicting_a_delivery = conflicting_refresh_delivery(&a_delivery);
        let (conflicting_a_status, conflicting_a_body) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH,
            &conflicting_a_delivery,
            &auth_headers,
        )?;
        assert_eq!(conflicting_a_status, 400);
        assert!(conflicting_a_body.contains("Deriver A refresh delivery slot is occupied"));
        let mut malformed_delivery = b_delivery.clone();
        malformed_delivery.package = package_with_tampered_ciphertext(&b_delivery.package);
        let (malformed_status, _) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH,
            &malformed_delivery,
            &auth_headers,
        )?;
        assert_eq!(malformed_status, 400);
        let conflicting_b_delivery = conflicting_refresh_delivery(&b_delivery);
        let (conflicting_b_status, conflicting_b_body) = post_json_to_path_with_headers(
            context.signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH,
            &conflicting_b_delivery,
            &auth_headers,
        )?;
        assert_eq!(conflicting_b_status, 400);
        assert!(conflicting_b_body.contains("refresh package bindings do not match"));
    }
    let (delivery_status, delivery_body) = post_json_to_path_with_headers(
        context.signing_worker_url,
        LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH,
        &b_delivery,
        &auth_headers,
    )?;
    assert_eq!(delivery_status, 200, "{delivery_body}");
    let active_receipt =
        serde_json::from_str::<LocalEd25519YaoSigningWorkerRefreshReceiptV1>(&delivery_body)?;
    let LocalEd25519YaoSigningWorkerRefreshReceiptV1::Active {
        registered_public_key: worker_public_key,
        signing_worker_verifying_share,
        state_epoch,
        ..
    } = active_receipt
    else {
        return Err("SigningWorker did not activate the refreshed share".into());
    };
    assert_eq!(
        state_epoch,
        context.request_a.binding.epochs().signing_worker.next()
    );
    let commitments = ActivationPublicCommitments::new(
        json_hex_32(&a_receipt, "client_commitment_hex")?,
        json_hex_32(&b_receipt, "client_commitment_hex")?,
        json_hex_32(&a_receipt, "signing_worker_commitment_hex")?,
        json_hex_32(&b_receipt, "signing_worker_commitment_hex")?,
    );
    let public_receipt = derive_registration_receipt(commitments)?;
    assert_eq!(
        &worker_public_key,
        context.request_a.binding.registered_public_key()
    );
    assert_eq!(
        public_receipt.registered_public_key(),
        context.request_a.binding.registered_public_key()
    );

    let promotion = LocalEd25519YaoRefreshPromotionRequestV1 {
        binding_digest: local_ed25519_yao_refresh_binding_digest_v1(&context.request_a.binding),
        session,
    };
    if context.mode.exercises_faults() {
        let mut wrong_digest_promotion = promotion;
        wrong_digest_promotion.binding_digest[0] ^= 1;
        let (a_wrong_digest_status, _) = post_json_to_path_with_headers(
            context.deriver_a_url,
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
            &wrong_digest_promotion,
            &auth_headers,
        )?;
        assert_eq!(a_wrong_digest_status, 400);
        let (b_wrong_digest_status, _) = post_json_to_path_with_headers(
            context.deriver_b_url,
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
            &wrong_digest_promotion,
            &auth_headers,
        )?;
        assert_eq!(b_wrong_digest_status, 400);
        let mut wrong_session_promotion = promotion;
        wrong_session_promotion.session[0] ^= 1;
        let (a_wrong_session_status, _) = post_json_to_path_with_headers(
            context.deriver_a_url,
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
            &wrong_session_promotion,
            &auth_headers,
        )?;
        assert_eq!(a_wrong_session_status, 400);
        let (b_wrong_session_status, _) = post_json_to_path_with_headers(
            context.deriver_b_url,
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
            &wrong_session_promotion,
            &auth_headers,
        )?;
        assert_eq!(b_wrong_session_status, 400);
    }
    let (a_promote_status, a_promote_body) = post_json_to_path_with_headers(
        context.deriver_a_url,
        LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
        &promotion,
        &auth_headers,
    )?;
    assert_eq!(a_promote_status, 200, "{a_promote_body}");
    if context.mode.exercises_faults() {
        let (a_promotion_retry_status, a_promotion_retry_body) = post_json_to_path_with_headers(
            context.deriver_a_url,
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
            &promotion,
            &auth_headers,
        )?;
        assert_eq!(a_promotion_retry_status, 200, "{a_promotion_retry_body}");
        assert_eq!(a_promotion_retry_body, a_promote_body);
    }
    let (b_promote_status, b_promote_body) = post_json_to_path_with_headers(
        context.deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
        &promotion,
        &auth_headers,
    )?;
    assert_eq!(b_promote_status, 200, "{b_promote_body}");
    if context.mode.exercises_faults() {
        let (b_promotion_retry_status, b_promotion_retry_body) = post_json_to_path_with_headers(
            context.deriver_b_url,
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
            &promotion,
            &auth_headers,
        )?;
        assert_eq!(b_promotion_retry_status, 200, "{b_promotion_retry_body}");
        assert_eq!(b_promotion_retry_body, b_promote_body);
        let (stale_b_status, _) = post_json_to_path_with_headers(
            context.deriver_b_url,
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH,
            &request_b_envelope,
            &auth_headers,
        )?;
        assert_eq!(stale_b_status, 400);
        let (stale_a_status, _) = post_json_to_path_with_headers(
            context.deriver_a_url,
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH,
            &request_a_envelope,
            &auth_headers,
        )?;
        assert_eq!(stale_a_status, 400);
    }

    Ok(LocalActivationProcessOutcome {
        client_scalar,
        signing_worker_verifying_share,
        public_receipt,
    })
}

fn burn_failed_refresh_exchange(
    deriver_b_url: &str,
    request: &LocalEd25519YaoRefreshDeriverBRequestV1,
    recipient: &LocalEd25519YaoRecipientKeyPairV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_headers = [(
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    )];
    let envelope =
        seal_local_ed25519_yao_refresh_deriver_b_input_v1(request, recipient.public_key)?;
    let (stage_status, stage_body) = post_json_to_path_with_headers(
        deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH,
        &envelope,
        &auth_headers,
    )?;
    assert_eq!(stage_status, 200, "{stage_body}");
    let rejected_exchange = serde_json::json!({
        "deriver_a_delta": {
            "binding_digest": vec![0_u8; 32],
            "session": request.binding.ceremony().session_id.into_bytes(),
            "delta_y": vec![1_u8; 32],
            "delta_tau": vec![0_u8; 32]
        }
    });
    let (exchange_status, _) = post_json_to_path_with_headers(
        deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH,
        &rejected_exchange,
        &auth_headers,
    )?;
    assert_eq!(exchange_status, 400);
    let (replay_status, _) = post_json_to_path_with_headers(
        deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH,
        &envelope,
        &auth_headers,
    )?;
    assert_eq!(replay_status, 400);
    Ok(())
}

fn burn_disconnected_activation_session(
    deriver_b_url: &str,
    request: &LocalEd25519YaoActivationDeriverBRequestV1,
    recipient: &LocalEd25519YaoRecipientKeyPairV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_headers = [(
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    )];
    let envelope =
        seal_local_ed25519_yao_activation_deriver_b_input_v1(request, recipient.public_key)?;
    let (stage_status, stage_body) = post_json_to_path_with_headers(
        deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
        &envelope,
        &auth_headers,
    )?;
    assert_eq!(stage_status, 200, "{stage_body}");

    let authority = deriver_b_url
        .strip_prefix("http://")
        .ok_or("Deriver B URL must use http://")?;
    let mut stream = TcpStream::connect(authority)?;
    write!(
        stream,
        "POST {LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/vnd.seams.ed25519-yao-stream-v1\r\ntransfer-encoding: chunked\r\n{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: {LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1}\r\nx-seams-ed25519-yao-session: {}\r\nconnection: close\r\n\r\n",
        hex::encode(request.binding.session_id.into_bytes()),
    )?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Both)?;

    let (replay_status, _) = post_json_to_path_with_headers(
        deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
        &envelope,
        &auth_headers,
    )?;
    assert_eq!(replay_status, 400);
    Ok(())
}

enum RejectedDeriverBPeerHeadV1 {
    MissingServiceAuth,
    WrongServiceAuth,
    WrongSession,
}

fn send_rejected_deriver_b_peer_head(
    deriver_b_url: &str,
    expected_session: [u8; 32],
    probe: RejectedDeriverBPeerHeadV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = deriver_b_url
        .strip_prefix("http://")
        .ok_or("Deriver B URL must use http://")?;
    let mut stream = TcpStream::connect(authority)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST {LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/vnd.seams.ed25519-yao-stream-v1\r\ntransfer-encoding: chunked\r\n",
    )?;
    match probe {
        RejectedDeriverBPeerHeadV1::MissingServiceAuth => {}
        RejectedDeriverBPeerHeadV1::WrongServiceAuth => {
            write!(
                stream,
                "{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: wrong-service-secret\r\n"
            )?;
        }
        RejectedDeriverBPeerHeadV1::WrongSession => {
            write!(
                stream,
                "{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: {LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1}\r\n"
            )?;
        }
    }
    let presented_session = match probe {
        RejectedDeriverBPeerHeadV1::WrongSession => [0xff; 32],
        RejectedDeriverBPeerHeadV1::MissingServiceAuth
        | RejectedDeriverBPeerHeadV1::WrongServiceAuth => expected_session,
    };
    write!(
        stream,
        "x-seams-ed25519-yao-session: {}\r\nconnection: close\r\n\r\n",
        hex::encode(presented_session),
    )?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert!(response.is_empty());
    Ok(())
}

#[test]
fn one_account_profile_completes_the_local_ed25519_yao_lifecycle(
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = build_local_ed25519_yao_one_account_plan_v1();
    run_local_ed25519_yao_lifecycle(
        "ed25519-yao-one-account",
        plan.root_for(LocalServiceRoleV1::DeriverA)
            .expect("Deriver A root"),
        plan.root_for(LocalServiceRoleV1::DeriverB)
            .expect("Deriver B root"),
        plan.root_for(LocalServiceRoleV1::SigningWorker)
            .expect("SigningWorker root"),
    )
}

#[test]
fn two_administrator_profile_completes_the_local_ed25519_yao_lifecycle(
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = build_local_ed25519_yao_two_administrator_plan_v1();
    run_local_ed25519_yao_lifecycle(
        "ed25519-yao-two-administrator",
        plan.root_for(LocalServiceRoleV1::DeriverA)
            .expect("Deriver A root"),
        plan.root_for(LocalServiceRoleV1::DeriverB)
            .expect("Deriver B root"),
        plan.root_for(LocalServiceRoleV1::SigningWorker)
            .expect("SigningWorker root"),
    )
}

fn run_local_ed25519_yao_lifecycle(
    temp_label: &str,
    deriver_a_relative_root: &str,
    deriver_b_relative_root: &str,
    signing_worker_relative_root: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _process_guard = local_worker_process_test_guard();
    let mode = LocalLifecycleRunModeV1::from_environment();
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let temp = temp_dir(temp_label)?;
    let deriver_a_root = temp.join(deriver_a_relative_root);
    let deriver_b_root = temp.join(deriver_b_relative_root);
    let signing_worker_root = temp.join(signing_worker_relative_root);
    let deriver_a_url = format!("http://127.0.0.1:{}", free_port()?);
    let deriver_b_url = format!("http://127.0.0.1:{}", free_port()?);
    let signing_worker_url = format!("http://127.0.0.1:{}", free_port()?);
    let signing_worker_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("SigningWorker recipient key");
    let deriver_a_input_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("Deriver A input key");
    let deriver_b_input_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("Deriver B input key");
    write_deriver_envs_to_roots(
        &deriver_a_root,
        &deriver_b_root,
        &deriver_a_url,
        &deriver_b_url,
    )?;
    replace_deriver_input_hpke_private_keys_in_roots(
        &deriver_a_root,
        &deriver_b_root,
        &deriver_a_input_recipient,
        &deriver_b_input_recipient,
    )?;
    write_signing_worker_env(&signing_worker_root, &signing_worker_url)?;
    replace_signing_worker_hpke_key_pair(&signing_worker_root, &signing_worker_recipient)?;

    let mut deriver_b = ChildGuard::spawn_in_root(
        binary,
        "deriver-b",
        deriver_b_root.join(".env.router-ab.deriver-b.local"),
        &deriver_b_root,
    )?;
    let mut deriver_a = ChildGuard::spawn_in_root(
        binary,
        "deriver-a",
        deriver_a_root.join(".env.router-ab.deriver-a.local"),
        &deriver_a_root,
    )?;
    let mut signing_worker = ChildGuard::spawn_in_root(
        binary,
        "signing-worker",
        signing_worker_root.join(".env.router-ab.signing-worker.local"),
        &signing_worker_root,
    )?;
    wait_for_health(&deriver_b_url, deriver_b.child_mut())?;
    wait_for_health(&deriver_a_url, deriver_a.child_mut())?;
    wait_for_health(&signing_worker_url, signing_worker.child_mut())?;

    let application = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet-process").expect("wallet"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_process")
            .expect("signing key"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:local").expect("signing root"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1).expect("slot"),
    );
    let context = Ed25519YaoStableKeyDerivationContextV1::new(application.digest(), 1, 2)?;
    let client_root =
        Ed25519YaoClientDerivationRootV1::from_secret_bytes(fresh_nonzero_bytes_32()?);
    let (client_a, client_b) =
        derive_ed25519_yao_client_contributions_v1(&client_root, &context)?.into_parts();
    let application_request = yao_application();
    let client_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("Client recipient key");
    let activation_recipients = LocalEd25519YaoActivationRecipientsV1 {
        client_public_key: client_recipient.public_key,
        signing_worker_public_key: signing_worker_recipient.public_key,
    };
    if mode.exercises_faults() {
        let disconnected_admission =
            admit_local_ed25519_yao_registration_v1(yao_registration_request(
                "local-process-disconnected-registration",
                "wallet-session-disconnected",
                application_request.clone(),
            ))?;
        let (_, disconnected_client_b) =
            derive_ed25519_yao_client_contributions_v1(&client_root, &context)?.into_parts();
        let (disconnected_client_b_y, disconnected_client_b_tau) =
            disconnected_client_b.into_parts();
        let disconnected_request_b = LocalEd25519YaoActivationDeriverBRequestV1 {
            binding: disconnected_admission.binding,
            application_binding: application_request.clone(),
            participant_ids: [1, 2],
            client_contribution: LocalEd25519YaoClientContributionV1 {
                y: disconnected_client_b_y.into_bytes(),
                tau: disconnected_client_b_tau.into_bytes(),
            },
            recipients: activation_recipients,
        };
        burn_disconnected_activation_session(
            &deriver_b_url,
            &disconnected_request_b,
            &deriver_b_input_recipient,
        )?;
    }

    let registration_started = Instant::now();
    let registration_admission =
        admit_local_ed25519_yao_registration_v1(yao_registration_request(
            "local-process-lifecycle-1",
            "wallet-session-1",
            application_request.clone(),
        ))?;
    let binding = registration_admission.binding;
    let activation_session = binding.session_id.into_bytes();
    let (client_a_y, client_a_tau) = client_a.into_parts();
    let (client_b_y, client_b_tau) = client_b.into_parts();
    let request_b = LocalEd25519YaoActivationDeriverBRequestV1 {
        binding: binding.clone(),
        application_binding: application_request.clone(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_b_y.into_bytes(),
            tau: client_b_tau.into_bytes(),
        },
        recipients: activation_recipients,
    };
    let request_a = LocalEd25519YaoActivationDeriverARequestV1 {
        binding,
        application_binding: application_request,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_a_y.into_bytes(),
            tau: client_a_tau.into_bytes(),
        },
        recipients: activation_recipients,
    };
    let auth_headers = [(
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
        LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    )];
    let request_b_envelope = seal_local_ed25519_yao_activation_deriver_b_input_v1(
        &request_b,
        deriver_b_input_recipient.public_key,
    )?;
    let request_a_envelope = seal_local_ed25519_yao_activation_deriver_a_input_v1(
        &request_a,
        deriver_a_input_recipient.public_key,
    )?;
    let (stage_status, _) = post_json_to_path_with_headers(
        &deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
        &request_b_envelope,
        &auth_headers,
    )?;
    assert_eq!(stage_status, 200);
    if mode.exercises_faults() {
        let result_request = serde_json::json!({
            "family": "activation",
            "session_id": activation_session,
        });
        assert_eq!(
            post_json_to_path_with_headers(
                &deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
                &result_request,
                &auth_headers,
            )?
            .0,
            400
        );
        send_rejected_deriver_b_peer_head(
            &deriver_b_url,
            activation_session,
            RejectedDeriverBPeerHeadV1::MissingServiceAuth,
        )?;
        send_rejected_deriver_b_peer_head(
            &deriver_b_url,
            activation_session,
            RejectedDeriverBPeerHeadV1::WrongServiceAuth,
        )?;
        send_rejected_deriver_b_peer_head(
            &deriver_b_url,
            activation_session,
            RejectedDeriverBPeerHeadV1::WrongSession,
        )?;
    }
    let (a_status, a_body) = post_json_to_path_with_headers(
        &deriver_a_url,
        LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH,
        &request_a_envelope,
        &auth_headers,
    )?;
    assert_eq!(a_status, 200);
    let result_request = serde_json::json!({
        "family": "activation",
        "session_id": activation_session,
    });
    let (b_status, b_body) = post_json_to_path_with_headers(
        &deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
        &result_request,
        &auth_headers,
    )?;
    assert_eq!(b_status, 200);
    let a_execution = activation_execution_from_json(&a_body, Ed25519YaoDeriverRoleV1::DeriverA)?;
    let b_execution = activation_execution_from_json(&b_body, Ed25519YaoDeriverRoleV1::DeriverB)?;
    assert_eq!(a_execution.binding, request_a.binding);
    assert_eq!(b_execution.binding, request_b.binding);
    assert_eq!(a_execution.transcript, b_execution.transcript);
    let a_client_envelope = a_execution.client_package.clone();
    let b_client_envelope = b_execution.client_package.clone();
    let a_worker_envelope = a_execution.signing_worker_package.clone();
    let b_worker_envelope = b_execution.signing_worker_package.clone();
    if mode.exercises_faults() {
        assert_eq!(
            b_body,
            post_json_to_path_with_headers(
                &deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
                &result_request,
                &auth_headers,
            )?
            .1
        );
    }
    let activation_transcript = a_execution.transcript;
    let mut a_client_plaintext = open_local_ed25519_yao_client_package_v1(
        &a_client_envelope,
        &client_recipient.private_key,
    )?;
    let mut b_client_plaintext = open_local_ed25519_yao_client_package_v1(
        &b_client_envelope,
        &client_recipient.private_key,
    )?;
    let a_client_package =
        ActivationDeriverAClientPackage::from_bytes(std::mem::take(&mut *a_client_plaintext))?;
    let b_client_package =
        ActivationDeriverBClientPackage::from_bytes(std::mem::take(&mut *b_client_plaintext))?;
    let mut client_scalar = Zeroizing::new(
        combine_client_activation_packages(
            activation_session,
            activation_transcript,
            a_client_package,
            b_client_package,
        )?
        .into_bytes(),
    );
    let a_delivery = LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
        binding: request_a.binding.clone(),
        client_commitment: a_execution.client_commitment,
        signing_worker_commitment: a_execution.signing_worker_commitment,
        package: a_worker_envelope,
    };
    let b_delivery = LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
        binding: request_b.binding.clone(),
        client_commitment: b_execution.client_commitment,
        signing_worker_commitment: b_execution.signing_worker_commitment,
        package: b_worker_envelope,
    };
    let delivery = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
        deriver_a: a_delivery.clone(),
        deriver_b: b_delivery,
    };
    let (delivery_status, delivery_body) = post_json_to_path_with_headers(
        &signing_worker_url,
        LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
        &delivery,
        &auth_headers,
    )?;
    assert_eq!(delivery_status, 200);
    let active_receipt =
        serde_json::from_str::<LocalEd25519YaoSigningWorkerActivationReceiptV1>(&delivery_body)?;
    let LocalEd25519YaoSigningWorkerActivationReceiptV1::Active {
        registered_public_key: worker_public_key,
        signing_worker_verifying_share,
        ..
    } = active_receipt
    else {
        return Err("SigningWorker did not activate after both packages".into());
    };
    if mode.exercises_faults() {
        let (replay_status, replay_body) = post_json_to_path_with_headers(
            &signing_worker_url,
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
            &delivery,
            &auth_headers,
        )?;
        assert_eq!(replay_status, 400);
        assert!(replay_body.contains("already has an active Yao signing share"));
    }
    let commitments = ActivationPublicCommitments::new(
        a_execution.client_commitment,
        b_execution.client_commitment,
        a_execution.signing_worker_commitment,
        b_execution.signing_worker_commitment,
    );
    let registration_receipt = derive_registration_receipt(commitments)?;
    let derived_public_key = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &verifying_share_bytes_from_signing_share_bytes(&client_scalar),
        &signing_worker_verifying_share,
        1,
        2,
    )?;
    assert_eq!(
        &derived_public_key,
        registration_receipt.registered_public_key()
    );
    assert_eq!(
        &worker_public_key,
        registration_receipt.registered_public_key()
    );
    let registration_microseconds = elapsed_microseconds(registration_started);

    let secondary_application = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet-process-secondary")
            .expect("secondary wallet"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_process_secondary")
            .expect("secondary signing key"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:local")
            .expect("secondary signing root"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(2).expect("secondary slot"),
    );
    let secondary_context =
        Ed25519YaoStableKeyDerivationContextV1::new(secondary_application.digest(), 1, 2)?;
    let secondary_client_root =
        Ed25519YaoClientDerivationRootV1::from_secret_bytes(fresh_nonzero_bytes_32()?);
    let (secondary_client_a, secondary_client_b) =
        derive_ed25519_yao_client_contributions_v1(&secondary_client_root, &secondary_context)?
            .into_parts();
    let (secondary_client_a_y, secondary_client_a_tau) = secondary_client_a.into_parts();
    let (secondary_client_b_y, secondary_client_b_tau) = secondary_client_b.into_parts();
    let secondary_application_request = RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-process-secondary",
        "ed25519ks_process_secondary",
        "project:local",
        2,
    )?;
    let secondary_admission = admit_local_ed25519_yao_registration_v1(yao_registration_request(
        "local-process-lifecycle-secondary",
        "wallet-session-secondary",
        secondary_application_request.clone(),
    ))?;
    let secondary_binding = secondary_admission.binding;
    let secondary_client_recipient =
        generate_local_ed25519_yao_recipient_key_pair_v1().expect("secondary Client recipient");
    let secondary_recipients = LocalEd25519YaoActivationRecipientsV1 {
        client_public_key: secondary_client_recipient.public_key,
        signing_worker_public_key: signing_worker_recipient.public_key,
    };
    let secondary_request_a = LocalEd25519YaoActivationDeriverARequestV1 {
        binding: secondary_binding.clone(),
        application_binding: secondary_application_request.clone(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: secondary_client_a_y.into_bytes(),
            tau: secondary_client_a_tau.into_bytes(),
        },
        recipients: secondary_recipients,
    };
    let secondary_request_b = LocalEd25519YaoActivationDeriverBRequestV1 {
        binding: secondary_binding,
        application_binding: secondary_application_request,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: secondary_client_b_y.into_bytes(),
            tau: secondary_client_b_tau.into_bytes(),
        },
        recipients: secondary_recipients,
    };
    let secondary_registration = run_local_activation_process_v1(LocalActivationProcessContext {
        deriver_a_url: &deriver_a_url,
        deriver_b_url: &deriver_b_url,
        signing_worker_url: &signing_worker_url,
        request_a: &secondary_request_a,
        request_b: &secondary_request_b,
        deriver_a_input_recipient: &deriver_a_input_recipient,
        deriver_b_input_recipient: &deriver_b_input_recipient,
        client_recipient: &secondary_client_recipient,
        mode: LocalLifecycleRunModeV1::Validation,
    })?;
    assert_ne!(
        secondary_registration
            .public_receipt
            .registered_public_key(),
        registration_receipt.registered_public_key()
    );

    drop(deriver_b);
    drop(deriver_a);
    drop(signing_worker);
    deriver_b = ChildGuard::spawn_in_root(
        binary,
        "deriver-b",
        deriver_b_root.join(".env.router-ab.deriver-b.local"),
        &deriver_b_root,
    )?;
    deriver_a = ChildGuard::spawn_in_root(
        binary,
        "deriver-a",
        deriver_a_root.join(".env.router-ab.deriver-a.local"),
        &deriver_a_root,
    )?;
    signing_worker = ChildGuard::spawn_in_root(
        binary,
        "signing-worker",
        signing_worker_root.join(".env.router-ab.signing-worker.local"),
        &signing_worker_root,
    )?;
    wait_for_health(&deriver_b_url, deriver_b.child_mut())?;
    wait_for_health(&deriver_a_url, deriver_a.child_mut())?;
    wait_for_health(&signing_worker_url, signing_worker.child_mut())?;

    let recovery_started = Instant::now();
    let active_credential =
        LocalEd25519YaoRecoveryCredentialBindingV1::new(fresh_nonzero_bytes_32()?)?;
    let replacement_credential =
        LocalEd25519YaoRecoveryCredentialBindingV1::new(fresh_nonzero_bytes_32()?)?;
    let mut recovery_state = LocalEd25519YaoRouterRecoveryStateV1::new(
        active_credential,
        *registration_receipt.registered_public_key(),
    )?;
    let recovery_application = request_a.application_binding.clone();
    let recovery_admission =
        recovery_state.begin(LocalEd25519YaoRouterRecoveryAdmissionRequestV1 {
            scope: yao_scope("local-process-recovery-1", "wallet-session-2"),
            application_binding: recovery_application.clone(),
            participant_ids: [1, 2],
            active_credential,
            replacement_credential,
        })?;
    let recovery_binding = recovery_admission.binding;
    let (recovery_client_a, recovery_client_b) =
        derive_ed25519_yao_client_contributions_v1(&client_root, &context)?.into_parts();
    let (recovery_client_a_y, recovery_client_a_tau) = recovery_client_a.into_parts();
    let (recovery_client_b_y, recovery_client_b_tau) = recovery_client_b.into_parts();
    let recovery_recipients = LocalEd25519YaoActivationRecipientsV1 {
        client_public_key: client_recipient.public_key,
        signing_worker_public_key: signing_worker_recipient.public_key,
    };
    let recovery_request_b = LocalEd25519YaoActivationDeriverBRequestV1 {
        binding: recovery_binding.clone(),
        application_binding: recovery_application.clone(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: recovery_client_b_y.into_bytes(),
            tau: recovery_client_b_tau.into_bytes(),
        },
        recipients: recovery_recipients,
    };
    let recovery_request_a = LocalEd25519YaoActivationDeriverARequestV1 {
        binding: recovery_binding.clone(),
        application_binding: recovery_application,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: recovery_client_a_y.into_bytes(),
            tau: recovery_client_a_tau.into_bytes(),
        },
        recipients: recovery_recipients,
    };
    let recovery = run_local_activation_process_v1(LocalActivationProcessContext {
        deriver_a_url: &deriver_a_url,
        deriver_b_url: &deriver_b_url,
        signing_worker_url: &signing_worker_url,
        request_a: &recovery_request_a,
        request_b: &recovery_request_b,
        deriver_a_input_recipient: &deriver_a_input_recipient,
        deriver_b_input_recipient: &deriver_b_input_recipient,
        client_recipient: &client_recipient,
        mode,
    })?;
    assert_eq!(
        recovery.public_receipt.registered_public_key(),
        registration_receipt.registered_public_key()
    );
    assert_eq!(&*recovery.client_scalar, &*client_scalar);
    assert_eq!(
        recovery.signing_worker_verifying_share,
        signing_worker_verifying_share
    );
    let promotion = recovery_state.promote(
        &recovery_binding,
        *recovery.public_receipt.registered_public_key(),
    )?;
    assert_eq!(promotion.active_credential, replacement_credential);
    assert_eq!(promotion.retired_credential, active_credential);
    assert!(recovery_state.is_tombstoned(active_credential));
    if mode.exercises_faults() {
        let retired_retry = recovery_state.begin(LocalEd25519YaoRouterRecoveryAdmissionRequestV1 {
            scope: yao_scope("local-process-retired-retry", "wallet-session-3"),
            application_binding: request_a.application_binding.clone(),
            participant_ids: [1, 2],
            active_credential,
            replacement_credential,
        });
        assert!(retired_retry.is_err());
    }
    client_scalar.zeroize();
    client_scalar = recovery.client_scalar;
    let recovery_microseconds = elapsed_microseconds(recovery_started);

    let epoch_1 = Ed25519YaoStateEpochV1::new(1)?;
    let epoch_2 = Ed25519YaoStateEpochV1::new(2)?;
    let epoch_3 = Ed25519YaoStateEpochV1::new(3)?;
    let deriver_transition = Ed25519YaoEpochTransitionV1::new(epoch_1, epoch_2)?;
    let signing_worker_transition = Ed25519YaoEpochTransitionV1::new(epoch_2, epoch_3)?;
    let active_epochs = LocalEd25519YaoRefreshActiveEpochsV1 {
        deriver_a: epoch_1,
        deriver_b: epoch_1,
        signing_worker: epoch_2,
    };
    let refresh_application = request_a.application_binding.clone();
    if mode.exercises_faults() {
        let mut failed_refresh_state = LocalEd25519YaoRouterRefreshStateV1::new(
            &recovery_binding,
            *registration_receipt.registered_public_key(),
            active_epochs,
        )?;
        let failed_refresh_binding =
            failed_refresh_state.begin(LocalEd25519YaoRouterRefreshAdmissionRequestV1 {
                scope: yao_scope(
                    "local-process-refresh-burned",
                    "wallet-session-refresh-burned",
                ),
                application_binding: refresh_application.clone(),
                participant_ids: [1, 2],
                registered_public_key: *registration_receipt.registered_public_key(),
                epochs: Ed25519YaoRefreshEpochsV1 {
                    deriver_a: deriver_transition,
                    deriver_b: deriver_transition,
                    signing_worker: signing_worker_transition,
                },
            })?;
        let failed_refresh_request_b = LocalEd25519YaoRefreshDeriverBRequestV1 {
            binding: failed_refresh_binding,
            application_binding: refresh_application.clone(),
            participant_ids: [1, 2],
            client_contribution: LocalEd25519YaoClientContributionV1 {
                y: recovery_request_b.client_contribution.y,
                tau: recovery_request_b.client_contribution.tau,
            },
            recipients: recovery_recipients,
        };
        burn_failed_refresh_exchange(
            &deriver_b_url,
            &failed_refresh_request_b,
            &deriver_b_input_recipient,
        )?;
    }

    let refresh_started = Instant::now();
    let mut refresh_state = LocalEd25519YaoRouterRefreshStateV1::new(
        &recovery_binding,
        *registration_receipt.registered_public_key(),
        active_epochs,
    )?;
    let refresh_binding = refresh_state.begin(LocalEd25519YaoRouterRefreshAdmissionRequestV1 {
        scope: yao_scope("local-process-refresh-1", "wallet-session-refresh-1"),
        application_binding: refresh_application.clone(),
        participant_ids: [1, 2],
        registered_public_key: *registration_receipt.registered_public_key(),
        epochs: Ed25519YaoRefreshEpochsV1 {
            deriver_a: deriver_transition,
            deriver_b: deriver_transition,
            signing_worker: signing_worker_transition,
        },
    })?;
    let refresh_request_a = LocalEd25519YaoRefreshDeriverARequestV1 {
        binding: refresh_binding.clone(),
        application_binding: refresh_application.clone(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: recovery_request_a.client_contribution.y,
            tau: recovery_request_a.client_contribution.tau,
        },
        recipients: recovery_recipients,
    };
    let refresh_request_b = LocalEd25519YaoRefreshDeriverBRequestV1 {
        binding: refresh_binding.clone(),
        application_binding: refresh_application,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: recovery_request_b.client_contribution.y,
            tau: recovery_request_b.client_contribution.tau,
        },
        recipients: recovery_recipients,
    };
    let refresh = run_local_refresh_process_v1(LocalRefreshProcessContext {
        deriver_a_url: &deriver_a_url,
        deriver_b_url: &deriver_b_url,
        signing_worker_url: &signing_worker_url,
        request_a: &refresh_request_a,
        request_b: &refresh_request_b,
        deriver_a_input_recipient: &deriver_a_input_recipient,
        deriver_b_input_recipient: &deriver_b_input_recipient,
        client_recipient: &client_recipient,
        mode,
    })?;
    assert_eq!(&*refresh.client_scalar, &*client_scalar);
    assert_eq!(
        refresh.public_receipt.registered_public_key(),
        registration_receipt.registered_public_key()
    );
    assert_eq!(
        refresh.signing_worker_verifying_share,
        signing_worker_verifying_share
    );
    refresh_state.mark_output_committed(&refresh_binding)?;
    refresh_state.mark_worker_activated(
        &refresh_binding,
        *refresh.public_receipt.registered_public_key(),
    )?;
    assert_eq!(
        refresh_state.promote(&refresh_binding)?.signing_worker,
        epoch_3
    );
    client_scalar.zeroize();
    client_scalar = refresh.client_scalar;
    let refresh_microseconds = elapsed_microseconds(refresh_started);

    let export_started = Instant::now();
    let (client_a, client_b) =
        derive_ed25519_yao_client_contributions_v1(&client_root, &context)?.into_parts();
    let export_application = yao_application();
    let export_admission =
        admit_local_ed25519_yao_export_v1(LocalEd25519YaoRouterExportAdmissionRequestV1 {
            scope: yao_scope("local-process-export-1", "wallet-session-1"),
            application_binding: export_application.clone(),
            participant_ids: [1, 2],
        })?;
    let export_binding = export_admission.binding;
    let export_session = export_binding.session_id.into_bytes();
    let (client_a_y, client_a_tau) = client_a.into_parts();
    let (client_b_y, client_b_tau) = client_b.into_parts();
    let export_b = LocalEd25519YaoExportDeriverBRequestV1 {
        binding: export_binding.clone(),
        application_binding: export_application.clone(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_b_y.into_bytes(),
            tau: client_b_tau.into_bytes(),
        },
        recipients: LocalEd25519YaoExportRecipientV1 {
            client_public_key: client_recipient.public_key,
        },
    };
    let export_a = LocalEd25519YaoExportDeriverARequestV1 {
        binding: export_binding,
        application_binding: export_application,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_a_y.into_bytes(),
            tau: client_a_tau.into_bytes(),
        },
        recipients: LocalEd25519YaoExportRecipientV1 {
            client_public_key: client_recipient.public_key,
        },
    };
    let export_b_envelope = seal_local_ed25519_yao_export_deriver_b_input_v1(
        &export_b,
        deriver_b_input_recipient.public_key,
    )?;
    let export_a_envelope = seal_local_ed25519_yao_export_deriver_a_input_v1(
        &export_a,
        deriver_a_input_recipient.public_key,
    )?;
    let (stage_status, _) = post_json_to_path_with_headers(
        &deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH,
        &export_b_envelope,
        &auth_headers,
    )?;
    assert_eq!(stage_status, 200);
    if mode.exercises_faults() {
        let result_request = serde_json::json!({
            "family": "export",
            "session_id": export_session,
        });
        assert_eq!(
            post_json_to_path_with_headers(
                &deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_EXPORT_RESULT_PATH,
                &result_request,
                &auth_headers,
            )?
            .0,
            400
        );
    }
    let (a_status, a_body) = post_json_to_path_with_headers(
        &deriver_a_url,
        LOCAL_DERIVER_A_ED25519_YAO_EXPORT_START_PATH,
        &export_a_envelope,
        &auth_headers,
    )?;
    assert_eq!(a_status, 200);
    let result_request = serde_json::json!({
        "family": "export",
        "session_id": export_session,
    });
    let (b_status, b_body) = post_json_to_path_with_headers(
        &deriver_b_url,
        LOCAL_DERIVER_B_ED25519_YAO_EXPORT_RESULT_PATH,
        &result_request,
        &auth_headers,
    )?;
    assert_eq!(b_status, 200);
    let a_execution = export_execution_from_json(&a_body, Ed25519YaoDeriverRoleV1::DeriverA)?;
    let b_execution = export_execution_from_json(&b_body, Ed25519YaoDeriverRoleV1::DeriverB)?;
    assert_eq!(a_execution.binding, export_a.binding);
    assert_eq!(b_execution.binding, export_b.binding);
    assert_eq!(a_execution.transcript, b_execution.transcript);
    let a_export_envelope = a_execution.client_package.clone();
    let b_export_envelope = b_execution.client_package.clone();
    if mode.exercises_faults() {
        assert_eq!(
            b_body,
            post_json_to_path_with_headers(
                &deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_EXPORT_RESULT_PATH,
                &result_request,
                &auth_headers,
            )?
            .1
        );
    }
    let export_transcript = a_execution.transcript;
    let mut a_export_plaintext = open_local_ed25519_yao_client_package_v1(
        &a_export_envelope,
        &client_recipient.private_key,
    )?;
    let mut b_export_plaintext = open_local_ed25519_yao_client_package_v1(
        &b_export_envelope,
        &client_recipient.private_key,
    )?;
    let a_export_package =
        ExportDeriverAClientPackage::from_bytes(std::mem::take(&mut *a_export_plaintext))?;
    let b_export_package =
        ExportDeriverBClientPackage::from_bytes(std::mem::take(&mut *b_export_plaintext))?;
    let mut exported_seed = Zeroizing::new(
        combine_export_packages(
            export_session,
            export_transcript,
            a_export_package,
            b_export_package,
        )?
        .into_bytes(),
    );
    let expanded = expand_ed25519_seed(*exported_seed);
    assert_eq!(
        &expanded.public_key_bytes,
        registration_receipt.registered_public_key()
    );
    let export_signing_key = SigningKey::from_bytes(&exported_seed);
    let export_proof_message = b"seams Phase 9C local process seed export";
    let export_signature = export_signing_key.sign(export_proof_message);
    export_signing_key
        .verifying_key()
        .verify(export_proof_message, &export_signature)?;
    let export_microseconds = elapsed_microseconds(export_started);
    exported_seed.zeroize();

    drop(deriver_a);
    drop(deriver_b);
    client_scalar.zeroize();

    write_phase9c_local_lifecycle_evidence(
        temp_label,
        registration_receipt.registered_public_key(),
        &expanded.public_key_bytes,
    )?;

    if mode.emits_sample() {
        let sample = LocalEd25519YaoLifecycleLatencySampleV1 {
            schema: "seams-ed25519-yao-local-latency-sample-v1",
            profile: temp_label,
            registration_microseconds,
            recovery_microseconds,
            refresh_microseconds,
            export_microseconds,
            activation_deriver_a_to_b_bytes: 2_185_420,
            activation_deriver_b_to_a_bytes: 37_164,
            activation_total_ab_bytes: 2_222_584,
            export_deriver_a_to_b_bytes: 82_636,
            export_deriver_b_to_a_bytes: 20_780,
            export_total_ab_bytes: 103_416,
        };
        println!("YAOS_AB_LOCAL_SAMPLE {}", serde_json::to_string(&sample)?);
    }

    drop(signing_worker);
    let _ = fs::remove_dir_all(temp);
    Ok(())
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn spawn(
        binary: &str,
        role: &str,
        env_path: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let child = Command::new(binary)
            .arg("--role")
            .arg(role)
            .arg("--env")
            .arg(env_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self { child })
    }

    fn spawn_in_root(
        binary: &str,
        role: &str,
        env_path: PathBuf,
        root: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let child = Command::new(binary)
            .arg("--role")
            .arg(role)
            .arg("--env")
            .arg(env_path)
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self { child })
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_deriver_envs(
    root: &Path,
    deriver_a_url: &str,
    deriver_b_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    write_deriver_envs_to_roots(root, root, deriver_a_url, deriver_b_url)
}

fn write_deriver_envs_to_roots(
    deriver_a_root: &Path,
    deriver_b_root: &Path,
    deriver_a_url: &str,
    deriver_b_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = fresh_nonzero_bytes_32()?;
    let plan = local_env_materialization_plan_v1(&seed)?;
    fs::create_dir_all(deriver_a_root)?;
    fs::create_dir_all(deriver_b_root)?;
    for file in plan.files {
        let root = match file.role {
            LocalServiceRoleV1::DeriverA => deriver_a_root,
            LocalServiceRoleV1::DeriverB => deriver_b_root,
            _ => continue,
        };
        let contents = file
            .contents
            .replace("http://127.0.0.1:9101", deriver_a_url)
            .replace("http://127.0.0.1:9102", deriver_b_url);
        fs::write(root.join(file.path), contents)?;
    }
    Ok(())
}

fn write_signing_worker_env(
    root: &Path,
    signing_worker_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = fresh_nonzero_bytes_32()?;
    let plan = local_env_materialization_plan_v1(&seed)?;
    fs::create_dir_all(root)?;
    for file in plan.files {
        if file.role != LocalServiceRoleV1::SigningWorker {
            continue;
        }
        let contents = file
            .contents
            .replace("http://127.0.0.1:9103", signing_worker_url);
        fs::write(root.join(file.path), contents)?;
    }
    Ok(())
}

fn replace_signing_worker_hpke_key_pair(
    root: &Path,
    key_pair: &router_ab_dev::LocalEd25519YaoRecipientKeyPairV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = root.join(".env.router-ab.signing-worker.local");
    let contents = fs::read_to_string(&path)?;
    let contents = replace_env_value(
        &contents,
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY",
        &format!("x25519:{}", hex::encode(key_pair.public_key)),
    );
    let contents = replace_env_value(
        &contents,
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY",
        &hex::encode(key_pair.private_key.as_bytes()),
    );
    fs::write(path, contents)?;
    Ok(())
}

fn replace_deriver_input_hpke_private_keys_in_roots(
    deriver_a_root: &Path,
    deriver_b_root: &Path,
    deriver_a: &router_ab_dev::LocalEd25519YaoRecipientKeyPairV1,
    deriver_b: &router_ab_dev::LocalEd25519YaoRecipientKeyPairV1,
) -> Result<(), Box<dyn std::error::Error>> {
    replace_worker_env_value(
        &deriver_a_root.join(".env.router-ab.deriver-a.local"),
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        &hex::encode(deriver_a.private_key.as_bytes()),
    )?;
    replace_worker_env_value(
        &deriver_b_root.join(".env.router-ab.deriver-b.local"),
        "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY",
        &hex::encode(deriver_b.private_key.as_bytes()),
    )
}

fn replace_worker_env_value(
    path: &Path,
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    fs::write(path, replace_env_value(&contents, key, value))?;
    Ok(())
}

fn replace_env_value(contents: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let mut output = String::new();
    for line in contents.lines() {
        if line.starts_with(&prefix) {
            output.push_str(&prefix);
            output.push_str(value);
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

fn post_json_to_path_with_headers<T: Serialize>(
    base_url: &str,
    path: &str,
    body: &T,
    headers: &[(&str, &str)],
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or("post URL must use http://")?;
    let body = serde_json::to_vec(body)?;
    let mut stream = TcpStream::connect(authority)?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/json\r\n",
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(
        stream,
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("response missing header terminator")?;
    let headers = std::str::from_utf8(&response[..header_end])?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("response missing status")?
        .parse::<u16>()?;
    Ok((
        status,
        String::from_utf8(response[header_end + 4..].to_vec())?,
    ))
}

fn get_path_with_headers(
    base_url: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or("GET URL must use http://")?;
    let mut stream = TcpStream::connect(authority)?;
    write!(stream, "GET {path} HTTP/1.1\r\nhost: {authority}\r\n")?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"connection: close\r\n\r\n")?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("response missing header terminator")?;
    let response_headers = std::str::from_utf8(&response[..header_end])?;
    let status = response_headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("response missing status")?
        .parse::<u16>()?;
    Ok((
        status,
        String::from_utf8(response[header_end + 4..].to_vec())?,
    ))
}

fn get_encrypted_package(
    base_url: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<Ed25519YaoEncryptedPackageV1, Box<dyn std::error::Error>> {
    let (status, body) = get_path_with_headers(base_url, path, headers)?;
    if status != 200 {
        return Err(format!("encrypted package route {path} returned {status}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

fn activation_execution_from_json(
    body: &str,
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> Result<Ed25519YaoActivationRoleExecutionV1, Box<dyn std::error::Error>> {
    let execution: Ed25519YaoRoleExecutionV1 = serde_json::from_str(body)?;
    execution.validate()?;
    match execution {
        Ed25519YaoRoleExecutionV1::Activation(execution)
            if execution.deriver == expected_deriver =>
        {
            Ok(execution)
        }
        Ed25519YaoRoleExecutionV1::Activation(_) => {
            Err("activation execution used the wrong Deriver role".into())
        }
        Ed25519YaoRoleExecutionV1::Export(_) => {
            Err("activation result returned an export execution".into())
        }
    }
}

fn export_execution_from_json(
    body: &str,
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> Result<Ed25519YaoExportRoleExecutionV1, Box<dyn std::error::Error>> {
    let execution: Ed25519YaoRoleExecutionV1 = serde_json::from_str(body)?;
    execution.validate()?;
    match execution {
        Ed25519YaoRoleExecutionV1::Export(execution) if execution.deriver == expected_deriver => {
            Ok(execution)
        }
        Ed25519YaoRoleExecutionV1::Export(_) => {
            Err("export execution used the wrong Deriver role".into())
        }
        Ed25519YaoRoleExecutionV1::Activation(_) => {
            Err("export result returned an activation execution".into())
        }
    }
}

fn json_hex_32(
    value: &serde_json::Value,
    field: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let encoded = value[field]
        .as_str()
        .ok_or_else(|| format!("receipt field {field} is missing"))?;
    Ok(hex::decode(encoded)?
        .try_into()
        .map_err(|_| format!("receipt field {field} is not 32 bytes"))?)
}

fn assert_exact_wire_ledger(
    deriver_a: &serde_json::Value,
    deriver_b: &serde_json::Value,
    expected_a_to_b: u64,
    expected_b_to_a: u64,
    expected_total: u64,
) {
    for (field, expected) in [
        ("deriver_a_to_b_transport_bytes", expected_a_to_b),
        ("deriver_b_to_a_transport_bytes", expected_b_to_a),
        ("total_ab_transport_bytes", expected_total),
    ] {
        assert_eq!(deriver_a[field].as_u64(), Some(expected));
        assert_eq!(deriver_b[field], deriver_a[field]);
    }
}

fn assert_typed_completion_pair(
    a_body: &str,
    b_body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let a: LocalEd25519YaoRoleCompletionV1 = serde_json::from_str(a_body)?;
    let b: LocalEd25519YaoRoleCompletionV1 = serde_json::from_str(b_body)?;
    match (a, b) {
        (
            LocalEd25519YaoRoleCompletionV1::Activation {
                session_hex: a_session,
                transcript_hex: a_transcript,
                frame_count: a_frames,
                deriver_a_to_b_transport_bytes: a_to_b_a,
                deriver_b_to_a_transport_bytes: b_to_a_a,
                total_ab_transport_bytes: total_a,
                ..
            },
            LocalEd25519YaoRoleCompletionV1::Activation {
                session_hex: b_session,
                transcript_hex: b_transcript,
                frame_count: b_frames,
                deriver_a_to_b_transport_bytes: a_to_b_b,
                deriver_b_to_a_transport_bytes: b_to_a_b,
                total_ab_transport_bytes: total_b,
                ..
            },
        )
        | (
            LocalEd25519YaoRoleCompletionV1::Export {
                session_hex: a_session,
                transcript_hex: a_transcript,
                frame_count: a_frames,
                deriver_a_to_b_transport_bytes: a_to_b_a,
                deriver_b_to_a_transport_bytes: b_to_a_a,
                total_ab_transport_bytes: total_a,
            },
            LocalEd25519YaoRoleCompletionV1::Export {
                session_hex: b_session,
                transcript_hex: b_transcript,
                frame_count: b_frames,
                deriver_a_to_b_transport_bytes: a_to_b_b,
                deriver_b_to_a_transport_bytes: b_to_a_b,
                total_ab_transport_bytes: total_b,
            },
        ) => {
            assert_eq!(a_session, b_session);
            assert_eq!(a_transcript, b_transcript);
            assert_eq!(a_frames, b_frames);
            assert_eq!(a_to_b_a, a_to_b_b);
            assert_eq!(b_to_a_a, b_to_a_b);
            assert_eq!(total_a, total_b);
        }
        _ => panic!("Deriver completion families do not match"),
    }
    Ok(())
}

fn wait_for_health(base_url: &str, child: &mut Child) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..80 {
        if child.try_wait()?.is_some() {
            return Err("local worker exited before health check".into());
        }
        if get_health(base_url).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("local worker did not become healthy".into())
}

fn get_health(base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or("health URL must use http://")?;
    let mut stream = TcpStream::connect(authority)?;
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nhost: {authority}\r\nconnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if response.starts_with("HTTP/1.1 200 ") {
        Ok(())
    } else {
        Err("health response was not 200".into())
    }
}

fn send_incomplete_http_probe(base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or("probe URL must use http://")?;
    let mut stream = TcpStream::connect(authority)?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\n")?;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn free_port() -> Result<u16, Box<dyn std::error::Error>> {
    static ALLOCATED_PORTS: OnceLock<Mutex<BTreeSet<u16>>> = OnceLock::new();
    loop {
        let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        let mut allocated = ALLOCATED_PORTS
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if allocated.insert(port) {
            return Ok(port);
        }
    }
}

fn fresh_nonzero_bytes_32() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    loop {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
}

fn local_worker_process_test_guard() -> MutexGuard<'static, ()> {
    static PROCESS_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    PROCESS_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn temp_dir(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path =
        std::env::temp_dir().join(format!("router-ab-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path)?;
    Ok(path)
}
