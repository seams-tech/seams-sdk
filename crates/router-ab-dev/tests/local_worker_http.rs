use base64::Engine;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use router_ab_cloudflare::{
    CloudflareRouterEd25519YaoExecuteRequestV2, CloudflareTenantRootCoordinatesV1,
};
use router_ab_core::{
    LocalHttpPathV1, LocalServiceRoleV1, MpcMaterialActivationRefV1, MpcPrfShareCommitmentWireV1,
    RootShareEpoch, RouterEd25519YaoExecuteResultV1, RouterEd25519YaoExecuteSuccessV1,
    RouterEd25519YaoGatewayExecuteTargetV2, TenantRootActivationReceiptTransitionV1,
    TenantRootCanaryCurveFamilyV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
    TenantRootIdentityDigestV1, TenantRootManagedBackupBindingV1,
    TenantRootManagedBackupSealRequestV1, TenantRootProviderCanaryReceiptBindingV1,
    TenantRootShareEpoch, TenantRootShareInstallationEvidenceV1,
    TenantRootShareInstallationTranscriptV1, TenantRootSignedActivationReceiptV1,
    TenantRootSignedManagedBackupV1, TenantRootSignedProviderCanaryReceiptV1,
    TenantRootSignedShareInstallationEvidenceV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};
use router_ab_dev::{
    admit_local_ed25519_yao_registration_v1, generate_local_ed25519_yao_recipient_key_pair_v1,
    local_env_materialization_plan_v1, run_example_local_router_ab_dev_http_ceremony_v1,
    seal_local_ed25519_yao_activation_deriver_a_input_v1,
    seal_local_ed25519_yao_activation_deriver_b_input_v1, LocalDeriverPeerMessageReceiptV1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoClientContributionV1,
    LocalHttpServiceBindingClientV1, RouterAbEd25519YaoApplicationBindingFactsV1,
    RouterAbEd25519YaoLifecycleScopeV1, RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1, LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientRootV1,
    Ed25519YaoStableKeyDerivationContextV1,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, MutexGuard, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use threshold_prf::{
    prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment, SigningRootShareWire,
    TwoPartyDeriverRole,
};

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
            source.contains("local_dev_http_handle_request_with_dispatcher_v1"),
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
fn local_router_worker_exposes_health_and_rejects_malformed_pair_routes(
) -> Result<(), Box<dyn std::error::Error>> {
    let _process_guard = local_worker_process_test_guard();
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let temp = temp_dir("router-boundary")?;
    let router_url = format!("http://127.0.0.1:{}", free_port()?);
    let deriver_a_url = format!("http://127.0.0.1:{}", free_port()?);
    let deriver_b_url = format!("http://127.0.0.1:{}", free_port()?);
    let signing_worker_url = format!("http://127.0.0.1:{}", free_port()?);
    write_router_env(
        &temp,
        &router_url,
        &deriver_a_url,
        &deriver_b_url,
        &signing_worker_url,
    )?;
    let mut router = ChildGuard::spawn(
        binary,
        "router",
        temp.join(router_ab_dev::LOCAL_ROUTER_ENV_FILE_V1),
    )?;
    wait_for_health(&router_url, router.child_mut())?;
    assert!(get_health(&router_url).is_ok());
    for path in [
        router_ab_dev::LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH,
        router_ab_dev::LOCAL_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    ] {
        let (status, body) = post_json_to_path_with_headers(
            &router_url,
            path,
            &serde_json::json!({}),
            &[(
                router_ab_dev::LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
                router_ab_dev::LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
            )],
        )?;
        if path == router_ab_dev::LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH {
            assert_eq!(status, 400, "{path}: {body}");
            assert!(body.contains("malformed") || body.contains("MalformedWirePayload"));
        } else {
            assert_eq!(status, 400, "{path}: {body}");
            assert!(body.contains("malformed") || body.contains("MalformedWirePayload"));
        }
    }
    drop(router);
    let _ = fs::remove_dir_all(temp);
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalEd25519YaoProductLatencySampleV1 {
    schema: &'static str,
    profile: &'static str,
    registration_microseconds: u64,
}

#[test]
fn product_topology_completes_local_ed25519_yao_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    let _process_guard = local_worker_process_test_guard();
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let temp = temp_dir("product-yao-registration")?;
    let router_url = format!("http://127.0.0.1:{}", free_port()?);
    let deriver_a_url = format!("http://127.0.0.1:{}", free_port()?);
    let deriver_b_url = format!("http://127.0.0.1:{}", free_port()?);
    let signing_worker_url = format!("http://127.0.0.1:{}", free_port()?);
    let tenant_root_fixture = product_tenant_root_fixture()?;
    let router_env = write_product_worker_envs(
        &temp,
        &router_url,
        &deriver_a_url,
        &deriver_b_url,
        &signing_worker_url,
        &tenant_root_fixture,
    )?;

    let mut router = ChildGuard::spawn_in_root(
        binary,
        "router",
        temp.join(router_ab_dev::LOCAL_ROUTER_ENV_FILE_V1),
        &temp,
    )?;
    let mut deriver_a = ChildGuard::spawn_in_root(
        binary,
        "deriver-a",
        temp.join(router_ab_dev::LOCAL_DERIVER_A_ENV_FILE_V1),
        &temp,
    )?;
    let mut deriver_b = ChildGuard::spawn_in_root(
        binary,
        "deriver-b",
        temp.join(router_ab_dev::LOCAL_DERIVER_B_ENV_FILE_V1),
        &temp,
    )?;
    let mut signing_worker = ChildGuard::spawn_in_root(
        binary,
        "signing-worker",
        temp.join(router_ab_dev::LOCAL_SIGNING_WORKER_ENV_FILE_V1),
        &temp,
    )?;
    wait_for_health(&router_url, router.child_mut())?;
    wait_for_health(&deriver_a_url, deriver_a.child_mut())?;
    wait_for_health(&deriver_b_url, deriver_b.child_mut())?;
    wait_for_health(&signing_worker_url, signing_worker.child_mut())?;

    let request = product_registration_request(&router_env, &tenant_root_fixture)?;
    let started = Instant::now();
    let (status, body) = post_json_to_path_with_headers(
        &router_url,
        LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH,
        &request,
        &[(
            LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
            LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
        )],
    )?;
    let registration_microseconds =
        u64::try_from(started.elapsed().as_micros()).map_err(|_| "latency exceeds u64")?;
    assert_eq!(status, 200, "{body}");
    let result = serde_json::from_str::<RouterEd25519YaoExecuteResultV1>(&body)?;
    let RouterEd25519YaoExecuteResultV1::Succeeded { result } = result else {
        return Err("product Yao registration did not succeed".into());
    };
    assert!(matches!(
        *result,
        RouterEd25519YaoExecuteSuccessV1::Registration { .. }
    ));
    println!(
        "YAOS_AB_LOCAL_SAMPLE {}",
        serde_json::to_string(&LocalEd25519YaoProductLatencySampleV1 {
            schema: "seams-ed25519-yao-local-latency-sample-v2",
            profile: "ed25519-yao-product-topology",
            registration_microseconds,
        })?
    );

    drop(router);
    drop(deriver_a);
    drop(deriver_b);
    drop(signing_worker);
    let _ = fs::remove_dir_all(temp);
    Ok(())
}

fn product_registration_request(
    router_env: &str,
    tenant_root_fixture: &ProductTenantRootFixture,
) -> Result<CloudflareRouterEd25519YaoExecuteRequestV2, Box<dyn std::error::Error>> {
    let application = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("account-product-benchmark")?,
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_product_benchmark")?,
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:local")?,
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1)?,
    );
    let context = Ed25519YaoStableKeyDerivationContextV1::new(application.digest(), 1, 2)?;
    let client_root = Ed25519YaoClientRootV1::from_secret_bytes(fresh_nonzero_bytes_32()?);
    let (client_a, client_b) =
        derive_ed25519_yao_client_contributions_v1(&client_root, &context)?.into_parts();
    let application_binding = RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "account-product-benchmark",
        "ed25519ks_product_benchmark",
        "project:local",
        1,
    )?;
    let admission = admit_local_ed25519_yao_registration_v1(
        RouterAbEd25519YaoRegistrationAdmissionRequestV1::new(
            RouterAbEd25519YaoLifecycleScopeV1::new(
                "product-benchmark-registration",
                RootShareEpoch::new("local-root-v1")?,
                "account-product-benchmark",
                "wallet-session-product-benchmark",
                "signer-set-product-benchmark",
                "signing-worker-local",
                MpcMaterialActivationRefV1::new(
                    "activation-product-benchmark",
                    "capability-product-benchmark",
                    "account-product-benchmark",
                    "key-product-benchmark",
                    "product-benchmark-registration",
                    "signing-worker-local",
                )?,
            )?,
            application_binding.clone(),
            [1, 2],
        )?,
    )?;
    let recipients = LocalEd25519YaoActivationRecipientsV1 {
        client_public_key: generate_local_ed25519_yao_recipient_key_pair_v1()?.public_key,
        signing_worker_public_key: x25519_public_key_from_env(
            router_env,
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY",
        )?,
    };
    let (client_a_y, client_a_tau) = client_a.into_parts();
    let (client_b_y, client_b_tau) = client_b.into_parts();
    let request_a = LocalEd25519YaoActivationDeriverARequestV1 {
        binding: admission.binding.clone(),
        application_binding: application_binding.clone(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_a_y.into_bytes(),
            tau: client_a_tau.into_bytes(),
        },
        recipients,
    };
    let request_b = LocalEd25519YaoActivationDeriverBRequestV1 {
        binding: admission.binding.clone(),
        application_binding,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: client_b_y.into_bytes(),
            tau: client_b_tau.into_bytes(),
        },
        recipients,
    };
    let input_a = seal_local_ed25519_yao_activation_deriver_a_input_v1(
        &request_a,
        x25519_public_key_from_env(router_env, "DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY")?,
    )?;
    let input_b = seal_local_ed25519_yao_activation_deriver_b_input_v1(
        &request_b,
        x25519_public_key_from_env(router_env, "DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY")?,
    )?;
    Ok(CloudflareRouterEd25519YaoExecuteRequestV2 {
        tenant_root: tenant_root_fixture.coordinates.clone(),
        application: tenant_root_fixture.application.clone(),
        participant_ids: tenant_root_fixture.participant_ids,
        target: RouterEd25519YaoGatewayExecuteTargetV2::registration(
            admission.binding,
            input_a,
            input_b,
        )?,
    })
}

fn x25519_public_key_from_env(
    contents: &str,
    key: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let prefix = format!("{key}=x25519:");
    let encoded = contents
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or("x25519 public key is missing")?;
    Ok(hex::decode(encoded)?
        .try_into()
        .map_err(|_| "x25519 key length")?)
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

fn write_router_env(
    root: &Path,
    router_url: &str,
    deriver_a_url: &str,
    deriver_b_url: &str,
    signing_worker_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = fresh_nonzero_bytes_32()?;
    let plan = local_env_materialization_plan_v1(&seed)?;
    let file = plan
        .files
        .into_iter()
        .find(|file| file.role == LocalServiceRoleV1::Router)
        .ok_or("local env plan is missing Router file")?;
    let contents = file
        .contents
        .replace("http://127.0.0.1:4100", router_url)
        .replace("http://127.0.0.1:4103", deriver_a_url)
        .replace("http://127.0.0.1:4104", deriver_b_url)
        .replace("http://127.0.0.1:4105", signing_worker_url);
    fs::create_dir_all(root)?;
    fs::write(root.join(file.path), contents)?;
    Ok(())
}

fn write_product_worker_envs(
    root: &Path,
    router_url: &str,
    deriver_a_url: &str,
    deriver_b_url: &str,
    signing_worker_url: &str,
    tenant_root_fixture: &ProductTenantRootFixture,
) -> Result<String, Box<dyn std::error::Error>> {
    let seed = fresh_nonzero_bytes_32()?;
    let plan = local_env_materialization_plan_v1(&seed)?;
    for directory in plan.directories {
        fs::create_dir_all(root.join(directory))?;
    }
    let mut router_env = None;
    for file in plan.files {
        let contents = file
            .contents
            .replace("http://127.0.0.1:4100", router_url)
            .replace("http://127.0.0.1:4103", deriver_a_url)
            .replace("http://127.0.0.1:4104", deriver_b_url)
            .replace("http://127.0.0.1:4105", signing_worker_url);
        let contents = match file.role {
            LocalServiceRoleV1::Router => contents.replace(
                "LOCAL_TENANT_ROOT_BINDINGS_JSON={}",
                &format!(
                    "LOCAL_TENANT_ROOT_BINDINGS_JSON={}",
                    tenant_root_fixture.router_bindings_json
                ),
            ),
            LocalServiceRoleV1::DeriverA => contents.replace(
                "LOCAL_TENANT_ROOT_ROLE_SHARES_JSON={}",
                &format!(
                    "LOCAL_TENANT_ROOT_ROLE_SHARES_JSON={}",
                    tenant_root_fixture.role_shares_a_json
                ),
            ),
            LocalServiceRoleV1::DeriverB => contents.replace(
                "LOCAL_TENANT_ROOT_ROLE_SHARES_JSON={}",
                &format!(
                    "LOCAL_TENANT_ROOT_ROLE_SHARES_JSON={}",
                    tenant_root_fixture.role_shares_b_json
                ),
            ),
            LocalServiceRoleV1::SigningWorker => contents,
        };
        if file.role == LocalServiceRoleV1::Router {
            router_env = Some(contents.clone());
        }
        fs::write(root.join(file.path), contents)?;
    }
    router_env.ok_or_else(|| "local env plan is missing Router file".into())
}

struct ProductTenantRootFixture {
    coordinates: CloudflareTenantRootCoordinatesV1,
    application: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    router_bindings_json: String,
    role_shares_a_json: String,
    role_shares_b_json: String,
}

fn product_tenant_root_fixture() -> Result<ProductTenantRootFixture, Box<dyn std::error::Error>> {
    const ISSUER_SIGNING_KEY_BYTES: [u8; 32] = [0x31; 32];
    const CANARY_SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];
    let participant_ids = [1, 2];
    let application = RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "account-product-benchmark",
        "ed25519ks_product_benchmark",
        "project:local",
        1,
    )?;
    let identity = TenantRootIdentityDigestV1::from_bytes([0x71; 32]);
    let lineage = TenantRootCustodyLineageId::from_bytes([0x72; 16])?;
    let issued_at_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let expires_at_ms = issued_at_ms
        .checked_add(300_000)
        .ok_or("tenant-root fixture expiry overflow")?;
    let context = TenantRootCeremonyContextV1::new(
        identity,
        lineage,
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x73; 16])?,
        TenantRootCeremonyNonceV1::from_bytes([0x74; 32])?,
        issued_at_ms,
        expires_at_ms,
        "local-deriver-a-signing-key",
        "local-deriver-b-signing-key",
    )?;
    let share_a = product_share(TwoPartyDeriverRole::DeriverA, 7)?;
    let share_b = product_share(TwoPartyDeriverRole::DeriverB, 11)?;
    let commitments = TenantRootEpochCommitmentsV1::new(
        product_share_commitment(&share_a)?,
        product_share_commitment(&share_b)?,
    )?;
    let installation_a = product_installation(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        &share_a,
        &share_b,
    )?;
    let installation_b = product_installation(
        context.clone(),
        TwoPartyDeriverRole::DeriverB,
        &share_b,
        &share_a,
    )?;
    let backup_a =
        product_managed_backup(&installation_a, &share_a, TwoPartyDeriverRole::DeriverA)?;
    let backup_b =
        product_managed_backup(&installation_b, &share_b, TwoPartyDeriverRole::DeriverB)?;
    let canary_a = product_provider_canary(
        &context,
        &commitments,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
        "local-canary-ecdsa",
        &CANARY_SIGNING_KEY_BYTES,
    )?;
    let canary_b = product_provider_canary(
        &context,
        &commitments,
        TenantRootCanaryCurveFamilyV1::Ed25519,
        "local-canary-ed25519",
        &CANARY_SIGNING_KEY_BYTES,
    )?;
    let bundle =
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            canary_a,
            canary_b,
            2,
            3,
        )?;
    let signed_receipt = TenantRootSignedActivationReceiptV1::sign_initial_creation(
        &bundle,
        issued_at_ms,
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        "local-tenant-root-issuer",
        &ISSUER_SIGNING_KEY_BYTES,
    )?;
    let receipt_bytes = signed_receipt.canonical_bytes()?;
    let receipt_digest: [u8; 32] = Sha256::digest(&receipt_bytes).into();
    let identity_b64u = encode_product_base64url(identity.as_bytes());
    let lineage_b64u = lineage.to_base64url();
    let coordinates = CloudflareTenantRootCoordinatesV1 {
        identity_digest_b64u: identity_b64u.clone(),
        custody_lineage_b64u: lineage_b64u.clone(),
    };
    let coordinate_key = format!("{identity_b64u}|{lineage_b64u}");
    let mut router_bindings = BTreeMap::new();
    router_bindings.insert(
        coordinate_key.clone(),
        json!({
            "activation_receipt_b64u": encode_product_base64url(&receipt_bytes),
            "issuer_verifying_key_hex": hex::encode(
                SigningKey::from_bytes(&ISSUER_SIGNING_KEY_BYTES)
                    .verifying_key()
                    .to_bytes(),
            ),
            "application": application,
            "participant_ids": participant_ids,
            "deriver_a_identity": "local-deriver-a",
            "deriver_b_identity": "local-deriver-b",
        }),
    );
    let router_bindings_json = serde_json::to_string(&router_bindings)?;
    let role_shares_a_json = product_role_share_json(
        &coordinate_key,
        identity_b64u.as_str(),
        lineage_b64u.as_str(),
        TwoPartyDeriverRole::DeriverA,
        &share_a,
        &context,
        &receipt_digest,
    )?;
    let role_shares_b_json = product_role_share_json(
        &coordinate_key,
        identity_b64u.as_str(),
        lineage_b64u.as_str(),
        TwoPartyDeriverRole::DeriverB,
        &share_b,
        &context,
        &receipt_digest,
    )?;
    Ok(ProductTenantRootFixture {
        coordinates,
        application,
        participant_ids,
        router_bindings_json,
        role_shares_a_json,
        role_shares_b_json,
    })
}

fn encode_product_base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn product_share(
    role: TwoPartyDeriverRole,
    scalar: u64,
) -> Result<SigningRootShare, Box<dyn std::error::Error>> {
    Ok(SigningRootShare::from_canonical_bytes(
        role.share_id(),
        Scalar::from(scalar).to_bytes(),
    )?)
}

fn product_share_commitment(
    share: &SigningRootShare,
) -> Result<MpcPrfShareCommitmentWireV1, Box<dyn std::error::Error>> {
    Ok(MpcPrfShareCommitmentWireV1::new(
        SigningRootShareCommitment::from_share(share)
            .to_bytes()
            .to_vec(),
    )?)
}

fn product_installation(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share: &SigningRootShare,
    peer: &SigningRootShare,
) -> Result<VerifiedTenantRootSignedShareInstallationEvidenceWireV1, Box<dyn std::error::Error>> {
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context,
        role,
        SigningRootShareCommitment::from_share(share),
        SigningRootShareCommitment::from_share(peer),
    )?;
    let mut rng = OsRng;
    let proof = prove_root_share_knowledge(share, &transcript.canonical_bytes()?, &mut rng)?;
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof)?;
    let signing_key = product_role_signing_key(role);
    let signed =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence, signing_key.as_bytes())?;
    let bytes = signed.canonical_bytes()?;
    Ok(
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &bytes,
            signing_key.verifying_key().as_bytes(),
        )?,
    )
}

fn product_role_signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    let byte = match role {
        TwoPartyDeriverRole::DeriverA => 0x51,
        TwoPartyDeriverRole::DeriverB => 0x61,
    };
    SigningKey::from_bytes(&[byte; 32])
}

fn product_managed_backup(
    installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    share: &SigningRootShare,
    role: TwoPartyDeriverRole,
) -> Result<router_ab_core::VerifiedTenantRootManagedBackupV1, Box<dyn std::error::Error>> {
    let context = installation.evidence().transcript().context();
    let share_wire = router_ab_core::MpcPrfSigningRootShareWireV1::new(
        SigningRootShareWire::from_share(share).to_bytes().to_vec(),
    )?;
    let binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
        installation,
        format!("local-backup-provider-{}", role.as_str()),
        format!("local-backup-key-{}", role.as_str()),
        context.signing_key_id(role),
        context.issued_at_ms(),
    )?;
    let request = TenantRootManagedBackupSealRequestV1::new(binding.clone(), share_wire)?;
    let signing_key = product_role_signing_key(role);
    let signed = TenantRootSignedManagedBackupV1::sign(
        request,
        vec![
            match role {
                TwoPartyDeriverRole::DeriverA => 0xa5,
                TwoPartyDeriverRole::DeriverB => 0xb5,
            };
            96
        ],
        signing_key.as_bytes(),
    )?;
    let bytes = signed.canonical_bytes()?;
    Ok(
        TenantRootSignedManagedBackupV1::decode_and_verify_canonical_bytes(
            &bytes,
            &binding,
            signing_key.verifying_key().as_bytes(),
        )?,
    )
}

fn product_provider_canary(
    context: &TenantRootCeremonyContextV1,
    commitments: &TenantRootEpochCommitmentsV1,
    family: TenantRootCanaryCurveFamilyV1,
    provider_key_version_ref: &str,
    signing_key_bytes: &[u8; 32],
) -> Result<router_ab_core::VerifiedTenantRootProviderCanaryReceiptV1, Box<dyn std::error::Error>> {
    let binding = TenantRootProviderCanaryReceiptBindingV1::new(
        context.identity_digest(),
        context.custody_lineage(),
        TenantRootActivationReceiptTransitionV1::InitialCreation,
        TenantRootShareEpoch::INITIAL,
        commitments.clone(),
        family,
        provider_key_version_ref,
        context.issued_at_ms(),
        TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
        "local-canary-signing-key",
        context.issued_at_ms(),
        context.expires_at_ms(),
    )?;
    let signed = TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), signing_key_bytes)?;
    Ok(signed.verify(
        &binding,
        SigningKey::from_bytes(signing_key_bytes)
            .verifying_key()
            .as_bytes(),
    )?)
}

fn product_role_share_json(
    coordinate_key: &str,
    identity_b64u: &str,
    lineage_b64u: &str,
    role: TwoPartyDeriverRole,
    share: &SigningRootShare,
    context: &TenantRootCeremonyContextV1,
    receipt_digest: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error>> {
    let installation_evidence_digest = context.digest()?;
    let mut shares = BTreeMap::new();
    shares.insert(
        format!("{coordinate_key}|1"),
        json!({
            "identity_digest_b64u": identity_b64u,
            "custody_lineage_b64u": lineage_b64u,
            "role": role.as_str(),
            "epoch": 1,
            "share_commitment_b64u": encode_product_base64url(
                SigningRootShareCommitment::from_share(share).to_bytes().as_ref(),
            ),
            "epoch_wrapping_key_ref": format!("local-epoch-wrap-{}", role.as_str()),
            "installation_evidence_digest_b64u": encode_product_base64url(
                installation_evidence_digest.as_bytes(),
            ),
            "share_wire_b64u": encode_product_base64url(
                SigningRootShareWire::from_share(share).to_bytes().as_ref(),
            ),
            "activation_receipt_digest_b64u": encode_product_base64url(receipt_digest),
        }),
    );
    Ok(serde_json::to_string(&shares)?)
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
            .replace("http://127.0.0.1:4103", deriver_a_url)
            .replace("http://127.0.0.1:4104", deriver_b_url);
        fs::write(root.join(file.path), contents)?;
    }
    Ok(())
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
