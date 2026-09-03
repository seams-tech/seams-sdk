use router_ab_core::{
    LocalHttpPathV1, LocalServiceRoleV1, MpcMaterialActivationRefV1, RootShareEpoch,
    RouterEd25519YaoExecuteResultV1, RouterEd25519YaoExecuteSuccessV1,
    RouterEd25519YaoGatewayExecuteTargetV2,
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
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientRootV1,
    Ed25519YaoStableKeyDerivationContextV1,
};
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
    let router_env = write_product_worker_envs(
        &temp,
        &router_url,
        &deriver_a_url,
        &deriver_b_url,
        &signing_worker_url,
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

    let request = product_registration_request(&router_env)?;
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
) -> Result<RouterEd25519YaoGatewayExecuteTargetV2, Box<dyn std::error::Error>> {
    let application = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet-product-benchmark")?,
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_product_benchmark")?,
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project:local")?,
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1)?,
    );
    let context = Ed25519YaoStableKeyDerivationContextV1::new(application.digest(), 1, 2)?;
    let client_root = Ed25519YaoClientRootV1::from_secret_bytes(fresh_nonzero_bytes_32()?);
    let (client_a, client_b) =
        derive_ed25519_yao_client_contributions_v1(&client_root, &context)?.into_parts();
    let application_binding = RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-product-benchmark",
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
    Ok(RouterEd25519YaoGatewayExecuteTargetV2::registration(
        admission.binding,
        input_a,
        input_b,
    )?)
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
        if file.role == LocalServiceRoleV1::Router {
            router_env = Some(contents.clone());
        }
        fs::write(root.join(file.path), contents)?;
    }
    router_env.ok_or_else(|| "local env plan is missing Router file".into())
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
