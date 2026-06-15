use router_ab_core::{
    LocalHttpPathV1, LocalServiceRoleV1, NormalSigningResponseV1,
    NormalSigningRound1PrepareResponseV1, NormalSigningSignatureSchemeV1,
    RouterAbEd25519NormalSigningPrepareRequestV2,
};
use router_ab_dev::{
    build_local_normal_signing_delegate_action_prepare_request_v2,
    build_local_normal_signing_finalize_request_v2,
    build_local_normal_signing_near_transaction_prepare_request_v2,
    build_local_normal_signing_nep413_prepare_request_v2, local_env_materialization_plan_v1,
    run_example_local_router_ab_hss_dev_http_ceremony_v1, LocalDeriverPeerMessageReceiptV1,
    LocalHttpServiceBindingClientV1, LocalSigningWorkerActivationRouteReceiptV1,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2, LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
    LOCAL_ROUTER_NORMAL_SIGNING_WALLET_SESSION_AUTHORIZATION_V2,
    LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
};
use serde::Serialize;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[test]
fn local_workers_accept_direct_deriver_peer_messages_over_http(
) -> Result<(), Box<dyn std::error::Error>> {
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

    let ceremony =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")?;
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
fn local_worker_accepts_only_signing_worker_activation_over_http(
) -> Result<(), Box<dyn std::error::Error>> {
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let temp = temp_dir("signing-worker-http")?;
    let signing_worker_url = format!("http://127.0.0.1:{}", free_port()?);
    write_signing_worker_env(&temp, &signing_worker_url)?;

    let mut signing_worker = ChildGuard::spawn(
        binary,
        "signing-worker",
        temp.join(".env.router-ab.signing-worker.local"),
    )?;
    wait_for_health(&signing_worker_url, signing_worker.child_mut())?;

    let ceremony =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")?;
    let (status, body) = post_json_to_path(
        &signing_worker_url,
        LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
        &ceremony.core_http_ceremony.signing_worker_activation,
    )?;
    assert_eq!(status, 200);
    let receipt: LocalSigningWorkerActivationRouteReceiptV1 = serde_json::from_str(&body)?;
    assert_eq!(receipt.receiver_role, LocalServiceRoleV1::SigningWorker);
    assert_eq!(receipt.accepted_opened_share_kind, "x_server_base");
    assert_eq!(receipt.status, "accepted");

    let client_bundle_activation = serde_json::json!({
        "deriver_a_signing_worker_bundle": ceremony.core_http_ceremony.router_response.deriver_a_client_bundle,
        "deriver_b_signing_worker_bundle": ceremony.core_http_ceremony.router_response.deriver_b_client_bundle,
    });
    let (status, body) = post_json_to_path(
        &signing_worker_url,
        LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
        &client_bundle_activation,
    )?;
    assert_eq!(status, 400);
    assert!(body.contains("InvalidLocalServiceConfig"));
    assert!(!body.contains("signing_worker_material_handle"));

    drop(signing_worker);
    let _ = fs::remove_dir_all(temp);
    Ok(())
}

#[test]
fn local_router_normal_signing_forwards_only_to_signing_worker_and_signs_smoke_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    let binary = env!("CARGO_BIN_EXE_router_ab_local_worker");
    let temp = temp_dir("normal-signing-http")?;
    let router_url = format!("http://127.0.0.1:{}", free_port()?);
    let signing_worker_url = format!("http://127.0.0.1:{}", free_port()?);
    write_router_and_signing_worker_env(&temp, &router_url, &signing_worker_url)?;

    let mut router = ChildGuard::spawn(binary, "router", temp.join(".env.router-ab.router.local"))?;
    let mut signing_worker = ChildGuard::spawn(
        binary,
        "signing-worker",
        temp.join(".env.router-ab.signing-worker.local"),
    )?;
    wait_for_health(&router_url, router.child_mut())?;
    wait_for_health(&signing_worker_url, signing_worker.child_mut())?;

    let mut prepare_requests = local_normal_signing_prepare_requests_v2("sign-http")?;
    let unauthenticated_prepare = prepare_requests
        .first()
        .ok_or("normal-signing prepare fixture missing")?;
    let (status, body) = post_json_to_path(
        &router_url,
        LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
        unauthenticated_prepare,
    )?;
    assert_eq!(status, 401);
    assert!(body.contains("Wallet Session authorization is missing"));

    for prepare_request in prepare_requests.drain(..) {
        assert_local_normal_signing_round_trip_v2(&router_url, prepare_request)?;
    }

    drop(router);
    drop(signing_worker);
    let _ = fs::remove_dir_all(temp);
    Ok(())
}

#[test]
fn local_bundled_server_exposes_router_and_signing_worker_paths_from_one_listener(
) -> Result<(), Box<dyn std::error::Error>> {
    let binary = env!("CARGO_BIN_EXE_router_ab_local_bundled");
    let temp = temp_dir("bundled-http")?;
    let bundled_url = format!("http://127.0.0.1:{}", free_port()?);
    write_router_and_signing_worker_env(&temp, &bundled_url, &bundled_url)?;

    let mut bundled = Command::new(binary)
        .arg("--root")
        .arg(&temp)
        .arg("--url")
        .arg(&bundled_url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait_for_health(&bundled_url, &mut bundled)?;

    for prepare_request in local_normal_signing_prepare_requests_v2("bundled-sign-http")? {
        assert_local_normal_signing_round_trip_v2(&bundled_url, prepare_request)?;
    }

    let _ = bundled.kill();
    let _ = bundled.wait();
    let _ = fs::remove_dir_all(temp);
    Ok(())
}

fn assert_local_normal_signing_round_trip_v2(
    router_url: &str,
    prepare_request: RouterAbEd25519NormalSigningPrepareRequestV2,
) -> Result<(), Box<dyn std::error::Error>> {
    let (status, body) = post_json_to_path_with_authorization(
        router_url,
        LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
        LOCAL_ROUTER_NORMAL_SIGNING_WALLET_SESSION_AUTHORIZATION_V2,
        &prepare_request,
    )?;
    assert_eq!(status, 200);
    let prepare_response: NormalSigningRound1PrepareResponseV1 = serde_json::from_str(&body)?;
    let request =
        build_local_normal_signing_finalize_request_v2(prepare_request, prepare_response)?;
    let (status, body) = post_json_to_path_with_authorization(
        router_url,
        LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2,
        LOCAL_ROUTER_NORMAL_SIGNING_WALLET_SESSION_AUTHORIZATION_V2,
        &request,
    )?;
    assert_eq!(status, 200);
    let response: NormalSigningResponseV1 = serde_json::from_str(&body)?;
    assert_eq!(
        response.signature_scheme,
        NormalSigningSignatureSchemeV1::Ed25519V1
    );
    assert_eq!(response.signature.as_bytes().len(), 64);
    Ok(())
}

fn local_normal_signing_prepare_requests_v2(
    request_id_prefix: &str,
) -> Result<Vec<RouterAbEd25519NormalSigningPrepareRequestV2>, Box<dyn std::error::Error>> {
    Ok(vec![
        build_local_normal_signing_near_transaction_prepare_request_v2(
            format!("{request_id_prefix}-near-transaction"),
            &local_unsigned_transaction_borsh_v2(),
        )?,
        build_local_normal_signing_nep413_prepare_request_v2(
            format!("{request_id_prefix}-nep413"),
            "Sign in to the local Router A/B HTTP test",
            "wallet.local.test.near",
            Some("https://local.example/callback".to_owned()),
        )?,
        build_local_normal_signing_delegate_action_prepare_request_v2(
            format!("{request_id_prefix}-delegate-action"),
            &local_delegate_action_borsh_v2(),
        )?,
    ])
}

fn local_unsigned_transaction_borsh_v2() -> Vec<u8> {
    let mut out = Vec::new();
    push_borsh_string(&mut out, "gamma.test.near");
    out.push(0);
    out.extend_from_slice(&[0; 32]);
    out.extend_from_slice(&7_u64.to_le_bytes());
    push_borsh_string(&mut out, "local-router.test.near");
    out.extend_from_slice(&[0x44; 32]);
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.push(2);
    push_borsh_string(&mut out, "transfer");
    push_borsh_bytes(&mut out, br#"{"amount":"1"}"#);
    out.extend_from_slice(&30_000_000_000_000_u64.to_le_bytes());
    out.extend_from_slice(&0_u128.to_le_bytes());
    out
}

fn local_delegate_action_borsh_v2() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_073_742_190_u32.to_le_bytes());
    push_borsh_string(&mut out, "gamma.test.near");
    push_borsh_string(&mut out, "local-router.test.near");
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.push(3);
    out.extend_from_slice(&1_u128.to_le_bytes());
    out.extend_from_slice(&7_u64.to_le_bytes());
    out.extend_from_slice(&2_000_000_u64.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&[0; 32]);
    out
}

fn push_borsh_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_borsh_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
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
    let plan = local_env_materialization_plan_v1(b"local-worker-http-peer-test-seed")?;
    fs::create_dir_all(root)?;
    for file in plan.files {
        if !matches!(
            file.role,
            LocalServiceRoleV1::DeriverA | LocalServiceRoleV1::DeriverB
        ) {
            continue;
        }
        let contents = file
            .contents
            .replace("http://127.0.0.1:8788", deriver_a_url)
            .replace("http://127.0.0.1:8789", deriver_b_url);
        fs::write(root.join(file.path), contents)?;
    }
    Ok(())
}

fn write_signing_worker_env(
    root: &Path,
    signing_worker_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = local_env_materialization_plan_v1(b"local-worker-http-signing-worker-test-seed")?;
    fs::create_dir_all(root)?;
    for file in plan.files {
        if file.role != LocalServiceRoleV1::SigningWorker {
            continue;
        }
        let contents = file
            .contents
            .replace("http://127.0.0.1:8790", signing_worker_url);
        fs::write(root.join(file.path), contents)?;
    }
    Ok(())
}

fn write_router_and_signing_worker_env(
    root: &Path,
    router_url: &str,
    signing_worker_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = local_env_materialization_plan_v1(b"local-worker-http-normal-signing-test-seed")?;
    fs::create_dir_all(root)?;
    for file in plan.files {
        if !matches!(
            file.role,
            LocalServiceRoleV1::Router | LocalServiceRoleV1::SigningWorker
        ) {
            continue;
        }
        let contents = file
            .contents
            .replace("http://127.0.0.1:8787", router_url)
            .replace("http://127.0.0.1:8790", signing_worker_url);
        fs::write(root.join(file.path), contents)?;
    }
    Ok(())
}

fn post_json_to_path<T: Serialize>(
    base_url: &str,
    path: &str,
    body: &T,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    post_json_to_path_with_headers(base_url, path, body, &[])
}

fn post_json_to_path_with_authorization<T: Serialize>(
    base_url: &str,
    path: &str,
    authorization: &str,
    body: &T,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    post_json_to_path_with_headers(base_url, path, body, &[("authorization", authorization)])
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

fn free_port() -> Result<u16, Box<dyn std::error::Error>> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn temp_dir(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path =
        std::env::temp_dir().join(format!("router-ab-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path)?;
    Ok(path)
}
