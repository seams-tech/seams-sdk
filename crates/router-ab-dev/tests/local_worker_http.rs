use router_ab_core::{LocalHttpPathV1, LocalServiceRoleV1};
use router_ab_dev::{
    local_env_materialization_plan_v1, run_example_local_router_ab_hss_dev_http_ceremony_v1,
    LocalDeriverPeerMessageReceiptV1, LocalHttpServiceBindingClientV1,
    LocalRouterNormalSigningSmokeResponseV1, LocalSigningWorkerActivationRouteReceiptV1,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1, LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
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
    assert_eq!(receipt.accepted_opened_share_kind, "x_relayer_base");
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

    let request = serde_json::json!({
        "request_id": "sign-smoke-1",
        "account_id": "gamma.test.near",
        "session_id": "session-1",
        "signing_payload_hex": hex::encode(b"router-ab local worker HTTP test payload")
    });
    let (status, body) =
        post_json_to_path(&router_url, LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1, &request)?;
    assert_eq!(status, 200);
    let response: LocalRouterNormalSigningSmokeResponseV1 = serde_json::from_str(&body)?;
    assert_eq!(response.status, "signed");
    assert_eq!(
        response.forwarded_to_role,
        LocalServiceRoleV1::SigningWorker
    );
    assert_eq!(response.signing_worker_status, "signed");
    assert_eq!(response.signature_scheme, "local_dev_ed25519_v1");
    assert_eq!(response.signature_hex.len(), 128);
    assert_eq!(response.verifying_key_hex.len(), 64);
    assert_eq!(response.deriver_a_request_count, 0);
    assert_eq!(response.deriver_b_request_count, 0);

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

    let request = serde_json::json!({
        "request_id": "bundled-sign-smoke-1",
        "account_id": "gamma.test.near",
        "session_id": "session-1",
        "signing_payload_hex": hex::encode(b"router-ab bundled server HTTP test payload")
    });
    let (status, body) =
        post_json_to_path(&bundled_url, LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1, &request)?;
    assert_eq!(status, 200);
    let response: LocalRouterNormalSigningSmokeResponseV1 = serde_json::from_str(&body)?;
    assert_eq!(response.status, "signed");
    assert_eq!(
        response.forwarded_to_role,
        LocalServiceRoleV1::SigningWorker
    );
    assert_eq!(response.signature_scheme, "local_dev_ed25519_v1");
    assert_eq!(response.deriver_a_request_count, 0);
    assert_eq!(response.deriver_b_request_count, 0);

    let _ = bundled.kill();
    let _ = bundled.wait();
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
    let authority = base_url
        .strip_prefix("http://")
        .ok_or("post URL must use http://")?;
    let body = serde_json::to_vec(body)?;
    let mut stream = TcpStream::connect(authority)?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
