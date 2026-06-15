#[path = "local_dev_process/mod.rs"]
mod local_dev_process;

use local_dev_process::{
    ephemeral_root, free_port_url, normalize_root, post_json_to_path,
    post_json_to_path_with_authorization, resolve_bundled_binary, resolve_worker_binary,
    wait_for_existing_health, wait_for_managed_health, write_materialized_envs_with_urls,
    LocalWorkerSpawnReceipt, LocalWorkerUrls, ManagedChild, LOCAL_WORKER_PROCESS_SPECS,
};
use router_ab_core::{
    LocalServiceRoleV1, NormalSigningResponseV1, NormalSigningRound1PrepareResponseV1,
    NormalSigningSignatureSchemeV1, Role, RouterAbEd25519NormalSigningPrepareRequestV2,
};
use router_ab_dev::{
    build_local_normal_signing_delegate_action_prepare_request_v2,
    build_local_normal_signing_finalize_request_v2,
    build_local_normal_signing_near_transaction_prepare_request_v2,
    build_local_normal_signing_nep413_prepare_request_v2,
    run_example_local_router_ab_hss_dev_http_ceremony_v1, LocalDeriverPeerMessageReceiptV1,
    LocalRouterSetupSmokeRequestV1, LocalSigningWorkerActivationRouteReceiptV1,
    LOCAL_DERIVER_A_PEER_PATH_V1, LOCAL_DERIVER_B_PEER_PATH_V1,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2, LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
    LOCAL_ROUTER_NORMAL_SIGNING_WALLET_SESSION_AUTHORIZATION_V2,
    LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1, LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
};
use serde::Serialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeOptions {
    root: PathBuf,
    ephemeral: bool,
    keep_ephemeral_root: bool,
    report_path: Option<PathBuf>,
    topology: SmokeTopology,
    bundled_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmokeTopology {
    FourWorker,
    Bundled,
}

impl SmokeTopology {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "four-worker" => Ok(Self::FourWorker),
            "bundled" => Ok(Self::Bundled),
            _ => Err(format!(
                "unknown topology {value}; expected four-worker or bundled"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::FourWorker => "four-worker",
            Self::Bundled => "bundled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SmokeSummary {
    root: String,
    mode: String,
    topology: &'static str,
    urls: LocalWorkerUrls,
    spawned_processes: Vec<LocalWorkerSpawnReceipt>,
    setup_status: String,
    deriver_b_peer_status: String,
    deriver_a_peer_status: String,
    signing_worker_activation_status: String,
    normal_signing_status: String,
    deriver_a_normal_signing_requests: u32,
    deriver_b_normal_signing_requests: u32,
    setup_elapsed_ms: u64,
    deriver_b_peer_elapsed_ms: u64,
    deriver_a_peer_elapsed_ms: u64,
    signing_worker_activation_elapsed_ms: u64,
    normal_signing_elapsed_ms: u64,
    total_elapsed_ms: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = match parse_args(env::args().skip(1)) {
        Ok(options) => options,
        Err(message) if message == usage() => {
            println!("{message}");
            return Ok(());
        }
        Err(message) => return Err(message.into()),
    };
    if options.ephemeral {
        run_ephemeral_smoke(options)
    } else {
        let root = normalize_root(options.root)?;
        let urls = existing_urls_for_topology(&root, options.topology, options.bundled_url)?;
        wait_for_topology_health(options.topology, &urls)?;
        let summary = run_smoke(&root, "existing", options.topology, urls, Vec::new())?;
        emit_summary(&summary, options.report_path.as_deref())?;
        Ok(())
    }
}

fn run_ephemeral_smoke(options: SmokeOptions) -> Result<(), Box<dyn std::error::Error>> {
    let root = if options.root == PathBuf::from(".") {
        ephemeral_root("local-smoke")?
    } else {
        normalize_root(options.root)?
    };
    let (children, urls, spawned_processes) = match options.topology {
        SmokeTopology::FourWorker => spawn_ephemeral_four_worker_topology(&root)?,
        SmokeTopology::Bundled => {
            spawn_ephemeral_bundled_topology(&root, options.bundled_url.as_deref())?
        }
    };
    let summary = run_smoke(
        &root,
        "ephemeral",
        options.topology,
        urls,
        spawned_processes,
    )?;
    emit_summary(&summary, options.report_path.as_deref())?;
    drop(children);
    if !options.keep_ephemeral_root {
        let _ = fs::remove_dir_all(&root);
    }
    Ok(())
}

fn existing_urls_for_topology(
    root: &Path,
    topology: SmokeTopology,
    bundled_url: Option<String>,
) -> Result<LocalWorkerUrls, Box<dyn std::error::Error>> {
    match topology {
        SmokeTopology::FourWorker => Ok(LocalWorkerUrls::from_env(root)?),
        SmokeTopology::Bundled => {
            let router_url = match bundled_url {
                Some(url) => url,
                None => LocalWorkerUrls::from_env(root)?.router,
            };
            Ok(LocalWorkerUrls::bundled(router_url))
        }
    }
}

fn wait_for_topology_health(
    topology: SmokeTopology,
    urls: &LocalWorkerUrls,
) -> Result<(), Box<dyn std::error::Error>> {
    match topology {
        SmokeTopology::FourWorker => {
            for url in [
                &urls.router,
                &urls.deriver_a,
                &urls.deriver_b,
                &urls.signing_worker,
            ] {
                wait_for_existing_health(url)?;
            }
            Ok(())
        }
        SmokeTopology::Bundled => wait_for_existing_health(&urls.router),
    }
}

type ManagedTopology = (
    Vec<(ManagedChild, LocalWorkerSpawnReceipt)>,
    LocalWorkerUrls,
    Vec<LocalWorkerSpawnReceipt>,
);

fn spawn_ephemeral_four_worker_topology(
    root: &Path,
) -> Result<ManagedTopology, Box<dyn std::error::Error>> {
    let urls = LocalWorkerUrls {
        router: free_port_url()?,
        deriver_a: free_port_url()?,
        deriver_b: free_port_url()?,
        signing_worker: free_port_url()?,
    };
    write_materialized_envs_with_urls(root, b"router-ab-local-smoke-ci-seed", &urls)?;
    let worker_binary = resolve_worker_binary()?;
    let mut children: Vec<(ManagedChild, LocalWorkerSpawnReceipt)> = Vec::new();
    for spec in LOCAL_WORKER_PROCESS_SPECS {
        let (mut child, receipt) = ManagedChild::spawn(&worker_binary, root, *spec)?;
        wait_for_managed_health(&receipt.url, child.child_mut())?;
        children.push((child, receipt));
    }
    let spawned_processes = children
        .iter()
        .map(|(_, receipt)| receipt.clone())
        .collect::<Vec<_>>();
    Ok((children, urls, spawned_processes))
}

fn spawn_ephemeral_bundled_topology(
    root: &Path,
    bundled_url: Option<&str>,
) -> Result<ManagedTopology, Box<dyn std::error::Error>> {
    let url = match bundled_url {
        Some(url) => url.to_owned(),
        None => free_port_url()?,
    };
    let urls = LocalWorkerUrls::bundled(url.clone());
    write_materialized_envs_with_urls(root, b"router-ab-local-smoke-ci-seed", &urls)?;
    let bundled_binary = resolve_bundled_binary()?;
    let (mut child, receipt) = ManagedChild::spawn_bundled(&bundled_binary, root, &url)?;
    wait_for_managed_health(&receipt.url, child.child_mut())?;
    Ok((vec![(child, receipt.clone())], urls, vec![receipt]))
}

fn run_smoke(
    root: &std::path::Path,
    mode: &str,
    topology: SmokeTopology,
    urls: LocalWorkerUrls,
    spawned_processes: Vec<LocalWorkerSpawnReceipt>,
) -> Result<SmokeSummary, Box<dyn std::error::Error>> {
    let total_start = Instant::now();
    let setup_request = LocalRouterSetupSmokeRequestV1::new("derived-gamma", "split-epoch-1")?;
    let setup_start = Instant::now();
    let (setup_status, setup_body) = post_json_to_path(
        &urls.router,
        LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1,
        &setup_request,
    )?;
    if setup_status != 200 {
        return Err(
            format!("Router setup smoke returned HTTP {setup_status}: {setup_body}").into(),
        );
    }
    let setup_value: serde_json::Value = serde_json::from_str(&setup_body)?;
    if setup_value
        .get("router_response")
        .and_then(|value| value.get("deriver_a_client_bundle"))
        .is_none()
    {
        return Err("Router setup smoke response did not include client-output bundles".into());
    }
    let setup_elapsed_ms = elapsed_ms(setup_start);

    let ceremony =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")?;
    let deriver_b_start = Instant::now();
    let (deriver_b_status, deriver_b_body) = post_json_to_path(
        &urls.deriver_b,
        LOCAL_DERIVER_B_PEER_PATH_V1,
        &ceremony
            .core_http_ceremony
            .deriver_a_peer_request
            .envelope
            .message,
    )?;
    if deriver_b_status != 200 {
        return Err(format!(
            "Deriver B peer smoke returned HTTP {deriver_b_status}: {deriver_b_body}"
        )
        .into());
    }
    let deriver_b_receipt: LocalDeriverPeerMessageReceiptV1 =
        serde_json::from_str(&deriver_b_body)?;
    if deriver_b_receipt.receiver_role != LocalServiceRoleV1::DeriverB
        || deriver_b_receipt.accepted_from_role != Role::SignerA
        || deriver_b_receipt.status != "accepted"
    {
        return Err("Deriver B peer smoke receipt had the wrong role binding".into());
    }
    let deriver_b_peer_elapsed_ms = elapsed_ms(deriver_b_start);

    let deriver_a_start = Instant::now();
    let (deriver_a_status, deriver_a_body) = post_json_to_path(
        &urls.deriver_a,
        LOCAL_DERIVER_A_PEER_PATH_V1,
        &ceremony
            .core_http_ceremony
            .deriver_b_peer_request
            .envelope
            .message,
    )?;
    if deriver_a_status != 200 {
        return Err(format!(
            "Deriver A peer smoke returned HTTP {deriver_a_status}: {deriver_a_body}"
        )
        .into());
    }
    let deriver_a_receipt: LocalDeriverPeerMessageReceiptV1 =
        serde_json::from_str(&deriver_a_body)?;
    if deriver_a_receipt.receiver_role != LocalServiceRoleV1::DeriverA
        || deriver_a_receipt.accepted_from_role != Role::SignerB
        || deriver_a_receipt.status != "accepted"
    {
        return Err("Deriver A peer smoke receipt had the wrong role binding".into());
    }
    let deriver_a_peer_elapsed_ms = elapsed_ms(deriver_a_start);

    let activation_start = Instant::now();
    let (activation_status, activation_body) = post_json_to_path(
        &urls.signing_worker,
        LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
        &ceremony.core_http_ceremony.signing_worker_activation,
    )?;
    if activation_status != 200 {
        return Err(format!(
            "SigningWorker activation smoke returned HTTP {activation_status}: {activation_body}"
        )
        .into());
    }
    let activation_receipt: LocalSigningWorkerActivationRouteReceiptV1 =
        serde_json::from_str(&activation_body)?;
    if activation_receipt.receiver_role != LocalServiceRoleV1::SigningWorker
        || activation_receipt.accepted_opened_share_kind != "x_server_base"
        || activation_receipt.status != "accepted"
    {
        return Err("SigningWorker activation smoke receipt had the wrong role binding".into());
    }
    let signing_worker_activation_elapsed_ms = elapsed_ms(activation_start);

    let normal_prepare_requests = vec![
        build_local_normal_signing_near_transaction_prepare_request_v2(
            "sign-smoke-near-transaction-1",
            &local_unsigned_transaction_borsh_v2(),
        )?,
        build_local_normal_signing_nep413_prepare_request_v2(
            "sign-smoke-nep413-1",
            "Sign in to the local Router A/B smoke",
            "wallet.local.test.near",
            Some("https://local.example/callback".to_owned()),
        )?,
        build_local_normal_signing_delegate_action_prepare_request_v2(
            "sign-smoke-delegate-action-1",
            &local_delegate_action_borsh_v2(),
        )?,
    ];
    let normal_start = Instant::now();
    let mut normal_response = None;
    for normal_prepare_request in normal_prepare_requests {
        normal_response = Some(run_normal_signing_smoke_request(
            &urls.router,
            normal_prepare_request,
        )?);
    }
    let normal_response =
        normal_response.ok_or("Router normal-signing smoke did not execute any requests")?;
    let normal_signing_elapsed_ms = elapsed_ms(normal_start);

    Ok(SmokeSummary {
        root: root.display().to_string(),
        mode: mode.to_owned(),
        topology: topology.as_str(),
        urls,
        spawned_processes,
        setup_status: "accepted".to_owned(),
        deriver_b_peer_status: deriver_b_receipt.status,
        deriver_a_peer_status: deriver_a_receipt.status,
        signing_worker_activation_status: activation_receipt.status,
        normal_signing_status: normal_response.signature_scheme.as_str().to_owned(),
        deriver_a_normal_signing_requests: 0,
        deriver_b_normal_signing_requests: 0,
        setup_elapsed_ms,
        deriver_b_peer_elapsed_ms,
        deriver_a_peer_elapsed_ms,
        signing_worker_activation_elapsed_ms,
        normal_signing_elapsed_ms,
        total_elapsed_ms: elapsed_ms(total_start),
    })
}

fn run_normal_signing_smoke_request(
    router_url: &str,
    normal_prepare_request: RouterAbEd25519NormalSigningPrepareRequestV2,
) -> Result<NormalSigningResponseV1, Box<dyn std::error::Error>> {
    let (prepare_status, prepare_body) = post_json_to_path_with_authorization(
        router_url,
        LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
        LOCAL_ROUTER_NORMAL_SIGNING_WALLET_SESSION_AUTHORIZATION_V2,
        &normal_prepare_request,
    )?;
    if prepare_status != 200 {
        return Err(format!(
            "Router normal-signing prepare expected HTTP 200, received {prepare_status}: {prepare_body}"
        )
        .into());
    }
    let prepare_response: NormalSigningRound1PrepareResponseV1 =
        serde_json::from_str(&prepare_body)?;
    let normal_request =
        build_local_normal_signing_finalize_request_v2(normal_prepare_request, prepare_response)?;
    let (normal_status, normal_body) = post_json_to_path_with_authorization(
        router_url,
        LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2,
        LOCAL_ROUTER_NORMAL_SIGNING_WALLET_SESSION_AUTHORIZATION_V2,
        &normal_request,
    )?;
    if normal_status != 200 {
        return Err(format!(
            "Router normal-signing smoke expected HTTP 200, received {normal_status}: {normal_body}"
        )
        .into());
    }
    let normal_response: NormalSigningResponseV1 = serde_json::from_str(&normal_body)?;
    if normal_response.signature_scheme != NormalSigningSignatureSchemeV1::Ed25519V1
        || normal_response.signature.as_bytes().len() != 64
    {
        return Err("Router normal-signing smoke did not return a SigningWorker signature".into());
    }
    Ok(normal_response)
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
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

fn emit_summary(
    summary: &SmokeSummary,
    report_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(summary)?;
    if let Some(path) = report_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{json}\n"))?;
    }
    println!("{json}");
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<SmokeOptions, String> {
    let mut root = PathBuf::from(".");
    let mut ephemeral = false;
    let mut keep_ephemeral_root = false;
    let mut report_path = None;
    let mut topology = SmokeTopology::FourWorker;
    let mut bundled_url = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {}
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("--root requires a path".to_owned());
                };
                root = PathBuf::from(value);
            }
            "--ephemeral" => {
                ephemeral = true;
            }
            "--keep-ephemeral-root" => {
                keep_ephemeral_root = true;
            }
            "--out" => {
                let Some(value) = iter.next() else {
                    return Err("--out requires a path".to_owned());
                };
                report_path = Some(PathBuf::from(value));
            }
            "--topology" => {
                let Some(value) = iter.next() else {
                    return Err("--topology requires four-worker or bundled".to_owned());
                };
                topology = SmokeTopology::parse(&value)?;
            }
            "--url" => {
                let Some(value) = iter.next() else {
                    return Err("--url requires an http://host:port value".to_owned());
                };
                bundled_url = Some(value);
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            _ => {
                return Err(format!("unknown argument {arg}\n{}", usage()));
            }
        }
    }
    if bundled_url.is_some() && topology != SmokeTopology::Bundled {
        return Err("--url is only valid with --topology bundled".to_owned());
    }
    Ok(SmokeOptions {
        root,
        ephemeral,
        keep_ephemeral_root,
        report_path,
        topology,
        bundled_url,
    })
}

fn usage() -> String {
    "usage: router_ab_local_smoke [--root <path>] [--ephemeral] [--keep-ephemeral-root] [--topology four-worker|bundled] [--url http://127.0.0.1:<port>] [--out <path>]".to_owned()
}
