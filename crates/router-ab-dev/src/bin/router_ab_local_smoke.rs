#[path = "local_dev_process/mod.rs"]
mod local_dev_process;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ecdsa_hss::ECDSA_HSS_PARTICIPANT_IDS;
use local_dev_process::{
    normalize_root, post_json_to_path, post_json_to_path_with_authorization,
    post_json_to_path_with_headers, read_worker_config, wait_for_existing_health,
    LocalWorkerSpawnReceipt, LocalWorkerUrls, LOCAL_WORKER_PROCESS_SPECS,
};
use router_ab_core::{
    LocalServiceRoleV1, NormalSigningResponseV1, NormalSigningRound1PrepareResponseV1,
    NormalSigningSignatureSchemeV1, Role, RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1, RouterAbEcdsaHssEvmDigestSigningRequestV1,
    RouterAbEcdsaHssEvmDigestSigningResponseV1, RouterAbEcdsaHssNormalSigningScopeV1,
    RouterAbEcdsaHssPublicIdentityV1, RouterAbEcdsaHssSignatureSchemeV1,
    RouterAbEcdsaHssStableKeyContextV1, RouterAbEd25519NormalSigningPrepareRequestV2,
    ServerIdentityV1,
};
use router_ab_dev::{
    build_local_normal_signing_delegate_action_prepare_request_v2,
    build_local_normal_signing_finalize_request_v2,
    build_local_normal_signing_near_transaction_prepare_request_v2,
    build_local_normal_signing_nep413_prepare_request_v2,
    build_local_router_ed25519_key_store_seed_v1, local_normal_signing_smoke_fixture_for_scope_v1,
    local_router_ab_internal_service_auth_secret_v1,
    run_example_local_router_ab_hss_dev_http_ceremony_v1, LocalDeriverPeerMessageReceiptV1,
    LocalNormalSigningSmokeFixtureV1, LocalRouterEd25519KeyStoreSeedV1,
    LocalSigningWorkerActivationRouteReceiptV1,
    LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1,
    LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1, LocalWorkerRoleConfigV1,
    LOCAL_DERIVER_A_PEER_PATH_V1, LOCAL_DERIVER_B_PEER_PATH_V1,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1, LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH_V1,
    LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1, LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2,
    LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2, LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
    LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signer_core::secp256k1::{
    map_additive_share_to_threshold_signatures_share_2p, secp256k1_private_key_32_to_public_key_33,
    secp256k1_public_key_33_to_ethereum_address_20,
};
use signer_core::threshold_ecdsa::{
    threshold_ecdsa_compute_signature_share, ThresholdEcdsaPresignSession,
};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeOptions {
    root: PathBuf,
    report_path: Option<PathBuf>,
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
    normal_signing_evidence_kind: String,
    ecdsa_hss_live_http_route_dispatch_status: String,
    ecdsa_hss_pool_fill_status: String,
    ecdsa_hss_prepare_status: String,
    ecdsa_hss_finalize_status: String,
    ecdsa_hss_replay_rejection_status: String,
    ecdsa_hss_signature_scheme: String,
    ecdsa_hss_evidence_kind: String,
    deriver_a_normal_signing_requests: u32,
    deriver_b_normal_signing_requests: u32,
    setup_elapsed_ms: u64,
    deriver_b_peer_elapsed_ms: u64,
    deriver_a_peer_elapsed_ms: u64,
    signing_worker_activation_elapsed_ms: u64,
    normal_signing_elapsed_ms: u64,
    ecdsa_hss_live_http_elapsed_ms: u64,
    total_elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EcdsaHssSmokeResult {
    pool_fill_status: String,
    prepare_status: String,
    finalize_status: String,
    replay_rejection_status: String,
    signature_scheme: String,
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
    let root = normalize_root(options.root)?;
    let urls = existing_urls(&root)?;
    wait_for_topology_health(&urls)?;
    let summary = run_smoke(&root, "existing", urls, Vec::new())?;
    emit_summary(&summary, options.report_path.as_deref())?;
    Ok(())
}

fn existing_urls(root: &Path) -> Result<LocalWorkerUrls, Box<dyn std::error::Error>> {
    Ok(LocalWorkerUrls::from_env(root)?)
}

fn wait_for_topology_health(urls: &LocalWorkerUrls) -> Result<(), Box<dyn std::error::Error>> {
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

fn run_smoke(
    root: &std::path::Path,
    mode: &str,
    urls: LocalWorkerUrls,
    spawned_processes: Vec<LocalWorkerSpawnReceipt>,
) -> Result<SmokeSummary, Box<dyn std::error::Error>> {
    let total_start = Instant::now();
    let setup_start = Instant::now();
    let ceremony =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")?;
    ceremony
        .core_http_ceremony
        .router_response
        .validate()
        .map_err(|error| format!("Router setup smoke response failed validation: {error}"))?;
    let setup_elapsed_ms = elapsed_ms(setup_start);

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
            &local_normal_signing_smoke_fixture()?,
            "sign-smoke-near-transaction-1",
            &local_unsigned_transaction_borsh_v2(),
        )?,
        build_local_normal_signing_nep413_prepare_request_v2(
            &local_normal_signing_smoke_fixture()?,
            "sign-smoke-nep413-1",
            "Sign in to the local Router A/B smoke",
            "wallet.local.test.near",
            Some("https://local.example/callback".to_owned()),
        )?,
        build_local_normal_signing_delegate_action_prepare_request_v2(
            &local_normal_signing_smoke_fixture()?,
            "sign-smoke-delegate-action-1",
            &local_delegate_action_borsh_v2(),
        )?,
    ];
    let normal_start = Instant::now();
    let local_ed25519_seed = build_local_router_ed25519_key_store_seed_v1(
        &local_normal_signing_smoke_fixture()?,
        "localhost",
        "v1",
    )?;
    seed_local_ed25519_router_key_store_for_existing_topology(mode, &local_ed25519_seed)?;
    let local_ed25519_relayer_key_id = local_ed25519_seed.relayer_key_id.clone();
    let mut normal_response = None;
    for normal_prepare_request in normal_prepare_requests {
        normal_response = Some(run_normal_signing_smoke_request(
            &urls.router,
            &local_ed25519_relayer_key_id,
            normal_prepare_request,
        )?);
    }
    let normal_response =
        normal_response.ok_or("Router normal-signing smoke did not execute any requests")?;
    let normal_signing_elapsed_ms = elapsed_ms(normal_start);

    let ecdsa_start = Instant::now();
    let ecdsa_result = run_ecdsa_hss_live_http_smoke(root, &urls)?;
    let ecdsa_hss_live_http_elapsed_ms = elapsed_ms(ecdsa_start);

    Ok(SmokeSummary {
        root: root.display().to_string(),
        mode: mode.to_owned(),
        topology: "main-router",
        urls,
        spawned_processes,
        setup_status: "accepted".to_owned(),
        deriver_b_peer_status: deriver_b_receipt.status,
        deriver_a_peer_status: deriver_a_receipt.status,
        signing_worker_activation_status: activation_receipt.status,
        normal_signing_status: normal_response.signature_scheme.as_str().to_owned(),
        normal_signing_evidence_kind: "live_http_route_dispatch".to_owned(),
        ecdsa_hss_live_http_route_dispatch_status: "accepted".to_owned(),
        ecdsa_hss_pool_fill_status: ecdsa_result.pool_fill_status,
        ecdsa_hss_prepare_status: ecdsa_result.prepare_status,
        ecdsa_hss_finalize_status: ecdsa_result.finalize_status,
        ecdsa_hss_replay_rejection_status: ecdsa_result.replay_rejection_status,
        ecdsa_hss_signature_scheme: ecdsa_result.signature_scheme,
        ecdsa_hss_evidence_kind: "live_http_route_dispatch".to_owned(),
        deriver_a_normal_signing_requests: 0,
        deriver_b_normal_signing_requests: 0,
        setup_elapsed_ms,
        deriver_b_peer_elapsed_ms,
        deriver_a_peer_elapsed_ms,
        signing_worker_activation_elapsed_ms,
        normal_signing_elapsed_ms,
        ecdsa_hss_live_http_elapsed_ms,
        total_elapsed_ms: elapsed_ms(total_start),
    })
}

fn run_normal_signing_smoke_request(
    router_url: &str,
    relayer_key_id: &str,
    normal_prepare_request: RouterAbEd25519NormalSigningPrepareRequestV2,
) -> Result<NormalSigningResponseV1, Box<dyn std::error::Error>> {
    let authorization = local_smoke_ed25519_wallet_session_authorization_v2(
        &normal_prepare_request,
        relayer_key_id,
    )?;
    let (prepare_status, prepare_body) = post_json_to_path_with_authorization(
        router_url,
        LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
        authorization.as_str(),
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
    let fixture = local_normal_signing_smoke_fixture_for_scope_v1(&normal_prepare_request.scope)?;
    let normal_request = build_local_normal_signing_finalize_request_v2(
        &fixture,
        normal_prepare_request,
        prepare_response,
    )?;
    let (normal_status, normal_body) = post_json_to_path_with_authorization(
        router_url,
        LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2,
        authorization.as_str(),
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

fn run_ecdsa_hss_live_http_smoke(
    root: &Path,
    urls: &LocalWorkerUrls,
) -> Result<EcdsaHssSmokeResult, Box<dyn std::error::Error>> {
    let signing_worker_identity = signing_worker_identity_from_root(root)?;
    let fixture = local_ecdsa_hss_fixture(signing_worker_identity)?;
    let authorization = local_smoke_ecdsa_hss_wallet_session_authorization_v1(&fixture)?;
    let pool_put = LocalSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
        scope: fixture.scope.clone(),
        server_presignature_id: fixture.server_presignature_id.clone(),
        server_big_r33_b64u: b64u(&fixture.server_big_r33),
        server_k_share32_b64u: b64u(&fixture.server_k_share32),
        server_sigma_share32_b64u: b64u(&fixture.server_sigma_share32),
        expires_at_ms: fixture.expires_at_ms,
    };
    let internal_service_auth = local_router_ab_internal_service_auth_secret_v1();
    let (pool_status, pool_body) = post_json_to_path_with_headers(
        &urls.signing_worker,
        LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
        &pool_put,
        &[(
            LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
            internal_service_auth.as_str(),
        )],
    )?;
    if pool_status != 200 {
        return Err(format!(
            "SigningWorker ECDSA-HSS pool-fill expected HTTP 200, received {pool_status}: {pool_body}"
        )
        .into());
    }
    let pool_receipt: LocalSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1 =
        serde_json::from_str(&pool_body)?;
    if !pool_receipt.stored
        || pool_receipt.server_presignature_id != fixture.server_presignature_id
        || pool_receipt.server_big_r33_b64u != b64u(&fixture.server_big_r33)
    {
        return Err("SigningWorker ECDSA-HSS pool-fill receipt did not match request".into());
    }

    let prepare_request = RouterAbEcdsaHssEvmDigestSigningRequestV1::new(
        fixture.scope.clone(),
        "local-ecdsa-hss-smoke-sign-1",
        fixture.server_presignature_id.clone(),
        fixture.expires_at_ms,
        b64u(&fixture.signing_digest32),
    )?;
    let (prepare_status, prepare_body) = post_json_to_path_with_authorization(
        &urls.router,
        LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
        authorization.as_str(),
        &prepare_request,
    )?;
    if prepare_status != 200 {
        return Err(format!(
            "Router ECDSA-HSS prepare expected HTTP 200, received {prepare_status}: {prepare_body}"
        )
        .into());
    }
    let prepare_response: RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1 =
        serde_json::from_str(&prepare_body)?;
    prepare_response.validate_for_request(&prepare_request)?;

    let entropy32: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&prepare_response.rerandomization_entropy32_b64u)?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("ECDSA-HSS entropy length {}", bytes.len()))?;
    let participant_ids = ECDSA_HSS_PARTICIPANT_IDS.map(u32::from);
    let client_signature_share32 = threshold_ecdsa_compute_signature_share(
        &participant_ids,
        1,
        &fixture.threshold_public_key33,
        &fixture.server_big_r33,
        &fixture.client_k_share32,
        &fixture.client_sigma_share32,
        &fixture.signing_digest32,
        &entropy32,
    )?;
    let finalize_request = RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1::new(
        fixture.scope,
        prepare_request.request_id,
        prepare_request.expires_at_ms,
        prepare_request.signing_digest_b64u,
        prepare_response.server_presignature_id,
        b64u(&client_signature_share32),
    )?;
    let (finalize_status, finalize_body) = post_json_to_path_with_authorization(
        &urls.router,
        LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH_V1,
        authorization.as_str(),
        &finalize_request,
    )?;
    if finalize_status != 200 {
        return Err(format!(
            "Router ECDSA-HSS finalize expected HTTP 200, received {finalize_status}: {finalize_body}"
        )
        .into());
    }
    let signing_response: RouterAbEcdsaHssEvmDigestSigningResponseV1 =
        serde_json::from_str(&finalize_body)?;
    signing_response.validate()?;
    if signing_response.request_digest != finalize_request.request_digest()?
        || signing_response.signature65_b64u.as_bytes().len() != 87
    {
        return Err("Router ECDSA-HSS finalize response did not bind request".into());
    }

    let (replay_status, replay_body) = post_json_to_path_with_authorization(
        &urls.router,
        LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH_V1,
        authorization.as_str(),
        &finalize_request,
    )?;
    if replay_status != 400 || !replay_body.contains("prepared presignature is not available") {
        return Err(format!(
            "Router ECDSA-HSS one-use replay expected HTTP 400 prepared-presignature rejection, received {replay_status}: {replay_body}"
        )
        .into());
    }

    Ok(EcdsaHssSmokeResult {
        pool_fill_status: "http_200_stored".to_owned(),
        prepare_status: "http_200_bound".to_owned(),
        finalize_status: "http_200_signature".to_owned(),
        replay_rejection_status: "http_400_one_use_replay_rejected".to_owned(),
        signature_scheme: ecdsa_hss_signature_scheme_label(signing_response.signature_scheme)
            .to_owned(),
    })
}

fn signing_worker_identity_from_root(
    root: &Path,
) -> Result<ServerIdentityV1, Box<dyn std::error::Error>> {
    let config = read_worker_config(root, LOCAL_WORKER_PROCESS_SPECS[2])?;
    let LocalWorkerRoleConfigV1::SigningWorker(config) = config else {
        return Err("expected signing worker config".into());
    };
    Ok(ServerIdentityV1::new(
        config.signing_worker_id,
        config.signing_worker_key_epoch,
        config.server_output_hpke_public_key,
    )?)
}

fn ecdsa_hss_signature_scheme_label(scheme: RouterAbEcdsaHssSignatureSchemeV1) -> &'static str {
    match scheme {
        RouterAbEcdsaHssSignatureSchemeV1::EcdsaSecp256k1RecoverableV1 => {
            "ecdsa_secp256k1_recoverable_v1"
        }
    }
}

struct LocalEcdsaHssFixture {
    scope: RouterAbEcdsaHssNormalSigningScopeV1,
    server_presignature_id: String,
    threshold_public_key33: [u8; 33],
    server_big_r33: [u8; 33],
    server_k_share32: [u8; 32],
    server_sigma_share32: [u8; 32],
    client_k_share32: [u8; 32],
    client_sigma_share32: [u8; 32],
    signing_digest32: [u8; 32],
    expires_at_ms: u64,
}

fn local_ecdsa_hss_fixture(
    signing_worker: ServerIdentityV1,
) -> Result<LocalEcdsaHssFixture, Box<dyn std::error::Error>> {
    let client_additive_share32 = scalar_be32(1);
    let server_additive_share32 = scalar_be32(1);
    let client_threshold_share =
        map_additive_share_to_threshold_signatures_share_2p(&client_additive_share32, 1)?;
    let client_threshold_share32: [u8; 32] = client_threshold_share
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("client threshold share length {}", bytes.len()))?;
    let server_threshold_share =
        map_additive_share_to_threshold_signatures_share_2p(&server_additive_share32, 2)?;
    let server_threshold_share32: [u8; 32] = server_threshold_share
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("server threshold share length {}", bytes.len()))?;
    let threshold_secret32 = scalar_be32(2);
    let threshold_public_key33_vec =
        secp256k1_private_key_32_to_public_key_33(&threshold_secret32)?;
    let threshold_public_key33: [u8; 33] = threshold_public_key33_vec
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("threshold public key length {}", bytes.len()))?;
    let client_public_key33 = secp256k1_private_key_32_to_public_key_33(&client_additive_share32)?;
    let server_public_key33 = secp256k1_private_key_32_to_public_key_33(&server_additive_share32)?;
    let ethereum_address20 =
        secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33)?;
    let (
        server_big_r33,
        server_k_share32,
        server_sigma_share32,
        client_k_share32,
        client_sigma_share32,
    ) = drive_ecdsa_presignature_pair(
        &client_threshold_share32,
        &server_threshold_share32,
        &threshold_public_key33,
    );
    let context = RouterAbEcdsaHssStableKeyContextV1::new(
        "wallet-ecdsa-hss-local",
        "localhost",
        "ecdsa-threshold-key-local",
        "signing-root-local",
        "root-v1",
        "evm-signing",
        "v1",
    )?;
    let public_identity = RouterAbEcdsaHssPublicIdentityV1::new(
        b64u(context.context_binding_digest()?.as_bytes()),
        b64u(&client_public_key33),
        b64u(&server_public_key33),
        b64u(&threshold_public_key33),
        b64u(&ethereum_address20),
        0,
        0,
    )?;
    let scope = RouterAbEcdsaHssNormalSigningScopeV1::new(
        context,
        public_identity,
        signing_worker,
        "activation-epoch-local",
    )?;
    let server_presignature_id =
        local_ecdsa_hss_smoke_server_presignature_id(&scope, &server_big_r33)?;
    Ok(LocalEcdsaHssFixture {
        scope,
        server_presignature_id,
        threshold_public_key33,
        server_big_r33,
        server_k_share32,
        server_sigma_share32,
        client_k_share32,
        client_sigma_share32,
        signing_digest32: [0x42; 32],
        expires_at_ms: 4_000_000_000_000,
    })
}

fn local_ecdsa_hss_smoke_server_presignature_id(
    scope: &RouterAbEcdsaHssNormalSigningScopeV1,
    server_big_r33: &[u8; 33],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(b"router-ab-local-smoke/ecdsa-hss/server-presignature-id/v1");
    hasher.update(scope.scope_digest()?.as_bytes());
    hasher.update(server_big_r33);
    Ok(format!(
        "local-ecdsa-presignature-smoke-{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    ))
}

fn drive_ecdsa_presignature_pair(
    client_share32: &[u8; 32],
    relayer_share32: &[u8; 32],
    public_key33: &[u8; 33],
) -> ([u8; 33], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let participant_ids = ECDSA_HSS_PARTICIPANT_IDS.map(u32::from);
    let mut client =
        ThresholdEcdsaPresignSession::new(&participant_ids, 1, 2, client_share32, public_key33)
            .expect("client presign session");
    let mut relayer =
        ThresholdEcdsaPresignSession::new(&participant_ids, 2, 2, relayer_share32, public_key33)
            .expect("relayer presign session");
    let mut stage_for_relayer = "triples";
    let mut stage_for_client = "triples";
    let mut client_outgoing = client.poll().expect("client initial poll").outgoing;
    let mut relayer_outgoing = relayer.poll().expect("relayer initial poll").outgoing;

    for _ in 0..96 {
        if !client_outgoing.is_empty() {
            if stage_for_relayer == "presign" && relayer.stage() == "triples_done" {
                relayer.start_presign().expect("relayer starts presign");
            }
            for message in client_outgoing.drain(..) {
                relayer
                    .message(1, &message)
                    .expect("relayer accepts client message");
            }
            let progress = relayer.poll().expect("relayer poll");
            if matches!(progress.stage.as_str(), "triples_done" | "presign" | "done") {
                stage_for_client = "presign";
            }
            relayer_outgoing.extend(progress.outgoing);
        }

        if !relayer_outgoing.is_empty() {
            if stage_for_client == "presign" && client.stage() == "triples_done" {
                client.start_presign().expect("client starts presign");
            }
            for message in relayer_outgoing.drain(..) {
                client
                    .message(2, &message)
                    .expect("client accepts relayer message");
            }
            let progress = client.poll().expect("client poll");
            if matches!(progress.stage.as_str(), "triples_done" | "presign" | "done") {
                stage_for_relayer = "presign";
            }
            client_outgoing.extend(progress.outgoing);
        }

        if client_outgoing.is_empty()
            && relayer_outgoing.is_empty()
            && stage_for_relayer == "presign"
            && relayer.stage() == "triples_done"
        {
            relayer.start_presign().expect("relayer starts presign");
            relayer_outgoing.extend(relayer.poll().expect("relayer presign poll").outgoing);
        }
        if client_outgoing.is_empty()
            && relayer_outgoing.is_empty()
            && stage_for_client == "presign"
            && client.stage() == "triples_done"
        {
            client.start_presign().expect("client starts presign");
            client_outgoing.extend(client.poll().expect("client presign poll").outgoing);
        }

        if client.is_done() && relayer.is_done() {
            let (client_big_r33, client_k_share32, client_sigma_share32) =
                split_ecdsa_presignature_97(
                    client.take_presignature_97().expect("client presignature"),
                );
            let (server_big_r33, server_k_share32, server_sigma_share32) =
                split_ecdsa_presignature_97(
                    relayer
                        .take_presignature_97()
                        .expect("relayer presignature"),
                );
            assert_eq!(client_big_r33, server_big_r33);
            return (
                server_big_r33,
                server_k_share32,
                server_sigma_share32,
                client_k_share32,
                client_sigma_share32,
            );
        }
    }
    panic!("ECDSA presign protocol did not finish");
}

fn split_ecdsa_presignature_97(bytes: Vec<u8>) -> ([u8; 33], [u8; 32], [u8; 32]) {
    assert_eq!(bytes.len(), 97, "presignature must be 97 bytes");
    (
        bytes[0..33].try_into().expect("presignature R length"),
        bytes[33..65].try_into().expect("presignature k length"),
        bytes[65..97].try_into().expect("presignature sigma length"),
    )
}

fn scalar_be32(value: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = value;
    out
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn seed_local_ed25519_router_key_store_for_existing_topology(
    mode: &str,
    seed: &LocalRouterEd25519KeyStoreSeedV1,
) -> Result<(), Box<dyn std::error::Error>> {
    if mode != "existing" {
        return Ok(());
    }
    let script_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/seed-ed25519-key-store.mjs");
    let mut child = Command::new("node")
        .arg(&script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            format!(
                "failed to start local Ed25519 key-store seed script {}: {error}",
                script_path.display()
            )
        })?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("local Ed25519 key-store seed script stdin was not available")?;
        stdin.write_all(&serde_json::to_vec(seed)?)?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(
            format!("local Ed25519 key-store seed script exited with status {status}").into(),
        );
    }
    Ok(())
}

const LOCAL_SMOKE_JWT_SECRET: &[u8] = b"demo-secret";
const LOCAL_SMOKE_JWT_ISSUER: &str = "relay-worker-demo";
const LOCAL_SMOKE_JWT_AUDIENCE: &str = "seams-app-demo";
const LOCAL_SMOKE_JWT_IAT: u64 = 1_700_000_000;
const LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS: u64 = 4_102_444_800_000;
const ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND: &str = "router_ab_ed25519_wallet_session_v1";
const ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND: &str = "router_ab_ecdsa_hss_wallet_session_v1";
const ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND: &str = "router_ab_ed25519_normal_signing_v1";
const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND: &str = "router_ab_ecdsa_hss_normal_signing_v1";

fn local_smoke_ed25519_wallet_session_authorization_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    relayer_key_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let claims = json!({
        "sub": request.scope.account_id,
        "kind": ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
        "walletId": request.scope.account_id,
        "sessionId": request.scope.session_id,
        "walletSigningSessionId": "local-ed25519-wallet-signing-session",
        "relayerKeyId": relayer_key_id,
        "rpId": "localhost",
        "participantIds": [1, 2],
        "thresholdExpiresAtMs": LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS,
        "runtimePolicyScope": {
            "orgId": "local-router-ab",
            "projectId": "local-router-ab",
            "envId": "dev",
            "signingRootVersion": "default"
        },
        "routerAbNormalSigning": {
            "kind": ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
            "signingWorkerId": request.scope.signing_worker_id
        },
        "iat": LOCAL_SMOKE_JWT_IAT,
        "exp": LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS / 1000,
        "iss": LOCAL_SMOKE_JWT_ISSUER,
        "aud": LOCAL_SMOKE_JWT_AUDIENCE
    });
    local_smoke_jwt_authorization(claims)
}

fn local_smoke_ecdsa_hss_wallet_session_authorization_v1(
    fixture: &LocalEcdsaHssFixture,
) -> Result<String, Box<dyn std::error::Error>> {
    let claims = json!({
        "sub": fixture.scope.context.wallet_id,
        "kind": ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
        "walletId": fixture.scope.context.wallet_id,
        "sessionId": "local-ecdsa-hss-session",
        "walletSigningSessionId": "local-ecdsa-hss-wallet-signing-session",
        "keyScope": "evm-family",
        "keyHandle": "local-ecdsa-hss-key-handle",
        "relayerKeyId": fixture.scope.context.ecdsa_threshold_key_id,
        "rpId": fixture.scope.context.rp_id,
        "participantIds": [1, 2],
        "thresholdExpiresAtMs": LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS,
        "routerAbEcdsaHssNormalSigning": {
            "kind": ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND,
            "scope": fixture.scope
        },
        "iat": LOCAL_SMOKE_JWT_IAT,
        "exp": LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS / 1000,
        "iss": LOCAL_SMOKE_JWT_ISSUER,
        "aud": LOCAL_SMOKE_JWT_AUDIENCE
    });
    local_smoke_jwt_authorization(claims)
}

fn local_smoke_jwt_authorization(claims: Value) -> Result<String, Box<dyn std::error::Error>> {
    let header = json!({ "alg": "HS256", "typ": "JWT" });
    let header = b64u(&serde_json::to_vec(&header)?);
    let claims = b64u(&serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{claims}");
    let signature = b64u(&hmac_sha256(
        LOCAL_SMOKE_JWT_SECRET,
        signing_input.as_bytes(),
    ));
    Ok(format!("Bearer {signing_input}.{signature}"))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut key_block = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for i in 0..BLOCK_BYTES {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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

fn local_normal_signing_smoke_fixture(
) -> Result<LocalNormalSigningSmokeFixtureV1, Box<dyn std::error::Error>> {
    Ok(LocalNormalSigningSmokeFixtureV1::new(
        "derived-gamma",
        "split-epoch-1",
        "gamma.test.near",
        "session-1",
        "local-signing-worker",
    )?)
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
    let mut report_path = None;
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
            "--out" => {
                let Some(value) = iter.next() else {
                    return Err("--out requires a path".to_owned());
                };
                report_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            _ => {
                return Err(format!("unknown argument {arg}\n{}", usage()));
            }
        }
    }
    Ok(SmokeOptions { root, report_path })
}

fn usage() -> String {
    "usage: router_ab_local_smoke [--root <path>] [--out <path>]".to_owned()
}
