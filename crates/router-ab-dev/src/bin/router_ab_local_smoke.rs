#[path = "local_dev_process/mod.rs"]
mod local_dev_process;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use local_dev_process::{
    normalize_root, post_json_to_path, post_json_to_path_with_authorization,
    post_json_to_path_with_headers, read_worker_config, wait_for_existing_health,
    LocalWorkerSpawnReceipt, LocalWorkerUrls, LOCAL_WORKER_PROCESS_SPECS,
};
use router_ab_core::{
    LocalServiceRoleV1, Role, RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningResponseV1, RouterAbEcdsaDerivationNormalSigningScopeV1,
    RouterAbEcdsaDerivationPublicIdentityV1, RouterAbEcdsaDerivationSignatureSchemeV1,
    RouterAbEcdsaDerivationStableKeyContextV1, ServerIdentityV1,
};
use router_ab_dev::{
    local_router_ab_internal_service_auth_secret_v1,
    run_example_local_router_ab_dev_http_ceremony_v1, LocalDeriverPeerMessageReceiptV1,
    LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutReceiptV1,
    LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1, LocalWorkerRoleConfigV1,
    LOCAL_DERIVER_A_PEER_PATH, LOCAL_DERIVER_B_PEER_PATH,
    LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
    LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
    LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
};
use router_ab_ecdsa_derivation::ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS;
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
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
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
    router_ab_ecdsa_derivation_live_http_route_dispatch_status: String,
    router_ab_ecdsa_derivation_pool_fill_status: String,
    router_ab_ecdsa_derivation_prepare_status: String,
    router_ab_ecdsa_derivation_finalize_status: String,
    router_ab_ecdsa_derivation_replay_rejection_status: String,
    router_ab_ecdsa_derivation_signature_scheme: String,
    router_ab_ecdsa_derivation_evidence_kind: String,
    setup_elapsed_ms: u64,
    deriver_b_peer_elapsed_ms: u64,
    deriver_a_peer_elapsed_ms: u64,
    router_ab_ecdsa_derivation_live_http_elapsed_ms: u64,
    total_elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouterAbEcdsaDerivationSmokeResult {
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
    let ceremony = run_example_local_router_ab_dev_http_ceremony_v1()?;
    ceremony
        .core_http_ceremony
        .router_response
        .validate()
        .map_err(|error| format!("Router setup smoke response failed validation: {error}"))?;
    let setup_elapsed_ms = elapsed_ms(setup_start);

    let deriver_b_start = Instant::now();
    let (deriver_b_status, deriver_b_body) = post_json_to_path(
        &urls.deriver_b,
        LOCAL_DERIVER_B_PEER_PATH,
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
        LOCAL_DERIVER_A_PEER_PATH,
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

    let smoke_run_id = local_smoke_run_id()?;
    let ecdsa_start = Instant::now();
    let ecdsa_result = run_router_ab_ecdsa_derivation_live_http_smoke(root, &urls, &smoke_run_id)?;
    let router_ab_ecdsa_derivation_live_http_elapsed_ms = elapsed_ms(ecdsa_start);

    Ok(SmokeSummary {
        root: root.display().to_string(),
        mode: mode.to_owned(),
        topology: "main-router",
        urls,
        spawned_processes,
        setup_status: "accepted".to_owned(),
        deriver_b_peer_status: deriver_b_receipt.status,
        deriver_a_peer_status: deriver_a_receipt.status,
        router_ab_ecdsa_derivation_live_http_route_dispatch_status: "accepted".to_owned(),
        router_ab_ecdsa_derivation_pool_fill_status: ecdsa_result.pool_fill_status,
        router_ab_ecdsa_derivation_prepare_status: ecdsa_result.prepare_status,
        router_ab_ecdsa_derivation_finalize_status: ecdsa_result.finalize_status,
        router_ab_ecdsa_derivation_replay_rejection_status: ecdsa_result.replay_rejection_status,
        router_ab_ecdsa_derivation_signature_scheme: ecdsa_result.signature_scheme,
        router_ab_ecdsa_derivation_evidence_kind: "live_http_route_dispatch".to_owned(),
        setup_elapsed_ms,
        deriver_b_peer_elapsed_ms,
        deriver_a_peer_elapsed_ms,
        router_ab_ecdsa_derivation_live_http_elapsed_ms,
        total_elapsed_ms: elapsed_ms(total_start),
    })
}

fn required_json_string(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .ok_or_else(|| format!("{context} missing {field}"))?;
    Ok(parsed.to_owned())
}

fn run_router_ab_ecdsa_derivation_live_http_smoke(
    root: &Path,
    urls: &LocalWorkerUrls,
    smoke_run_id: &str,
) -> Result<RouterAbEcdsaDerivationSmokeResult, Box<dyn std::error::Error>> {
    let signing_worker_identity = signing_worker_identity_from_root(root)?;
    let fixture = local_router_ab_ecdsa_derivation_fixture(signing_worker_identity)?;
    seed_local_ecdsa_wallet_session(&urls.router, &fixture)?;
    let authorization =
        local_smoke_router_ab_ecdsa_derivation_wallet_session_authorization_v1(&fixture)?;
    let pool_put = LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1 {
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
        LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
        &pool_put,
        &[(
            LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
            internal_service_auth.as_str(),
        )],
    )?;
    if pool_status != 200 {
        return Err(format!(
            "SigningWorker Router A/B ECDSA derivation pool-fill expected HTTP 200, received {pool_status}: {pool_body}"
        )
        .into());
    }
    let pool_receipt: LocalSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutReceiptV1 =
        serde_json::from_str(&pool_body)?;
    if !pool_receipt.stored
        || pool_receipt.server_presignature_id != fixture.server_presignature_id
        || pool_receipt.server_big_r33_b64u != b64u(&fixture.server_big_r33)
    {
        return Err(
            "SigningWorker Router A/B ECDSA derivation pool-fill receipt did not match request"
                .into(),
        );
    }

    let prepare_request = RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        fixture.scope.clone(),
        &format!("local-router-ab-ecdsa-derivation-smoke-sign-{smoke_run_id}"),
        fixture.server_presignature_id.clone(),
        fixture.expires_at_ms,
        b64u(&fixture.signing_digest32),
    )?;
    let (prepare_status, prepare_body) = post_json_to_path_with_authorization(
        &urls.router,
        LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH,
        authorization.as_str(),
        &prepare_request,
    )?;
    if prepare_status != 200 {
        return Err(format!(
            "Router Router A/B ECDSA derivation prepare expected HTTP 200, received {prepare_status}: {prepare_body}"
        )
        .into());
    }
    let prepare_value: Value = serde_json::from_str(&prepare_body)?;
    let budget_reservation_id = required_json_string(
        &prepare_value,
        "budget_reservation_id",
        "Router A/B ECDSA derivation prepare",
    )?;
    let budget_operation_id = required_json_string(
        &prepare_value,
        "budget_operation_id",
        "Router A/B ECDSA derivation prepare",
    )?;
    let mut prepare_core_value = prepare_value;
    let prepare_core_object = prepare_core_value
        .as_object_mut()
        .ok_or("Router A/B ECDSA derivation prepare response must serialize to an object")?;
    prepare_core_object.remove("budget_reservation_id");
    prepare_core_object.remove("budget_operation_id");
    prepare_core_object.remove("budget_status");
    let prepare_response: RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1 =
        serde_json::from_value(prepare_core_value)?;
    prepare_response.validate_for_request(&prepare_request)?;

    let entropy32: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&prepare_response.rerandomization_entropy32_b64u)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            format!("Router A/B ECDSA derivation entropy length {}", bytes.len())
        })?;
    let participant_ids = ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS.map(u32::from);
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
    let finalize_request = RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1::new(
        fixture.scope,
        prepare_request.request_id,
        prepare_request.expires_at_ms,
        prepare_request.signing_digest_b64u,
        prepare_response.server_presignature_id,
        b64u(&client_signature_share32),
    )?;
    let mut finalize_request_body = serde_json::to_value(&finalize_request)?;
    let finalize_request_object = finalize_request_body
        .as_object_mut()
        .ok_or("Router A/B ECDSA derivation finalize request must serialize to an object")?;
    finalize_request_object.insert(
        "budget_reservation_id".to_owned(),
        Value::String(budget_reservation_id),
    );
    finalize_request_object.insert(
        "budget_operation_id".to_owned(),
        Value::String(budget_operation_id),
    );
    let (finalize_status, finalize_body) = post_json_to_path_with_authorization(
        &urls.router,
        LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
        authorization.as_str(),
        &finalize_request_body,
    )?;
    if finalize_status != 200 {
        return Err(format!(
            "Router Router A/B ECDSA derivation finalize expected HTTP 200, received {finalize_status}: {finalize_body}"
        )
        .into());
    }
    let signing_response: RouterAbEcdsaDerivationEvmDigestSigningResponseV1 =
        serde_json::from_str(&finalize_body)?;
    signing_response.validate()?;
    if signing_response.request_digest != finalize_request.request_digest()?
        || signing_response.signature65_b64u.as_bytes().len() != 87
    {
        return Err(
            "Router Router A/B ECDSA derivation finalize response did not bind request".into(),
        );
    }

    let (replay_status, replay_body) = post_json_to_path_with_authorization(
        &urls.router,
        LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
        authorization.as_str(),
        &finalize_request_body,
    )?;
    if replay_status != 400 || !replay_body.contains("prepared presignature is not available") {
        return Err(format!(
            "Router Router A/B ECDSA derivation one-use replay expected HTTP 400 prepared-presignature rejection, received {replay_status}: {replay_body}"
        )
        .into());
    }

    Ok(RouterAbEcdsaDerivationSmokeResult {
        pool_fill_status: "http_200_stored".to_owned(),
        prepare_status: "http_200_bound".to_owned(),
        finalize_status: "http_200_signature".to_owned(),
        replay_rejection_status: "http_400_one_use_replay_rejected".to_owned(),
        signature_scheme: router_ab_ecdsa_derivation_signature_scheme_label(
            signing_response.signature_scheme,
        )
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

fn router_ab_ecdsa_derivation_signature_scheme_label(
    scheme: RouterAbEcdsaDerivationSignatureSchemeV1,
) -> &'static str {
    match scheme {
        RouterAbEcdsaDerivationSignatureSchemeV1::EcdsaSecp256k1RecoverableV1 => {
            "ecdsa_secp256k1_recoverable_v1"
        }
    }
}

struct LocalRouterAbEcdsaDerivationFixture {
    scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
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

fn local_router_ab_ecdsa_derivation_fixture(
    signing_worker: ServerIdentityV1,
) -> Result<LocalRouterAbEcdsaDerivationFixture, Box<dyn std::error::Error>> {
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
    let derivation_client_share_public_key33 =
        secp256k1_private_key_32_to_public_key_33(&client_additive_share32)?;
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
    let application_binding_digest = Sha256::digest(
        b"router-ab-local-smoke/router-ab-ecdsa-derivation/application-binding/wallet-router-ab-ecdsa-derivation-local/v1",
    );
    let context =
        RouterAbEcdsaDerivationStableKeyContextV1::new(b64u(&application_binding_digest))?;
    let public_identity = RouterAbEcdsaDerivationPublicIdentityV1::new(
        b64u(context.context_binding_digest()?.as_bytes()),
        b64u(&derivation_client_share_public_key33),
        b64u(&server_public_key33),
        b64u(&threshold_public_key33),
        b64u(&ethereum_address20),
        0,
        0,
    )?;
    let scope = RouterAbEcdsaDerivationNormalSigningScopeV1::new(
        LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
        LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
        LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
        LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
        LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        context,
        public_identity,
        signing_worker,
        "activation-epoch-local",
    )?;
    let server_presignature_id =
        local_router_ab_ecdsa_derivation_smoke_server_presignature_id(&scope, &server_big_r33)?;
    Ok(LocalRouterAbEcdsaDerivationFixture {
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

fn local_router_ab_ecdsa_derivation_smoke_server_presignature_id(
    scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    server_big_r33: &[u8; 33],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(b"router-ab-local-smoke/router-ab-ecdsa-derivation/server-presignature-id/v1");
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
    let participant_ids = ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS.map(u32::from);
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

fn local_smoke_run_id() -> Result<String, Box<dyn std::error::Error>> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    Ok(format!("{}-{millis}", std::process::id()))
}

fn seed_local_ecdsa_wallet_session(
    router_url: &str,
    fixture: &LocalRouterAbEcdsaDerivationFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = json!({
        "walletId": fixture.scope.wallet_id,
        "evmFamilySigningKeySlotId": fixture.scope.wallet_key_id,
        "ecdsaThresholdKeyId": fixture.scope.ecdsa_threshold_key_id,
        "signingRootId": fixture.scope.signing_root_id,
        "signingRootVersion": fixture.scope.signing_root_version,
        "walletKeyVersion": "v1",
        "derivationVersion": 1,
        "relayerKeyId": fixture.scope.ecdsa_threshold_key_id,
        "thresholdSessionId": LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_SESSION_ID,
        "signingGrantId": LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_GRANT_ID,
        "thresholdExpiresAtMs": LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS,
        "participantIds": [1, 2],
        "remainingUses": LOCAL_SMOKE_WALLET_SESSION_REMAINING_USES
    });
    let internal_auth = local_router_ab_internal_service_auth_secret_v1();
    let (status, body) = post_json_to_path_with_headers(
        router_url,
        LOCAL_ROUTER_AB_ECDSA_DERIVATION_SEED_PATH,
        &seed,
        &[(
            LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
            internal_auth.as_str(),
        )],
    )?;
    if status != 200 {
        return Err(format!(
            "local Router A/B ECDSA derivation Router seed expected HTTP 200, received {status}: {body}"
        )
        .into());
    }
    Ok(())
}

const LOCAL_SMOKE_JWT_SECRET: &[u8] =
    b"seams-local-d1-relay-session-secret-change-before-shared-dev";
const LOCAL_ROUTER_AB_ECDSA_DERIVATION_SEED_PATH: &str =
    "/router-ab/dev/ecdsa-derivation/normal-signing/seed";
const LOCAL_SMOKE_JWT_ISSUER: &str = "seams-local-d1-relay";
const LOCAL_SMOKE_JWT_AUDIENCE: &str = "seams-local-d1";
const LOCAL_SMOKE_JWT_IAT: u64 = 1_700_000_000;
const LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS: u64 = 4_102_444_800_000;
const LOCAL_SMOKE_WALLET_SESSION_REMAINING_USES: u32 = 32;
const LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_GRANT_ID: &str =
    "local-router-ab-ecdsa-derivation-signing-grant";
const LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_SESSION_ID: &str =
    "local-router-ab-ecdsa-derivation-session";
const LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_WALLET_ID: &str =
    "wallet-router-ab-ecdsa-derivation-local";
const LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID: &str =
    "wallet-key:evm-family:wallet-router-ab-ecdsa-derivation-local:signing-root-local:root-v1";
const LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID: &str = "ecdsa-threshold-key-local";
const LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID: &str = "signing-root-local";
const LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION: &str = "root-v1";
const ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND: &str =
    "router_ab_ecdsa_derivation_wallet_session_v1";
const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND: &str =
    "router_ab_ecdsa_derivation_normal_signing_v1";

fn local_smoke_router_ab_ecdsa_derivation_wallet_session_authorization_v1(
    fixture: &LocalRouterAbEcdsaDerivationFixture,
) -> Result<String, Box<dyn std::error::Error>> {
    let claims = json!({
        "sub": fixture.scope.wallet_id,
        "kind": ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
        "walletId": fixture.scope.wallet_id,
        "thresholdSessionId": LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_SESSION_ID,
        "signingGrantId": LOCAL_SMOKE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_GRANT_ID,
        "keyScope": "evm-family",
        "keyHandle": "local-router-ab-ecdsa-derivation-key-handle",
        "relayerKeyId": fixture.scope.ecdsa_threshold_key_id,
        "evmFamilySigningKeySlotId": fixture.scope.wallet_key_id,
        "participantIds": [1, 2],
        "thresholdExpiresAtMs": LOCAL_SMOKE_WALLET_SESSION_EXPIRES_AT_MS,
        "runtimePolicyScope": {
            "orgId": "local-router-ab",
            "projectId": "local-router-ab",
            "envId": "dev",
            "signingRootVersion": "default"
        },
        "routerAbRouterAbEcdsaDerivationNormalSigning": {
            "kind": ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND,
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
