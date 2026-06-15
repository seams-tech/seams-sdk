use router_ab_core::{
    CanonicalWireBytesV1, LocalClientRouterRequestV1, LocalDeriverAEndpointV1,
    LocalDeriverBEndpointV1, LocalEnvSnapshotV1, LocalHttpMethodV1, LocalHttpPathV1,
    LocalHttpRequestV1, LocalReplayCacheV1, LocalRouterEndpointV1, LocalServiceRoleV1,
    LocalServiceStackV1, LocalServiceStartupV1, LocalSigningWorkerEndpointV1,
    LocalTransportEnvelopeV1, LocalTransportRouteV1, ServerIdentityV1, SignerIdentityV1,
    WireMessageKindV1, WireMessageV1,
};
use router_ab_core::{PublicDigest32, Role};
use serde::Serialize;

#[derive(Serialize)]
struct DevRouterAbSignerSummary {
    router_url: &'static str,
    deriver_a_url: &'static str,
    deriver_b_url: &'static str,
    signing_worker_url: &'static str,
    router_client_bundle_count: usize,
    signing_worker_bundle_count: usize,
    deriver_a_peer_path: &'static str,
    deriver_b_peer_path: &'static str,
    signing_worker_id: String,
    transcript_digest_hex: String,
    signing_worker_activation_digest_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stack = LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint()?, router_env_snapshot()?)?,
        LocalServiceStartupV1::deriver_a(
            deriver_a_endpoint()?,
            signer_a_identity()?,
            deriver_a_env_snapshot()?,
        )?,
        LocalServiceStartupV1::deriver_b(
            deriver_b_endpoint()?,
            signer_b_identity()?,
            deriver_b_env_snapshot()?,
        )?,
        LocalServiceStartupV1::signing_worker(
            signing_worker_endpoint()?,
            server_identity()?,
            signing_worker_env_snapshot()?,
        )?,
    )?;
    let mut replay_cache = LocalReplayCacheV1::new();
    let result = stack.handle_local_client_request_with_replay_cache(
        1_000,
        &mut replay_cache,
        LocalClientRouterRequestV1::new(
            "local-router-ab-lifecycle",
            "local-request-nonce-1",
            2_000,
            http_request(
                LocalHttpPathV1::RouterToSignerA,
                LocalTransportRouteV1::RouterToSignerA,
                WireMessageKindV1::RouterToSignerA,
            )?,
            http_request(
                LocalHttpPathV1::RouterToSignerB,
                LocalTransportRouteV1::RouterToSignerB,
                WireMessageKindV1::RouterToSignerB,
            )?,
        )?,
    )?;

    let summary = DevRouterAbSignerSummary {
        router_url: "http://127.0.0.1:8787",
        deriver_a_url: "http://127.0.0.1:8788",
        deriver_b_url: "http://127.0.0.1:8789",
        signing_worker_url: "http://127.0.0.1:8790",
        router_client_bundle_count: [
            &result.router_response.deriver_a_client_bundle,
            &result.router_response.deriver_b_client_bundle,
        ]
        .len(),
        signing_worker_bundle_count: [
            &result
                .signing_worker_activation
                .deriver_a_signing_worker_bundle,
            &result
                .signing_worker_activation
                .deriver_b_signing_worker_bundle,
        ]
        .len(),
        deriver_a_peer_path: result.deriver_a_peer_request.path.as_str(),
        deriver_b_peer_path: result.deriver_b_peer_request.path.as_str(),
        signing_worker_id: result
            .signing_worker_activation_receipt
            .signing_worker
            .server_id
            .clone(),
        transcript_digest_hex: digest_hex(
            result.signing_worker_activation_receipt.transcript_digest,
        ),
        signing_worker_activation_digest_hex: digest_hex(
            result.signing_worker_activation_receipt.activation_digest,
        ),
    };

    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn digest_hex(digest: PublicDigest32) -> String {
    hex::encode(digest.as_bytes())
}

fn wire(kind: WireMessageKindV1) -> Result<WireMessageV1, Box<dyn std::error::Error>> {
    Ok(WireMessageV1::new(
        kind,
        digest(0x33),
        CanonicalWireBytesV1::new(vec![0xab])?,
    )?)
}

fn transport(
    route: LocalTransportRouteV1,
    kind: WireMessageKindV1,
) -> Result<LocalTransportEnvelopeV1, Box<dyn std::error::Error>> {
    Ok(LocalTransportEnvelopeV1::new(route, wire(kind)?)?)
}

fn http_request(
    path: LocalHttpPathV1,
    route: LocalTransportRouteV1,
    kind: WireMessageKindV1,
) -> Result<LocalHttpRequestV1, Box<dyn std::error::Error>> {
    Ok(LocalHttpRequestV1::new(
        LocalHttpMethodV1::Post,
        path,
        transport(route, kind)?,
    )?)
}

fn router_endpoint() -> Result<LocalRouterEndpointV1, Box<dyn std::error::Error>> {
    Ok(LocalRouterEndpointV1::new(
        "http://127.0.0.1:8787",
        "http://127.0.0.1:8788",
        "http://127.0.0.1:8789",
        "http://127.0.0.1:8790",
    )?)
}

fn deriver_a_endpoint() -> Result<LocalDeriverAEndpointV1, Box<dyn std::error::Error>> {
    Ok(LocalDeriverAEndpointV1::new(
        "http://127.0.0.1:8788",
        "http://127.0.0.1:8789",
    )?)
}

fn deriver_b_endpoint() -> Result<LocalDeriverBEndpointV1, Box<dyn std::error::Error>> {
    Ok(LocalDeriverBEndpointV1::new(
        "http://127.0.0.1:8789",
        "http://127.0.0.1:8788",
    )?)
}

fn signing_worker_endpoint() -> Result<LocalSigningWorkerEndpointV1, Box<dyn std::error::Error>> {
    Ok(LocalSigningWorkerEndpointV1::new(
        "http://127.0.0.1:8790",
        "local-server-output",
    )?)
}

fn signer_a_identity() -> Result<SignerIdentityV1, Box<dyn std::error::Error>> {
    Ok(SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a")?)
}

fn signer_b_identity() -> Result<SignerIdentityV1, Box<dyn std::error::Error>> {
    Ok(SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b")?)
}

fn server_identity() -> Result<ServerIdentityV1, Box<dyn std::error::Error>> {
    Ok(ServerIdentityV1::new(
        "server-a",
        "server-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )?)
}

fn router_env_snapshot() -> Result<LocalEnvSnapshotV1, Box<dyn std::error::Error>> {
    Ok(LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::Router,
        vec![
            "ROUTER_PUBLIC_URL".to_owned(),
            "DERIVER_A_URL".to_owned(),
            "DERIVER_B_URL".to_owned(),
            "SIGNING_WORKER_URL".to_owned(),
        ],
    )?)
}

fn deriver_a_env_snapshot() -> Result<LocalEnvSnapshotV1, Box<dyn std::error::Error>> {
    Ok(LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverA,
        vec![
            "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_A_KEK".to_owned(),
            "DERIVER_B_URL".to_owned(),
        ],
    )?)
}

fn deriver_b_env_snapshot() -> Result<LocalEnvSnapshotV1, Box<dyn std::error::Error>> {
    Ok(LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverB,
        vec![
            "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_B_KEK".to_owned(),
            "DERIVER_A_URL".to_owned(),
        ],
    )?)
}

fn signing_worker_env_snapshot() -> Result<LocalEnvSnapshotV1, Box<dyn std::error::Error>> {
    Ok(LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SigningWorker,
        vec!["SERVER_OUTPUT_STORAGE".to_owned()],
    )?)
}
