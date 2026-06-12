use router_ab_core::{
    CanonicalWireBytesV1, LocalClientRouterRequestV1, LocalEnvSnapshotV1, LocalHttpMethodV1,
    LocalHttpPathV1, LocalHttpRequestV1, LocalReplayCacheV1, LocalRouterEndpointV1,
    LocalServiceRoleV1, LocalServiceStackV1, LocalServiceStartupV1, LocalSignerARelayerEndpointV1,
    LocalSignerBEndpointV1, LocalTransportEnvelopeV1, LocalTransportRouteV1, RelayerIdentityV1,
    SignerIdentityV1, WireMessageKindV1, WireMessageV1,
};
use router_ab_core::{PublicDigest32, Role};
use serde::Serialize;

#[derive(Serialize)]
struct DevRouterAbSignerSummary {
    router_url: &'static str,
    signer_a_relayer_url: &'static str,
    signer_b_url: &'static str,
    signer_a_response_status: u16,
    signer_b_response_status: u16,
    signer_a_response_route: String,
    signer_b_response_route: String,
    signer_a_peer_path: &'static str,
    signer_b_peer_path: &'static str,
    relayer_activation_path: &'static str,
    relayer_id: String,
    transcript_digest_hex: String,
    relayer_activation_digest_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stack = LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint()?, router_env_snapshot()?)?,
        LocalServiceStartupV1::signer_a_relayer(
            signer_a_endpoint()?,
            signer_a_identity()?,
            relayer_identity()?,
            signer_a_env_snapshot()?,
        )?,
        LocalServiceStartupV1::signer_b(
            signer_b_endpoint()?,
            signer_b_identity()?,
            signer_b_env_snapshot()?,
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
        signer_a_relayer_url: "http://127.0.0.1:8788",
        signer_b_url: "http://127.0.0.1:8789",
        signer_a_response_status: result.signer_a_response.status.status_code(),
        signer_b_response_status: result.signer_b_response.status.status_code(),
        signer_a_response_route: format!("{:?}", result.signer_a_response.envelope.route),
        signer_b_response_route: format!("{:?}", result.signer_b_response.envelope.route),
        signer_a_peer_path: result.signer_a_peer_request.path.as_str(),
        signer_b_peer_path: result.signer_b_peer_request.path.as_str(),
        relayer_activation_path: result.relayer_activation_request.path.as_str(),
        relayer_id: result.relayer_activation_receipt.relayer.relayer_id.clone(),
        transcript_digest_hex: digest_hex(result.relayer_activation_receipt.transcript_digest),
        relayer_activation_digest_hex: digest_hex(
            result.relayer_activation_receipt.activation_digest,
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
    )?)
}

fn signer_a_endpoint() -> Result<LocalSignerARelayerEndpointV1, Box<dyn std::error::Error>> {
    Ok(LocalSignerARelayerEndpointV1::new(
        "http://127.0.0.1:8788",
        "http://127.0.0.1:8789",
        "local-relayer-output",
    )?)
}

fn signer_b_endpoint() -> Result<LocalSignerBEndpointV1, Box<dyn std::error::Error>> {
    Ok(LocalSignerBEndpointV1::new(
        "http://127.0.0.1:8789",
        "http://127.0.0.1:8788",
    )?)
}

fn signer_a_identity() -> Result<SignerIdentityV1, Box<dyn std::error::Error>> {
    Ok(SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a")?)
}

fn signer_b_identity() -> Result<SignerIdentityV1, Box<dyn std::error::Error>> {
    Ok(SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b")?)
}

fn relayer_identity() -> Result<RelayerIdentityV1, Box<dyn std::error::Error>> {
    Ok(RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )?)
}

fn router_env_snapshot() -> Result<LocalEnvSnapshotV1, Box<dyn std::error::Error>> {
    Ok(LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::Router,
        vec![
            "ROUTER_PUBLIC_URL".to_owned(),
            "SIGNER_A_URL".to_owned(),
            "SIGNER_B_URL".to_owned(),
        ],
    )?)
}

fn signer_a_env_snapshot() -> Result<LocalEnvSnapshotV1, Box<dyn std::error::Error>> {
    Ok(LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SignerARelayer,
        vec![
            "SIGNER_A_ENVELOPE_AEAD_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_A_KEK".to_owned(),
            "RELAYER_OUTPUT_STORAGE".to_owned(),
            "SIGNER_B_URL".to_owned(),
        ],
    )?)
}

fn signer_b_env_snapshot() -> Result<LocalEnvSnapshotV1, Box<dyn std::error::Error>> {
    Ok(LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SignerB,
        vec![
            "SIGNER_B_ENVELOPE_AEAD_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_B_KEK".to_owned(),
            "SIGNER_A_URL".to_owned(),
        ],
    )?)
}
