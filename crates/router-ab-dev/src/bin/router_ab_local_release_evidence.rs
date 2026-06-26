use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use router_ab_core::{
    parse_router_ab_ecdsa_hss_evm_digest_signing_finalize_request_v1_json,
    parse_router_ab_ecdsa_hss_evm_digest_signing_prepare_response_v1_json,
    parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json,
    parse_router_ab_ed25519_normal_signing_finalize_request_v2_json,
    parse_router_ab_ed25519_normal_signing_prepare_request_v2_json,
    parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json,
    parse_router_ab_ed25519_presign_pool_prepare_request_v2_json,
    parse_router_ab_ed25519_presign_pool_prepare_response_v2_json,
    router_ab_ed25519_nep413_canonical_message_b64u_v2,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningScopeV1,
    NormalSigningSignatureSchemeV1, PublicDigest32,
    RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1, RouterAbEcdsaHssEvmDigestSigningRequestV1,
    RouterAbEcdsaHssEvmDigestSigningResponseV1, RouterAbEcdsaHssNormalSigningScopeV1,
    RouterAbEcdsaHssPublicIdentityV1, RouterAbEcdsaHssStableKeyContextV1,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningIntentV2, RouterAbEd25519NormalSigningPrepareBindingV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbEd25519PresignPoolAcceptedEntryV2,
    RouterAbEd25519PresignPoolClientOfferV2, RouterAbEd25519PresignPoolHitBindingV2,
    RouterAbEd25519PresignPoolHitFinalizeRequestV2, RouterAbEd25519PresignPoolPrepareRequestV2,
    RouterAbEd25519PresignPoolPrepareResponseV2, RouterAbEd25519SigningPayloadV2,
    RouterAbEd25519TwoPartyFrostFinalizeProtocolV2, RouterAbNearNetworkIdV2,
    RouterAbProtocolResult, ServerIdentityV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const ITERATIONS: u64 = 250;
const EVIDENCE_VERSION: &str = "router-ab-local-release-evidence-v1";

#[derive(Debug, Clone, Serialize)]
struct EvidenceSummary {
    evidence_version: &'static str,
    generated_at_unix_ms: u128,
    iterations: u64,
    ecdsa_hss_normal_signing: EcdsaHssEvidence,
    ed25519_presign_pool: Ed25519PoolEvidence,
}

#[derive(Debug, Clone, Serialize)]
struct EcdsaHssEvidence {
    evidence_kind: &'static str,
    live_http_route_dispatch_evidence: &'static str,
    route_shape: EcdsaHssRouteShape,
    prepare_finalize_protocol_timing: TimingEvidence,
    signed_digest_b64u: String,
    signature_scheme: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct EcdsaHssRouteShape {
    prepare_route: &'static str,
    finalize_route: &'static str,
    private_pool_fill_route: &'static str,
    private_prepare_route: &'static str,
    private_finalize_route: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct Ed25519PoolEvidence {
    evidence_kind: &'static str,
    route_shape: Ed25519PoolRouteShape,
    refill_timing: TimingEvidence,
    pool_hit_finalize_timing: TimingEvidence,
    pool_miss_prepare_finalize_timing: TimingEvidence,
    accepted_pool_entries: usize,
    rejected_pool_entries: usize,
    pool_hit_lowers_to_finalize: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Ed25519PoolRouteShape {
    refill_route: &'static str,
    pool_hit_finalize_route: &'static str,
    pool_miss_prepare_route: &'static str,
    pool_miss_finalize_route: &'static str,
    private_refill_route: &'static str,
    private_finalize_route: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct TimingEvidence {
    iterations: u64,
    elapsed_us: u128,
    average_us: u128,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(env::args().skip(1))?;
    let evidence = build_evidence()?;
    let json = serde_json::to_string_pretty(&evidence)?;
    if let Some(path) = options.report_path.as_deref() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{json}\n"))?;
    }
    println!("{json}");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    report_path: Option<PathBuf>,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut report_path = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--out" => {
                let Some(value) = iter.next() else {
                    return Err("--out requires a path".to_owned());
                };
                report_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("unknown argument {arg}\n{}", usage())),
        }
    }
    Ok(Options { report_path })
}

fn usage() -> String {
    "usage: router_ab_local_release_evidence [--out <path>]".to_owned()
}

fn build_evidence() -> RouterAbProtocolResult<EvidenceSummary> {
    let ecdsa = ecdsa_hss_evidence()?;
    let ed25519 = ed25519_pool_evidence()?;
    Ok(EvidenceSummary {
        evidence_version: EVIDENCE_VERSION,
        generated_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default(),
        iterations: ITERATIONS,
        ecdsa_hss_normal_signing: ecdsa,
        ed25519_presign_pool: ed25519,
    })
}

fn ecdsa_hss_evidence() -> RouterAbProtocolResult<EcdsaHssEvidence> {
    let prepare = ecdsa_signing_request()?;
    let prepare_response = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &prepare,
        "server-presignature-1",
        secp256k1_public_key33_b64u(0x03, 0x99),
        b64u(&[0x55; 32]),
        1_800_000_000_000,
    )?;
    let finalize = RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1::new(
        ecdsa_scope()?,
        "ecdsa-sign-request-1",
        1_900_000_000_000,
        b64u(&[0x66; 32]),
        "server-presignature-1",
        b64u(&[0x77; 32]),
    )?;
    let response =
        RouterAbEcdsaHssEvmDigestSigningResponseV1::new_for_request(&prepare, b64u(&[0x88; 65]))?;
    let timing = time_iterations(ITERATIONS, || {
        let prepare_json = serde_json::to_vec(&prepare).expect("ECDSA prepare JSON");
        let parsed_prepare =
            parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json(&prepare_json)
                .expect("ECDSA prepare parses");
        parsed_prepare
            .validate_at(1_700_000_000_000)
            .expect("ECDSA prepare time-validates");

        let prepare_response_json =
            serde_json::to_vec(&prepare_response).expect("ECDSA prepare response JSON");
        let parsed_prepare_response =
            parse_router_ab_ecdsa_hss_evm_digest_signing_prepare_response_v1_json(
                &prepare_response_json,
            )
            .expect("ECDSA prepare response parses");
        parsed_prepare_response
            .validate_for_request(&parsed_prepare)
            .expect("ECDSA prepare response binds request");

        let finalize_json = serde_json::to_vec(&finalize).expect("ECDSA finalize JSON");
        let parsed_finalize =
            parse_router_ab_ecdsa_hss_evm_digest_signing_finalize_request_v1_json(&finalize_json)
                .expect("ECDSA finalize parses");
        parsed_finalize
            .validate_at(1_700_000_000_000)
            .expect("ECDSA finalize time-validates");
        if parsed_finalize.prepare_request_digest().expect("digest")
            != parsed_prepare.request_digest().expect("digest")
        {
            panic!("ECDSA finalize does not bind prepare request");
        }

        response
            .validate_for_request(&parsed_prepare)
            .expect("ECDSA response binds request");
    });

    Ok(EcdsaHssEvidence {
        evidence_kind: "protocol_shape_parser_binding_timing",
        live_http_route_dispatch_evidence:
            "run pnpm router:check after local services are ready; this report does not open local HTTP listeners",
        route_shape: EcdsaHssRouteShape {
            prepare_route: "/router-ab/ecdsa-hss/sign/prepare",
            finalize_route: "/router-ab/ecdsa-hss/sign",
            private_pool_fill_route: "/router-ab/signing-worker/ecdsa-hss/presignature-pool/put",
            private_prepare_route: "/router-ab/signing-worker/ecdsa-hss/sign/prepare",
            private_finalize_route: "/router-ab/signing-worker/ecdsa-hss/sign",
        },
        prepare_finalize_protocol_timing: timing,
        signed_digest_b64u: prepare.signing_digest_b64u,
        signature_scheme: "ecdsa_secp256k1_recoverable_v1",
    })
}

fn ed25519_pool_evidence() -> RouterAbProtocolResult<Ed25519PoolEvidence> {
    let refill = ed25519_pool_prepare_request()?;
    let offer = refill.client_offers.first().expect("pool offer").clone();
    let accepted = accepted_pool_entry(&refill, &offer, 0x81)?;
    let refill_response = RouterAbEd25519PresignPoolPrepareResponseV2::new(
        refill.scope.clone(),
        refill.generation,
        vec![accepted.clone()],
        vec!["client-presign-2".to_owned()],
    )?;
    refill_response.validate_for_request(&refill)?;

    let pool_hit = ed25519_pool_hit_finalize_request(&refill, &offer, &accepted)?;
    let lowered = pool_hit.to_normal_finalize_request_v2()?;
    let pool_hit_lowers_to_finalize =
        lowered.server_round1_handle() == pool_hit.server_round1_handle();
    let pool_miss_prepare = ed25519_prepare_request()?;
    let pool_miss_finalize = ed25519_finalize_request(&pool_miss_prepare)?;

    let refill_timing = time_iterations(ITERATIONS, || {
        let request_json = serde_json::to_vec(&refill).expect("refill request JSON");
        let parsed_request =
            parse_router_ab_ed25519_presign_pool_prepare_request_v2_json(&request_json)
                .expect("refill request parses");
        parsed_request
            .validate_at(1_700_000_000_000)
            .expect("refill request time-validates");

        let response_json = serde_json::to_vec(&refill_response).expect("refill response JSON");
        let parsed_response =
            parse_router_ab_ed25519_presign_pool_prepare_response_v2_json(&response_json)
                .expect("refill response parses");
        parsed_response
            .validate_for_request(&parsed_request)
            .expect("refill response binds request");
    });

    let pool_hit_finalize_timing = time_iterations(ITERATIONS, || {
        let request_json = serde_json::to_vec(&pool_hit).expect("pool hit JSON");
        let parsed =
            parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json(&request_json)
                .expect("pool hit parses");
        parsed
            .validate_at(1_700_000_000_000)
            .expect("pool hit time-validates");
        parsed
            .to_normal_finalize_request_v2()
            .expect("pool hit lowers");
    });

    let pool_miss_prepare_finalize_timing = time_iterations(ITERATIONS, || {
        let prepare_json = serde_json::to_vec(&pool_miss_prepare).expect("prepare JSON");
        let parsed_prepare =
            parse_router_ab_ed25519_normal_signing_prepare_request_v2_json(&prepare_json)
                .expect("prepare parses");
        parsed_prepare
            .validate_at(1_700_000_000_000)
            .expect("prepare time-validates");

        let finalize_json = serde_json::to_vec(&pool_miss_finalize).expect("finalize JSON");
        let parsed_finalize =
            parse_router_ab_ed25519_normal_signing_finalize_request_v2_json(&finalize_json)
                .expect("finalize parses");
        parsed_finalize
            .validate_at(1_700_000_000_000)
            .expect("finalize time-validates");
    });

    Ok(Ed25519PoolEvidence {
        evidence_kind: "protocol_shape_parser_binding_timing",
        route_shape: Ed25519PoolRouteShape {
            refill_route: "/router-ab/ed25519/sign/presign-pool/prepare",
            pool_hit_finalize_route: "/router-ab/ed25519/sign",
            pool_miss_prepare_route: "/router-ab/ed25519/sign/prepare",
            pool_miss_finalize_route: "/router-ab/ed25519/sign",
            private_refill_route: "/router-ab/signing-worker/sign/presign-pool/prepare",
            private_finalize_route: "/router-ab/signing-worker/sign",
        },
        refill_timing,
        pool_hit_finalize_timing,
        pool_miss_prepare_finalize_timing,
        accepted_pool_entries: refill_response.accepted.len(),
        rejected_pool_entries: refill_response.rejected_client_presign_ids.len(),
        pool_hit_lowers_to_finalize,
    })
}

fn time_iterations(iterations: u64, mut f: impl FnMut()) -> TimingEvidence {
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed_us = start.elapsed().as_micros();
    TimingEvidence {
        iterations,
        elapsed_us,
        average_us: elapsed_us / u128::from(iterations),
    }
}

fn ecdsa_signing_request() -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningRequestV1> {
    RouterAbEcdsaHssEvmDigestSigningRequestV1::new(
        ecdsa_scope()?,
        "ecdsa-sign-request-1",
        "server-presignature-1",
        1_900_000_000_000,
        b64u(&[0x66; 32]),
    )
}

fn ecdsa_scope() -> RouterAbProtocolResult<RouterAbEcdsaHssNormalSigningScopeV1> {
    RouterAbEcdsaHssNormalSigningScopeV1::new(
        "wallet-key-1",
        "wallet-1",
        "ecdsa-threshold-key-1",
        "signing-root-1",
        "root-v1",
        ecdsa_context()?,
        ecdsa_public_identity()?,
        signing_worker_identity()?,
        "root-epoch-1",
    )
}

fn ecdsa_context() -> RouterAbProtocolResult<RouterAbEcdsaHssStableKeyContextV1> {
    RouterAbEcdsaHssStableKeyContextV1::new(b64u(&[0x42; 32]))
}

fn ecdsa_public_identity() -> RouterAbProtocolResult<RouterAbEcdsaHssPublicIdentityV1> {
    let context = ecdsa_context()?;
    RouterAbEcdsaHssPublicIdentityV1::new(
        b64u(context.context_binding_digest()?.as_bytes()),
        secp256k1_public_key33_b64u(0x02, 0x11),
        secp256k1_public_key33_b64u(0x03, 0x22),
        secp256k1_public_key33_b64u(0x02, 0x33),
        b64u(&[0x44; 20]),
        0,
        1,
    )
}

fn ed25519_pool_prepare_request(
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolPrepareRequestV2> {
    RouterAbEd25519PresignPoolPrepareRequestV2::new(
        ed25519_scope()?,
        1_900_000_000_000,
        7,
        vec![
            pool_offer("client-presign-1", 0x51)?,
            pool_offer("client-presign-2", 0x61)?,
        ],
    )
}

fn pool_offer(
    client_presign_id: &str,
    nonce_seed: u8,
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolClientOfferV2> {
    RouterAbEd25519PresignPoolClientOfferV2::new(
        client_presign_id,
        format!("client-nonce-handle-{nonce_seed}"),
        commitments(nonce_seed, nonce_seed.wrapping_add(1))?,
        b64u(&[nonce_seed.wrapping_add(2); 32]),
    )
}

fn accepted_pool_entry(
    request: &RouterAbEd25519PresignPoolPrepareRequestV2,
    offer: &RouterAbEd25519PresignPoolClientOfferV2,
    nonce_seed: u8,
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolAcceptedEntryV2> {
    RouterAbEd25519PresignPoolAcceptedEntryV2::new(
        offer.client_presign_id.clone(),
        request.generation,
        request.pool_entry_binding_digest(offer)?,
        signing_worker_identity()?,
        format!("server-round1/pool-{nonce_seed}"),
        commitments(nonce_seed, nonce_seed.wrapping_add(1))?,
        b64u(&[nonce_seed.wrapping_add(2); 32]),
        NormalSigningSignatureSchemeV1::Ed25519V1,
        1_800_000_000_000,
        request.expires_at_ms,
    )
}

fn ed25519_pool_hit_finalize_request(
    request: &RouterAbEd25519PresignPoolPrepareRequestV2,
    offer: &RouterAbEd25519PresignPoolClientOfferV2,
    accepted: &RouterAbEd25519PresignPoolAcceptedEntryV2,
) -> RouterAbProtocolResult<RouterAbEd25519PresignPoolHitFinalizeRequestV2> {
    let (intent, payload) = nep413_intent_and_payload()?;
    RouterAbEd25519PresignPoolHitFinalizeRequestV2::new(
        request.scope.clone(),
        request.expires_at_ms,
        RouterAbEd25519PresignPoolHitBindingV2::new(
            offer.client_presign_id.clone(),
            offer.client_nonce_handle.clone(),
            request.generation,
            accepted.server_round1_handle.clone(),
            accepted.pool_entry_binding_digest,
        )?,
        intent,
        payload,
        finalize_protocol()?,
    )
}

fn ed25519_prepare_request() -> RouterAbProtocolResult<RouterAbEd25519NormalSigningPrepareRequestV2>
{
    let (intent, payload) = nep413_intent_and_payload()?;
    RouterAbEd25519NormalSigningPrepareRequestV2::new(
        ed25519_scope()?,
        1_900_000_000_000,
        intent,
        payload,
    )
}

fn ed25519_finalize_request(
    prepare: &RouterAbEd25519NormalSigningPrepareRequestV2,
) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningFinalizeRequestV2> {
    let material = prepare.admission_material()?;
    let binding = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        "server-round1/sign-request-1",
        prepare.round1_binding_digest()?,
        material.intent_digest,
        material.signing_payload_digest,
    )?;
    RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        prepare.scope.clone(),
        prepare.expires_at_ms,
        binding,
        finalize_protocol()?,
    )
}

fn nep413_intent_and_payload() -> RouterAbProtocolResult<(
    RouterAbEd25519NormalSigningIntentV2,
    RouterAbEd25519SigningPayloadV2,
)> {
    let message = "Sign in to the local Router A/B evidence harness";
    let recipient = "wallet.local.test.near";
    let nonce_b64u = b64u(&[0x41; 32]);
    let callback_url = Some("https://local.example/callback".to_owned());
    let canonical_message_b64u = router_ab_ed25519_nep413_canonical_message_b64u_v2(
        message,
        recipient,
        &nonce_b64u,
        callback_url.as_deref(),
    )?;
    let canonical_message = decode_b64u(&canonical_message_b64u)?;
    let expected_signing_digest_b64u = b64u(digest(&canonical_message).as_bytes());
    Ok((
        RouterAbEd25519NormalSigningIntentV2::Nep413V1 {
            operation_id: "operation-1".to_owned(),
            operation_fingerprint: "fingerprint-1".to_owned(),
            near_account_id: "alice.testnet".to_owned(),
            near_network_id: RouterAbNearNetworkIdV2::Testnet,
            recipient: recipient.to_owned(),
            message: message.to_owned(),
            nonce_b64u,
            callback_url,
        },
        RouterAbEd25519SigningPayloadV2::Nep413MessageV1 {
            canonical_message_b64u,
            expected_signing_digest_b64u,
        },
    ))
}

fn finalize_protocol() -> RouterAbProtocolResult<RouterAbEd25519NormalSigningFinalizeProtocolV2> {
    Ok(
        RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
            RouterAbEd25519TwoPartyFrostFinalizeProtocolV2::new(
                commitments(0x11, 0x12)?,
                commitments(0x21, 0x22)?,
                b64u(&[0x31; 32]),
                b64u(&[0x32; 32]),
                b64u(&[0x41; 32]),
            )?,
        ),
    )
}

fn commitments(
    hiding: u8,
    binding: u8,
) -> RouterAbProtocolResult<NormalSigningEd25519TwoPartyFrostCommitmentsV1> {
    NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(b64u(&[hiding; 32]), b64u(&[binding; 32]))
}

fn ed25519_scope() -> RouterAbProtocolResult<NormalSigningScopeV1> {
    NormalSigningScopeV1::new(
        "router-ab-normal-signing/request-1",
        "alice.testnet",
        "session-1",
        "signing-worker-1",
    )
}

fn signing_worker_identity() -> RouterAbProtocolResult<ServerIdentityV1> {
    ServerIdentityV1::new(
        "signing-worker-1",
        "epoch-1",
        "x25519:signing-worker-recipient-key",
    )
}

fn digest(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64u(value: &str) -> RouterAbProtocolResult<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|error| {
        router_ab_core::RouterAbProtocolError::new(
            router_ab_core::RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local evidence base64url decode failed: {error}"),
        )
    })
}

fn secp256k1_public_key33_b64u(prefix: u8, tail: u8) -> String {
    let mut bytes = [tail; 33];
    bytes[0] = prefix;
    b64u(&bytes)
}
