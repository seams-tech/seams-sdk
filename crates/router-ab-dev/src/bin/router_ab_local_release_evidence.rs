use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use router_ab_core::{
    parse_router_ab_ecdsa_derivation_evm_digest_signing_finalize_request_v1_json,
    parse_router_ab_ecdsa_derivation_evm_digest_signing_prepare_response_v1_json,
    parse_router_ab_ecdsa_derivation_evm_digest_signing_request_v1_json,
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningResponseV1, RouterAbEcdsaDerivationNormalSigningScopeV1,
    RouterAbEcdsaDerivationPublicIdentityV1, RouterAbEcdsaDerivationStableKeyContextV1,
    RouterAbProtocolResult, ServerIdentityV1,
};
use serde::Serialize;
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
    router_ab_ecdsa_derivation_normal_signing: RouterAbEcdsaDerivationEvidence,
}

#[derive(Debug, Clone, Serialize)]
struct RouterAbEcdsaDerivationEvidence {
    evidence_kind: &'static str,
    live_http_route_dispatch_evidence: &'static str,
    route_shape: RouterAbEcdsaDerivationRouteShape,
    prepare_finalize_protocol_timing: TimingEvidence,
    signed_digest_b64u: String,
    signature_scheme: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RouterAbEcdsaDerivationRouteShape {
    prepare_route: &'static str,
    finalize_route: &'static str,
    private_pool_fill_route: &'static str,
    private_prepare_route: &'static str,
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
    let ecdsa = router_ab_ecdsa_derivation_evidence()?;
    Ok(EvidenceSummary {
        evidence_version: EVIDENCE_VERSION,
        generated_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default(),
        iterations: ITERATIONS,
        router_ab_ecdsa_derivation_normal_signing: ecdsa,
    })
}

fn router_ab_ecdsa_derivation_evidence() -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvidence>
{
    let prepare = ecdsa_signing_request()?;
    let prepare_response =
        RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1::new_for_request(
            &prepare,
            "server-presignature-1",
            secp256k1_public_key33_b64u(0x03, 0x99),
            b64u(&[0x55; 32]),
            1_800_000_000_000,
        )?;
    let finalize = RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1::new(
        ecdsa_scope()?,
        "ecdsa-sign-request-1",
        1_900_000_000_000,
        b64u(&[0x66; 32]),
        "server-presignature-1",
        b64u(&[0x77; 32]),
    )?;
    let response = RouterAbEcdsaDerivationEvmDigestSigningResponseV1::new_for_request(
        &prepare,
        b64u(&[0x88; 65]),
    )?;
    let timing = time_iterations(ITERATIONS, || {
        let prepare_json = serde_json::to_vec(&prepare).expect("ECDSA prepare JSON");
        let parsed_prepare =
            parse_router_ab_ecdsa_derivation_evm_digest_signing_request_v1_json(&prepare_json)
                .expect("ECDSA prepare parses");
        parsed_prepare
            .validate_at(1_700_000_000_000)
            .expect("ECDSA prepare time-validates");

        let prepare_response_json =
            serde_json::to_vec(&prepare_response).expect("ECDSA prepare response JSON");
        let parsed_prepare_response =
            parse_router_ab_ecdsa_derivation_evm_digest_signing_prepare_response_v1_json(
                &prepare_response_json,
            )
            .expect("ECDSA prepare response parses");
        parsed_prepare_response
            .validate_for_request(&parsed_prepare)
            .expect("ECDSA prepare response binds request");

        let finalize_json = serde_json::to_vec(&finalize).expect("ECDSA finalize JSON");
        let parsed_finalize =
            parse_router_ab_ecdsa_derivation_evm_digest_signing_finalize_request_v1_json(
                &finalize_json,
            )
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

    Ok(RouterAbEcdsaDerivationEvidence {
        evidence_kind: "protocol_shape_parser_binding_timing",
        live_http_route_dispatch_evidence:
            "run pnpm router:check after local services are ready; this report does not open local HTTP listeners",
        route_shape: RouterAbEcdsaDerivationRouteShape {
            prepare_route: "/router-ab/ecdsa-derivation/sign/prepare",
            finalize_route: "/router-ab/ecdsa-derivation/sign",
            private_pool_fill_route: "/router-ab/signing-worker/ecdsa-derivation/presignature-pool/put",
            private_prepare_route: "/router-ab/signing-worker/ecdsa-derivation/sign/prepare",
            private_finalize_route: "/router-ab/signing-worker/ecdsa-derivation/sign",
        },
        prepare_finalize_protocol_timing: timing,
        signed_digest_b64u: prepare.signing_digest_b64u,
        signature_scheme: "ecdsa_secp256k1_recoverable_v1",
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

fn ecdsa_signing_request(
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningRequestV1> {
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        ecdsa_scope()?,
        "ecdsa-sign-request-1",
        "server-presignature-1",
        1_900_000_000_000,
        b64u(&[0x66; 32]),
    )
}

fn ecdsa_scope() -> RouterAbProtocolResult<RouterAbEcdsaDerivationNormalSigningScopeV1> {
    RouterAbEcdsaDerivationNormalSigningScopeV1::new(
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

fn ecdsa_context() -> RouterAbProtocolResult<RouterAbEcdsaDerivationStableKeyContextV1> {
    RouterAbEcdsaDerivationStableKeyContextV1::new(b64u(&[0x42; 32]))
}

fn ecdsa_public_identity() -> RouterAbProtocolResult<RouterAbEcdsaDerivationPublicIdentityV1> {
    let context = ecdsa_context()?;
    RouterAbEcdsaDerivationPublicIdentityV1::new(
        b64u(context.context_binding_digest()?.as_bytes()),
        secp256k1_public_key33_b64u(0x02, 0x11),
        secp256k1_public_key33_b64u(0x03, 0x22),
        secp256k1_public_key33_b64u(0x02, 0x33),
        b64u(&[0x44; 20]),
        0,
        1,
    )
}

fn signing_worker_identity() -> RouterAbProtocolResult<ServerIdentityV1> {
    ServerIdentityV1::new(
        "signing-worker-1",
        "epoch-1",
        "x25519:signing-worker-recipient-key",
    )
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn secp256k1_public_key33_b64u(prefix: u8, tail: u8) -> String {
    let mut bytes = [tail; 33];
    bytes[0] = prefix;
    b64u(&bytes)
}
