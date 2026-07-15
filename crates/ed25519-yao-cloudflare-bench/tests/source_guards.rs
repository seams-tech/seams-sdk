use std::fs;
use std::path::Path;

fn crate_file(path: &str) -> String {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(manifest.join(path)).expect("guard input")
}

fn wrangler_config_paths() -> Vec<String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    for entry in fs::read_dir(manifest).expect("benchmark crate directory") {
        let entry = entry.expect("benchmark crate entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("wrangler") && name.ends_with(".jsonc") {
            paths.push(name);
        }
    }
    paths.sort();
    paths
}

#[test]
fn adapter_keeps_the_phase9b_slice_isolated_and_streaming() {
    let source = crate_file("src/lib.rs");
    for forbidden in [
        "#![allow(dead_code)]",
        "Body::from_stream",
        ".array_buffer(",
        ".collect::<Vec",
        "DurableObject",
        "router_ab",
        "ed25519_hss",
        "ecdsa_hss",
        "isolate_memory_bytes",
        "platform_internal_copy_bytes",
        "worker::response_from_wasm",
        "ByteStream",
        "Uint8Array::to_vec",
        "Bytes::copy_from_slice",
        "dependency-owned-workers-rs-vec-bytes-unzeroized",
        "workers_rs_incoming_generic_body_copy_bytes",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden Phase 9B adapter path: {forbidden}"
        );
    }
    for required in [
        "mpsc::channel(0)",
        "StreamBody::new(outbound)",
        "Pin::new(&mut self.inbound).poll_next(cx)",
        "finish_at_transport_eof()",
        "finish_after_transport_close()",
        "AbortController::default()",
        "Duration::from_secs(15)",
        "Bytes::from_owner(Zeroizing::new(envelope))",
        "struct SecretIncomingBody",
        "try_into_stream()",
        ".dyn_into::<worker::js_sys::Uint8Array>()",
        "chunk.copy_to(owner.as_mut_slice())",
        "chunk.fill(0, 0, chunk.length())",
        "Bytes::from_owner(owner)",
        "request: worker::web_sys::Request",
        "worker_sys::Fetcher",
        "adapter_secret_ingress_rust_copy_bytes",
        "adapter_secret_ingress_js_overwrite_bytes",
        "workers_rs_outgoing_stream_body_copy_bytes",
        "total_incoming_body_bytes",
        "total_outgoing_envelope_bytes",
        "ot_payload_bytes",
        "ot_message_count",
        "ot_sequential_round_count",
        "other_control_payload_bytes",
        "table_transport_bytes",
        "control_transport_bytes",
        "total_ab_transport_bytes",
        "validate_deriver_a_wire_bytes",
        "validate_deriver_b_wire_bytes",
        "YAOS_AB_WIRE_ACCOUNTING",
        "BENCHMARK_DEPLOYMENT_ID",
        "x-ed25519-yao-deployment-id",
        "YAOS_AB_DEPLOYMENT_IDENTITY",
        ".header(DEPLOYMENT_ID_HEADER, deployment_id.header_value()?)",
        "validate_deriver_b_response_identity(",
        "require_matching_deployment_id_header(&headers, &deployment_id)",
        "add_deployment_id_field(&mut report, result.deployment_id())",
        "add_deployment_id_field(&mut report, deployment_id)",
        "serde_json::Value::String(deployment_id.as_str().to_owned())",
        "max_incoming_platform_fragment_bytes",
        "peak_outgoing_envelope_bytes",
        "max_queued_outgoing_envelopes",
        "add_nonpromotion_fields(&mut report)",
        "serde_json::Value::Bool(PRODUCTION_ELIGIBLE)",
        "serde_json::Value::String(INCOMING_SECRET_BUFFER_DISPOSAL.to_owned())",
        "rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled",
    ] {
        assert!(
            source.contains(required),
            "missing source guard: {required}"
        );
    }
}

#[test]
fn every_benchmark_config_pins_one_nonzero_deployment_identity() {
    let paths = wrangler_config_paths();
    assert_eq!(paths.len(), 19, "unexpected Wrangler configuration matrix");
    for path in paths {
        let config: serde_json::Value =
            serde_json::from_str(&crate_file(&path)).expect("Wrangler config");
        let deployment_id = config["vars"]["BENCHMARK_DEPLOYMENT_ID"]
            .as_str()
            .expect("BENCHMARK_DEPLOYMENT_ID string");
        assert_eq!(deployment_id.len(), 32, "invalid deployment ID in {path}");
        assert!(
            deployment_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "deployment ID must be lowercase hex in {path}"
        );
        assert!(
            deployment_id.bytes().any(|byte| byte != b'0'),
            "deployment ID must be nonzero in {path}"
        );
    }
}

#[test]
fn wrangler_configs_pin_the_benchmark_topology() {
    let a: serde_json::Value =
        serde_json::from_str(&crate_file("wrangler.a.jsonc")).expect("A config");
    let b: serde_json::Value =
        serde_json::from_str(&crate_file("wrangler.b.jsonc")).expect("B config");

    for config in [&a, &b] {
        assert_eq!(config["compatibility_date"], "2026-07-02");
        assert_eq!(config["build"]["watch_dir"], "src");
        assert_eq!(config["compatibility_flags"][0], "nodejs_compat");
        assert_eq!(config["observability"]["enabled"], true);
        assert_eq!(config["observability"]["logs"]["enabled"], true);
        assert_eq!(config["observability"]["traces"]["enabled"], true);
        assert_eq!(config["vars"]["BENCHMARK_CLASSIFICATION"], "NON_PRODUCTION");
        assert_eq!(
            config["vars"]["BENCHMARK_TOPOLOGY"],
            "SAME_ACCOUNT_SERVICE_BINDING"
        );
    }
    assert_eq!(a["services"][0]["binding"], "DERIVER_B");
    assert_eq!(a["services"][0]["service"], "ed25519-yao-ab-benchmark-b");
    assert_eq!(a["main"], "build/deriver-a/index.js");
    assert_eq!(b["main"], "build/deriver-b/index.js");
    assert!(b.get("services").is_none());
}

#[test]
fn cross_account_config_is_a_distinct_fixed_https_artifact() {
    let cross: serde_json::Value =
        serde_json::from_str(&crate_file("wrangler.a.cross-account.jsonc"))
            .expect("cross-account A config");
    let cross_b: serde_json::Value =
        serde_json::from_str(&crate_file("wrangler.b.cross-account.jsonc"))
            .expect("cross-account B config");

    assert_eq!(cross["compatibility_date"], "2026-07-02");
    assert_eq!(cross["compatibility_flags"][0], "nodejs_compat");
    assert_eq!(cross["observability"]["enabled"], true);
    assert_eq!(cross["observability"]["logs"]["enabled"], true);
    assert_eq!(cross["observability"]["traces"]["enabled"], true);
    assert_eq!(cross["vars"]["BENCHMARK_CLASSIFICATION"], "NON_PRODUCTION");
    assert_eq!(cross["vars"]["BENCHMARK_TOPOLOGY"], "CROSS_ACCOUNT_HTTPS");
    assert_eq!(
        cross["vars"]["DERIVER_B_HTTPS_ENDPOINT"],
        "https://deriver-b.example.com/benchmark/activation"
    );
    assert_eq!(cross["main"], "build/deriver-a-cross-account/index.js");
    assert!(cross.get("services").is_none());
    assert_eq!(cross_b["compatibility_date"], "2026-07-02");
    assert_eq!(cross_b["compatibility_flags"][0], "nodejs_compat");
    assert_eq!(cross_b["observability"]["enabled"], true);
    assert_eq!(
        cross_b["vars"]["BENCHMARK_CLASSIFICATION"],
        "NON_PRODUCTION"
    );
    assert_eq!(cross_b["vars"]["BENCHMARK_TOPOLOGY"], "CROSS_ACCOUNT_HTTPS");
    assert_eq!(cross_b["main"], "build/deriver-b-cross-account/index.js");
    assert!(cross_b.get("services").is_none());
}

#[test]
fn role_features_are_separate_build_products() {
    let manifest = crate_file("Cargo.toml");
    let source = crate_file("src/lib.rs");
    assert!(manifest.contains("deriver-a = []"));
    assert!(manifest.contains("deriver-a-cross-account = []"));
    assert!(manifest.contains("deriver-b = []"));
    assert!(manifest.contains("deriver-b-cross-account = []"));
    assert!(source.contains("select exactly one Cloudflare role feature"));
    assert!(source.contains("a Worker build requires deriver-a"));
    assert!(source.contains("feature = \"deriver-a-cross-account\""));
    assert!(source.contains(
        "#[cfg(any(feature = \"deriver-a\", feature = \"deriver-a-cross-account\"))]\n    pub(super) struct OutboundEnvelopeStream"
    ));
    assert!(source.contains(
        "#[cfg(any(feature = \"deriver-b\", feature = \"deriver-b-cross-account\", test))]\n    pub(super) struct DeriverBResponseStream"
    ));
}

#[test]
fn cross_account_transport_reuses_the_streaming_driver_without_negotiation() {
    let source = crate_file("src/lib.rs");
    for required in [
        "CrossAccountEndpoint::parse(&raw)",
        "url.scheme() != \"https\"",
        "url.path() != BENCHMARK_PATH",
        "url.query().is_some()",
        "url.fragment().is_some()",
        "RequestRedirect::Error",
        "A_TOPOLOGY_LABEL: &str = \"cross-account-https\"",
        "A_TOPOLOGY_LABEL: &str = \"same-account-service-binding\"",
        "B_TOPOLOGY_LABEL: &str = \"cross-account-https\"",
        "B_TOPOLOGY_LABEL: &str = \"same-account-service-binding\"",
    ] {
        assert!(
            source.contains(required),
            "missing source guard: {required}"
        );
    }
    assert_eq!(
        source.matches("pub(super) async fn run_deriver_a(").count(),
        1
    );
    assert!(!source.contains("runtime_topology"));
    assert!(!source.contains("transport_profile"));
}

#[test]
fn copy_accounting_is_pinned_to_the_workers_rs_boundary() {
    let manifest = crate_file("Cargo.toml");
    let source = crate_file("src/lib.rs");
    assert!(manifest.contains("worker = { version = \"=0.8.5\""));
    assert!(manifest.contains("worker-sys = \"=0.8.5\""));
    assert!(manifest.contains("wasm-streams = \"=0.6.0\""));
    assert!(manifest.contains("zeroize = \"1.8\""));
    assert!(source.contains("WORKERS_RS_VERSION: &str = \"0.8.5\""));
    assert!(source.contains("ADAPTER_SECRET_INGRESS_RUST_COPY_PASSES: u64 = 1"));
    assert!(source.contains("WORKERS_RS_OUTGOING_STREAM_BODY_COPY_PASSES: u64 = 1"));
    assert!(source.contains("MAX_QUEUED_OUTGOING_ENVELOPES: usize = 1"));
    assert!(!source.contains("Bytes::from(envelope)"));
}

#[test]
fn ci_has_a_dedicated_native_and_worker_wasm_constant_time_lane() {
    let workflow = crate_file("../../.github/workflows/ci.yml");
    let job = workflow
        .find("  ed25519-yao-constant-time-codegen:")
        .expect("dedicated constant-time codegen job");
    let next_job = workflow[job + 2..]
        .find("\n  build-and-test:")
        .map(|offset| job + 2 + offset)
        .expect("job following constant-time codegen");
    let lane = &workflow[job..next_job];
    for required in [
        "runs-on: ubuntu-latest",
        "rustup target add wasm32-unknown-unknown",
        "node-version: '24'",
        "sudo apt-get install --yes llvm",
        "command -v llvm-objdump",
        "node crates/ed25519-yao/scripts/check_constant_time_codegen.mjs",
    ] {
        assert!(
            lane.contains(required),
            "missing constant-time CI lane requirement: {required}"
        );
    }
}

#[test]
fn deployment_uploads_the_exact_constant_time_inspected_worker_artifacts() {
    let planner = crate_file("scripts/plan_cloudflare_benchmark.mjs");
    let receipt = crate_file("scripts/deployment_receipt.mjs");
    let viability = crate_file("scripts/evaluate_phase13a_viability.mjs");
    let cold_series = crate_file("scripts/assemble_fresh_version_first_request_series.mjs");
    for required in [
        "inspectWorkerArtifacts(",
        "bindPrebuiltArtifact(configs.b, bArtifactDirectory)",
        "bindPrebuiltArtifact(configs.a, aArtifactDirectory)",
        "attachConstantTimeCodegen(receipt, inspection)",
        "'--no-bundle'",
        "delete rendered.build",
        "validatedLocalReadinessBundleSha256()",
        "evaluateLocalPreflight(bundle.evidence, loadWorkspaceArtifact)",
        "localReadinessBundleSha256",
    ] {
        assert!(
            planner.contains(required),
            "deployment path lost exact inspected-artifact binding: {required}"
        );
    }
    for required in [
        "ed25519_yao_phase9b_deployment_receipt_v4",
        "ed25519_yao_phase9b_topology_binding_v1",
        "ed25519_yao_worker_constant_time_codegen_v1",
        "receipt.constant_time_codegen === null",
        "evidence.wasm_sha256 !== wasm?.sha256",
        "local_readiness_bundle_sha256",
    ] {
        assert!(
            receipt.contains(required),
            "deployment receipt lost constant-time evidence binding: {required}"
        );
    }
    assert!(
        viability.contains(
            "localReadinessBundleSha256 !== validatedCurrentLocalReadinessBundleSha256()"
        ),
        "Phase 13A lost its exact local-readiness bundle binding"
    );
    assert!(
        viability.contains("collectLocalReadinessInputs()"),
        "Phase 13A lost current source/build-input validation"
    );
    for required in [
        "requiredAccountCommitment(",
        "requireExact(aAccount, bAccount",
        "if (aAccount === bAccount)",
        "if (aHostname === bHostname)",
    ] {
        assert!(
            viability.contains(required),
            "Phase 13A lost account/hostname topology validation: {required}"
        );
    }
    assert!(
        cold_series.contains("deployment.local_readiness_bundle_sha256"),
        "cold-proxy cohorts lost their local-readiness bundle binding"
    );
}

#[test]
fn placement_evidence_is_validated_at_fixed_worker_boundaries() {
    let source = crate_file("src/lib.rs");
    for required in [
        "raw.len() != 3 || !raw.bytes().all(|byte| byte.is_ascii_uppercase())",
        "extensions()\n            .get::<worker::Cf>()",
        "x-ed25519-yao-a-colo",
        "x-ed25519-yao-b-colo",
        "optional_colo_header(&response.headers, DERIVER_B_COLO_HEADER)",
        "raw_incoming_colo(&request)",
        "request_builder.header(DERIVER_A_COLO_HEADER, colo.header_value()?)",
        "response = response.header(adapter::DERIVER_B_COLO_HEADER, colo)",
        "\"deriver_a_colo\": placement.deriver_a_colo().map",
        "\"deriver_b_colo\": placement.deriver_b_colo().map",
        "YAOS_AB_PLACEMENT_EVIDENCE",
    ] {
        assert!(
            source.contains(required),
            "missing placement source guard: {required}"
        );
    }
    assert_eq!(source.matches("pub(super) struct Colo(String);").count(), 1);
    assert!(source.matches("DERIVER_A_COLO_HEADER").count() > 2);
    assert!(source.matches("DERIVER_B_COLO_HEADER").count() > 2);
    assert!(!source.contains("cf-ray"));
    assert!(!source.contains("cf-ipcountry"));

    let b_response_header = source
        .rfind("response = response.header(adapter::DERIVER_B_COLO_HEADER, colo)")
        .expect("B colo response header");
    let b_stream = source
        .rfind("match adapter::DeriverBResponseStream::new")
        .expect("B response stream construction");
    let b_body = source
        .rfind("http_body_util::StreamBody::new(stream)")
        .expect("B streaming response body");
    assert!(b_response_header < b_stream);
    assert!(b_stream < b_body);
}

#[test]
fn transport_timing_uses_io_boundaries_without_changing_protocol_frames() {
    let source = crate_file("src/lib.rs");
    let evaluator = crate_file("scripts/evaluate_phase13a_viability.mjs");
    for required in [
        "trait IoBoundaryClock",
        "worker::js_sys::Date::now()",
        "TransportTimingRecorder::worker()?",
        "TimingEvent::BResponseHeadersReceived",
        "TimingEvent::BToABodyByteReceived",
        "TimingEvent::OfferReceived",
        "TimingEvent::AToBBodyByteEmitted",
        "TimingEvent::ExtensionReceived",
        "TimingEvent::TableFrameAccepted",
        "TimingEvent::TranslationAccepted",
        "TimingEvent::RequestDirectionClosed",
        "TimingEvent::ReturnedReceived",
        "TimingEvent::ResponseEofComplete",
        "worker-date-now",
        "deployed-advances-after-io",
        "deriver-a-protocol-start",
        "outbound-stream-backpressure-acceptance",
        "raw-stream-chunk-emission-and-receipt",
        "b_to_a_first_body_byte_received_ms",
        "a_to_b_first_body_byte_emitted_ms",
        "a_to_b_final_body_byte_emitted_ms",
        "b_to_a_final_body_byte_received_ms",
        "first_table_frame_accepted_ms",
        "last_table_frame_accepted_ms",
        "table_stream_duration_ms",
        "total_protocol_duration_ms",
        "YAOS_AB_TIMING_EVIDENCE",
    ] {
        assert!(
            source.contains(required),
            "missing timing source guard: {required}"
        );
    }
    assert!(!source.contains("static mut"));
    assert!(!source.contains("SystemTime::now"));
    assert!(!source.contains("Instant::now"));
    assert_eq!(
        source.matches("pub(super) async fn run_deriver_a(").count(),
        1
    );
    for required in [
        "mismatchedActivationWireField(result)",
        "result.last_table_frame_accepted_ms - result.first_table_frame_accepted_ms",
        "requireColdProxyArtifactsMatch(sameColdProxy, sameBenchmark",
        "requireColdProxyArtifactsMatch(crossColdProxy, crossBenchmark",
    ] {
        assert!(
            evaluator.contains(required),
            "Phase 13A lost exact timing/wire/cold-cohort validation: {required}"
        );
    }
}

#[test]
fn fault_artifacts_are_compile_time_only_and_topology_fixed() {
    let manifest = crate_file("Cargo.toml");
    let source = crate_file("src/lib.rs");
    for feature in [
        "fault-fragmentation = []",
        "fault-request-disconnect-after-base-choices = []",
        "fault-response-disconnect-after-offer = []",
        "fault-trailing-after-terminal = []",
        "fault-short-timeout = []",
        "fault-stall-after-offer = []",
        "fault-wrong-role-offer-tag = []",
        "fault-session-mismatch = []",
    ] {
        assert!(
            manifest.contains(feature),
            "missing fault feature: {feature}"
        );
    }
    for forbidden in [
        "x-yaos-fault",
        "fault_mode",
        "FAULT_MODE",
        "query_pairs",
        "runtime_fault",
    ] {
        assert!(
            !source.contains(forbidden),
            "runtime fault negotiation is forbidden: {forbidden}"
        );
    }
    for required in [
        "DeterministicFragments",
        "YAOS_AB_INJECTED_REQUEST_DISCONNECT",
        "YAOS_AB_INJECTED_RESPONSE_DISCONNECT",
        "YAOS_AB_FAULT_TRAILING_AFTER_TERMINAL",
        "Duration::from_millis(250)",
        "fault-stall-after-offer",
        "inject_wrong_role_offer_tag",
        "role_session(session)",
        "require_empty_public_request_body",
        "YAOS_AB_PUBLIC_BODY_NONEMPTY",
        "injected_outgoing_fragment_count",
        "max_injected_outgoing_fragment_bytes",
    ] {
        assert!(source.contains(required), "missing fault guard: {required}");
    }
    let public_body_boundary = source
        .find("require_empty_public_request_body(request.body_mut())")
        .expect("public body boundary");
    let session_creation = source
        .find("let session = match adapter::random_session()")
        .expect("session creation");
    assert!(
        public_body_boundary < session_creation,
        "public input must be rejected before session creation or any A/B fetch"
    );

    for path in [
        "wrangler.fault.fragmentation.a.jsonc",
        "wrangler.fault.fragmentation.b.jsonc",
        "wrangler.fault.request-disconnect.a.jsonc",
        "wrangler.fault.response-disconnect.a.jsonc",
        "wrangler.fault.response-disconnect.b.jsonc",
        "wrangler.fault.trailing.a.jsonc",
        "wrangler.fault.trailing.b.jsonc",
        "wrangler.fault.timeout.a.jsonc",
        "wrangler.fault.timeout.b.jsonc",
        "wrangler.fault.wrong-service.a.jsonc",
        "wrangler.fault.wrong-service.service.jsonc",
        "wrangler.fault.wrong-role.a.jsonc",
        "wrangler.fault.wrong-role.b.jsonc",
        "wrangler.fault.session-mismatch.a.jsonc",
        "wrangler.fault.session-mismatch.b.jsonc",
    ] {
        let config: serde_json::Value =
            serde_json::from_str(&crate_file(path)).expect("fault config");
        assert_eq!(config["compatibility_date"], "2026-07-02");
        assert_eq!(config["compatibility_flags"][0], "nodejs_compat");
        assert_eq!(
            config["vars"]["BENCHMARK_CLASSIFICATION"],
            "NON_PRODUCTION_FAULT_INJECTION"
        );
        assert_eq!(
            config["vars"]["BENCHMARK_TOPOLOGY"],
            "SAME_ACCOUNT_SERVICE_BINDING"
        );
    }

    let wrong_service_a: serde_json::Value =
        serde_json::from_str(&crate_file("wrangler.fault.wrong-service.a.jsonc"))
            .expect("wrong-service A config");
    let wrong_service: serde_json::Value =
        serde_json::from_str(&crate_file("wrangler.fault.wrong-service.service.jsonc"))
            .expect("wrong-service config");
    assert_eq!(
        wrong_service_a["services"][0]["service"],
        "ed25519-yao-ab-benchmark-fixed-wrong-service"
    );
    assert_eq!(wrong_service["main"], "src/wrong_service.mjs");
    let package = crate_file("package.json");
    let wrong_service_dev = package
        .lines()
        .find(|line| line.contains("dev:fault:wrong-service"))
        .expect("wrong-service dev command");
    assert!(!wrong_service_dev.contains("wrangler.b.jsonc"));
    assert!(!wrong_service_dev.contains("wrangler.b.cross-account.jsonc"));
}
