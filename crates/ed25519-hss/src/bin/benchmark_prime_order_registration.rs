use std::fs;
use std::hint::black_box;
use std::process;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_hss::ddh::DdhHiddenEvalStageProfile;
use ed25519_hss::fixtures::{deterministic_fixture_corpus, FExpandFixture};
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
use ed25519_hss::server::ServerEvalOperation;
use ed25519_hss::shared::{FExpandInput, ProtoError, ProtoResult};
use ed25519_hss::wire::StagedEvaluatorArtifact;
use serde::{Deserialize, Serialize};

const REPORT_VERSION: &str = "prime_order_hss_registration_benchmark_v1";

fn main() {
    let args = match CliArgs::parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };

    let fixture = select_fixture(args.fixture_name.as_deref());
    for _ in 0..args.warmup_iterations {
        run_registration_sample(&fixture.input, 0).expect("warm up registration benchmark");
    }

    let mut samples = Vec::with_capacity(args.sample_count);
    for sample_index in 0..args.sample_count {
        samples.push(
            run_registration_sample(&fixture.input, sample_index)
                .expect("run registration benchmark sample"),
        );
    }

    let report = PrimeOrderRegistrationBenchmarkReport::from_samples(
        fixture.name,
        args.into_config_record(),
        samples,
    );
    let json = serde_json::to_string_pretty(&report)
        .expect("serialize prime-order registration benchmark report");

    if let Some(path) = report.config.output_path.as_ref() {
        fs::write(path, &json).expect("write prime-order registration benchmark report");
        eprintln!("wrote prime-order registration benchmark report to {path}");
    }

    if report.config.emit_json {
        println!("{json}");
    } else {
        for line in report.summary_lines() {
            println!("{line}");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    emit_json: bool,
    output_path: Option<String>,
    fixture_name: Option<String>,
    warmup_iterations: usize,
    sample_count: usize,
}

impl CliArgs {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut parsed = Self {
            emit_json: false,
            output_path: None,
            fixture_name: None,
            warmup_iterations: 1,
            sample_count: 6,
        };

        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--json" => {
                    parsed.emit_json = true;
                    idx += 1;
                }
                "--output" => {
                    parsed.output_path = Some(read_next_value(&args, &mut idx, "--output")?);
                }
                "--fixture" => {
                    parsed.fixture_name = Some(read_next_value(&args, &mut idx, "--fixture")?);
                }
                "--warmup" => {
                    parsed.warmup_iterations =
                        parse_usize(&read_next_value(&args, &mut idx, "--warmup")?, "--warmup")?;
                }
                "--samples" => {
                    parsed.sample_count =
                        parse_usize(&read_next_value(&args, &mut idx, "--samples")?, "--samples")?;
                    if parsed.sample_count == 0 {
                        return Err(format!(
                            "--samples must be greater than 0\n\n{}",
                            Self::usage()
                        ));
                    }
                }
                "--help" | "-h" => {
                    return Err(Self::usage());
                }
                other => {
                    return Err(format!("unknown argument: {other}\n\n{}", Self::usage()));
                }
            }
        }

        Ok(parsed)
    }

    fn usage() -> String {
        [
            "Usage: benchmark_prime_order_registration [options]",
            "",
            "Options:",
            "  --json                  Print the full JSON report",
            "  --output <path>         Write the JSON report to a file",
            "  --fixture <name>        Use a specific deterministic fixture",
            "  --warmup <n>            Full-flow warmup iterations",
            "  --samples <n>           Number of timed samples",
        ]
        .join("\n")
    }

    fn into_config_record(self) -> PrimeOrderRegistrationBenchmarkConfigRecord {
        PrimeOrderRegistrationBenchmarkConfigRecord {
            emit_json: self.emit_json,
            output_path: self.output_path,
            fixture_name: self.fixture_name,
            warmup_iterations: self.warmup_iterations,
            sample_count: self.sample_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrimeOrderRegistrationBenchmarkConfigRecord {
    emit_json: bool,
    output_path: Option<String>,
    fixture_name: Option<String>,
    warmup_iterations: usize,
    sample_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PrimeOrderRegistrationBenchmarkReport {
    report_version: String,
    generated_at_unix_secs: u64,
    fixture_name: String,
    config: PrimeOrderRegistrationBenchmarkConfigRecord,
    phase_stats: Vec<NamedLatencyStats>,
    hidden_eval_stats: Vec<NamedLatencyStats>,
    samples: Vec<PrimeOrderRegistrationBenchmarkSample>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PrimeOrderRegistrationBenchmarkSample {
    sample_index: usize,
    total_ns: u128,
    prepare_session_ns: u128,
    materialize_sessions_ns: u128,
    client_offer_message_ns: u128,
    client_request_ns: u128,
    server_input_delivery_ns: u128,
    client_artifact_ns: u128,
    finalize_report_ns: u128,
    artifact_bytes: usize,
    staged_evaluator_artifact_bytes: usize,
    staged_evaluator_artifact_b64url_chars: usize,
    staged_evaluator_artifact_field_sizes: StagedEvaluatorArtifactSizeBreakdown,
    client_request_bytes: usize,
    server_input_delivery_bytes: usize,
    client_output_bytes: usize,
    seed_output_bytes: usize,
    server_output_bytes: usize,
    hidden_eval_profile: DdhHiddenEvalStageProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StagedEvaluatorArtifactSizeBreakdown {
    backend_version: usize,
    context_binding: usize,
    bindings: usize,
    projection_mode: usize,
    output_projector_binding: usize,
    client_output_value_kind: usize,
    client_output_commitment: usize,
    evaluator_witness: usize,
    client_output: usize,
    client_output_binding: usize,
    seed_output: usize,
    seed_output_binding: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NamedLatencyStats {
    name: String,
    count: usize,
    min_ns: u128,
    mean_ns: u128,
    p50_ns: u128,
    p95_ns: u128,
    max_ns: u128,
}

impl PrimeOrderRegistrationBenchmarkReport {
    fn from_samples(
        fixture_name: String,
        config: PrimeOrderRegistrationBenchmarkConfigRecord,
        samples: Vec<PrimeOrderRegistrationBenchmarkSample>,
    ) -> Self {
        let phase_stats = vec![
            latency_stats(
                "total",
                samples.iter().map(|sample| sample.total_ns).collect(),
            ),
            latency_stats(
                "prepare_session",
                samples
                    .iter()
                    .map(|sample| sample.prepare_session_ns)
                    .collect(),
            ),
            latency_stats(
                "materialize_sessions",
                samples
                    .iter()
                    .map(|sample| sample.materialize_sessions_ns)
                    .collect(),
            ),
            latency_stats(
                "client_offer_message",
                samples
                    .iter()
                    .map(|sample| sample.client_offer_message_ns)
                    .collect(),
            ),
            latency_stats(
                "client_request",
                samples
                    .iter()
                    .map(|sample| sample.client_request_ns)
                    .collect(),
            ),
            latency_stats(
                "server_input_delivery",
                samples
                    .iter()
                    .map(|sample| sample.server_input_delivery_ns)
                    .collect(),
            ),
            latency_stats(
                "client_artifact",
                samples
                    .iter()
                    .map(|sample| sample.client_artifact_ns)
                    .collect(),
            ),
            latency_stats(
                "finalize_report",
                samples
                    .iter()
                    .map(|sample| sample.finalize_report_ns)
                    .collect(),
            ),
        ];
        let hidden_eval_stats = vec![
            profile_latency_stats("hidden_eval_total", &samples, |profile| {
                profile.total_duration_ns
            }),
            profile_latency_stats("hidden_eval_round_core", &samples, |profile| {
                profile.round_core_duration_ns
            }),
            profile_latency_stats("hidden_eval_output_projector", &samples, |profile| {
                profile.output_projector_duration_ns
            }),
            profile_latency_stats("hidden_eval_message_schedule", &samples, |profile| {
                profile.message_schedule_duration_ns
            }),
            profile_latency_stats("hidden_eval_round_ch", &samples, |profile| {
                profile.round_ch_duration_ns
            }),
            profile_latency_stats("hidden_eval_round_maj", &samples, |profile| {
                profile.round_maj_duration_ns
            }),
            profile_latency_stats("hidden_eval_round_new_a_bits", &samples, |profile| {
                profile.round_new_a_bits_duration_ns
            }),
            profile_latency_stats("hidden_eval_round_new_e_bits", &samples, |profile| {
                profile.round_new_e_bits_duration_ns
            }),
        ];

        Self {
            report_version: REPORT_VERSION.to_string(),
            generated_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default(),
            fixture_name,
            config,
            phase_stats,
            hidden_eval_stats,
            samples,
        }
    }

    fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "prime-order HSS registration benchmark: fixture={} samples={}",
            self.fixture_name, self.config.sample_count
        )];

        lines.push("phases:".to_string());
        lines.extend(self.phase_stats.iter().map(summary_line));
        lines.push("hidden_eval:".to_string());
        lines.extend(self.hidden_eval_stats.iter().map(summary_line));

        lines
    }
}

fn run_registration_sample(
    input: &FExpandInput,
    sample_index: usize,
) -> ProtoResult<PrimeOrderRegistrationBenchmarkSample> {
    let total_started = Instant::now();

    let prepare_started = Instant::now();
    let session = prepare_prime_order_succinct_hss(&input.context)?;
    let prepare_session_ns = prepare_started.elapsed().as_nanos();

    let materialize_started = Instant::now();
    let runtime = session.shared_runtime();
    let garbler_session = session.garbler_session();
    let evaluator_session = session.evaluator_session();
    let materialize_sessions_ns = materialize_started.elapsed().as_nanos();

    let client_offer_started = Instant::now();
    let client_ot_offer_message = garbler_session.client_ot_offer_message()?;
    let client_offer_message_ns = client_offer_started.elapsed().as_nanos();

    let client_request_started = Instant::now();
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            input.y_client,
            input.tau_client,
        )?;
    let client_request_ns = client_request_started.elapsed().as_nanos();

    let server_input_delivery_started = Instant::now();
    let (delivery, server_eval_state) = garbler_session
        .prepare_role_separated_server_input_delivery_message(
            &client_request_message,
            input.y_server,
            input.tau_server,
            ServerEvalOperation::Registration,
        )?;
    let server_input_delivery_ns = server_input_delivery_started.elapsed().as_nanos();

    let client_artifact_started = Instant::now();
    let (artifact, hidden_eval_profile) = evaluator_session
        .build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_message_profiled(
            &runtime,
            &client_request_message,
            &evaluator_ot_state,
            &delivery,
            [0x5a; 32],
        )?;
    let client_artifact_ns = client_artifact_started.elapsed().as_nanos();
    let staged_evaluator_artifact_bytes = serialize_for_size(&artifact, "staged artifact")?;
    let staged_evaluator_artifact_field_sizes =
        staged_evaluator_artifact_size_breakdown(&artifact)?;

    let finalize_started = Instant::now();
    let flow = session
        .prepare_server_assist_flow_to_output_projection_from_role_separated_delivery(
            &server_eval_state,
            &client_request_message,
            &evaluator_ot_state,
            &delivery,
        )?;
    let finalize_state = flow
        .final_server_eval_state
        .finalize_state()
        .ok_or_else(|| {
            ProtoError::InvalidInput("server eval state must be finalized".to_string())
        })?;
    let report = runtime.finalize_report_from_staged_evaluator_artifact(
        &garbler_session,
        &artifact,
        &finalize_state.output,
    )?;
    let finalize_report_ns = finalize_started.elapsed().as_nanos();
    black_box(&report);

    Ok(PrimeOrderRegistrationBenchmarkSample {
        sample_index,
        total_ns: total_started.elapsed().as_nanos(),
        prepare_session_ns,
        materialize_sessions_ns,
        client_offer_message_ns,
        client_request_ns,
        server_input_delivery_ns,
        client_artifact_ns,
        finalize_report_ns,
        artifact_bytes: session.artifact_bytes().len(),
        staged_evaluator_artifact_b64url_chars: base64_url_len(&staged_evaluator_artifact_bytes),
        staged_evaluator_artifact_bytes: staged_evaluator_artifact_bytes.len(),
        staged_evaluator_artifact_field_sizes,
        client_request_bytes: client_request_message.bytes.len(),
        server_input_delivery_bytes: delivery.server_inputs.nonce.len()
            + delivery.server_inputs.ciphertext.len(),
        client_output_bytes: report.output_delivery.client.bytes.len(),
        seed_output_bytes: report.output_delivery.seed.bytes.len(),
        server_output_bytes: report.output_delivery.server.bytes.len(),
        hidden_eval_profile,
    })
}

fn staged_evaluator_artifact_size_breakdown(
    artifact: &StagedEvaluatorArtifact,
) -> ProtoResult<StagedEvaluatorArtifactSizeBreakdown> {
    Ok(StagedEvaluatorArtifactSizeBreakdown {
        backend_version: serialize_for_size(&artifact.backend_version, "backend_version")?.len(),
        context_binding: serialize_for_size(&artifact.context_binding, "context_binding")?.len(),
        bindings: serialize_for_size(&artifact.bindings, "bindings")?.len(),
        projection_mode: serialize_for_size(&artifact.projection_mode, "projection_mode")?.len(),
        output_projector_binding: serialize_for_size(
            &artifact.output_projector_binding,
            "output_projector_binding",
        )?
        .len(),
        client_output_value_kind: serialize_for_size(
            &artifact.client_output_value_kind,
            "client_output_value_kind",
        )?
        .len(),
        client_output_commitment: serialize_for_size(
            &artifact.client_output_commitment,
            "client_output_commitment",
        )?
        .len(),
        evaluator_witness: serialize_for_size(&artifact.evaluator_witness, "evaluator_witness")?
            .len(),
        client_output: serialize_for_size(&artifact.client_output, "client_output")?.len(),
        client_output_binding: serialize_for_size(
            &artifact.client_output_binding,
            "client_output_binding",
        )?
        .len(),
        seed_output: serialize_for_size(&artifact.seed_output, "seed_output")?.len(),
        seed_output_binding: serialize_for_size(
            &artifact.seed_output_binding,
            "seed_output_binding",
        )?
        .len(),
    })
}

fn serialize_for_size<T: serde::Serialize>(value: &T, label: &str) -> ProtoResult<Vec<u8>> {
    bincode::serialize(value).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to serialize {label} for benchmark sizing: {err}"
        ))
    })
}

fn base64_url_len(bytes: &[u8]) -> usize {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(bytes)
        .len()
}

fn select_fixture(name: Option<&str>) -> FExpandFixture {
    let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
    match name {
        Some(fixture_name) => fixtures
            .into_iter()
            .find(|fixture| fixture.name == fixture_name)
            .unwrap_or_else(|| panic!("unknown fixture: {fixture_name}")),
        None => fixtures.into_iter().next().expect("at least one fixture"),
    }
}

fn latency_stats(name: &str, mut values: Vec<u128>) -> NamedLatencyStats {
    values.sort_unstable();
    let count = values.len();
    let min_ns = values.first().copied().unwrap_or_default();
    let max_ns = values.last().copied().unwrap_or_default();
    let mean_ns = if count == 0 {
        0
    } else {
        values.iter().sum::<u128>() / count as u128
    };
    NamedLatencyStats {
        name: name.to_string(),
        count,
        min_ns,
        mean_ns,
        p50_ns: percentile_sorted(&values, 0.50),
        p95_ns: percentile_sorted(&values, 0.95),
        max_ns,
    }
}

fn profile_latency_stats<F>(
    name: &str,
    samples: &[PrimeOrderRegistrationBenchmarkSample],
    read: F,
) -> NamedLatencyStats
where
    F: Fn(&DdhHiddenEvalStageProfile) -> u128,
{
    latency_stats(
        name,
        samples
            .iter()
            .map(|sample| read(&sample.hidden_eval_profile))
            .collect(),
    )
}

fn percentile_sorted(values: &[u128], percentile: f64) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let index = ((values.len() - 1) as f64 * percentile).ceil() as usize;
    values[index.min(values.len() - 1)]
}

fn summary_line(stats: &NamedLatencyStats) -> String {
    format!(
        "  {}: p50={:.3}ms p95={:.3}ms mean={:.3}ms max={:.3}ms",
        stats.name,
        ns_to_ms(stats.p50_ns),
        ns_to_ms(stats.p95_ns),
        ns_to_ms(stats.mean_ns),
        ns_to_ms(stats.max_ns),
    )
}

fn ns_to_ms(ns: u128) -> f64 {
    ns as f64 / 1_000_000.0
}

fn read_next_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    if *idx >= args.len() {
        return Err(format!("missing value for {flag}\n\n{}", CliArgs::usage()));
    }
    let value = args[*idx].clone();
    *idx += 1;
    Ok(value)
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}
