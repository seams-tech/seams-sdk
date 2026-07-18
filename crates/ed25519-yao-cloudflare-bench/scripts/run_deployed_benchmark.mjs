import { pathToFileURL } from "node:url";

import { BoundaryError, parseDeploymentEnvironment } from "./deployment_boundary.mjs";
import {
  deploymentReceiptEvidence,
  deploymentReceiptPath,
  readDeploymentReceipt,
} from "./deployment_receipt.mjs";
import { mismatchedActivationWireField } from "./activation_wire_profile.mjs";

const MAX_RESPONSE_BYTES = 65_536;
const REQUEST_TIMEOUT_MS = 120_000;
const EXPECTED_BENCHMARK = "phase9b-cloudflare-activation-128kib";
const EXPECTED_TABLE_PAYLOAD_BYTES = 2_104_960;
const EXPECTED_TIMING_SEMANTICS =
  "worker-date-now;deployed-advances-after-io;milestones-relative-to-deriver-a-protocol-start";
const EXPECTED_TABLE_TIMING_BOUNDARY = "websocket-send-queue-acceptance";
const EXPECTED_BODY_BYTE_TIMING_BOUNDARY = "websocket-binary-message-send-and-receipt";
const EXPECTED_INCOMING_SECRET_BUFFER_DISPOSAL =
  "rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled";
const METRIC_FIELDS = Object.freeze([
  "elapsed_ms",
  "b_response_headers_received_ms",
  "b_to_a_first_body_byte_received_ms",
  "offer_received_ms",
  "a_to_b_first_body_byte_emitted_ms",
  "extension_received_ms",
  "first_table_frame_accepted_ms",
  "last_table_frame_accepted_ms",
  "translation_accepted_ms",
  "a_to_b_final_body_byte_emitted_ms",
  "request_direction_closed_ms",
  "b_to_a_final_body_byte_received_ms",
  "returned_received_ms",
  "response_eof_complete_ms",
  "table_stream_duration_ms",
  "total_protocol_duration_ms",
  "table_payload_bytes",
  "body_bytes",
  "frame_count",
  "table_framing_payload_bytes",
  "table_protocol_bytes",
  "ot_payload_bytes",
  "other_control_payload_bytes",
  "envelope_header_bytes",
  "table_transport_bytes",
  "control_transport_bytes",
  "deriver_a_to_b_transport_bytes",
  "deriver_b_to_a_transport_bytes",
  "total_ab_transport_bytes",
  "transport_message_count",
  "ot_message_count",
  "ot_sequential_round_count",
  "peak_table_buffer_bytes",
  "total_incoming_body_bytes",
  "max_incoming_platform_fragment_bytes",
  "adapter_secret_ingress_rust_copy_bytes",
  "adapter_secret_ingress_js_overwrite_bytes",
  "total_outgoing_envelope_bytes",
  "peak_outgoing_envelope_bytes",
  "workers_rs_outgoing_stream_body_copy_bytes",
  "injected_outgoing_fragment_count",
  "max_injected_outgoing_fragment_bytes",
  "max_queued_outgoing_envelopes",
]);
const AUXILIARY_NUMERIC_FIELDS = Object.freeze([
  "client_package_bytes",
  "signing_worker_package_bytes",
  "adapter_secret_ingress_rust_copy_passes",
  "workers_rs_outgoing_stream_body_copy_passes",
]);

function compareNumbers(left, right) {
  return left - right;
}

function percentile(values, percentileValue) {
  if (values.length === 0) {
    return null;
  }
  const sorted = [...values].sort(compareNumbers);
  const rank = Math.max(0, Math.ceil(percentileValue * sorted.length) - 1);
  return sorted[rank];
}

function summarize(values) {
  if (values.length === 0) {
    return null;
  }
  return Object.freeze({
    min: Math.min(...values),
    p50: percentile(values, 0.5),
    p95: percentile(values, 0.95),
    p99: percentile(values, 0.99),
    max: Math.max(...values),
  });
}

function isFiniteNonnegative(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function requireMetric(result, field) {
  const value = result[field];
  if (!isFiniteNonnegative(value)) {
    throw new BoundaryError(`benchmark response has invalid ${field}`);
  }
  return value;
}

function isNullableColo(value) {
  return value === null || (typeof value === "string" && /^[A-Z]{3}$/.test(value));
}

function validateTimingEvidence(result) {
  const milestones = [
    result.b_response_headers_received_ms,
    result.b_to_a_first_body_byte_received_ms,
    result.offer_received_ms,
    result.a_to_b_first_body_byte_emitted_ms,
    result.extension_received_ms,
    result.first_table_frame_accepted_ms,
    result.last_table_frame_accepted_ms,
    result.translation_accepted_ms,
    result.a_to_b_final_body_byte_emitted_ms,
    result.request_direction_closed_ms,
    result.b_to_a_final_body_byte_received_ms,
    result.returned_received_ms,
    result.response_eof_complete_ms,
  ];
  for (let index = 1; index < milestones.length; index += 1) {
    if (milestones[index - 1] > milestones[index]) {
      throw new BoundaryError("benchmark response has unordered timing evidence");
    }
  }
  if (
    result.table_stream_duration_ms !==
      result.last_table_frame_accepted_ms - result.first_table_frame_accepted_ms ||
    result.total_protocol_duration_ms !== result.response_eof_complete_ms ||
    result.elapsed_ms < result.total_protocol_duration_ms
  ) {
    throw new BoundaryError("benchmark response has inconsistent timing evidence");
  }
}

function validateSuccess(result, expectedTopology, deploymentId) {
  if (
    result === null ||
    typeof result !== "object" ||
    result.ok !== true ||
    result.benchmark_only !== true ||
    result.production_eligible !== false ||
    result.incoming_secret_buffer_disposal !== EXPECTED_INCOMING_SECRET_BUFFER_DISPOSAL ||
    result.benchmark !== EXPECTED_BENCHMARK ||
    result.role !== "deriver-a" ||
    result.topology !== expectedTopology ||
    result.deployment_id !== deploymentId ||
    result.family !== "activation" ||
    result.profile !== "128KiB" ||
    result.timing_semantics !== EXPECTED_TIMING_SEMANTICS ||
    result.table_timing_boundary !== EXPECTED_TABLE_TIMING_BOUNDARY ||
    result.body_byte_timing_boundary !== EXPECTED_BODY_BYTE_TIMING_BOUNDARY ||
    result.table_payload_bytes !== EXPECTED_TABLE_PAYLOAD_BYTES ||
    result.max_queued_outgoing_envelopes !== 1 ||
    !Object.hasOwn(result, "deriver_a_colo") ||
    !Object.hasOwn(result, "deriver_b_colo") ||
    !isNullableColo(result.deriver_a_colo) ||
    !isNullableColo(result.deriver_b_colo)
  ) {
    throw new BoundaryError("benchmark response violates the fixed profile");
  }
  for (const field of METRIC_FIELDS) {
    requireMetric(result, field);
  }
  for (const field of AUXILIARY_NUMERIC_FIELDS) {
    requireMetric(result, field);
  }
  const mismatchedWireField = mismatchedActivationWireField(result);
  if (mismatchedWireField !== null) {
    throw new BoundaryError(
      `benchmark response has invalid wire accounting: ${mismatchedWireField}`,
    );
  }
  if (
    result.adapter_secret_ingress_rust_copy_passes !== 1 ||
    result.adapter_secret_ingress_rust_copy_bytes !== result.total_incoming_body_bytes ||
    result.adapter_secret_ingress_js_overwrite_bytes !== result.total_incoming_body_bytes ||
    result.workers_rs_outgoing_stream_body_copy_passes !== 1 ||
    result.workers_rs_outgoing_stream_body_copy_bytes !== result.total_outgoing_envelope_bytes
  ) {
    throw new BoundaryError("benchmark response has invalid secret transport copy accounting");
  }
  validateTimingEvidence(result);
  if (typeof result.workers_rs_version !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(result.workers_rs_version)) {
    throw new BoundaryError("benchmark response has invalid workers_rs_version");
  }
}

function sanitizeSuccess(result) {
  const sanitized = {
    benchmark: result.benchmark,
    benchmark_only: result.benchmark_only,
    production_eligible: result.production_eligible,
    incoming_secret_buffer_disposal: result.incoming_secret_buffer_disposal,
    role: result.role,
    topology: result.topology,
    deployment_id: result.deployment_id,
    family: result.family,
    profile: result.profile,
    workers_rs_version: result.workers_rs_version,
    timing_semantics: result.timing_semantics,
    table_timing_boundary: result.table_timing_boundary,
    deriver_a_colo: result.deriver_a_colo,
    deriver_b_colo: result.deriver_b_colo,
  };
  for (const field of [...METRIC_FIELDS, ...AUXILIARY_NUMERIC_FIELDS]) {
    sanitized[field] = result[field];
  }
  return Object.freeze(sanitized);
}

function rayColo(ray) {
  if (typeof ray !== "string") {
    return null;
  }
  const match = /-([A-Z]{3})$/.exec(ray);
  return match?.[1] ?? null;
}

function responseObservation(response) {
  const cfRay = response.headers.get("cf-ray");
  return Object.freeze({
    cf_ray_present: cfRay !== null,
    a_colo: rayColo(cfRay),
    server: response.headers.get("server"),
    server_timing: response.headers.get("server-timing"),
    alt_svc: response.headers.get("alt-svc"),
    connection: response.headers.get("connection"),
    cache_status: response.headers.get("cf-cache-status"),
  });
}

async function readBoundedJson(response) {
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) {
    throw new BoundaryError("benchmark response exceeds the bounded JSON limit");
  }
  if (response.body === null) {
    throw new BoundaryError("benchmark response has no body");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const next = await reader.read();
    if (next.done) {
      break;
    }
    total += next.value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel("bounded benchmark response exceeded");
      throw new BoundaryError("benchmark response exceeds the bounded JSON limit");
    }
    chunks.push(next.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(merged));
  } catch {
    throw new BoundaryError("benchmark response is not valid JSON");
  }
  return parsed;
}

function recoverableFailure(index, startedAt, clientWallMs, status, observation, errorCode) {
  return Object.freeze({
    index,
    started_at: startedAt,
    client_wall_ms: clientWallMs,
    status,
    observation,
    error_code: errorCode,
  });
}

function errorCode(error) {
  if (error instanceof BoundaryError) {
    return "INVALID_BENCHMARK_RESPONSE";
  }
  if (error?.name === "TimeoutError" || error?.name === "AbortError") {
    return "CLIENT_TIMEOUT";
  }
  return "CLIENT_FETCH_FAILURE";
}

export async function runSample(configuration, deploymentId, index, fetchImplementation = fetch) {
  const startedAt = new Date().toISOString();
  const started = performance.now();
  let response;
  try {
    response = await fetchImplementation(configuration.a.publicEndpoint, {
      method: "POST",
      headers: Object.freeze({
        accept: "application/json",
        "cache-control": "no-store",
        "user-agent": `ed25519-yao-phase9b/${configuration.regionLabel}`,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    return Object.freeze({
      kind: "failure",
      failure: recoverableFailure(
        index,
        startedAt,
        performance.now() - started,
        null,
        null,
        errorCode(error),
      ),
    });
  }
  const observation = responseObservation(response);
  let body;
  try {
    body = await readBoundedJson(response);
  } catch (error) {
    const clientWallMs = performance.now() - started;
    return Object.freeze({
      kind: "failure",
      failure: recoverableFailure(
        index,
        startedAt,
        clientWallMs,
        response.status,
        observation,
        errorCode(error),
      ),
    });
  }
  const clientWallMs = performance.now() - started;
  if (!response.ok) {
    const code =
      typeof body.error_code === "string" && /^[A-Z0-9_]{1,64}$/.test(body.error_code)
        ? body.error_code
        : "HTTP_FAILURE";
    return Object.freeze({
      kind: "failure",
      failure: recoverableFailure(
        index,
        startedAt,
        clientWallMs,
        response.status,
        observation,
        code,
      ),
    });
  }
  try {
    validateSuccess(body, configuration.expectedTopologyLabel, deploymentId);
  } catch (error) {
    return Object.freeze({
      kind: "failure",
      failure: recoverableFailure(
        index,
        startedAt,
        clientWallMs,
        response.status,
        observation,
        errorCode(error),
      ),
    });
  }
  return Object.freeze({
    kind: "success",
    sample: Object.freeze({
      index,
      started_at: startedAt,
      client_wall_ms: clientWallMs,
      observation,
      result: sanitizeSuccess(body),
    }),
  });
}

function sampleMetric(sample, field) {
  return field === "client_wall_ms" ? sample.client_wall_ms : sample.result[field];
}

function metricValues(samples, field) {
  const values = [];
  for (const sample of samples) {
    values.push(sampleMetric(sample, field));
  }
  return values;
}

function uniqueNonNull(values) {
  const seen = new Set();
  for (const value of values) {
    if (value !== null) {
      seen.add(value);
    }
  }
  return [...seen].sort();
}

function sampleAColos(samples) {
  const values = [];
  for (const sample of samples) {
    values.push(sample.result.deriver_a_colo);
  }
  return uniqueNonNull(values);
}

function sampleBColos(samples) {
  const values = [];
  for (const sample of samples) {
    values.push(sample.result.deriver_b_colo);
  }
  return uniqueNonNull(values);
}

function sampleRayColos(samples) {
  const values = [];
  for (const sample of samples) {
    values.push(sample.observation.a_colo);
  }
  return uniqueNonNull(values);
}

function invariantRange(samples, field) {
  const values = metricValues(samples, field);
  if (values.length === 0) {
    return null;
  }
  return Object.freeze({ min: Math.min(...values), max: Math.max(...values) });
}

function buildMetricSummary(samples) {
  const output = {};
  for (const field of ["client_wall_ms", ...METRIC_FIELDS]) {
    output[field] = summarize(metricValues(samples, field));
  }
  return Object.freeze(output);
}

function firstObservation(results) {
  if (results.length === 0) {
    return null;
  }
  const first = results[0];
  return first.kind === "success" ? first.sample : first.failure;
}

function collectResults(results) {
  const successes = [];
  const failures = [];
  for (const result of results) {
    if (result.kind === "success") {
      successes.push(result.sample);
    } else {
      failures.push(result.failure);
    }
  }
  return { successes, failures };
}

function warmSuccesses(successes) {
  const warm = [];
  for (const sample of successes) {
    if (sample.index > 0) {
      warm.push(sample);
    }
  }
  return warm;
}

export function buildDeployedReport(configuration, receipt, results, startedAt, endedAt) {
  const { successes, failures } = collectResults(results);
  const warm = warmSuccesses(successes);
  return Object.freeze({
    benchmark: EXPECTED_BENCHMARK,
    benchmark_only: true,
    security_claim: "none",
    topology: configuration.expectedTopologyLabel,
    requested_topology: configuration.topology,
    region_label: configuration.regionLabel,
    deployment: deploymentReceiptEvidence(receipt),
    generated_at: endedAt,
    measurement_window: Object.freeze({ start: startedAt, end: endedAt }),
    requested_samples: configuration.sampleCount,
    completed_samples: results.length,
    success_count: successes.length,
    failure_count: failures.length,
    first_observation: firstObservation(results),
    warm: Object.freeze({
      success_count: warm.length,
      metrics: buildMetricSummary(warm),
    }),
    fixed_profile_ranges: Object.freeze({
      table_payload_bytes: invariantRange(successes, "table_payload_bytes"),
      body_bytes: invariantRange(successes, "body_bytes"),
      frame_count: invariantRange(successes, "frame_count"),
      max_queued_outgoing_envelopes: invariantRange(
        successes,
        "max_queued_outgoing_envelopes",
      ),
    }),
    colo: Object.freeze({
      a: Object.freeze({ source: "A Worker cf.colo", values: sampleAColos(successes) }),
      b: Object.freeze({
        source: "validated Deriver B transport placement evidence when available",
        values: sampleBColos(successes),
      }),
      client_edge_cross_check: Object.freeze({
        source: "client-facing cf-ray response header",
        values: sampleRayColos(successes),
      }),
    }),
    connection_reuse: Object.freeze({
      directly_observable_from_fetch: false,
      observation:
        "Sequential fetch may reuse pooled connections, but Fetch exposes no connection identifier or handshake timing. Treat warm/cold deltas and stable colos as observations, not proof of reuse.",
    }),
    failures,
    samples: successes,
  });
}

export async function collectDeployedBenchmark(configuration, receipt, fetchImplementation = fetch) {
  const startedAt = new Date().toISOString();
  const results = [];
  for (let index = 0; index < configuration.sampleCount; index += 1) {
    results.push(
      await runSample(configuration, receipt.deployment_id, index, fetchImplementation),
    );
  }
  return buildDeployedReport(
    configuration,
    receipt,
    results,
    startedAt,
    new Date().toISOString(),
  );
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

async function main() {
  const configuration = parseDeploymentEnvironment(process.env);
  const receipt = readDeploymentReceipt(
    deploymentReceiptPath(process.env),
    configuration,
    true,
  );
  const report = await collectDeployedBenchmark(configuration, receipt);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function handleFatal(error) {
  const message = error instanceof BoundaryError ? error.message : "deployed benchmark collector failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

if (isMainModule()) {
  main().catch(handleFatal);
}
