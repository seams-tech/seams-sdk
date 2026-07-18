import { pathToFileURL } from "node:url";

import {
  ACTIVATION_128KIB_WIRE_PROFILE,
  mismatchedActivationWireField,
} from "./activation_wire_profile.mjs";

const DEFAULT_SAMPLES = 51;
const DEFAULT_ENDPOINT = "http://127.0.0.1:8787/benchmark/activation";
const EXPECTED_TABLE_PAYLOAD_BYTES = 2_104_960;
const EXPECTED_TIMING_SEMANTICS =
  "worker-date-now;deployed-advances-after-io;milestones-relative-to-deriver-a-protocol-start";
const EXPECTED_TABLE_TIMING_BOUNDARY = "websocket-send-queue-acceptance";
const EXPECTED_BODY_BYTE_TIMING_BOUNDARY = "websocket-binary-message-send-and-receipt";
const EXPECTED_INCOMING_SECRET_BUFFER_DISPOSAL =
  "rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled";
const TIMING_FIELDS = Object.freeze([
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
]);
const ORDERED_MILESTONE_FIELDS = Object.freeze([
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
]);

function compareNumbers(left, right) {
  return left - right;
}

function percentile(values, percentileValue) {
  if (values.length === 0) {
    throw new Error("cannot compute a percentile without samples");
  }
  const sorted = [...values].sort(compareNumbers);
  const rank = Math.max(0, Math.ceil(percentileValue * sorted.length) - 1);
  return sorted[rank];
}

function summarize(values) {
  return {
    min: Math.min(...values),
    p50: percentile(values, 0.5),
    p95: percentile(values, 0.95),
    p99: percentile(values, 0.99),
    max: Math.max(...values),
  };
}

function parseSampleCount(raw) {
  if (raw === undefined) {
    return DEFAULT_SAMPLES;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 2 || parsed > 1_000) {
    throw new Error("sample count must be an integer from 2 through 1000");
  }
  return parsed;
}

function isFiniteNonnegative(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isNullableColo(value) {
  return value === null || (typeof value === "string" && /^[A-Z]{3}$/.test(value));
}

function validateTiming(result) {
  for (const field of TIMING_FIELDS) {
    if (!isFiniteNonnegative(result[field])) {
      throw new Error(`invalid timing field: ${field}`);
    }
  }
  for (let index = 1; index < ORDERED_MILESTONE_FIELDS.length; index += 1) {
    const previous = result[ORDERED_MILESTONE_FIELDS[index - 1]];
    const current = result[ORDERED_MILESTONE_FIELDS[index]];
    if (previous > current) {
      throw new Error("transport timing milestones are unordered");
    }
  }
  if (
    result.table_stream_duration_ms !==
      result.last_table_frame_accepted_ms - result.first_table_frame_accepted_ms ||
    result.total_protocol_duration_ms !== result.response_eof_complete_ms ||
    result.elapsed_ms < result.total_protocol_duration_ms
  ) {
    throw new Error("transport timing evidence is inconsistent");
  }
}

export function validateResult(result) {
  if (
    result.ok !== true ||
    result.benchmark_only !== true ||
    result.production_eligible !== false ||
    result.incoming_secret_buffer_disposal !== EXPECTED_INCOMING_SECRET_BUFFER_DISPOSAL ||
    result.benchmark !== "phase9b-cloudflare-activation-128kib" ||
    result.role !== "deriver-a" ||
    result.topology !== "same-account-service-binding-websocket" ||
    result.family !== "activation" ||
    result.profile !== "128KiB" ||
    result.timing_semantics !== EXPECTED_TIMING_SEMANTICS ||
    result.table_timing_boundary !== EXPECTED_TABLE_TIMING_BOUNDARY ||
    result.body_byte_timing_boundary !== EXPECTED_BODY_BYTE_TIMING_BOUNDARY ||
    result.table_payload_bytes !== EXPECTED_TABLE_PAYLOAD_BYTES ||
    result.max_queued_outgoing_envelopes !== 1 ||
    !isNullableColo(result.deriver_a_colo) ||
    !isNullableColo(result.deriver_b_colo)
  ) {
    throw new Error(`unexpected benchmark response: ${JSON.stringify(result)}`);
  }
  const mismatchedWireField = mismatchedActivationWireField(result);
  if (mismatchedWireField !== null) {
    throw new Error(`invalid activation wire accounting: ${mismatchedWireField}`);
  }
  if (
    result.adapter_secret_ingress_rust_copy_passes !== 1 ||
    result.adapter_secret_ingress_rust_copy_bytes !== result.total_incoming_body_bytes ||
    result.adapter_secret_ingress_js_overwrite_bytes !== result.total_incoming_body_bytes ||
    result.workers_rs_outgoing_stream_body_copy_passes !== 1 ||
    result.workers_rs_outgoing_stream_body_copy_bytes !== result.total_outgoing_envelope_bytes
  ) {
    throw new Error("invalid secret transport copy accounting");
  }
  validateTiming(result);
}

async function runSample(endpoint, index) {
  const started = performance.now();
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(120_000),
  });
  const clientWallMs = performance.now() - started;
  const result = await response.json();
  if (!response.ok) {
    throw new Error(`sample ${index} failed with ${response.status}: ${JSON.stringify(result)}`);
  }
  validateResult(result);
  return { index, client_wall_ms: clientWallMs, ...result };
}

function selectMetric(samples, field) {
  return samples.map((sample) => sample[field]);
}

function observedRange(samples, field) {
  const values = selectMetric(samples, field);
  return { min: Math.min(...values), max: Math.max(...values) };
}

function summarizeFields(samples, fields) {
  const summaries = {};
  for (const field of fields) {
    summaries[field] = summarize(selectMetric(samples, field));
  }
  return summaries;
}

export function buildReport(endpoint, samples) {
  const coldFirst = samples[0];
  const warm = samples.slice(1);
  return {
    benchmark: "phase9b-cloudflare-activation-128kib",
    benchmark_only: true,
    topology: "same-account-service-binding-websocket",
    generated_at: new Date().toISOString(),
    endpoint,
    sample_count: samples.length,
    cold_first: coldFirst,
    warm: {
      sample_count: warm.length,
      client_wall_ms: summarize(selectMetric(warm, "client_wall_ms")),
      worker_elapsed_ms: summarize(selectMetric(warm, "elapsed_ms")),
      transport_timing_ms: summarizeFields(warm, TIMING_FIELDS),
    },
    invariants: {
      ...ACTIVATION_128KIB_WIRE_PROFILE,
      max_queued_outgoing_envelopes: 1,
      workers_rs_version: samples[0].workers_rs_version,
      timing_semantics: EXPECTED_TIMING_SEMANTICS,
      table_timing_boundary: EXPECTED_TABLE_TIMING_BOUNDARY,
      body_byte_timing_boundary: EXPECTED_BODY_BYTE_TIMING_BOUNDARY,
      production_eligible: false,
      incoming_secret_buffer_disposal: EXPECTED_INCOMING_SECRET_BUFFER_DISPOSAL,
    },
    observed_ranges: {
      max_incoming_platform_fragment_bytes: observedRange(
        samples,
        "max_incoming_platform_fragment_bytes",
      ),
      peak_outgoing_envelope_bytes: observedRange(samples, "peak_outgoing_envelope_bytes"),
      adapter_secret_ingress_rust_copy_bytes: observedRange(
        samples,
        "adapter_secret_ingress_rust_copy_bytes",
      ),
      adapter_secret_ingress_js_overwrite_bytes: observedRange(
        samples,
        "adapter_secret_ingress_js_overwrite_bytes",
      ),
      workers_rs_outgoing_stream_body_copy_bytes: observedRange(
        samples,
        "workers_rs_outgoing_stream_body_copy_bytes",
      ),
    },
    samples,
  };
}

async function main() {
  const sampleCount = parseSampleCount(process.argv[2]);
  const endpoint = process.argv[3] ?? DEFAULT_ENDPOINT;
  const samples = [];
  for (let index = 0; index < sampleCount; index += 1) {
    samples.push(await runSample(endpoint, index));
  }
  process.stdout.write(`${JSON.stringify(buildReport(endpoint, samples), null, 2)}\n`);
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  main().catch(handleFatal);
}
