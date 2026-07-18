import { readFileSync, statSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { mismatchedActivationWireField } from "./activation_wire_profile.mjs";
import { loadLocalReadinessBundle } from "./local_readiness_bundle.mjs";
import { collectLocalReadinessInputs } from "./local_readiness_inputs.mjs";

const BENCHMARK_ID = "phase9b-cloudflare-activation-128kib";
const ANALYTICS_ID = "phase9b-cloudflare-workers-analytics";
const COST_ID = "phase9b-cloudflare-cost-model";
const OPERATIONAL_ACCEPTANCE_SCHEMA = "ed25519_yao_phase13a_operational_acceptance_v1";
const SAME_TOPOLOGY = "same-account-service-binding-websocket";
const CROSS_TOPOLOGY = "cross-account-websocket";
const INCOMING_SECRET_BUFFER_DISPOSAL =
  "rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled";
const MAX_REPORT_BYTES = 16 * 1024 * 1024;
const MINIMUM_WARM_SAMPLES = 50;
const COST_MODEL_CEREMONIES = 1_000_000;
const TABLE_MAX_BYTES_FLOOR = Math.floor(2.1 * 1024 * 1024);
const MEMORY_MAX_BYTES = 96 * 1024 * 1024;
const MEMORY_GATE_COMPARISON = "memoryUsageBytesP999 < threshold_bytes";
const MEMORY_EVIDENCE_CLASSIFICATION =
  "cloudflare-reservoir-sampled-shared-isolate-operational-proxy";
const PLATFORM_COPY_ACCOUNTING = "unavailable";
let currentLocalReadinessBundleSha256 = null;
const SCRIPT_NAMES = Object.freeze({
  [SAME_TOPOLOGY]: Object.freeze({
    "deriver-a": "ed25519-yao-ab-benchmark-a",
    "deriver-b": "ed25519-yao-ab-benchmark-b",
  }),
  [CROSS_TOPOLOGY]: Object.freeze({
    "deriver-a": "ed25519-yao-ab-benchmark-a-cross-account",
    "deriver-b": "ed25519-yao-ab-benchmark-b-cross-account",
  }),
});

export const PHASE13A_THRESHOLDS = Object.freeze({
  table_payload_mib_max: 2.1,
  table_payload_bytes_max_floor: TABLE_MAX_BYTES_FLOOR,
  cross_account_table_stream_p95_ms_exclusive: 75,
  ceremony_p95_ms_max: 250,
  ceremony_p99_ms_max: 500,
  combined_cpu_p95_ms_max: 150,
  role_memory_p999_bytes_exclusive: MEMORY_MAX_BYTES,
  warm_sample_count_min: MINIMUM_WARM_SAMPLES,
});

export class EvidenceError extends Error {
  constructor(code, field) {
    super(`${code}: ${field}`);
    this.name = "EvidenceError";
    this.code = code;
    this.field = field;
  }
}

function evidenceError(code, field) {
  throw new EvidenceError(code, field);
}

function requiredObject(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return value;
}

function requiredArray(value, field) {
  if (!Array.isArray(value)) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return value;
}

function requiredString(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return value;
}

function requiredBoolean(value, field) {
  if (typeof value !== "boolean") {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return value;
}

function requiredNumber(value, field) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return value;
}

function requiredInteger(value, field) {
  const parsed = requiredNumber(value, field);
  if (!Number.isSafeInteger(parsed)) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return parsed;
}

function requiredPositiveNumber(value, field) {
  const parsed = requiredNumber(value, field);
  if (parsed <= 0) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return parsed;
}

function requiredInstant(value, field) {
  const instant = requiredString(value, field);
  const timestamp = Date.parse(instant);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== instant) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return Object.freeze({ raw: instant, timestamp });
}

function requiredDate(value, field) {
  const date = requiredString(value, field);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  const canonical = new Date(`${date}T00:00:00.000Z`).toISOString().slice(0, 10);
  if (canonical !== date) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return date;
}

function requiredHttpsUrl(value, field) {
  const raw = requiredString(value, field);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "") {
    evidenceError("PHASE13A_INVALID_EVIDENCE_TYPE", field);
  }
  return parsed.href;
}

function requireExact(value, expected, field) {
  if (value !== expected) {
    evidenceError("PHASE13A_REPORT_IDENTITY_MISMATCH", field);
  }
}

function validatedCurrentLocalReadinessBundleSha256() {
  if (currentLocalReadinessBundleSha256 !== null) {
    return currentLocalReadinessBundleSha256;
  }
  let bundle;
  try {
    bundle = loadLocalReadinessBundle();
  } catch {
    evidenceError("PHASE13A_LOCAL_READINESS_BUNDLE", "local_readiness_bundle");
  }
  const expected = requiredObject(bundle.evidence.validated_inputs, "validated_inputs");
  const observed = collectLocalReadinessInputs();
  requireExact(
    expected.schema,
    "ed25519_yao_local_readiness_inputs_v1",
    "validated_inputs.schema",
  );
  requireExact(expected.file_count, observed.file_count, "validated_inputs.file_count");
  requireExact(expected.total_bytes, observed.total_bytes, "validated_inputs.total_bytes");
  requireExact(expected.sha256, observed.sha256, "validated_inputs.sha256");
  currentLocalReadinessBundleSha256 = bundle.sha256;
  return currentLocalReadinessBundleSha256;
}

function requiredPath(root, path, field) {
  let current = root;
  for (const segment of path) {
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, segment)) {
      evidenceError("PHASE13A_REQUIRED_EVIDENCE_MISSING", field);
    }
    current = current[segment];
  }
  return current;
}

function quantile(report, metric, percentile, fieldPrefix) {
  return requiredNumber(
    requiredPath(report, ["warm", "metrics", metric, percentile], `${fieldPrefix}.${percentile}`),
    `${fieldPrefix}.${percentile}`,
  );
}

function compareNumbers(left, right) {
  return left - right;
}

function percentile(values, percentileValue) {
  const sorted = [...values].sort(compareNumbers);
  const rank = Math.max(0, Math.ceil(percentileValue * sorted.length) - 1);
  return sorted[rank];
}

function requireSummaryMatchesValues(summary, values, fieldPrefix) {
  const root = requiredObject(summary, fieldPrefix);
  for (const [name, probability] of [
    ["p50", 0.5],
    ["p95", 0.95],
    ["p99", 0.99],
  ]) {
    requireExact(
      requiredNumber(root[name], `${fieldPrefix}.${name}`),
      percentile(values, probability),
      `${fieldPrefix}.${name}`,
    );
  }
  return Object.freeze({ p50: root.p50, p95: root.p95, p99: root.p99 });
}

function sampleMetric(sample, field) {
  return field === "client_wall_ms" ? sample.client_wall_ms : sample.result[field];
}

function warmMetricValues(samples, field) {
  const values = [];
  for (const sample of samples) {
    if (sample.index > 0) {
      values.push(sampleMetric(sample, field));
    }
  }
  return values;
}

function requireSummaryMatchesSamples(report, samples, metric, percentileName, fieldPrefix) {
  const values = warmMetricValues(samples, metric);
  if (values.length === 0) {
    evidenceError("PHASE13A_RAW_SAMPLES_MISSING", fieldPrefix);
  }
  const probability = percentileName === "p95" ? 0.95 : 0.99;
  const observed = percentile(values, probability);
  const summarized = quantile(report, metric, percentileName, fieldPrefix);
  requireExact(summarized, observed, `${fieldPrefix}.${percentileName}`);
  return observed;
}

function tableRange(report, fieldPrefix) {
  const range = requiredObject(
    requiredPath(
      report,
      ["fixed_profile_ranges", "table_payload_bytes"],
      `${fieldPrefix}.table_payload_bytes`,
    ),
    `${fieldPrefix}.table_payload_bytes`,
  );
  const minimum = requiredInteger(range.min, `${fieldPrefix}.table_payload_bytes.min`);
  const maximum = requiredInteger(range.max, `${fieldPrefix}.table_payload_bytes.max`);
  if (minimum > maximum) {
    evidenceError("PHASE13A_INVALID_EVIDENCE_RANGE", `${fieldPrefix}.table_payload_bytes`);
  }
  return Object.freeze({
    min: minimum,
    max: maximum,
    exact_known_bytes: minimum === maximum ? minimum : null,
  });
}

function measurementWindow(report, fieldPrefix) {
  const start = requiredString(
    requiredPath(report, ["measurement_window", "start"], `${fieldPrefix}.measurement_window.start`),
    `${fieldPrefix}.measurement_window.start`,
  );
  const end = requiredString(
    requiredPath(report, ["measurement_window", "end"], `${fieldPrefix}.measurement_window.end`),
    `${fieldPrefix}.measurement_window.end`,
  );
  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || startMs >= endMs) {
    evidenceError("PHASE13A_INVALID_MEASUREMENT_WINDOW", `${fieldPrefix}.measurement_window`);
  }
  return Object.freeze({ start, end, start_ms: startMs, end_ms: endMs });
}

function parseDeploymentRole(raw, expectedScriptName, fieldPrefix) {
  const role = requiredObject(raw, fieldPrefix);
  requireExact(role.script_name, expectedScriptName, `${fieldPrefix}.script_name`);
  const wranglerVersion = requiredString(role.wrangler_version, `${fieldPrefix}.wrangler_version`);
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(wranglerVersion)) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", `${fieldPrefix}.wrangler_version`);
  }
  const workerTag = requiredString(role.worker_tag, `${fieldPrefix}.worker_tag`);
  const versionId = requiredString(role.version_id, `${fieldPrefix}.version_id`);
  const artifactSha256 = requiredString(
    role.artifact_sha256,
    `${fieldPrefix}.artifact_sha256`,
  );
  if (!/^[A-Za-z0-9-]{8,128}$/.test(workerTag) || !/^[A-Za-z0-9-]{8,128}$/.test(versionId)) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", fieldPrefix);
  }
  if (!/^[0-9a-f]{64}$/.test(artifactSha256)) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", `${fieldPrefix}.artifact_sha256`);
  }
  const deployedAt = requiredString(role.deployed_at, `${fieldPrefix}.deployed_at`);
  if (!Number.isFinite(Date.parse(deployedAt))) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", `${fieldPrefix}.deployed_at`);
  }
  return Object.freeze({
    script_name: expectedScriptName,
    wrangler_version: wranglerVersion,
    worker_tag: workerTag,
    version_id: versionId,
    artifact_sha256: artifactSha256,
    deployed_at: deployedAt,
  });
}

function parseConstantTimeRole(raw, artifactSha256, fieldPrefix) {
  const role = requiredObject(raw, fieldPrefix);
  requireExact(role.artifact_sha256, artifactSha256, `${fieldPrefix}.artifact_sha256`);
  const wasmSha256 = requiredString(role.wasm_sha256, `${fieldPrefix}.wasm_sha256`);
  if (!/^[0-9a-f]{64}$/.test(wasmSha256)) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", `${fieldPrefix}.wasm_sha256`);
  }
  return Object.freeze({ artifact_sha256: artifactSha256, wasm_sha256: wasmSha256 });
}

function parseConstantTimeEvidence(raw, a, b, fieldPrefix) {
  const evidence = requiredObject(raw, fieldPrefix);
  requireExact(
    evidence.schema,
    "ed25519_yao_worker_constant_time_codegen_v1",
    `${fieldPrefix}.schema`,
  );
  requireExact(
    evidence.inspector,
    "llvm-objdump-secret-bit-branch-gate-v1",
    `${fieldPrefix}.inspector`,
  );
  requireExact(evidence.result, "pass", `${fieldPrefix}.result`);
  return Object.freeze({
    schema: evidence.schema,
    inspector: evidence.inspector,
    result: evidence.result,
    roles: Object.freeze({
      a: parseConstantTimeRole(
        evidence.roles?.a,
        a.artifact_sha256,
        `${fieldPrefix}.roles.a`,
      ),
      b: parseConstantTimeRole(
        evidence.roles?.b,
        b.artifact_sha256,
        `${fieldPrefix}.roles.b`,
      ),
    }),
  });
}

function requiredHostname(value, field) {
  const hostname = requiredString(value, field);
  const labels = hostname.split(".");
  if (
    hostname !== hostname.toLowerCase() ||
    hostname.length > 253 ||
    hostname.includes("..") ||
    labels.length < 2 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", field);
  }
  return hostname;
}

function requiredAccountCommitment(value, field) {
  const commitment = requiredString(value, field);
  if (!/^[0-9a-f]{64}$/.test(commitment) || /^0+$/.test(commitment)) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", field);
  }
  return commitment;
}

function parseTopologyBinding(raw, topology, fieldPrefix) {
  const binding = requiredObject(raw, fieldPrefix);
  requireExact(
    binding.schema,
    "ed25519_yao_phase9b_topology_binding_v1",
    `${fieldPrefix}.schema`,
  );
  requireExact(binding.kind, topology, `${fieldPrefix}.kind`);
  const aAccount = requiredAccountCommitment(
    binding.a_account_sha256,
    `${fieldPrefix}.a_account_sha256`,
  );
  const bAccount = requiredAccountCommitment(
    binding.b_account_sha256,
    `${fieldPrefix}.b_account_sha256`,
  );
  const aHostname = requiredHostname(
    binding.a_public_hostname,
    `${fieldPrefix}.a_public_hostname`,
  );
  if (topology === SAME_TOPOLOGY) {
    requireExact(aAccount, bAccount, `${fieldPrefix}.b_account_sha256`);
    requireExact(
      binding.b_service_name,
      SCRIPT_NAMES[topology]["deriver-b"],
      `${fieldPrefix}.b_service_name`,
    );
    return Object.freeze({
      schema: binding.schema,
      kind: binding.kind,
      a_account_sha256: aAccount,
      b_account_sha256: bAccount,
      a_public_hostname: aHostname,
      b_service_name: binding.b_service_name,
    });
  }
  if (aAccount === bAccount) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", `${fieldPrefix}.b_account_sha256`);
  }
  const bHostname = requiredHostname(
    binding.b_public_hostname,
    `${fieldPrefix}.b_public_hostname`,
  );
  if (aHostname === bHostname) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", `${fieldPrefix}.b_public_hostname`);
  }
  return Object.freeze({
    schema: binding.schema,
    kind: binding.kind,
    a_account_sha256: aAccount,
    b_account_sha256: bAccount,
    a_public_hostname: aHostname,
    b_public_hostname: bHostname,
  });
}

function parseDeploymentEvidence(raw, topology, fieldPrefix) {
  const deployment = requiredObject(raw, fieldPrefix);
  requireExact(
    deployment.schema,
    "ed25519_yao_phase9b_deployment_receipt_v4",
    `${fieldPrefix}.schema`,
  );
  requireExact(deployment.topology, topology, `${fieldPrefix}.topology`);
  const deploymentId = requiredString(deployment.deployment_id, `${fieldPrefix}.deployment_id`);
  if (!/^[0-9a-f]{32}$/.test(deploymentId) || /^0+$/.test(deploymentId)) {
    evidenceError("PHASE13A_DEPLOYMENT_IDENTITY", `${fieldPrefix}.deployment_id`);
  }
  const localReadinessBundleSha256 = requiredString(
    deployment.local_readiness_bundle_sha256,
    `${fieldPrefix}.local_readiness_bundle_sha256`,
  );
  if (
    !/^[0-9a-f]{64}$/.test(localReadinessBundleSha256) ||
    localReadinessBundleSha256 !== validatedCurrentLocalReadinessBundleSha256()
  ) {
    evidenceError(
      "PHASE13A_DEPLOYMENT_IDENTITY",
      `${fieldPrefix}.local_readiness_bundle_sha256`,
    );
  }
  const a = parseDeploymentRole(
    deployment.a,
    SCRIPT_NAMES[topology]["deriver-a"],
    `${fieldPrefix}.a`,
  );
  const b = parseDeploymentRole(
    deployment.b,
    SCRIPT_NAMES[topology]["deriver-b"],
    `${fieldPrefix}.b`,
  );
  return Object.freeze({
    deployment_id: deploymentId,
    local_readiness_bundle_sha256: localReadinessBundleSha256,
    topology_binding: parseTopologyBinding(
      deployment.topology_binding,
      topology,
      `${fieldPrefix}.topology_binding`,
    ),
    a,
    b,
    constant_time_codegen: parseConstantTimeEvidence(
      deployment.constant_time_codegen,
      a,
      b,
      `${fieldPrefix}.constant_time_codegen`,
    ),
  });
}

function validateSampleTiming(result, fieldPrefix) {
  const fields = [
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
  ];
  let previous = null;
  for (const field of fields) {
    const value = requiredNumber(result[field], `${fieldPrefix}.result.${field}`);
    if (previous !== null && previous > value) {
      evidenceError("PHASE13A_RAW_SAMPLE_TIMING", `${fieldPrefix}.result.${field}`);
    }
    previous = value;
  }
  if (result.b_to_a_first_body_byte_received_ms >= result.request_direction_closed_ms) {
    evidenceError("PHASE13A_EARLY_RESPONSE_NOT_PROVEN", fieldPrefix);
  }
  requireExact(
    requiredNumber(result.total_protocol_duration_ms, `${fieldPrefix}.result.total_protocol_duration_ms`),
    result.response_eof_complete_ms,
    `${fieldPrefix}.result.total_protocol_duration_ms`,
  );
  requireExact(
    requiredNumber(
      result.table_stream_duration_ms,
      `${fieldPrefix}.result.table_stream_duration_ms`,
    ),
    result.last_table_frame_accepted_ms - result.first_table_frame_accepted_ms,
    `${fieldPrefix}.result.table_stream_duration_ms`,
  );
}

function validateFixedActivationWireProfile(result, fieldPrefix) {
  const mismatch = mismatchedActivationWireField(result);
  if (mismatch !== null) {
    evidenceError("PHASE13A_RAW_SAMPLE_WIRE_PROFILE", `${fieldPrefix}.result.${mismatch}`);
  }
}

function validateSecretTransportAccounting(result, fieldPrefix) {
  requireExact(
    result.incoming_secret_buffer_disposal,
    INCOMING_SECRET_BUFFER_DISPOSAL,
    `${fieldPrefix}.result.incoming_secret_buffer_disposal`,
  );
  requireExact(
    requiredInteger(
      result.adapter_secret_ingress_rust_copy_passes,
      `${fieldPrefix}.result.adapter_secret_ingress_rust_copy_passes`,
    ),
    1,
    `${fieldPrefix}.result.adapter_secret_ingress_rust_copy_passes`,
  );
  const incomingBytes = requiredInteger(
    result.total_incoming_body_bytes,
    `${fieldPrefix}.result.total_incoming_body_bytes`,
  );
  requireExact(
    requiredInteger(
      result.adapter_secret_ingress_rust_copy_bytes,
      `${fieldPrefix}.result.adapter_secret_ingress_rust_copy_bytes`,
    ),
    incomingBytes,
    `${fieldPrefix}.result.adapter_secret_ingress_rust_copy_bytes`,
  );
  requireExact(
    requiredInteger(
      result.adapter_secret_ingress_js_overwrite_bytes,
      `${fieldPrefix}.result.adapter_secret_ingress_js_overwrite_bytes`,
    ),
    incomingBytes,
    `${fieldPrefix}.result.adapter_secret_ingress_js_overwrite_bytes`,
  );
  requireExact(
    requiredInteger(
      result.workers_rs_outgoing_stream_body_copy_passes,
      `${fieldPrefix}.result.workers_rs_outgoing_stream_body_copy_passes`,
    ),
    1,
    `${fieldPrefix}.result.workers_rs_outgoing_stream_body_copy_passes`,
  );
  requireExact(
    requiredInteger(
      result.workers_rs_outgoing_stream_body_copy_bytes,
      `${fieldPrefix}.result.workers_rs_outgoing_stream_body_copy_bytes`,
    ),
    requiredInteger(
      result.total_outgoing_envelope_bytes,
      `${fieldPrefix}.result.total_outgoing_envelope_bytes`,
    ),
    `${fieldPrefix}.result.workers_rs_outgoing_stream_body_copy_bytes`,
  );
}

function parseRawSample(raw, topology, deploymentId, fieldPrefix, window) {
  const sample = requiredObject(raw, fieldPrefix);
  const index = requiredInteger(sample.index, `${fieldPrefix}.index`);
  const startedAt = requiredString(sample.started_at, `${fieldPrefix}.started_at`);
  const startedAtMs = Date.parse(startedAt);
  if (
    !Number.isFinite(startedAtMs) ||
    startedAtMs < window.start_ms ||
    startedAtMs > window.end_ms
  ) {
    evidenceError("PHASE13A_RAW_SAMPLE_WINDOW", `${fieldPrefix}.started_at`);
  }
  const clientWall = requiredNumber(sample.client_wall_ms, `${fieldPrefix}.client_wall_ms`);
  const result = requiredObject(sample.result, `${fieldPrefix}.result`);
  requireExact(result.benchmark, BENCHMARK_ID, `${fieldPrefix}.result.benchmark`);
  requireExact(result.benchmark_only, true, `${fieldPrefix}.result.benchmark_only`);
  requireExact(result.production_eligible, false, `${fieldPrefix}.result.production_eligible`);
  requireExact(
    result.body_byte_timing_boundary,
    "websocket-binary-message-send-and-receipt",
    `${fieldPrefix}.result.body_byte_timing_boundary`,
  );
  requireExact(result.role, "deriver-a", `${fieldPrefix}.result.role`);
  validateFixedActivationWireProfile(result, fieldPrefix);
  validateSecretTransportAccounting(result, fieldPrefix);
  requireExact(result.topology, topology, `${fieldPrefix}.result.topology`);
  requireExact(result.deployment_id, deploymentId, `${fieldPrefix}.result.deployment_id`);
  validateSampleTiming(result, fieldPrefix);
  if (clientWall < result.total_protocol_duration_ms) {
    evidenceError("PHASE13A_CLIENT_WALL_INCOMPLETE", `${fieldPrefix}.client_wall_ms`);
  }
  return Object.freeze({ index, client_wall_ms: clientWall, result });
}

function validateRawSamples(report, topology, deploymentId, fieldPrefix, window, counts) {
  const rawSamples = requiredArray(report.samples, `${fieldPrefix}.samples`);
  const failures = requiredArray(report.failures, `${fieldPrefix}.failures`);
  if (rawSamples.length !== counts.successes || failures.length !== counts.failures) {
    evidenceError("PHASE13A_RAW_SAMPLE_COUNT", fieldPrefix);
  }
  const indexes = new Set();
  const samples = [];
  for (let position = 0; position < rawSamples.length; position += 1) {
    const sample = parseRawSample(
      rawSamples[position],
      topology,
      deploymentId,
      `${fieldPrefix}.samples.${position}`,
      window,
    );
    if (indexes.has(sample.index)) {
      evidenceError("PHASE13A_RAW_SAMPLE_INDEX", `${fieldPrefix}.samples.${position}.index`);
    }
    indexes.add(sample.index);
    samples.push(sample);
  }
  for (let position = 0; position < failures.length; position += 1) {
    const failure = requiredObject(failures[position], `${fieldPrefix}.failures.${position}`);
    const index = requiredInteger(failure.index, `${fieldPrefix}.failures.${position}.index`);
    if (indexes.has(index)) {
      evidenceError("PHASE13A_RAW_SAMPLE_INDEX", `${fieldPrefix}.failures.${position}.index`);
    }
    indexes.add(index);
  }
  if (indexes.size !== counts.completed) {
    evidenceError("PHASE13A_RAW_SAMPLE_COUNT", fieldPrefix);
  }
  for (let index = 0; index < counts.completed; index += 1) {
    if (!indexes.has(index)) {
      evidenceError("PHASE13A_RAW_SAMPLE_INDEX", `${fieldPrefix}.${index}`);
    }
  }
  return samples;
}

function parseBenchmarkReport(report, topology, fieldPrefix, requireTableStream) {
  const root = requiredObject(report, fieldPrefix);
  requireExact(root.benchmark, BENCHMARK_ID, `${fieldPrefix}.benchmark`);
  requireExact(root.benchmark_only, true, `${fieldPrefix}.benchmark_only`);
  requireExact(root.topology, topology, `${fieldPrefix}.topology`);
  const requested = requiredInteger(root.requested_samples, `${fieldPrefix}.requested_samples`);
  const completed = requiredInteger(root.completed_samples, `${fieldPrefix}.completed_samples`);
  const successes = requiredInteger(root.success_count, `${fieldPrefix}.success_count`);
  const failures = requiredInteger(root.failure_count, `${fieldPrefix}.failure_count`);
  const warmSuccesses = requiredInteger(
    requiredPath(root, ["warm", "success_count"], `${fieldPrefix}.warm.success_count`),
    `${fieldPrefix}.warm.success_count`,
  );
  requireExact(root.security_claim, "none", `${fieldPrefix}.security_claim`);
  const deployment = parseDeploymentEvidence(
    root.deployment,
    topology,
    `${fieldPrefix}.deployment`,
  );
  const window = measurementWindow(root, fieldPrefix);
  const latestDeployment = Math.max(
    Date.parse(deployment.a.deployed_at),
    Date.parse(deployment.b.deployed_at),
  );
  if (window.start_ms < latestDeployment) {
    evidenceError("PHASE13A_MEASUREMENT_PREDEPLOYMENT", `${fieldPrefix}.measurement_window.start`);
  }
  const samples = validateRawSamples(root, topology, deployment.deployment_id, fieldPrefix, window, {
    completed,
    successes,
    failures,
  });
  const rawWarmCount = warmMetricValues(samples, "client_wall_ms").length;
  requireExact(warmSuccesses, rawWarmCount, `${fieldPrefix}.warm.success_count`);
  if (rawWarmCount < MINIMUM_WARM_SAMPLES) {
    evidenceError("PHASE13A_WARM_SAMPLE_COUNT_INSUFFICIENT", `${fieldPrefix}.warm.success_count`);
  }
  const clientP95 = requireSummaryMatchesSamples(
    root,
    samples,
    "client_wall_ms",
    "p95",
    `${fieldPrefix}.warm.client_wall_ms`,
  );
  const clientP99 = requireSummaryMatchesSamples(
    root,
    samples,
    "client_wall_ms",
    "p99",
    `${fieldPrefix}.warm.client_wall_ms`,
  );
  const tableStreamP95 = requireTableStream
    ? requireSummaryMatchesSamples(
        root,
        samples,
        "table_stream_duration_ms",
        "p95",
        `${fieldPrefix}.warm.table_stream_duration_ms`,
      )
    : null;
  const range = tableRange(root, fieldPrefix);
  const tableValues = [];
  const transportValues = [];
  for (const sample of samples) {
    tableValues.push(sample.result.table_payload_bytes);
    transportValues.push(sample.result.total_ab_transport_bytes);
  }
  requireExact(range.min, Math.min(...tableValues), `${fieldPrefix}.table_payload_bytes.min`);
  requireExact(range.max, Math.max(...tableValues), `${fieldPrefix}.table_payload_bytes.max`);
  const transportBytes = transportValues[0];
  for (let index = 1; index < transportValues.length; index += 1) {
    requireExact(
      transportValues[index],
      transportBytes,
      `${fieldPrefix}.samples.${index}.result.total_ab_transport_bytes`,
    );
  }
  return Object.freeze({
    requested_samples: requested,
    completed_samples: completed,
    success_count: successes,
    failure_count: failures,
    warm_success_count: warmSuccesses,
    client_wall_p95_ms: clientP95,
    client_wall_p99_ms: clientP99,
    table_stream_p95_ms: tableStreamP95,
    table_payload_bytes: range,
    total_ab_transport_bytes_per_ceremony: transportBytes,
    measurement_window: window,
    region_label: requiredString(root.region_label, `${fieldPrefix}.region_label`),
    early_response_sample_count: samples.length,
    deployment,
  });
}

function analyticsWindow(report, fieldPrefix) {
  const start = requiredString(
    requiredPath(report, ["window", "start"], `${fieldPrefix}.window.start`),
    `${fieldPrefix}.window.start`,
  );
  const end = requiredString(
    requiredPath(report, ["window", "end"], `${fieldPrefix}.window.end`),
    `${fieldPrefix}.window.end`,
  );
  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || startMs >= endMs) {
    evidenceError("PHASE13A_INVALID_MEASUREMENT_WINDOW", `${fieldPrefix}.window`);
  }
  return Object.freeze({ start, end, start_ms: startMs, end_ms: endMs });
}

function parseRawMemory(role, fieldPrefix) {
  const memory = requiredObject(role.memory, `${fieldPrefix}.memory`);
  const available = requiredBoolean(memory.available, `${fieldPrefix}.memory.available`);
  if (!available) {
    return Object.freeze({ available: false, memory_usage_bytes_p999: null });
  }
  const quantiles = requiredObject(
    memory.quantiles_bytes,
    `${fieldPrefix}.memory.quantiles_bytes`,
  );
  for (const name of [
    "memoryUsageBytesP50",
    "memoryUsageBytesP90",
    "memoryUsageBytesP99",
    "memoryUsageBytesP999",
  ]) {
    requiredInteger(quantiles[name], `${fieldPrefix}.memory.quantiles_bytes.${name}`);
  }
  return Object.freeze({
    available: true,
    memory_usage_bytes_p999: quantiles.memoryUsageBytesP999,
  });
}

function derivedMemoryGate(coreAvailable, p999, exceededCount) {
  let result;
  if (exceededCount !== null && exceededCount > 0) {
    result = "fail";
  } else if (!coreAvailable || p999 === null || exceededCount === null) {
    result = "unavailable";
  } else {
    result = p999 < MEMORY_MAX_BYTES ? "pass" : "fail";
  }
  return Object.freeze({
    result,
    threshold_bytes: MEMORY_MAX_BYTES,
    comparison: MEMORY_GATE_COMPARISON,
    memory_usage_bytes_p999: p999,
    exceeded_memory_status_count: exceededCount,
    exceeded_memory_status_observed: exceededCount === null ? null : exceededCount > 0,
  });
}

function parseNullableInteger(value, field) {
  return value === null ? null : requiredInteger(value, field);
}

function parseNullableBoolean(value, field) {
  return value === null ? null : requiredBoolean(value, field);
}

function requireMemoryGateMatches(role, expected, fieldPrefix) {
  const gate = requiredObject(role.sampled_memory_gate, `${fieldPrefix}.sampled_memory_gate`);
  requireExact(
    requiredString(gate.result, `${fieldPrefix}.sampled_memory_gate.result`),
    expected.result,
    `${fieldPrefix}.sampled_memory_gate.result`,
  );
  requireExact(
    requiredInteger(gate.threshold_bytes, `${fieldPrefix}.sampled_memory_gate.threshold_bytes`),
    expected.threshold_bytes,
    `${fieldPrefix}.sampled_memory_gate.threshold_bytes`,
  );
  requireExact(
    requiredString(gate.comparison, `${fieldPrefix}.sampled_memory_gate.comparison`),
    expected.comparison,
    `${fieldPrefix}.sampled_memory_gate.comparison`,
  );
  requireExact(
    parseNullableInteger(
      gate.memory_usage_bytes_p999,
      `${fieldPrefix}.sampled_memory_gate.memory_usage_bytes_p999`,
    ),
    expected.memory_usage_bytes_p999,
    `${fieldPrefix}.sampled_memory_gate.memory_usage_bytes_p999`,
  );
  requireExact(
    parseNullableInteger(
      gate.exceeded_memory_status_count,
      `${fieldPrefix}.sampled_memory_gate.exceeded_memory_status_count`,
    ),
    expected.exceeded_memory_status_count,
    `${fieldPrefix}.sampled_memory_gate.exceeded_memory_status_count`,
  );
  requireExact(
    parseNullableBoolean(
      gate.exceeded_memory_status_observed,
      `${fieldPrefix}.sampled_memory_gate.exceeded_memory_status_observed`,
    ),
    expected.exceeded_memory_status_observed,
    `${fieldPrefix}.sampled_memory_gate.exceeded_memory_status_observed`,
  );
  return expected;
}

function parseAnalyticsRole(role, expectedRole, expectedScriptName, fieldPrefix) {
  const root = requiredObject(role, fieldPrefix);
  requireExact(root.role, expectedRole, `${fieldPrefix}.role`);
  requireExact(root.script_name, expectedScriptName, `${fieldPrefix}.script_name`);
  const core = requiredObject(root.core, `${fieldPrefix}.core`);
  const available = requiredBoolean(core.available, `${fieldPrefix}.core.available`);
  const cpuP95 = available
    ? requiredNumber(
        requiredPath(
          core,
          ["quantiles", "milliseconds", "cpuTimeP95"],
          `${fieldPrefix}.core.quantiles.milliseconds.cpuTimeP95`,
        ),
        `${fieldPrefix}.core.quantiles.milliseconds.cpuTimeP95`,
      )
    : null;
  const cpuP99 = available
    ? requiredNumber(
        requiredPath(
          core,
          ["quantiles", "milliseconds", "cpuTimeP99"],
          `${fieldPrefix}.core.quantiles.milliseconds.cpuTimeP99`,
        ),
        `${fieldPrefix}.core.quantiles.milliseconds.cpuTimeP99`,
      )
    : null;
  const sumErrors = available
    ? requiredInteger(
        requiredPath(core, ["sum", "errors"], `${fieldPrefix}.core.sum.errors`),
        `${fieldPrefix}.core.sum.errors`,
      )
    : null;
  const sumRequests = available
    ? requiredInteger(
        requiredPath(core, ["sum", "requests"], `${fieldPrefix}.core.sum.requests`),
        `${fieldPrefix}.core.sum.requests`,
      )
    : null;
  const sumCpuTimeUs = available
    ? requiredNumber(
        requiredPath(core, ["sum", "cpuTimeUs"], `${fieldPrefix}.core.sum.cpuTimeUs`),
        `${fieldPrefix}.core.sum.cpuTimeUs`,
      )
    : null;
  const byColo = available
    ? requiredArray(core.by_colo, `${fieldPrefix}.core.by_colo`)
    : [];
  let byColoRequests = 0;
  let exceededMemoryCount = available ? 0 : null;
  for (let index = 0; index < byColo.length; index += 1) {
    const row = requiredObject(byColo[index], `${fieldPrefix}.core.by_colo.${index}`);
    requireExact(
      requiredPath(
        row,
        ["dimensions", "scriptName"],
        `${fieldPrefix}.core.by_colo.${index}.dimensions.scriptName`,
      ),
      expectedScriptName,
      `${fieldPrefix}.core.by_colo.${index}.dimensions.scriptName`,
    );
    const requests = requiredInteger(
      requiredPath(row, ["sum", "requests"], `${fieldPrefix}.core.by_colo.${index}.sum.requests`),
      `${fieldPrefix}.core.by_colo.${index}.sum.requests`,
    );
    const status = requiredString(
      requiredPath(
        row,
        ["dimensions", "status"],
        `${fieldPrefix}.core.by_colo.${index}.dimensions.status`,
      ),
      `${fieldPrefix}.core.by_colo.${index}.dimensions.status`,
    );
    byColoRequests += requests;
    if (status === "exceededMemory") {
      exceededMemoryCount += requests;
    }
  }
  if (available && (byColo.length === 0 || byColoRequests !== sumRequests)) {
    evidenceError("PHASE13A_ANALYTICS_REQUEST_IDENTITY", fieldPrefix);
  }
  const memory = parseRawMemory(root, fieldPrefix);
  const derivedGate = derivedMemoryGate(
    available,
    memory.memory_usage_bytes_p999,
    exceededMemoryCount,
  );
  return Object.freeze({
    core_available: available,
    cpu_p95_ms: cpuP95,
    cpu_p99_ms: cpuP99,
    errors: sumErrors,
    requests: sumRequests,
    cpu_time_us: sumCpuTimeUs,
    cpu_mean_ms:
      sumCpuTimeUs === null || sumRequests === null || sumRequests === 0
        ? null
        : sumCpuTimeUs / 1_000 / sumRequests,
    by_colo_rows: byColo.length,
    memory_gate: requireMemoryGateMatches(root, derivedGate, fieldPrefix),
  });
}

function parseAnalyticsReport(report, topology, fieldPrefix) {
  const root = requiredObject(report, fieldPrefix);
  requireExact(root.benchmark, ANALYTICS_ID, `${fieldPrefix}.benchmark`);
  requireExact(root.benchmark_only, true, `${fieldPrefix}.benchmark_only`);
  requireExact(root.topology, topology, `${fieldPrefix}.topology`);
  requireExact(root.adaptive_sampling, true, `${fieldPrefix}.adaptive_sampling`);
  requireExact(
    root.memory_evidence_classification,
    MEMORY_EVIDENCE_CLASSIFICATION,
    `${fieldPrefix}.memory_evidence_classification`,
  );
  requireExact(root.exact_peak_proven, false, `${fieldPrefix}.exact_peak_proven`);
  requireExact(
    root.platform_copy_accounting,
    PLATFORM_COPY_ACCOUNTING,
    `${fieldPrefix}.platform_copy_accounting`,
  );
  const deployment = parseDeploymentEvidence(
    root.deployment,
    topology,
    `${fieldPrefix}.deployment`,
  );
  const window = analyticsWindow(root, fieldPrefix);
  const latestDeployment = Math.max(
    Date.parse(deployment.a.deployed_at),
    Date.parse(deployment.b.deployed_at),
  );
  if (window.start_ms < latestDeployment) {
    evidenceError("PHASE13A_MEASUREMENT_PREDEPLOYMENT", `${fieldPrefix}.window.start`);
  }
  return Object.freeze({
    region_label: requiredString(root.region_label, `${fieldPrefix}.region_label`),
    window,
    a: parseAnalyticsRole(
      root.a,
      "deriver-a",
      SCRIPT_NAMES[topology]["deriver-a"],
      `${fieldPrefix}.a`,
    ),
    b: parseAnalyticsRole(
      root.b,
      "deriver-b",
      SCRIPT_NAMES[topology]["deriver-b"],
      `${fieldPrefix}.b`,
    ),
    deployment,
  });
}

function parseCostRates(raw, fieldPrefix) {
  const root = requiredObject(raw, fieldPrefix);
  return Object.freeze({
    requests_usd_per_million: requiredPositiveNumber(
      root.requestsUsdPerMillion,
      `${fieldPrefix}.requestsUsdPerMillion`,
    ),
    cpu_usd_per_million_ms: requiredPositiveNumber(
      root.cpuUsdPerMillionMs,
      `${fieldPrefix}.cpuUsdPerMillionMs`,
    ),
    included_requests: requiredNumber(root.includedRequests, `${fieldPrefix}.includedRequests`),
    included_cpu_ms: requiredNumber(root.includedCpuMs, `${fieldPrefix}.includedCpuMs`),
  });
}

function expectedAccountCost(requests, cpuMs, rates) {
  const billableRequests = Math.max(0, requests - rates.included_requests);
  const billableCpuMs = Math.max(0, cpuMs - rates.included_cpu_ms);
  const requestsUsd = (billableRequests / 1_000_000) * rates.requests_usd_per_million;
  const cpuUsd = (billableCpuMs / 1_000_000) * rates.cpu_usd_per_million_ms;
  return Object.freeze({
    measured_requests: requests,
    measured_cpu_ms: cpuMs,
    included_requests: rates.included_requests,
    included_cpu_ms: rates.included_cpu_ms,
    billable_requests: billableRequests,
    billable_cpu_ms: billableCpuMs,
    requests_usd: requestsUsd,
    cpu_usd: cpuUsd,
    subtotal_usd: requestsUsd + cpuUsd,
  });
}

function requireAccountCost(raw, expected, fieldPrefix) {
  const root = requiredObject(raw, fieldPrefix);
  for (const field of [
    "measured_requests",
    "measured_cpu_ms",
    "included_requests",
    "included_cpu_ms",
    "billable_requests",
    "billable_cpu_ms",
    "requests_usd",
    "cpu_usd",
    "subtotal_usd",
  ]) {
    requireExact(
      requiredNumber(root[field], `${fieldPrefix}.${field}`),
      expected[field],
      `${fieldPrefix}.${field}`,
    );
  }
  return expected;
}

function parseCostReport(report, fieldPrefix) {
  const root = requiredObject(report, fieldPrefix);
  requireExact(root.benchmark, COST_ID, `${fieldPrefix}.benchmark`);
  requireExact(root.benchmark_only, true, `${fieldPrefix}.benchmark_only`);
  requireExact(root.topology, "two-account", `${fieldPrefix}.topology`);
  requireExact(root.ceremonies, COST_MODEL_CEREMONIES, `${fieldPrefix}.ceremonies`);
  requiredInstant(root.generated_at, `${fieldPrefix}.generated_at`);
  const regionLabel = requiredString(root.region_label, `${fieldPrefix}.region_label`);
  const deployment = parseDeploymentEvidence(
    root.deployment,
    CROSS_TOPOLOGY,
    `${fieldPrefix}.deployment`,
  );
  const measured = requiredObject(root.measured, `${fieldPrefix}.measured`);
  const parsedMeasured = Object.freeze({
    requests_a: requiredNumber(
      measured.requestsAPerCeremony,
      `${fieldPrefix}.measured.requestsAPerCeremony`,
    ),
    requests_b: requiredNumber(
      measured.requestsBPerCeremony,
      `${fieldPrefix}.measured.requestsBPerCeremony`,
    ),
    cpu_a_ms: requiredNumber(measured.cpuAMsPerCeremony, `${fieldPrefix}.measured.cpuAMsPerCeremony`),
    cpu_b_ms: requiredNumber(measured.cpuBMsPerCeremony, `${fieldPrefix}.measured.cpuBMsPerCeremony`),
    network_bytes: requiredNumber(
      measured.networkBytesPerCeremony,
      `${fieldPrefix}.measured.networkBytesPerCeremony`,
    ),
    statistic: requiredString(measured.statistic, `${fieldPrefix}.measured.statistic`),
  });
  requireExact(
    root.measured_cpu_statistic,
    parsedMeasured.statistic,
    `${fieldPrefix}.measured_cpu_statistic`,
  );
  requireExact(
    parsedMeasured.statistic,
    "GraphQL mean CPU from sum.cpuTimeUs/requests",
    `${fieldPrefix}.measured.statistic`,
  );
  requireExact(parsedMeasured.requests_a, 1, `${fieldPrefix}.measured.requestsAPerCeremony`);
  requireExact(parsedMeasured.requests_b, 1, `${fieldPrefix}.measured.requestsBPerCeremony`);
  const requestModel = requiredObject(root.request_model, `${fieldPrefix}.request_model`);
  requireExact(requestModel.matches_expected, true, `${fieldPrefix}.request_model.matches_expected`);
  const pricing = requiredObject(root.pricing, `${fieldPrefix}.pricing`);
  requireExact(pricing.usage_model, "standard", `${fieldPrefix}.pricing.usage_model`);
  requireExact(pricing.user_supplied, true, `${fieldPrefix}.pricing.user_supplied`);
  const effectiveDate = requiredDate(pricing.effective_date, `${fieldPrefix}.pricing.effective_date`);
  requiredHttpsUrl(pricing.source, `${fieldPrefix}.pricing.source`);
  requireExact(pricing.network_usd_per_gb, 0, `${fieldPrefix}.pricing.network_usd_per_gb`);
  const accounts = requiredObject(pricing.accounts, `${fieldPrefix}.pricing.accounts`);
  const ratesA = parseCostRates(accounts.a, `${fieldPrefix}.pricing.accounts.a`);
  const ratesB = parseCostRates(accounts.b, `${fieldPrefix}.pricing.accounts.b`);
  const expectedA = expectedAccountCost(
    COST_MODEL_CEREMONIES * parsedMeasured.requests_a,
    COST_MODEL_CEREMONIES * parsedMeasured.cpu_a_ms,
    ratesA,
  );
  const expectedB = expectedAccountCost(
    COST_MODEL_CEREMONIES * parsedMeasured.requests_b,
    COST_MODEL_CEREMONIES * parsedMeasured.cpu_b_ms,
    ratesB,
  );
  const accountCosts = requiredObject(root.account_costs, `${fieldPrefix}.account_costs`);
  requireAccountCost(accountCosts.a_account_combined, expectedA, `${fieldPrefix}.account_costs.a_account_combined`);
  requireAccountCost(accountCosts.b_account, expectedB, `${fieldPrefix}.account_costs.b_account`);
  const network = requiredObject(root.network, `${fieldPrefix}.network`);
  const networkBytes = COST_MODEL_CEREMONIES * parsedMeasured.network_bytes;
  requireExact(network.measured_bytes, networkBytes, `${fieldPrefix}.network.measured_bytes`);
  requireExact(network.decimal_gb, networkBytes / 1_000_000_000, `${fieldPrefix}.network.decimal_gb`);
  requireExact(network.usd, 0, `${fieldPrefix}.network.usd`);
  const totalUsd = expectedA.subtotal_usd + expectedB.subtotal_usd;
  requireExact(root.total_usd, totalUsd, `${fieldPrefix}.total_usd`);
  requireExact(root.usd_per_ceremony, totalUsd / COST_MODEL_CEREMONIES, `${fieldPrefix}.usd_per_ceremony`);
  return Object.freeze({
    topology: CROSS_TOPOLOGY,
    deployment,
    region_label: regionLabel,
    pricing_effective_date: effectiveDate,
    measured: parsedMeasured,
    total_usd_per_million: totalUsd,
  });
}

function parseOperationalAcceptance(raw) {
  const root = requiredObject(raw, "operational_acceptance");
  requireExact(root.schema, OPERATIONAL_ACCEPTANCE_SCHEMA, "operational_acceptance.schema");
  requireExact(root.decision, "accept", "operational_acceptance.decision");
  const acceptedAt = requiredInstant(root.accepted_at, "operational_acceptance.accepted_at");
  requiredString(root.accepted_by, "operational_acceptance.accepted_by");
  requireExact(
    root.independent_two_account_administration_accepted,
    true,
    "operational_acceptance.independent_two_account_administration_accepted",
  );
  requireExact(
    root.pricing_source_reviewed,
    true,
    "operational_acceptance.pricing_source_reviewed",
  );
  return Object.freeze({
    accepted_at: acceptedAt.raw,
    accepted_at_ms: acceptedAt.timestamp,
    pricing_effective_date: requiredDate(
      root.pricing_effective_date,
      "operational_acceptance.pricing_effective_date",
    ),
    maximum_cross_account_usd_per_million: requiredPositiveNumber(
      root.maximum_cross_account_usd_per_million,
      "operational_acceptance.maximum_cross_account_usd_per_million",
    ),
  });
}

function deploymentIdentity(role) {
  return `${role.script_name}|${role.wrangler_version}|${role.worker_tag}|${role.version_id}|${role.artifact_sha256}`;
}

function deploymentsMatch(benchmark, analytics) {
  return (
    benchmark.deployment.deployment_id === analytics.deployment.deployment_id &&
    benchmark.deployment.local_readiness_bundle_sha256 ===
      analytics.deployment.local_readiness_bundle_sha256 &&
    JSON.stringify(benchmark.deployment.topology_binding) ===
      JSON.stringify(analytics.deployment.topology_binding) &&
    deploymentIdentity(benchmark.deployment.a) === deploymentIdentity(analytics.deployment.a) &&
    deploymentIdentity(benchmark.deployment.b) === deploymentIdentity(analytics.deployment.b) &&
    JSON.stringify(benchmark.deployment.constant_time_codegen) ===
      JSON.stringify(analytics.deployment.constant_time_codegen)
  );
}

function costEvidenceMatches(cost, benchmark, analytics) {
  return (
    deploymentsMatch(cost, benchmark) &&
    deploymentsMatch(cost, analytics) &&
    cost.region_label === benchmark.region_label &&
    cost.region_label === analytics.region_label &&
    cost.measured.cpu_a_ms === analytics.a.cpu_mean_ms &&
    cost.measured.cpu_b_ms === analytics.b.cpu_mean_ms &&
    cost.measured.network_bytes === benchmark.total_ab_transport_bytes_per_ceremony
  );
}

function reason(code, observed, threshold, comparison) {
  return Object.freeze({ code, observed, threshold, comparison });
}

function pushSampleReasons(reasons, evidence, prefix) {
  if (
    evidence.completed_samples !== evidence.requested_samples ||
    evidence.success_count !== evidence.requested_samples ||
    evidence.warm_success_count !== evidence.requested_samples - 1
  ) {
    reasons.push(reason(`PHASE13A_${prefix}_SAMPLES_INCOMPLETE`, evidence, null, "complete"));
  }
  if (evidence.failure_count !== 0) {
    reasons.push(reason(`PHASE13A_${prefix}_FAILURES_PRESENT`, evidence.failure_count, 0, "=="));
  }
}

function pushTableReason(reasons, evidence, prefix) {
  if (evidence.table_payload_bytes.max > TABLE_MAX_BYTES_FLOOR) {
    reasons.push(
      reason(
        `PHASE13A_${prefix}_TABLE_BYTES_EXCEEDED`,
        evidence.table_payload_bytes.max,
        TABLE_MAX_BYTES_FLOOR,
        "<=",
      ),
    );
  }
}

function pushAnalyticsAvailabilityReasons(reasons, analytics, prefix) {
  for (const [roleName, role] of [
    ["A", analytics.a],
    ["B", analytics.b],
  ]) {
    if (!role.core_available) {
      reasons.push(reason(`PHASE13A_${prefix}_${roleName}_CORE_UNAVAILABLE`, null, true, "available"));
    } else if (role.errors !== 0) {
      reasons.push(reason(`PHASE13A_${prefix}_${roleName}_ANALYTICS_ERRORS`, role.errors, 0, "=="));
    }
  }
}

function pushAnalyticsRequestReasons(reasons, analytics, benchmark, prefix) {
  for (const [roleName, role] of [
    ["A", analytics.a],
    ["B", analytics.b],
  ]) {
    if (role.core_available && role.requests !== benchmark.success_count) {
      reasons.push(
        reason(
          `PHASE13A_${prefix}_${roleName}_REQUEST_COUNT_MISMATCH`,
          role.requests,
          benchmark.success_count,
          "==",
        ),
      );
    }
  }
}

function pushMemoryReason(reasons, role, topologyName, roleName) {
  const gate = role.memory_gate;
  const validPass =
    gate.result === "pass" &&
    gate.threshold_bytes === MEMORY_MAX_BYTES &&
    gate.memory_usage_bytes_p999 !== null &&
    gate.memory_usage_bytes_p999 < MEMORY_MAX_BYTES &&
    gate.exceeded_memory_status_count === 0 &&
    gate.exceeded_memory_status_observed === false;
  if (!validPass) {
    reasons.push(
      reason(
        `PHASE13A_${topologyName}_${roleName}_MEMORY_GATE_FAILED`,
        gate,
        MEMORY_MAX_BYTES,
        "P999 < threshold and no exceededMemory",
      ),
    );
  }
}

function pushCostReasons(reasons, crossCost, acceptance) {
  if (acceptance.pricing_effective_date !== crossCost.pricing_effective_date) {
    reasons.push(reason("PHASE13A_COST_ACCEPTANCE_DATE_MISMATCH", null, null, "equal"));
  }
  if (
    crossCost.total_usd_per_million > acceptance.maximum_cross_account_usd_per_million
  ) {
    reasons.push(
      reason(
        "PHASE13A_CROSS_COST_EXCEEDED",
        crossCost.total_usd_per_million,
        acceptance.maximum_cross_account_usd_per_million,
        "<=",
      ),
    );
  }
}

function windowsCover(benchmark, analytics) {
  return (
    analytics.window.start_ms <= benchmark.measurement_window.start_ms &&
    analytics.window.end_ms >= benchmark.measurement_window.end_ms
  );
}

export function evaluatePhase13A(input) {
  const root = requiredObject(input, "input");
  const crossBenchmark = parseBenchmarkReport(
    root.cross_benchmark,
    CROSS_TOPOLOGY,
    "cross_benchmark",
    true,
  );
  const crossAnalytics = parseAnalyticsReport(
    root.cross_analytics,
    CROSS_TOPOLOGY,
    "cross_analytics",
  );
  const crossCost = parseCostReport(root.cross_cost, "cross_cost");
  const operationalAcceptance = parseOperationalAcceptance(root.operational_acceptance);
  if (operationalAcceptance.accepted_at_ms > crossBenchmark.measurement_window.start_ms) {
    evidenceError(
      "PHASE13A_OPERATIONAL_ACCEPTANCE_POSTMEASUREMENT",
      "operational_acceptance.accepted_at",
    );
  }
  const reasons = [];
  pushSampleReasons(reasons, crossBenchmark, "CROSS");
  pushTableReason(reasons, crossBenchmark, "CROSS");
  pushAnalyticsAvailabilityReasons(reasons, crossAnalytics, "CROSS");
  pushAnalyticsRequestReasons(reasons, crossAnalytics, crossBenchmark, "CROSS");
  if (crossBenchmark.region_label !== crossAnalytics.region_label) {
    reasons.push(reason("PHASE13A_CROSS_REGION_MISMATCH", null, null, "equal"));
  }
  if (!windowsCover(crossBenchmark, crossAnalytics)) {
    reasons.push(reason("PHASE13A_CROSS_ANALYTICS_WINDOW_MISMATCH", null, null, "covers"));
  }
  if (!deploymentsMatch(crossBenchmark, crossAnalytics)) {
    reasons.push(reason("PHASE13A_CROSS_DEPLOYMENT_MISMATCH", null, null, "equal"));
  }
  if (
    crossBenchmark.table_stream_p95_ms >=
    PHASE13A_THRESHOLDS.cross_account_table_stream_p95_ms_exclusive
  ) {
    reasons.push(
      reason(
        "PHASE13A_CROSS_TABLE_STREAM_P95_EXCEEDED",
        crossBenchmark.table_stream_p95_ms,
        PHASE13A_THRESHOLDS.cross_account_table_stream_p95_ms_exclusive,
        "<",
      ),
    );
  }
  if (crossBenchmark.client_wall_p95_ms > PHASE13A_THRESHOLDS.ceremony_p95_ms_max) {
    reasons.push(
      reason(
        "PHASE13A_CROSS_CEREMONY_P95_EXCEEDED",
        crossBenchmark.client_wall_p95_ms,
        PHASE13A_THRESHOLDS.ceremony_p95_ms_max,
        "<=",
      ),
    );
  }
  if (crossBenchmark.client_wall_p99_ms > PHASE13A_THRESHOLDS.ceremony_p99_ms_max) {
    reasons.push(
      reason(
        "PHASE13A_CROSS_CEREMONY_P99_EXCEEDED",
        crossBenchmark.client_wall_p99_ms,
        PHASE13A_THRESHOLDS.ceremony_p99_ms_max,
        "<=",
      ),
    );
  }
  const combinedCpuP95Bound =
    crossAnalytics.a.cpu_p99_ms === null || crossAnalytics.b.cpu_p99_ms === null
      ? null
      : crossAnalytics.a.cpu_p99_ms + crossAnalytics.b.cpu_p99_ms;
  if (combinedCpuP95Bound === null) {
    reasons.push(
      reason(
        "PHASE13A_COMBINED_CPU_P95_UNAVAILABLE",
        null,
        PHASE13A_THRESHOLDS.combined_cpu_p95_ms_max,
        "<=",
      ),
    );
  } else if (combinedCpuP95Bound > PHASE13A_THRESHOLDS.combined_cpu_p95_ms_max) {
    reasons.push(
      reason(
        "PHASE13A_COMBINED_CPU_P95_EXCEEDED",
        combinedCpuP95Bound,
        PHASE13A_THRESHOLDS.combined_cpu_p95_ms_max,
        "<=",
      ),
    );
  }
  pushMemoryReason(reasons, crossAnalytics.a, "CROSS", "A");
  pushMemoryReason(reasons, crossAnalytics.b, "CROSS", "B");
  if (!costEvidenceMatches(crossCost, crossBenchmark, crossAnalytics)) {
    reasons.push(reason("PHASE13A_CROSS_COST_EVIDENCE_MISMATCH", null, null, "equal"));
  }
  pushCostReasons(reasons, crossCost, operationalAcceptance);
  return Object.freeze({
    evaluator: "phase13a-deployed-viability-v1",
    decision: reasons.length === 0 ? "go" : "stop",
    thresholds: PHASE13A_THRESHOLDS,
    evidence: Object.freeze({
      cross_account: crossBenchmark,
      cross_account_cost: crossCost,
      operational_acceptance: operationalAcceptance,
      combined_cross_account_cpu_p95_upper_bound_ms: combinedCpuP95Bound,
      cpu_composition:
        "sum of marginal Deriver A and Deriver B CPU P99 values; union bound establishes at least 98% joint coverage and therefore a conservative P95 bound",
      cross_account_memory: Object.freeze({
        a: crossAnalytics.a.memory_gate,
        b: crossAnalytics.b.memory_gate,
      }),
    }),
    reasons,
  });
}

function requiredReportPath(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || !value.startsWith("/") || /[\r\n\0]/.test(value)) {
    evidenceError("PHASE13A_REPORT_PATH_INVALID", name);
  }
  return value;
}

function readReport(path, field) {
  let size;
  try {
    size = statSync(path).size;
  } catch {
    evidenceError("PHASE13A_REPORT_FILE_UNAVAILABLE", field);
  }
  if (size <= 0 || size > MAX_REPORT_BYTES) {
    evidenceError("PHASE13A_REPORT_FILE_SIZE_INVALID", field);
  }
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    evidenceError("PHASE13A_REPORT_JSON_INVALID", field);
  }
}

function loadInput(environment) {
  return Object.freeze({
    cross_benchmark: readReport(
      requiredReportPath(environment, "YAOS_AB_PHASE13A_CROSS_BENCHMARK_REPORT"),
      "cross_benchmark",
    ),
    cross_analytics: readReport(
      requiredReportPath(environment, "YAOS_AB_PHASE13A_CROSS_ANALYTICS_REPORT"),
      "cross_analytics",
    ),
    cross_cost: readReport(
      requiredReportPath(environment, "YAOS_AB_PHASE13A_CROSS_COST_REPORT"),
      "cross_cost",
    ),
    operational_acceptance: readReport(
      requiredReportPath(environment, "YAOS_AB_PHASE13A_OPERATIONAL_ACCEPTANCE"),
      "operational_acceptance",
    ),
  });
}

function incompleteForError(error) {
  const code = error instanceof EvidenceError ? error.code : "PHASE13A_EVALUATOR_FAILURE";
  const field = error instanceof EvidenceError ? error.field : "unknown";
  return Object.freeze({
    evaluator: "phase13a-deployed-viability-v1",
    decision: "evidence-incomplete",
    thresholds: PHASE13A_THRESHOLDS,
    evidence: null,
    reasons: [Object.freeze({ code, field })],
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

function main() {
  try {
    const result = evaluatePhase13A(loadInput(process.env));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.decision === "go" ? 0 : 2;
  } catch (error) {
    process.stdout.write(`${JSON.stringify(incompleteForError(error), null, 2)}\n`);
    process.exitCode = 2;
  }
}

if (isMainModule()) {
  main();
}
