import { readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

import { BoundaryError } from "./deployment_boundary.mjs";

const MINIMUM_REPORTS = 20;
const MAXIMUM_REPORTS = 1_000;
const MAXIMUM_REPORT_BYTES = 4 * 1024 * 1024;
const EXPECTED_BENCHMARK = "phase9b-cloudflare-activation-128kib";
const EXPECTED_TABLE_PAYLOAD_BYTES = 2_104_960;
const INCOMING_SECRET_BUFFER_DISPOSAL =
  "rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled";
const OUTPUT_SCHEMA = "ed25519_yao_phase9b_fresh_version_first_request_series_v1";
const CLASSIFICATION = "fresh-version-first-request-operational-cold-proxy";
const DEPLOYMENT_ID_PATTERN = /^[0-9a-f]{32}$/;
const VERSION_ID_PATTERN = /^[A-Za-z0-9-]{8,128}$/;
const WORKER_TAG_PATTERN = /^[A-Za-z0-9-]{8,128}$/;
const SEMVER_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/;
const ARTIFACT_DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const REGION_LABEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TOPOLOGIES = Object.freeze([
  "same-account-service-binding",
  "cross-account-https",
]);
const SCRIPT_NAMES = Object.freeze({
  "same-account-service-binding": Object.freeze({
    a: "ed25519-yao-ab-benchmark-a",
    b: "ed25519-yao-ab-benchmark-b",
  }),
  "cross-account-https": Object.freeze({
    a: "ed25519-yao-ab-benchmark-a-cross-account",
    b: "ed25519-yao-ab-benchmark-b-cross-account",
  }),
});

function fail(message) {
  throw new BoundaryError(message);
}

function requiredObject(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${field} must be an object`);
  }
  return value;
}

function requiredArray(value, field) {
  if (!Array.isArray(value)) {
    fail(`${field} must be an array`);
  }
  return value;
}

function requiredInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative integer`);
  }
  return value;
}

function requiredMetric(value, field) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    fail(`${field} must be a finite nonnegative number`);
  }
  return value;
}

function validateSecretTransportAccounting(result, field) {
  requireExact(
    result.incoming_secret_buffer_disposal,
    INCOMING_SECRET_BUFFER_DISPOSAL,
    `${field}.incoming_secret_buffer_disposal`,
  );
  requireExact(
    requiredInteger(
      result.adapter_secret_ingress_rust_copy_passes,
      `${field}.adapter_secret_ingress_rust_copy_passes`,
    ),
    1,
    `${field}.adapter_secret_ingress_rust_copy_passes`,
  );
  const incomingBytes = requiredInteger(
    result.total_incoming_body_bytes,
    `${field}.total_incoming_body_bytes`,
  );
  requireExact(
    requiredInteger(
      result.adapter_secret_ingress_rust_copy_bytes,
      `${field}.adapter_secret_ingress_rust_copy_bytes`,
    ),
    incomingBytes,
    `${field}.adapter_secret_ingress_rust_copy_bytes`,
  );
  requireExact(
    requiredInteger(
      result.adapter_secret_ingress_js_overwrite_bytes,
      `${field}.adapter_secret_ingress_js_overwrite_bytes`,
    ),
    incomingBytes,
    `${field}.adapter_secret_ingress_js_overwrite_bytes`,
  );
  requireExact(
    requiredInteger(
      result.workers_rs_outgoing_stream_body_copy_passes,
      `${field}.workers_rs_outgoing_stream_body_copy_passes`,
    ),
    1,
    `${field}.workers_rs_outgoing_stream_body_copy_passes`,
  );
  requireExact(
    requiredInteger(
      result.workers_rs_outgoing_stream_body_copy_bytes,
      `${field}.workers_rs_outgoing_stream_body_copy_bytes`,
    ),
    requiredInteger(
      result.total_outgoing_envelope_bytes,
      `${field}.total_outgoing_envelope_bytes`,
    ),
    `${field}.workers_rs_outgoing_stream_body_copy_bytes`,
  );
}

function requireExact(value, expected, field) {
  if (value !== expected) {
    fail(`${field} must equal ${expected}`);
  }
}

function requiredPattern(value, pattern, field) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${field} has an invalid format`);
  }
  return value;
}

function requiredInstant(value, field) {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    fail(`${field} must be a canonical UTC instant`);
  }
  return value;
}

function requiredDeploymentId(value, field) {
  const deploymentId = requiredPattern(value, DEPLOYMENT_ID_PATTERN, field);
  if (/^0+$/.test(deploymentId)) {
    fail(`${field} must be nonzero`);
  }
  return deploymentId;
}

function requiredHostname(value, field) {
  const hostname = requiredPattern(value, /^[a-z0-9.-]{3,253}$/, field);
  const labels = hostname.split(".");
  if (hostname.includes("..") || labels.length < 2 || labels.some((label) => !HOST_LABEL_PATTERN.test(label))) {
    fail(`${field} has an invalid hostname`);
  }
  return hostname;
}

function validateTopologyBinding(raw, topology, field) {
  const binding = requiredObject(raw, field);
  requireExact(binding.schema, "ed25519_yao_phase9b_topology_binding_v1", `${field}.schema`);
  requireExact(binding.kind, topology, `${field}.kind`);
  const aAccount = requiredPattern(
    binding.a_account_sha256,
    ARTIFACT_DIGEST_PATTERN,
    `${field}.a_account_sha256`,
  );
  const bAccount = requiredPattern(
    binding.b_account_sha256,
    ARTIFACT_DIGEST_PATTERN,
    `${field}.b_account_sha256`,
  );
  const aHostname = requiredHostname(binding.a_public_hostname, `${field}.a_public_hostname`);
  if (topology === "same-account-service-binding") {
    requireExact(aAccount, bAccount, `${field}.b_account_sha256`);
    requireExact(binding.b_service_name, SCRIPT_NAMES[topology].b, `${field}.b_service_name`);
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
    fail(`${field} must identify distinct account commitments`);
  }
  const bHostname = requiredHostname(binding.b_public_hostname, `${field}.b_public_hostname`);
  if (aHostname === bHostname) {
    fail(`${field} must identify distinct A and B hostnames`);
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

function compareNumbers(left, right) {
  return left - right;
}

function percentile(values, fraction) {
  const sorted = [...values].sort(compareNumbers);
  const rank = Math.max(0, Math.ceil(fraction * sorted.length) - 1);
  return sorted[rank];
}

function summarize(values) {
  return Object.freeze({
    p50: percentile(values, 0.5),
    p95: percentile(values, 0.95),
    p99: percentile(values, 0.99),
  });
}

function readReport(path) {
  if (typeof path !== "string" || !isAbsolute(path) || !path.endsWith(".json")) {
    fail("each deployed benchmark report path must be an absolute JSON path");
  }
  let size;
  try {
    size = statSync(path).size;
  } catch {
    fail(`deployed benchmark report is unavailable: ${path}`);
  }
  if (size <= 0 || size > MAXIMUM_REPORT_BYTES) {
    fail(`deployed benchmark report has an invalid size: ${path}`);
  }
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail(`deployed benchmark report is not valid JSON: ${path}`);
  }
}

function validateRoleEvidence(raw, expectedScriptName, field) {
  const role = requiredObject(raw, field);
  requireExact(role.script_name, expectedScriptName, `${field}.script_name`);
  return Object.freeze({
    deployed_at: requiredInstant(role.deployed_at, `${field}.deployed_at`),
    wrangler_version: requiredPattern(
      role.wrangler_version,
      SEMVER_PATTERN,
      `${field}.wrangler_version`,
    ),
    worker_tag: requiredPattern(role.worker_tag, WORKER_TAG_PATTERN, `${field}.worker_tag`),
    version_id: requiredPattern(role.version_id, VERSION_ID_PATTERN, `${field}.version_id`),
    artifact_sha256: requiredPattern(
      role.artifact_sha256,
      ARTIFACT_DIGEST_PATTERN,
      `${field}.artifact_sha256`,
    ),
  });
}

function validateConstantTimeRole(raw, artifactSha256, field) {
  const role = requiredObject(raw, field);
  requireExact(role.artifact_sha256, artifactSha256, `${field}.artifact_sha256`);
  return Object.freeze({
    artifact_sha256: artifactSha256,
    wasm_sha256: requiredPattern(
      role.wasm_sha256,
      ARTIFACT_DIGEST_PATTERN,
      `${field}.wasm_sha256`,
    ),
  });
}

function validateConstantTimeEvidence(raw, a, b, field) {
  const evidence = requiredObject(raw, field);
  requireExact(
    evidence.schema,
    "ed25519_yao_worker_constant_time_codegen_v1",
    `${field}.schema`,
  );
  requireExact(
    evidence.inspector,
    "llvm-objdump-secret-bit-branch-gate-v1",
    `${field}.inspector`,
  );
  requireExact(evidence.result, "pass", `${field}.result`);
  return Object.freeze({
    schema: evidence.schema,
    inspector: evidence.inspector,
    result: evidence.result,
    roles: Object.freeze({
      a: validateConstantTimeRole(evidence.roles?.a, a.artifact_sha256, `${field}.roles.a`),
      b: validateConstantTimeRole(evidence.roles?.b, b.artifact_sha256, `${field}.roles.b`),
    }),
  });
}

function validateDeployment(raw, topology, field) {
  const deployment = requiredObject(raw, field);
  requireExact(deployment.schema, "ed25519_yao_phase9b_deployment_receipt_v4", `${field}.schema`);
  requireExact(deployment.topology, topology, `${field}.topology`);
  requiredInstant(deployment.recorded_at, `${field}.recorded_at`);
  const scripts = SCRIPT_NAMES[topology];
  const a = validateRoleEvidence(deployment.a, scripts.a, `${field}.a`);
  const b = validateRoleEvidence(deployment.b, scripts.b, `${field}.b`);
  if (a.version_id === b.version_id) {
    fail(`${field} must identify distinct A and B versions`);
  }
  const localReadinessBundleSha256 = requiredPattern(
    deployment.local_readiness_bundle_sha256,
    ARTIFACT_DIGEST_PATTERN,
    `${field}.local_readiness_bundle_sha256`,
  );
  return Object.freeze({
    deployment_id: requiredDeploymentId(deployment.deployment_id, `${field}.deployment_id`),
    local_readiness_bundle_sha256: localReadinessBundleSha256,
    topology_binding: validateTopologyBinding(
      deployment.topology_binding,
      topology,
      `${field}.topology_binding`,
    ),
    a,
    b,
    constant_time_codegen: validateConstantTimeEvidence(
      deployment.constant_time_codegen,
      a,
      b,
      `${field}.constant_time_codegen`,
    ),
  });
}

function validateSuccessfulSamples(report, deploymentId, field) {
  const requestedSamples = requiredInteger(report.requested_samples, `${field}.requested_samples`);
  const completedSamples = requiredInteger(report.completed_samples, `${field}.completed_samples`);
  const successCount = requiredInteger(report.success_count, `${field}.success_count`);
  const failureCount = requiredInteger(report.failure_count, `${field}.failure_count`);
  const failures = requiredArray(report.failures, `${field}.failures`);
  const samples = requiredArray(report.samples, `${field}.samples`);
  if (
    requestedSamples === 0 ||
    completedSamples !== requestedSamples ||
    successCount !== requestedSamples ||
    failureCount !== 0 ||
    failures.length !== 0 ||
    samples.length !== requestedSamples
  ) {
    fail(`${field} is not a completely successful deployed benchmark report`);
  }
  const indexes = new Set();
  let firstSample = null;
  for (let position = 0; position < samples.length; position += 1) {
    const sample = requiredObject(samples[position], `${field}.samples.${position}`);
    const index = requiredInteger(sample.index, `${field}.samples.${position}.index`);
    if (index >= requestedSamples || indexes.has(index)) {
      fail(`${field}.samples has invalid or duplicate indexes`);
    }
    indexes.add(index);
    const result = requiredObject(sample.result, `${field}.samples.${position}.result`);
    requireExact(result.deployment_id, deploymentId, `${field}.samples.${position}.result.deployment_id`);
    if (index === 0) {
      firstSample = sample;
    }
  }
  if (firstSample === null) {
    fail(`${field}.samples has no raw sample at index 0`);
  }
  const firstObservation = requiredObject(report.first_observation, `${field}.first_observation`);
  requireExact(firstObservation.index, 0, `${field}.first_observation.index`);
  requireExact(
    firstObservation.result?.deployment_id,
    deploymentId,
    `${field}.first_observation.result.deployment_id`,
  );
  requireExact(firstSample.result.benchmark, EXPECTED_BENCHMARK, `${field}.samples.index0.result.benchmark`);
  requireExact(firstSample.result.benchmark_only, true, `${field}.samples.index0.result.benchmark_only`);
  requireExact(
    firstSample.result.production_eligible,
    false,
    `${field}.samples.index0.result.production_eligible`,
  );
  validateSecretTransportAccounting(firstSample.result, `${field}.samples.index0.result`);
  requireExact(firstSample.result.role, "deriver-a", `${field}.samples.index0.result.role`);
  requireExact(firstSample.result.topology, report.topology, `${field}.samples.index0.result.topology`);
  requireExact(
    firstSample.result.body_byte_timing_boundary,
    "raw-stream-chunk-emission-and-receipt",
    `${field}.samples.index0.result.body_byte_timing_boundary`,
  );
  requireExact(
    firstSample.result.table_payload_bytes,
    EXPECTED_TABLE_PAYLOAD_BYTES,
    `${field}.samples.index0.result.table_payload_bytes`,
  );
  requiredInteger(
    firstSample.result.total_ab_transport_bytes,
    `${field}.samples.index0.result.total_ab_transport_bytes`,
  );
  requireExact(
    firstSample.result.ot_message_count,
    4,
    `${field}.samples.index0.result.ot_message_count`,
  );
  requireExact(
    firstSample.result.ot_sequential_round_count,
    4,
    `${field}.samples.index0.result.ot_sequential_round_count`,
  );
  const clientWall = requiredMetric(firstSample.client_wall_ms, `${field}.samples.index0.client_wall_ms`);
  const tableStream = requiredMetric(
    firstSample.result.table_stream_duration_ms,
    `${field}.samples.index0.result.table_stream_duration_ms`,
  );
  requiredMetric(
    firstSample.result.total_protocol_duration_ms,
    `${field}.samples.index0.result.total_protocol_duration_ms`,
  );
  const timingFields = [
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
  for (const timingField of timingFields) {
    const value = requiredMetric(
      firstSample.result[timingField],
      `${field}.samples.index0.result.${timingField}`,
    );
    if (previous !== null && previous > value) {
      fail(`${field}.samples.index0 has unordered timing evidence`);
    }
    previous = value;
  }
  if (
    firstSample.result.b_to_a_first_body_byte_received_ms >=
      firstSample.result.request_direction_closed_ms ||
    tableStream !==
      firstSample.result.last_table_frame_accepted_ms -
        firstSample.result.first_table_frame_accepted_ms ||
    firstSample.result.total_protocol_duration_ms !==
      firstSample.result.response_eof_complete_ms ||
    clientWall < firstSample.result.total_protocol_duration_ms
  ) {
    fail(`${field}.samples.index0 has inconsistent timing evidence`);
  }
  return firstSample;
}

function validateReport(raw, path, index) {
  const field = `reports.${index}`;
  const report = requiredObject(raw, field);
  requireExact(report.benchmark, EXPECTED_BENCHMARK, `${field}.benchmark`);
  requireExact(report.benchmark_only, true, `${field}.benchmark_only`);
  requireExact(report.security_claim, "none", `${field}.security_claim`);
  if (!TOPOLOGIES.includes(report.topology)) {
    fail(`${field}.topology is invalid`);
  }
  const requestedTopology =
    report.topology === "same-account-service-binding" ? "one-account" : "two-account";
  requireExact(report.requested_topology, requestedTopology, `${field}.requested_topology`);
  requiredPattern(report.region_label, REGION_LABEL_PATTERN, `${field}.region_label`);
  const deployment = validateDeployment(report.deployment, report.topology, `${field}.deployment`);
  const firstSample = validateSuccessfulSamples(report, deployment.deployment_id, field);
  const sampleStartedAt = requiredInstant(firstSample.started_at, `${field}.samples.index0.started_at`);
  const latestDeployment = Math.max(
    Date.parse(deployment.a.deployed_at),
    Date.parse(deployment.b.deployed_at),
  );
  if (Date.parse(sampleStartedAt) < latestDeployment) {
    fail(`${field}.samples.index0 predates its role deployments`);
  }
  return Object.freeze({ path, report, deployment, firstSample });
}

function requireUnique(value, seen, field) {
  if (seen.has(value)) {
    fail(`${field} must be distinct across the cohort`);
  }
  seen.add(value);
}

function cohortIdentity(validatedReports) {
  const first = validatedReports[0].report;
  for (let index = 1; index < validatedReports.length; index += 1) {
    const report = validatedReports[index].report;
    requireExact(report.topology, first.topology, `reports.${index}.topology`);
    requireExact(report.region_label, first.region_label, `reports.${index}.region_label`);
  }
  return Object.freeze({ topology: first.topology, regionLabel: first.region_label });
}

function validateCohortDeployments(validatedReports) {
  const deploymentIds = new Set();
  const versionIds = new Set();
  const first = validatedReports[0].deployment;
  for (let index = 0; index < validatedReports.length; index += 1) {
    const deployment = validatedReports[index].deployment;
    requireUnique(deployment.deployment_id, deploymentIds, `reports.${index}.deployment.deployment_id`);
    requireUnique(deployment.a.version_id, versionIds, `reports.${index}.deployment.a.version_id`);
    requireUnique(deployment.b.version_id, versionIds, `reports.${index}.deployment.b.version_id`);
    requireExact(
      deployment.a.artifact_sha256,
      first.a.artifact_sha256,
      `reports.${index}.deployment.a.artifact_sha256`,
    );
    requireExact(
      deployment.b.artifact_sha256,
      first.b.artifact_sha256,
      `reports.${index}.deployment.b.artifact_sha256`,
    );
    requireExact(
      deployment.local_readiness_bundle_sha256,
      first.local_readiness_bundle_sha256,
      `reports.${index}.deployment.local_readiness_bundle_sha256`,
    );
    requireExact(
      JSON.stringify(deployment.topology_binding),
      JSON.stringify(first.topology_binding),
      `reports.${index}.deployment.topology_binding`,
    );
  }
}

function outputSample(validated) {
  return Object.freeze({
    source_report: validated.path,
    deployment: validated.report.deployment,
    first_raw_sample: validated.firstSample,
  });
}

function outputSamples(validatedReports) {
  const samples = [];
  for (const validated of validatedReports) {
    samples.push(outputSample(validated));
  }
  return Object.freeze(samples);
}

function metricValues(validatedReports, field) {
  const values = [];
  for (const validated of validatedReports) {
    if (field === "client_wall_ms") {
      values.push(validated.firstSample.client_wall_ms);
    } else {
      values.push(validated.firstSample.result[field]);
    }
  }
  return values;
}

export function assembleFreshVersionFirstRequestSeries(reportPaths) {
  if (
    !Array.isArray(reportPaths) ||
    reportPaths.length < MINIMUM_REPORTS ||
    reportPaths.length > MAXIMUM_REPORTS
  ) {
    fail(`fresh-version first-request evidence requires ${MINIMUM_REPORTS} through ${MAXIMUM_REPORTS} reports`);
  }
  const validatedReports = [];
  for (let index = 0; index < reportPaths.length; index += 1) {
    const path = reportPaths[index];
    validatedReports.push(validateReport(readReport(path), path, index));
  }
  const identity = cohortIdentity(validatedReports);
  validateCohortDeployments(validatedReports);
  return Object.freeze({
    schema: OUTPUT_SCHEMA,
    benchmark: EXPECTED_BENCHMARK,
    benchmark_only: true,
    topology: identity.topology,
    region_label: identity.regionLabel,
    sample_count: validatedReports.length,
    classification: CLASSIFICATION,
    physical_isolate_cold_proven: false,
    metrics: Object.freeze({
      client_wall_ms: summarize(metricValues(validatedReports, "client_wall_ms")),
      table_stream_duration_ms: summarize(
        metricValues(validatedReports, "table_stream_duration_ms"),
      ),
    }),
    samples: outputSamples(validatedReports),
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

function main() {
  const report = assembleFreshVersionFirstRequestSeries(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function handleFatal(error) {
  const message = error instanceof BoundaryError ? error.message : "cold-cohort evidence assembly failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    handleFatal(error);
  }
}
