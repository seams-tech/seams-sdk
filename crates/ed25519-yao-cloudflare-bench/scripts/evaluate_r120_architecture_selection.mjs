import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { pathToFileURL } from 'node:url';

import { buildR120Report } from './run_r120_architecture_benchmark.mjs';

const MAX_REPORT_BYTES = 32 * 1024 * 1024;
const MAX_CPU_P95_DELTA_US = 5_000;
const MAX_MEMORY_P999_INCREASE_NUMERATOR = 11;
const MAX_MEMORY_P999_INCREASE_DENOMINATOR = 10;
const CPU_LIMIT_MS = 300;
const CPU_HEADROOM_THRESHOLD_MS = 225;
const MEMORY_LIMIT_BYTES = 128 * 1024 * 1024;
const MEMORY_HEADROOM_THRESHOLD_BYTES = 96 * 1024 * 1024;
const TOPOLOGIES = Object.freeze([
  'same-account-service-binding-websocket',
  'cross-account-websocket',
]);

export class R120EvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'R120EvidenceError';
  }
}

function fail(message) {
  throw new R120EvidenceError(message);
}

function requiredNumber(value, field) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail(`${field} must be a finite nonnegative number`);
  }
  return value;
}

function requiredInteger(value, field) {
  const parsed = requiredNumber(value, field);
  if (!Number.isSafeInteger(parsed)) {
    fail(`${field} must be an integer`);
  }
  return parsed;
}

function requiredSha256(value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value)
      .sort()
      .map(function canonicalEntry(key) {
        return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
      });
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

export function r120ApprovalPayloadSha256(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function validateLatencyReport(report, expectedTopology) {
  if (
    report?.benchmark !== 'r120-threshold-prf-architecture-selection-v1' ||
    report.benchmark_only !== true ||
    report.topology !== expectedTopology ||
    report.evidence_scope?.kind !== 'deployed-selection' ||
    report.evidence_scope.deployment?.topology !== expectedTopology
  ) {
    fail(`${expectedTopology} latency evidence has an invalid identity`);
  }
  const rebuilt = buildR120Report({
    endpoint: report.endpoint,
    expectedTopology: report.topology,
    samples: report.samples,
    samplesPerCohort: report.samples_per_cohort,
    evidenceScope: report.evidence_scope,
    startedAt: report.measurement_window?.start,
    endedAt: report.measurement_window?.end,
  });
  if (!isDeepStrictEqual(rebuilt, report)) {
    fail(`${expectedTopology} latency evidence is inconsistent with its raw samples`);
  }
  return Object.freeze({
    deployment: report.evidence_scope.deployment,
    window: window(report, `${expectedTopology}.latency`),
  });
}

function window(report, field) {
  const start = Date.parse(report.measurement_window?.start);
  const end = Date.parse(report.measurement_window?.end);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) {
    fail(`${field} has an invalid measurement window`);
  }
  return Object.freeze({ start, end });
}

function validateResourceIdentity(report, expectedTopology, expectedProfile, deployment) {
  if (
    report?.benchmark !== 'r120-threshold-prf-workers-resource-v1' ||
    report.benchmark_only !== true ||
    report.topology !== expectedTopology ||
    report.profile !== expectedProfile ||
    !isDeepStrictEqual(report.deployment, deployment) ||
    report.cpu_limit_ms !== CPU_LIMIT_MS ||
    report.cpu_headroom_threshold_ms !== CPU_HEADROOM_THRESHOLD_MS ||
    report.memory_limit_bytes !== MEMORY_LIMIT_BYTES ||
    report.memory_headroom_threshold_bytes !== MEMORY_HEADROOM_THRESHOLD_BYTES ||
    !/^[0-9a-f]{64}$/.test(report.campaign_sha256) ||
    report.websocket_headroom?.websocket_message_limit_bytes !== 32 * 1024 * 1024 ||
    report.websocket_headroom?.headroom_threshold_bytes !== 24 * 1024 * 1024 ||
    !Number.isFinite(report.websocket_headroom?.maximum_outgoing_envelope_bytes) ||
    report.websocket_headroom.maximum_outgoing_envelope_bytes < 0 ||
    report.websocket_headroom.maximum_outgoing_envelope_bytes > 24 * 1024 * 1024 ||
    !Number.isFinite(report.websocket_headroom?.maximum_incoming_platform_fragment_bytes) ||
    report.websocket_headroom.maximum_incoming_platform_fragment_bytes < 0 ||
    report.websocket_headroom.maximum_incoming_platform_fragment_bytes > 24 * 1024 * 1024 ||
    report.websocket_headroom?.result !== 'pass' ||
    report.http_duration_limit !== 'unbounded-while-client-connected' ||
    report.cold_start_incidence !== 'not-observable-from-workers-invocations-adaptive' ||
    report.memory_evidence_classification !==
      'cloudflare-reservoir-sampled-shared-isolate-operational-proxy' ||
    report.platform_copy_accounting !== 'unavailable' ||
    report.exact_peak_proven !== false
  ) {
    fail(`${expectedTopology} ${expectedProfile} resource evidence has an invalid identity`);
  }
  return window(report, `${expectedTopology}.${expectedProfile}`);
}

function windowsOverlap(left, right) {
  return left.start < right.end && right.start < left.end;
}

function roleResource(report, role, field) {
  const value = report[role];
  const expectedRequests = requiredInteger(
    report.expected_requests_per_role,
    `${field}.expected_requests_per_role`,
  );
  const requests = requiredInteger(value?.core?.sum?.requests, `${field}.core.sum.requests`);
  const errors = requiredInteger(value?.core?.sum?.errors, `${field}.core.sum.errors`);
  const cpuP95Us = requiredInteger(
    value?.core?.quantiles?.microseconds?.cpuTimeP95,
    `${field}.core.quantiles.microseconds.cpuTimeP95`,
  );
  const cpuP95Ms = requiredNumber(
    value?.core?.quantiles?.milliseconds?.cpuTimeP95,
    `${field}.core.quantiles.milliseconds.cpuTimeP95`,
  );
  const memoryP999Bytes = requiredNumber(
    value?.memory?.quantiles_bytes?.memoryUsageBytesP999,
    `${field}.memory.quantiles_bytes.memoryUsageBytesP999`,
  );
  if (memoryP999Bytes === 0) {
    fail(`${field}.memory.quantiles_bytes.memoryUsageBytesP999 must be positive`);
  }
  if (
    value?.core?.available !== true ||
    value?.memory?.available !== true ||
    cpuP95Ms !== cpuP95Us / 1_000 ||
    value?.sampled_memory_gate?.threshold_bytes !== MEMORY_HEADROOM_THRESHOLD_BYTES ||
    value.sampled_memory_gate.memory_usage_bytes_p999 !== memoryP999Bytes ||
    value.sampled_memory_gate.exceeded_memory_status_count !== 0 ||
    value.sampled_memory_gate.exceeded_memory_status_observed !== false ||
    value.sampled_memory_gate.result !== 'pass'
  ) {
    fail(`${field} resource analytics are unavailable or failed`);
  }
  return Object.freeze({
    expectedRequests,
    requests,
    errors,
    cpuP95Us,
    memoryP999Bytes,
  });
}

function evaluateRole(current, candidate, role, reasons, evidence) {
  const currentRole = roleResource(current, role, `${current.topology}.current.${role}`);
  const candidateRole = roleResource(
    candidate,
    role,
    `${candidate.topology}.threshold-prf-v1.${role}`,
  );
  const cpuDeltaUs = candidateRole.cpuP95Us - currentRole.cpuP95Us;
  if (
    currentRole.requests !== currentRole.expectedRequests ||
    candidateRole.requests !== candidateRole.expectedRequests ||
    currentRole.errors !== 0 ||
    candidateRole.errors !== 0
  ) {
    reasons.push(`${candidate.topology}:${role}:exclusive-window-request-accounting-failed`);
  }
  if (cpuDeltaUs > MAX_CPU_P95_DELTA_US) {
    reasons.push(`${candidate.topology}:${role}:cpu-p95-delta-exceeded`);
  }
  if (
    currentRole.cpuP95Us > CPU_HEADROOM_THRESHOLD_MS * 1_000 ||
    candidateRole.cpuP95Us > CPU_HEADROOM_THRESHOLD_MS * 1_000
  ) {
    reasons.push(`${candidate.topology}:${role}:cpu-headroom-failed`);
  }
  if (
    candidateRole.memoryP999Bytes * MAX_MEMORY_P999_INCREASE_DENOMINATOR >
    currentRole.memoryP999Bytes * MAX_MEMORY_P999_INCREASE_NUMERATOR
  ) {
    reasons.push(`${candidate.topology}:${role}:memory-p999-delta-exceeded`);
  }
  if (
    currentRole.memoryP999Bytes >= MEMORY_HEADROOM_THRESHOLD_BYTES ||
    candidateRole.memoryP999Bytes >= MEMORY_HEADROOM_THRESHOLD_BYTES
  ) {
    reasons.push(`${candidate.topology}:${role}:memory-headroom-failed`);
  }
  evidence[role] = Object.freeze({
    current_cpu_p95_microseconds: currentRole.cpuP95Us,
    candidate_cpu_p95_microseconds: candidateRole.cpuP95Us,
    cpu_p95_delta_microseconds: cpuDeltaUs,
    current_memory_p999_bytes: currentRole.memoryP999Bytes,
    candidate_memory_p999_bytes: candidateRole.memoryP999Bytes,
  });
}

function evaluateTopology(topology, input, reasons) {
  requiredSha256(input.latency?.sha256, `${topology}.latency.sha256`);
  requiredSha256(input.currentResources?.sha256, `${topology}.currentResources.sha256`);
  requiredSha256(input.candidateResources?.sha256, `${topology}.candidateResources.sha256`);
  const latency = validateLatencyReport(input.latency.report, topology);
  const currentWindow = validateResourceIdentity(
    input.currentResources.report,
    topology,
    'current',
    latency.deployment,
  );
  const candidateWindow = validateResourceIdentity(
    input.candidateResources.report,
    topology,
    'threshold-prf-v1',
    latency.deployment,
  );
  if (windowsOverlap(currentWindow, candidateWindow)) {
    reasons.push(`${topology}:resource-windows-overlap`);
  }
  if (
    windowsOverlap(latency.window, currentWindow) ||
    windowsOverlap(latency.window, candidateWindow)
  ) {
    reasons.push(`${topology}:latency-and-resource-windows-overlap`);
  }
  if (
    input.latency.report.acceptance.latency_gate_passed !== true ||
    input.latency.report.acceptance.sample_count_gate_passed !== true ||
    input.latency.report.acceptance.artifact_and_wire_parity_passed !== true
  ) {
    reasons.push(`${topology}:latency-or-wire-gate-failed`);
  }
  const roles = {};
  evaluateRole(input.currentResources.report, input.candidateResources.report, 'a', reasons, roles);
  evaluateRole(input.currentResources.report, input.candidateResources.report, 'b', reasons, roles);
  return Object.freeze({
    deployment_id: latency.deployment.deployment_id,
    latency_report_sha256: input.latency.sha256,
    current_resource_report_sha256: input.currentResources.sha256,
    candidate_resource_report_sha256: input.candidateResources.sha256,
    current_resource_campaign_sha256: input.currentResources.report.campaign_sha256,
    candidate_resource_campaign_sha256: input.candidateResources.report.campaign_sha256,
    roles: Object.freeze(roles),
  });
}

export function evaluateR120ArchitectureSelection(input) {
  const reasons = [];
  const evidence = {};
  for (const topology of TOPOLOGIES) {
    evidence[topology] = evaluateTopology(topology, input[topology], reasons);
  }
  const approvalPayload = Object.freeze({
    schema: 'r120-threshold-prf-architecture-approval-payload-v1',
    architecture: 'role-targeted-threshold-prf-preface-v1',
    yao_circuit_change: false,
    frozen_limits: Object.freeze({
      maximum_warm_p95_latency_delta_ms: 10,
      maximum_warm_p95_per_role_cpu_delta_microseconds: MAX_CPU_P95_DELTA_US,
      maximum_memory_p999_increase_numerator: MAX_MEMORY_P999_INCREASE_NUMERATOR,
      maximum_memory_p999_increase_denominator: MAX_MEMORY_P999_INCREASE_DENOMINATOR,
      worker_cpu_limit_ms: CPU_LIMIT_MS,
      worker_cpu_headroom_threshold_ms: CPU_HEADROOM_THRESHOLD_MS,
      worker_memory_limit_bytes: MEMORY_LIMIT_BYTES,
      worker_memory_headroom_threshold_bytes: MEMORY_HEADROOM_THRESHOLD_BYTES,
      websocket_message_limit_bytes: 32 * 1024 * 1024,
      websocket_message_headroom_threshold_bytes: 24 * 1024 * 1024,
    }),
    evidence: Object.freeze(evidence),
  });
  const passed = reasons.length === 0;
  return Object.freeze({
    schema: 'r120-threshold-prf-architecture-selection-candidate-v1',
    decision: passed ? 'ready-for-release-signature' : 'rejected',
    reasons: Object.freeze(reasons),
    approval_payload: passed ? approvalPayload : null,
    approval_payload_sha256: passed ? r120ApprovalPayloadSha256(approvalPayload) : null,
    signature: Object.freeze({ status: 'required', selection_ready: false }),
  });
}

function artifactPath(environment, name) {
  const path = environment[name];
  if (
    typeof path !== 'string' ||
    !isAbsolute(path) ||
    !path.endsWith('.json') ||
    /[\r\n\0]/.test(path)
  ) {
    fail(`${name} must be an absolute JSON path`);
  }
  return path;
}

function readArtifact(path) {
  let size;
  try {
    size = statSync(path).size;
  } catch {
    fail(`R120 evidence artifact is unavailable: ${path}`);
  }
  if (size <= 0 || size > MAX_REPORT_BYTES) {
    fail(`R120 evidence artifact has an invalid size: ${path}`);
  }
  let bytes;
  let report;
  try {
    bytes = readFileSync(path);
    report = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`R120 evidence artifact is invalid JSON: ${path}`);
  }
  return Object.freeze({
    path,
    report,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
}

function topologyInput(environment, prefix) {
  return Object.freeze({
    latency: readArtifact(artifactPath(environment, `${prefix}_LATENCY_REPORT`)),
    currentResources: readArtifact(artifactPath(environment, `${prefix}_CURRENT_RESOURCE_REPORT`)),
    candidateResources: readArtifact(
      artifactPath(environment, `${prefix}_CANDIDATE_RESOURCE_REPORT`),
    ),
  });
}

export function loadR120SelectionInput(environment) {
  return Object.freeze({
    'same-account-service-binding-websocket': topologyInput(
      environment,
      'YAOS_AB_R120_SAME_ACCOUNT',
    ),
    'cross-account-websocket': topologyInput(environment, 'YAOS_AB_R120_CROSS_ACCOUNT'),
  });
}

function checklistArtifact(kind, artifact, expectedTopology, expectedProfile) {
  const report = artifact.report;
  const latency = kind === 'latency';
  if (
    (latency && report?.benchmark !== 'r120-threshold-prf-architecture-selection-v1') ||
    (!latency && report?.benchmark !== 'r120-threshold-prf-workers-resource-v1') ||
    report?.benchmark_only !== true ||
    report.topology !== expectedTopology ||
    (!latency && report.profile !== expectedProfile)
  ) {
    fail(`${expectedTopology} ${kind} artifact has an invalid identity`);
  }
  const deployment = latency ? report.evidence_scope?.deployment : report.deployment;
  if (deployment?.deployment_id === undefined || deployment.topology !== expectedTopology) {
    fail(`${expectedTopology} ${kind} artifact has an invalid deployment identity`);
  }
  return Object.freeze({
    kind,
    path: artifact.path,
    sha256: requiredSha256(artifact.sha256, `${expectedTopology}.${kind}.sha256`),
    benchmark: report.benchmark,
    topology: expectedTopology,
    profile: latency ? 'paired-latency' : expectedProfile,
    deployment_id: deployment.deployment_id,
  });
}

export function buildR120SelectionInputChecklist(input) {
  const artifacts = [];
  for (const topology of TOPOLOGIES) {
    const topologyInputValue = input[topology];
    artifacts.push(
      checklistArtifact('latency', topologyInputValue?.latency, topology, null),
      checklistArtifact(
        'current-resources',
        topologyInputValue?.currentResources,
        topology,
        'current',
      ),
      checklistArtifact(
        'candidate-resources',
        topologyInputValue?.candidateResources,
        topology,
        'threshold-prf-v1',
      ),
    );
  }
  const paths = artifacts.map(function artifactPathValue(artifact) {
    return artifact.path;
  });
  if (
    paths.some(function missingPath(path) {
      return typeof path !== 'string';
    })
  ) {
    fail('R120 selection checklist requires source paths for all six artifacts');
  }
  if (new Set(paths).size !== paths.length) {
    fail('R120 selection checklist requires six distinct artifact paths');
  }
  return Object.freeze({
    schema: 'r120-threshold-prf-selection-input-checklist-v1',
    status: 'ready-for-evaluation',
    artifact_count: artifacts.length,
    artifacts: Object.freeze(artifacts),
    selection_ready: false,
  });
}

function main() {
  const result = evaluateR120ArchitectureSelection(loadR120SelectionInput(process.env));
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.decision === 'rejected') {
    process.exitCode = 2;
  }
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    handleFatal(error);
  }
}
