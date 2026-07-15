import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { PHASE13A_THRESHOLDS } from './evaluate_phase13a_viability.mjs';
import { ACTIVATION_128KIB_WIRE_PROFILE } from './activation_wire_profile.mjs';
import { loadLocalReadinessBundle } from './local_readiness_bundle.mjs';
import { collectLocalReadinessInputs } from './local_readiness_inputs.mjs';

const MAX_EVIDENCE_BYTES = 256 * 1024;
const ROOT_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const KAT_JSON_PATH =
  'crates/ed25519-yao/artifacts/passive-benchmark-v1/phase5-stream-wire-kats-v1.json';
const PHASE9C_LIFECYCLE_REPORT_PATH =
  'crates/router-ab-dev/reports/ed25519-yao-local-latency-v1.json';
const PHASE9C_VALIDATION_RECEIPT_PATH =
  'crates/router-ab-dev/target/phase9c-yaos-ab-local-evidence-v1.json';
const PHASE9C_PROFILES = Object.freeze([
  'ed25519-yao-one-account',
  'ed25519-yao-two-administrator',
]);
const PHASE9C_LIFECYCLE_VECTORS = Object.freeze([
  'registration',
  'activation',
  'recovery',
  'refresh',
  'exact_export',
  'post_refresh_ordinary_signing',
]);
const PHASE9C_COMPLETED_CHECKS = Object.freeze([
  'canonical Yao derivation',
  'transport-neutral Yao composition',
  'Client-owned registration boundary',
  'Client-owned registration WASM boundary',
  'SDK Router boundary guard',
  'SDK Yao local TypeScript gate',
  'SDK Router, WASM Client, wallet lifecycle, and process gates',
  'local role boundaries and process lifecycle',
  'constant-time code-generation guard',
]);
const REQUIRED_ARTIFACT_PATHS = Object.freeze([
  KAT_JSON_PATH,
  'crates/ed25519-yao/artifacts/passive-benchmark-v1/phase5-stream-wire-kats-v1.bin',
  'crates/ed25519-yao/docs/phase3-passive-benchmark-report.md',
  'crates/ed25519-yao/docs/phase4-role-separated-report.md',
  'crates/ed25519-yao/docs/phase5-streaming-report.md',
  'crates/ed25519-yao/docs/phase13a-local-compute-report.md',
  'crates/ed25519-yao-cloudflare-bench/docs/phase13a-isolation-audit-v1.md',
  'crates/ed25519-yao-cloudflare-bench/docs/phase9b-same-account-report-v085.md',
  'crates/ed25519-yao-cloudflare-bench/tests/source_guards.rs',
  'crates/ed25519-yao-cloudflare-bench/Cargo.toml',
  PHASE9C_LIFECYCLE_REPORT_PATH,
]);
const REQUIRED_DEPLOYED_EVIDENCE = Object.freeze([
  'same_account_http_benchmark',
  'same_account_worker_analytics',
  'same_account_fresh_version_first_request_proxy',
  'same_account_measured_cost',
  'cross_account_https_benchmark',
  'cross_account_worker_analytics',
  'cross_account_fresh_version_first_request_proxy',
  'cross_account_measured_cost',
  'worker_isolate_memory',
  'deployed_placement_and_connection',
  'operational_cost_and_topology_acceptance',
]);

export class LocalPreflightError extends Error {
  constructor(code, field) {
    super(`${code}: ${field}`);
    this.name = 'LocalPreflightError';
    this.code = code;
    this.field = field;
  }
}

function fail(code, field) {
  throw new LocalPreflightError(code, field);
}

function requiredObject(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('PHASE13A_LOCAL_INVALID_TYPE', field);
  }
  return value;
}

function requiredArray(value, field) {
  if (!Array.isArray(value)) {
    fail('PHASE13A_LOCAL_INVALID_TYPE', field);
  }
  return value;
}

function requiredString(value, field) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
    fail('PHASE13A_LOCAL_INVALID_TYPE', field);
  }
  return value;
}

function requiredNumber(value, field) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail('PHASE13A_LOCAL_INVALID_TYPE', field);
  }
  return value;
}

function requiredInteger(value, field) {
  const parsed = requiredNumber(value, field);
  if (!Number.isSafeInteger(parsed)) {
    fail('PHASE13A_LOCAL_INVALID_TYPE', field);
  }
  return parsed;
}

function requireExact(value, expected, field) {
  if (value !== expected) {
    fail('PHASE13A_LOCAL_IDENTITY_MISMATCH', field);
  }
}

function requireExactStringArray(value, expected, field) {
  const observed = requiredArray(value, field);
  if (observed.length !== expected.length) {
    fail('PHASE13A_LOCAL_IDENTITY_MISMATCH', field);
  }
  for (let index = 0; index < expected.length; index += 1) {
    requireExact(observed[index], expected[index], `${field}.${index}`);
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function loadLocalEvidence() {
  return loadLocalReadinessBundle().evidence;
}

export function loadWorkspaceArtifact(path) {
  if (typeof path !== 'string' || path.includes('..') || path.startsWith('/')) {
    fail('PHASE13A_LOCAL_ARTIFACT_PATH', String(path));
  }
  const absolute = resolve(ROOT_PATH, path);
  if (!absolute.startsWith(`${ROOT_PATH}${sep}`)) {
    fail('PHASE13A_LOCAL_ARTIFACT_PATH', path);
  }
  try {
    return readFileSync(absolute);
  } catch {
    fail('PHASE13A_LOCAL_ARTIFACT_UNAVAILABLE', path);
  }
}

function artifactEntries(evidence) {
  const entries = requiredArray(evidence.artifacts, 'artifacts');
  if (entries.length !== REQUIRED_ARTIFACT_PATHS.length) {
    fail('PHASE13A_LOCAL_ARTIFACT_SET', 'artifacts');
  }
  const byPath = new Map();
  for (const raw of entries) {
    const entry = requiredObject(raw, 'artifacts[]');
    const path = requiredString(entry.path, 'artifacts[].path');
    const digest = requiredString(entry.sha256, `artifacts.${path}.sha256`);
    if (!/^[0-9a-f]{64}$/.test(digest) || byPath.has(path)) {
      fail('PHASE13A_LOCAL_ARTIFACT_SET', path);
    }
    byPath.set(path, digest);
  }
  return byPath;
}

function validateArtifacts(evidence, artifactLoader) {
  const byPath = artifactEntries(evidence);
  for (const path of REQUIRED_ARTIFACT_PATHS) {
    const expected = byPath.get(path);
    if (expected === undefined) {
      fail('PHASE13A_LOCAL_ARTIFACT_SET', path);
    }
    const observed = sha256(artifactLoader(path));
    if (observed !== expected) {
      fail('PHASE13A_LOCAL_ARTIFACT_DIGEST', path);
    }
  }
}

function parseKatArtifact(bytes) {
  try {
    return requiredObject(JSON.parse(bytes.toString('utf8')), 'stream_kat_artifact');
  } catch (error) {
    if (error instanceof LocalPreflightError) {
      throw error;
    }
    fail('PHASE13A_LOCAL_KAT_JSON', KAT_JSON_PATH);
  }
}

function katCasesByName(cases, field) {
  const byName = new Map();
  for (const raw of requiredArray(cases, field)) {
    const entry = requiredObject(raw, `${field}[]`);
    const name = requiredString(entry.name, `${field}[].name`);
    if (byName.has(name)) {
      fail('PHASE13A_LOCAL_KAT_SET', name);
    }
    byName.set(name, entry);
  }
  return byName;
}

function validateKatNumber(evidenceCase, artifactCase, field) {
  const expected = requiredInteger(evidenceCase[field], `stream_kat_cases.${field}`);
  const observed = requiredInteger(artifactCase[field], `stream_kat_artifact.${field}`);
  requireExact(observed, expected, `stream_kat_cases.${evidenceCase.name}.${field}`);
}

function validateKatCases(evidence, artifactLoader) {
  const artifact = parseKatArtifact(artifactLoader(KAT_JSON_PATH));
  const expected = katCasesByName(evidence.stream_kat_cases, 'stream_kat_cases');
  const observed = katCasesByName(artifact.cases, 'stream_kat_artifact.cases');
  if (expected.size !== 2 || observed.size !== expected.size) {
    fail('PHASE13A_LOCAL_KAT_SET', 'stream_kat_cases');
  }
  for (const [name, evidenceCase] of expected) {
    const artifactCase = observed.get(name);
    if (artifactCase === undefined) {
      fail('PHASE13A_LOCAL_KAT_SET', name);
    }
    for (const field of ['and_gates', 'table_bytes', 'body_bytes', 'frame_count', 'chunk_bytes']) {
      validateKatNumber(evidenceCase, artifactCase, field);
    }
    if (evidenceCase.table_bytes !== evidenceCase.and_gates * 32) {
      fail('PHASE13A_LOCAL_TABLE_FORMULA', name);
    }
  }
}

function validateLifecycleLatencyOperation(operation, field) {
  const value = requiredObject(operation, field);
  const minimum = requiredInteger(value.minimum_microseconds, `${field}.minimum_microseconds`);
  const p50 = requiredInteger(value.p50_microseconds, `${field}.p50_microseconds`);
  const p95 = requiredInteger(value.p95_microseconds, `${field}.p95_microseconds`);
  const p99 = requiredInteger(value.p99_microseconds, `${field}.p99_microseconds`);
  const maximum = requiredInteger(value.maximum_microseconds, `${field}.maximum_microseconds`);
  if (!(minimum <= p50 && p50 <= p95 && p95 <= p99 && p99 <= maximum)) {
    fail('PHASE13A_LOCAL_PHASE9C_LATENCY_ORDER', field);
  }
  return Object.freeze({ p95_microseconds: p95, p99_microseconds: p99 });
}

function validateLifecycleWireBytes(wireBytes, field) {
  const value = requiredObject(wireBytes, field);
  const deriverAToB = requiredInteger(value.deriver_a_to_b, `${field}.deriver_a_to_b`);
  const deriverBToA = requiredInteger(value.deriver_b_to_a, `${field}.deriver_b_to_a`);
  const total = requiredInteger(value.total, `${field}.total`);
  requireExact(total, deriverAToB + deriverBToA, `${field}.total`);
  return Object.freeze({ deriver_a_to_b: deriverAToB, deriver_b_to_a: deriverBToA, total });
}

function validatePhase9CLifecycleReport(artifactLoader) {
  let report;
  try {
    report = requiredObject(
      JSON.parse(artifactLoader(PHASE9C_LIFECYCLE_REPORT_PATH).toString('utf8')),
      'phase9c_lifecycle_report',
    );
  } catch (error) {
    if (error instanceof LocalPreflightError) {
      throw error;
    }
    fail('PHASE13A_LOCAL_PHASE9C_REPORT', PHASE9C_LIFECYCLE_REPORT_PATH);
  }
  requireExact(
    report.schema,
    'seams-ed25519-yao-local-latency-report-v1',
    'phase9c_lifecycle_report.schema',
  );
  requireExact(
    report.evidence_kind,
    'nonproduction_local_process',
    'phase9c_lifecycle_report.evidence_kind',
  );
  requireExact(report.production_eligible, false, 'phase9c_lifecycle_report.production_eligible');
  requireExact(report.deployed_evidence, false, 'phase9c_lifecycle_report.deployed_evidence');
  requireExact(
    requiredInteger(report.samples_per_profile, 'phase9c_lifecycle_report.samples_per_profile'),
    100,
    'phase9c_lifecycle_report.samples_per_profile',
  );
  requireExact(
    requiredInteger(report.warmups_per_profile, 'phase9c_lifecycle_report.warmups_per_profile'),
    1,
    'phase9c_lifecycle_report.warmups_per_profile',
  );
  requireExact(report.rust_build_profile, 'release', 'phase9c_lifecycle_report.rust_build_profile');
  requireExact(
    report.percentile_method,
    'nearest_rank',
    'phase9c_lifecycle_report.percentile_method',
  );
  requireExact(
    report.statistically_sufficient_for_p99,
    true,
    'phase9c_lifecycle_report.statistically_sufficient_for_p99',
  );

  const profiles = requiredArray(report.profiles, 'phase9c_lifecycle_report.profiles');
  if (profiles.length !== PHASE9C_PROFILES.length) {
    fail('PHASE13A_LOCAL_PHASE9C_PROFILE_SET', 'phase9c_lifecycle_report.profiles');
  }
  const summary = [];
  for (let index = 0; index < PHASE9C_PROFILES.length; index += 1) {
    const profile = requiredObject(profiles[index], `phase9c_lifecycle_report.profiles.${index}`);
    requireExact(
      profile.profile,
      PHASE9C_PROFILES[index],
      `phase9c_lifecycle_report.profiles.${index}.profile`,
    );
    const operations = requiredObject(
      profile.operations,
      `phase9c_lifecycle_report.profiles.${index}.operations`,
    );
    for (const operation of ['registration', 'recovery', 'refresh', 'export', 'ordinary_signing']) {
      validateLifecycleLatencyOperation(
        operations[operation],
        `phase9c_lifecycle_report.profiles.${index}.operations.${operation}`,
      );
    }
    const wireBytes = requiredObject(
      profile.wire_bytes,
      `phase9c_lifecycle_report.profiles.${index}.wire_bytes`,
    );
    const activation = validateLifecycleWireBytes(
      wireBytes.activation,
      `phase9c_lifecycle_report.profiles.${index}.wire_bytes.activation`,
    );
    const exportWire = validateLifecycleWireBytes(
      wireBytes.export,
      `phase9c_lifecycle_report.profiles.${index}.wire_bytes.export`,
    );
    const ordinarySigning = validateLifecycleWireBytes(
      wireBytes.ordinary_signing,
      `phase9c_lifecycle_report.profiles.${index}.wire_bytes.ordinary_signing`,
    );
    requireExact(activation.deriver_a_to_b, 2_185_420, 'phase9c activation A-to-B bytes');
    requireExact(activation.deriver_b_to_a, 37_164, 'phase9c activation B-to-A bytes');
    requireExact(exportWire.deriver_a_to_b, 82_636, 'phase9c export A-to-B bytes');
    requireExact(exportWire.deriver_b_to_a, 20_780, 'phase9c export B-to-A bytes');
    requireExact(ordinarySigning.total, 0, 'phase9c ordinary-signing Deriver bytes');
    summary.push(
      Object.freeze({
        profile: profile.profile,
        activation_bytes: activation.total,
        export_bytes: exportWire.total,
        ordinary_signing_deriver_bytes: ordinarySigning.total,
      }),
    );
  }
  return Object.freeze(summary);
}

function validatePhase9CReceiptInputTree(receipt, expectedInputs) {
  const observed = requiredObject(receipt.validated_inputs, 'phase9c_receipt.validated_inputs');
  requireExact(observed.schema, expectedInputs.schema, 'phase9c_receipt.validated_inputs.schema');
  requireExact(
    requiredInteger(observed.file_count, 'phase9c_receipt.validated_inputs.file_count'),
    expectedInputs.file_count,
    'phase9c_receipt.validated_inputs.file_count',
  );
  requireExact(
    requiredInteger(observed.total_bytes, 'phase9c_receipt.validated_inputs.total_bytes'),
    expectedInputs.total_bytes,
    'phase9c_receipt.validated_inputs.total_bytes',
  );
  requireExact(
    requiredString(observed.sha256, 'phase9c_receipt.validated_inputs.sha256'),
    expectedInputs.sha256,
    'phase9c_receipt.validated_inputs.sha256',
  );
}

function validatePhase9CLifecycleEvidence(raw, profile, index) {
  const field = `phase9c_receipt.lifecycle_evidence.${index}`;
  const evidence = requiredObject(raw, field);
  requireExact(
    evidence.schema,
    'seams-ed25519-yao-phase9c-lifecycle-evidence-v1',
    `${field}.schema`,
  );
  requireExact(evidence.profile, profile, `${field}.profile`);
  requireExactStringArray(
    evidence.lifecycle_vectors,
    PHASE9C_LIFECYCLE_VECTORS,
    `${field}.vectors`,
  );
  for (const booleanField of [
    'export_public_key_matches_registered',
    'export_standard_signature_verified',
    'recovery_preserved_identity',
    'refresh_preserved_identity',
    'deriver_processes_terminated_before_signing',
    'ordinary_signing_standard_signature_verified',
  ]) {
    requireExact(evidence[booleanField], true, `${field}.${booleanField}`);
  }
  const registeredDigest = requiredString(
    evidence.registered_public_key_sha256,
    `${field}.registered_public_key_sha256`,
  );
  const exportedDigest = requiredString(
    evidence.exported_public_key_sha256,
    `${field}.exported_public_key_sha256`,
  );
  if (!/^[0-9a-f]{64}$/.test(registeredDigest)) {
    fail('PHASE13A_LOCAL_PHASE9C_PUBLIC_KEY_DIGEST', field);
  }
  requireExact(exportedDigest, registeredDigest, `${field}.exported_public_key_sha256`);
  for (const zeroField of [
    'ordinary_signing_deriver_a_requests',
    'ordinary_signing_deriver_b_requests',
    'ordinary_signing_deriver_a_to_b_bytes',
    'ordinary_signing_deriver_b_to_a_bytes',
  ]) {
    requireExact(
      requiredInteger(evidence[zeroField], `${field}.${zeroField}`),
      0,
      `${field}.${zeroField}`,
    );
  }
  return Object.freeze({
    profile,
    public_key_sha256: registeredDigest,
    lifecycle_vector_count: PHASE9C_LIFECYCLE_VECTORS.length,
    ordinary_signing_deriver_requests: 0,
    ordinary_signing_deriver_bytes: 0,
  });
}

function validatePhase9CValidationReceipt(evidence, artifactLoader, validatedInputs) {
  const binding = requiredObject(evidence.phase9c_validation, 'phase9c_validation');
  requireExact(
    binding.receipt_path,
    PHASE9C_VALIDATION_RECEIPT_PATH,
    'phase9c_validation.receipt_path',
  );
  requireExact(binding.gate, 'validate:yaos-ab-local', 'phase9c_validation.gate');
  requireExact(binding.result, 'pass', 'phase9c_validation.result');
  requireExact(binding.production_eligible, false, 'phase9c_validation.production_eligible');
  requireExact(
    requiredInteger(binding.profile_count, 'phase9c_validation.profile_count'),
    PHASE9C_PROFILES.length,
    'phase9c_validation.profile_count',
  );
  requireExact(
    requiredInteger(binding.lifecycle_vector_count, 'phase9c_validation.lifecycle_vector_count'),
    PHASE9C_LIFECYCLE_VECTORS.length,
    'phase9c_validation.lifecycle_vector_count',
  );

  const receiptBytes = artifactLoader(PHASE9C_VALIDATION_RECEIPT_PATH);
  if (receiptBytes.length === 0 || receiptBytes.length > MAX_EVIDENCE_BYTES) {
    fail('PHASE13A_LOCAL_PHASE9C_RECEIPT_SIZE', PHASE9C_VALIDATION_RECEIPT_PATH);
  }
  let receipt;
  try {
    receipt = requiredObject(JSON.parse(receiptBytes.toString('utf8')), 'phase9c_receipt');
  } catch (error) {
    if (error instanceof LocalPreflightError) {
      throw error;
    }
    fail('PHASE13A_LOCAL_PHASE9C_RECEIPT', PHASE9C_VALIDATION_RECEIPT_PATH);
  }
  requireExact(
    receipt.schema,
    'seams-ed25519-yao-phase9c-validation-receipt-v1',
    'phase9c_receipt.schema',
  );
  requireExact(receipt.gate, binding.gate, 'phase9c_receipt.gate');
  requireExact(receipt.result, binding.result, 'phase9c_receipt.result');
  requireExact(
    receipt.production_eligible,
    binding.production_eligible,
    'phase9c_receipt.production_eligible',
  );
  const generatedAt = requiredString(receipt.generated_at, 'phase9c_receipt.generated_at');
  if (!Number.isFinite(Date.parse(generatedAt))) {
    fail('PHASE13A_LOCAL_PHASE9C_RECEIPT_TIME', 'phase9c_receipt.generated_at');
  }
  validatePhase9CReceiptInputTree(receipt, validatedInputs);
  requireExactStringArray(
    receipt.completed_checks,
    PHASE9C_COMPLETED_CHECKS,
    'phase9c_receipt.completed_checks',
  );
  const lifecycleReport = requiredObject(
    receipt.lifecycle_report,
    'phase9c_receipt.lifecycle_report',
  );
  requireExact(
    lifecycleReport.path,
    PHASE9C_LIFECYCLE_REPORT_PATH,
    'phase9c_receipt.lifecycle_report.path',
  );
  requireExact(
    requiredString(lifecycleReport.sha256, 'phase9c_receipt.lifecycle_report.sha256'),
    sha256(artifactLoader(PHASE9C_LIFECYCLE_REPORT_PATH)),
    'phase9c_receipt.lifecycle_report.sha256',
  );
  const lifecycleEvidence = requiredArray(
    receipt.lifecycle_evidence,
    'phase9c_receipt.lifecycle_evidence',
  );
  if (lifecycleEvidence.length !== PHASE9C_PROFILES.length) {
    fail('PHASE13A_LOCAL_PHASE9C_PROFILE_SET', 'phase9c_receipt.lifecycle_evidence');
  }
  const profiles = [];
  for (let index = 0; index < PHASE9C_PROFILES.length; index += 1) {
    profiles.push(
      validatePhase9CLifecycleEvidence(lifecycleEvidence[index], PHASE9C_PROFILES[index], index),
    );
  }
  return Object.freeze({
    receipt_sha256: sha256(receiptBytes),
    source_input_sha256: validatedInputs.sha256,
    lifecycle_report_sha256: lifecycleReport.sha256,
    profiles: Object.freeze(profiles),
  });
}

function validateBenchmark(evidence) {
  const benchmark = requiredObject(evidence.benchmark, 'benchmark');
  requireExact(benchmark.id, 'phase9b-cloudflare-activation-128kib', 'benchmark.id');
  requireExact(
    benchmark.topology,
    'same-account-service-binding-local-workerd',
    'benchmark.topology',
  );
  requireExact(
    requiredInteger(benchmark.sample_count, 'benchmark.sample_count'),
    51,
    'benchmark.sample_count',
  );
  requireExact(
    requiredInteger(benchmark.warm_sample_count, 'benchmark.warm_sample_count'),
    50,
    'benchmark.warm_sample_count',
  );
  requireExact(
    requiredInteger(benchmark.failure_count, 'benchmark.failure_count'),
    0,
    'benchmark.failure_count',
  );
  const tableBytes = requiredInteger(
    benchmark.table_payload_bytes,
    'benchmark.table_payload_bytes',
  );
  if (tableBytes > PHASE13A_THRESHOLDS.table_payload_bytes_max_floor) {
    fail('PHASE13A_LOCAL_TABLE_LIMIT', 'benchmark.table_payload_bytes');
  }
  const p95 = requiredNumber(benchmark.client_wall_p95_ms, 'benchmark.client_wall_p95_ms');
  const p99 = requiredNumber(benchmark.client_wall_p99_ms, 'benchmark.client_wall_p99_ms');
  if (p95 > PHASE13A_THRESHOLDS.ceremony_p95_ms_max) {
    fail('PHASE13A_LOCAL_CEREMONY_P95', 'benchmark.client_wall_p95_ms');
  }
  if (p99 > PHASE13A_THRESHOLDS.ceremony_p99_ms_max) {
    fail('PHASE13A_LOCAL_CEREMONY_P99', 'benchmark.client_wall_p99_ms');
  }
  requiredNumber(benchmark.protocol_p95_ms, 'benchmark.protocol_p95_ms');
  requiredNumber(benchmark.protocol_p99_ms, 'benchmark.protocol_p99_ms');
  requiredNumber(
    benchmark.table_stream_acceptance_p95_ms,
    'benchmark.table_stream_acceptance_p95_ms',
  );
  requiredNumber(
    benchmark.table_stream_acceptance_p99_ms,
    'benchmark.table_stream_acceptance_p99_ms',
  );
  return benchmark;
}

function validateWireProfile(evidence) {
  const profile = requiredObject(
    evidence.activation_128kib_wire_profile,
    'activation_128kib_wire_profile',
  );
  for (const [field, expected] of Object.entries(ACTIVATION_128KIB_WIRE_PROFILE)) {
    requireExact(
      requiredInteger(profile[field], `activation_128kib_wire_profile.${field}`),
      expected,
      `activation_128kib_wire_profile.${field}`,
    );
  }
  requireExact(
    profile.table_framing_payload_bytes,
    profile.body_bytes - profile.table_payload_bytes,
    'activation_128kib_wire_profile.table_framing_payload_bytes',
  );
  requireExact(
    profile.table_protocol_bytes,
    profile.body_bytes + 248,
    'activation_128kib_wire_profile.table_protocol_bytes',
  );
  requireExact(
    profile.envelope_header_bytes,
    profile.transport_message_count * 16,
    'activation_128kib_wire_profile.envelope_header_bytes',
  );
  requireExact(
    profile.total_ab_transport_bytes,
    profile.table_transport_bytes + profile.control_transport_bytes,
    'activation_128kib_wire_profile.total_ab_transport_bytes',
  );
  requireExact(
    profile.total_ab_transport_bytes,
    profile.deriver_a_to_b_transport_bytes + profile.deriver_b_to_a_transport_bytes,
    'activation_128kib_wire_profile.directional_transport_bytes',
  );
  return profile;
}

function validateLocalCompute(evidence) {
  const compute = requiredObject(evidence.local_compute, 'local_compute');
  requireExact(
    compute.scope,
    'local-lower-bound-not-cloudflare-worker-evidence',
    'local_compute.scope',
  );
  const native = requiredObject(
    compute.native_activation_128kib,
    'local_compute.native_activation_128kib',
  );
  const wasm = requiredObject(
    compute.wasm_activation_128kib,
    'local_compute.wasm_activation_128kib',
  );
  requireExact(native.warm_sample_count, 20, 'local_compute.native.warm_sample_count');
  requireExact(wasm.warm_sample_count, 20, 'local_compute.wasm.warm_sample_count');
  for (const field of [
    'wall_p95_ms',
    'deriver_a_cpu_p95_ms',
    'deriver_b_cpu_p95_ms',
    'combined_cpu_p95_ms',
    'deriver_a_rss_p95_bytes',
    'deriver_b_rss_p95_bytes',
  ]) {
    requiredNumber(native[field], `local_compute.native.${field}`);
  }
  for (const field of [
    'wall_p95_ms',
    'deriver_a_synchronous_p95_ms',
    'deriver_b_synchronous_p95_ms',
    'combined_role_synchronous_p95_ms',
    'linear_memory_peak_bytes',
    'deriver_a_peak_arena_bytes',
    'deriver_b_peak_arena_bytes',
    'deriver_a_peak_table_buffer_bytes',
    'deriver_b_peak_table_buffer_bytes',
    'peak_rust_frame_bytes',
    'peak_js_live_wire_bytes',
  ]) {
    requiredNumber(wasm[field], `local_compute.wasm.${field}`);
  }
  const nativeWallP95 = requiredNumber(native.wall_p95_ms, 'local_compute.native.wall_p95_ms');
  const nativeCombinedCpuP95 = requiredNumber(
    native.combined_cpu_p95_ms,
    'local_compute.native.combined_cpu_p95_ms',
  );
  const wasmWallP95 = requiredNumber(wasm.wall_p95_ms, 'local_compute.wasm.wall_p95_ms');
  const wasmCombinedP95 = requiredNumber(
    wasm.combined_role_synchronous_p95_ms,
    'local_compute.wasm.combined_role_synchronous_p95_ms',
  );
  if (
    nativeWallP95 > PHASE13A_THRESHOLDS.ceremony_p95_ms_max ||
    wasmWallP95 > PHASE13A_THRESHOLDS.ceremony_p95_ms_max ||
    nativeCombinedCpuP95 > PHASE13A_THRESHOLDS.combined_cpu_p95_ms_max ||
    wasmCombinedP95 > PHASE13A_THRESHOLDS.combined_cpu_p95_ms_max
  ) {
    fail('PHASE13A_LOCAL_COMPUTE_LIMIT', 'local_compute');
  }
  const memoryLimit = PHASE13A_THRESHOLDS.role_memory_p999_bytes_exclusive;
  for (const [field, value] of [
    ['native.deriver_a_rss_p95_bytes', native.deriver_a_rss_p95_bytes],
    ['native.deriver_b_rss_p95_bytes', native.deriver_b_rss_p95_bytes],
    ['wasm.linear_memory_peak_bytes', wasm.linear_memory_peak_bytes],
  ]) {
    if (requiredInteger(value, `local_compute.${field}`) >= memoryLimit) {
      fail('PHASE13A_LOCAL_MEMORY_LIMIT', `local_compute.${field}`);
    }
  }
  requireExact(
    requiredInteger(
      wasm.deriver_a_peak_table_buffer_bytes,
      'local_compute.wasm.deriver_a_peak_table_buffer_bytes',
    ),
    131_072,
    'local_compute.wasm.deriver_a_peak_table_buffer_bytes',
  );
  requireExact(
    requiredInteger(
      wasm.deriver_b_peak_table_buffer_bytes,
      'local_compute.wasm.deriver_b_peak_table_buffer_bytes',
    ),
    131_072,
    'local_compute.wasm.deriver_b_peak_table_buffer_bytes',
  );
  return Object.freeze({
    native_wall_p95_ms: nativeWallP95,
    native_combined_cpu_p95_ms: nativeCombinedCpuP95,
    wasm_wall_p95_ms: wasmWallP95,
    wasm_combined_role_synchronous_p95_ms: wasmCombinedP95,
    wasm_linear_memory_peak_bytes: wasm.linear_memory_peak_bytes,
  });
}

function validateLocalCommandEvidence(evidence) {
  const validation = requiredObject(evidence.validation, 'validation');
  requireExact(validation.command, 'npm run validate:local-readiness', 'validation.command');
  requireExact(validation.result, 'pass', 'validation.result');
  requireExact(validation.rust_unit_tests, 18, 'validation.rust_unit_tests');
  requireExact(validation.source_guard_tests, 12, 'validation.source_guard_tests');
  requireExact(validation.normal_role_artifacts, 4, 'validation.normal_role_artifacts');
  requireExact(validation.fault_artifacts, 9, 'validation.fault_artifacts');
  requireExact(validation.wrangler_dry_run_artifacts, 4, 'validation.wrangler_dry_run_artifacts');
  requireExact(validation.core_passive_rust_tests, 99, 'validation.core_passive_rust_tests');
  requireExact(validation.independent_python_tests, 186, 'validation.independent_python_tests');
  requireExact(
    validation.deterministic_differential_cases,
    128,
    'validation.deterministic_differential_cases',
  );
  requireExact(
    validation.phase5_stream_kat_drift_tests,
    1,
    'validation.phase5_stream_kat_drift_tests',
  );
  requireExact(validation.strict_core_clippy_targets, 3, 'validation.strict_core_clippy_targets');
  requireExact(validation.wasm_stream_profiles, 6, 'validation.wasm_stream_profiles');
  requireExact(validation.wasm_stream_modes, 2, 'validation.wasm_stream_modes');
  requireExact(
    validation.formal_parity_production_rust_tests,
    80,
    'validation.formal_parity_production_rust_tests',
  );
  requireExact(
    validation.formal_parity_generator_rust_tests,
    418,
    'validation.formal_parity_generator_rust_tests',
  );
  requireExact(
    validation.formal_parity_circuit_rust_tests,
    25,
    'validation.formal_parity_circuit_rust_tests',
  );
  requireExact(
    validation.formal_parity_artifact_filesystem_tests,
    3,
    'validation.formal_parity_artifact_filesystem_tests',
  );
  requireExact(
    validation.local_native_compute_profiles,
    2,
    'validation.local_native_compute_profiles',
  );
  requireExact(validation.local_wasm_compute_profiles, 2, 'validation.local_wasm_compute_profiles');
  requireExact(
    validation.local_compute_samples_per_profile,
    21,
    'validation.local_compute_samples_per_profile',
  );
}

function validateLocalReadinessInputs(evidence) {
  const expected = requiredObject(evidence.validated_inputs, 'validated_inputs');
  requireExact(expected.schema, 'ed25519_yao_local_readiness_inputs_v1', 'validated_inputs.schema');
  const observed = collectLocalReadinessInputs();
  requireExact(
    requiredInteger(expected.file_count, 'validated_inputs.file_count'),
    observed.file_count,
    'validated_inputs.file_count',
  );
  requireExact(
    requiredInteger(expected.total_bytes, 'validated_inputs.total_bytes'),
    observed.total_bytes,
    'validated_inputs.total_bytes',
  );
  requireExact(
    requiredString(expected.sha256, 'validated_inputs.sha256'),
    observed.sha256,
    'validated_inputs.sha256',
  );
  return observed;
}

function validateIsolationEvidence(evidence) {
  const isolation = requiredObject(evidence.benchmark_isolation, 'benchmark_isolation');
  requireExact(
    isolation.schema,
    'ed25519_yao_benchmark_isolation_audit_v1',
    'benchmark_isolation.schema',
  );
  requireExact(isolation.status, 'pass', 'benchmark_isolation.status');
  requireExact(isolation.production_reachable, false, 'benchmark_isolation.production_reachable');
  requireExact(
    requiredInteger(
      isolation.authorized_core_dependents,
      'benchmark_isolation.authorized_core_dependents',
    ),
    5,
    'benchmark_isolation.authorized_core_dependents',
  );
  requireExact(
    requiredInteger(isolation.benchmark_dependents, 'benchmark_isolation.benchmark_dependents'),
    0,
    'benchmark_isolation.benchmark_dependents',
  );
  if (
    requiredInteger(isolation.product_files_scanned, 'benchmark_isolation.product_files_scanned') <
    100
  ) {
    fail('PHASE13A_LOCAL_ISOLATION', 'benchmark_isolation.product_files_scanned');
  }
  requireExact(
    requiredInteger(isolation.product_references, 'benchmark_isolation.product_references'),
    0,
    'benchmark_isolation.product_references',
  );
  requireExact(
    requiredInteger(
      isolation.benchmark_wrangler_configs,
      'benchmark_isolation.benchmark_wrangler_configs',
    ),
    19,
    'benchmark_isolation.benchmark_wrangler_configs',
  );
  requireExact(
    requiredInteger(isolation.production_routes, 'benchmark_isolation.production_routes'),
    0,
    'benchmark_isolation.production_routes',
  );
  return Object.freeze({
    production_reachable: false,
    authorized_core_dependents: isolation.authorized_core_dependents,
    product_files_scanned: isolation.product_files_scanned,
    benchmark_wrangler_configs: isolation.benchmark_wrangler_configs,
  });
}

function validateUnavailableEvidence(evidence) {
  const unavailable = requiredArray(
    evidence.deployed_evidence_unavailable,
    'deployed_evidence_unavailable',
  );
  if (unavailable.length !== REQUIRED_DEPLOYED_EVIDENCE.length) {
    fail('PHASE13A_LOCAL_DEPLOYED_GATE', 'deployed_evidence_unavailable');
  }
  for (let index = 0; index < REQUIRED_DEPLOYED_EVIDENCE.length; index += 1) {
    requireExact(
      unavailable[index],
      REQUIRED_DEPLOYED_EVIDENCE[index],
      `deployed_evidence_unavailable.${index}`,
    );
  }
}

function passedCheck(code, evidence) {
  return Object.freeze({ code, result: 'pass', evidence });
}

export function evaluateLocalPreflight(evidence, artifactLoader) {
  const root = requiredObject(evidence, 'evidence');
  requireExact(root.schema, 'phase13a-local-preflight-evidence-v1', 'schema');
  requireExact(root.scope, 'local-evidence-only', 'scope');
  requireExact(root.phase13a_decision, 'unavailable', 'phase13a_decision');
  requireExact(root.production_eligible, false, 'production_eligible');
  requireExact(
    root.incoming_secret_buffer_disposal,
    'rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled',
    'incoming_secret_buffer_disposal',
  );
  validateArtifacts(root, artifactLoader);
  validateKatCases(root, artifactLoader);
  const phase9cLifecycleReport = validatePhase9CLifecycleReport(artifactLoader);
  const validatedInputs = validateLocalReadinessInputs(root);
  const phase9cValidation = validatePhase9CValidationReceipt(root, artifactLoader, validatedInputs);
  const benchmark = validateBenchmark(root);
  const wireProfile = validateWireProfile(root);
  const localCompute = validateLocalCompute(root);
  const isolation = validateIsolationEvidence(root);
  validateLocalCommandEvidence(root);
  validateUnavailableEvidence(root);
  return Object.freeze({
    evaluator: 'phase13a-local-preflight-v1',
    status: 'deployment-required',
    phase13a_decision: 'unavailable',
    production_eligible: false,
    local_checks: Object.freeze([
      passedCheck('PHASE13A_LOCAL_VALIDATED_INPUT_TREE', validatedInputs),
      passedCheck('PHASE13A_LOCAL_ARTIFACT_DIGESTS', REQUIRED_ARTIFACT_PATHS.length),
      passedCheck(
        'PHASE13A_LOCAL_PHASE9C_GATE',
        Object.freeze({
          validation: phase9cValidation,
          lifecycle_report: phase9cLifecycleReport,
        }),
      ),
      passedCheck('PHASE13A_LOCAL_STREAM_KATS', root.stream_kat_cases.length),
      passedCheck('PHASE13A_LOCAL_TABLE_BYTES', benchmark.table_payload_bytes),
      passedCheck(
        'PHASE13A_LOCAL_WIRE_BYTES',
        Object.freeze({
          ot_payload_bytes: wireProfile.ot_payload_bytes,
          ot_message_count: wireProfile.ot_message_count,
          ot_sequential_round_count: wireProfile.ot_sequential_round_count,
          other_control_payload_bytes: wireProfile.other_control_payload_bytes,
          table_transport_bytes: wireProfile.table_transport_bytes,
          envelope_header_bytes: wireProfile.envelope_header_bytes,
          total_ab_transport_bytes: wireProfile.total_ab_transport_bytes,
        }),
      ),
      passedCheck('PHASE13A_LOCAL_COMPUTE', localCompute),
      passedCheck('PHASE13A_LOCAL_ISOLATION', isolation),
      passedCheck('PHASE13A_LOCAL_CEREMONY_P95_MS', benchmark.client_wall_p95_ms),
      passedCheck('PHASE13A_LOCAL_CEREMONY_P99_MS', benchmark.client_wall_p99_ms),
      passedCheck('PHASE13A_LOCAL_VALIDATION_MATRIX', root.validation.command),
      passedCheck(
        'PHASE13A_LOCAL_CORE_CORRECTNESS',
        Object.freeze({
          rust_tests: root.validation.core_passive_rust_tests,
          python_tests: root.validation.independent_python_tests,
          differential_cases: root.validation.deterministic_differential_cases,
          wasm_stream_profiles: root.validation.wasm_stream_profiles,
          wasm_stream_modes: root.validation.wasm_stream_modes,
          formal_parity_production_rust_tests: root.validation.formal_parity_production_rust_tests,
          formal_parity_generator_rust_tests: root.validation.formal_parity_generator_rust_tests,
          formal_parity_circuit_rust_tests: root.validation.formal_parity_circuit_rust_tests,
          formal_parity_artifact_filesystem_tests:
            root.validation.formal_parity_artifact_filesystem_tests,
        }),
      ),
      passedCheck('PHASE13A_LOCAL_SECRET_INGRESS_DISPOSAL', root.incoming_secret_buffer_disposal),
    ]),
    deployed_evidence_unavailable: Object.freeze([...REQUIRED_DEPLOYED_EVIDENCE]),
  });
}

function failedResult(error) {
  return Object.freeze({
    evaluator: 'phase13a-local-preflight-v1',
    status: 'failed',
    phase13a_decision: 'unavailable',
    production_eligible: false,
    error_code:
      error instanceof LocalPreflightError ? error.code : 'PHASE13A_LOCAL_PREFLIGHT_FAILURE',
    error_field: error instanceof LocalPreflightError ? error.field : 'unknown',
  });
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

function main() {
  try {
    const result = evaluateLocalPreflight(loadLocalEvidence(), loadWorkspaceArtifact);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify(failedResult(error), null, 2)}\n`);
    process.exitCode = 2;
  }
}

if (isMainModule()) {
  main();
}
