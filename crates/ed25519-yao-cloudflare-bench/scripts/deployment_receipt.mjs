import { existsSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join } from 'node:path';

import { BoundaryError } from './deployment_boundary.mjs';

const MAX_RECEIPT_BYTES = 64 * 1024;
const DEPLOYMENT_ID_PATTERN = /^[0-9a-f]{32}$/;
const VERSION_ID_PATTERN = /^[A-Za-z0-9-]{8,128}$/;
const WORKER_TAG_PATTERN = /^[A-Za-z0-9-]{8,128}$/;
const SEMVER_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/;
const ARTIFACT_FILES = Object.freeze([
  'index.js',
  'index_bg.wasm',
  'package.json',
  'worker/shim.mjs',
]);

function fail(message) {
  throw new BoundaryError(message);
}

function exactIsoInstant(value, field) {
  if (
    typeof value !== 'string' ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    fail(`${field} must be a canonical UTC instant`);
  }
  return value;
}

export function parseDeploymentId(value) {
  if (typeof value !== 'string' || !DEPLOYMENT_ID_PATTERN.test(value) || /^0+$/.test(value)) {
    fail('benchmark deployment ID must be 16 nonzero lowercase hexadecimal bytes');
  }
  return value;
}

export function deploymentReceiptPath(environment) {
  const path = environment.YAOS_AB_DEPLOYMENT_RECEIPT_PATH;
  if (
    typeof path !== 'string' ||
    !isAbsolute(path) ||
    !path.endsWith('.json') ||
    /[\r\n\0]/.test(path)
  ) {
    fail('YAOS_AB_DEPLOYMENT_RECEIPT_PATH must be an absolute JSON path');
  }
  return path;
}

function parseOutputLines(raw) {
  const entries = [];
  for (const line of raw.split('\n')) {
    if (line.trim().length === 0) {
      continue;
    }
    try {
      entries.push(JSON.parse(line));
    } catch {
      fail('Wrangler output receipt contains invalid JSONL');
    }
  }
  return entries;
}

function matchingEntries(entries, type) {
  const matches = [];
  for (const entry of entries) {
    if (entry?.type === type) {
      matches.push(entry);
    }
  }
  return matches;
}

function validatedTargets(raw) {
  if (!Array.isArray(raw) || raw.length === 0) {
    fail('Wrangler deployment receipt has no targets');
  }
  const targets = [];
  for (const value of raw) {
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      fail('Wrangler deployment receipt has an invalid target');
    }
    if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '') {
      fail('Wrangler deployment receipt target must use HTTPS');
    }
    targets.push(parsed.href);
  }
  return Object.freeze(targets);
}

export function parseWranglerDeploymentOutput(raw, expectedScriptName) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_RECEIPT_BYTES) {
    fail('Wrangler deployment output has an invalid size');
  }
  const entries = parseOutputLines(raw);
  const sessions = matchingEntries(entries, 'wrangler-session');
  const deployments = matchingEntries(entries, 'deploy');
  if (sessions.length !== 1 || deployments.length !== 1) {
    fail('Wrangler deployment output must contain one session and one deployment');
  }
  const session = sessions[0];
  const deployment = deployments[0];
  if (
    typeof session.wrangler_version !== 'string' ||
    !SEMVER_PATTERN.test(session.wrangler_version)
  ) {
    fail('Wrangler deployment output has an invalid Wrangler version');
  }
  if (
    deployment.worker_name !== expectedScriptName ||
    deployment.worker_name_overridden !== false
  ) {
    fail('Wrangler deployment output has an unexpected Worker identity');
  }
  if (
    typeof deployment.version_id !== 'string' ||
    !VERSION_ID_PATTERN.test(deployment.version_id)
  ) {
    fail('Wrangler deployment output has an invalid version ID');
  }
  if (
    typeof deployment.worker_tag !== 'string' ||
    !WORKER_TAG_PATTERN.test(deployment.worker_tag)
  ) {
    fail('Wrangler deployment output has an invalid Worker tag');
  }
  return Object.freeze({
    script_name: expectedScriptName,
    wrangler_version: session.wrangler_version,
    worker_tag: deployment.worker_tag,
    version_id: deployment.version_id,
    targets: validatedTargets(deployment.targets),
    deployed_at: exactIsoInstant(deployment.timestamp, 'deployment timestamp'),
  });
}

function parseSha256(value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function accountCommitment(accountId) {
  return createHash('sha256')
    .update('ed25519-yao-phase9b-cloudflare-account-v1\0')
    .update(accountId)
    .digest('hex');
}

function topologyBinding(configuration) {
  const common = {
    a_account_sha256: accountCommitment(configuration.a.accountId),
    b_account_sha256: accountCommitment(configuration.b.accountId),
    a_public_hostname: configuration.a.publicHostname,
  };
  if (configuration.topology === 'one-account') {
    return {
      schema: 'ed25519_yao_phase9b_topology_binding_v1',
      kind: 'same-account-service-binding',
      ...common,
      b_service_name: configuration.b.scriptName,
    };
  }
  return {
    schema: 'ed25519_yao_phase9b_topology_binding_v1',
    kind: 'cross-account-websocket',
    ...common,
    b_public_hostname: configuration.b.publicHostname,
  };
}

function validateTopologyBinding(binding, configuration) {
  const expected = topologyBinding(configuration);
  if (
    binding === null ||
    typeof binding !== 'object' ||
    Array.isArray(binding) ||
    binding.schema !== expected.schema ||
    binding.kind !== expected.kind ||
    binding.a_account_sha256 !== expected.a_account_sha256 ||
    binding.b_account_sha256 !== expected.b_account_sha256 ||
    binding.a_public_hostname !== expected.a_public_hostname
  ) {
    fail('deployment receipt topology binding does not match the benchmark configuration');
  }
  if (
    (expected.kind === 'same-account-service-binding' &&
      binding.b_service_name !== expected.b_service_name) ||
    (expected.kind === 'cross-account-websocket' &&
      binding.b_public_hostname !== expected.b_public_hostname)
  ) {
    fail('deployment receipt topology binding does not match the benchmark configuration');
  }
}

export function initialDeploymentReceipt(
  configuration,
  deploymentId,
  recordedAt,
  localReadinessBundleSha256,
) {
  return {
    schema: 'ed25519_yao_phase9b_deployment_receipt_v4',
    benchmark: 'phase9b-cloudflare-activation-128kib',
    benchmark_only: true,
    security_claim: 'none',
    status: 'deploying',
    topology: configuration.expectedTopologyLabel,
    region_label: configuration.regionLabel,
    deployment_id: parseDeploymentId(deploymentId),
    recorded_at: exactIsoInstant(recordedAt, 'recorded_at'),
    local_readiness_bundle_sha256: parseSha256(
      localReadinessBundleSha256,
      'local_readiness_bundle_sha256',
    ),
    topology_binding: topologyBinding(configuration),
    constant_time_codegen: null,
    roles: {
      a: { script_name: configuration.a.scriptName, deployment: null, artifact: null },
      b: { script_name: configuration.b.scriptName, deployment: null, artifact: null },
    },
  };
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function collectArtifactEvidence(directory) {
  const files = [];
  const aggregate = createHash('sha256');
  for (const path of ARTIFACT_FILES) {
    let bytes;
    try {
      bytes = readFileSync(join(directory, path));
    } catch {
      fail(`deployment artifact is missing ${path}`);
    }
    const digest = sha256(bytes);
    files.push(Object.freeze({ path, bytes: bytes.length, sha256: digest }));
    aggregate.update(path);
    aggregate.update('\0');
    aggregate.update(String(bytes.length));
    aggregate.update('\0');
    aggregate.update(digest);
    aggregate.update('\0');
  }
  return Object.freeze({
    schema: 'ed25519_yao_worker_artifact_digest_v1',
    sha256: aggregate.digest('hex'),
    files: Object.freeze(files),
  });
}

export function assertArtifactEvidenceEqual(expected, observed, field) {
  validateArtifactEvidence(expected, `${field}.expected`);
  validateArtifactEvidence(observed, `${field}.observed`);
  if (expected.sha256 !== observed.sha256) {
    fail(`${field} changed after constant-time inspection`);
  }
  for (let index = 0; index < ARTIFACT_FILES.length; index += 1) {
    const left = expected.files[index];
    const right = observed.files[index];
    if (left.path !== right.path || left.bytes !== right.bytes || left.sha256 !== right.sha256) {
      fail(`${field}.${left.path} changed after constant-time inspection`);
    }
  }
}

export function attachRoleArtifact(receipt, role, artifact) {
  const record = receipt.roles[role];
  if (record === undefined || record.artifact !== null) {
    fail('deployment receipt artifact transition is invalid');
  }
  validateArtifactEvidence(artifact, `roles.${role}.artifact`);
  record.artifact = artifact;
}

export function attachRoleDeployment(receipt, role, rawOutput) {
  const record = receipt.roles[role];
  if (record === undefined || record.deployment !== null) {
    fail('deployment receipt role transition is invalid');
  }
  record.deployment = parseWranglerDeploymentOutput(rawOutput, record.script_name);
}

function artifactFile(artifact, path) {
  return artifact.files.find((file) => file.path === path);
}

function validateConstantTimeCodegen(raw, receipt, field) {
  if (
    raw === null ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    raw.schema !== 'ed25519_yao_worker_constant_time_codegen_v1' ||
    raw.inspector !== 'llvm-objdump-secret-bit-branch-gate-v1' ||
    raw.result !== 'pass'
  ) {
    fail(`${field} is invalid`);
  }
  for (const role of ['a', 'b']) {
    const artifact = receipt.roles[role].artifact;
    const evidence = raw.roles?.[role];
    if (artifact === null || evidence === null || typeof evidence !== 'object') {
      fail(`${field}.roles.${role} is invalid`);
    }
    const wasm = artifactFile(artifact, 'index_bg.wasm');
    if (evidence.artifact_sha256 !== artifact.sha256 || evidence.wasm_sha256 !== wasm?.sha256) {
      fail(`${field}.roles.${role} does not match the deployment artifact`);
    }
  }
}

export function attachConstantTimeCodegen(receipt, inspection) {
  if (
    receipt.constant_time_codegen !== null ||
    receipt.roles.a.artifact === null ||
    receipt.roles.b.artifact === null
  ) {
    fail('deployment receipt constant-time transition is invalid');
  }
  const record = {
    schema: inspection.schema,
    inspector: inspection.inspector,
    result: inspection.result,
    roles: {
      a: {
        artifact_sha256: receipt.roles.a.artifact.sha256,
        wasm_sha256: inspection.roles?.a?.wasm_sha256,
      },
      b: {
        artifact_sha256: receipt.roles.b.artifact.sha256,
        wasm_sha256: inspection.roles?.b?.wasm_sha256,
      },
    },
  };
  validateConstantTimeCodegen(record, receipt, 'constant_time_codegen');
  receipt.constant_time_codegen = record;
}

export function completeDeploymentReceipt(receipt) {
  if (
    receipt.roles.a.deployment === null ||
    receipt.roles.b.deployment === null ||
    receipt.roles.a.artifact === null ||
    receipt.roles.b.artifact === null ||
    receipt.constant_time_codegen === null
  ) {
    fail('deployment receipt cannot complete without both roles');
  }
  receipt.status = 'deployed';
}

function validateArtifactEvidence(raw, field) {
  if (
    raw === null ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    raw.schema !== 'ed25519_yao_worker_artifact_digest_v1' ||
    typeof raw.sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/.test(raw.sha256) ||
    !Array.isArray(raw.files) ||
    raw.files.length !== ARTIFACT_FILES.length
  ) {
    fail(`${field} is invalid`);
  }
  const aggregate = createHash('sha256');
  for (let index = 0; index < ARTIFACT_FILES.length; index += 1) {
    const file = raw.files[index];
    if (
      file?.path !== ARTIFACT_FILES[index] ||
      !Number.isSafeInteger(file.bytes) ||
      file.bytes <= 0 ||
      typeof file.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(file.sha256)
    ) {
      fail(`${field}.files.${index} is invalid`);
    }
    aggregate.update(file.path);
    aggregate.update('\0');
    aggregate.update(String(file.bytes));
    aggregate.update('\0');
    aggregate.update(file.sha256);
    aggregate.update('\0');
  }
  if (aggregate.digest('hex') !== raw.sha256) {
    fail(`${field}.sha256 is inconsistent`);
  }
}

function validateRoleReceipt(raw, expectedScriptName, field) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    fail(`${field} is invalid`);
  }
  if (raw.script_name !== expectedScriptName) {
    fail(`${field} has an unexpected script name`);
  }
  if (raw.deployment !== null) {
    const deployment = raw.deployment;
    parseWranglerDeploymentOutput(
      `${JSON.stringify({
        type: 'wrangler-session',
        wrangler_version: deployment.wrangler_version,
      })}\n${JSON.stringify({
        type: 'deploy',
        worker_name: raw.script_name,
        worker_name_overridden: false,
        worker_tag: deployment.worker_tag,
        version_id: deployment.version_id,
        targets: deployment.targets,
        timestamp: deployment.deployed_at,
      })}\n`,
      expectedScriptName,
    );
  }
  if (raw.artifact !== null) {
    validateArtifactEvidence(raw.artifact, `${field}.artifact`);
  }
}

export function validateDeploymentReceipt(receipt, configuration, requireComplete) {
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    fail('deployment receipt is invalid');
  }
  if (
    receipt.schema !== 'ed25519_yao_phase9b_deployment_receipt_v4' ||
    receipt.benchmark !== 'phase9b-cloudflare-activation-128kib' ||
    receipt.benchmark_only !== true ||
    receipt.security_claim !== 'none' ||
    receipt.topology !== configuration.expectedTopologyLabel ||
    receipt.region_label !== configuration.regionLabel
  ) {
    fail('deployment receipt identity does not match the benchmark configuration');
  }
  parseDeploymentId(receipt.deployment_id);
  exactIsoInstant(receipt.recorded_at, 'recorded_at');
  parseSha256(receipt.local_readiness_bundle_sha256, 'local_readiness_bundle_sha256');
  validateTopologyBinding(receipt.topology_binding, configuration);
  validateRoleReceipt(receipt.roles?.a, configuration.a.scriptName, 'roles.a');
  validateRoleReceipt(receipt.roles?.b, configuration.b.scriptName, 'roles.b');
  if (receipt.constant_time_codegen !== null) {
    validateConstantTimeCodegen(receipt.constant_time_codegen, receipt, 'constant_time_codegen');
  }
  const complete =
    receipt.roles.a.deployment !== null &&
    receipt.roles.b.deployment !== null &&
    receipt.roles.a.artifact !== null &&
    receipt.roles.b.artifact !== null &&
    receipt.constant_time_codegen !== null;
  if (requireComplete && (receipt.status !== 'deployed' || !complete)) {
    fail('deployment receipt does not identify a complete deployment');
  }
  if (!requireComplete && receipt.status !== 'deploying' && receipt.status !== 'deployed') {
    fail('deployment receipt has an invalid lifecycle status');
  }
  return receipt;
}

function roleEvidence(role) {
  return Object.freeze({
    script_name: role.script_name,
    wrangler_version: role.deployment.wrangler_version,
    worker_tag: role.deployment.worker_tag,
    version_id: role.deployment.version_id,
    deployed_at: role.deployment.deployed_at,
    artifact_sha256: role.artifact.sha256,
  });
}

export function deploymentReceiptEvidence(receipt) {
  if (receipt.status !== 'deployed') {
    fail('only a complete deployment receipt can produce measurement evidence');
  }
  return Object.freeze({
    schema: receipt.schema,
    deployment_id: receipt.deployment_id,
    topology: receipt.topology,
    recorded_at: receipt.recorded_at,
    local_readiness_bundle_sha256: receipt.local_readiness_bundle_sha256,
    topology_binding: Object.freeze(receipt.topology_binding),
    constant_time_codegen: Object.freeze(receipt.constant_time_codegen),
    a: roleEvidence(receipt.roles.a),
    b: roleEvidence(receipt.roles.b),
  });
}

export function readDeploymentReceipt(path, configuration, requireComplete) {
  let size;
  try {
    size = statSync(path).size;
  } catch {
    fail('deployment receipt is unavailable');
  }
  if (size <= 0 || size > MAX_RECEIPT_BYTES) {
    fail('deployment receipt has an invalid size');
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    fail('deployment receipt is not valid JSON');
  }
  return validateDeploymentReceipt(parsed, configuration, requireComplete);
}

export function writeDeploymentReceipt(path, receipt, mustNotExist) {
  const temporaryPath = join(
    dirname(path),
    `.ed25519-yao-receipt-${process.pid}-${Date.now()}.tmp`,
  );
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(receipt, null, 2)}\n`, {
      mode: 0o600,
      flag: 'wx',
    });
    if (mustNotExist && existsSync(path)) {
      fail('deployment receipt path already exists');
    }
    renameSync(temporaryPath, path);
  } catch (error) {
    if (existsSync(temporaryPath)) {
      unlinkSync(temporaryPath);
    }
    throw error;
  }
}
