#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  assertFrontendApiCompatible,
  parseSupportedFrontendApiContractRange,
} from './deployment-api-compatibility.mjs';
import { parseAndVerifyReleaseSetManifest } from './deployment-release.mjs';

const TARGETS = new Set(['staging', 'production']);
const RECEIPT_MODES = new Set(['backend-deployment', 'frontend-only-no-op']);
const BACKEND_COMPONENTS = Object.freeze(
  ['gateway', 'router', 'deriver-a', 'deriver-b', 'signing-worker'].sort(),
);
const RECEIPT_FIELDS = Object.freeze([
  'acceptedSourceSha',
  'acceptedValidationRunId',
  'activeBackendReceiptRunId',
  'activeBackendSourceSha',
  'backendReleaseSetId',
  'createdAt',
  'deployedComponentDigests',
  'kind',
  'mode',
  'receiptDigestSha256',
  'receiptId',
  'receiptRunId',
  'schemaVersion',
  'selectedBackendComponents',
  'smokeResult',
  'supportedFrontendApiContractRange',
  'target',
]);
const INPUT_COMMON_FIELDS = Object.freeze([
  'acceptedSourceSha',
  'acceptedValidationRunId',
  'createdAt',
  'mode',
  'receiptRunId',
  'selectedBackendComponents',
  'target',
]);
const DEPLOYMENT_INPUT_FIELDS = Object.freeze([
  ...INPUT_COMMON_FIELDS,
  'backendArtifactRunId',
  'backendReleaseSetId',
  'backendReleaseSetManifest',
  'deployedComponentDigests',
  'smokeResult',
]);
const NO_OP_INPUT_FIELDS = Object.freeze([...INPUT_COMMON_FIELDS, 'previousActiveReceipt']);
const SMOKE_FIELDS = Object.freeze(['checks', 'completedAt', 'status']);
const SMOKE_CHECK_FIELDS = Object.freeze(['name', 'status']);
const DIGEST_FIELDS = Object.freeze(['component', 'digestSha256']);
const SOURCE_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/u;
const RUN_ID_PATTERN = /^[1-9][0-9]*$/u;
const RELEASE_SET_ID_PATTERN = /^rs_[0-9a-f]{64}$/u;
const CREATED_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

export const COORDINATION_RECEIPT_SCHEMA_VERSION = 1;
export const COORDINATION_RECEIPT_KIND = 'backend-coordination-receipt';
export { BACKEND_COMPONENTS };

export function createBackendCoordinationReceipt(input) {
  if (!isRecord(input) || typeof input.mode !== 'string') {
    throw new TypeError('backend coordination receipt input is invalid');
  }
  if (input.mode === 'backend-deployment') return createBackendDeploymentReceipt(input);
  if (input.mode === 'frontend-only-no-op') return createFrontendOnlyNoOpReceipt(input);
  throw new TypeError(`unsupported backend coordination receipt mode: ${input.mode}`);
}

export function parseBackendCoordinationReceipt(value) {
  assertExactKeys(value, RECEIPT_FIELDS, 'backend coordination receipt');
  if (
    !isRecord(value) ||
    value.schemaVersion !== COORDINATION_RECEIPT_SCHEMA_VERSION ||
    value.kind !== COORDINATION_RECEIPT_KIND ||
    typeof value.mode !== 'string' ||
    !RECEIPT_MODES.has(value.mode)
  ) {
    throw new TypeError('backend coordination receipt identity is invalid');
  }
  const common = parseCommonReceiptFields(value);
  const selectedBackendComponents = parseBackendComponents(value.selectedBackendComponents);
  const deployedComponentDigests = parseComponentDigests(value.deployedComponentDigests);
  const supportedFrontendApiContractRange = parseSupportedFrontendApiContractRange(
    value.supportedFrontendApiContractRange,
  );
  const smokeResult = parseSmokeResult(value.smokeResult);
  const receipt = deepFreeze({
    schemaVersion: COORDINATION_RECEIPT_SCHEMA_VERSION,
    kind: COORDINATION_RECEIPT_KIND,
    mode: value.mode,
    target: common.target,
    receiptRunId: common.receiptRunId,
    acceptedSourceSha: common.acceptedSourceSha,
    acceptedValidationRunId: common.acceptedValidationRunId,
    selectedBackendComponents,
    activeBackendSourceSha: parseSourceSha(
      value.activeBackendSourceSha,
      'active backend source SHA',
    ),
    activeBackendReceiptRunId: parseRunId(
      value.activeBackendReceiptRunId,
      'active backend receipt run ID',
    ),
    backendReleaseSetId: parseReleaseSetId(value.backendReleaseSetId),
    deployedComponentDigests,
    supportedFrontendApiContractRange,
    smokeResult,
    createdAt: common.createdAt,
    receiptDigestSha256: parseDigest(value.receiptDigestSha256, 'receipt digest'),
    receiptId: parseReceiptId(value.receiptId),
  });
  assertReceiptSemantics(receipt);
  assertReceiptDigest(receipt);
  return receipt;
}

export function assertBackendCoordinationReceiptMatches(value, expected) {
  const receipt = parseBackendCoordinationReceipt(value);
  assertExactKeys(
    expected,
    ['acceptedSourceSha', 'acceptedValidationRunId', 'receiptRunId', 'target'],
    'backend coordination receipt expectation',
  );
  if (
    receipt.target !== parseTarget(expected.target) ||
    receipt.acceptedSourceSha !==
      parseSourceSha(expected.acceptedSourceSha, 'expected source SHA') ||
    receipt.acceptedValidationRunId !==
      parseRunId(expected.acceptedValidationRunId, 'expected validation run ID') ||
    receipt.receiptRunId !== parseRunId(expected.receiptRunId, 'expected receipt run ID')
  ) {
    throw new Error('backend coordination receipt does not match expected deployment identity');
  }
  return receipt;
}

export function assertFrontendApiCompatibleWithBackendReceipt(receiptValue, frontendContractValue) {
  const receipt = parseBackendCoordinationReceipt(receiptValue);
  const compatibility = assertFrontendApiCompatible(
    frontendContractValue,
    receipt.supportedFrontendApiContractRange,
  );
  return deepFreeze({ receipt, compatibility });
}

async function main(args) {
  const options = parseOptions(args);
  const command = options.get('command');
  if (command === 'create') {
    await createFromFile(options);
    return;
  }
  if (command === 'verify') {
    await verifyFromFile(options);
    return;
  }
  throw new Error(
    'usage: deployment-coordination-receipt.mjs --command <create|verify> --input-file <file> --output <file>',
  );
}

async function createFromFile(options) {
  const input = await readJsonFile(requireOption(options, 'input-file'), 'receipt input');
  const receipt = createBackendCoordinationReceipt(input);
  const output = resolve(requireOption(options, 'output'));
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(receipt, null, 2)}\n`, 'utf8');
  process.stdout.write(`${receipt.receiptId}\n`);
}

async function verifyFromFile(options) {
  const receipt = parseBackendCoordinationReceipt(
    await readJsonFile(requireOption(options, 'receipt-file'), 'coordination receipt'),
  );
  if (options.has('expected-file')) {
    const expected = await readJsonFile(options.get('expected-file'), 'receipt expectation');
    assertBackendCoordinationReceiptMatches(receipt, expected);
  }
  process.stdout.write(`${receipt.receiptId}\n`);
}

function createBackendDeploymentReceipt(input) {
  assertExactKeys(input, DEPLOYMENT_INPUT_FIELDS, 'backend deployment receipt input');
  const common = parseInputCommon(input);
  const selectedBackendComponents = parseBackendComponents(input.selectedBackendComponents);
  if (selectedBackendComponents.length === 0) {
    throw new Error('backend deployment receipt must select at least one backend component');
  }
  const deployedComponentDigests = parseComponentDigests(input.deployedComponentDigests);
  assertDigestCoverage(selectedBackendComponents, deployedComponentDigests);
  const backendReleaseSetManifest = parseAndVerifyReleaseSetManifest(
    input.backendReleaseSetManifest,
  );
  assertBackendReleaseSetBinding({
    manifest: backendReleaseSetManifest,
    target: common.target,
    acceptedSourceSha: common.acceptedSourceSha,
    acceptedValidationRunId: common.acceptedValidationRunId,
    backendArtifactRunId: input.backendArtifactRunId,
    backendReleaseSetId: input.backendReleaseSetId,
    selectedBackendComponents,
    deployedComponentDigests,
  });
  const receipt = buildReceipt({
    target: common.target,
    receiptRunId: common.receiptRunId,
    acceptedSourceSha: common.acceptedSourceSha,
    acceptedValidationRunId: common.acceptedValidationRunId,
    createdAt: common.createdAt,
    mode: 'backend-deployment',
    selectedBackendComponents,
    activeBackendSourceSha: common.acceptedSourceSha,
    activeBackendReceiptRunId: common.receiptRunId,
    backendReleaseSetId: parseReleaseSetId(input.backendReleaseSetId),
    deployedComponentDigests,
    supportedFrontendApiContractRange: backendReleaseSetManifest.supportedFrontendApiContractRange,
    smokeResult: parseSmokeResult(input.smokeResult),
  });
  return parseBackendCoordinationReceipt(receipt);
}

function createFrontendOnlyNoOpReceipt(input) {
  assertExactKeys(input, NO_OP_INPUT_FIELDS, 'frontend-only coordination receipt input');
  const common = parseInputCommon(input);
  if (common.selectedBackendComponents.length !== 0) {
    throw new Error('frontend-only no-op receipt must select no backend components');
  }
  const previous = parseBackendCoordinationReceipt(input.previousActiveReceipt);
  if (previous.target !== common.target) {
    throw new Error('frontend-only no-op receipt target does not match active backend receipt');
  }
  if (previous.receiptRunId === common.receiptRunId) {
    throw new Error('frontend-only no-op receipt must have a new receipt run ID');
  }
  const receipt = buildReceipt({
    target: common.target,
    receiptRunId: common.receiptRunId,
    acceptedSourceSha: common.acceptedSourceSha,
    acceptedValidationRunId: common.acceptedValidationRunId,
    createdAt: common.createdAt,
    mode: 'frontend-only-no-op',
    selectedBackendComponents: common.selectedBackendComponents,
    activeBackendSourceSha: previous.activeBackendSourceSha,
    activeBackendReceiptRunId: previous.activeBackendReceiptRunId,
    backendReleaseSetId: previous.backendReleaseSetId,
    deployedComponentDigests: previous.deployedComponentDigests,
    supportedFrontendApiContractRange: previous.supportedFrontendApiContractRange,
    smokeResult: previous.smokeResult,
  });
  return parseBackendCoordinationReceipt(receipt);
}

function buildReceipt(input) {
  const payload = {
    schemaVersion: COORDINATION_RECEIPT_SCHEMA_VERSION,
    kind: COORDINATION_RECEIPT_KIND,
    mode: input.mode,
    target: input.target,
    receiptRunId: input.receiptRunId,
    acceptedSourceSha: input.acceptedSourceSha,
    acceptedValidationRunId: input.acceptedValidationRunId,
    selectedBackendComponents: input.selectedBackendComponents,
    activeBackendSourceSha: input.activeBackendSourceSha,
    activeBackendReceiptRunId: input.activeBackendReceiptRunId,
    backendReleaseSetId: input.backendReleaseSetId,
    deployedComponentDigests: input.deployedComponentDigests,
    supportedFrontendApiContractRange: input.supportedFrontendApiContractRange,
    smokeResult: input.smokeResult,
    createdAt: input.createdAt,
  };
  const receiptDigestSha256 = sha256(stableJson(payload));
  return {
    schemaVersion: payload.schemaVersion,
    kind: payload.kind,
    mode: payload.mode,
    target: payload.target,
    receiptRunId: payload.receiptRunId,
    acceptedSourceSha: payload.acceptedSourceSha,
    acceptedValidationRunId: payload.acceptedValidationRunId,
    selectedBackendComponents: payload.selectedBackendComponents,
    activeBackendSourceSha: payload.activeBackendSourceSha,
    activeBackendReceiptRunId: payload.activeBackendReceiptRunId,
    backendReleaseSetId: payload.backendReleaseSetId,
    deployedComponentDigests: payload.deployedComponentDigests,
    supportedFrontendApiContractRange: payload.supportedFrontendApiContractRange,
    smokeResult: payload.smokeResult,
    createdAt: payload.createdAt,
    receiptDigestSha256,
    receiptId: `bcr_${receiptDigestSha256}`,
  };
}

function parseInputCommon(input) {
  return {
    target: parseTarget(input.target),
    receiptRunId: parseRunId(input.receiptRunId, 'receipt run ID'),
    acceptedSourceSha: parseSourceSha(input.acceptedSourceSha, 'accepted source SHA'),
    acceptedValidationRunId: parseRunId(
      input.acceptedValidationRunId,
      'accepted validation run ID',
    ),
    selectedBackendComponents: parseBackendComponents(input.selectedBackendComponents),
    createdAt: parseCreatedAt(input.createdAt),
  };
}

function parseCommonReceiptFields(value) {
  return {
    target: parseTarget(value.target),
    receiptRunId: parseRunId(value.receiptRunId, 'receipt run ID'),
    acceptedSourceSha: parseSourceSha(value.acceptedSourceSha, 'accepted source SHA'),
    acceptedValidationRunId: parseRunId(
      value.acceptedValidationRunId,
      'accepted validation run ID',
    ),
    createdAt: parseCreatedAt(value.createdAt),
  };
}

function parseBackendComponents(value) {
  if (!Array.isArray(value) || value.some((component) => !BACKEND_COMPONENTS.includes(component))) {
    throw new TypeError('backend components must contain only supported component names');
  }
  const canonical = [...new Set(value)].sort();
  if (canonical.length !== value.length || stableJson(canonical) !== stableJson(value)) {
    throw new TypeError('backend components must be unique and sorted');
  }
  return deepFreeze(canonical);
}

function parseComponentDigests(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError('deployed component digests must be a non-empty array');
  }
  const parsed = [];
  for (const entry of value) {
    assertExactKeys(entry, DIGEST_FIELDS, 'deployed component digest');
    if (!isRecord(entry) || !BACKEND_COMPONENTS.includes(entry.component)) {
      throw new TypeError('deployed component digest component is invalid');
    }
    parsed.push({
      component: entry.component,
      digestSha256: parseDigest(entry.digestSha256, 'component digest'),
    });
  }
  const canonical = [...parsed].sort(compareComponentDigests);
  if (stableJson(canonical) !== stableJson(parsed)) {
    throw new TypeError('deployed component digests must be sorted by component');
  }
  const names = new Set(parsed.map(componentDigestName));
  if (names.size !== parsed.length) {
    throw new TypeError('deployed component digests must contain unique components');
  }
  return deepFreeze(canonical);
}

function parseSmokeResult(value) {
  assertExactKeys(value, SMOKE_FIELDS, 'backend smoke result');
  if (!isRecord(value) || value.status !== 'passed') {
    throw new TypeError('backend smoke result must have passed status');
  }
  if (!Array.isArray(value.checks) || value.checks.length === 0) {
    throw new TypeError('backend smoke result must contain checks');
  }
  const checks = [];
  for (const check of value.checks) {
    assertExactKeys(check, SMOKE_CHECK_FIELDS, 'backend smoke check');
    if (
      !isRecord(check) ||
      typeof check.name !== 'string' ||
      check.name.length === 0 ||
      !Number.isSafeInteger(check.status) ||
      check.status < 200 ||
      check.status >= 400
    ) {
      throw new TypeError('backend smoke check is invalid');
    }
    checks.push({ name: check.name, status: check.status });
  }
  const canonicalChecks = [...checks].sort(compareSmokeChecks);
  if (stableJson(canonicalChecks) !== stableJson(checks)) {
    throw new TypeError('backend smoke checks must be sorted by name');
  }
  const names = new Set(checks.map(smokeCheckName));
  if (names.size !== checks.length) throw new TypeError('backend smoke checks must be unique');
  return deepFreeze({
    status: 'passed',
    completedAt: parseCreatedAt(value.completedAt),
    checks: canonicalChecks,
  });
}

function assertDigestCoverage(selectedComponents, deployedComponentDigests) {
  const digestNames = new Set(deployedComponentDigests.map(componentDigestName));
  if (
    digestNames.size !== selectedComponents.length ||
    selectedComponents.some((component) => !digestNames.has(component))
  ) {
    throw new Error('deployed component digests must exactly cover selected backend components');
  }
}

function assertBackendReleaseSetBinding(input) {
  const manifest = input.manifest;
  if (
    manifest.lane !== 'backend' ||
    manifest.target !== input.target ||
    manifest.sourceSha !== input.acceptedSourceSha ||
    manifest.acceptedValidationRunId !== input.acceptedValidationRunId ||
    manifest.artifactRunId !== parseRunId(input.backendArtifactRunId, 'backend artifact run ID') ||
    manifest.releaseSetId !== parseReleaseSetId(input.backendReleaseSetId)
  ) {
    throw new Error(
      'backend coordination receipt is not bound to the verified backend release set',
    );
  }
  if (
    stableJson(manifest.buildIdentity.selectedComponents) !==
    stableJson(input.selectedBackendComponents)
  ) {
    throw new Error('backend coordination receipt components do not match the backend release set');
  }
  const digestByComponent = new Map(
    manifest.components.map((component) => [component.name, component.contentDigestSha256]),
  );
  for (const digest of input.deployedComponentDigests) {
    if (digestByComponent.get(digest.component) !== digest.digestSha256) {
      throw new Error(
        `backend coordination receipt digest does not match release set: ${digest.component}`,
      );
    }
  }
}

function assertReceiptSemantics(receipt) {
  if (receipt.mode === 'backend-deployment') {
    if (receipt.selectedBackendComponents.length === 0) {
      throw new Error('backend deployment receipt must select at least one backend component');
    }
    if (
      receipt.activeBackendSourceSha !== receipt.acceptedSourceSha ||
      receipt.activeBackendReceiptRunId !== receipt.receiptRunId
    ) {
      throw new Error('backend deployment receipt active identity is invalid');
    }
    assertDigestCoverage(receipt.selectedBackendComponents, receipt.deployedComponentDigests);
    return;
  }
  if (receipt.selectedBackendComponents.length !== 0) {
    throw new Error('frontend-only no-op receipt must select no backend components');
  }
  if (receipt.activeBackendReceiptRunId === receipt.receiptRunId) {
    throw new Error('frontend-only no-op receipt must reference a prior backend receipt');
  }
}

function assertReceiptDigest(receipt) {
  const payload = {
    schemaVersion: receipt.schemaVersion,
    kind: receipt.kind,
    mode: receipt.mode,
    target: receipt.target,
    receiptRunId: receipt.receiptRunId,
    acceptedSourceSha: receipt.acceptedSourceSha,
    acceptedValidationRunId: receipt.acceptedValidationRunId,
    selectedBackendComponents: receipt.selectedBackendComponents,
    activeBackendSourceSha: receipt.activeBackendSourceSha,
    activeBackendReceiptRunId: receipt.activeBackendReceiptRunId,
    backendReleaseSetId: receipt.backendReleaseSetId,
    deployedComponentDigests: receipt.deployedComponentDigests,
    supportedFrontendApiContractRange: receipt.supportedFrontendApiContractRange,
    smokeResult: receipt.smokeResult,
    createdAt: receipt.createdAt,
  };
  const expectedDigest = sha256(stableJson(payload));
  if (receipt.receiptDigestSha256 !== expectedDigest) {
    throw new Error('backend coordination receipt digest mismatch');
  }
  if (receipt.receiptId !== `bcr_${expectedDigest}`) {
    throw new Error('backend coordination receipt ID does not match digest');
  }
}

function parseTarget(value) {
  if (typeof value !== 'string' || !TARGETS.has(value)) {
    throw new TypeError(`unsupported deployment target: ${value}`);
  }
  return value;
}

function parseSourceSha(value, label) {
  if (typeof value !== 'string' || !SOURCE_SHA_PATTERN.test(value)) {
    throw new TypeError(`${label} must be exactly 40 lowercase hexadecimal characters`);
  }
  return value;
}

function parseRunId(value, label) {
  if (typeof value !== 'string' || !RUN_ID_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a positive decimal GitHub Actions run ID`);
  }
  return value;
}

function parseReleaseSetId(value) {
  if (typeof value !== 'string' || !RELEASE_SET_ID_PATTERN.test(value)) {
    throw new TypeError(
      'backend release-set ID must be rs_ followed by 64 lowercase hexadecimal characters',
    );
  }
  return value;
}

function parseDigest(value, label) {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${label} must be 64 lowercase hexadecimal characters`);
  }
  return value;
}

function parseReceiptId(value) {
  if (typeof value !== 'string' || !/^bcr_[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError('coordination receipt ID is invalid');
  }
  return value;
}

function parseCreatedAt(value) {
  if (
    typeof value !== 'string' ||
    !CREATED_AT_PATTERN.test(value) ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new TypeError('receipt timestamp must be an ISO-8601 UTC timestamp with milliseconds');
  }
  return value;
}

function assertExactKeys(value, expectedKeys, label) {
  if (!isRecord(value)) throw new TypeError(`${label} is invalid`);
  const actualKeys = Object.keys(value).sort();
  const canonicalExpectedKeys = [...expectedKeys].sort();
  if (actualKeys.length !== canonicalExpectedKeys.length) {
    throw new TypeError(`${label} fields are invalid`);
  }
  for (let index = 0; index < actualKeys.length; index += 1) {
    if (actualKeys[index] !== canonicalExpectedKeys[index]) {
      throw new TypeError(`${label} fields are invalid`);
    }
  }
}

function compareComponentDigests(left, right) {
  return left.component.localeCompare(right.component);
}

function compareSmokeChecks(left, right) {
  return left.name.localeCompare(right.name);
}

function componentDigestName(value) {
  return value.component;
}

function smokeCheckName(value) {
  return value.name;
}

function stableJson(value) {
  return JSON.stringify(sortJson(value));
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (isRecord(value)) {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = sortJson(value[key]);
    return sorted;
  }
  return value;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze(value) {
  if (!isRecord(value) && !Array.isArray(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function readJsonFile(filePath, label) {
  try {
    return JSON.parse(await readFile(resolve(filePath), 'utf8'));
  } catch (error) {
    throw new Error(
      `${label} could not be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function parseOptions(args) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith('--') || value === undefined || value.startsWith('--')) {
      throw new Error(`invalid argument: ${name ?? '<missing>'}`);
    }
    options.set(name.slice(2), value);
  }
  return options;
}

function requireOption(options, name) {
  const value = options.get(name);
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

if (isMainModule()) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

function isMainModule() {
  return (
    process.argv[1] !== undefined &&
    resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)
  );
}
