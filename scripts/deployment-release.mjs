#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

import { readMigrationSet } from './migration-fingerprint.mjs';

const SCHEMA_VERSION = 1;
const TARGETS = new Set(['staging', 'production']);
const COMPONENT_KINDS = new Set([
  'router',
  'deriver-a',
  'deriver-b',
  'signing-worker',
  'gateway-wasm',
  'pages',
  'sdk-r2',
]);
const COMPONENT_NAMES = new Set([
  'router',
  'deriver-a',
  'deriver-b',
  'signing-worker',
  'gateway',
  'site',
  'signer-iframe',
]);
const COMPONENT_NAME_BY_KIND = new Map([
  ['router', 'router'],
  ['deriver-a', 'deriver-a'],
  ['deriver-b', 'deriver-b'],
  ['signing-worker', 'signing-worker'],
  ['gateway-wasm', 'gateway'],
  ['pages', 'site'],
  ['sdk-r2', 'signer-iframe'],
]);
const COMPONENT_KIND_ORDER = Object.freeze([
  'router',
  'deriver-a',
  'deriver-b',
  'signing-worker',
  'gateway-wasm',
  'pages',
  'sdk-r2',
]);
const COMPONENT_KIND_INDEX = buildComponentKindIndex();
const COMPONENT_FIELDS = Object.freeze([
  'name',
  'kind',
  'artifactName',
  'contentDigestSha256',
  'sourceSha',
  'target',
  'releaseId',
]);
const IMMUTABLE_RELEASE_SET_FIELDS = Object.freeze([
  'schemaVersion',
  'target',
  'sourceSha',
  'acceptedValidationRunId',
  'artifactRunId',
  'createdAt',
  'buildIdentity',
  'migrationSets',
  'components',
]);
const DERIVED_RELEASE_SET_FIELDS = Object.freeze(['manifestDigestSha256', 'releaseSetId']);
const SOURCE_SHA_PATTERN = /^[a-f0-9]{40}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const RUN_ID_PATTERN = /^[1-9][0-9]*$/u;
const RELEASE_SET_ID_PATTERN = /^rs_[a-f0-9]{64}$/u;
const COMPONENT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const ARTIFACT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const RELEASE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const CREATED_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

await main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});

async function main(args) {
  const [commandName, ...rawArgs] = args;
  const commandOptions = parseOptions(rawArgs, allowedOptions(commandName));
  switch (commandName) {
    case 'create':
      await createReleaseSet(commandOptions);
      return;
    case 'verify':
      await verifyReleaseSet(commandOptions);
      return;
    case 'verify-component':
      await verifyComponent(commandOptions);
      return;
    case 'migration-fingerprint':
      await printMigrationFingerprint(commandOptions);
      return;
    default:
      throw new Error(
        'usage: deployment-release.mjs <create|verify|verify-component|migration-fingerprint> [options]',
      );
  }
}

async function verifyComponent(options) {
  const manifest = parseManifest(
    await readJsonFile(requireOption(options, 'manifest'), 'release-set manifest'),
  );
  const componentName = requireOption(options, 'component-name');
  const component = manifest.components.find((value) => value.name === componentName);
  if (component === undefined)
    throw new Error(`release-set component is missing: ${componentName}`);
  const artifact = await readJsonFile(
    requireOption(options, 'artifact-manifest'),
    'deployment artifact manifest',
  );
  if (
    !isRecord(artifact) ||
    artifact.kind !== component.kind ||
    artifact.target !== component.target ||
    artifact.sourceSha !== component.sourceSha ||
    artifact.contentDigestSha256 !== component.contentDigestSha256
  ) {
    throw new Error(`release-set component artifact mismatch: ${componentName}`);
  }
  process.stdout.write(`verified release-set component ${componentName}\n`);
}

async function createReleaseSet(options) {
  const target = parseTarget(requireOption(options, 'target'));
  const sourceSha = parseSourceSha(requireOption(options, 'source-sha'));
  const acceptedValidationRunId = parseRunId(
    requireOption(options, 'accepted-validation-run-id'),
    'accepted validation run ID',
  );
  const artifactRunId = parseRunId(requireOption(options, 'artifact-run-id'), 'artifact run ID');
  const components = await readComponents(requireOption(options, 'components-file'));
  assertComponentMappings(components, target, sourceSha);
  const migrationSets = await readMigrationSets(options.get('migrations-file'));
  const createdAt = parseCreatedAt(options.get('created-at') ?? new Date().toISOString());
  const buildIdentity = parseJsonObject(
    await readJsonFile(requireOption(options, 'build-identity-file'), 'build identity'),
    'build identity',
  );
  assertSelectedComponentTopology(buildIdentity, components);
  const base = buildManifestBase({
    target,
    sourceSha,
    acceptedValidationRunId,
    artifactRunId,
    createdAt,
    buildIdentity,
    migrationSets,
    components,
  });
  const manifestDigestSha256 = sha256(stableJson(base));
  const manifest = {
    schemaVersion: base.schemaVersion,
    target: base.target,
    sourceSha: base.sourceSha,
    acceptedValidationRunId: base.acceptedValidationRunId,
    artifactRunId: base.artifactRunId,
    createdAt: base.createdAt,
    buildIdentity: base.buildIdentity,
    migrationSets: base.migrationSets,
    components: base.components,
    manifestDigestSha256,
    releaseSetId: releaseSetIdForDigest(manifestDigestSha256),
  };
  const output = requireOption(options, 'output');
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  printSummary('created', manifest);
}

async function verifyReleaseSet(options) {
  const manifest = parseManifest(
    await readJsonFile(requireOption(options, 'manifest'), 'release-set manifest'),
  );
  const expectedDigest = sha256(stableJson(manifestBase(manifest)));
  if (manifest.manifestDigestSha256 !== expectedDigest) {
    throw new Error('release-set manifest digest mismatch');
  }
  const expectedTargetOption = options.get('target');
  if (expectedTargetOption !== undefined) {
    const expectedTarget = parseTarget(expectedTargetOption);
    if (manifest.target !== expectedTarget) {
      throw new Error(
        `release-set target mismatch: expected ${expectedTarget}, received ${manifest.target}`,
      );
    }
  }
  const expectedSourceShaOption = options.get('source-sha');
  if (expectedSourceShaOption !== undefined) {
    const expectedSourceSha = parseSourceSha(expectedSourceShaOption);
    if (manifest.sourceSha !== expectedSourceSha) {
      throw new Error(
        `release-set source SHA mismatch: expected ${expectedSourceSha}, received ${manifest.sourceSha}`,
      );
    }
  }
  const expectedValidationRunIdOption = options.get('accepted-validation-run-id');
  if (expectedValidationRunIdOption !== undefined) {
    const expectedValidationRunId = parseRunId(
      expectedValidationRunIdOption,
      'accepted validation run ID',
    );
    if (manifest.acceptedValidationRunId !== expectedValidationRunId) {
      throw new Error(
        `release-set validation run mismatch: expected ${expectedValidationRunId}, received ${manifest.acceptedValidationRunId}`,
      );
    }
  }
  const expectedArtifactRunIdOption = options.get('artifact-run-id');
  if (expectedArtifactRunIdOption !== undefined) {
    const expectedArtifactRunId = parseRunId(expectedArtifactRunIdOption, 'artifact run ID');
    if (manifest.artifactRunId !== expectedArtifactRunId) {
      throw new Error(
        `release-set artifact run mismatch: expected ${expectedArtifactRunId}, received ${manifest.artifactRunId}`,
      );
    }
  }
  const expectedReleaseSetIdOption = options.get('release-set-id');
  if (expectedReleaseSetIdOption !== undefined) {
    const expectedReleaseSetId = parseReleaseSetId(expectedReleaseSetIdOption);
    if (manifest.releaseSetId !== expectedReleaseSetId) {
      throw new Error(
        `release-set ID mismatch: expected ${expectedReleaseSetId}, received ${manifest.releaseSetId}`,
      );
    }
  }
  if (manifest.releaseSetId !== releaseSetIdForDigest(expectedDigest)) {
    throw new Error('release-set ID does not match manifest digest');
  }
  assertComponentMappings(manifest.components, manifest.target, manifest.sourceSha);
  printSummary('verified', manifest);
}

async function printMigrationFingerprint(options) {
  const database = requireOption(options, 'database');
  const migrationsDir = requireOption(options, 'migrations-dir');
  const format = options.get('format');
  if (format !== undefined && format !== 'json') {
    throw new Error(`unsupported migration fingerprint format: ${format}`);
  }
  const migrationSet = readMigrationSet(migrationsDir);
  if (format === 'json') {
    process.stdout.write(`${JSON.stringify({ database, ...migrationSet })}\n`);
    return;
  }
  process.stdout.write(`${migrationSet.fingerprint}\n`);
}

async function readComponents(path) {
  const value = await readJsonFile(path, 'release-set components');
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('release-set components must be a non-empty array');
  }
  return canonicalizeComponents(value.map(parseComponent));
}

async function readMigrationSets(path) {
  if (path === undefined) return {};
  return parseJsonObject(
    await readJsonFile(path, 'release-set migration sets'),
    'release-set migration sets',
  );
}

async function readJsonFile(path, label) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(
      `failed to read ${label}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function parseComponent(value) {
  assertExactKeys(value, COMPONENT_FIELDS, 'release-set component');
  if (
    !isRecord(value) ||
    typeof value.name !== 'string' ||
    !COMPONENT_NAME_PATTERN.test(value.name) ||
    typeof value.kind !== 'string' ||
    !COMPONENT_KINDS.has(value.kind) ||
    typeof value.artifactName !== 'string' ||
    !ARTIFACT_NAME_PATTERN.test(value.artifactName) ||
    typeof value.contentDigestSha256 !== 'string' ||
    !DIGEST_PATTERN.test(value.contentDigestSha256) ||
    typeof value.sourceSha !== 'string' ||
    !SOURCE_SHA_PATTERN.test(value.sourceSha) ||
    typeof value.target !== 'string' ||
    !TARGETS.has(value.target) ||
    typeof value.releaseId !== 'string' ||
    !RELEASE_ID_PATTERN.test(value.releaseId)
  ) {
    throw new Error('release-set component record is invalid');
  }
  return {
    name: value.name,
    kind: value.kind,
    artifactName: value.artifactName,
    contentDigestSha256: value.contentDigestSha256,
    sourceSha: value.sourceSha,
    target: value.target,
    releaseId: value.releaseId,
  };
}

function parseManifest(value) {
  const expectedFields = [...IMMUTABLE_RELEASE_SET_FIELDS, ...DERIVED_RELEASE_SET_FIELDS];
  assertExactKeys(value, expectedFields, 'release-set manifest');
  if (
    !isRecord(value) ||
    value.schemaVersion !== SCHEMA_VERSION ||
    typeof value.target !== 'string' ||
    !TARGETS.has(value.target) ||
    typeof value.sourceSha !== 'string' ||
    !SOURCE_SHA_PATTERN.test(value.sourceSha) ||
    typeof value.acceptedValidationRunId !== 'string' ||
    !RUN_ID_PATTERN.test(value.acceptedValidationRunId) ||
    typeof value.artifactRunId !== 'string' ||
    !RUN_ID_PATTERN.test(value.artifactRunId) ||
    typeof value.createdAt !== 'string' ||
    !isCanonicalCreatedAt(value.createdAt) ||
    !isRecord(value.buildIdentity) ||
    !isRecord(value.migrationSets) ||
    !Array.isArray(value.components) ||
    value.components.length === 0 ||
    typeof value.manifestDigestSha256 !== 'string' ||
    !DIGEST_PATTERN.test(value.manifestDigestSha256) ||
    typeof value.releaseSetId !== 'string' ||
    !RELEASE_SET_ID_PATTERN.test(value.releaseSetId)
  ) {
    throw new Error('release-set manifest is invalid');
  }
  const components = value.components.map(parseComponent);
  const canonicalComponents = canonicalizeComponents(components);
  if (stableJson(components) !== stableJson(canonicalComponents)) {
    throw new Error('release-set components are not in canonical order');
  }
  assertUniqueComponents(components);
  const buildIdentity = parseJsonObject(value.buildIdentity, 'build identity');
  const migrationSets = parseJsonObject(value.migrationSets, 'release-set migration sets');
  assertSelectedComponentTopology(buildIdentity, components);
  return {
    schemaVersion: SCHEMA_VERSION,
    target: value.target,
    sourceSha: value.sourceSha,
    acceptedValidationRunId: value.acceptedValidationRunId,
    artifactRunId: value.artifactRunId,
    createdAt: value.createdAt,
    buildIdentity: sortValue(buildIdentity),
    migrationSets: sortValue(migrationSets),
    components,
    manifestDigestSha256: value.manifestDigestSha256,
    releaseSetId: value.releaseSetId,
  };
}

function assertSelectedComponentTopology(buildIdentity, components) {
  const selectedComponents = buildIdentity.selectedComponents;
  if (
    !Array.isArray(selectedComponents) ||
    selectedComponents.length === 0 ||
    selectedComponents.some(
      (component) => typeof component !== 'string' || !COMPONENT_NAMES.has(component),
    )
  ) {
    throw new Error('build identity selectedComponents is invalid');
  }
  const canonicalSelectedComponents = [...new Set(selectedComponents)].sort(compareStrings);
  if (
    canonicalSelectedComponents.length !== selectedComponents.length ||
    stableJson(selectedComponents) !== stableJson(canonicalSelectedComponents)
  ) {
    throw new Error('build identity selectedComponents must be unique and sorted');
  }
  if (selectedComponents.includes('router')) {
    for (const role of ['router', 'deriver-a', 'deriver-b', 'signing-worker']) {
      if (!selectedComponents.includes(role)) {
        throw new Error(`build identity Router topology is incomplete: ${role}`);
      }
    }
  }
  if (selectedComponents.includes('signer-iframe') && !selectedComponents.includes('site')) {
    throw new Error('build identity Pages topology is incomplete: site');
  }
  const componentNames = components
    .map((component) => COMPONENT_NAME_BY_KIND.get(component.kind) ?? component.name)
    .sort(compareStrings);
  if (stableJson(componentNames) !== stableJson(selectedComponents)) {
    throw new Error('build identity selectedComponents do not match release-set components');
  }
}

function buildManifestBase(input) {
  return {
    schemaVersion: SCHEMA_VERSION,
    target: input.target,
    sourceSha: input.sourceSha,
    acceptedValidationRunId: input.acceptedValidationRunId,
    artifactRunId: input.artifactRunId,
    createdAt: input.createdAt,
    buildIdentity: sortValue(input.buildIdentity),
    migrationSets: sortValue(input.migrationSets),
    components: canonicalizeComponents(input.components),
  };
}

function manifestBase(manifest) {
  return {
    schemaVersion: manifest.schemaVersion,
    target: manifest.target,
    sourceSha: manifest.sourceSha,
    acceptedValidationRunId: manifest.acceptedValidationRunId,
    artifactRunId: manifest.artifactRunId,
    createdAt: manifest.createdAt,
    buildIdentity: manifest.buildIdentity,
    migrationSets: manifest.migrationSets,
    components: manifest.components,
  };
}

function canonicalizeComponents(components) {
  const canonical = [...components].sort(compareComponents);
  assertUniqueComponents(canonical);
  return canonical;
}

function compareComponents(left, right) {
  const kindOrder = COMPONENT_KIND_INDEX.get(left.kind) - COMPONENT_KIND_INDEX.get(right.kind);
  if (kindOrder !== 0) return kindOrder;
  return compareStrings(left.name, right.name);
}

function assertUniqueComponents(components) {
  const names = new Set();
  const kinds = new Set();
  const artifactNames = new Set();
  for (const component of components) {
    if (names.has(component.name)) {
      throw new Error(`duplicate release-set component name: ${component.name}`);
    }
    if (kinds.has(component.kind)) {
      throw new Error(`duplicate release-set component kind: ${component.kind}`);
    }
    if (artifactNames.has(component.artifactName)) {
      throw new Error(`duplicate release-set artifact name: ${component.artifactName}`);
    }
    names.add(component.name);
    kinds.add(component.kind);
    artifactNames.add(component.artifactName);
  }
}

function assertComponentMappings(components, target, sourceSha) {
  for (const component of components) {
    if (component.sourceSha !== sourceSha || component.target !== target) {
      throw new Error(`release-set component mapping is invalid: ${component.name}`);
    }
  }
}

function parseTarget(value) {
  if (!TARGETS.has(value)) throw new Error(`unsupported release-set target: ${value}`);
  return value;
}

function parseSourceSha(value) {
  if (!SOURCE_SHA_PATTERN.test(value)) {
    throw new Error('release-set source SHA must be exactly 40 lowercase hexadecimal characters');
  }
  return value;
}

function parseRunId(value, label) {
  if (!RUN_ID_PATTERN.test(value)) {
    throw new Error(`${label} must be a positive decimal GitHub Actions run ID`);
  }
  return value;
}

function parseReleaseSetId(value) {
  if (!RELEASE_SET_ID_PATTERN.test(value)) {
    throw new Error('release-set ID must be rs_ followed by 64 lowercase hexadecimal characters');
  }
  return value;
}

function parseCreatedAt(value) {
  if (!isCanonicalCreatedAt(value)) {
    throw new Error('release-set createdAt must be an ISO-8601 UTC timestamp with milliseconds');
  }
  return value;
}

function isCanonicalCreatedAt(value) {
  return (
    typeof value === 'string' &&
    CREATED_AT_PATTERN.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function parseJsonObject(value, label) {
  if (!isRecord(value)) throw new Error(`${label} must be a JSON object`);
  assertJsonValue(value, label);
  return value;
}

function assertJsonValue(value, label) {
  if (Array.isArray(value)) {
    for (const child of value) assertJsonValue(child, label);
    return;
  }
  if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (key.length === 0) throw new Error(`${label} contains an empty object key`);
      assertJsonValue(child, label);
    }
    return;
  }
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value !== 'number') {
    throw new Error(`${label} contains an unsupported JSON value`);
  }
  throw new Error(`${label} contains a non-finite JSON number`);
}

function assertExactKeys(value, expectedKeys, label) {
  if (!isRecord(value)) throw new Error(`${label} is invalid`);
  const actualKeys = Object.keys(value).sort(compareStrings);
  const canonicalExpectedKeys = [...expectedKeys].sort(compareStrings);
  if (!sameStrings(actualKeys, canonicalExpectedKeys)) {
    throw new Error(`${label} fields are invalid`);
  }
}

function buildComponentKindIndex() {
  const index = new Map();
  for (let position = 0; position < COMPONENT_KIND_ORDER.length; position += 1) {
    index.set(COMPONENT_KIND_ORDER[position], position);
  }
  return index;
}

function sameStrings(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function printSummary(action, manifest) {
  process.stdout.write(
    `${action} release set ${manifest.releaseSetId} (${manifest.target}, ${manifest.sourceSha}, artifacts ${manifest.artifactRunId})\n`,
  );
}

function allowedOptions(commandName) {
  switch (commandName) {
    case 'create':
      return new Set([
        'components-file',
        'migrations-file',
        'created-at',
        'target',
        'source-sha',
        'accepted-validation-run-id',
        'artifact-run-id',
        'build-identity-file',
        'output',
      ]);
    case 'verify':
      return new Set([
        'manifest',
        'target',
        'source-sha',
        'accepted-validation-run-id',
        'artifact-run-id',
        'release-set-id',
      ]);
    case 'verify-component':
      return new Set(['manifest', 'component-name', 'artifact-manifest']);
    case 'migration-fingerprint':
      return new Set(['database', 'migrations-dir', 'format']);
    default:
      return new Set();
  }
}

function parseOptions(args, allowed) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token.startsWith('--')) throw new Error(`unexpected argument: ${token}`);
    const name = token.slice(2);
    if (!allowed.has(name)) throw new Error(`unsupported option: --${name}`);
    if (options.has(name)) throw new Error(`duplicate option: --${name}`);
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--') || value.length === 0) {
      throw new Error(`--${name} requires a value`);
    }
    options.set(name, value);
    index += 1;
  }
  return options;
}

function requireOption(options, name) {
  const value = options.get(name);
  if (value === undefined || value.length === 0) throw new Error(`--${name} is required`);
  return value;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function releaseSetIdForDigest(digest) {
  return `rs_${digest}`;
}

function stableJson(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (!isRecord(value)) return value;
  const sorted = Object.create(null);
  for (const key of Object.keys(value).sort(compareStrings)) {
    sorted[key] = sortValue(value[key]);
  }
  return sorted;
}

function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
