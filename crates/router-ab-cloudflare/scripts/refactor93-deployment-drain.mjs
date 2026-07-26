#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SCHEMA_VERSION = 1;
const ENVIRONMENTS = new Set(['staging', 'production']);
const OPERATIONS = ['registration', 'recovery', 'export'];
const INVENTORY_KEYS = Object.freeze([
  'MPC_ROUTER',
  'MPC_ROUTER_URL',
  'DERIVER_A',
  'DERIVER_B',
  'SIGNING_WORKER',
  'ROUTER_AB_SIGNING_WORKER_URL',
  'ROUTER_API_RUNTIME',
  'DERIVER_A_URL',
  'DERIVER_B_URL',
  'SIGNING_WORKER_URL',
]);
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

export function parseRefactor93DrainReceipt(value) {
  const record = requireRecord(value, 'drain receipt');
  requireExactKeys(record, 'drain receipt', [
    'schemaVersion',
    'environment',
    'capturedAt',
    'release',
    'coherentDeployment',
    'stagingRuns',
    'lifetime',
    'rollback',
    'postDrain',
  ]);
  if (record.schemaVersion !== SCHEMA_VERSION) {
    throw new Error('drain receipt schemaVersion must be 1');
  }
  const environment = requireEnum(record.environment, ENVIRONMENTS, 'drain receipt environment');
  const release = parseRelease(record.release);
  const coherentDeployment = parseCoherentDeployment(record.coherentDeployment, release);
  const stagingRuns = parseStagingRuns(record.stagingRuns);
  const lifetime = parseLifetime(record.lifetime);
  const rollback = parseRollback(record.rollback);
  const postDrain = parsePostDrain(record.postDrain);
  return {
    schemaVersion: SCHEMA_VERSION,
    environment,
    capturedAt: requireIsoTimestamp(record.capturedAt, 'drain receipt capturedAt'),
    release,
    coherentDeployment,
    stagingRuns,
    lifetime,
    rollback,
    postDrain,
  };
}

export function validateRefactor93DrainReceipt(value) {
  const receipt = parseRefactor93DrainReceipt(value);
  const blockers = [];
  if (receipt.environment !== 'staging') {
    blockers.push('drain receipt environment must be staging before route deletion');
  }
  if (!receipt.coherentDeployment.noLegacyGatewayCalls) {
    blockers.push('coherent deployment still reports Gateway calls to legacy role routes');
  }
  for (const operation of OPERATIONS) {
    const run = receipt.stagingRuns[operation];
    if (run.status !== 'success') blockers.push(`${operation} staging run did not succeed`);
    if (run.exactReplay !== 'verified') {
      blockers.push(`${operation} exact replay evidence is missing`);
    }
    if (run.conflict !== 'verified') {
      blockers.push(`${operation} conflict evidence is missing`);
    }
  }
  const requiredDrainMs =
    receipt.lifetime.stagedLifetimeMs +
    receipt.lifetime.runningLifetimeMs +
    receipt.lifetime.transportFailureBudgetMs +
    receipt.lifetime.rollbackBudgetMs;
  if (receipt.lifetime.observedDrainMs < requiredDrainMs) {
    blockers.push(
      `observed drain ${receipt.lifetime.observedDrainMs}ms is shorter than required ${requiredDrainMs}ms`,
    );
  }
  if (!receipt.rollback.rehearsalPassed || !receipt.rollback.previousVersionDeployable) {
    blockers.push(
      'rollback rehearsal is missing or the previous Gateway version is not deployable',
    );
  }
  if (receipt.postDrain.generatedConfigOwners.length > 0) {
    blockers.push('generated config still has legacy owners');
  }
  if (receipt.postDrain.sourceOwners.length > 0) {
    blockers.push('source still has legacy owners');
  }
  return {
    ready: blockers.length === 0,
    blockers,
    requiredDrainMs,
    receipt,
  };
}

export function inventoryRefactor93LegacyKeys(inputs) {
  if (!Array.isArray(inputs) || inputs.length === 0) {
    throw new Error('at least one inventory input is required');
  }
  const sources = inputs.map((input, index) => {
    const record = requireRecord(input, `inventory input[${index}]`);
    requireExactKeys(record, `inventory input[${index}]`, ['path', 'text']);
    return {
      path: requireNonEmptyString(record.path, `inventory input[${index}] path`),
      text: requireString(record.text, `inventory input[${index}] text`),
    };
  });
  return INVENTORY_KEYS.map((key) => ({
    key,
    references: sources
      .map((source) => ({ path: source.path, count: countOccurrences(source.text, key) }))
      .filter((source) => source.count > 0),
    decision: inventoryDecision(key),
  }));
}

function inventoryDecision(key) {
  if (key === 'MPC_ROUTER' || key === 'MPC_ROUTER_URL') return 'retain_yao_owner';
  if (key === 'SIGNING_WORKER' || key === 'ROUTER_AB_SIGNING_WORKER_URL') {
    return 'retain_non_yao_owner';
  }
  return 'drain_or_follow_up';
}

function parseRelease(value) {
  const record = requireRecord(value, 'drain receipt release');
  requireExactKeys(record, 'drain receipt release', [
    'sourceSha',
    'gatewayVersionId',
    'routerVersionId',
    'deriverAVersionId',
    'deriverBVersionId',
    'signingWorkerVersionId',
  ]);
  const release = {};
  for (const key of Object.keys(record)) {
    release[key] = requireNonEmptyString(record[key], `drain receipt release ${key}`);
  }
  if (!/^[0-9a-f]{40}$/u.test(release.sourceSha)) {
    throw new Error('drain receipt release sourceSha must be a lowercase Git SHA');
  }
  return release;
}

function parseCoherentDeployment(value, release) {
  const record = requireRecord(value, 'drain receipt coherentDeployment');
  requireExactKeys(record, 'drain receipt coherentDeployment', [
    'gatewayVersionId',
    'routerVersionId',
    'deriverAVersionId',
    'deriverBVersionId',
    'signingWorkerVersionId',
    'noLegacyGatewayCalls',
  ]);
  for (const key of [
    'gatewayVersionId',
    'routerVersionId',
    'deriverAVersionId',
    'deriverBVersionId',
    'signingWorkerVersionId',
  ]) {
    if (record[key] !== release[key]) {
      throw new Error(`coherent deployment ${key} does not match release`);
    }
  }
  if (typeof record.noLegacyGatewayCalls !== 'boolean') {
    throw new Error('coherent deployment noLegacyGatewayCalls must be boolean');
  }
  return { ...record };
}

function parseStagingRuns(value) {
  const record = requireRecord(value, 'drain receipt stagingRuns');
  requireExactKeys(record, 'drain receipt stagingRuns', OPERATIONS);
  const runs = {};
  for (const operation of OPERATIONS) {
    const run = requireRecord(record[operation], `stagingRuns.${operation}`);
    requireExactKeys(run, `stagingRuns.${operation}`, ['status', 'exactReplay', 'conflict']);
    runs[operation] = {
      status: requireEnum(
        run.status,
        new Set(['success', 'failure']),
        `stagingRuns.${operation} status`,
      ),
      exactReplay: requireEnum(
        run.exactReplay,
        new Set(['verified', 'missing']),
        `stagingRuns.${operation} exactReplay`,
      ),
      conflict: requireEnum(
        run.conflict,
        new Set(['verified', 'missing']),
        `stagingRuns.${operation} conflict`,
      ),
    };
  }
  return runs;
}

function parseLifetime(value) {
  const record = requireRecord(value, 'drain receipt lifetime');
  requireExactKeys(record, 'drain receipt lifetime', [
    'stagedLifetimeMs',
    'runningLifetimeMs',
    'transportFailureBudgetMs',
    'rollbackBudgetMs',
    'observedDrainMs',
  ]);
  const lifetime = {};
  for (const key of Object.keys(record)) {
    lifetime[key] = requireNonNegativeSafeInteger(record[key], `drain receipt lifetime ${key}`);
  }
  return lifetime;
}

function parseRollback(value) {
  const record = requireRecord(value, 'drain receipt rollback');
  requireExactKeys(record, 'drain receipt rollback', [
    'previousGatewayVersionId',
    'rehearsalPassed',
    'previousVersionDeployable',
  ]);
  return {
    previousGatewayVersionId: requireNonEmptyString(
      record.previousGatewayVersionId,
      'drain receipt rollback previousGatewayVersionId',
    ),
    rehearsalPassed: requireBoolean(
      record.rehearsalPassed,
      'drain receipt rollback rehearsalPassed',
    ),
    previousVersionDeployable: requireBoolean(
      record.previousVersionDeployable,
      'drain receipt rollback previousVersionDeployable',
    ),
  };
}

function parsePostDrain(value) {
  const record = requireRecord(value, 'drain receipt postDrain');
  requireExactKeys(record, 'drain receipt postDrain', ['generatedConfigOwners', 'sourceOwners']);
  return {
    generatedConfigOwners: requireStringArray(
      record.generatedConfigOwners,
      'postDrain generatedConfigOwners',
    ),
    sourceOwners: requireStringArray(record.sourceOwners, 'postDrain sourceOwners'),
  };
}

function countOccurrences(text, needle) {
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const matches = text.match(new RegExp(`(^|[^A-Za-z0-9_])${escaped}(?=$|[^A-Za-z0-9_])`, 'gu'));
  return matches?.length ?? 0;
}

function requireRecord(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireExactKeys(record, label, keys) {
  const expected = new Set(keys);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) throw new Error(`${label}.${key} is not supported`);
  }
  for (const key of keys) {
    if (!Object.hasOwn(record, key)) throw new Error(`${label}.${key} is required`);
  }
}

function requireString(value, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return value;
}

function requireNonEmptyString(value, label) {
  const parsed = requireString(value, label);
  if (parsed.length === 0) throw new Error(`${label} must be non-empty`);
  return parsed;
}

function requireBoolean(value, label) {
  if (typeof value !== 'boolean') throw new Error(`${label} must be boolean`);
  return value;
}

function requireStringArray(value, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`${label} must be a string array`);
  }
  return [...value];
}

function requireIsoTimestamp(value, label) {
  const timestamp = requireNonEmptyString(value, label);
  const parsed = new Date(timestamp);
  if (!ISO_TIMESTAMP_PATTERN.test(timestamp) || Number.isNaN(parsed.valueOf())) {
    throw new Error(`${label} must be a canonical ISO timestamp`);
  }
  return timestamp;
}

function requireEnum(value, values, label) {
  if (typeof value !== 'string' || !values.has(value)) throw new Error(`${label} is invalid`);
  return value;
}

function requireNonNegativeSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function parseArgs(args) {
  const [command, ...raw] = args;
  if (command !== 'validate-receipt' && command !== 'inventory') {
    throw new Error(
      'usage: refactor93-deployment-drain.mjs <validate-receipt|inventory> [options]',
    );
  }
  const options = new Map();
  for (let index = 0; index < raw.length; index += 1) {
    const option = raw[index];
    const value = raw[index + 1];
    if (!option?.startsWith('--') || value === undefined)
      throw new Error(`invalid option: ${option ?? '<missing>'}`);
    if (command === 'validate-receipt' && option !== '--receipt') {
      throw new Error(`unsupported option: ${option}`);
    }
    if (command === 'inventory' && option !== '--input') {
      throw new Error(`unsupported option: ${option}`);
    }
    if (option === '--receipt' && options.has(option))
      throw new Error('--receipt may be provided once');
    if (option === '--receipt') options.set(option, resolve(value));
    else options.set(option, [...(options.get(option) ?? []), resolve(value)]);
    index += 1;
  }
  return { command, options };
}

async function runCli() {
  const { command, options } = parseArgs(process.argv.slice(2));
  if (command === 'validate-receipt') {
    const receiptPath = options.get('--receipt');
    if (typeof receiptPath !== 'string') throw new Error('--receipt is required');
    const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
    const result = validateRefactor93DrainReceipt(receipt);
    process.stdout.write(
      `${JSON.stringify({ ready: result.ready, blockers: result.blockers, requiredDrainMs: result.requiredDrainMs }, null, 2)}\n`,
    );
    if (!result.ready) process.exitCode = 1;
    return;
  }
  const paths = options.get('--input');
  if (!Array.isArray(paths) || paths.length === 0)
    throw new Error('at least one --input is required');
  const inputs = await Promise.all(
    paths.map(async (path) => ({ path, text: await readFile(path, 'utf8') })),
  );
  process.stdout.write(`${JSON.stringify(inventoryRefactor93LegacyKeys(inputs), null, 2)}\n`);
}

function isMainModule() {
  return (
    process.argv[1] !== undefined &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href
  );
}

if (isMainModule()) await runCli();
