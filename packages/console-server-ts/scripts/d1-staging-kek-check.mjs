#!/usr/bin/env node
import path from 'node:path';

import {
  d1StagingGatewayManifestArgDefaults,
  isDirectInvocation,
  normalizeGeneratedAtIso,
  arrayTableBodies,
  commaList,
  normalizeGatewayD1StagingConfig,
  normalizeString,
  normalizeStagingMode,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  readSelectedWranglerConfig,
  readString,
  relativeToRepo,
  requireSuccessfulCommandResult,
  runShellCommand,
  secretStoreBindingNameForSecretName,
  shellArg,
  tableBody,
  valueLooksPlaceholder,
  writeD1StagingManifest,
  wranglerPackageCommand,
} from './d1-staging-config.mjs';
import { requireGatewayD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-kek-checks');
const checkModes = Object.freeze(['dry-run', 'remote']);

export function buildD1StagingKekCheckPlan(input = {}) {
  const options = normalizeOptions(input);
  requireGatewayD1StagingReadiness({
    label: 'KEK check',
    gatewayConfigPath: options.gatewayConfigPath,
    environmentName: options.environmentName,
  });
  const keks = readGatewayKekMetadata({
    configPath: options.gatewayConfigPath,
    environmentName: options.environmentName,
  });
  return {
    version: 'seams_d1_staging_kek_check_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    environmentName: options.environmentName,
    gatewayConfigPath: relativeToRepo(options.gatewayConfigPath),
    keks,
    commands: listSecretsStoreCommands(keks),
  };
}

export function runD1StagingKekCheck(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingKekCheckPlan(options);
  const checks = [];

  if (options.mode === 'remote') {
    const expectedByStoreId = groupKeksByStoreId(plan.keks);
    for (const store of expectedByStoreId) {
      const command = secretsStoreListCommand(store.storeId);
      const result = requireSuccessfulCommandResult(command, options.commandRunner(command));
      const presentSecretNames = requireSecretsInListing({
        storeId: store.storeId,
        expectedSecretNames: store.secretNames,
        stdout: result.stdout,
      });
      checks.push({
        storeId: store.storeId,
        command,
        status: result.status,
        presentSecretNames,
      });
    }
  }

  const manifest = {
    ...plan,
    checks,
  };
  return writeD1StagingManifest(options, defaultManifestRoot, manifest);
}

function main() {
  try {
    const result = runD1StagingKekCheck(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging KEK check manifest', 'Dry run commands:', result.manifest.commands);
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, d1StagingGatewayManifestArgDefaults, {
    '--environment': 'environmentName',
    '--generated-at': 'generatedAtIso',
    '--manifest': 'manifestPath',
    '--mode': 'mode',
    '--gateway-config': 'gatewayConfigPath',
  });
}

function normalizeOptions(input) {
  return {
    ...normalizeGatewayD1StagingConfig(input),
    generatedAtIso: normalizeGeneratedAtIso(input.generatedAtIso),
    manifestPath: normalizeString(input.manifestPath),
    mode: normalizeStagingMode(input.mode, checkModes, 'KEK check'),
    commandRunner: input.commandRunner || runShellCommand,
  };
}

function readGatewayKekMetadata(input) {
  const source = readSelectedWranglerConfig({
    configPath: input.configPath,
    environmentName: input.environmentName,
    label: 'Gateway',
  });
  const vars = tableBody(source, 'vars');
  const kekIds = commaList(readString(vars, 'SIGNING_ROOT_KEK_IDS'));
  if (kekIds.length === 0) throw new Error('SIGNING_ROOT_KEK_IDS must list at least one KEK id');

  const blocks = arrayTableBodies(source, 'secrets_store_secrets');
  const keks = [];
  for (const kekId of kekIds) {
    keks.push(
      readKekSecretBinding({
        blocks,
        kekId,
      }),
    );
  }
  return keks;
}

function readKekSecretBinding(input) {
  const expectedBinding = secretStoreBindingNameForSecretName(input.kekId);
  for (const block of input.blocks) {
    const secretName = readString(block, 'secret_name');
    if (secretName !== input.kekId) continue;
    const binding = readString(block, 'binding');
    const storeId = readString(block, 'store_id');
    if (binding !== expectedBinding) {
      throw new Error(`KEK ${input.kekId} binding must be ${expectedBinding}`);
    }
    if (!storeId || valueLooksPlaceholder(storeId)) {
      throw new Error(`KEK ${input.kekId} requires a concrete Secrets Store ID`);
    }
    return {
      kekId: input.kekId,
      binding,
      secretName,
      storeId,
    };
  }
  throw new Error(`missing Secrets Store binding for KEK ${input.kekId}`);
}

function listSecretsStoreCommands(keks) {
  const commands = [];
  for (const store of groupKeksByStoreId(keks)) {
    commands.push(secretsStoreListCommand(store.storeId));
  }
  return commands;
}

function groupKeksByStoreId(keks) {
  const stores = [];
  for (const kek of keks) {
    let store = findStoreById(stores, kek.storeId);
    if (!store) {
      store = {
        storeId: kek.storeId,
        secretNames: [],
      };
      stores.push(store);
    }
    store.secretNames.push(kek.secretName);
  }
  return stores;
}

function findStoreById(stores, storeId) {
  for (const store of stores) {
    if (store.storeId === storeId) return store;
  }
  return undefined;
}

function secretsStoreListCommand(storeId) {
  return wranglerPackageCommand(
    `secrets-store secret list ${shellArg(storeId)} --remote --per-page 100`,
  );
}

function requireSecretsInListing(input) {
  const stdout = normalizeString(input.stdout);
  const listedSecretNames = parseSecretsStoreSecretNames(stdout);
  const presentSecretNames = [];
  for (const secretName of input.expectedSecretNames) {
    if (!listedSecretNames.has(secretName)) {
      throw new Error(`Secrets Store ${input.storeId} does not list required KEK secret ${secretName}`);
    }
    presentSecretNames.push(secretName);
  }
  return presentSecretNames;
}

function parseSecretsStoreSecretNames(stdout) {
  const names = parseSecretsStoreSecretNamesFromJson(stdout);
  if (names.size > 0) return names;
  return parseSecretsStoreSecretNamesFromText(stdout);
}

function parseSecretsStoreSecretNamesFromJson(stdout) {
  const names = new Set();
  if (!stdout) return names;
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return names;
  }
  collectSecretsStoreSecretNames(parsed, names);
  return names;
}

function collectSecretsStoreSecretNames(value, names) {
  if (Array.isArray(value)) {
    for (const item of value) collectSecretsStoreSecretNames(item, names);
    return;
  }
  if (!value || typeof value !== 'object') return;
  const secretName =
    normalizeString(value.name) ||
    normalizeString(value.secretName) ||
    normalizeString(value.secret_name);
  if (isSecretsStoreSecretName(secretName)) names.add(secretName);
  for (const key of ['secrets', 'items', 'result']) {
    collectSecretsStoreSecretNames(value[key], names);
  }
}

function parseSecretsStoreSecretNamesFromText(stdout) {
  const names = new Set();
  for (const rawLine of stdout.split(/\r?\n/g)) {
    const secretName = parseSecretsStoreSecretNameLine(rawLine);
    if (secretName) names.add(secretName);
  }
  return names;
}

function parseSecretsStoreSecretNameLine(rawLine) {
  const line = normalizeString(rawLine);
  if (!line || line.includes('──') || line.includes('==')) return '';
  const cells = splitTableCells(line);
  const token = cells[0] || line.split(/\s+/)[0] || '';
  if (!isSecretsStoreSecretName(token)) return '';
  return token;
}

function splitTableCells(line) {
  const delimiter = line.includes('│') ? '│' : line.includes('|') ? '|' : '';
  if (!delimiter) return [];
  return line
    .split(delimiter)
    .map((cell) => normalizeString(cell))
    .filter(Boolean)
    .filter((cell) => !/^-+$/.test(cell));
}

function isSecretsStoreSecretName(value) {
  if (!value || value === 'name' || value === 'secret_name' || value === 'secretName') return false;
  return /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{1,255}$/.test(value);
}

if (isDirectInvocation(import.meta.url)) main();
