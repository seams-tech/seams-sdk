#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

import {
  isDirectInvocation,
  arrayTableBodies,
  commaList,
  escapeRegExp,
  normalizeString,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  readArray,
  readString,
  relativeToRepo,
  rootBody,
  secretStoreBindingNameForSecretName,
  selectEnvironmentSource,
  stagingReadinessFailureMessage,
  tableBody,
  valueLooksPlaceholder,
} from './d1-staging-config.mjs';

const defaultConfigByProfile = Object.freeze({
  console: 'wrangler.d1-staging-console.toml',
  gateway: 'wrangler.d1-staging-gateway.toml',
});
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const consoleD1Database = Object.freeze({
  binding: 'CONSOLE_DB',
  databaseName: 'seams-console-staging',
  migrationsDir: 'migrations/d1-console',
});
const signerD1Database = Object.freeze({
  binding: 'SIGNER_DB',
  databaseName: 'seams-signer-staging',
  migrationsDir: '../sdk-server-ts/migrations/d1-signer',
});
const requiredD1DatabasesByProfile = Object.freeze({
  console: Object.freeze([consoleD1Database]),
  gateway: Object.freeze([consoleD1Database, signerD1Database]),
});

const stagingProfiles = Object.freeze(['console', 'gateway']);
const expectedMainByProfile = Object.freeze({
  console: 'src/router/cloudflare/d1ConsoleStagingWorker.ts',
  gateway: 'src/router/cloudflare/d1RouterApiStagingWorker.ts',
});
const requiredSecretVarsByProfile = Object.freeze({
  console: Object.freeze(['CONSOLE_SESSION_HMAC_SECRET']),
  gateway: Object.freeze([
    'RELAY_SESSION_HMAC_SECRET',
    'ACCOUNT_ID_DERIVATION_SECRET',
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
    'SPONSORED_EVM_EXECUTORS_JSON',
  ]),
});
const requiredVarsByProfile = Object.freeze({
  console: Object.freeze([
    'SEAMS_TENANT_STORAGE_NAMESPACE',
    'CONSOLE_SESSION_ISSUER',
    'CONSOLE_SESSION_AUDIENCE',
  ]),
  gateway: Object.freeze([
    'SEAMS_TENANT_STORAGE_NAMESPACE',
    'SEAMS_STAGING_ORG_ID',
    'SEAMS_STAGING_PROJECT_ID',
    'SEAMS_STAGING_ENV_ID',
    'ROUTER_AB_NORMAL_SIGNING_WORKER_ID',
    'SIGNING_WORKER_ID',
    'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
    'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
    'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
    'RELAYER_ACCOUNT_ID',
    'RELAYER_PUBLIC_KEY',
    'RELAY_SESSION_ISSUER',
    'RELAY_SESSION_AUDIENCE',
  ]),
});
const forbiddenPostgresTokens = Object.freeze([
  'POSTGRES_URL',
  'CONSOLE_POSTGRES_URL',
  'POSTGRES_MIGRATION_URL',
  'CONSOLE_POSTGRES_MIGRATION_URL',
  'BILLING_POSTGRES_URL',
  'RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL',
  'WEBHOOK_RETRY_POSTGRES_URL',
]);
const forbiddenPlaintextVars = Object.freeze([
  'SEAMS_LOCAL_SIGNING_ROOT_KEK_ID',
  'SEAMS_LOCAL_SIGNING_ROOT_KEK_B64U',
  'SEAMS_LOCAL_RELAYER_ACCOUNT',
  'SEAMS_LOCAL_RELAYER_PUBLIC_KEY',
  'SPONSORED_EVM_EXECUTORS_JSON',
  'ACCOUNT_ID_DERIVATION_SECRET',
]);
const forbiddenConsoleProfileTokens = Object.freeze([
  'SIGNER_DB',
  'THRESHOLD_STORE',
  'SIGNING_ROOT_KEK_PROVIDER',
  'SIGNING_ROOT_KEK_ENCODING',
  'SIGNING_ROOT_KEK_IDS',
  'secrets_store_secrets',
]);

export function checkD1StagingReadiness(input = {}) {
  const profile = normalizeProfile(input.profile);
  const configPath = resolveConfigPath(input.configPath, profile);
  const environmentName = normalizeString(input.environmentName) || 'staging';
  const errors = [];

  if (!existsSync(configPath)) {
    errors.push(`Wrangler config does not exist: ${path.relative(packageRoot, configPath)}`);
    return { ok: false, configPath, environmentName, profile, errors };
  }

  const rawSource = readFileSync(configPath, 'utf8');
  const source = selectEnvironmentSource(rawSource, environmentName);

  checkRawSource(rawSource, errors);
  checkWorkerRoot(source, profile, errors);
  checkPlaintextVars(source, errors);
  checkProfileBoundary(source, profile, errors);
  checkRequiredVars(source, profile, errors);
  checkSecretVars(source, profile, errors);
  checkD1Databases(source, profile, errors);
  if (profile === 'gateway') {
    checkDurableObject(source, errors);
    checkRouterAbServiceBindings(source, errors);
    checkSigningRootKekProvider(source, errors);
  }

  return {
    ok: errors.length === 0,
    configPath,
    environmentName,
    profile,
    errors,
  };
}

export function requireConsoleAndGatewayD1StagingReadiness(input = {}) {
  return requireD1StagingReadiness({
    label: input.label,
    errorFormat: input.errorFormat,
    checks: [
      {
        profile: 'console',
        configPath: input.consoleConfigPath,
        environmentName: input.environmentName,
      },
      {
        profile: 'gateway',
        configPath: input.gatewayConfigPath,
        environmentName: input.environmentName,
      },
    ],
  });
}

export function requireGatewayD1StagingReadiness(input = {}) {
  return requireD1StagingReadiness({
    label: input.label,
    errorFormat: input.errorFormat,
    checks: [
      {
        profile: 'gateway',
        configPath: input.gatewayConfigPath,
        environmentName: input.environmentName,
      },
    ],
  });
}

export function requireD1StagingReadiness(input = {}) {
  const checks = [];
  for (const check of input.checks || []) {
    checks.push(checkD1StagingReadiness(check));
  }
  const errors = d1StagingReadinessErrors(checks, input.errorFormat);
  if (errors.length > 0) {
    throw new Error(
      stagingReadinessFailureMessage(normalizeString(input.label) || 'readiness', errors),
    );
  }
  return checks;
}

function d1StagingReadinessErrors(checks, errorFormat) {
  const errors = [];
  for (const check of checks) collectD1StagingReadinessErrors(check, errors, errorFormat);
  return errors;
}

function collectD1StagingReadinessErrors(check, errors, errorFormat) {
  if (check.ok) return;
  const prefix = d1StagingReadinessErrorPrefix(check, errorFormat);
  for (const error of check.errors) errors.push(`${prefix}${error}`);
}

function d1StagingReadinessErrorPrefix(check, errorFormat) {
  if (errorFormat === 'profile_config') {
    return `${check.profile} ${relativeToRepo(check.configPath)}: `;
  }
  return `${check.profile}: `;
}

function main() {
  try {
    const result = checkD1StagingReadiness(parseArgs(process.argv.slice(2)));
    if (result.ok) {
      console.log(
        `D1 ${result.profile} staging readiness check passed for ${path.relative(
          packageRoot,
          result.configPath,
        )}`,
      );
      return;
    }
    console.error(`D1 ${result.profile} staging readiness check failed:`);
    for (const error of result.errors) console.error(`- ${error}`);
    process.exitCode = 1;
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(
    args,
    {
      configPath: '',
      environmentName: 'staging',
      profile: 'gateway',
    },
    {
      '--config': 'configPath',
      '--environment': 'environmentName',
      '--profile': 'profile',
    },
  );
}

function normalizeProfile(input) {
  const value = normalizeString(input) || 'gateway';
  for (const profile of stagingProfiles) {
    if (value === profile) return value;
  }
  throw new Error(`Unknown staging profile: ${value}`);
}

function resolveConfigPath(configPath, profile) {
  const selected = normalizeString(configPath) || defaultConfigByProfile[profile];
  if (path.isAbsolute(selected)) return selected;
  return path.resolve(packageRoot, selected);
}

function checkRawSource(source, errors) {
  for (const token of forbiddenPostgresTokens) {
    if (source.includes(token)) errors.push(`config references forbidden Postgres token ${token}`);
  }
  if (source.includes('0x1111111111111111111111111111111111111111111111111111111111111111')) {
    errors.push('config includes the local deterministic sponsored EVM test private key');
  }
}

function checkWorkerRoot(source, profile, errors) {
  const root = rootBody(source);
  const name = requireString(readString(root, 'name'), 'name', errors);
  const profileLabel = stagingProfileLabel(profile);
  if (name && !name.includes('staging')) {
    errors.push('Worker name must identify the staging environment');
  }
  if (name && !name.includes(profile)) {
    errors.push(`Worker name must identify the ${profileLabel} profile`);
  }

  const main = requireString(readString(root, 'main'), 'main', errors);
  if (main && main.includes('d1LocalDevWorker')) {
    errors.push('staging must not use the local D1 development Worker entrypoint');
  }
  if (main && valueLooksPlaceholder(main)) {
    errors.push('main must point at the selected staging Worker entrypoint');
  }
  if (main && main !== expectedMainByProfile[profile]) {
    errors.push(`main must be ${expectedMainByProfile[profile]}`);
  }
  requireString(readString(root, 'compatibility_date'), 'compatibility_date', errors);
}

function checkPlaintextVars(source, errors) {
  const vars = tableBody(source, 'vars');
  for (const varName of forbiddenPlaintextVars) {
    if (hasAssignment(vars, varName)) {
      errors.push(`${varName} must not be configured as a plaintext [vars] value`);
    }
  }
}

function checkProfileBoundary(source, profile, errors) {
  if (profile !== 'console') return;
  for (const token of forbiddenConsoleProfileTokens) {
    if (source.includes(token)) {
      errors.push(`console staging config must not reference ${token}`);
    }
  }
}

function checkD1Databases(source, profile, errors) {
  const blocks = arrayTableBodies(source, 'd1_databases');
  const requiredDatabases = requiredD1DatabasesByProfile[profile];
  const profileLabel = stagingProfileLabel(profile);
  const expectedBindings = new Set(requiredDatabases.map(d1DatabaseBinding));
  const seenBindings = new Set();
  for (const block of blocks) {
    const binding = readString(block, 'binding');
    if (!binding) {
      errors.push('D1 binding is required');
      continue;
    }
    if (seenBindings.has(binding)) {
      errors.push(`duplicate D1 binding ${binding}`);
    }
    seenBindings.add(binding);
    if (!expectedBindings.has(binding)) {
      errors.push(`unexpected D1 binding ${binding} for ${profileLabel} profile`);
    }
  }
  for (const required of requiredDatabases) {
    const block = findBlockByAssignment(blocks, 'binding', required.binding);
    if (!block) {
      errors.push(`missing D1 binding ${required.binding}`);
      continue;
    }
    checkExactString(
      readString(block, 'database_name'),
      required.databaseName,
      `${required.binding}.database_name`,
      errors,
    );
    checkUuid(readString(block, 'database_id'), `${required.binding}.database_id`, errors);
    checkExactString(
      readString(block, 'migrations_dir'),
      required.migrationsDir,
      `${required.binding}.migrations_dir`,
      errors,
    );
  }
}

function stagingProfileLabel(profile) {
  if (profile === 'gateway') return 'Gateway';
  return profile;
}

function d1DatabaseBinding(database) {
  return database.binding;
}

function checkDurableObject(source, errors) {
  const blocks = arrayTableBodies(source, 'durable_objects.bindings');
  checkRequiredDurableObject({
    source,
    blocks,
    bindingName: 'THRESHOLD_STORE',
    className: 'ThresholdStoreDurableObject',
    errors,
  });
  checkRequiredDurableObject({
    source,
    blocks,
    bindingName: 'ROUTER_API_RUNTIME',
    className: 'RouterApiRuntimeDurableObject',
    errors,
  });
}

function checkRequiredDurableObject(input) {
  const block = findBlockByAssignment(input.blocks, 'name', input.bindingName);
  if (!block) {
    input.errors.push(`missing Durable Object binding ${input.bindingName}`);
    return;
  }
  checkExactString(
    readString(block, 'class_name'),
    input.className,
    `${input.bindingName}.class_name`,
    input.errors,
  );
  if (!hasSqliteClassMigration(input.source, input.className)) {
    input.errors.push(`missing Durable Object new_sqlite_classes migration for ${input.className}`);
  }
}

function checkRouterAbServiceBindings(source, errors) {
  const blocks = arrayTableBodies(source, 'services');
  checkRequiredServiceBinding({
    blocks,
    bindingName: 'DERIVER_A',
    serviceName: 'router-ab-deriver-a-staging',
    errors,
  });
  checkRequiredServiceBinding({
    blocks,
    bindingName: 'DERIVER_B',
    serviceName: 'router-ab-deriver-b-staging',
    errors,
  });
  checkRequiredServiceBinding({
    blocks,
    bindingName: 'SIGNING_WORKER',
    serviceName: 'router-ab-signing-worker-staging',
    errors,
  });
}

function checkRequiredServiceBinding(input) {
  const block = findBlockByAssignment(input.blocks, 'binding', input.bindingName);
  if (!block) {
    input.errors.push(`missing Service Binding ${input.bindingName}`);
    return;
  }
  checkExactString(
    readString(block, 'service'),
    input.serviceName,
    `${input.bindingName}.service`,
    input.errors,
  );
}

function checkRequiredVars(source, profile, errors) {
  const vars = tableBody(source, 'vars');
  for (const required of requiredVarsByProfile[profile]) {
    const value = readString(vars, required);
    if (!value) {
      errors.push(`${required} is required under [vars]`);
      continue;
    }
    if (valueLooksPlaceholder(value)) {
      errors.push(`${required} still contains a placeholder`);
    }
  }
}

function checkSecretVars(source, profile, errors) {
  const secretVars = readArray(tableBody(source, 'secrets'), 'required');
  for (const required of requiredSecretVarsByProfile[profile]) {
    if (!includesString(secretVars, required))
      errors.push(`${required} must be declared under [secrets].required`);
  }
}

function checkSigningRootKekProvider(source, errors) {
  const vars = tableBody(source, 'vars');
  checkExactString(
    readString(vars, 'SIGNING_ROOT_KEK_PROVIDER'),
    'cloudflare_secrets_store',
    'SIGNING_ROOT_KEK_PROVIDER',
    errors,
  );

  const encoding = readString(vars, 'SIGNING_ROOT_KEK_ENCODING');
  if (!encoding) errors.push('SIGNING_ROOT_KEK_ENCODING is required');
  if (encoding && !isSupportedKekEncoding(encoding)) {
    errors.push('SIGNING_ROOT_KEK_ENCODING must be base64url, base64, or hex');
  }

  const kekIds = commaList(readString(vars, 'SIGNING_ROOT_KEK_IDS'));
  if (kekIds.length === 0) {
    errors.push('SIGNING_ROOT_KEK_IDS must list at least one hosted signer KEK id');
    return;
  }
  for (const kekId of kekIds) {
    if (!hasSecretStoreSecret(source, kekId)) {
      errors.push(`missing Cloudflare Secrets Store binding for signer KEK ${kekId}`);
    }
  }
}

function hasAssignment(source, key) {
  const pattern = new RegExp(`^\\s*${escapeRegExp(key)}\\s*=`, 'm');
  return pattern.test(source);
}

function findBlockByAssignment(blocks, key, expected) {
  for (const block of blocks) {
    if (readString(block, key) === expected) return block;
  }
  return '';
}

function hasSqliteClassMigration(source, className) {
  const blocks = arrayTableBodies(source, 'migrations');
  for (const block of blocks) {
    if (includesString(readArray(block, 'new_sqlite_classes'), className)) return true;
  }
  return false;
}

function hasSecretStoreSecret(source, secretName) {
  const blocks = arrayTableBodies(source, 'secrets_store_secrets');
  const expectedBinding = secretStoreBindingNameForSecretName(secretName);
  for (const block of blocks) {
    if (readString(block, 'secret_name') !== secretName) continue;
    if (readString(block, 'binding') !== expectedBinding) continue;
    if (valueLooksPlaceholder(readString(block, 'store_id'))) continue;
    return true;
  }
  return false;
}

function checkExactString(value, expected, label, errors) {
  if (value === expected) return;
  errors.push(`${label} must be ${expected}`);
}

function checkUuid(value, label, errors) {
  if (!value) {
    errors.push(`${label} is required`);
    return;
  }
  if (valueLooksPlaceholder(value)) {
    errors.push(`${label} still contains a placeholder`);
    return;
  }
  if (value === '00000000-0000-0000-0000-000000000000') {
    errors.push(`${label} must not be the zero UUID`);
    return;
  }
  if (!uuidPattern.test(value)) errors.push(`${label} must be a D1 database UUID`);
}

function requireString(value, label, errors) {
  if (!value) {
    errors.push(`${label} is required`);
    return '';
  }
  if (valueLooksPlaceholder(value)) errors.push(`${label} still contains a placeholder`);
  return value;
}

function includesString(values, expected) {
  for (const value of values) {
    if (value === expected) return true;
  }
  return false;
}

function isSupportedKekEncoding(value) {
  return value === 'base64url' || value === 'base64' || value === 'hex';
}

if (isDirectInvocation(import.meta.url)) main();
