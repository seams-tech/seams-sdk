#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import {
  BACKEND_COMPONENTS,
  componentSecretNames,
  readBackendLane,
} from './deployment-targets.mjs';
import { readMigrationSet } from './migration-fingerprint.mjs';
import { formatFailedCheck, isFailedCheck, runReadinessChecks } from './deployment-smoke.mjs';
import {
  consoleOriginFor,
  GATEWAY_WORKER_COMPATIBILITY_DATE,
  GATEWAY_WORKER_COMPATIBILITY_FLAGS,
} from '../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, '..');
const requireFromWalletConsole = createRequire(
  path.join(REPOSITORY_ROOT, 'packages', 'wallet-console-server-ts', 'package.json'),
);
const WALLET_SERVER_ROOT = resolveWalletServerRoot();
const SOURCE_ROUTER_ROOT = path.join(REPOSITORY_ROOT, 'crates', 'router-ab-cloudflare');
const PACKAGED_ROUTER_ROOT = path.join(WALLET_SERVER_ROOT, 'cloudflare-router-ab');
const RELEASE_ROUTER_ROOT = path.join(REPOSITORY_ROOT, '.release-artifacts', 'router-ab-runtime');
const ROUTER_ROOT = resolveRouterRuntimeRoot();
const GATEWAY_ROOT = path.join(REPOSITORY_ROOT, 'packages', 'console-server-ts');
const GATEWAY_BUILD_CONFIG = path.join(
  GATEWAY_ROOT,
  '.wrangler',
  'generated',
  'gateway-build.jsonc',
);
const GATEWAY_GENERATED_ROOT = path.join(GATEWAY_ROOT, '.wrangler', 'generated');
const GATEWAY_BUNDLE = path.join(
  REPOSITORY_ROOT,
  '.release-artifacts',
  'gateway',
  'payload',
  'd1GatewayWorker.js',
);
const CONSOLE_BUILD_CONFIG = path.join(GATEWAY_GENERATED_ROOT, 'console-build.jsonc');
const CONSOLE_BUNDLE = path.join(
  REPOSITORY_ROOT,
  '.release-artifacts',
  'console',
  'payload',
  'd1ConsoleStagingWorker.js',
);
const WALLET_RUNTIME_BUILD_CONFIG = path.join(GATEWAY_GENERATED_ROOT, 'wallet-runtime-build.jsonc');
const WALLET_RUNTIME_BUNDLE = path.join(
  REPOSITORY_ROOT,
  '.release-artifacts',
  'wallet-runtime',
  'payload',
  'd1WalletRuntimeWorker.js',
);
const BACKEND_SMOKE_PATHS = Object.freeze([
  '/readyz',
  '/healthz',
  '/.well-known/router-ab-ceremony-jwks.json',
  '/router-ab/ed25519/healthz',
  '/router-ab/ecdsa-derivation/healthz',
]);
const PREFLIGHT_VARIABLE_ALIASES = Object.freeze({
  ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY: 'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
  ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX: 'DERIVER_A_PEER_VERIFYING_KEY_HEX',
  ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY: 'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
  ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX: 'DERIVER_B_PEER_VERIFYING_KEY_HEX',
  ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
    'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
  ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_ID: 'SIGNING_WORKER_PRIVATE_D1_ID',
  ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY: 'SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY',
  ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_KEK_VERSION: 'SIGNING_WORKER_PRIVATE_D1_KEK_VERSION',
  ROUTER_AB_DERIVER_A_PRIVATE_D1_ID: 'DERIVER_A_PRIVATE_D1_ID',
  ROUTER_AB_DERIVER_B_PRIVATE_D1_ID: 'DERIVER_B_PRIVATE_D1_ID',
  ROUTER_AB_DERIVER_A_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY: 'DERIVER_A_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY',
  ROUTER_AB_DERIVER_A_ROLE_PRIVATE_D1_KEK_VERSION: 'DERIVER_A_ROLE_PRIVATE_D1_KEK_VERSION',
  ROUTER_AB_DERIVER_B_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY: 'DERIVER_B_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY',
  ROUTER_AB_DERIVER_B_ROLE_PRIVATE_D1_KEK_VERSION: 'DERIVER_B_ROLE_PRIVATE_D1_KEK_VERSION',
});
const PRIVATE_D1_DEPLOYMENTS = Object.freeze({
  'signing-worker': Object.freeze({
    binding: 'SIGNING_WORKER_PRIVATE_DB',
    databaseIdEnvironment: 'SIGNING_WORKER_PRIVATE_D1_ID',
    placeholders: Object.freeze({
      'staging-testnet': '__STAGING_TESTNET_SIGNING_WORKER_PRIVATE_D1_ID__',
      'production-testnet': '__PRODUCTION_TESTNET_SIGNING_WORKER_PRIVATE_D1_ID__',
      'production-mainnet': '__PRODUCTION_MAINNET_SIGNING_WORKER_PRIVATE_D1_ID__',
    }),
  }),
  'deriver-a': Object.freeze({
    binding: 'DERIVER_ROLE_PRIVATE_DB',
    databaseIdEnvironment: 'DERIVER_A_PRIVATE_D1_ID',
    placeholders: Object.freeze({
      'staging-testnet': '__STAGING_TESTNET_DERIVER_A_PRIVATE_D1_ID__',
      'production-testnet': '__PRODUCTION_TESTNET_DERIVER_A_PRIVATE_D1_ID__',
      'production-mainnet': '__PRODUCTION_MAINNET_DERIVER_A_PRIVATE_D1_ID__',
    }),
  }),
  'deriver-b': Object.freeze({
    binding: 'DERIVER_ROLE_PRIVATE_DB',
    databaseIdEnvironment: 'DERIVER_B_PRIVATE_D1_ID',
    placeholders: Object.freeze({
      'staging-testnet': '__STAGING_TESTNET_DERIVER_B_PRIVATE_D1_ID__',
      'production-testnet': '__PRODUCTION_TESTNET_DERIVER_B_PRIVATE_D1_ID__',
      'production-mainnet': '__PRODUCTION_MAINNET_DERIVER_B_PRIVATE_D1_ID__',
    }),
  }),
});

if (isDirectInvocation()) {
  main(process.argv.slice(2)).catch(handleFailure);
}

function resolveWalletServerRoot() {
  try {
    return path.dirname(requireFromWalletConsole.resolve('@seams/wallet-server/package.json'));
  } catch {
    const workspacePackage = path.join(REPOSITORY_ROOT, 'packages', 'wallet-server');
    if (fs.existsSync(path.join(workspacePackage, 'package.json'))) return workspacePackage;
    throw new Error('@seams/wallet-server must be installed for hosted deployment');
  }
}

function isDirectInvocation() {
  return (
    process.argv[1] &&
    path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
  );
}

async function main(args) {
  const options = parseArguments(args);
  const lane = readBackendLane(options.lane);
  if (options.operation !== 'plan') {
    requireProvisionedLane(lane);
    assertDeploymentBranch(lane);
  }
  switch (options.operation) {
    case 'plan':
      printPlan(lane);
      return;
    case 'build':
      buildBackend(lane);
      return;
    case 'preflight':
      preflightBackend(lane, options.component, readPreflightEnvironment());
      return;
    case 'migrate':
      migrateBackend(lane);
      return;
    case 'deploy':
      deployBackend(lane, options.component);
      return;
    case 'smoke':
      await smokeBackend(lane);
      return;
    default:
      throw new Error(`Unsupported backend operation: ${options.operation}`);
  }
}

function parseArguments(args) {
  const operation = String(args[0] || '').trim();
  const options = { operation, lane: '', component: '' };
  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--lane') {
      options.lane = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--component') {
      options.component = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(
      `usage: deploy-backend.mjs <plan|build|preflight|migrate|deploy|smoke> --lane <lane>`,
    );
  }
  if (!['plan', 'build', 'preflight', 'migrate', 'deploy', 'smoke'].includes(operation)) {
    throw new Error(
      'usage: deploy-backend.mjs <plan|build|preflight|migrate|deploy|smoke> --lane <lane>',
    );
  }
  if (!options.lane)
    throw new Error('--lane is required (usage: deploy-backend.mjs <operation> --lane <lane>)');
  if (['preflight', 'deploy'].includes(operation)) {
    if (!options.component) throw new Error('--component is required');
    if (!BACKEND_COMPONENTS.includes(options.component)) {
      throw new Error(`unknown component: ${options.component}`);
    }
  } else if (options.component) {
    throw new Error('--component is not allowed for this operation');
  }
  return options;
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  return value;
}

function assertDeploymentBranch(lane) {
  const ref = resolveDeploymentRef();
  if (!ref) return;
  const expectedRef = `refs/heads/${lane.branch}`;
  if (ref !== expectedRef) {
    throw new Error(`lane ${lane.id} requires branch ${lane.branch}; received ${ref}`);
  }
}

function resolveDeploymentRef() {
  const ref = String(process.env.GITHUB_REF || '').trim();
  if (ref) return ref;
  const branch = String(process.env.GITHUB_REF_NAME || '').trim();
  return branch ? `refs/heads/${branch}` : '';
}

function requireProvisionedLane(lane) {
  switch (lane.provisioning.kind) {
    case 'provisioned':
      return lane.provisioning.gatewayDeploymentConfig;
    case 'pending':
      throw new Error(
        `lane ${lane.id} is pending provisioning; required values: ${lane.provisioning.requiredValues.join(', ')}`,
      );
    default:
      throw new Error(`Unsupported provisioning state for lane ${lane.id}`);
  }
}

function printPlan(lane) {
  const provisioningLines = provisioningPlanLines(lane);
  const lines = [
    `Backend deployment plan: ${lane.id}`,
    `Release: ${lane.release}`,
    `Network: ${lane.network}`,
    `Branch: ${lane.branch}`,
    ...provisioningLines,
    `Gateway: ${lane.resources.gateway.workerName}`,
    `Gateway origin: ${lane.gatewayOrigin}`,
    `Wallet origin: ${lane.walletOrigin}`,
    `Site origin: ${lane.site.origin}`,
    `Console D1: ${lane.resources.gateway.consoleD1Name}`,
    `Signer D1: ${lane.resources.gateway.signerD1Name}`,
    `Capabilities: ${formatCapabilities(lane)}`,
    '',
    'Order:',
    '  1. build all backend components once and require the lane branch',
    '  2. preflight all seven backend components',
    `  3. migrate ${lane.resources.gateway.consoleD1Name} (console D1)`,
    `  4. migrate ${lane.resources.gateway.signerD1Name} (signer D1)`,
    '  5. migrate and deploy signing-worker, deriver-a, and deriver-b concurrently',
    '  6. deploy router after all three workers complete',
    '  7. deploy wallet-runtime after router',
    '  8. deploy console after wallet-runtime',
    '  9. deploy gateway after router and console',
    '  10. smoke Gateway, Console, and Router A/B endpoints',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

function provisioningPlanLines(lane) {
  switch (lane.provisioning.kind) {
    case 'provisioned':
      return [
        'Provisioning: provisioned',
        `Runtime profile: ${lane.provisioning.gatewayDeploymentConfig.runtimeProfile.kind}`,
      ];
    case 'pending':
      return [
        'Provisioning: pending',
        `Runtime profile: ${lane.provisioning.runtimeProfileKind}`,
        `Required values: ${lane.provisioning.requiredValues.join(', ')}`,
      ];
    default:
      throw new Error(`Unsupported provisioning state for lane ${lane.id}`);
  }
}

function formatCapabilities(lane) {
  const names = ['billing', 'sponsoredExecution', 'signingSessionSeal'];
  const values = [];
  for (const name of names) {
    values.push(`${name}=${lane.capabilities[name].enabled ? 'enabled' : 'disabled'}`);
  }
  return values.join(', ');
}

function buildBackend(lane) {
  process.stdout.write(`Building backend lane ${lane.id} (${lane.network})\n`);
  runCommand('pnpm', ['install', '--frozen-lockfile']);
  if (hasRouterSource()) {
    runCommand('pnpm', ['-C', 'crates/router-ab-cloudflare', 'run', 'worker-build:install']);
    const routerEnvironment = buildEnvironment({
      DEPLOYMENT_LANE: lane.id,
      ROUTER_AB_WORKER_BUILD_PROFILE: 'release',
    });
    for (const role of ['signing-worker', 'deriver-a', 'deriver-b', 'router']) {
      runCommand('pnpm', ['-C', 'crates/router-ab-cloudflare', 'run', `build:${role}`], {
        env: routerEnvironment,
      });
    }
    runCommand('pnpm', ['-C', 'packages/wallet-server', 'run', 'package:cloudflare-runtime']);
  }
  stageRouterRuntimeArtifact();
  runCommand('pnpm', [
    '--filter',
    '@seams/wallet',
    'exec',
    'bash',
    'scripts/build/install-ci-wasm-tooling.sh',
  ]);
  const sdkWasmEnvironment = buildEnvironment({
    DEPLOYMENT_LANE: lane.id,
    WASM_SDK_BUILD_MODE: 'prod',
    WASM_SDK_BUILD_TARGET: 'all',
  });
  runCommand('pnpm', ['--filter', '@seams/wallet', 'run', 'build:wasm'], {
    env: sdkWasmEnvironment,
  });
  runCommand('pnpm', ['--filter', '@seams/wallet-server', 'run', 'build']);
  runCommand('pnpm', ['-C', 'packages/console-server-ts', 'run', 'build']);
  runCommand('pnpm', ['-C', 'packages/wallet-console-server-ts', 'run', 'build']);
  runCommand('pnpm', ['-C', 'packages/console-server-ts', 'run', 'd1:local:ensure-wasm'], {
    env: sdkWasmEnvironment,
  });
  writeGatewayBuildConfig(lane.id);
  fs.mkdirSync(path.dirname(GATEWAY_BUNDLE), { recursive: true });
  runCommand(
    'pnpm',
    [
      'exec',
      'wrangler',
      'deploy',
      '--dry-run',
      '--config',
      GATEWAY_BUILD_CONFIG,
      '--outdir',
      path.dirname(GATEWAY_BUNDLE),
      '--metafile',
      path.join(path.dirname(GATEWAY_BUNDLE), 'worker-meta.json'),
    ],
    { cwd: GATEWAY_ROOT },
  );
  assertFile(GATEWAY_BUNDLE, 'Gateway build entry');
  writeConsoleBuildConfig(lane.id);
  fs.mkdirSync(path.dirname(CONSOLE_BUNDLE), { recursive: true });
  runCommand(
    'pnpm',
    [
      'exec',
      'wrangler',
      'deploy',
      '--dry-run',
      '--config',
      CONSOLE_BUILD_CONFIG,
      '--outdir',
      path.dirname(CONSOLE_BUNDLE),
      '--metafile',
      path.join(path.dirname(CONSOLE_BUNDLE), 'worker-meta.json'),
    ],
    { cwd: GATEWAY_ROOT },
  );
  assertFile(CONSOLE_BUNDLE, 'Console build entry');
  writeWalletRuntimeBuildConfig(lane.id);
  fs.mkdirSync(path.dirname(WALLET_RUNTIME_BUNDLE), { recursive: true });
  runCommand(
    'pnpm',
    [
      'exec',
      'wrangler',
      'deploy',
      '--dry-run',
      '--config',
      WALLET_RUNTIME_BUILD_CONFIG,
      '--outdir',
      path.dirname(WALLET_RUNTIME_BUNDLE),
      '--metafile',
      path.join(path.dirname(WALLET_RUNTIME_BUNDLE), 'worker-meta.json'),
    ],
    { cwd: GATEWAY_ROOT },
  );
  assertFile(WALLET_RUNTIME_BUNDLE, 'Wallet Runtime build entry');
}

function hasRouterSource() {
  return (
    fs.existsSync(path.join(SOURCE_ROUTER_ROOT, 'Cargo.toml')) &&
    fs.existsSync(path.join(SOURCE_ROUTER_ROOT, 'package.json'))
  );
}

function isRouterRuntimeRoot(directory) {
  return ['router', 'deriver-a', 'deriver-b', 'signing-worker'].every((role) =>
    fs.existsSync(path.join(directory, 'build', role, 'worker', 'shim.mjs')),
  );
}

function resolveRouterRuntimeRoot() {
  for (const candidate of [RELEASE_ROUTER_ROOT, PACKAGED_ROUTER_ROOT, SOURCE_ROUTER_ROOT]) {
    if (isRouterRuntimeRoot(candidate)) return candidate;
  }
  if (fs.existsSync(path.join(SOURCE_ROUTER_ROOT, 'wrangler.router.toml'))) {
    return SOURCE_ROUTER_ROOT;
  }
  return PACKAGED_ROUTER_ROOT;
}

function stageRouterRuntimeArtifact() {
  if (!isRouterRuntimeRoot(PACKAGED_ROUTER_ROOT)) {
    throw new Error(
      `@seams/wallet-server is missing its packaged Cloudflare runtime at ${PACKAGED_ROUTER_ROOT}`,
    );
  }
  fs.rmSync(RELEASE_ROUTER_ROOT, { recursive: true, force: true });
  fs.cpSync(PACKAGED_ROUTER_ROOT, RELEASE_ROUTER_ROOT, { recursive: true });
}

function routerConfigPath(resource) {
  return path.join(ROUTER_ROOT, path.basename(resource.configPath));
}

function writeGatewayBuildConfig(laneId) {
  const config = {
    name: `seams-sdk-d1-gateway-build-${laneId}`,
    main: path.join(
      REPOSITORY_ROOT,
      'packages/wallet-console-server-ts/src/router/cloudflare/d1GatewayWorker.ts',
    ),
    compatibility_date: GATEWAY_WORKER_COMPATIBILITY_DATE,
    compatibility_flags: GATEWAY_WORKER_COMPATIBILITY_FLAGS,
  };
  fs.mkdirSync(path.dirname(GATEWAY_BUILD_CONFIG), { recursive: true });
  fs.writeFileSync(GATEWAY_BUILD_CONFIG, `${JSON.stringify(config, null, 2)}\n`, {
    mode: 0o600,
  });
}

function writeConsoleBuildConfig(laneId) {
  const config = {
    name: `seams-sdk-d1-console-build-${laneId}`,
    main: path.join(
      REPOSITORY_ROOT,
      'packages/wallet-console-server-ts/src/router/cloudflare/d1ConsoleStagingWorker.ts',
    ),
    compatibility_date: GATEWAY_WORKER_COMPATIBILITY_DATE,
    compatibility_flags: GATEWAY_WORKER_COMPATIBILITY_FLAGS,
  };
  fs.mkdirSync(path.dirname(CONSOLE_BUILD_CONFIG), { recursive: true });
  fs.writeFileSync(CONSOLE_BUILD_CONFIG, `${JSON.stringify(config, null, 2)}\n`, {
    mode: 0o600,
  });
}

function writeWalletRuntimeBuildConfig(laneId) {
  const config = {
    name: `seams-sdk-d1-wallet-runtime-build-${laneId}`,
    main: path.join(
      REPOSITORY_ROOT,
      'packages/wallet-console-server-ts/src/router/cloudflare/d1WalletRuntimeWorker.ts',
    ),
    compatibility_date: GATEWAY_WORKER_COMPATIBILITY_DATE,
    compatibility_flags: GATEWAY_WORKER_COMPATIBILITY_FLAGS,
  };
  fs.mkdirSync(path.dirname(WALLET_RUNTIME_BUILD_CONFIG), { recursive: true });
  fs.writeFileSync(WALLET_RUNTIME_BUILD_CONFIG, `${JSON.stringify(config, null, 2)}\n`, {
    mode: 0o600,
  });
}

function preflightBackend(lane, component, environment = process.env) {
  assertLaneResourceBindings(lane, component);
  const requiredNames = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'];
  requiredNames.push(...componentSecretNames(lane, component));
  for (const name of componentRuntimeRequirements(lane, component)) {
    requiredNames.push(name);
  }
  if (component === 'gateway' || component === 'wallet-runtime') {
    const config = requireProvisionedLane(lane);
    if (config.optional.nearRelayer) requiredNames.push('RELAYER_PRIVATE_KEY');
  }
  requireEnvironmentValues(unique(requiredNames), environment);
  if (component === 'gateway') warnDisabledGatewayIntegrations(environment);
  process.stdout.write(`Preflight passed: ${lane.id}/${component}\n`);
}

function assertLaneResourceBindings(lane, component) {
  if (component === 'gateway' || component === 'console' || component === 'wallet-runtime') return;
  const resourceKey = {
    'signing-worker': 'signingWorker',
    'deriver-a': 'deriverA',
    'deriver-b': 'deriverB',
    router: 'router',
  }[component];
  if (!resourceKey) throw new Error(`Unsupported backend component: ${component}`);
  const resource = lane.resources[resourceKey];
  const configPath = routerConfigPath(resource);
  assertFile(configPath, `Wrangler config for ${resource.workerName}`);
  const section = readWranglerWorkerSection(
    fs.readFileSync(configPath, 'utf8'),
    resource.deploymentEnvironment,
  );
  requireConfigLine(section, 'name', resource.workerName, `${lane.id}/${component} Worker`);
  assertExpectedWorkerServices(lane, component, section);
  assertExpectedPrivateD1Binding(lane, component, section);
}

function readWranglerWorkerSection(source, deploymentEnvironment) {
  if (deploymentEnvironment.kind === 'default') {
    return source.split(/\n\[env\./u, 1)[0];
  }
  const marker = `\n[env.${deploymentEnvironment.name}]`;
  const start = source.indexOf(marker);
  if (start < 0) {
    throw new Error(`Wrangler config is missing [env.${deploymentEnvironment.name}]`);
  }
  const sectionStart = start + 1;
  const end = source.indexOf('\n[env.', sectionStart);
  return source.slice(sectionStart, end < 0 ? source.length : end);
}

function requireConfigLine(section, key, expected, label) {
  const pattern = new RegExp(`^${key}\\s*=\\s*"([^"]+)"\\s*$`, 'mu');
  const match = pattern.exec(section);
  if (!match || match[1] !== expected) {
    throw new Error(`${label} must bind ${key}=${expected}`);
  }
}

export function assertExpectedWorkerServices(lane, component, section) {
  const expectedServices = {
    router: [
      ['DERIVER_A', lane.resources.deriverA.workerName],
      ['DERIVER_B', lane.resources.deriverB.workerName],
      ['SIGNING_WORKER', lane.resources.signingWorker.workerName],
    ],
    'deriver-a': [['DERIVER_B', lane.resources.deriverB.workerName]],
    'deriver-b': [['DERIVER_A', lane.resources.deriverA.workerName]],
    'signing-worker': [],
  }[component];
  const serviceBindings = parseWranglerServiceBindings(section);
  for (const [binding, service] of expectedServices) {
    if (serviceBindings.get(binding) !== service) {
      throw new Error(`${lane.id}/${component} must bind ${binding} to ${service}`);
    }
  }
}

export function parseWranglerServiceBindings(section) {
  const headerPattern = /^\[\[(?:[^\r\n]+?\.)?services\]\][ \t]*$/gmu;
  const headers = [...section.matchAll(headerPattern)];
  const bindings = new Map();
  for (let index = 0; index < headers.length; index += 1) {
    const start = headers[index].index;
    const end = headers[index + 1]?.index ?? section.length;
    const block = section.slice(start, end);
    const binding = /^binding\s*=\s*"([^"]+)"\s*$/mu.exec(block)?.[1];
    const service = /^service\s*=\s*"([^"]+)"\s*$/mu.exec(block)?.[1];
    if (!binding || !service) {
      throw new Error('Wrangler service binding blocks must define binding and service');
    }
    if (bindings.has(binding)) {
      throw new Error(`Wrangler service binding ${binding} is defined more than once`);
    }
    bindings.set(binding, service);
  }
  return bindings;
}

function assertExpectedPrivateD1Binding(lane, component, section) {
  const deployment = PRIVATE_D1_DEPLOYMENTS[component];
  if (!deployment) return;
  const suffix = {
    'staging-testnet': '-staging',
    'production-testnet': '-testnet',
    'production-mainnet': '',
  }[lane.id];
  const componentName =
    component === 'signing-worker' ? 'signing-worker' : `deriver-${component.slice(-1)}`;
  const expectedDatabaseName = `router-ab-${componentName}${suffix}-private`;
  requireConfigLine(
    section,
    'database_name',
    expectedDatabaseName,
    `${lane.id}/${component} private D1`,
  );
  const expectedPlaceholder = deployment.placeholders[lane.id];
  requireConfigLine(
    section,
    'database_id',
    expectedPlaceholder,
    `${lane.id}/${component} private D1`,
  );
}

function warnDisabledGatewayIntegrations(environment) {
  if (!String(environment.STRIPE_WEBHOOK_SECRET || '').trim()) {
    process.stderr.write(
      'Warning: Stripe webhook processing is disabled because STRIPE_WEBHOOK_SECRET is not configured.\n',
    );
  }
  process.stderr.write(
    'Warning: Console email delivery is disabled because no email provider is configured.\n',
  );
}

function readPreflightEnvironment() {
  return {
    ...normalizePreflightVariables(parseEnvironmentInventory('DEPLOYMENT_VARS_JSON')),
    ...readSecretNameInventory(),
  };
}

function normalizePreflightVariables(variables) {
  const normalized = { ...variables };
  for (const [source, destination] of Object.entries(PREFLIGHT_VARIABLE_ALIASES)) {
    if (Object.hasOwn(variables, source)) normalized[destination] = variables[source];
  }
  return normalized;
}

function readSecretNameInventory() {
  const secrets = parseEnvironmentInventory('DEPLOYMENT_SECRETS_JSON');
  return Object.fromEntries(Object.keys(secrets).map((name) => [name, 'configured']));
}

function parseEnvironmentInventory(name) {
  let value;
  try {
    value = JSON.parse(requireEnvironmentValue(name));
  } catch (error) {
    throw new Error(`${name} must be a JSON object: ${formatError(error)}`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be a JSON object`);
  }
  return value;
}

function componentRuntimeRequirements(lane, component) {
  switch (component) {
    case 'signing-worker':
      return [
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
        'SIGNING_WORKER_PRIVATE_D1_ID',
        'SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY',
        'SIGNING_WORKER_PRIVATE_D1_KEK_VERSION',
      ];
    case 'deriver-a':
      return [
        'DERIVER_A_PRIVATE_D1_ID',
        'DERIVER_A_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY',
        'DERIVER_A_ROLE_PRIVATE_D1_KEK_VERSION',
        'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
      ];
    case 'deriver-b':
      return [
        'DERIVER_B_PRIVATE_D1_ID',
        'DERIVER_B_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY',
        'DERIVER_B_ROLE_PRIVATE_D1_KEK_VERSION',
        'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
      ];
    case 'router':
      return [
        'ROUTER_AB_JWT_JWKS_JSON',
        'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
        'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
        ...(lane.network === 'mainnet' ? ['ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON'] : []),
      ];
    case 'gateway':
    case 'wallet-runtime':
    case 'console':
      return [];
    default:
      throw new Error(`Unsupported backend component: ${component}`);
  }
}

function migrateBackend(lane) {
  requireEnvironmentValues(['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID']);
  const gatewayConfig = gatewayConfigPath(lane.id);
  const consoleConfig = consoleConfigPath(lane.id);
  renderGatewayConfig(lane.id, gatewayConfig);
  renderConsoleConfig(lane.id, consoleConfig);
  const migrations = [
    {
      database: 'CONSOLE_DB',
      config: consoleConfig,
      directory: path.join(
        REPOSITORY_ROOT,
        'packages',
        'wallet-console-server-ts',
        'migrations',
        'd1-console',
      ),
    },
    {
      database: 'SIGNER_DB',
      config: gatewayConfig,
      directory: path.join(WALLET_SERVER_ROOT, 'migrations', 'd1-signer'),
    },
  ];
  for (const migration of migrations) {
    const fingerprint = readMigrationSet(migration.directory).fingerprint;
    const migrationArgs = [
      'scripts/apply-remote-d1-migrations.mjs',
      '--database',
      migration.database,
      '--config',
      migration.config,
      '--migrations-dir',
      migration.directory,
      '--expected-fingerprint',
      fingerprint,
    ];
    runCommand('node', migrationArgs, { cwd: GATEWAY_ROOT });
  }
}

function deployBackend(lane, component) {
  preflightBackend(lane, component);
  validateDeploymentKeyPairs(component);
  switch (component) {
    case 'signing-worker':
      deploySigningWorker(lane);
      return;
    case 'deriver-a':
      deployDeriver(lane, 'a');
      return;
    case 'deriver-b':
      deployDeriver(lane, 'b');
      return;
    case 'router':
      deployMpcRouter(lane);
      return;
    case 'wallet-runtime':
      deployWalletRuntime(lane);
      return;
    case 'gateway':
      deployGateway(lane);
      return;
    case 'console':
      deployConsole(lane);
      return;
    default:
      throw new Error(`Unsupported backend component: ${component}`);
  }
}

export function validateDeploymentKeyPairs(component, environment = process.env) {
  switch (component) {
    case 'deriver-a':
      assertX25519KeyPair(
        'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
        'hpke-x25519-private-v1:',
        'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
        environment,
      );
      assertX25519KeyPair(
        'DERIVER_A_ROLE_PRIVATE_D1_KEK',
        'hpke-x25519-role-private-d1-private-v1:',
        'DERIVER_A_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY',
        environment,
      );
      return;
    case 'deriver-b':
      assertX25519KeyPair(
        'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
        'hpke-x25519-private-v1:',
        'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
        environment,
      );
      assertX25519KeyPair(
        'DERIVER_B_ROLE_PRIVATE_D1_KEK',
        'hpke-x25519-role-private-d1-private-v1:',
        'DERIVER_B_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY',
        environment,
      );
      return;
    case 'signing-worker':
      assertX25519KeyPair(
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
        'hpke-x25519-server-output-private-v1:',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
        environment,
      );
      assertX25519KeyPair(
        'SIGNING_WORKER_PRIVATE_D1_KEK',
        'hpke-x25519-server-output-private-v1:',
        'SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY',
        environment,
      );
      return;
    case 'gateway':
    case 'router':
    case 'console':
    case 'wallet-runtime':
      return;
    default:
      throw new Error(`Unsupported backend component: ${component}`);
  }
}

function assertX25519KeyPair(privateName, privatePrefix, publicName, environment) {
  const privateValue = requireEnvironmentValue(privateName, environment);
  if (!privateValue.startsWith(privatePrefix)) {
    throw new Error(`${privateName} must use the ${privatePrefix} format`);
  }
  const privateKeyHex = privateValue.slice(privatePrefix.length);
  if (!/^[0-9a-f]{64}$/u.test(privateKeyHex)) {
    throw new Error(`${privateName} must contain 32 lowercase hexadecimal bytes`);
  }
  const expectedPublicKey = requireEnvironmentValue(publicName, environment);
  const derivedPublicKey = deriveX25519PublicKey(privateKeyHex);
  if (derivedPublicKey !== expectedPublicKey) {
    throw new Error(`${privateName} does not match ${publicName}`);
  }
}

function deriveX25519PublicKey(privateKeyHex) {
  // Node imports a raw X25519 scalar after it is wrapped in the fixed PKCS#8 header.
  const pkcs8Prefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.from(privateKeyHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return `x25519:${publicKey.subarray(-32).toString('hex')}`;
}

function deploySigningWorker(lane) {
  const resource = lane.resources.signingWorker;
  putWorkerSecret(resource, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  putWorkerSecret(resource, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY');
  putWorkerSecret(resource, 'SIGNING_WORKER_PRIVATE_D1_KEK');
  const configPath = renderPrivateD1WorkerConfig(lane, resource, 'signing-worker');
  migratePrivateD1(resource, configPath, 'signing-worker');
  const args = workerDeployArguments(resource, configPath);
  args.push(
    '--var',
    `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:${requireEnvironmentValue('SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY')}`,
    '--var',
    `SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY:${requireEnvironmentValue('SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY')}`,
    '--var',
    `SIGNING_WORKER_PRIVATE_D1_KEK_VERSION:${requireEnvironmentValue('SIGNING_WORKER_PRIVATE_D1_KEK_VERSION')}`,
    '--var',
    `SIGNING_WORKER_PRIVATE_D1_ENVIRONMENT:${lane.id}`,
  );
  runRouterCommand(args);
}

function deployDeriver(lane, role) {
  const resource = role === 'a' ? lane.resources.deriverA : lane.resources.deriverB;
  const prefix = role === 'a' ? 'DERIVER_A' : 'DERIVER_B';
  putWorkerSecret(resource, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  putWorkerSecret(resource, `${prefix}_ROOT_SHARE_WIRE_SECRET`);
  putWorkerSecret(resource, `${prefix}_ENVELOPE_HPKE_PRIVATE_KEY`);
  putWorkerSecret(resource, `${prefix}_PEER_SIGNING_KEY`);
  putWorkerSecret(resource, `${prefix}_ROLE_PRIVATE_D1_KEK`);
  const component = `deriver-${role}`;
  const configPath = renderPrivateD1WorkerConfig(lane, resource, component);
  migratePrivateD1(resource, configPath, component);
  const args = workerDeployArguments(resource, configPath);
  args.push(
    '--var',
    `${prefix}_ENVELOPE_HPKE_PUBLIC_KEY:${requireEnvironmentValue(`${prefix}_ENVELOPE_HPKE_PUBLIC_KEY`)}`,
    '--var',
    `DERIVER_A_PEER_VERIFYING_KEY_HEX:${requireEnvironmentValue('DERIVER_A_PEER_VERIFYING_KEY_HEX')}`,
    '--var',
    `DERIVER_B_PEER_VERIFYING_KEY_HEX:${requireEnvironmentValue('DERIVER_B_PEER_VERIFYING_KEY_HEX')}`,
    '--var',
    `DERIVER_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY:${requireEnvironmentValue(`${prefix}_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY`)}`,
    '--var',
    `DERIVER_ROLE_PRIVATE_D1_KEK_VERSION:${requireEnvironmentValue(`${prefix}_ROLE_PRIVATE_D1_KEK_VERSION`)}`,
    '--var',
    `DERIVER_ROLE_PRIVATE_D1_ENVIRONMENT:${lane.id}`,
  );
  runRouterCommand(args);
}

function deployMpcRouter(lane) {
  const resource = lane.resources.router;
  putWorkerSecret(resource, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  const args = workerDeployArguments(resource);
  args.push(
    '--var',
    `ROUTER_JWT_ISSUER:${lane.gatewayOrigin}`,
    '--var',
    'ROUTER_JWT_AUDIENCE:router-ab',
    '--var',
    `ROUTER_JWT_JWKS_JSON:${requireEnvironmentValue('ROUTER_AB_JWT_JWKS_JSON')}`,
    '--var',
    `DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY:${requireEnvironmentValue('DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY')}`,
    '--var',
    `DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY:${requireEnvironmentValue('DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY')}`,
    '--var',
    `DERIVER_A_PEER_VERIFYING_KEY_HEX:${requireEnvironmentValue('DERIVER_A_PEER_VERIFYING_KEY_HEX')}`,
    '--var',
    `DERIVER_B_PEER_VERIFYING_KEY_HEX:${requireEnvironmentValue('DERIVER_B_PEER_VERIFYING_KEY_HEX')}`,
    '--var',
    `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:${requireEnvironmentValue('SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY')}`,
  );
  if (lane.network === 'mainnet') {
    args.push(
      '--var',
      `ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON:${requireEnvironmentValue('ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON')}`,
    );
  }
  runRouterCommand(args);
}

function consoleConfigPath(laneId) {
  return path.join(GATEWAY_GENERATED_ROOT, `console.${laneId}.jsonc`);
}

function consoleSecretsPath(laneId) {
  return path.join(GATEWAY_GENERATED_ROOT, `console-secrets.${laneId}.json`);
}

function walletRuntimeConfigPath(laneId) {
  return path.join(GATEWAY_GENERATED_ROOT, `wallet-runtime.${laneId}.jsonc`);
}

function walletRuntimeSecretsPath(laneId) {
  return path.join(GATEWAY_GENERATED_ROOT, `wallet-runtime-secrets.${laneId}.json`);
}

// Wallet Runtime deploys before Console, and Console deploys before Gateway,
// so each service-binding target exists before its caller is uploaded.
function deployConsole(lane) {
  const consoleConfig = consoleConfigPath(lane.id);
  const consoleSecrets = consoleSecretsPath(lane.id);
  runCommand(
    'node',
    [
      'scripts/render-d1-gateway-config.mjs',
      '--lane',
      lane.id,
      '--worker',
      'console',
      '--output',
      consoleConfig,
    ],
    { cwd: GATEWAY_ROOT },
  );
  runCommand(
    'node',
    ['scripts/write-gateway-secrets-file.mjs', '--output', consoleSecrets, '--profile', 'console'],
    {
      cwd: GATEWAY_ROOT,
      env: buildEnvironment({ DEPLOYMENT_LANE: lane.id }),
    },
  );
  assertFile(CONSOLE_BUNDLE, 'Console build entry');
  runCommand(
    'pnpm',
    [
      'exec',
      'wrangler',
      'deploy',
      CONSOLE_BUNDLE,
      '--no-bundle',
      '--config',
      consoleConfig,
      '--secrets-file',
      consoleSecrets,
      '--message',
      process.env.DEPLOY_SHA || `runtime-${lane.id}`,
    ],
    { cwd: GATEWAY_ROOT },
  );
}

function deployWalletRuntime(lane) {
  const runtimeConfig = walletRuntimeConfigPath(lane.id);
  const runtimeSecrets = walletRuntimeSecretsPath(lane.id);
  renderWalletRuntimeConfig(lane.id, runtimeConfig);
  assertFile(WALLET_RUNTIME_BUNDLE, 'Wallet Runtime build entry');
  runCommand('node', ['scripts/write-gateway-secrets-file.mjs', '--output', runtimeSecrets], {
    cwd: GATEWAY_ROOT,
    env: buildEnvironment({ DEPLOYMENT_LANE: lane.id }),
  });
  runCommand(
    'pnpm',
    [
      'exec',
      'wrangler',
      'deploy',
      WALLET_RUNTIME_BUNDLE,
      '--no-bundle',
      '--config',
      runtimeConfig,
      '--secrets-file',
      runtimeSecrets,
      '--message',
      process.env.DEPLOY_SHA || `runtime-${lane.id}`,
    ],
    { cwd: GATEWAY_ROOT },
  );
}

function deployGateway(lane) {
  const gatewayConfig = gatewayConfigPath(lane.id);
  const gatewaySecrets = gatewaySecretsPath(lane.id);
  renderGatewayConfig(lane.id, gatewayConfig);
  assertFile(GATEWAY_BUNDLE, 'Gateway build entry');
  runCommand('node', ['scripts/write-gateway-secrets-file.mjs', '--output', gatewaySecrets], {
    cwd: GATEWAY_ROOT,
    env: buildEnvironment({ DEPLOYMENT_LANE: lane.id }),
  });
  runCommand(
    'pnpm',
    [
      'exec',
      'wrangler',
      'deploy',
      GATEWAY_BUNDLE,
      '--no-bundle',
      '--config',
      gatewayConfig,
      '--secrets-file',
      gatewaySecrets,
      '--message',
      process.env.DEPLOY_SHA || `runtime-${lane.id}`,
    ],
    { cwd: GATEWAY_ROOT },
  );
}

function workerDeployArguments(resource, renderedConfigPath) {
  const configPath = renderedConfigPath || routerConfigPath(resource);
  assertFile(configPath, `Wrangler config for ${resource.workerName}`);
  const args = ['exec', 'wrangler', 'deploy', '--config', configPath];
  if (resource.deploymentEnvironment.kind === 'named') {
    args.push('--env', resource.deploymentEnvironment.name);
  }
  return args;
}

function renderPrivateD1WorkerConfig(lane, resource, component) {
  const deployment = PRIVATE_D1_DEPLOYMENTS[component];
  if (!deployment) throw new Error(`Private D1 deployment is missing for ${component}`);
  const sourcePath = routerConfigPath(resource);
  assertFile(sourcePath, `Wrangler config for ${resource.workerName}`);
  const placeholder = deployment.placeholders[lane.id];
  if (!placeholder) {
    throw new Error(`Private D1 placeholder is missing for ${lane.id}/${component}`);
  }
  const databaseId = requireDatabaseId(
    requireEnvironmentValue(deployment.databaseIdEnvironment),
    deployment.databaseIdEnvironment,
  );
  const source = fs.readFileSync(sourcePath, 'utf8');
  if (!source.includes(`database_id = "${placeholder}"`)) {
    throw new Error(`${sourcePath} is missing the ${lane.id} private D1 placeholder`);
  }
  const rendered = source.replace(
    `database_id = "${placeholder}"`,
    `database_id = "${databaseId}"`,
  );
  const outputPath = path.join(
    path.dirname(sourcePath),
    `.wrangler.generated.${component}.${lane.id}.toml`,
  );
  fs.writeFileSync(outputPath, rendered, { mode: 0o600 });
  return outputPath;
}

function requireDatabaseId(value, name) {
  const normalized = String(value || '').trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(normalized)) {
    throw new Error(`${name} must be a Cloudflare D1 database ID`);
  }
  if (/^0{8}-0{4}-0{4}-0{4}-0{12}$/u.test(normalized)) {
    throw new Error(`${name} must not be all zeroes`);
  }
  return normalized;
}

function migratePrivateD1(resource, configPath, component) {
  const deployment = PRIVATE_D1_DEPLOYMENTS[component];
  const args = [
    'exec',
    'wrangler',
    'd1',
    'migrations',
    'apply',
    deployment.binding,
    '--remote',
    '--config',
    configPath,
  ];
  if (resource.deploymentEnvironment.kind === 'named') {
    args.push('--env', resource.deploymentEnvironment.name);
  }
  runRouterCommand(args);
}

function putWorkerSecret(resource, name) {
  const args = ['exec', 'wrangler', 'secret', 'put', name, '--config', routerConfigPath(resource)];
  if (resource.deploymentEnvironment.kind === 'named') {
    args.push('--env', resource.deploymentEnvironment.name);
  }
  runCommandWithInput('pnpm', args, requireEnvironmentValue(name), { cwd: ROUTER_ROOT });
}

function runRouterCommand(args) {
  runCommand('pnpm', args, { cwd: ROUTER_ROOT });
}

async function smokeBackend(lane) {
  const checks = [];
  const consoleOrigin = consoleOriginFor(lane.gatewayOrigin);
  for (const requestPath of BACKEND_SMOKE_PATHS) {
    checks.push({
      name: requestPath,
      url: new URL(requestPath, lane.gatewayOrigin).toString(),
    });
  }
  checks.push({
    name: 'Console /readyz',
    url: new URL('/readyz', consoleOrigin).toString(),
  });
  checks.push({
    name: '/console/session CORS preflight',
    url: new URL('/console/session', consoleOrigin).toString(),
    request: {
      method: 'OPTIONS',
      headers: {
        Origin: lane.site.origin,
        'Access-Control-Request-Method': 'GET',
      },
    },
    isReady: isDashboardConsoleCorsPreflight.bind(null, lane.site.origin),
  });
  const results = await runReadinessChecks(checks);
  const failed = results.filter(isFailedCheck);
  process.stdout.write(`${JSON.stringify({ results })}\n`);
  if (failed.length > 0) {
    throw new Error(
      `backend smoke failed for ${lane.id}: ${failed.map(formatFailedCheck).join(', ')}`,
    );
  }
}

function isDashboardConsoleCorsPreflight(dashboardOrigin, response) {
  return (
    response.status === 204 &&
    response.headers.get('Access-Control-Allow-Origin') === dashboardOrigin &&
    response.headers.get('Access-Control-Allow-Credentials') === 'true'
  );
}

function gatewayConfigPath(laneId) {
  return path.join(GATEWAY_GENERATED_ROOT, `gateway.${laneId}.jsonc`);
}

function gatewaySecretsPath(laneId) {
  return path.join(GATEWAY_GENERATED_ROOT, `gateway-secrets.${laneId}.json`);
}

function renderGatewayConfig(laneId, outputPath) {
  runCommand(
    'node',
    ['scripts/render-d1-gateway-config.mjs', '--lane', laneId, '--output', outputPath],
    { cwd: GATEWAY_ROOT },
  );
}

function renderConsoleConfig(laneId, outputPath) {
  runCommand(
    'node',
    [
      'scripts/render-d1-gateway-config.mjs',
      '--lane',
      laneId,
      '--worker',
      'console',
      '--output',
      outputPath,
    ],
    { cwd: GATEWAY_ROOT },
  );
}

function renderWalletRuntimeConfig(laneId, outputPath) {
  runCommand(
    'node',
    [
      'scripts/render-d1-gateway-config.mjs',
      '--lane',
      laneId,
      '--worker',
      'wallet-runtime',
      '--output',
      outputPath,
    ],
    { cwd: GATEWAY_ROOT },
  );
}

function requireEnvironmentValues(names, environment = process.env) {
  for (const name of names) requireEnvironmentValue(name, environment);
}

function requireEnvironmentValue(name, environment = process.env) {
  const value = String(environment[name] || '').trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function buildEnvironment(overrides) {
  return { ...process.env, ...overrides };
}

function runCommand(command, args, options = {}) {
  const child = spawnSync(command, args, {
    cwd: options.cwd || REPOSITORY_ROOT,
    env: options.env || process.env,
    encoding: 'utf8',
    stdio: 'inherit',
  });
  if (child.error) throw child.error;
  if (child.status !== 0)
    throw new Error(`${command} ${args.join(' ')} failed with status ${child.status}`);
}

function runCommandWithInput(command, args, input, options = {}) {
  const child = spawnSync(command, args, {
    cwd: options.cwd || REPOSITORY_ROOT,
    env: options.env || process.env,
    encoding: 'utf8',
    input: `${input}\n`,
    stdio: ['pipe', 'inherit', 'inherit'],
  });
  if (child.error) throw child.error;
  if (child.status !== 0)
    throw new Error(`${command} ${args.join(' ')} failed with status ${child.status}`);
}

function assertFile(filePath, label) {
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    throw new Error(`${label} is missing: ${filePath}`);
  }
}

function unique(values) {
  return [...new Set(values)];
}

function formatError(error) {
  return error instanceof Error ? error.message : String(error);
}

function handleFailure(error) {
  process.stderr.write(`${formatError(error)}\n`);
  process.exitCode = 1;
}
