#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  BACKEND_COMPONENTS,
  componentSecretNames,
  readDeploymentTarget,
} from './deployment-targets.mjs';
import { readMigrationSet } from './migration-fingerprint.mjs';
import { formatFailedCheck, isFailedCheck, runReadinessChecks } from './deployment-smoke.mjs';
import {
  GATEWAY_WORKER_COMPATIBILITY_DATE,
  GATEWAY_WORKER_COMPATIBILITY_FLAGS,
} from '../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, '..');
const ROUTER_ROOT = path.join(REPOSITORY_ROOT, 'crates', 'router-ab-cloudflare');
const GATEWAY_ROOT = path.join(REPOSITORY_ROOT, 'packages', 'console-server-ts');
const GATEWAY_BUILD_CONFIG = path.join(
  GATEWAY_ROOT,
  '.wrangler',
  'generated',
  'gateway-build.jsonc',
);
const GATEWAY_CONFIG = path.join(GATEWAY_ROOT, '.wrangler', 'generated', 'gateway.jsonc');
const GATEWAY_PLAN = path.join(
  GATEWAY_ROOT,
  '.wrangler',
  'generated',
  'gateway-deployment-plan.json',
);
const GATEWAY_SECRETS = path.join(GATEWAY_ROOT, '.wrangler', 'generated', 'gateway-secrets.json');
const GATEWAY_BUNDLE = path.join(
  REPOSITORY_ROOT,
  '.release-artifacts',
  'gateway',
  'payload',
  'd1RouterApiWorker.js',
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
    productionPlaceholder: '00000000-0000-0000-0000-0000000094c1',
    stagingPlaceholder: '00000000-0000-0000-0000-0000000094c2',
  }),
  'deriver-a': Object.freeze({
    binding: 'DERIVER_ROLE_PRIVATE_DB',
    databaseIdEnvironment: 'DERIVER_A_PRIVATE_D1_ID',
    productionPlaceholder: '00000000-0000-0000-0000-0000000094a1',
    stagingPlaceholder: '00000000-0000-0000-0000-0000000094a2',
  }),
  'deriver-b': Object.freeze({
    binding: 'DERIVER_ROLE_PRIVATE_DB',
    databaseIdEnvironment: 'DERIVER_B_PRIVATE_D1_ID',
    productionPlaceholder: '00000000-0000-0000-0000-0000000094b1',
    stagingPlaceholder: '00000000-0000-0000-0000-0000000094b2',
  }),
});

main(process.argv.slice(2)).catch(handleFailure);

async function main(args) {
  const options = parseArguments(args);
  const target = readDeploymentTarget(options.target);
  switch (options.operation) {
    case 'plan':
      printPlan(options.target, target);
      return;
    case 'build':
      buildBackend();
      return;
    case 'preflight':
      preflightBackend(options.target, target, options.component, readPreflightEnvironment());
      return;
    case 'migrate':
      migrateBackend(options.target);
      return;
    case 'deploy':
      deployBackend(options.target, target, options.component);
      return;
    case 'smoke':
      await smokeBackend(target);
      return;
    default:
      throw new Error(`Unsupported backend operation: ${options.operation}`);
  }
}

function parseArguments(args) {
  const operation = String(args[0] || '').trim();
  const options = { operation, target: '', component: '' };
  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--target') {
      options.target = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--component') {
      options.component = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(
      `usage: deploy-backend.mjs <plan|build|preflight|migrate|deploy|smoke> --target <target>`,
    );
  }
  if (!['plan', 'build', 'preflight', 'migrate', 'deploy', 'smoke'].includes(operation)) {
    throw new Error(
      'usage: deploy-backend.mjs <plan|build|preflight|migrate|deploy|smoke> --target <target>',
    );
  }
  if (!options.target)
    throw new Error(
      '--target is required (usage: deploy-backend.mjs <operation> --target <target>)',
    );
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

function printPlan(targetName, target) {
  const lines = [
    `Backend deployment plan: ${targetName}`,
    `Branch: ${target.branch}`,
    `Gateway: ${target.resources.gateway.workerName}`,
    `Gateway origin: ${target.origins.gateway}`,
    `Capabilities: ${formatCapabilities(target)}`,
    '',
    'Order:',
    '  1. build all backend components once and require the target branch',
    '  2. preflight all five backend custody components',
    `  3. migrate ${target.resources.gateway.consoleD1Name} (console D1)`,
    `  4. migrate ${target.resources.gateway.signerD1Name} (signer D1)`,
    '  5. migrate and deploy signing-worker, deriver-a, and deriver-b concurrently',
    '  6. deploy router after all three workers complete',
    '  7. upsert Gateway signing-root KEK',
    '  8. deploy gateway',
    '  9. smoke Gateway and Router A/B endpoints',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

function formatCapabilities(target) {
  const names = ['billing', 'sponsoredExecution', 'signingSessionSeal'];
  const values = [];
  for (const name of names) {
    values.push(`${name}=${target.capabilities[name].enabled ? 'enabled' : 'disabled'}`);
  }
  return values.join(', ');
}

function buildBackend() {
  runCommand('pnpm', ['install', '--frozen-lockfile']);
  runCommand('pnpm', ['-C', 'crates/router-ab-cloudflare', 'run', 'worker-build:install']);
  const routerEnvironment = buildEnvironment({ ROUTER_AB_WORKER_BUILD_PROFILE: 'release' });
  for (const role of ['signing-worker', 'deriver-a', 'deriver-b', 'router']) {
    runCommand('pnpm', ['-C', 'crates/router-ab-cloudflare', 'run', `build:${role}`], {
      env: routerEnvironment,
    });
  }
  runCommand('bash', ['packages/sdk-web/scripts/build/install-ci-wasm-tooling.sh']);
  const sdkWasmEnvironment = buildEnvironment({
    WASM_SDK_BUILD_MODE: 'prod',
    WASM_SDK_BUILD_TARGET: 'all',
  });
  runCommand('pnpm', ['-C', 'packages/sdk-web', 'run', 'build:wasm'], {
    env: sdkWasmEnvironment,
  });
  runCommand('pnpm', ['-C', 'packages/sdk-server-ts', 'build']);
  runCommand('pnpm', ['-C', 'packages/console-server-ts', 'run', 'd1:local:ensure-wasm'], {
    env: sdkWasmEnvironment,
  });
  writeGatewayBuildConfig();
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
}

function writeGatewayBuildConfig() {
  const config = {
    name: 'seams-sdk-d1-gateway-build',
    main: path.join(GATEWAY_ROOT, 'src/router/cloudflare/d1RouterApiWorker.ts'),
    compatibility_date: GATEWAY_WORKER_COMPATIBILITY_DATE,
    compatibility_flags: GATEWAY_WORKER_COMPATIBILITY_FLAGS,
  };
  fs.mkdirSync(path.dirname(GATEWAY_BUILD_CONFIG), { recursive: true });
  fs.writeFileSync(GATEWAY_BUILD_CONFIG, `${JSON.stringify(config, null, 2)}\n`, {
    mode: 0o600,
  });
}

function preflightBackend(targetName, target, component, environment = process.env) {
  const requiredNames = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'];
  requiredNames.push(...componentSecretNames(target, component));
  for (const name of componentRuntimeRequirements(targetName, target, component)) {
    requiredNames.push(name);
  }
  if (component === 'gateway') {
    requiredNames.push('SIGNING_ROOT_KEK_VALUE');
    const config = target.gatewayDeploymentConfig;
    if (config.optional.nearRelayer) requiredNames.push('RELAYER_PRIVATE_KEY');
  }
  requireEnvironmentValues(unique(requiredNames), environment);
  if (component === 'gateway') warnDisabledGatewayIntegrations(environment);
  process.stdout.write(`Preflight passed: ${targetName}/${component}\n`);
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

function componentRuntimeRequirements(targetName, target, component) {
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
        ...(targetName === 'production' ? ['ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON'] : []),
      ];
    case 'gateway':
      return [];
    default:
      throw new Error(`Unsupported backend component: ${component}`);
  }
}

function migrateBackend(targetName) {
  requireEnvironmentValues(['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID']);
  renderGatewayConfig(targetName);
  const migrations = [
    ['CONSOLE_DB', path.join(GATEWAY_ROOT, 'migrations', 'd1-console')],
    ['SIGNER_DB', path.join(GATEWAY_ROOT, '..', 'sdk-server-ts', 'migrations', 'd1-signer')],
  ];
  for (const [database, migrationsDirectory] of migrations) {
    const fingerprint = readMigrationSet(migrationsDirectory).fingerprint;
    runCommand(
      'node',
      [
        'scripts/apply-remote-d1-migrations.mjs',
        '--database',
        database,
        '--config',
        GATEWAY_CONFIG,
        '--migrations-dir',
        migrationsDirectory,
        '--expected-fingerprint',
        fingerprint,
      ],
      { cwd: GATEWAY_ROOT },
    );
  }
}

function deployBackend(targetName, target, component) {
  preflightBackend(targetName, target, component);
  switch (component) {
    case 'signing-worker':
      deploySigningWorker(targetName, target);
      return;
    case 'deriver-a':
      deployDeriver(targetName, target, 'a');
      return;
    case 'deriver-b':
      deployDeriver(targetName, target, 'b');
      return;
    case 'router':
      deployMpcRouter(targetName, target);
      return;
    case 'gateway':
      deployGateway(targetName);
      return;
    default:
      throw new Error(`Unsupported backend component: ${component}`);
  }
}

function deploySigningWorker(targetName, target) {
  const resource = target.resources.signingWorker;
  putWorkerSecret(resource, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  putWorkerSecret(resource, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY');
  putWorkerSecret(resource, 'SIGNING_WORKER_PRIVATE_D1_KEK');
  const configPath = renderPrivateD1WorkerConfig(targetName, resource, 'signing-worker');
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
    `SIGNING_WORKER_PRIVATE_D1_ENVIRONMENT:${targetName}`,
  );
  runRouterCommand(args);
}

function deployDeriver(targetName, target, role) {
  const resource = role === 'a' ? target.resources.deriverA : target.resources.deriverB;
  const prefix = role === 'a' ? 'DERIVER_A' : 'DERIVER_B';
  putWorkerSecret(resource, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  putWorkerSecret(resource, `${prefix}_ROOT_SHARE_WIRE_SECRET`);
  putWorkerSecret(resource, `${prefix}_ENVELOPE_HPKE_PRIVATE_KEY`);
  putWorkerSecret(resource, `${prefix}_PEER_SIGNING_KEY`);
  putWorkerSecret(resource, `${prefix}_ROLE_PRIVATE_D1_KEK`);
  const component = `deriver-${role}`;
  const configPath = renderPrivateD1WorkerConfig(targetName, resource, component);
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
    `DERIVER_ROLE_PRIVATE_D1_ENVIRONMENT:${targetName}`,
  );
  runRouterCommand(args);
}

function deployMpcRouter(targetName, target) {
  const resource = target.resources.router;
  putWorkerSecret(resource, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET');
  const args = workerDeployArguments(resource);
  args.push(
    '--var',
    `ROUTER_JWT_ISSUER:${target.origins.gateway}`,
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
  if (targetName === 'production') {
    args.push(
      '--var',
      `ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON:${requireEnvironmentValue('ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON')}`,
    );
  }
  runRouterCommand(args);
}

function deployGateway(targetName) {
  renderGatewayConfig(targetName);
  assertFile(GATEWAY_BUNDLE, 'Gateway build entry');
  runCommand('node', ['scripts/upsert-signing-root-kek.mjs', '--plan', GATEWAY_PLAN], {
    cwd: GATEWAY_ROOT,
  });
  runCommand('node', ['scripts/write-gateway-secrets-file.mjs', '--output', GATEWAY_SECRETS], {
    cwd: GATEWAY_ROOT,
    env: buildEnvironment({ DEPLOY_TARGET: targetName }),
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
      GATEWAY_CONFIG,
      '--secrets-file',
      GATEWAY_SECRETS,
      '--message',
      process.env.DEPLOY_SHA || `runtime-${targetName}`,
    ],
    { cwd: GATEWAY_ROOT },
  );
}

function workerDeployArguments(resource, renderedConfigPath) {
  const configPath = renderedConfigPath || path.resolve(REPOSITORY_ROOT, resource.configPath);
  assertFile(configPath, `Wrangler config for ${resource.workerName}`);
  const args = ['exec', 'wrangler', 'deploy', '--config', configPath];
  if (resource.deploymentEnvironment.kind === 'named') {
    args.push('--env', resource.deploymentEnvironment.name);
  }
  return args;
}

function renderPrivateD1WorkerConfig(targetName, resource, component) {
  const deployment = PRIVATE_D1_DEPLOYMENTS[component];
  if (!deployment) throw new Error(`Private D1 deployment is missing for ${component}`);
  const sourcePath = path.resolve(REPOSITORY_ROOT, resource.configPath);
  assertFile(sourcePath, `Wrangler config for ${resource.workerName}`);
  const placeholder =
    targetName === 'staging' ? deployment.stagingPlaceholder : deployment.productionPlaceholder;
  const databaseId = requireEnvironmentValue(deployment.databaseIdEnvironment);
  const source = fs.readFileSync(sourcePath, 'utf8');
  if (!source.includes(`database_id = "${placeholder}"`)) {
    throw new Error(`${sourcePath} is missing the ${targetName} private D1 placeholder`);
  }
  const rendered = source.replace(
    `database_id = "${placeholder}"`,
    `database_id = "${databaseId}"`,
  );
  const outputPath = path.join(
    path.dirname(sourcePath),
    `.wrangler.generated.${component}.${targetName}.toml`,
  );
  fs.writeFileSync(outputPath, rendered, { mode: 0o600 });
  return outputPath;
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
  const args = [
    'exec',
    'wrangler',
    'secret',
    'put',
    name,
    '--config',
    path.resolve(REPOSITORY_ROOT, resource.configPath),
  ];
  if (resource.deploymentEnvironment.kind === 'named') {
    args.push('--env', resource.deploymentEnvironment.name);
  }
  runCommandWithInput('pnpm', args, requireEnvironmentValue(name), { cwd: ROUTER_ROOT });
}

function runRouterCommand(args) {
  runCommand('pnpm', args, { cwd: ROUTER_ROOT });
}

async function smokeBackend(target) {
  const checks = [];
  for (const requestPath of BACKEND_SMOKE_PATHS) {
    checks.push({
      name: requestPath,
      url: new URL(requestPath, target.origins.gateway).toString(),
    });
  }
  checks.push({
    name: '/console/session CORS preflight',
    url: new URL('/console/session', target.origins.gateway).toString(),
    request: {
      method: 'OPTIONS',
      headers: {
        Origin: target.origins.site,
        'Access-Control-Request-Method': 'GET',
      },
    },
    isReady: isDashboardConsoleCorsPreflight.bind(null, target.origins.site),
  });
  const results = await runReadinessChecks(checks);
  const failed = results.filter(isFailedCheck);
  process.stdout.write(`${JSON.stringify({ results })}\n`);
  if (failed.length > 0) {
    throw new Error(`backend smoke failed: ${failed.map(formatFailedCheck).join(', ')}`);
  }
}

function isDashboardConsoleCorsPreflight(dashboardOrigin, response) {
  return (
    response.status === 204 &&
    response.headers.get('Access-Control-Allow-Origin') === dashboardOrigin &&
    response.headers.get('Access-Control-Allow-Credentials') === 'true'
  );
}

function renderGatewayConfig(targetName) {
  runCommand(
    'node',
    [
      'scripts/render-d1-gateway-config.mjs',
      '--target',
      targetName,
      '--output',
      GATEWAY_CONFIG,
      '--deployment-plan-output',
      GATEWAY_PLAN,
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
