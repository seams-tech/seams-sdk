#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readFrontendSite } from './deployment-targets.mjs';
import { formatFailedCheck, isFailedCheck, runReadinessChecks } from './deployment-smoke.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, '..');
const ROUTER_ROOT = path.join(REPOSITORY_ROOT, 'crates', 'router-ab-cloudflare');
const SITE_ROOT = path.join(REPOSITORY_ROOT, 'apps', 'seams-site');
const SITE_OUTPUT = path.join(SITE_ROOT, 'dist');
const SDK_OUTPUT = path.join(REPOSITORY_ROOT, 'packages', 'sdk-web', 'dist');
const DEFAULT_DOCS_ORIGIN = 'https://docs.localhost';
const FRONTEND_SMOKE_PATHS = Object.freeze({
  site: ['/', '/sdk/workers/near-signer.worker.js'],
  wallet: [
    '/',
    '/wallet-service/index.html',
    '/sdk/workers/near-signer.worker.js',
    '/sdk/workers/router_ab_ed25519_yao_client_bg.wasm',
  ],
});

main(process.argv.slice(2)).catch(handleFailure);

async function main(args) {
  const options = parseArguments(args);
  const site = readFrontendSite(options.site);
  if (options.operation !== 'plan') {
    assertSiteProvisioning(site);
    assertDeploymentBranch(site);
  }
  switch (options.operation) {
    case 'plan':
      printPlan(site);
      return;
    case 'build':
      buildFrontend(site);
      return;
    case 'deploy':
      deployFrontend(site);
      return;
    case 'smoke':
      await smokeFrontend(site);
      return;
    default:
      throw new Error(`Unsupported frontend operation: ${options.operation}`);
  }
}

function parseArguments(args) {
  const operation = String(args[0] || '').trim();
  let siteId = '';
  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--site') {
      siteId = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--component') {
      throw new Error('--component is not allowed for frontend operations');
    }
    throw new Error('usage: deploy-frontend.mjs <plan|build|deploy|smoke> --site <site>');
  }
  if (!['plan', 'build', 'deploy', 'smoke'].includes(operation)) {
    throw new Error('usage: deploy-frontend.mjs <plan|build|deploy|smoke> --site <site>');
  }
  if (!siteId)
    throw new Error('--site is required (usage: deploy-frontend.mjs <operation> --site <site>)');
  return { operation, site: siteId };
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  return value;
}

function printPlan(site) {
  const lines = [
    `Frontend deployment plan: ${site.id}`,
    `Branch: ${site.branch}`,
    `Site: ${site.origin}`,
    `Default network: ${site.defaultNetwork}`,
    `Available networks: ${site.availableNetworks.join(', ')}`,
    `Pages project environment: ${site.pagesProjectEnv}`,
    ...site.lanes.flatMap((lane) => [
      `Gateway (${lane.network}): ${lane.gatewayOrigin}`,
      `Wallet (${lane.network}): ${lane.walletOrigin}`,
      `Wallet Pages project environment (${lane.network}): ${lane.walletPagesProjectEnv}`,
    ]),
    ...formatLaneProvisioning(site.lanes),
    '',
    'Order:',
    '  1. build production SDK and Pages output once',
    '  2. deploy the app Pages project',
    '  3. deploy one wallet Pages project for every declared network',
    '  4. smoke app, SDK, and every wallet origin',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

function formatLaneProvisioning(lanes) {
  const lines = [];
  for (const lane of lanes) {
    if (lane.provisioning.kind === 'provisioned') {
      lines.push(`Provisioning (${lane.id}): provisioned`);
      continue;
    }
    lines.push(
      `Provisioning (${lane.id}): pending (${lane.provisioning.requiredValues.join(', ')})`,
    );
  }
  return lines;
}

function buildFrontend(site) {
  runCommand('pnpm', ['install', '--frozen-lockfile']);
  const buildEnvironment = buildFrontendEnvironment(site);
  runCommand('pnpm', ['-C', 'packages/sdk-web', 'run', 'build:prod'], {
    env: buildEnvironment,
  });
  runCommand('pnpm', ['-C', 'apps/seams-site', 'exec', 'vite', 'build'], {
    env: buildEnvironment,
  });
  copySdkAssets();
  assertDirectory(SITE_OUTPUT, 'Pages build output');
  assertFile(path.join(SITE_OUTPUT, 'wallet-service', 'index.html'), 'wallet-service entry');
}

function buildFrontendEnvironment(site) {
  const environment = {
    ...process.env,
    VITE_SITE_ID: site.id,
    VITE_SITE_ORIGIN: site.origin,
    VITE_DOCS_ORIGIN: String(process.env.VITE_DOCS_ORIGIN || '').trim() || DEFAULT_DOCS_ORIGIN,
  };
  for (const lane of site.lanes) {
    const prefix = site.id === 'production' ? `VITE_${lane.network.toUpperCase()}_` : 'VITE_';
    environment[`${prefix}RELAYER_URL`] = lane.gatewayOrigin;
    environment[`${prefix}CONSOLE_BASE_URL`] = lane.gatewayOrigin;
    environment[`${prefix}WALLET_ORIGIN`] = lane.walletOrigin;
    environment[`${prefix}RP_ID_BASE`] = new URL(lane.walletOrigin).hostname;
    environment[`${prefix}ROUTER_AB_NORMAL_SIGNING_WORKER_ID`] =
      lane.resources.signingWorker.workerName;
    if (site.id === 'staging') {
      requireEnvironmentValues(
        [
          'VITE_SEAMS_PROJECT_ENVIRONMENT_ID',
          'VITE_SEAMS_PUBLISHABLE_KEY',
          'VITE_NEAR_NETWORK',
          'VITE_NEAR_RPC_URL',
          'VITE_NEAR_EXPLORER',
          'VITE_SIGNING_SESSION_PERSISTENCE_MODE',
        ],
        environment,
      );
      continue;
    }
    requireEnvironmentValues(
      [
        `${prefix}SEAMS_PROJECT_ENVIRONMENT_ID`,
        `${prefix}SEAMS_PUBLISHABLE_KEY`,
        `${prefix}NEAR_NETWORK`,
        `${prefix}NEAR_RPC_URL`,
        `${prefix}NEAR_EXPLORER`,
        `${prefix}SIGNING_SESSION_PERSISTENCE_MODE`,
      ],
      environment,
    );
  }
  return environment;
}

function copySdkAssets() {
  const sdkEsm = path.join(SDK_OUTPUT, 'esm', 'sdk');
  const sdkWorkers = path.join(SDK_OUTPUT, 'workers');
  const walletService = path.join(SDK_OUTPUT, 'public', 'wallet-service');
  assertDirectory(sdkEsm, 'SDK ESM output');
  assertFile(path.join(walletService, 'index.html'), 'SDK wallet-service output');
  copyDirectory(sdkEsm, path.join(SITE_OUTPUT, 'sdk'));
  if (fs.existsSync(sdkWorkers))
    copyDirectory(sdkWorkers, path.join(SITE_OUTPUT, 'sdk', 'workers'));
  copyDirectory(walletService, path.join(SITE_OUTPUT, 'wallet-service'));
}

function copyDirectory(source, destination) {
  fs.mkdirSync(destination, { recursive: true });
  runCommand('rsync', ['-a', '--delete', `${source}${path.sep}`, `${destination}${path.sep}`]);
}

function deployFrontend(site) {
  requireEnvironmentValues(['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'], process.env);
  const walletProjectEnvironments = site.lanes.map((lane) => lane.walletPagesProjectEnv);
  requireEnvironmentValues(
    [site.pagesProjectEnv, ...new Set(walletProjectEnvironments)],
    process.env,
  );
  assertDirectory(SITE_OUTPUT, 'Pages build output');
  const commonArguments = [
    'pages',
    'deploy',
    path.relative(ROUTER_ROOT, SITE_OUTPUT),
    '--branch',
    site.branch,
    '--commit-dirty=false',
  ];
  const sourceSha = String(process.env.DEPLOY_SHA || '').trim();
  if (sourceSha) commonArguments.push('--commit-hash', sourceSha);
  deployPagesProject(commonArguments, process.env[site.pagesProjectEnv]);
  for (const lane of site.lanes) {
    deployPagesProject(commonArguments, process.env[lane.walletPagesProjectEnv]);
  }
  process.stdout.write(`Frontend deploy completed: ${site.id}\n`);
}

function deployPagesProject(commonArguments, projectName) {
  const args = ['exec', 'wrangler', ...commonArguments, '--project-name', projectName];
  runCommand('pnpm', args, { cwd: ROUTER_ROOT });
}

async function smokeFrontend(site) {
  const checks = buildSmokeChecks(site);
  const results = await runReadinessChecks(checks);
  const failed = results.filter(isFailedCheck);
  process.stdout.write(`${JSON.stringify({ results })}\n`);
  if (failed.length > 0) {
    throw new Error(`frontend smoke failed: ${failed.map(formatFailedCheck).join(', ')}`);
  }
}

function buildSmokeChecks(site) {
  const checks = [];
  addSmokeChecks(checks, 'site', site.origin, FRONTEND_SMOKE_PATHS.site);
  for (const lane of site.lanes) {
    addSmokeChecks(
      checks,
      `wallet-${lane.network}`,
      lane.walletOrigin,
      FRONTEND_SMOKE_PATHS.wallet,
    );
  }
  return checks;
}

function assertSiteProvisioning(site) {
  const pending = pendingProvisioningLanes(site.lanes);
  if (pending.length === 0) return;
  const details = pending.map(formatPendingProvisioningLane).join('; ');
  throw new Error(`frontend site ${site.id} has pending lane provisioning: ${details}`);
}

function pendingProvisioningLanes(lanes) {
  const pending = [];
  for (const lane of lanes) {
    if (lane.provisioning.kind === 'pending') pending.push(lane);
  }
  return pending;
}

function formatPendingProvisioningLane(lane) {
  return `${lane.id} (${lane.provisioning.requiredValues.join(', ')})`;
}

function assertDeploymentBranch(site) {
  const ref = resolveDeploymentRef();
  if (!ref) return;
  const expectedRef = `refs/heads/${site.branch}`;
  if (ref !== expectedRef) {
    throw new Error(`site ${site.id} requires branch ${site.branch}; received ${ref}`);
  }
}

function resolveDeploymentRef() {
  const ref = String(process.env.GITHUB_REF || '').trim();
  if (ref) return ref;
  const branch = String(process.env.GITHUB_REF_NAME || '').trim();
  return branch ? `refs/heads/${branch}` : '';
}

function addSmokeChecks(checks, surface, origin, requestPaths) {
  for (const requestPath of requestPaths) {
    checks.push({
      name: `${surface}${requestPath}`,
      url: new URL(requestPath, origin).toString(),
    });
  }
}

function requireEnvironmentValues(names, environment) {
  for (const name of names) {
    const value = String(environment[name] || '').trim();
    if (!value) throw new Error(`${name} is required`);
  }
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

function assertDirectory(directory, label) {
  if (!fs.existsSync(directory) || !fs.statSync(directory).isDirectory()) {
    throw new Error(`${label} is missing: ${directory}`);
  }
}

function assertFile(filePath, label) {
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    throw new Error(`${label} is missing: ${filePath}`);
  }
}

function formatError(error) {
  return error instanceof Error ? error.message : String(error);
}

function handleFailure(error) {
  process.stderr.write(`${formatError(error)}\n`);
  process.exitCode = 1;
}
