#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { readFrontendSite } from './deployment-targets.mjs';
import { formatFailedCheck, isFailedCheck, runReadinessChecks } from './deployment-smoke.mjs';
import { consoleOriginFor } from '../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, '..');
const ROUTER_ROOT = path.join(REPOSITORY_ROOT, 'crates', 'router-ab-cloudflare');
const SITE_ROOT = path.join(REPOSITORY_ROOT, 'apps', 'seams-site');
const SITE_OUTPUT = path.join(SITE_ROOT, 'dist');
const CONSOLE_ROOT = path.join(REPOSITORY_ROOT, 'apps', 'seams-console');
const CONSOLE_OUTPUT = path.join(CONSOLE_ROOT, 'dist');
const DOCS_ROOT = path.join(REPOSITORY_ROOT, 'apps', 'docs');
const DOCS_OUTPUT = path.join(DOCS_ROOT, 'dist');
const FRONTEND_SMOKE_PATHS = Object.freeze({
  site: ['/', '/dashboard/', '/dashboard/login', '/sdk/workers/near-signer.worker.js'],
  docs: ['/', '/concepts/', '/concepts/auth-methods/', '/concepts/policy/mandates'],
  wallet: [
    '/',
    '/wallet-service/index.html',
    { path: '/wallet-assets.manifest.json', isReady: jsonManifestIsReady },
    { path: '/headers.manifest.json', isReady: jsonManifestIsReady },
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
      await deployFrontend(site);
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
    `Docs: ${site.docsOrigin}`,
    `Default network: ${site.defaultNetwork}`,
    `Available networks: ${site.availableNetworks.join(', ')}`,
    `Pages project environment: ${site.pagesProjectEnv}`,
    `Docs Pages project environment: ${site.docsPagesProjectEnv}`,
    ...site.lanes.flatMap((lane) => [
      `Gateway (${lane.network}): ${lane.gatewayOrigin}`,
      `Wallet (${lane.network}): ${lane.walletOrigin}`,
      `Wallet Pages project environment (${lane.network}): ${lane.walletPagesProjectEnv}`,
    ]),
    ...formatLaneProvisioning(site.lanes),
    '',
    'Order:',
    '  1. build the Wallet SDK, marketing site, Console app, and VitePress docs',
    '  2. mount the Console build at /dashboard and deploy the site Pages project',
    '  3. deploy the docs Pages project and bind its custom domain',
    '  4. deploy one wallet Pages project for every declared network',
    '  5. smoke site, Console routes, docs, SDK, and every Wallet origin',
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
  const buildEnvironment = buildFrontendEnvironment(site);
  runCommand('pnpm', ['install', '--frozen-lockfile']);
  runCommand('pnpm', ['--filter', '@seams/wallet', 'run', 'build:prod'], {
    env: buildEnvironment,
  });
  runCommand('pnpm', ['-C', 'apps/seams-site', 'exec', 'vite', 'build'], {
    env: buildEnvironment,
  });
  runCommand('pnpm', ['-C', 'apps/seams-console', 'run', 'build'], {
    env: buildEnvironment,
  });
  runCommand('pnpm', ['-C', 'apps/docs', 'run', 'build'], {
    env: buildEnvironment,
  });
  copySdkAssets();
  copyDirectory(CONSOLE_OUTPUT, path.join(SITE_OUTPUT, 'dashboard'));
  assertDirectory(SITE_OUTPUT, 'Pages build output');
  assertFile(path.join(SITE_OUTPUT, 'dashboard', 'index.html'), 'Console dashboard entry');
  assertFile(path.join(SITE_OUTPUT, 'wallet-service', 'index.html'), 'wallet-service entry');
  assertDirectory(DOCS_OUTPUT, 'VitePress Pages build output');
  assertFile(path.join(DOCS_OUTPUT, 'concepts', 'index.html'), 'concepts docs entry');
  assertFile(
    path.join(DOCS_OUTPUT, 'concepts', 'auth-methods', 'index.html'),
    'auth methods docs entry',
  );
  assertFile(
    path.join(DOCS_OUTPUT, 'concepts', 'policy', 'mandates.html'),
    'policy mandates docs entry',
  );
}

function buildFrontendEnvironment(site) {
  const environment = {
    ...process.env,
    VITE_SITE_ID: site.id,
    VITE_SITE_ORIGIN: site.origin,
    VITE_DOCS_ORIGIN: site.docsOrigin,
  };
  for (const lane of site.lanes) {
    const prefix = site.id === 'production' ? `VITE_${lane.network.toUpperCase()}_` : 'VITE_';
    environment[`${prefix}RELAYER_URL`] = lane.gatewayOrigin;
    environment[`${prefix}CONSOLE_BASE_URL`] = consoleOriginFor(lane.gatewayOrigin);
    environment[`${prefix}WALLET_ORIGIN`] = lane.walletOrigin;
    environment[`${prefix}RP_ID_BASE`] = new URL(lane.walletOrigin).hostname;
    environment[`${prefix}ROUTER_AB_NORMAL_SIGNING_WORKER_ID`] =
      lane.resources.signingWorker.workerName;
    if (site.id === 'staging') {
      const projectEnvironmentVariable = 'VITE_SEAMS_PROJECT_ENVIRONMENT_ID';
      requireEnvironmentValues(
        [
          projectEnvironmentVariable,
          'VITE_SEAMS_PUBLISHABLE_KEY',
          'VITE_NEAR_NETWORK',
          'VITE_NEAR_RPC_URL',
          'VITE_NEAR_EXPLORER',
          'VITE_SIGNING_SESSION_PERSISTENCE_MODE',
        ],
        environment,
      );
      assertLaneProjectEnvironmentId(lane, projectEnvironmentVariable, environment);
      continue;
    }
    const projectEnvironmentVariable = `${prefix}SEAMS_PROJECT_ENVIRONMENT_ID`;
    requireEnvironmentValues(
      [
        projectEnvironmentVariable,
        `${prefix}SEAMS_PUBLISHABLE_KEY`,
        `${prefix}NEAR_NETWORK`,
        `${prefix}NEAR_RPC_URL`,
        `${prefix}NEAR_EXPLORER`,
        `${prefix}SIGNING_SESSION_PERSISTENCE_MODE`,
      ],
      environment,
    );
    assertLaneProjectEnvironmentId(lane, projectEnvironmentVariable, environment);
  }
  return environment;
}

function assertLaneProjectEnvironmentId(lane, variableName, environment) {
  if (lane.provisioning.kind !== 'provisioned') {
    throw new Error(`lane ${lane.id} must be provisioned before frontend configuration validation`);
  }
  const expected = lane.provisioning.gatewayDeploymentConfig.tenant.environmentId;
  const received = String(environment[variableName] || '').trim();
  if (received !== expected) {
    throw new Error(
      `${variableName} must match ${lane.id} tenant environment ${expected}; received ${received}`,
    );
  }
}

function copySdkAssets() {
  const requireFromSite = createRequire(path.join(SITE_ROOT, 'package.json'));
  const sdkOutput = path.join(
    path.dirname(requireFromSite.resolve('@seams/wallet/package.json')),
    'dist',
  );
  const sdkEsm = path.join(sdkOutput, 'esm', 'sdk');
  const sdkWorkers = path.join(sdkOutput, 'workers');
  const walletAssetsManifest = path.join(sdkOutput, 'public', 'wallet-assets.manifest.json');
  const walletHeadersManifest = path.join(sdkOutput, 'public', 'headers.manifest.json');
  const walletService = path.join(sdkOutput, 'public', 'wallet-service');
  assertDirectory(sdkEsm, 'SDK ESM output');
  assertFile(walletAssetsManifest, 'SDK wallet assets manifest');
  assertFile(walletHeadersManifest, 'SDK wallet headers manifest');
  assertFile(path.join(walletService, 'index.html'), 'SDK wallet-service output');
  copyDirectory(sdkEsm, path.join(SITE_OUTPUT, 'sdk'));
  if (fs.existsSync(sdkWorkers))
    copyDirectory(sdkWorkers, path.join(SITE_OUTPUT, 'sdk', 'workers'));
  fs.copyFileSync(walletAssetsManifest, path.join(SITE_OUTPUT, 'wallet-assets.manifest.json'));
  fs.copyFileSync(walletHeadersManifest, path.join(SITE_OUTPUT, 'headers.manifest.json'));
  copyDirectory(walletService, path.join(SITE_OUTPUT, 'wallet-service'));
}

function copyDirectory(source, destination) {
  fs.mkdirSync(destination, { recursive: true });
  runCommand('rsync', ['-a', '--delete', `${source}${path.sep}`, `${destination}${path.sep}`]);
}

async function deployFrontend(site) {
  requireEnvironmentValues(['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'], process.env);
  const walletProjectEnvironments = site.lanes.map((lane) => lane.walletPagesProjectEnv);
  requireEnvironmentValues(
    [site.pagesProjectEnv, site.docsPagesProjectEnv, ...new Set(walletProjectEnvironments)],
    process.env,
  );
  assertDirectory(SITE_OUTPUT, 'Pages build output');
  assertDirectory(DOCS_OUTPUT, 'VitePress Pages build output');
  deployPagesProject(SITE_OUTPUT, site, process.env[site.pagesProjectEnv]);
  const docsProject = process.env[site.docsPagesProjectEnv];
  deployPagesProject(DOCS_OUTPUT, site, docsProject);
  await ensurePagesCustomDomain(site, docsProject);
  for (const lane of site.lanes) {
    deployPagesProject(SITE_OUTPUT, site, process.env[lane.walletPagesProjectEnv]);
  }
  process.stdout.write(`Frontend deploy completed: ${site.id}\n`);
}

function deployPagesProject(outputDirectory, site, projectName) {
  const args = [
    'exec',
    'wrangler',
    'pages',
    'deploy',
    path.relative(ROUTER_ROOT, outputDirectory),
    '--branch',
    site.branch,
    '--commit-dirty=false',
    '--project-name',
    projectName,
  ];
  const sourceSha = String(process.env.DEPLOY_SHA || '').trim();
  if (sourceSha) args.push('--commit-hash', sourceSha);
  runCommand('pnpm', args, { cwd: ROUTER_ROOT });
}

async function ensurePagesCustomDomain(site, projectName) {
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
  const apiToken = process.env.CLOUDFLARE_API_TOKEN;
  const hostname = new URL(site.docsOrigin).hostname;
  const projectPath = `/accounts/${encodeURIComponent(accountId)}/pages/projects/${encodeURIComponent(projectName)}`;
  const domainPath = `${projectPath}/domains/${encodeURIComponent(hostname)}`;
  const existing = await requestCloudflareApi(domainPath, apiToken, 'GET', [200, 404]);
  if (existing.status === 200) return;
  await requestCloudflareApi(`${projectPath}/domains`, apiToken, 'POST', [200], {
    name: hostname,
  });
  process.stdout.write(`Bound Pages custom domain: ${hostname}\n`);
}

async function requestCloudflareApi(apiPath, apiToken, method, expectedStatuses, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${apiPath}`, {
    method,
    headers: {
      Authorization: `Bearer ${apiToken}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (expectedStatuses.includes(response.status)) return response;
  const responseText = await response.text();
  throw new Error(
    `Cloudflare Pages custom-domain request failed (${method} ${apiPath}): ${response.status} ${responseText}`,
  );
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
  addSmokeChecks(checks, 'docs', site.docsOrigin, FRONTEND_SMOKE_PATHS.docs);
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
  for (const request of requestPaths) {
    const requestPath = typeof request === 'string' ? request : request.path;
    checks.push({
      name: `${surface}${requestPath}`,
      url: new URL(requestPath, origin).toString(),
      ...(typeof request === 'string' ? {} : { isReady: request.isReady }),
    });
  }
}

function jsonManifestIsReady(response) {
  return (
    response.status >= 200 &&
    response.status < 400 &&
    String(response.headers.get('content-type') || '')
      .toLowerCase()
      .startsWith('application/json')
  );
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
