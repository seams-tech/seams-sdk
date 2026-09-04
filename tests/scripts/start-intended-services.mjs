#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import dotenv from 'dotenv';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { prepareRouterAbD1LocalRuntimeConfig } from '../../crates/router-ab-dev/scripts/d1-local-runtime-config.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
dotenv.config({ path: path.join(repoRoot, '.env.local'), override: false });
const checkOnly = process.argv.includes('--check');
const appUrl = process.env.SEAMS_INTENDED_APP_URL || 'http://localhost:4001';
const routerUrl = process.env.SEAMS_INTENDED_ROUTER_URL || 'https://localhost:4101';
const walletOrigin = process.env.SEAMS_INTENDED_WALLET_ORIGIN || 'https://localhost:4002';
const consoleOrigin = 'http://localhost:4005';
const consoleStaticUrl = `${consoleOrigin}/dashboard-static/`;
const projectEnvironmentId = process.env.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID || 'local-env';
const publishableKey = process.env.SEAMS_INTENDED_PUBLISHABLE_KEY || 'pk_local';
const docsOrigin = process.env.SEAMS_INTENDED_DOCS_ORIGIN || 'https://docs.localhost:4003';
const siteViteUrl = 'http://127.0.0.1:4004';
const routerAbLocalRoot =
  process.env.SEAMS_INTENDED_ROUTER_AB_ROOT ||
  path.join(tmpdir(), `${path.basename(repoRoot)}-intended-router-ab`);
const d1LocalPersistPath =
  process.env.SEAMS_INTENDED_D1_PERSIST_TO ||
  path.join(routerAbLocalRoot, '.local', 'cloudflare-state', 'gateway');
const d1LocalWranglerRuntimeDir =
  process.env.SEAMS_INTENDED_D1_WRANGLER_RUNTIME_DIR ||
  path.join(routerAbLocalRoot, '.runtime', 'wrangler-d1-local');
const d1LocalWranglerConfigPath =
  process.env.SEAMS_D1_LOCAL_WRANGLER_CONFIG ||
  path.join(d1LocalWranglerRuntimeDir, 'wrangler.d1-local.toml');
const siteViteCacheDir =
  process.env.SEAMS_INTENDED_SITE_VITE_CACHE_DIR ||
  path.join(tmpdir(), `${path.basename(repoRoot)}-intended-vite-cache`);
const sdkDistSnapshotRoot = path.join(repoRoot, '.local', 'intended-wallet-sdk-dist');
const intendedServicesLockPath = path.join(
  tmpdir(),
  `${path.basename(repoRoot)}-intended-services.lock`,
);
const intendedServicesLockOwnerPath = path.join(intendedServicesLockPath, 'owner.json');
const webServerReadyHost = '127.0.0.1';
const webServerReadyPort = parseWebServerReadyPort();
const resetState = process.env.SEAMS_INTENDED_SKIP_STATE_RESET !== '1';
const skipBuild = process.env.SEAMS_INTENDED_SKIP_BUILD === '1';
const managedChildren = [];
let shutdownStarted = false;
let ownsIntendedServicesLock = false;
let webServerReadyServer;
let localConsoleOrganizationId = '';
let d1LocalRuntimeConfig;
const transientViteCachePaths = [
  'apps/seams-site/node_modules/.vite',
  'apps/seams-console/node_modules/.vite',
];
const requiredSdkDistArtifacts = [
  'packages/wallet/dist/esm/advanced.js',
  'packages/wallet/dist/esm/core/config/chains.js',
  'packages/wallet/dist/esm/core/idempotency/createIntentId.js',
  'packages/wallet/dist/esm/core/rpcClients/evm/EvmClient.js',
  'packages/wallet/dist/esm/core/rpcClients/near/NearClient.js',
  'packages/wallet/dist/esm/react/context/SeamsWebProvider.js',
  'packages/wallet/dist/esm/react/context/index.js',
  'packages/wallet/dist/esm/react/index.js',
  'packages/wallet/dist/esm/react/styles/styles.css',
  'packages/wallet/dist/esm/sdk/router_ab_ed25519_yao_client_bg.wasm',
  'packages/wallet/dist/esm/wasm/router_ab_ed25519_yao_client/pkg/router_ab_ed25519_yao_client.js',
  'packages/wallet/dist/esm/wasm/router_ab_ed25519_yao_client/pkg/router_ab_ed25519_yao_client_bg.wasm',
  'packages/wallet/dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js',
  'packages/wallet/dist/workers/router_ab_ed25519_yao_client_bg.wasm',
  'packages/wallet/dist/workers/evm-crypto.worker.js',
  'packages/wallet/dist/workers/near-signer.worker.js',
  'packages/wallet/dist/workers/tempo-signer.worker.js',
];
const requiredSiteModuleGraphArtifacts = [
  'packages/wallet/dist/esm/advanced.js',
  'packages/wallet/dist/esm/core/config/chains.js',
  'packages/wallet/dist/esm/core/idempotency/createIntentId.js',
  'packages/wallet/dist/esm/core/rpcClients/evm/EvmClient.js',
  'packages/wallet/dist/esm/core/rpcClients/near/NearClient.js',
  'packages/wallet/dist/esm/react/context/SeamsWebProvider.js',
  'packages/wallet/dist/esm/react/context/index.js',
  'packages/wallet/dist/esm/react/index.js',
  'packages/wallet/dist/esm/react/styles/styles.css',
];
if (isMainModule()) await main().catch(failStartup);

function isMainModule() {
  return process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
}

async function main() {
  assertLocalIntendedUrls();
  if (checkOnly) {
    printResolvedConfig();
    return;
  }

  installSignalHandlers();
  await acquireIntendedServicesLock();
  assertNoConflictingLocalProcesses();
  if (resetState) {
    resetLocalState();
  }
  initializeRouterAbLocalEnv();
  if (skipBuild) {
    console.log('[intended-services] skipping SDK build because SEAMS_INTENDED_SKIP_BUILD=1');
  } else {
    buildSdkArtifacts();
  }
  assertSdkDistArtifacts();
  snapshotSdkDistArtifacts();
  assertD1LocalWasmArtifacts();
  clearTransientViteCaches();
  prepareD1LocalWranglerRuntimeConfig();
  applyD1LocalMigrations();

  startCaddy();
  const router = startRouter();
  await waitForHttpOk(`${routerUrl}/healthz`, 'router healthz', 180_000);
  await waitForHttpOk(`${routerUrl}/readyz`, 'router readyz', 180_000);
  await waitForHttpOk(`${routerUrl}/console/readyz`, 'console readyz', 180_000);
  seedLocalConsole();
  await createLocalTenantRoot();

  const site = startSite();
  await waitForHttpOk(siteViteUrl, 'site Vite', 120_000);
  const consoleApp = startConsole();
  await waitForHttpOk(appUrl, 'site', 120_000);
  await waitForHttpOk(consoleStaticUrl, 'console frontend', 120_000);
  await waitForConsoleDocument(
    new URL('/dashboard/login', appUrl).href,
    'public console login',
    120_000,
  );
  await waitForAuthenticatedConsoleOverview();
  await waitForSiteModuleGraphArtifacts();
  await waitForHttpOk(intendedPageSmokeUrl(), 'intended page', 60_000);
  await waitForRouterStability();
  await startWebServerReadyServer();

  console.log('[intended-services] console, site, and router are ready');
  await waitUntilStopped(site, router, consoleApp);
}

function assertLocalIntendedUrls() {
  assertUrlOrigin('SEAMS_INTENDED_APP_URL', appUrl, [
    'http://localhost:4001',
    'https://localhost',
    'https://localhost:9443',
  ]);
  assertUrlOrigin('SEAMS_INTENDED_ROUTER_URL', routerUrl, 'https://localhost:4101');
  assertUrlOrigin('SEAMS_INTENDED_WALLET_ORIGIN', walletOrigin, 'https://localhost:4002');
  assertUrlOrigin('SEAMS_INTENDED_DOCS_ORIGIN', docsOrigin, [
    'https://docs.localhost',
    'https://docs.localhost:4003',
  ]);
}

function assertUrlOrigin(name, value, expectedOrigin) {
  const origin = new URL(value).origin;
  const expectedOrigins = Array.isArray(expectedOrigin) ? expectedOrigin : [expectedOrigin];
  if (expectedOrigins.includes(origin)) return;
  throw new Error(
    `${name}=${value} is incompatible with CI-managed local startup; expected ${expectedOrigins.join(' or ')}`,
  );
}

function printResolvedConfig() {
  console.log(
    JSON.stringify(
      {
        appUrl,
        routerUrl,
        walletOrigin,
        webServerReadyUrl: webServerReadyUrl(),
        projectEnvironmentId,
        publishableKey,
        d1LocalPersistPath,
        routerAbLocalRoot,
        d1LocalWranglerConfigPath,
        siteViteCacheDir,
        resetState,
        skipBuild,
      },
      null,
      2,
    ),
  );
}

function resetLocalState() {
  removeAbsolutePath(routerAbLocalRoot);
  removePath('packages/console-server-ts/.wrangler/state/seams-d1');
  removePath('.runtime/intended-d1');
  removeAbsolutePath(d1LocalPersistPath);
  removeAbsolutePath(siteViteCacheDir);
}

function buildSdkArtifacts() {
  runRequiredBuild('sdk and Router A/B Workers', ['run', 'build:sdk-full'], {
    ...process.env,
    SEAMS_ROUTER_AB_LOCAL_ROOT: routerAbLocalRoot,
  });
  runRequiredBuild('wallet server', ['-C', 'packages/wallet-server', 'run', 'build']);
}

function assertSdkDistArtifacts() {
  const missingArtifacts = requiredSdkDistArtifacts.filter(isMissingRepoPath);
  if (missingArtifacts.length > 0) {
    throw new Error(`SDK build did not emit required artifacts: ${missingArtifacts.join(', ')}`);
  }
  console.log(`[intended-services] verified ${requiredSdkDistArtifacts.length} SDK dist artifacts`);
}

function clearTransientViteCaches() {
  for (const relativePath of transientViteCachePaths) {
    removePath(relativePath);
  }
}

function isMissingRepoPath(relativePath) {
  return !existsSync(path.join(repoRoot, relativePath));
}

function runRequiredBuild(label, args, env = process.env) {
  console.log(`[intended-services] building ${label}: pnpm ${args.join(' ')}`);
  const result = spawnSync('pnpm', args, {
    cwd: repoRoot,
    env,
    stdio: 'inherit',
  });
  if (result.error) {
    throw new Error(`${label} build failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`${label} build exited with ${String(result.status ?? 'unknown')}`);
  }
}

function assertD1LocalWasmArtifacts() {
  console.log('[intended-services] verifying D1 local WASM artifacts');
  runRequiredBuild(
    'd1-local-wasm',
    ['-C', 'packages/console-server-ts', 'run', 'd1:local:ensure-wasm'],
    {
      ...process.env,
      SEAMS_D1_LOCAL_WASM_AUTO_BUILD: '0',
    },
  );
}

function removePath(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  removeAbsolutePath(absolutePath);
}

function removeAbsolutePath(absolutePath) {
  if (!existsSync(absolutePath)) return;
  console.log(
    `[intended-services] removing ${path.relative(repoRoot, absolutePath) || absolutePath}`,
  );
  rmSync(absolutePath, { recursive: true, force: true });
}

function snapshotSdkDistArtifacts() {
  removeAbsolutePath(sdkDistSnapshotRoot);
  mkdirSync(path.dirname(sdkDistSnapshotRoot), { recursive: true });
  cpSync(path.join(repoRoot, 'packages/wallet/dist'), sdkDistSnapshotRoot, { recursive: true });
}

function assertNoConflictingLocalProcesses() {
  const conflicts = collectManagedProcessLeaks();
  if (conflicts.length === 0) return;
  const processes = conflicts.map((entry) => `${entry.pid}: ${entry.command}`).join('\n');
  throw new Error(
    `local services are already running; stop them before starting the isolated intended-behaviour runtime:\n${processes}`,
  );
}

function startSite() {
  return spawnManaged(
    'site',
    ['-C', 'apps/seams-site', 'exec', 'vite', '--host', '127.0.0.1', '--port', '4004'],
    siteEnv(),
  );
}

function startConsole() {
  return spawnManaged(
    'console',
    ['-C', 'apps/seams-console', 'exec', 'vite', '--host', '127.0.0.1', '--port', '4005'],
    consoleEnv(),
  );
}

function startCaddy() {
  return spawnManaged('caddy', ['-C', 'apps/seams-site', 'run', 'caddy'], caddyEnv());
}

function startRouter() {
  return spawnManaged(
    'router',
    ['run', 'router', '--', '--root', routerAbLocalRoot, '--no-init'],
    routerEnv(),
  );
}

function initializeRouterAbLocalEnv() {
  const buildEnvironmentPath = path.join(routerAbLocalRoot, '.env.router-ab.router.local');
  if (!resetState && existsSync(buildEnvironmentPath)) {
    console.log('[intended-services] reusing Router A/B local runtime identity');
    return;
  }
  console.log('[intended-services] generating Router A/B local runtime identity');
  const result = spawnSync(
    'cargo',
    [
      'run',
      '--quiet',
      '--manifest-path',
      'crates/router-ab-dev/Cargo.toml',
      '--bin',
      'router_ab_local_init',
      '--',
      '--root',
      routerAbLocalRoot,
    ],
    {
      cwd: repoRoot,
      env: process.env,
      stdio: 'inherit',
    },
  );
  if (result.error) {
    throw new Error(`Router A/B local init failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`Router A/B local init exited with ${String(result.status ?? 'unknown')}`);
  }
}

function seedLocalConsole() {
  console.log('[intended-services] seeding local console state');
  const result = spawnSync('pnpm', ['-C', 'tests', 'seed:intended-local-console'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID: projectEnvironmentId,
      SEAMS_INTENDED_PUBLISHABLE_KEY: publishableKey,
      SEAMS_LOCAL_CONSOLE_ORG_ID: requireLocalConsoleOrganizationId(),
      SEAMS_D1_LOCAL_PERSIST_TO: d1LocalPersistPath,
      SEAMS_D1_LOCAL_WRANGLER_CONFIG: d1LocalWranglerConfigPath,
    },
    stdio: 'inherit',
  });
  if (result.error) {
    throw new Error(`local console seed failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`local console seed exited with ${String(result.status ?? 'unknown')}`);
  }
}

async function createLocalTenantRoot() {
  console.log('[intended-services] creating server-owned local tenant root');
  const response = await requestJson(
    new URL('/console/tenant-root/creation', routerUrl).href,
    180_000,
    {
      ...localConsoleAuthHeaders(),
      'content-type': 'application/json',
    },
    { operationId: 'intended-local-tenant-root-creation-v1' },
  );
  let result;
  try {
    result = JSON.parse(response.body);
  } catch {
    throw new Error(
      `local tenant-root creation returned invalid JSON (HTTP ${response.statusCode})`,
    );
  }
  if (
    response.statusCode < 200 ||
    response.statusCode >= 300 ||
    result?.ok !== true ||
    result?.status !== 'ACTIVE'
  ) {
    throw new Error(
      `local tenant-root creation failed (HTTP ${response.statusCode}): ${response.body}`,
    );
  }
}

function siteEnv() {
  const runtime = requireD1LocalRuntimeConfig();
  return {
    ...process.env,
    VITE_RELAYER_URL: routerUrl,
    VITE_SEAMS_BROKER_URL: routerUrl,
    VITE_CONSOLE_BASE_URL: routerUrl,
    VITE_WALLET_ORIGIN: walletOrigin,
    VITE_DOCS_ORIGIN: docsOrigin,
    VITE_RP_ID_BASE: 'localhost',
    VITE_ROR_ALLOWED_ORIGINS: docsOrigin,
    VITE_CACHE_DIR: siteViteCacheDir,
    VITE_SEAMS_WALLET_DIST_ROOT: sdkDistSnapshotRoot,
    VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'local-signing-worker',
    VITE_SEAMS_PROJECT_ENVIRONMENT_ID: projectEnvironmentId,
    VITE_SEAMS_PUBLISHABLE_KEY: publishableKey,
    VITE_SIGNING_SESSION_PERSISTENCE_MODE: runtime.signingSessionPersistenceMode,
    VITE_ENABLE_INTENDED_E2E: '1',
  };
}

function consoleEnv() {
  return {
    ...process.env,
    VITE_SITE_ORIGIN: appUrl,
    VITE_CONSOLE_BASE_URL: routerUrl,
    VITE_RELAYER_URL: routerUrl,
    VITE_WALLET_ORIGIN: walletOrigin,
    VITE_DOCS_ORIGIN: docsOrigin,
    VITE_RP_ID_BASE: 'localhost',
    VITE_ENABLE_INTENDED_E2E: '1',
  };
}

function caddyEnv() {
  return {
    ...process.env,
    SEAMS_APP_CADDY_ADDRESS: new URL(appUrl).origin,
    SEAMS_DOCS_CADDY_ADDRESS: new URL(docsOrigin).host,
  };
}

function routerEnv() {
  return {
    ...process.env,
    SEAMS_D1_LOCAL_PERSIST_TO: d1LocalPersistPath,
    SEAMS_D1_LOCAL_WRANGLER_CONFIG: d1LocalWranglerConfigPath,
    SEAMS_D1_LOCAL_WASM_AUTO_BUILD: '0',
    SEAMS_D1_LOCAL_SKIP_ENV_FILE: '1',
    SEAMS_LOCAL_CONSOLE_ORG_ID: requireLocalConsoleOrganizationId(),
    SEAMS_LOCAL_CONSOLE_PROJECT_ID: 'local-smoke-project',
    SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID: projectEnvironmentId,
  };
}

function prepareD1LocalWranglerRuntimeConfig() {
  const runtime = prepareRouterAbD1LocalRuntimeConfig({
    repoRoot,
    localEnvRoot: routerAbLocalRoot,
    outputConfigPath: d1LocalWranglerConfigPath,
    localConsoleProjectId: 'local-smoke-project',
    localConsoleEnvironmentId: projectEnvironmentId,
  });
  d1LocalRuntimeConfig = runtime;
  localConsoleOrganizationId = runtime.localConsoleOrganizationId;

  console.log(
    `[intended-services] prepared D1 local wrangler config at ${path.relative(repoRoot, d1LocalWranglerConfigPath)}`,
  );
}

function applyD1LocalMigrations() {
  for (const databaseName of ['seams-console', 'seams-signer']) {
    console.log(`[intended-services] applying ${databaseName} migrations`);
    const result = spawnSync(
      'pnpm',
      [
        '-C',
        'packages/console-server-ts',
        'exec',
        'wrangler',
        'd1',
        'migrations',
        'apply',
        databaseName,
        '--local',
        '--persist-to',
        d1LocalPersistPath,
        '--config',
        d1LocalWranglerConfigPath,
      ],
      {
        cwd: repoRoot,
        env: { ...process.env, CI: 'true' },
        stdio: 'inherit',
      },
    );
    if (result.error) {
      throw new Error(`${databaseName} migrations failed to start: ${result.error.message}`);
    }
    if (result.status !== 0) {
      throw new Error(
        `${databaseName} migrations exited with ${String(result.status ?? 'unknown')}`,
      );
    }
  }
}

function requireD1LocalRuntimeConfig() {
  if (!d1LocalRuntimeConfig) {
    throw new Error('D1 local runtime config has not been prepared');
  }
  return d1LocalRuntimeConfig;
}

function requireLocalConsoleOrganizationId() {
  if (!localConsoleOrganizationId) {
    throw new Error('local console organization ID has not been prepared');
  }
  return localConsoleOrganizationId;
}

function spawnManaged(label, args, env) {
  console.log(`[intended-services] starting ${label}: pnpm ${args.join(' ')}`);
  const child = spawn('pnpm', args, {
    cwd: repoRoot,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });
  managedChildren.push({ label, child, killAsGroup: process.platform !== 'win32' });
  child.stdout.on('data', handleChildStdout);
  child.stderr.on('data', handleChildStderr);
  child.once('exit', handleManagedExit);
  child.once('error', handleManagedError);
  return child;
}

function childLabel(child) {
  const entry = managedChildren.find((candidate) => candidate.child === child);
  return entry?.label || 'service';
}

function handleChildStdout(chunk) {
  process.stdout.write(prefixChunk(this, chunk));
}

function handleChildStderr(chunk) {
  process.stderr.write(prefixChunk(this, chunk));
}

function prefixChunk(stream, chunk) {
  const entry = managedChildren.find(
    (candidate) => candidate.child.stdout === stream || candidate.child.stderr === stream,
  );
  const label = entry?.label || 'service';
  return String(chunk).split(/\r?\n/).map(prefixLine(label)).join('\n');
}

function prefixLine(label) {
  return function prefixServiceLine(line, index, lines) {
    if (!line && index === lines.length - 1) return '';
    return `[${label}] ${line}`;
  };
}

function handleManagedExit(code, signal) {
  if (shutdownStarted) return;
  const label = childLabel(this);
  const status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
  failStartup(new Error(`${label} stopped before Playwright completed (${status})`));
}

function handleManagedError(error) {
  if (shutdownStarted) return;
  const label = childLabel(this);
  failStartup(new Error(`${label} failed to start: ${error.message}`));
}

async function waitUntilStopped() {
  await new Promise(() => undefined);
}

function parseWebServerReadyPort() {
  const rawPort = process.env.SEAMS_INTENDED_WEB_SERVER_READY_PORT || '37888';
  const port = Number(rawPort);
  if (Number.isInteger(port) && port > 0 && port < 65536) return port;
  throw new Error(`SEAMS_INTENDED_WEB_SERVER_READY_PORT must be a valid TCP port: ${rawPort}`);
}

function webServerReadyUrl() {
  return `http://${webServerReadyHost}:${webServerReadyPort}/readyz`;
}

async function startWebServerReadyServer() {
  if (webServerReadyServer) return;
  webServerReadyServer = http.createServer(handleWebServerReadyRequest);
  await listenWebServerReadyServer(webServerReadyServer);
  console.log(`[intended-services] Playwright webServer ready at ${webServerReadyUrl()}`);
}

function handleWebServerReadyRequest(request, response) {
  if (request.url === '/readyz') {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('ok\n');
    return;
  }
  response.writeHead(404, { 'content-type': 'text/plain' });
  response.end('not found\n');
}

function listenWebServerReadyServer(server) {
  return new Promise(createWebServerReadyListenExecutor(server));
}

function createWebServerReadyListenExecutor(server) {
  return function listen(resolve, reject) {
    server.once('error', reject);
    server.listen(webServerReadyPort, webServerReadyHost, resolve);
  };
}

function intendedPageSmokeUrl() {
  const url = new URL('/__intended-e2e', appUrl);
  url.searchParams.set('flow', 'passkey.registration');
  url.searchParams.set('walletId', 'intended-ci-smoke');
  return url.href;
}

async function waitForHttpOk(url, label, timeoutMs, headers = {}) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await httpOk(url, headers)) {
      console.log(`[intended-services] ${label} ready at ${url}`);
      return;
    }
    await delay(500);
  }
  throw new Error(`${label} did not become ready at ${url}`);
}

async function waitForConsoleDocument(url, label, timeoutMs, headers = {}) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await requestText(url, 1_000, headers);
      if (
        response.statusCode >= 200 &&
        response.statusCode < 300 &&
        isConsoleDocument(response.body)
      ) {
        console.log(`[intended-services] ${label} ready at ${url}`);
        return;
      }
    } catch {}
    await delay(500);
  }
  throw new Error(`${label} did not return the Console application at ${url}`);
}

async function waitForAuthenticatedConsoleOverview() {
  const headers = localConsoleAuthHeaders();
  const overviewUrl = new URL('/dashboard/overview', appUrl).href;
  await waitForConsoleDocument(overviewUrl, 'authenticated console overview', 120_000, headers);
  for (const path of [
    '/console/session',
    '/console/onboarding/state',
    '/console/account/organizations',
    '/console/projects?status=ACTIVE',
    '/console/environments',
  ]) {
    await waitForHttpOk(
      new URL(path, routerUrl).href,
      `authenticated console request ${path}`,
      60_000,
      headers,
    );
  }
}

function localConsoleAuthHeaders() {
  return {
    'X-Console-User-Id': process.env.SEAMS_LOCAL_CONSOLE_USER_ID || 'local-console-user',
    'X-Console-Org-Id': requireLocalConsoleOrganizationId(),
    'X-Console-Project-Id': process.env.SEAMS_LOCAL_CONSOLE_PROJECT_ID || 'local-smoke-project',
    'X-Console-Environment-Id': projectEnvironmentId,
  };
}

function isConsoleDocument(body) {
  return body.includes('<title>Seams Console</title>') && body.includes('id="root"');
}

async function waitForSiteModuleGraphArtifacts() {
  for (const relativePath of requiredSiteModuleGraphArtifacts) {
    await waitForHttpOk(siteModuleGraphUrl(relativePath), `sdk module ${relativePath}`, 60_000);
  }
}

async function waitForRouterStability() {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    await waitForHttpOk(`${routerUrl}/healthz`, `router healthz stability ${attempt}`, 10_000);
    await waitForHttpOk(`${routerUrl}/readyz`, `router readyz stability ${attempt}`, 10_000);
    await delay(500);
  }
}

function siteModuleGraphUrl(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  const url = new URL(`/@fs${absolutePath}`, appUrl);
  return url.href;
}

async function httpOk(url, headers = {}) {
  try {
    const status = await requestStatus(url, 1_000, headers);
    return status >= 200 && status < 300;
  } catch {
    return false;
  }
}

function requestStatus(urlValue, timeoutMs, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlValue);
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.get(
      url,
      {
        timeout: timeoutMs,
        rejectUnauthorized: false,
        headers,
      },
      handleStatusResponse(resolve),
    );
    req.once('timeout', handleTimeout(req));
    req.once('error', reject);
  });
}

function requestText(urlValue, timeoutMs, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlValue);
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.get(
      url,
      {
        timeout: timeoutMs,
        rejectUnauthorized: false,
        headers,
      },
      handleTextResponse(resolve),
    );
    req.once('timeout', handleTimeout(req));
    req.once('error', reject);
  });
}

function requestJson(urlValue, timeoutMs, headers, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlValue);
    const transport = url.protocol === 'https:' ? https : http;
    const encodedBody = JSON.stringify(body);
    const req = transport.request(
      url,
      {
        timeout: timeoutMs,
        rejectUnauthorized: false,
        method: 'POST',
        headers: {
          ...headers,
          'content-length': Buffer.byteLength(encodedBody),
        },
      },
      handleTextResponse(resolve),
    );
    req.once('timeout', handleTimeout(req));
    req.once('error', reject);
    req.end(encodedBody);
  });
}

function handleTextResponse(resolve) {
  return function onTextResponse(response) {
    let body = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => {
      body += chunk;
    });
    response.on('end', () => {
      resolve({ statusCode: response.statusCode || 0, body });
    });
  };
}

function handleStatusResponse(resolve) {
  return function onStatusResponse(response) {
    response.resume();
    resolve(response.statusCode || 0);
  };
}

function handleTimeout(req) {
  return function onTimeout() {
    req.destroy(new Error('timeout'));
  };
}

function delay(ms) {
  return new Promise(resolveDelay(ms));
}

function resolveDelay(ms) {
  return function resolveAfterDelay(resolve) {
    setTimeout(resolve, ms);
  };
}

function installSignalHandlers() {
  process.once('SIGINT', handleSigint);
  process.once('SIGTERM', handleSigterm);
}

function handleSigint() {
  shutdown(130);
}

function handleSigterm() {
  shutdown(143);
}

async function failStartup(error) {
  console.error(`[intended-services] ${error instanceof Error ? error.message : String(error)}`);
  await shutdown(1);
}

async function shutdown(exitCode) {
  if (shutdownStarted) return;
  shutdownStarted = true;
  try {
    closeWebServerReadyServer();
    const ownedDescendantPids = collectManagedDescendantPids();
    for (const entry of [...managedChildren].reverse()) {
      stopChild(entry);
    }
    terminateProcesses(ownedDescendantPids, 'SIGTERM');
    await delay(1_500);
    for (const entry of [...managedChildren].reverse()) {
      forceStopChild(entry);
    }
    terminateProcesses(ownedDescendantPids, 'SIGKILL');
  } catch (error) {
    reportShutdownError('unexpected cleanup failure', error);
  } finally {
    releaseIntendedServicesLock();
    process.exit(exitCode);
  }
}

async function acquireIntendedServicesLock() {
  const startedAt = Date.now();
  let announcedWait = false;
  while (Date.now() - startedAt < 1_500_000) {
    try {
      mkdirSync(intendedServicesLockPath);
      writeFileSync(
        intendedServicesLockOwnerPath,
        `${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() })}\n`,
      );
      ownsIntendedServicesLock = true;
      return;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    if (removeStaleIntendedServicesLock()) continue;
    if (!announcedWait) {
      console.log('[intended-services] waiting for the active intended-behaviour stack');
      announcedWait = true;
    }
    await delay(500);
  }
  throw new Error('timed out waiting for the active intended-behaviour stack');
}

function removeStaleIntendedServicesLock() {
  const ownerPid = readIntendedServicesLockOwnerPid();
  if (ownerPid !== undefined && isProcessRunning(ownerPid)) return false;
  if (ownerPid === undefined && !isOldIntendedServicesLock()) return false;
  rmSync(intendedServicesLockPath, { recursive: true, force: true });
  return true;
}

function readIntendedServicesLockOwnerPid() {
  try {
    const owner = JSON.parse(readFileSync(intendedServicesLockOwnerPath, 'utf8'));
    return Number.isInteger(owner?.pid) && owner.pid > 0 ? owner.pid : undefined;
  } catch {
    return undefined;
  }
}

function isOldIntendedServicesLock() {
  try {
    return Date.now() - statSync(intendedServicesLockPath).mtimeMs > 5_000;
  } catch {
    return true;
  }
}

function isProcessRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

function releaseIntendedServicesLock() {
  if (!ownsIntendedServicesLock) return;
  try {
    rmSync(intendedServicesLockPath, { recursive: true, force: true });
  } catch (error) {
    reportShutdownError('could not release the intended-services lock', error);
  }
  ownsIntendedServicesLock = false;
}

function stopChild(entry) {
  if (!entry.killAsGroup && !isChildRunning(entry.child)) return;
  console.log(`[intended-services] stopping ${entry.label}`);
  killChild(entry.child, 'SIGTERM', entry.killAsGroup);
}

function forceStopChild(entry) {
  if (!entry.killAsGroup && !isChildRunning(entry.child)) return;
  console.log(`[intended-services] force stopping ${entry.label}`);
  killChild(entry.child, 'SIGKILL', entry.killAsGroup);
}

function isChildRunning(child) {
  return Boolean(child && child.exitCode === null && child.signalCode === null);
}

function killChild(child, signal, killAsGroup) {
  if (!child.pid) return;
  try {
    if (killAsGroup) {
      process.kill(-child.pid, signal);
      return;
    }
    child.kill(signal);
  } catch (error) {
    if (killAsGroup && error?.code === 'EPERM') {
      killChildDirectly(child, signal);
      return;
    }
    if (error?.code !== 'ESRCH') {
      reportShutdownError(
        `could not send ${signal} to managed process ${String(child.pid)}`,
        error,
      );
    }
  }
}

function killChildDirectly(child, signal) {
  try {
    child.kill(signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      reportShutdownError(
        `could not send ${signal} directly to managed process ${String(child.pid)}`,
        error,
      );
    }
  }
}

function collectManagedDescendantPids() {
  const result = spawnSync('ps', ['-axo', 'pid=,ppid='], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) return [];
  const childrenByParent = new Map();
  for (const line of String(result.stdout || '').split(/\r?\n/)) {
    const relation = parseProcessRelation(line);
    if (!relation) continue;
    const children = childrenByParent.get(relation.parentPid) || [];
    children.push(relation.pid);
    childrenByParent.set(relation.parentPid, children);
  }
  const descendants = [];
  const queue = [];
  for (const entry of managedChildren) {
    if (entry.child.pid) queue.push(entry.child.pid);
  }
  while (queue.length > 0) {
    const parentPid = queue.shift();
    const children = childrenByParent.get(parentPid) || [];
    for (const childPid of children) {
      descendants.push(childPid);
      queue.push(childPid);
    }
  }
  return descendants.reverse();
}

function parseProcessRelation(line) {
  const match = line.match(/^\s*(\d+)\s+(\d+)\s*$/);
  if (!match) return undefined;
  return { pid: Number(match[1]), parentPid: Number(match[2]) };
}

function terminateProcesses(pids, signal) {
  for (const pid of pids) {
    try {
      process.kill(pid, signal);
    } catch (error) {
      if (error?.code !== 'ESRCH') {
        reportShutdownError(`could not send ${signal} to descendant ${String(pid)}`, error);
      }
    }
  }
}

function reportShutdownError(action, error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[intended-services] teardown warning: ${action}: ${message}`);
}

function collectManagedProcessLeaks() {
  const result = spawnSync('ps', ['-axo', 'pid=,command='], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) return [];
  return String(result.stdout || '')
    .split(/\r?\n/)
    .map(parseProcessEntry)
    .filter(isManagedProcessLeak);
}

function parseProcessEntry(line) {
  const match = line.match(/^\s*(\d+)\s+(.+)$/);
  if (!match) return { pid: 0, command: '' };
  return { pid: Number(match[1]), command: match[2] };
}

function isManagedProcessLeak(entry) {
  return entry.pid > 0 && entry.pid !== process.pid && isManagedProcessCommand(entry.command);
}

function isManagedProcessCommand(command) {
  return (
    isRouterDevWorkerCommand(command) ||
    isWranglerD1Command(command) ||
    isLocalWorkerdCommand(command) ||
    isSiteViteCommand(command) ||
    isConsoleViteCommand(command) ||
    isSiteCaddyCommand(command) ||
    isDocsVitepressCommand(command)
  );
}

function isRouterDevWorkerCommand(command) {
  return command.includes('crates/router-ab-dev/scripts/dev-local-workers.mjs --mode logs');
}

function isWranglerD1Command(command) {
  return (
    command.includes('wrangler dev') &&
    command.includes('wrangler.d1-local.toml') &&
    command.includes('--port 4100')
  );
}

function isLocalWorkerdCommand(command) {
  return command.includes('workerd serve') && command.includes('localhost:4100');
}

function isSiteViteCommand(command) {
  return (
    command.includes(path.join(repoRoot, 'apps/seams-site')) &&
    command.includes('vite') &&
    command.includes('--port 4004')
  );
}

function isConsoleViteCommand(command) {
  return (
    command.includes(path.join(repoRoot, 'apps/seams-console')) &&
    command.includes('vite') &&
    command.includes('--port 4005')
  );
}

function isSiteCaddyCommand(command) {
  return command.includes(`caddy run --config ${path.join(repoRoot, 'apps/seams-site/Caddyfile')}`);
}

function isDocsVitepressCommand(command) {
  return (
    command.includes(path.join(repoRoot, 'apps/docs')) &&
    command.includes('vitepress') &&
    command.includes('--port 4006')
  );
}

function closeWebServerReadyServer() {
  if (!webServerReadyServer) return;
  const server = webServerReadyServer;
  webServerReadyServer = undefined;
  try {
    server.close();
    server.closeAllConnections();
  } catch (error) {
    reportShutdownError('could not close the Playwright readiness server', error);
  }
}

export { killChild, terminateProcesses };
