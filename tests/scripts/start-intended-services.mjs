#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import dotenv from 'dotenv';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
dotenv.config({ path: path.join(repoRoot, '.env.intended.local'), override: true });
const checkOnly = process.argv.includes('--check');
const appUrl = process.env.SEAMS_INTENDED_APP_URL || 'https://localhost';
const routerUrl = process.env.SEAMS_INTENDED_ROUTER_URL || 'https://localhost:9444';
const walletOrigin = process.env.SEAMS_INTENDED_WALLET_ORIGIN || 'https://localhost:8443';
const projectEnvironmentId =
  process.env.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID || 'local-env';
const publishableKey = process.env.SEAMS_INTENDED_PUBLISHABLE_KEY || 'pk_local';
const docsOrigin = process.env.SEAMS_INTENDED_DOCS_ORIGIN || 'https://docs.localhost';
const d1LocalPersistPath =
  process.env.SEAMS_INTENDED_D1_PERSIST_TO ||
  path.join(tmpdir(), `${path.basename(repoRoot)}-intended-d1`);
const d1LocalWranglerRuntimeDir =
  process.env.SEAMS_INTENDED_D1_WRANGLER_RUNTIME_DIR ||
  path.join(repoRoot, '.runtime', 'wrangler-d1-local');
const d1LocalWranglerConfigPath =
  process.env.SEAMS_D1_LOCAL_WRANGLER_CONFIG ||
  path.join(d1LocalWranglerRuntimeDir, 'wrangler.d1-local.toml');
const siteViteCacheDir =
  process.env.SEAMS_INTENDED_SITE_VITE_CACHE_DIR ||
  path.join(tmpdir(), `${path.basename(repoRoot)}-intended-vite-cache`);
const webServerReadyHost = '127.0.0.1';
const webServerReadyPort = parseWebServerReadyPort();
const resetState = process.env.SEAMS_INTENDED_SKIP_STATE_RESET !== '1';
const skipBuild = process.env.SEAMS_INTENDED_SKIP_BUILD === '1';
const managedChildren = [];
let shutdownStarted = false;
let webServerReadyServer;
const transientViteCachePaths = ['apps/seams-site/node_modules/.vite'];
const requiredSdkDistArtifacts = [
  'packages/sdk-web/dist/esm/advanced.js',
  'packages/sdk-web/dist/esm/core/config/chains.js',
  'packages/sdk-web/dist/esm/core/idempotency/createIntentId.js',
  'packages/sdk-web/dist/esm/core/rpcClients/evm/EvmClient.js',
  'packages/sdk-web/dist/esm/core/rpcClients/near/NearClient.js',
  'packages/sdk-web/dist/esm/react/context/SeamsWebProvider.js',
  'packages/sdk-web/dist/esm/react/context/index.js',
  'packages/sdk-web/dist/esm/react/index.js',
  'packages/sdk-web/dist/esm/react/styles/styles.css',
  'packages/sdk-web/dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js',
  'packages/sdk-web/dist/workers/eth-signer.worker.js',
  'packages/sdk-web/dist/workers/near-signer.worker.js',
  'packages/sdk-web/dist/workers/tempo-signer.worker.js',
];
const requiredSiteModuleGraphArtifacts = [
  'packages/sdk-web/dist/esm/advanced.js',
  'packages/sdk-web/dist/esm/core/config/chains.js',
  'packages/sdk-web/dist/esm/core/idempotency/createIntentId.js',
  'packages/sdk-web/dist/esm/core/rpcClients/evm/EvmClient.js',
  'packages/sdk-web/dist/esm/core/rpcClients/near/NearClient.js',
  'packages/sdk-web/dist/esm/react/context/SeamsWebProvider.js',
  'packages/sdk-web/dist/esm/react/context/index.js',
  'packages/sdk-web/dist/esm/react/index.js',
  'packages/sdk-web/dist/esm/react/styles/styles.css',
];

await main().catch(failStartup);

async function main() {
  assertLocalIntendedUrls();
  if (checkOnly) {
    printResolvedConfig();
    return;
  }

  installSignalHandlers();
  await terminateManagedProcessLeaksBeforeStartup();
  if (skipBuild) {
    console.log('[intended-services] skipping SDK build because SEAMS_INTENDED_SKIP_BUILD=1');
  } else {
    buildSdkArtifacts();
  }
  assertSdkDistArtifacts();
  assertD1LocalWasmArtifacts();
  clearTransientViteCaches();
  if (resetState) {
    resetLocalState();
  }
  prepareD1LocalWranglerRuntimeConfig();

  const router = startRouter();
  await waitForHttpOk(`${routerUrl}/healthz`, 'router healthz', 180_000);
  await waitForHttpOk(`${routerUrl}/readyz`, 'router readyz', 180_000);
  seedLocalConsole();

  const site = startSite();
  await waitForHttpOk(appUrl, 'site', 120_000);
  await waitForSiteModuleGraphArtifacts();
  await waitForHttpOk(intendedPageSmokeUrl(), 'intended page', 60_000);
  await waitForRouterStability();
  await startWebServerReadyServer();

  console.log('[intended-services] site and router are ready');
  await waitUntilStopped(site, router);
}

function assertLocalIntendedUrls() {
  assertUrlOrigin('SEAMS_INTENDED_APP_URL', appUrl, 'https://localhost');
  assertUrlOrigin('SEAMS_INTENDED_ROUTER_URL', routerUrl, 'https://localhost:9444');
  assertUrlOrigin('SEAMS_INTENDED_WALLET_ORIGIN', walletOrigin, 'https://localhost:8443');
}

function assertUrlOrigin(name, value, expectedOrigin) {
  const origin = new URL(value).origin;
  if (origin === expectedOrigin) return;
  throw new Error(
    `${name}=${value} is incompatible with CI-managed local startup; expected ${expectedOrigin}`,
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
  removePath('.router-ab-local');
  removePath('packages/sdk-server-ts/.wrangler/state/seams-d1');
  removePath('.runtime/intended-d1');
  removeAbsolutePath(d1LocalPersistPath);
  removeAbsolutePath(siteViteCacheDir);
}

function buildSdkArtifacts() {
  runRequiredBuild('sdk', ['run', 'build:sdk-full']);
}

function assertSdkDistArtifacts() {
  const missingArtifacts = requiredSdkDistArtifacts.filter(isMissingRepoPath);
  if (missingArtifacts.length > 0) {
    throw new Error(`SDK build did not emit required artifacts: ${missingArtifacts.join(', ')}`);
  }
  console.log(
    `[intended-services] verified ${requiredSdkDistArtifacts.length} SDK dist artifacts`,
  );
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
  runRequiredBuild('d1-local-wasm', ['-C', 'packages/sdk-server-ts', 'run', 'd1:local:ensure-wasm'], {
    ...process.env,
    SEAMS_D1_LOCAL_WASM_AUTO_BUILD: '0',
  });
}

function removePath(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  removeAbsolutePath(absolutePath);
}

function removeAbsolutePath(absolutePath) {
  if (!existsSync(absolutePath)) return;
  console.log(`[intended-services] removing ${path.relative(repoRoot, absolutePath) || absolutePath}`);
  rmSync(absolutePath, { recursive: true, force: true });
}

async function terminateManagedProcessLeaksBeforeStartup() {
  const leaks = collectManagedProcessLeaks();
  if (leaks.length === 0) return;
  console.log(`[intended-services] terminating ${leaks.length} stale managed processes`);
  terminateManagedProcessLeaks('SIGTERM');
  await delay(1_000);
  terminateManagedProcessLeaks('SIGKILL');
}

function startSite() {
  return spawnManaged('site', ['-C', 'apps/seams-site', 'run', 'vite'], siteEnv());
}

function startRouter() {
  return spawnManaged('router', ['run', 'router', '--', '--fresh'], routerEnv());
}

function seedLocalConsole() {
  console.log('[intended-services] seeding local console state');
  const result = spawnSync('pnpm', ['-C', 'tests', 'seed:intended-local-console'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID: projectEnvironmentId,
      SEAMS_INTENDED_PUBLISHABLE_KEY: publishableKey,
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

function siteEnv() {
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
    VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'local-signing-worker',
    VITE_SEAMS_PROJECT_ENVIRONMENT_ID: projectEnvironmentId,
    VITE_SEAMS_PUBLISHABLE_KEY: publishableKey,
    VITE_ENABLE_INTENDED_E2E: '1',
  };
}

function routerEnv() {
  return {
    ...process.env,
    SEAMS_D1_LOCAL_PERSIST_TO: d1LocalPersistPath,
    SEAMS_D1_LOCAL_WRANGLER_CONFIG: d1LocalWranglerConfigPath,
    SEAMS_D1_LOCAL_WASM_AUTO_BUILD: '0',
  };
}

function prepareD1LocalWranglerRuntimeConfig() {
  mkdirSync(d1LocalWranglerRuntimeDir, { recursive: true });
  const sourceConfigPath = path.join(repoRoot, 'packages/sdk-server-ts/wrangler.d1-local.toml');
  const sourceConfig = readFileSync(sourceConfigPath, 'utf8');
  const runtimeConfig = sourceConfig
    .replace(
      'main = "src/router/cloudflare/d1LocalDevWorker.ts"',
      'main = "../../packages/sdk-server-ts/src/router/cloudflare/d1LocalDevWorker.ts"',
    )
    .replace(
      'migrations_dir = "migrations/d1-console"',
      'migrations_dir = "../../packages/sdk-server-ts/migrations/d1-console"',
    )
    .replace(
      'migrations_dir = "migrations/d1-signer"',
      'migrations_dir = "../../packages/sdk-server-ts/migrations/d1-signer"',
    );
  writeFileSync(d1LocalWranglerConfigPath, runtimeConfig);

  const sourceDevVarsPath = path.join(repoRoot, 'packages/sdk-server-ts/.dev.vars');
  const fallbackDevVarsPath = path.join(repoRoot, 'packages/sdk-server-ts/dev.vars');
  const runtimeDevVarsPath = path.join(d1LocalWranglerRuntimeDir, '.dev.vars');
  if (existsSync(sourceDevVarsPath)) {
    copyFileSync(sourceDevVarsPath, runtimeDevVarsPath);
  } else if (existsSync(fallbackDevVarsPath)) {
    copyFileSync(fallbackDevVarsPath, runtimeDevVarsPath);
  }

  console.log(
    `[intended-services] prepared D1 local wrangler config at ${path.relative(repoRoot, d1LocalWranglerConfigPath)}`,
  );
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

async function waitForHttpOk(url, label, timeoutMs) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await httpOk(url)) {
      console.log(`[intended-services] ${label} ready at ${url}`);
      return;
    }
    await delay(500);
  }
  throw new Error(`${label} did not become ready at ${url}`);
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

async function httpOk(url) {
  try {
    const status = await requestStatus(url, 1_000);
    return status >= 200 && status < 300;
  } catch {
    return false;
  }
}

function requestStatus(urlValue, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlValue);
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.get(
      url,
      {
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      handleStatusResponse(resolve),
    );
    req.once('timeout', handleTimeout(req));
    req.once('error', reject);
  });
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
  await closeWebServerReadyServer();
  for (const entry of [...managedChildren].reverse()) {
    stopChild(entry);
  }
  await delay(1_500);
  for (const entry of [...managedChildren].reverse()) {
    forceStopChild(entry);
  }
  terminateManagedProcessLeaks('SIGTERM');
  await delay(1_000);
  terminateManagedProcessLeaks('SIGKILL');
  process.exit(exitCode);
}

function stopChild(entry) {
  if (!isChildRunning(entry.child)) return;
  console.log(`[intended-services] stopping ${entry.label}`);
  killChild(entry.child, 'SIGTERM', entry.killAsGroup);
}

function forceStopChild(entry) {
  if (!isChildRunning(entry.child)) return;
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
    if (error?.code !== 'ESRCH') throw error;
  }
}

function terminateManagedProcessLeaks(signal) {
  for (const entry of collectManagedProcessLeaks()) {
    killProcessId(entry.pid, signal);
  }
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
    isSiteCaddyCommand(command) ||
    isDocsVitepressCommand(command)
  );
}

function isRouterDevWorkerCommand(command) {
  return command.includes('crates/router-ab-dev/scripts/dev-local-workers.mjs --mode logs -- --fresh');
}

function isWranglerD1Command(command) {
  return (
    command.includes('wrangler dev --config wrangler.d1-local.toml') &&
    command.includes('--port 9090')
  );
}

function isLocalWorkerdCommand(command) {
  return command.includes('workerd serve') && command.includes('localhost:9090');
}

function isSiteViteCommand(command) {
  return (
    command.includes(path.join(repoRoot, 'apps/seams-site')) &&
    command.includes('vite') &&
    command.includes('--port 3600')
  );
}

function isSiteCaddyCommand(command) {
  return command.includes(`caddy run --config ${path.join(repoRoot, 'apps/seams-site/Caddyfile')}`);
}

function isDocsVitepressCommand(command) {
  return (
    command.includes(path.join(repoRoot, 'apps/docs')) &&
    command.includes('vitepress') &&
    command.includes('--port 5222')
  );
}

function killProcessId(pid, signal) {
  try {
    process.kill(pid, signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error;
  }
}

function closeWebServerReadyServer() {
  return new Promise(resolveCloseWebServerReadyServer);
}

function resolveCloseWebServerReadyServer(resolve) {
  if (!webServerReadyServer) {
    resolve();
    return;
  }
  webServerReadyServer.close(finishCloseWebServerReadyServer(resolve));
}

function finishCloseWebServerReadyServer(resolve) {
  return function finishClose() {
    webServerReadyServer = undefined;
    resolve();
  };
}
