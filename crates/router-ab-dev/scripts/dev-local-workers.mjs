import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { isAbsolute, join, relative } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const workerBinary = join(
  repoRoot,
  'crates',
  'router-ab-dev',
  'target',
  'debug',
  process.platform === 'win32' ? 'router_ab_local_worker.exe' : 'router_ab_local_worker',
);
const frontendRelayHost = '127.0.0.1';
const frontendRelayPort = 8444;
const frontendRelayBaseUrl = `http://${frontendRelayHost}:${frontendRelayPort}`;
const frontendRelayPublicUrl = 'https://localhost:9444';
const frontendRelayPublicWellKnownUrl = `${frontendRelayPublicUrl}/.well-known/webauthn`;
const frontendRelayPublicHost = 'localhost';
const frontendRelayPublicPort = 9444;

const roles = [
  {
    title: 'Router',
    role: 'router',
    envFile: '.env.router-ab.router.local',
    urlKey: 'ROUTER_PUBLIC_URL',
    requiredKeys: [
      'ROUTER_AB_LOCAL_WORKER_ROLE',
      'ROUTER_PUBLIC_URL',
      'DERIVER_A_URL',
      'DERIVER_B_URL',
      'SIGNING_WORKER_URL',
      'ROUTER_REPLAY_STORAGE_PATH',
      'ROUTER_LIFECYCLE_STORAGE_PATH',
      'ROUTER_PROJECT_POLICY_STORAGE_PATH',
      'ROUTER_QUOTA_STORAGE_PATH',
      'ROUTER_ABUSE_STORAGE_PATH',
    ],
  },
  {
    title: 'Deriver A',
    role: 'deriver-a',
    envFile: '.env.router-ab.deriver-a.local',
    urlKey: 'DERIVER_A_URL',
    requiredKeys: [
      'ROUTER_AB_LOCAL_WORKER_ROLE',
      'DERIVER_A_URL',
      'DERIVER_B_URL',
      'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
      'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
      'DERIVER_A_PEER_SIGNING_KEY',
      'DERIVER_A_PEER_VERIFYING_KEY',
      'DERIVER_B_PEER_VERIFYING_KEY',
      'DERIVER_A_ROOT_SHARE_STORAGE_PATH',
      'DERIVER_A_SEALED_ROOT_SHARES_PATH',
    ],
  },
  {
    title: 'Deriver B',
    role: 'deriver-b',
    envFile: '.env.router-ab.deriver-b.local',
    urlKey: 'DERIVER_B_URL',
    requiredKeys: [
      'ROUTER_AB_LOCAL_WORKER_ROLE',
      'DERIVER_B_URL',
      'DERIVER_A_URL',
      'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
      'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
      'DERIVER_B_PEER_SIGNING_KEY',
      'DERIVER_A_PEER_VERIFYING_KEY',
      'DERIVER_B_PEER_VERIFYING_KEY',
      'DERIVER_B_ROOT_SHARE_STORAGE_PATH',
      'DERIVER_B_SEALED_ROOT_SHARES_PATH',
    ],
  },
  {
    title: 'SigningWorker',
    role: 'signing-worker',
    envFile: '.env.router-ab.signing-worker.local',
    urlKey: 'SIGNING_WORKER_URL',
    requiredKeys: [
      'ROUTER_AB_LOCAL_WORKER_ROLE',
      'SIGNING_WORKER_URL',
      'SIGNING_WORKER_ID',
      'SIGNING_WORKER_KEY_EPOCH',
      'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
      'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      'SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH',
    ],
    forbiddenKeys: [
      'SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PUBLIC_KEY',
      'SIGNING_WORKER_RELAYER_OUTPUT_HPKE_PRIVATE_KEY',
      'SIGNING_WORKER_RELAYER_OUTPUT_STORAGE_PATH',
    ],
  },
];

const argv = process.argv.slice(2);
const options = parseArgs(argv);
const root = resolvePath(options.root);
const displayMode = options.mode === 'multiplex' && process.stdout.isTTY ? 'multiplex' : 'logs';
const labelWidth = Math.max(...roles.map((role) => role.role.length));
const panes = roles.map((role) => ({
  ...role,
  status: 'pending',
  pid: null,
  url: null,
  lines: [],
  child: null,
  exitPromise: null,
}));

let screenActive = false;
let renderTimer = null;
let shutdownStarted = false;
let rawModeEnabled = false;
const frontendRelay = {
  child: null,
  exitPromise: null,
  killAsGroup: false,
};
const frontendProxy = {
  child: null,
  exitPromise: null,
  killAsGroup: false,
};

const labelColors = {
  router: '\x1b[36m',
  'deriver-a': '\x1b[32m',
  'deriver-b': '\x1b[33m',
  'signing-worker': '\x1b[35m',
};
const resetColor = '\x1b[0m';

try {
  if (options.help) {
    printUsage();
    process.exit(0);
  }

  process.once('SIGINT', () => shutdown(130));
  process.once('SIGTERM', () => shutdown(143));
  ensureLocalEnv();
  await stopStaleLocalWorkers();
  buildWorkerBinary();
  await ensureFrontendRelay();
  if (options.mode === 'multiplex' && displayMode === 'logs') {
    console.log('Multiplex mode requires a TTY; using interleaved logs.');
  }
  startWorkers();
  if (displayMode === 'multiplex') {
    enterDashboard();
    captureInput();
    process.stdout.on('resize', scheduleRender);
  }
  scheduleRender();
} catch (error) {
  await stopStartedChildren();
  restoreTerminal();
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

function ensureLocalEnv() {
  const missing = roles.filter((role) => !existsSync(join(root, role.envFile)));
  const invalid = missing.length > 0 ? [] : collectInvalidLocalEnvFiles();
  if (options.noInit && (missing.length > 0 || invalid.length > 0)) {
    const details = [
      ...missing.map((role) => `${role.envFile}: missing`),
      ...invalid.map((entry) => `${entry.role.envFile}: ${entry.reason}`),
    ];
    throw new Error(
      `invalid Router A/B local env files: ${details.join(', ')}`,
    );
  }
  if (!options.fresh && missing.length === 0 && invalid.length === 0) {
    return;
  }
  if (!options.fresh && invalid.length > 0) {
    for (const entry of invalid) {
      console.log(`regenerating Router A/B local env: ${entry.role.envFile} ${entry.reason}`);
    }
  }

  mkdirSync(root, { recursive: true });
  const args = [
    'run',
    '--manifest-path',
    'crates/router-ab-dev/Cargo.toml',
    '--bin',
    'router_ab_local_init',
    '--',
    '--root',
    root,
    '--force',
  ];
  if (!options.defaultPorts) {
    args.push('--ephemeral-ports');
  }
  run('cargo', args);
}

function collectInvalidLocalEnvFiles() {
  const invalid = [];
  for (const role of roles) {
    const path = join(root, role.envFile);
    const env = readEnvFile(path);
    const missingKey = role.requiredKeys.find((key) => !env.has(key) || !env.get(key));
    if (missingKey) {
      invalid.push({ role, reason: `missing ${missingKey}` });
      continue;
    }
    const forbiddenKey = role.forbiddenKeys?.find((key) => env.has(key));
    if (forbiddenKey) {
      invalid.push({ role, reason: `contains obsolete ${forbiddenKey}` });
    }
  }
  return invalid;
}

async function stopStaleLocalWorkers() {
  const staleWorkers = findStaleLocalWorkers();
  if (staleWorkers.length === 0) {
    return;
  }

  const pane = getRouterPane();
  for (const stale of staleWorkers) {
    appendLine(pane, `stopping stale ${stale.role} worker pid ${stale.pid}`);
    killPid(stale.pid, 'SIGTERM');
  }

  const deadline = Date.now() + 1_500;
  while (Date.now() < deadline && staleWorkers.some((stale) => isPidRunning(stale.pid))) {
    await sleep(100);
  }

  for (const stale of staleWorkers) {
    if (isPidRunning(stale.pid)) {
      appendLine(pane, `force stopping stale ${stale.role} worker pid ${stale.pid}`);
      killPid(stale.pid, 'SIGKILL');
    }
  }
}

function findStaleLocalWorkers() {
  const child = spawnSync('ps', ['-ww', '-axo', 'pid=,command='], {
    encoding: 'utf8',
  });
  if (child.status !== 0 || !child.stdout) {
    return [];
  }

  const stale = [];
  for (const line of child.stdout.split(/\r?\n/)) {
    const match = line.match(/^\s*(\d+)\s+(.+)$/);
    if (!match) {
      continue;
    }
    const pid = Number(match[1]);
    const command = match[2];
    if (!Number.isSafeInteger(pid) || pid === process.pid) {
      continue;
    }
    for (const role of roles) {
      const envPath = join(root, role.envFile);
      if (
        command.includes('router_ab_local_worker') &&
        command.includes(`--role ${role.role}`) &&
        command.includes(`--env ${envPath}`)
      ) {
        stale.push({ pid, role: role.role });
      }
    }
  }
  return stale;
}

function buildWorkerBinary() {
  run('cargo', [
    'build',
    '--manifest-path',
    'crates/router-ab-dev/Cargo.toml',
    '--bin',
    'router_ab_local_worker',
  ]);
}

function startWorkers() {
  for (const pane of panes) {
    pane.url = readEnvValue(join(root, pane.envFile), pane.urlKey);
    appendLine(pane, `env ${relative(repoRoot, join(root, pane.envFile))}`);
    appendLine(pane, `url ${pane.url}`);
    appendLine(pane, 'starting worker...');
    pane.status = 'starting';

    const child = spawn(workerBinary, ['--role', pane.role, '--env', join(root, pane.envFile)], {
      cwd: root,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    pane.child = child;
    pane.pid = child.pid ?? null;
    pane.exitPromise = new Promise((resolve) => child.once('exit', resolve));

    child.stdout.on('data', (chunk) => appendChunk(pane, chunk));
    child.stderr.on('data', (chunk) => appendChunk(pane, chunk, 'stderr: '));
    child.once('spawn', () => {
      appendLine(pane, `pid ${child.pid}`);
      appendProcessStatus(pane, child.pid);
      pollReady(pane);
    });
    child.once('exit', (code, signal) => {
      pane.status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
      appendLine(pane, `worker stopped: ${pane.status}`);
      scheduleRender();
      if (!shutdownStarted) {
        shutdown(exitCodeForChildExit(code, signal));
      }
    });
    child.once('error', (error) => {
      pane.status = 'spawn error';
      appendLine(pane, `spawn error: ${error.message}`);
      scheduleRender();
    });
  }
}

async function ensureFrontendRelay() {
  const pane = getRouterPane();
  if (options.noRelay) {
    appendLine(pane, 'frontend relay auto-start disabled');
    return;
  }
  if (await healthzIsReady(frontendRelayBaseUrl)) {
    appendLine(pane, `frontend relay ready at ${frontendRelayBaseUrl}`);
    await ensureFrontendRelayPublicProxy();
    return;
  }
  if (await tcpIsListening(frontendRelayHost, frontendRelayPort)) {
    throw new Error(
      `${frontendRelayBaseUrl} is already listening, but /healthz did not return 200. Stop that process or start the relay with pnpm server.`,
    );
  }

  appendLine(pane, 'frontend relay not running; starting pnpm server...');
  const child = spawn('pnpm', ['run', 'server'], {
    cwd: repoRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });
  frontendRelay.child = child;
  frontendRelay.killAsGroup = process.platform !== 'win32';
  frontendRelay.exitPromise = new Promise((resolve) => child.once('exit', resolve));

  child.stdout.on('data', (chunk) => appendChunk(pane, chunk, 'relay: '));
  child.stderr.on('data', (chunk) => appendChunk(pane, chunk, 'relay stderr: '));
  child.once('spawn', () => {
    appendLine(pane, `frontend relay pid ${child.pid}`);
    appendProcessStatus(pane, child.pid);
  });
  child.once('exit', (code, signal) => {
    const status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
    appendLine(pane, `frontend relay stopped: ${status}`);
    scheduleRender();
    if (!shutdownStarted) {
      shutdown(exitCodeForChildExit(code, signal));
    }
  });
  child.once('error', (error) => {
    appendLine(pane, `frontend relay spawn error: ${error.message}`);
    scheduleRender();
    if (!shutdownStarted) {
      shutdown(1);
    }
  });

  await waitForHealthz(frontendRelayBaseUrl, 90_000);
  appendLine(pane, `frontend relay ready at ${frontendRelayBaseUrl}`);
  await ensureFrontendRelayPublicProxy();
}

async function ensureFrontendRelayPublicProxy() {
  const pane = getRouterPane();
  if (await urlStatusIsReady(frontendRelayPublicWellKnownUrl)) {
    await waitForStableUrlStatus(frontendRelayPublicWellKnownUrl, 2_000, 15_000);
    appendLine(pane, `frontend relay HTTPS proxy ready at ${frontendRelayPublicUrl}`);
    return;
  }

  if (await tcpIsListening(frontendRelayPublicHost, frontendRelayPublicPort)) {
    try {
      await waitForUrlStatus(frontendRelayPublicWellKnownUrl, 5_000);
      await waitForStableUrlStatus(frontendRelayPublicWellKnownUrl, 2_000, 15_000);
      appendLine(pane, `frontend relay HTTPS proxy ready at ${frontendRelayPublicUrl}`);
      return;
    } catch {
      const status = await describeUrlStatus(frontendRelayPublicWellKnownUrl);
      throw new Error(
        `${frontendRelayPublicWellKnownUrl} is listening but not healthy (${status}). ` +
          `${frontendRelayBaseUrl}/healthz is healthy, so restart the local Caddy proxy with pnpm caddy or stop the process on ${frontendRelayPublicPort}.`,
      );
    }
  }

  appendLine(pane, 'frontend relay HTTPS proxy not running; starting pnpm caddy...');
  const child = spawn('pnpm', ['run', 'caddy'], {
    cwd: repoRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });
  frontendProxy.child = child;
  frontendProxy.killAsGroup = process.platform !== 'win32';
  frontendProxy.exitPromise = new Promise((resolve) => child.once('exit', resolve));

  child.stdout.on('data', (chunk) => appendChunk(pane, chunk, 'caddy: '));
  child.stderr.on('data', (chunk) => appendChunk(pane, chunk, 'caddy stderr: '));
  child.once('spawn', () => {
    appendLine(pane, `frontend relay HTTPS proxy pid ${child.pid}`);
    appendProcessStatus(pane, child.pid);
  });
  child.once('exit', (code, signal) => {
    const status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
    appendLine(pane, `frontend relay HTTPS proxy stopped: ${status}`);
    scheduleRender();
    if (!shutdownStarted) {
      shutdown(exitCodeForChildExit(code, signal));
    }
  });
  child.once('error', (error) => {
    appendLine(pane, `frontend relay HTTPS proxy spawn error: ${error.message}`);
    scheduleRender();
    if (!shutdownStarted) {
      shutdown(1);
    }
  });

  await waitForUrlStatus(frontendRelayPublicWellKnownUrl, 90_000);
  await waitForStableUrlStatus(frontendRelayPublicWellKnownUrl, 2_000, 15_000);
  appendLine(pane, `frontend relay HTTPS proxy ready at ${frontendRelayPublicUrl}`);
}

function pollReady(pane, attempts = 0) {
  if (shutdownStarted || pane.status.startsWith('exit') || pane.status.startsWith('signal')) {
    return;
  }
  healthCheck(pane.url)
    .then(() => {
      pane.status = 'ready';
      appendLine(pane, 'health ready');
    })
    .catch(() => {
      if (attempts < 100) {
        setTimeout(() => pollReady(pane, attempts + 1), 50);
      } else {
        pane.status = 'not ready';
        appendLine(pane, 'health check timed out');
      }
    })
    .finally(scheduleRender);
}

function healthCheck(baseUrl) {
  return requestStatus(new URL('/healthz', baseUrl), 500).then((status) => {
    if (status.statusCode !== 200) {
      throw new Error(`status ${status.statusCode}`);
    }
  });
}

async function healthzIsReady(baseUrl) {
  try {
    await healthCheck(baseUrl);
    return true;
  } catch {
    return false;
  }
}

function tcpIsListening(host, port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;
    const done = (value) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(250);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

async function waitForHealthz(baseUrl, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await healthzIsReady(baseUrl)) {
      return;
    }
    await sleep(250);
  }
  throw new Error(`frontend relay did not become healthy at ${baseUrl}/healthz`);
}

async function urlStatusIsReady(url) {
  try {
    const status = await requestStatus(url, 750);
    return status.statusCode === 200;
  } catch {
    return false;
  }
}

async function waitForUrlStatus(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await urlStatusIsReady(url)) {
      return;
    }
    await sleep(250);
  }
  const status = await describeUrlStatus(url);
  throw new Error(`${url} did not return HTTP 200 (${status})`);
}

async function waitForStableUrlStatus(url, stableMs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let stableSince = null;
  while (Date.now() < deadline) {
    if (await urlStatusIsReady(url)) {
      stableSince ??= Date.now();
      if (Date.now() - stableSince >= stableMs) {
        return;
      }
    } else {
      stableSince = null;
    }
    await sleep(250);
  }
  const status = await describeUrlStatus(url);
  throw new Error(`${url} did not stay healthy for ${stableMs}ms (${status})`);
}

async function describeUrlStatus(url) {
  try {
    const status = await requestStatus(url, 1_000);
    return `HTTP ${status.statusCode ?? 'unknown'}`;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

function requestStatus(urlInput, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = urlInput instanceof URL ? urlInput : new URL(urlInput);
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.get(
      url,
      {
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      (response) => {
        response.resume();
        resolve({ statusCode: response.statusCode ?? null });
      },
    );
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
}

async function shutdown(exitCode) {
  if (shutdownStarted) {
    return;
  }
  shutdownStarted = true;
  if (isChildRunning(frontendProxy.child)) {
    appendLine(getRouterPane(), 'stopping frontend relay HTTPS proxy...');
    killChild(frontendProxy.child, 'SIGTERM', frontendProxy.killAsGroup);
  }
  if (isChildRunning(frontendRelay.child)) {
    appendLine(getRouterPane(), 'stopping frontend relay...');
    killChild(frontendRelay.child, 'SIGTERM', frontendRelay.killAsGroup);
  }
  for (const pane of panes) {
    if (isChildRunning(pane.child)) {
      pane.status = 'stopping';
      appendLine(pane, 'stopping worker...');
      killChild(pane.child, 'SIGTERM');
    }
  }
  scheduleRender();

  await Promise.race([
    Promise.all(
      [
        frontendProxy.exitPromise,
        frontendRelay.exitPromise,
        ...panes.map((pane) => pane.exitPromise),
      ].filter(Boolean),
    ),
    sleep(1200),
  ]);

  if (isChildRunning(frontendProxy.child)) {
    killChild(frontendProxy.child, 'SIGKILL', frontendProxy.killAsGroup);
  }
  if (isChildRunning(frontendRelay.child)) {
    killChild(frontendRelay.child, 'SIGKILL', frontendRelay.killAsGroup);
  }
  for (const pane of panes) {
    if (isChildRunning(pane.child)) {
      killChild(pane.child, 'SIGKILL');
    }
  }
  restoreTerminal();
  console.log('Stopped Router A/B local dev workers, frontend relay, and HTTPS proxy.');
  process.exit(exitCode);
}

async function stopStartedChildren() {
  for (const pane of panes) {
    if (isChildRunning(pane.child)) {
      killChild(pane.child, 'SIGTERM');
    }
  }
  if (isChildRunning(frontendRelay.child)) {
    killChild(frontendRelay.child, 'SIGTERM', frontendRelay.killAsGroup);
  }
  if (isChildRunning(frontendProxy.child)) {
    killChild(frontendProxy.child, 'SIGTERM', frontendProxy.killAsGroup);
  }
  await Promise.race([
    Promise.all(
      [
        frontendProxy.exitPromise,
        frontendRelay.exitPromise,
        ...panes.map((pane) => pane.exitPromise),
      ].filter(Boolean),
    ),
    sleep(1200),
  ]);
}

function isChildRunning(child) {
  return Boolean(child && child.exitCode === null && child.signalCode === null);
}

function exitCodeForChildExit(code, signal) {
  if (code === 0) {
    return 0;
  }
  if (signal === 'SIGINT') {
    return 130;
  }
  if (signal === 'SIGTERM') {
    return 143;
  }
  return 1;
}

function isPidRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function killPid(pid, signal) {
  try {
    process.kill(pid, signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      throw error;
    }
  }
}

function killChild(child, signal, killAsGroup = false) {
  if (!child?.pid) {
    return;
  }
  try {
    if (killAsGroup) {
      process.kill(-child.pid, signal);
    } else {
      child.kill(signal);
    }
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      throw error;
    }
  }
}

function enterDashboard() {
  if (displayMode !== 'multiplex' || !process.stdout.isTTY) {
    return;
  }
  screenActive = true;
  process.stdout.write(
    [
      '\x1b[?1049h',
      '\x1b[?25l',
      '\x1b[?7l',
      '\x1b[?1000h',
      '\x1b[?1002h',
      '\x1b[?1006h',
      '\x1b[?1007h',
      '\x1b[2J',
      '\x1b[H',
    ].join(''),
  );
}

function restoreTerminal() {
  releaseInput();
  if (!screenActive) {
    return;
  }
  screenActive = false;
  process.stdout.write(
    [
      '\x1b[?1007l',
      '\x1b[?1006l',
      '\x1b[?1002l',
      '\x1b[?1000l',
      '\x1b[?7h',
      '\x1b[?25h',
      '\x1b[?1049l',
    ].join(''),
  );
}

function captureInput() {
  if (displayMode !== 'multiplex' || !process.stdin.isTTY) {
    return;
  }
  process.stdin.resume();
  process.stdin.on('data', handleInput);
  if (typeof process.stdin.setRawMode === 'function') {
    process.stdin.setRawMode(true);
    rawModeEnabled = true;
  }
}

function releaseInput() {
  process.stdin.off('data', handleInput);
  if (rawModeEnabled && typeof process.stdin.setRawMode === 'function') {
    process.stdin.setRawMode(false);
    rawModeEnabled = false;
  }
}

function handleInput(chunk) {
  for (const byte of chunk) {
    if (byte === 0x03) {
      shutdown(130);
      return;
    }
  }
}

function scheduleRender() {
  if (displayMode !== 'multiplex' || !process.stdout.isTTY) {
    return;
  }
  if (renderTimer) {
    return;
  }
  renderTimer = setTimeout(() => {
    renderTimer = null;
    renderDashboard();
  }, 40);
}

function renderDashboard() {
  if (!screenActive) {
    return;
  }
  const width = Math.max(process.stdout.columns ?? 120, 60);
  const height = Math.max(process.stdout.rows ?? 32, 16);
  const grid = Array.from({ length: height }, () => Array(width).fill(' '));
  const centerX = Math.floor(width / 2);
  const splitY = Math.floor(height / 2);
  drawDashboardBorders(grid, width, height, centerX, splitY);
  const layouts = [
    { x: 1, y: 1, w: centerX - 1, h: splitY - 1, headerX: 2, headerY: 0 },
    {
      x: centerX + 1,
      y: 1,
      w: width - centerX - 2,
      h: splitY - 1,
      headerX: centerX + 2,
      headerY: 0,
    },
    {
      x: 1,
      y: splitY + 1,
      w: centerX - 1,
      h: height - splitY - 2,
      headerX: 2,
      headerY: splitY,
    },
    {
      x: centerX + 1,
      y: splitY + 1,
      w: width - centerX - 2,
      h: height - splitY - 2,
      headerX: centerX + 2,
      headerY: splitY,
    },
  ];

  panes.forEach((pane, index) => drawPane(grid, layouts[index], pane));
  process.stdout.write(`\x1b[H${grid.map((row) => row.join('')).join('\n')}`);
}

function drawDashboardBorders(grid, width, height, centerX, splitY) {
  for (let col = 0; col < width; col += 1) {
    grid[0][col] = '─';
    grid[splitY][col] = '─';
    grid[height - 1][col] = '─';
  }
  for (let row = 0; row < height; row += 1) {
    grid[row][0] = '│';
    grid[row][centerX] = '│';
    grid[row][width - 1] = '│';
  }

  grid[0][0] = '┌';
  grid[0][centerX] = '┬';
  grid[0][width - 1] = '┐';
  grid[splitY][0] = '├';
  grid[splitY][centerX] = '┼';
  grid[splitY][width - 1] = '┤';
  grid[height - 1][0] = '└';
  grid[height - 1][centerX] = '┴';
  grid[height - 1][width - 1] = '┘';
}

function drawPane(grid, layout, pane) {
  const { x, y, w, h, headerX, headerY } = layout;
  if (w < 8 || h < 2) {
    return;
  }

  const header = ` ${pane.title} | ${pane.status}${pane.pid ? ` | pid ${pane.pid}` : ''} `;
  drawText(grid, headerX, headerY, clip(header, w - 2), w - 2);

  const visibleLines = pane.lines.slice(-h);
  for (let index = 0; index < visibleLines.length; index += 1) {
    drawText(grid, x, y + index, clip(visibleLines[index], w), w);
  }
}

function drawText(grid, x, y, text, maxWidth) {
  if (y < 0 || y >= grid.length) {
    return;
  }
  const clean = stripAnsi(text).slice(0, maxWidth);
  for (let i = 0; i < clean.length && x + i < grid[y].length; i += 1) {
    if (x + i >= 0) {
      grid[y][x + i] = clean[i];
    }
  }
}

function appendChunk(pane, chunk, prefix = '') {
  const text = stripAnsi(String(chunk));
  for (const rawLine of text.split(/\r?\n/)) {
    if (rawLine.length === 0) {
      continue;
    }
    appendLine(pane, `${prefix}${rawLine}`);
  }
}

function appendLine(pane, line) {
  const wrapped = wrap(stripAnsi(line), 180);
  pane.lines.push(...wrapped);
  if (pane.lines.length > 500) {
    pane.lines.splice(0, pane.lines.length - 500);
  }
  if (displayMode === 'logs') {
    for (const wrappedLine of wrapped) {
      process.stdout.write(`${formatLogLine(pane, wrappedLine)}\n`);
    }
  }
  scheduleRender();
}

function formatLogLine(pane, line) {
  const label = pane.role.padEnd(labelWidth, ' ');
  if (!process.stdout.isTTY || process.env.NO_COLOR) {
    return `${label} | ${line}`;
  }
  const color = labelColors[pane.role] ?? '';
  return `${color}${label}${resetColor} | ${line}`;
}

function appendProcessStatus(pane, pid) {
  if (!pid || process.platform === 'win32') {
    return;
  }
  const child = spawnSync('ps', ['-p', String(pid), '-o', 'pid=,ppid=,stat=,command='], {
    encoding: 'utf8',
  });
  const line = child.stdout?.trim().split(/\r?\n/)[0];
  if (line) {
    appendLine(pane, `ps ${line}`);
  }
}

function wrap(line, width) {
  if (line.length <= width) {
    return [line];
  }
  const lines = [];
  for (let i = 0; i < line.length; i += width) {
    lines.push(line.slice(i, i + width));
  }
  return lines;
}

function clip(value, width) {
  if (value.length <= width) {
    return value;
  }
  if (width <= 3) {
    return value.slice(0, width);
  }
  return `${value.slice(0, width - 3)}...`;
}

function stripAnsi(value) {
  return value.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '');
}

function readEnvValue(path, key) {
  const env = readEnvFile(path);
  const value = env.get(key);
  if (value) {
    return value;
  }
  throw new Error(`${path} is missing ${key}`);
}

function readEnvFile(path) {
  const env = new Map();
  const contents = readFileSync(path, 'utf8');
  for (const [lineIndex, line] of contents.split(/\r?\n/).entries()) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const delimiterIndex = trimmed.indexOf('=');
    if (delimiterIndex === -1) {
      throw new Error(`${path}:${lineIndex + 1} expected KEY=value`);
    }
    const key = trimmed.slice(0, delimiterIndex);
    const value = trimmed.slice(delimiterIndex + 1);
    if (!key) {
      throw new Error(`${path}:${lineIndex + 1} has an empty env key`);
    }
    if (env.has(key)) {
      throw new Error(`${path}:${lineIndex + 1} has duplicate env key ${key}`);
    }
    env.set(key, value);
  }
  return env;
}

function run(command, args) {
  const child = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
  });
  if (child.status !== 0) {
    process.exit(child.status ?? 1);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseArgs(args) {
  const parsed = {
    root: '.',
    mode: 'logs',
    fresh: false,
    defaultPorts: false,
    noInit: false,
    noRelay: false,
    help: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case '--':
        break;
      case '--root':
        parsed.root = readArgValue(args, ++index, '--root');
        break;
      case '--mode': {
        const mode = readArgValue(args, ++index, '--mode');
        if (mode !== 'logs' && mode !== 'multiplex') {
          throw new Error(`--mode must be logs or multiplex\n${usage()}`);
        }
        parsed.mode = mode;
        break;
      }
      case '--fresh':
        parsed.fresh = true;
        break;
      case '--default-ports':
        parsed.defaultPorts = true;
        break;
      case '--no-init':
        parsed.noInit = true;
        break;
      case '--no-relay':
        parsed.noRelay = true;
        break;
      case '--help':
      case '-h':
        parsed.help = true;
        break;
      default:
        throw new Error(`unknown argument ${arg}\n${usage()}`);
    }
  }
  return parsed;
}

function getRouterPane() {
  return panes[0];
}

function readArgValue(args, index, name) {
  const value = args[index];
  if (!value || value.startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function resolvePath(path) {
  return isAbsolute(path) ? path : join(repoRoot, path);
}

function printUsage() {
  console.log(usage());
}

function usage() {
  return `usage: pnpm router [-- --root <path>] [--fresh] [--default-ports] [--no-init] [--no-relay]
       pnpm router:multiplex [-- --root <path>] [--fresh] [--default-ports] [--no-init] [--no-relay]

Runs Router, Deriver A, Deriver B, and SigningWorker in one terminal.
Also starts the frontend relay server on 127.0.0.1:8444 when it is not already running.
Also verifies https://localhost:9444/.well-known/webauthn and starts Caddy when that local HTTPS proxy is absent.

Options:
  --root <path>      Local root containing generated env files. Defaults to repo root.
  --mode <mode>      Display mode: logs or multiplex. Defaults to logs.
  --fresh           Regenerate env files before launch.
  --default-ports   Use 8787-8790 when generating env files. Fresh init defaults to free ports.
  --no-init         Require env files to already exist.
  --no-relay        Do not start the frontend relay server.

Press Ctrl-C to stop all workers, stop started relay/proxy processes, and restore the terminal.`;
}
