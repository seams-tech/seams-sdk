import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { isAbsolute, join, relative } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

import { prepareRouterAbD1LocalRuntimeConfig } from './d1-local-runtime-config.mjs';
import { prepareRouterAbStrictLocalRuntimeConfigs } from './strict-local-runtime-config.mjs';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
dotenv.config({ path: join(repoRoot, '.env.intended.local') });
const gatewayHost = '127.0.0.1';
const gatewayPort = 9090;
const gatewayBaseUrl = `http://${gatewayHost}:${gatewayPort}`;
const gatewayInternalWellKnownUrl = `${gatewayBaseUrl}/.well-known/webauthn`;
const gatewayPublicUrl = 'https://localhost:9444';
const gatewayPublicWellKnownUrl = `${gatewayPublicUrl}/.well-known/webauthn`;
const gatewayPublicHost = 'localhost';
const gatewayPublicPort = 9444;
const commitmentPolicyBuildEnvFile = '.env.router-ab.ecdsa-commitment-policy.build.local';
const productionWorkerEndpoints = Object.freeze([
  { role: 'router', label: 'mpc-router', port: 9100, url: 'http://127.0.0.1:9100' },
  { role: 'deriver-a', port: 9101, url: 'http://127.0.0.1:9101' },
  { role: 'deriver-b', port: 9102, url: 'http://127.0.0.1:9102' },
  { role: 'signing-worker', port: 9103, url: 'http://127.0.0.1:9103' },
]);

const localEnvRoles = [
  {
    role: 'deriver-a',
    envFile: '.env.router-ab.deriver-a.local',
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
    role: 'deriver-b',
    envFile: '.env.router-ab.deriver-b.local',
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
    role: 'signing-worker',
    envFile: '.env.router-ab.signing-worker.local',
    requiredKeys: [
      'ROUTER_AB_LOCAL_WORKER_ROLE',
      'SIGNING_WORKER_URL',
      'SIGNING_WORKER_ID',
      'SIGNING_WORKER_KEY_EPOCH',
      'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
      'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      'SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH',
      'ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON',
    ],
    requiredJsonObjectKeys: ['ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON'],
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
const d1LocalPersistPath = resolvePath(
  process.env.SEAMS_D1_LOCAL_PERSIST_TO || join(root, '.runtime', 'router-d1-local'),
);
const d1LocalWranglerConfigPath = resolvePath(
  process.env.SEAMS_D1_LOCAL_WRANGLER_CONFIG ||
    join(root, '.runtime', 'wrangler-d1-local', 'wrangler.d1-local.toml'),
);
const strictPersistPath = join(root, '.runtime', 'router-ab-strict-state');
const strictWorkerBuildRoot = join(repoRoot, 'crates', 'router-ab-cloudflare', 'build');
const strictBuildReceiptPath = join(strictWorkerBuildRoot, 'local-build-receipt.json');
const ecdsaDerivationClientRoot = join(repoRoot, 'wasm', 'router_ab_ecdsa_derivation_client');
const ecdsaDerivationClientDependencyPath = join(
  ecdsaDerivationClientRoot,
  'target',
  'wasm32-unknown-unknown',
  'release',
  'deps',
  'router_ab_ecdsa_derivation_client.d',
);
const ecdsaDerivationClientPackageWasmPath = join(
  ecdsaDerivationClientRoot,
  'pkg',
  'router_ab_ecdsa_derivation_client_bg.wasm',
);
const ecdsaDerivationClientSdkWasmPaths = [
  join(
    repoRoot,
    'packages',
    'sdk-web',
    'dist',
    'workers',
    'router_ab_ecdsa_derivation_client_bg.wasm',
  ),
  join(
    repoRoot,
    'packages',
    'sdk-web',
    'dist',
    'public',
    'sdk',
    'workers',
    'router_ab_ecdsa_derivation_client_bg.wasm',
  ),
  join(
    repoRoot,
    'packages',
    'sdk-web',
    'dist',
    'esm',
    'wasm',
    'router_ab_ecdsa_derivation_client',
    'pkg',
    'router_ab_ecdsa_derivation_client_bg.wasm',
  ),
];
const ecdsaCommitmentPolicyBuildKeys = [
  'ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX',
  'ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX',
  'ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH',
];
let strictRuntime;
const displayMode = options.mode === 'multiplex' && process.stdout.isTTY ? 'multiplex' : 'logs';
const labelWidth = 'signing-worker'.length;
const gatewayPane = {
  title: 'Gateway',
  role: 'gateway',
  logLabel: 'gateway',
  status: 'pending',
  pid: null,
  url: gatewayBaseUrl,
  lines: [],
  child: null,
  exitPromise: null,
};
const workerPanes = [
  { title: 'MPCRouter', role: 'mpc-router', logLabel: 'mpc-router' },
  { title: 'Deriver A', role: 'deriver-a', logLabel: 'deriver-a' },
  { title: 'Deriver B', role: 'deriver-b', logLabel: 'deriver-b' },
  {
    title: 'SigningWorker',
    role: 'signing-worker',
    logLabel: 'signing-worker',
  },
].map((role) => ({
  ...role,
  status: 'pending',
  pid: null,
  url: null,
  lines: [],
  child: null,
  exitPromise: null,
  killAsGroup: false,
}));
const panes = [gatewayPane, ...workerPanes];

let screenActive = false;
let renderTimer = null;
let shutdownStarted = false;
let rawModeEnabled = false;
const gateway = {
  child: null,
  exitPromise: null,
  killAsGroup: false,
};
const gatewayHttpsProxy = {
  child: null,
  exitPromise: null,
  killAsGroup: false,
};

const labelColors = {
  gateway: '\x1b[36m',
  'mpc-router': '\x1b[94m',
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
  if (options.buildOnly) {
    await assertProductionWorkerPortsAvailable();
  } else {
    await stopExistingProductionWorkerProcesses();
  }
  ensureLocalEnv();
  if (options.buildOnly) {
    buildProductionWorkerBinaries();
    console.log('Router A/B Cloudflare Worker artifacts are ready.');
    process.exit(0);
  }
  strictRuntime = prepareRouterAbStrictLocalRuntimeConfigs({
    repoRoot,
    localEnvRoot: root,
  });
  prepareD1LocalRouterConfig();
  assertProductionWorkerBinariesReady();
  assertBrowserEcdsaClientPolicyReady();
  await assertProductionWorkerPortsAvailable();
  if (options.mode === 'multiplex' && displayMode === 'logs') {
    console.log('Multiplex mode requires a TTY; using interleaved logs.');
  }
  startProductionWorkers();
  await waitForProductionWorkers();
  await ensureGateway();
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
  const missing = localEnvRoles.filter((role) => !existsSync(join(root, role.envFile)));
  const commitmentPolicyBuildEnvMissing = !existsSync(join(root, commitmentPolicyBuildEnvFile));
  const invalid = missing.length > 0 ? [] : collectInvalidLocalEnvFiles();
  if (
    options.noInit &&
    (missing.length > 0 || invalid.length > 0 || commitmentPolicyBuildEnvMissing)
  ) {
    const details = [
      ...missing.map((role) => `${role.envFile}: missing`),
      ...invalid.map((entry) => `${entry.role.envFile}: ${entry.reason}`),
      ...(commitmentPolicyBuildEnvMissing ? [`${commitmentPolicyBuildEnvFile}: missing`] : []),
    ];
    throw new Error(`invalid Router A/B local env files: ${details.join(', ')}`);
  }
  if (
    !options.fresh &&
    missing.length === 0 &&
    invalid.length === 0 &&
    !commitmentPolicyBuildEnvMissing
  ) {
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
  run('cargo', args);
}

function prepareD1LocalRouterConfig() {
  prepareRouterAbD1LocalRuntimeConfig({
    repoRoot,
    localEnvRoot: root,
    outputConfigPath: d1LocalWranglerConfigPath,
    workerUrls: strictRuntime.workerUrls,
  });
}

function collectInvalidLocalEnvFiles() {
  const invalid = [];
  for (const role of localEnvRoles) {
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
      continue;
    }
    const invalidJsonObjectKey = role.requiredJsonObjectKeys?.find(
      (key) => !isJsonObject(env.get(key)),
    );
    if (invalidJsonObjectKey) {
      invalid.push({ role, reason: `${invalidJsonObjectKey} must be a JSON object` });
    }
  }
  return invalid;
}

function isJsonObject(value) {
  if (typeof value !== 'string') return false;
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

function buildProductionWorkerBinaries() {
  const buildEnvironment = loadCommitmentPolicyBuildEnvironment();
  const strictWorkerRoot = join(repoRoot, 'crates', 'router-ab-cloudflare');
  for (const role of ['router', 'deriver-a', 'deriver-b', 'signing-worker']) {
    run('bash', ['scripts/build-strict-worker.sh', role], buildEnvironment, strictWorkerRoot);
  }
  const missingArtifacts = missingProductionWorkerArtifactPaths();
  if (missingArtifacts.length > 0) {
    throw new Error(
      `Router A/B Worker build completed without required artifacts: ${missingArtifacts.join(', ')}`,
    );
  }
  mkdirSync(strictWorkerBuildRoot, { recursive: true });
  writeFileSync(
    strictBuildReceiptPath,
    `${JSON.stringify(
      {
        schema_version: 'router_ab_strict_local_build_v1',
        commitment_policy_build_sha256: commitmentPolicyBuildSha256(),
        roles: ['router', 'deriver-a', 'deriver-b', 'signing-worker'],
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
}

function assertProductionWorkerBinariesReady() {
  const missingArtifacts = missingProductionWorkerArtifactPaths();
  if (missingArtifacts.length > 0) {
    throw new Error(
      `Router A/B Worker artifacts are missing. Run pnpm build:sdk before pnpm router. Missing: ${missingArtifacts.join(', ')}`,
    );
  }
  if (!existsSync(strictBuildReceiptPath)) {
    throw new Error(
      'Router A/B Worker build receipt is missing. Run pnpm build:sdk before pnpm router.',
    );
  }

  let receipt;
  try {
    receipt = JSON.parse(readFileSync(strictBuildReceiptPath, 'utf8'));
  } catch {
    throw new Error(
      'Router A/B Worker build receipt is invalid. Run pnpm build:sdk before pnpm router.',
    );
  }
  const expectedRoles = ['router', 'deriver-a', 'deriver-b', 'signing-worker'];
  const rolesMatch =
    Array.isArray(receipt.roles) &&
    receipt.roles.length === expectedRoles.length &&
    receipt.roles.join('\0') === expectedRoles.join('\0');
  if (
    receipt.schema_version !== 'router_ab_strict_local_build_v1' ||
    receipt.commitment_policy_build_sha256 !== commitmentPolicyBuildSha256() ||
    !rolesMatch
  ) {
    throw new Error(
      'Router A/B Worker artifacts do not match the current local commitment policy. Run pnpm build:sdk before pnpm router.',
    );
  }
}

function assertBrowserEcdsaClientPolicyReady() {
  const requiredPaths = [
    ecdsaDerivationClientDependencyPath,
    ecdsaDerivationClientPackageWasmPath,
    ...ecdsaDerivationClientSdkWasmPaths,
  ];
  const missingPaths = [];
  for (const path of requiredPaths) {
    if (!existsSync(path)) {
      missingPaths.push(path);
    }
  }
  if (missingPaths.length > 0) {
    throw staleBrowserEcdsaClientError(`Missing: ${missingPaths.join(', ')}`);
  }

  const compiledPins = parseCompiledEcdsaCommitmentPolicyPins(
    readFileSync(ecdsaDerivationClientDependencyPath, 'utf8'),
  );
  const expectedPins = loadCommitmentPolicyBuildEnvironment();
  for (const key of ecdsaCommitmentPolicyBuildKeys) {
    if (compiledPins[key] !== expectedPins[key]) {
      throw staleBrowserEcdsaClientError(`Compile-time pin mismatch: ${key}`);
    }
  }

  const packageWasmSha256 = sha256File(ecdsaDerivationClientPackageWasmPath);
  for (const path of ecdsaDerivationClientSdkWasmPaths) {
    if (sha256File(path) !== packageWasmSha256) {
      throw staleBrowserEcdsaClientError(`Bundled WASM does not match package output: ${path}`);
    }
  }
}

function parseCompiledEcdsaCommitmentPolicyPins(dependencyMetadata) {
  const pins = {};
  for (const line of dependencyMetadata.split('\n')) {
    const match = /^# env-dep:([^=]+)=(.*)$/.exec(line);
    if (match && ecdsaCommitmentPolicyBuildKeys.includes(match[1])) {
      pins[match[1]] = match[2];
    }
  }
  return pins;
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function staleBrowserEcdsaClientError(detail) {
  return new Error(
    `Browser ECDSA client artifacts do not match the current local commitment policy. Run pnpm build:sdk-full before pnpm router. ${detail}`,
  );
}

function productionWorkerArtifactPaths() {
  const paths = [];
  for (const role of ['router', 'deriver-a', 'deriver-b', 'signing-worker']) {
    paths.push(join(strictWorkerBuildRoot, role, 'worker', 'shim.mjs'));
    paths.push(join(strictWorkerBuildRoot, role, 'index_bg.wasm'));
  }
  return paths;
}

function missingProductionWorkerArtifactPaths() {
  const missing = [];
  for (const path of productionWorkerArtifactPaths()) {
    if (!existsSync(path)) {
      missing.push(path);
    }
  }
  return missing;
}

function commitmentPolicyBuildSha256() {
  const source = readFileSync(join(root, commitmentPolicyBuildEnvFile));
  return createHash('sha256').update(source).digest('hex');
}

async function stopExistingProductionWorkerProcesses() {
  const processGroups = findExistingProductionWorkerProcessGroups();
  if (processGroups.length === 0) {
    await assertProductionWorkerPortsAvailable();
    return;
  }

  console.log(
    `Stopping existing Router A/B local Worker topology (${processGroups.length} process groups)...`,
  );
  signalProductionWorkerProcessGroups(processGroups, 'SIGTERM');
  if (await waitForProductionWorkerPortsFree(2_000)) {
    return;
  }

  console.log('Existing Router A/B Workers did not stop cleanly; forcing shutdown...');
  signalProductionWorkerProcessGroups(processGroups, 'SIGKILL');
  await waitForProductionWorkerPortsFree(1_500);
  await assertProductionWorkerPortsAvailable();
}

function findExistingProductionWorkerProcessGroups() {
  if (process.platform === 'win32') {
    return [];
  }
  const child = spawnSync('ps', ['-ww', '-axo', 'pid=,pgid=,command='], {
    encoding: 'utf8',
  });
  if (child.status !== 0 || !child.stdout) {
    return [];
  }

  const specs = productionWorkerProcessSpecs();
  const groups = new Map();
  for (const line of child.stdout.split(/\r?\n/)) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.+)$/);
    if (!match) {
      continue;
    }
    const pid = Number(match[1]);
    const processGroupId = Number(match[2]);
    const command = match[3];
    if (
      !Number.isSafeInteger(pid) ||
      !Number.isSafeInteger(processGroupId) ||
      pid === process.pid
    ) {
      continue;
    }
    const spec = matchingProductionWorkerProcessSpec(command, specs);
    if (!spec) {
      continue;
    }
    const group = groups.get(processGroupId) ?? {
      processGroupId,
      role: spec.label ?? spec.role,
      memberPids: [],
      hasMatchedLeader: false,
    };
    group.memberPids.push(pid);
    group.hasMatchedLeader ||= pid === processGroupId;
    groups.set(processGroupId, group);
  }
  return [...groups.values()];
}

function productionWorkerProcessSpecs() {
  const strictConfigRoot = join(root, '.runtime', 'router-ab-strict');
  const specs = [];
  for (const endpoint of productionWorkerEndpoints) {
    specs.push({
      role: endpoint.role,
      label: endpoint.label,
      port: endpoint.port,
      configPath: join(strictConfigRoot, `wrangler.${endpoint.role}.toml`),
      persistPath: join(strictPersistPath, endpoint.role),
    });
  }
  return specs;
}

function matchingProductionWorkerProcessSpec(command, specs) {
  if (!command.includes('wrangler') || !command.includes(' dev ')) {
    return null;
  }
  for (const spec of specs) {
    if (
      command.includes(spec.configPath) &&
      command.includes(spec.persistPath) &&
      command.includes(`--port ${spec.port}`)
    ) {
      return spec;
    }
  }
  return null;
}

function signalProductionWorkerProcessGroups(processGroups, signal) {
  for (const group of processGroups) {
    if (group.hasMatchedLeader) {
      signalPid(-group.processGroupId, signal);
      continue;
    }
    for (const pid of group.memberPids) {
      signalPid(pid, signal);
    }
  }
}

function signalPid(pid, signal) {
  try {
    process.kill(pid, signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      throw error;
    }
  }
}

async function waitForProductionWorkerPortsFree(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await productionWorkerPortsAreFree()) {
      return true;
    }
    await sleep(100);
  }
  return productionWorkerPortsAreFree();
}

async function productionWorkerPortsAreFree() {
  for (const config of productionWorkerEndpoints) {
    if (await tcpIsListening('127.0.0.1', config.port)) {
      return false;
    }
  }
  return true;
}

function loadCommitmentPolicyBuildEnvironment() {
  const path = join(root, commitmentPolicyBuildEnvFile);
  if (!existsSync(path)) {
    throw new Error(`missing signed commitment policy build pins: ${path}`);
  }
  return { ...process.env, ...dotenv.parse(readFileSync(path)) };
}

function startProductionWorkers() {
  for (let index = 0; index < strictRuntime.configs.length; index += 1) {
    const config = strictRuntime.configs[index];
    const pane = workerPanes[index];
    pane.url = config.url;
    pane.status = 'starting';
    appendLine(pane, `config ${relative(repoRoot, config.configPath)}`);
    appendLine(pane, `url ${config.url}`);

    const child = spawn(
      'pnpm',
      [
        'exec',
        'wrangler',
        'dev',
        '--config',
        config.configPath,
        '--port',
        String(config.port),
        '--inspector-port',
        String(config.port + 100),
        '--persist-to',
        join(strictPersistPath, config.role),
        '--env-file',
        config.secretPath,
        '--local',
        '--show-interactive-dev-session=false',
      ],
      {
        cwd: repoRoot,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      },
    );
    pane.child = child;
    pane.pid = child.pid ?? null;
    pane.killAsGroup = process.platform !== 'win32';
    pane.exitPromise = new Promise((resolve) => child.once('exit', resolve));
    child.stdout.on('data', (chunk) => appendChunk(pane, chunk));
    child.stderr.on('data', (chunk) => appendChunk(pane, chunk, 'stderr: '));
    child.once('spawn', () => {
      appendLine(pane, `pid ${child.pid}`);
      appendProcessStatus(pane, child.pid);
    });
    child.once('exit', (code, signal) => {
      pane.status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
      appendLine(pane, `worker stopped: ${pane.status}`);
      if (!shutdownStarted) shutdown(exitCodeForChildExit(code, signal));
    });
    child.once('error', (error) => {
      pane.status = 'spawn error';
      appendLine(pane, `spawn error: ${error.message}`);
      if (!shutdownStarted) shutdown(1);
    });
  }
}

async function waitForProductionWorkers() {
  for (let index = 0; index < strictRuntime.configs.length; index += 1) {
    const config = strictRuntime.configs[index];
    await waitForUrlResponse(config.url, 90_000);
    workerPanes[index].status = 'ready';
    appendLine(workerPanes[index], 'worker ready');
  }
  const keysetUrl = `${strictRuntime.mpcRouterUrl}/.well-known/router-ab/keyset`;
  await waitForUrlStatus(keysetUrl, 90_000);
  appendLine(workerPanes[0], 'production topology ready');
}

async function assertProductionWorkerPortsAvailable() {
  const conflicts = [];
  for (const config of productionWorkerEndpoints) {
    if (await tcpIsListening('127.0.0.1', config.port)) {
      conflicts.push(`${config.label ?? config.role} ${config.url}`);
    }
  }
  if (conflicts.length > 0) {
    throw new Error(
      `production-shaped MPC worker port conflict: ${conflicts.join(', ')}. Stop the processes using these ports and retry.`,
    );
  }
}

async function ensureGateway() {
  const pane = getGatewayPane();
  if (options.noGateway) {
    appendLine(pane, 'Gateway auto-start disabled');
    if (!(await gatewayIsReady())) {
      const status = await describeUrlStatus(`${gatewayBaseUrl}/healthz`);
      throw new Error(
        `${gatewayBaseUrl} is not a healthy external Gateway (${status}). Start it with pnpm gateway:server or omit --no-gateway.`,
      );
    }
    appendLine(pane, `external Gateway ready at ${gatewayBaseUrl}`);
    await ensureGatewayHttpsProxy();
    return;
  }
  if (await tcpIsListening(gatewayHost, gatewayPort)) {
    const healthStatus = await describeUrlStatus(`${gatewayBaseUrl}/healthz`);
    const wellKnownStatus = await describeUrlStatus(gatewayInternalWellKnownUrl);
    throw new Error(
      `${gatewayBaseUrl} is already listening (${healthStatus}, well-known ${wellKnownStatus}). ` +
        'Stop that process so pnpm router can supervise the Gateway, or run pnpm router -- --no-gateway to use an external Gateway explicitly.',
    );
  }

  appendLine(pane, 'Gateway not running; starting pnpm gateway:server...');
  const child = spawn('pnpm', ['run', 'gateway:server'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      SEAMS_D1_LOCAL_PERSIST_TO: d1LocalPersistPath,
      SEAMS_D1_LOCAL_WRANGLER_CONFIG: d1LocalWranglerConfigPath,
      ROUTER_AB_SIGNING_WORKER_URL: strictRuntime.workerUrls.signingWorker,
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET:
        process.env.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET || 'dev-router-ab-internal-service-auth',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });
  gateway.child = child;
  gateway.killAsGroup = process.platform !== 'win32';
  gateway.exitPromise = new Promise((resolve) => child.once('exit', resolve));

  child.stdout.on('data', (chunk) => appendChunk(pane, chunk));
  child.stderr.on('data', (chunk) => appendChunk(pane, chunk, 'stderr: '));
  child.once('spawn', () => {
    appendLine(pane, `Gateway pid ${child.pid}`);
    appendProcessStatus(pane, child.pid);
  });
  child.once('exit', (code, signal) => {
    const status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
    appendLine(pane, `Gateway stopped: ${status}`);
    scheduleRender();
    if (!shutdownStarted) {
      shutdown(exitCodeForChildExit(code, signal));
    }
  });
  child.once('error', (error) => {
    appendLine(pane, `Gateway spawn error: ${error.message}`);
    scheduleRender();
    if (!shutdownStarted) {
      shutdown(1);
    }
  });

  await waitForHealthz(gatewayBaseUrl, 90_000);
  appendLine(pane, `Gateway ready at ${gatewayBaseUrl}`);
  await ensureGatewayHttpsProxy();
}

async function ensureGatewayHttpsProxy() {
  const pane = getGatewayPane();
  if (await urlStatusIsReady(gatewayPublicWellKnownUrl)) {
    await waitForStableUrlStatus(gatewayPublicWellKnownUrl, 2_000, 15_000);
    appendLine(pane, `Gateway HTTPS proxy ready at ${gatewayPublicUrl}`);
    return;
  }

  if (await tcpIsListening(gatewayPublicHost, gatewayPublicPort)) {
    try {
      await waitForUrlStatus(gatewayPublicWellKnownUrl, 5_000);
      await waitForStableUrlStatus(gatewayPublicWellKnownUrl, 2_000, 15_000);
      appendLine(pane, `Gateway HTTPS proxy ready at ${gatewayPublicUrl}`);
      return;
    } catch {
      const status = await describeUrlStatus(gatewayPublicWellKnownUrl);
      throw new Error(
        `${gatewayPublicWellKnownUrl} is listening but not healthy (${status}). ` +
          `${gatewayBaseUrl}/healthz is healthy, so restart the local Caddy proxy with pnpm caddy or stop the process on ${gatewayPublicPort}.`,
      );
    }
  }

  appendLine(pane, 'Gateway HTTPS proxy not running; starting pnpm caddy...');
  const child = spawn('pnpm', ['run', 'caddy'], {
    cwd: repoRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });
  gatewayHttpsProxy.child = child;
  gatewayHttpsProxy.killAsGroup = process.platform !== 'win32';
  gatewayHttpsProxy.exitPromise = new Promise((resolve) => child.once('exit', resolve));

  child.stdout.on('data', (chunk) => appendChunk(pane, chunk, 'caddy: '));
  child.stderr.on('data', (chunk) => appendChunk(pane, chunk, 'caddy stderr: '));
  child.once('spawn', () => {
    appendLine(pane, `Gateway HTTPS proxy pid ${child.pid}`);
    appendProcessStatus(pane, child.pid);
  });
  child.once('exit', (code, signal) => {
    const status = signal ? `signal ${signal}` : `exit ${code ?? 'unknown'}`;
    appendLine(pane, `Gateway HTTPS proxy stopped: ${status}`);
    scheduleRender();
    handleRouterHttpsProxyExit(child, code, signal);
  });
  child.once('error', (error) => {
    appendLine(pane, `Gateway HTTPS proxy spawn error: ${error.message}`);
    scheduleRender();
    if (!shutdownStarted) {
      shutdown(1);
    }
  });

  await waitForUrlStatus(gatewayPublicWellKnownUrl, 90_000);
  await waitForStableUrlStatus(gatewayPublicWellKnownUrl, 2_000, 15_000);
  appendLine(pane, `Gateway HTTPS proxy ready at ${gatewayPublicUrl}`);
}

async function handleRouterHttpsProxyExit(child, code, signal) {
  if (shutdownStarted) {
    return;
  }
  try {
    await waitForStableUrlStatus(gatewayPublicWellKnownUrl, 750, 10_000);
    if (gatewayHttpsProxy.child === child) {
      gatewayHttpsProxy.child = null;
      gatewayHttpsProxy.exitPromise = null;
      gatewayHttpsProxy.killAsGroup = false;
    }
    appendLine(
      getGatewayPane(),
      `Gateway HTTPS proxy still healthy at ${gatewayPublicUrl}; continuing with external proxy`,
    );
    scheduleRender();
    return;
  } catch {}
  shutdown(exitCodeForChildExit(code, signal));
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

async function gatewayIsReady() {
  if (!(await healthzIsReady(gatewayBaseUrl))) {
    return false;
  }
  return urlStatusIsReady(gatewayInternalWellKnownUrl);
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
  throw new Error(`Gateway did not become healthy at ${baseUrl}/healthz`);
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

async function waitForUrlResponse(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await requestStatus(url, 750);
      return;
    } catch {
      await sleep(250);
    }
  }
  const status = await describeUrlStatus(url);
  throw new Error(`${url} did not accept HTTP requests (${status})`);
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
  if (isChildRunning(gatewayHttpsProxy.child)) {
    appendLine(getGatewayPane(), 'stopping Gateway HTTPS proxy...');
    killChild(gatewayHttpsProxy.child, 'SIGTERM', gatewayHttpsProxy.killAsGroup);
  }
  if (isChildRunning(gateway.child)) {
    appendLine(getGatewayPane(), 'stopping Gateway...');
    killChild(gateway.child, 'SIGTERM', gateway.killAsGroup);
  }
  for (const pane of workerPanes) {
    if (isChildRunning(pane.child)) {
      pane.status = 'stopping';
      appendLine(pane, 'stopping worker...');
      killChild(pane.child, 'SIGTERM', pane.killAsGroup);
    }
  }
  scheduleRender();

  await Promise.race([
    Promise.all(
      [
        gatewayHttpsProxy.exitPromise,
        gateway.exitPromise,
        ...workerPanes.map((pane) => pane.exitPromise),
      ].filter(Boolean),
    ),
    sleep(1200),
  ]);

  if (isChildRunning(gatewayHttpsProxy.child)) {
    killChild(gatewayHttpsProxy.child, 'SIGKILL', gatewayHttpsProxy.killAsGroup);
  }
  if (isChildRunning(gateway.child)) {
    killChild(gateway.child, 'SIGKILL', gateway.killAsGroup);
  }
  for (const pane of workerPanes) {
    if (isChildRunning(pane.child)) {
      killChild(pane.child, 'SIGKILL', pane.killAsGroup);
    }
  }
  restoreTerminal();
  console.log('Stopped Router A/B local dev workers, Gateway, and HTTPS proxy.');
  process.exit(exitCode);
}

async function stopStartedChildren() {
  for (const pane of workerPanes) {
    if (isChildRunning(pane.child)) {
      killChild(pane.child, 'SIGTERM', pane.killAsGroup);
    }
  }
  if (isChildRunning(gateway.child)) {
    killChild(gateway.child, 'SIGTERM', gateway.killAsGroup);
  }
  if (isChildRunning(gatewayHttpsProxy.child)) {
    killChild(gatewayHttpsProxy.child, 'SIGTERM', gatewayHttpsProxy.killAsGroup);
  }
  await Promise.race([
    Promise.all(
      [
        gatewayHttpsProxy.exitPromise,
        gateway.exitPromise,
        ...workerPanes.map((pane) => pane.exitPromise),
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
  const columnCount = width >= 100 ? 2 : 1;
  const rowCount = Math.ceil(panes.length / columnCount);
  const columnBounds = gridBounds(width, columnCount);
  const rowBounds = gridBounds(height, rowCount);
  drawDashboardBorders(grid, columnBounds, rowBounds);
  const layouts = panes.map((_, index) =>
    dashboardPaneLayout(index, columnCount, columnBounds, rowBounds),
  );

  panes.forEach((pane, index) => drawPane(grid, layouts[index], pane));
  process.stdout.write(`\x1b[H${grid.map((row) => row.join('')).join('\n')}`);
}

function gridBounds(size, partitionCount) {
  return Array.from({ length: partitionCount + 1 }, (_, index) =>
    Math.floor((index * (size - 1)) / partitionCount),
  );
}

function dashboardPaneLayout(index, columnCount, columnBounds, rowBounds) {
  const column = index % columnCount;
  const row = Math.floor(index / columnCount);
  const left = columnBounds[column];
  const right = columnBounds[column + 1];
  const top = rowBounds[row];
  const bottom = rowBounds[row + 1];
  return {
    x: left + 1,
    y: top + 1,
    w: right - left - 1,
    h: bottom - top - 1,
    headerX: left + 2,
    headerY: top,
  };
}

function drawDashboardBorders(grid, columnBounds, rowBounds) {
  for (const row of rowBounds) {
    for (let column = 0; column < grid[row].length; column += 1) {
      grid[row][column] = '─';
    }
  }
  for (const column of columnBounds) {
    for (let row = 0; row < grid.length; row += 1) {
      grid[row][column] = '│';
    }
  }
  const lastColumnIndex = columnBounds.length - 1;
  const lastRowIndex = rowBounds.length - 1;
  for (let rowIndex = 0; rowIndex <= lastRowIndex; rowIndex += 1) {
    for (let columnIndex = 0; columnIndex <= lastColumnIndex; columnIndex += 1) {
      grid[rowBounds[rowIndex]][columnBounds[columnIndex]] = borderIntersection(
        rowIndex,
        columnIndex,
        lastRowIndex,
        lastColumnIndex,
      );
    }
  }
}

function borderIntersection(row, column, lastRow, lastColumn) {
  if (row === 0 && column === 0) return '┌';
  if (row === 0 && column === lastColumn) return '┐';
  if (row === lastRow && column === 0) return '└';
  if (row === lastRow && column === lastColumn) return '┘';
  if (row === 0) return '┬';
  if (row === lastRow) return '┴';
  if (column === 0) return '├';
  if (column === lastColumn) return '┤';
  return '┼';
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
  const label = (pane.logLabel ?? pane.role).padEnd(labelWidth, ' ');
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

function run(command, args, env = process.env, cwd = repoRoot) {
  const child = spawnSync(command, args, {
    cwd,
    stdio: 'inherit',
    env,
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
    noInit: false,
    noGateway: false,
    buildOnly: false,
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
      case '--no-init':
        parsed.noInit = true;
        break;
      case '--no-gateway':
        parsed.noGateway = true;
        break;
      case '--build-only':
        parsed.buildOnly = true;
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

function getGatewayPane() {
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
  return `usage: pnpm router [-- --root <path>] [--fresh] [--no-init] [--no-gateway]
       pnpm router:multiplex [-- --root <path>] [--fresh] [--no-init] [--no-gateway]
       pnpm router:build [-- --root <path>] [--fresh] [--no-init]

Runs Gateway, MPCRouter, Deriver A, Deriver B, and SigningWorker in one terminal.
Also starts the Gateway on 127.0.0.1:9090 when it is not already running.
Also verifies https://localhost:9444/.well-known/webauthn and starts Caddy when that local HTTPS proxy is absent.

Options:
  --root <path>      Local root containing generated env files. Defaults to repo root.
  --mode <mode>      Display mode: logs or multiplex. Defaults to logs.
  --fresh           Regenerate env files before launch.
  --no-init         Require env files to already exist.
  --no-gateway
                    Use an already-running external Gateway on 127.0.0.1:9090.
  --build-only      Build strict Worker artifacts and exit without starting services.

Press Ctrl-C to stop all workers, stop started Gateway/proxy processes, and restore the terminal.`;
}
