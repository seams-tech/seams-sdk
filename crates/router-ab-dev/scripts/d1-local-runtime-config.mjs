import { createPrivateKey, createPublicKey, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

const ROUTER_RUNTIME_ASSIGNMENTS = Object.freeze([
  'DERIVER_A_URL',
  'DERIVER_B_URL',
  'SIGNING_WORKER_URL',
  'SIGNING_WORKER_ID',
  'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
  'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
  'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
  'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
]);

export function prepareRouterAbD1LocalRuntimeConfig(input) {
  const repoRoot = path.resolve(input.repoRoot);
  const localEnvRoot = path.resolve(input.localEnvRoot ?? repoRoot);
  const sourceConfigPath = path.resolve(
    input.sourceConfigPath ??
      path.join(repoRoot, 'packages/console-server-ts/wrangler.d1-local.toml'),
  );
  const outputConfigPath = path.resolve(
    input.outputConfigPath ??
      path.join(localEnvRoot, '.runtime/wrangler-d1-local/wrangler.d1-local.toml'),
  );
  const routerEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.router.local'));
  const deriverAEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.deriver-a.local'));
  const deriverBEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.deriver-b.local'));
  const signingWorkerEnv = readEnvMap(
    path.join(localEnvRoot, '.env.router-ab.signing-worker.local'),
  );

  assertRuntimeUrlsAgree(routerEnv, deriverAEnv, deriverBEnv, signingWorkerEnv);
  assertRuntimeHpkeKeysAgree(routerEnv, deriverAEnv, deriverBEnv, signingWorkerEnv);

  let runtimeConfig = applyRuntimePaths(
    readFileSync(sourceConfigPath, 'utf8'),
    repoRoot,
    outputConfigPath,
  );
  for (const key of ROUTER_RUNTIME_ASSIGNMENTS) {
    runtimeConfig = replaceTomlAssignment(runtimeConfig, key, requiredEnv(routerEnv, key));
  }
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
    requiredEnv(routerEnv, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
    requiredEnv(routerEnv, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
  );

  mkdirSync(path.dirname(outputConfigPath), { recursive: true });
  writeFileSync(outputConfigPath, runtimeConfig, { mode: 0o600 });
  return Object.freeze({ outputConfigPath });
}

function readEnvMap(filePath) {
  const env = new Map();
  const source = readFileSync(filePath, 'utf8');
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) throw new Error(`invalid env entry in ${filePath}`);
    const key = line.slice(0, separator);
    if (env.has(key)) throw new Error(`duplicate env key ${key} in ${filePath}`);
    env.set(key, line.slice(separator + 1));
  }
  return env;
}

function requiredEnv(env, key) {
  const value = env.get(key);
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`Router A/B local runtime env is missing ${key}`);
  }
  return value.trim();
}

function assertRuntimeUrlsAgree(router, deriverA, deriverB, signingWorker) {
  assertEqualEnv(router, 'DERIVER_A_URL', deriverA, 'DERIVER_A_URL');
  assertEqualEnv(router, 'DERIVER_B_URL', deriverB, 'DERIVER_B_URL');
  assertEqualEnv(router, 'SIGNING_WORKER_URL', signingWorker, 'SIGNING_WORKER_URL');
  assertEqualEnv(router, 'SIGNING_WORKER_ID', signingWorker, 'SIGNING_WORKER_ID');
}

function assertRuntimeHpkeKeysAgree(router, deriverA, deriverB, signingWorker) {
  assertX25519KeyPair(
    'Deriver A input',
    requiredEnv(router, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
    requiredEnv(deriverA, 'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY'),
  );
  assertX25519KeyPair(
    'Deriver B input',
    requiredEnv(router, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
    requiredEnv(deriverB, 'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY'),
  );
  const signingWorkerPublicKey = requiredEnv(
    signingWorker,
    'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
  );
  if (
    requiredEnv(router, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY') !== signingWorkerPublicKey
  ) {
    throw new Error('Router and SigningWorker output HPKE public keys do not match');
  }
  assertX25519KeyPair(
    'SigningWorker output',
    signingWorkerPublicKey,
    requiredEnv(signingWorker, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY'),
  );
}

function assertEqualEnv(left, leftKey, right, rightKey) {
  if (requiredEnv(left, leftKey) !== requiredEnv(right, rightKey)) {
    throw new Error(`Router A/B local runtime mismatch: ${leftKey} != ${rightKey}`);
  }
}

function assertX25519KeyPair(label, encodedPublicKey, privateKeyHex) {
  const expectedPublicKey = parseX25519PublicKey(encodedPublicKey, label);
  const privateKey = parseHex32(privateKeyHex, `${label} private key`);
  const privateKeyDer = Buffer.concat([X25519_PKCS8_PREFIX, privateKey]);
  const publicKeyDer = createPublicKey(
    createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' }),
  ).export({ format: 'der', type: 'spki' });
  if (
    publicKeyDer.length !== X25519_SPKI_PREFIX.length + 32 ||
    !publicKeyDer.subarray(0, X25519_SPKI_PREFIX.length).equals(X25519_SPKI_PREFIX)
  ) {
    throw new Error(`${label} X25519 public-key encoding is invalid`);
  }
  const derivedPublicKey = publicKeyDer.subarray(X25519_SPKI_PREFIX.length);
  if (!timingSafeEqual(expectedPublicKey, derivedPublicKey)) {
    throw new Error(`${label} HPKE public/private keys do not match`);
  }
}

function parseX25519PublicKey(value, label) {
  if (!value.startsWith('x25519:')) {
    throw new Error(`${label} public key must use x25519:<hex>`);
  }
  return parseHex32(value.slice('x25519:'.length), `${label} public key`);
}

function parseHex32(value, label) {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must contain exactly 32 hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function applyRuntimePaths(source, repoRoot, outputConfigPath) {
  const outputDirectory = path.dirname(outputConfigPath);
  const mainPath = relativeTomlPath(
    outputDirectory,
    path.join(repoRoot, 'packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts'),
  );
  const consoleMigrationsPath = relativeTomlPath(
    outputDirectory,
    path.join(repoRoot, 'packages/console-server-ts/migrations/d1-console'),
  );
  const signerMigrationsPath = relativeTomlPath(
    outputDirectory,
    path.join(repoRoot, 'packages/sdk-server-ts/migrations/d1-signer'),
  );
  return replaceExactLine(
    replaceExactLine(
      replaceExactLine(
        source,
        'main = "src/router/cloudflare/d1LocalDevWorker.ts"',
        `main = ${JSON.stringify(mainPath)}`,
      ),
      'migrations_dir = "migrations/d1-console"',
      `migrations_dir = ${JSON.stringify(consoleMigrationsPath)}`,
    ),
    'migrations_dir = "../sdk-server-ts/migrations/d1-signer"',
    `migrations_dir = ${JSON.stringify(signerMigrationsPath)}`,
  );
}

function relativeTomlPath(fromDirectory, targetPath) {
  return path.relative(fromDirectory, targetPath).split(path.sep).join('/');
}

function replaceExactLine(source, expected, replacement) {
  const matches = source.split(/\r?\n/).filter((line) => line === expected).length;
  if (matches !== 1) throw new Error(`expected one D1 local config line: ${expected}`);
  return source.replace(expected, replacement);
}

function replaceTomlAssignment(source, key, value) {
  const assignment = new RegExp(`^${escapeRegExp(key)}\\s*=.*$`, 'gm');
  const matches = source.match(assignment) ?? [];
  if (matches.length !== 1) throw new Error(`D1 local Wrangler config must define ${key} once`);
  return source.replace(assignment, `${key} = ${JSON.stringify(value)}`);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
