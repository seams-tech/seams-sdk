import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  timingSafeEqual,
} from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { localPeerVerifyingKeyHex } from './router-ab-local-key-material.mjs';

const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const LOCAL_ROUTER_ID = 'local-router';
const LOCAL_SIGNER_SET_ID = 'signer-set-v1';
const LOCAL_SIGNER_KEY_EPOCH = 'epoch-1';
const LOCAL_CEREMONY_JWT_AUDIENCE = 'router-ab';
const LOCAL_CEREMONY_JWT_KEY_ID = 'local-router-ab-r1';

const ROUTER_RUNTIME_ASSIGNMENTS = Object.freeze([
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

  assertEqualEnv(routerEnv, 'SIGNING_WORKER_ID', signingWorkerEnv, 'SIGNING_WORKER_ID');
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
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'DERIVER_A_PEER_VERIFYING_KEY_HEX',
    localPeerVerifyingKeyHex(requiredEnv(deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'DERIVER_B_PEER_VERIFYING_KEY_HEX',
    localPeerVerifyingKeyHex(requiredEnv(deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'GATEWAY_PUBLIC_URL',
    requiredEnv(routerEnv, 'GATEWAY_PUBLIC_URL'),
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'ROUTER_AB_CEREMONY_JWT_ISSUER',
    requiredEnv(routerEnv, 'GATEWAY_PUBLIC_URL'),
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'ROUTER_AB_CEREMONY_JWT_AUDIENCE',
    LOCAL_CEREMONY_JWT_AUDIENCE,
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'ROUTER_AB_CEREMONY_JWT_KEY_ID',
    LOCAL_CEREMONY_JWT_KEY_ID,
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
    resolveLocalCeremonyPrivateJwkJson(outputConfigPath),
  );
  runtimeConfig = replaceTomlAssignment(
    runtimeConfig,
    'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON',
    createLocalEcdsaRegistrationTopologyJson({
      routerEnv,
      signingWorkerEnv,
    }),
  );

  mkdirSync(path.dirname(outputConfigPath), { recursive: true });
  writeFileSync(outputConfigPath, runtimeConfig, { mode: 0o600 });
  chmodSync(outputConfigPath, 0o600);
  return Object.freeze({ outputConfigPath });
}

function createLocalCeremonyPrivateJwkJson() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return JSON.stringify(privateKey.export({ format: 'jwk' }));
}

function resolveLocalCeremonyPrivateJwkJson(outputConfigPath) {
  if (!existsSync(outputConfigPath)) return createLocalCeremonyPrivateJwkJson();
  const source = readFileSync(outputConfigPath, 'utf8');
  let assignment;
  for (const line of source.split(/\r?\n/)) {
    if (line.startsWith('ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK = ')) {
      assignment = line;
      break;
    }
  }
  if (!assignment) {
    throw new Error('existing D1 local Wrangler config is missing ceremony JWT private JWK');
  }
  let jwkJson;
  let jwk;
  try {
    jwkJson = JSON.parse(assignment.slice(assignment.indexOf('=') + 1).trim());
    jwk = JSON.parse(jwkJson);
  } catch {
    throw new Error('existing D1 local ceremony JWT private JWK is invalid');
  }
  if (
    typeof jwk !== 'object' ||
    jwk === null ||
    Array.isArray(jwk) ||
    jwk.kty !== 'OKP' ||
    jwk.crv !== 'Ed25519' ||
    typeof jwk.x !== 'string' ||
    !jwk.x ||
    typeof jwk.d !== 'string' ||
    !jwk.d
  ) {
    throw new Error('existing D1 local ceremony JWT private JWK has an invalid shape');
  }
  return JSON.stringify(jwk);
}

function createLocalEcdsaRegistrationTopologyJson(input) {
  const signingWorkerKeyEpoch = requiredEnv(input.signingWorkerEnv, 'SIGNING_WORKER_KEY_EPOCH');
  return JSON.stringify({
    routerId: LOCAL_ROUTER_ID,
    signerSet: {
      signer_set_id: LOCAL_SIGNER_SET_ID,
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a',
        key_epoch: LOCAL_SIGNER_KEY_EPOCH,
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b',
        key_epoch: LOCAL_SIGNER_KEY_EPOCH,
      },
      selected_server: {
        server_id: requiredEnv(input.signingWorkerEnv, 'SIGNING_WORKER_ID'),
        key_epoch: signingWorkerKeyEpoch,
        recipient_encryption_key: requiredEnv(
          input.signingWorkerEnv,
          'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
        ),
      },
    },
    deriverRecipientKeys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: LOCAL_SIGNER_KEY_EPOCH,
        public_key: requiredEnv(input.routerEnv, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: LOCAL_SIGNER_KEY_EPOCH,
        public_key: requiredEnv(input.routerEnv, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
      },
    },
  });
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
