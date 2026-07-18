import { expect, test } from '@playwright/test';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { prepareRouterAbD1LocalRuntimeConfig } from '../../crates/router-ab-dev/scripts/d1-local-runtime-config.mjs';
import { localPeerVerifyingKeyHex } from '../../crates/router-ab-dev/scripts/router-ab-local-key-material.mjs';
import { prepareRouterAbStrictLocalRuntimeConfigs } from '../../crates/router-ab-dev/scripts/strict-local-runtime-config.mjs';

const DERIVER_A_PEER_KEY_HEX = '11'.repeat(32);
const DERIVER_B_PEER_KEY_HEX = '22'.repeat(32);
const ECDSA_COMMITMENT_REGISTRY = Object.freeze({
  policy: Object.freeze({ releaseEpoch: 7 }),
  records: Object.freeze({ signerA: 'fixture-a', signerB: 'fixture-b' }),
});
const PRODUCTION_WORKER_URLS = Object.freeze({
  mpcRouter: 'http://127.0.0.1:9100',
  deriverA: 'http://127.0.0.1:9101',
  deriverB: 'http://127.0.0.1:9102',
  signingWorker: 'http://127.0.0.1:9103',
});

type X25519Fixture = {
  readonly publicKey: string;
  readonly privateKeyHex: string;
};

type RuntimeFixture = {
  readonly root: string;
  readonly outputConfigPath: string;
  readonly deriverA: X25519Fixture;
  readonly deriverB: X25519Fixture;
  readonly signingWorker: X25519Fixture;
};

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
}

function x25519Fixture(): X25519Fixture {
  const pair = generateKeyPairSync('x25519');
  const publicDer = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }));
  const privateDer = Buffer.from(pair.privateKey.export({ format: 'der', type: 'pkcs8' }));
  return {
    publicKey: `x25519:${publicDer.subarray(publicDer.length - 32).toString('hex')}`,
    privateKeyHex: privateDer.subarray(privateDer.length - 32).toString('hex'),
  };
}

function writeEnv(root: string, name: string, entries: Readonly<Record<string, string>>): void {
  const body = Object.entries(entries)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  writeFileSync(path.join(root, name), `${body}\n`);
}

function createRuntimeFixture(): RuntimeFixture {
  const root = mkdtempSync(path.join(tmpdir(), 'seams-router-ab-d1-runtime-'));
  const deriverA = x25519Fixture();
  const deriverB = x25519Fixture();
  const signingWorker = x25519Fixture();
  const router = {
    DERIVER_A_URL: 'http://127.0.0.1:9191',
    DERIVER_B_URL: 'http://127.0.0.1:9192',
    SIGNING_WORKER_URL: 'http://127.0.0.1:9193',
    SIGNING_WORKER_ID: 'local-signing-worker',
    GATEWAY_PUBLIC_URL: 'http://127.0.0.1:9190',
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-test-service-auth',
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: deriverA.publicKey,
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: deriverB.publicKey,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: signingWorker.publicKey,
  };
  writeEnv(root, '.env.router-ab.router.local', router);
  writeEnv(root, '.env.router-ab.deriver-a.local', {
    DERIVER_A_URL: router.DERIVER_A_URL,
    DERIVER_A_ROOT_SHARE_WIRE_SECRET: `mpc-prf-root-share-wire-v1:${'33'.repeat(32)}`,
    DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY: deriverA.privateKeyHex,
    DERIVER_A_PEER_SIGNING_KEY: `dev-only-generated-a:${DERIVER_A_PEER_KEY_HEX}`,
    DERIVER_A_PEER_VERIFYING_KEY: `dev-only-generated-a:${DERIVER_A_PEER_KEY_HEX}`,
    DERIVER_B_PEER_VERIFYING_KEY: `dev-only-generated-b:${DERIVER_B_PEER_KEY_HEX}`,
  });
  writeEnv(root, '.env.router-ab.deriver-b.local', {
    DERIVER_B_URL: router.DERIVER_B_URL,
    DERIVER_B_ROOT_SHARE_WIRE_SECRET: `mpc-prf-root-share-wire-v1:${'44'.repeat(32)}`,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY: deriverB.privateKeyHex,
    DERIVER_B_PEER_SIGNING_KEY: `dev-only-generated-b:${DERIVER_B_PEER_KEY_HEX}`,
    DERIVER_A_PEER_VERIFYING_KEY: `dev-only-generated-a:${DERIVER_A_PEER_KEY_HEX}`,
    DERIVER_B_PEER_VERIFYING_KEY: `dev-only-generated-b:${DERIVER_B_PEER_KEY_HEX}`,
  });
  writeEnv(root, '.env.router-ab.signing-worker.local', {
    SIGNING_WORKER_URL: router.SIGNING_WORKER_URL,
    SIGNING_WORKER_ID: router.SIGNING_WORKER_ID,
    SIGNING_WORKER_KEY_EPOCH: 'signing-worker-epoch-7',
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: signingWorker.publicKey,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY: signingWorker.privateKeyHex,
    ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON: JSON.stringify(ECDSA_COMMITMENT_REGISTRY),
  });
  const outputConfigPath = path.join(root, '.runtime/wrangler/wrangler.d1-local.toml');
  mkdirSync(path.dirname(outputConfigPath), { recursive: true });
  return { root, outputConfigPath, deriverA, deriverB, signingWorker };
}

test('local Gateway startup projects the generated HPKE keyset into D1 Wrangler', () => {
  const fixture = createRuntimeFixture();

  prepareRouterAbD1LocalRuntimeConfig({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
    outputConfigPath: fixture.outputConfigPath,
    workerUrls: PRODUCTION_WORKER_URLS,
  });

  const config = readFileSync(fixture.outputConfigPath, 'utf8');
  expect(config).toContain(
    `DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY = ${JSON.stringify(fixture.deriverB.publicKey)}`,
  );
  expect(config).toContain(
    `DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.deriverB.publicKey)}`,
  );
  expect(config).not.toContain(
    'x25519:2222222222222222222222222222222222222222222222222222222222222222',
  );
  expect(config).toContain('DERIVER_A_URL = "http://127.0.0.1:9101"');
  expect(config).toContain('DERIVER_B_URL = "http://127.0.0.1:9102"');
  expect(config).toContain('SIGNING_WORKER_URL = "http://127.0.0.1:9103"');
  expect(config).toContain('ROUTER_AB_SIGNING_WORKER_URL = "http://127.0.0.1:9103"');
  expect(config).toContain('GATEWAY_PUBLIC_URL = "http://127.0.0.1:9190"');
  expect(config).toContain('ROUTER_AB_MPC_ROUTER_URL = "http://127.0.0.1:9100"');
  expect(config).toContain(
    `DERIVER_A_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(
      `dev-only-generated-a:${DERIVER_A_PEER_KEY_HEX}`,
    )}"`,
  );

  const ceremonyPrivateJwk = parseTomlJsonAssignment(config, 'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK');
  expect(ceremonyPrivateJwk).toMatchObject({
    kty: 'OKP',
    crv: 'Ed25519',
  });
  expect(Object.keys(ceremonyPrivateJwk).sort()).toEqual(['crv', 'd', 'kty', 'x']);
  prepareRouterAbD1LocalRuntimeConfig({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
    outputConfigPath: fixture.outputConfigPath,
    workerUrls: PRODUCTION_WORKER_URLS,
  });
  expect(
    parseTomlJsonAssignment(
      readFileSync(fixture.outputConfigPath, 'utf8'),
      'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
    ),
  ).toEqual(ceremonyPrivateJwk);

  const topology = parseTomlJsonAssignment(config, 'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON');
  expect(topology).toEqual({
    routerId: 'local-router',
    signerSet: {
      signer_set_id: 'signer-set-v1',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a',
        key_epoch: 'epoch-1',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b',
        key_epoch: 'epoch-1',
      },
      selected_server: {
        server_id: 'local-signing-worker',
        key_epoch: 'signing-worker-epoch-7',
        recipient_encryption_key: fixture.signingWorker.publicKey,
      },
    },
    deriverRecipientKeys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-1',
        public_key: fixture.deriverA.publicKey,
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-1',
        public_key: fixture.deriverB.publicKey,
      },
    },
  });
});

test('local Gateway startup renders the production-shaped MPC Worker topology', () => {
  const fixture = createRuntimeFixture();
  const runtime = prepareRouterAbStrictLocalRuntimeConfigs({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
  });

  expect(runtime.mpcRouterUrl).toBe('http://127.0.0.1:9100');
  expect(runtime.workerUrls).toEqual(PRODUCTION_WORKER_URLS);
  expect(runtime.configs.map(({ role, port }) => ({ role, port }))).toEqual([
    { role: 'router', port: 9100 },
    { role: 'deriver-a', port: 9101 },
    { role: 'deriver-b', port: 9102 },
    { role: 'signing-worker', port: 9103 },
  ]);

  const routerConfig = readFileSync(runtime.configs[0].configPath, 'utf8');
  const routerBaseVars = tomlSection(routerConfig, 'vars');
  expect(
    parseTomlJsonAssignment(routerBaseVars, 'ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON'),
  ).toEqual(ECDSA_COMMITMENT_REGISTRY);
  expect(routerConfig).toContain('ROUTER_JWT_ISSUER = "http://127.0.0.1:9190"');
  expect(routerConfig).toContain(
    'ROUTER_JWT_JWKS_URL = "http://127.0.0.1:9190/.well-known/router-ab-ceremony-jwks.json"',
  );
  expect(routerConfig).toContain('binding = "DERIVER_A"');
  expect(routerConfig).toContain('service = "router-ab-deriver-a"');
  expect(routerConfig).not.toContain('[build]');
  expect(
    parseTomlJsonAssignment(routerConfig, 'ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON'),
  ).toMatchObject({
    org_id: 'local-smoke-org',
    project_id: 'local-smoke-project',
    environment: 'local',
  });

  const deriverASecretFile = readFileSync(runtime.configs[1].secretPath, 'utf8');
  expect(deriverASecretFile).toContain(
    'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:',
  );
  expect(deriverASecretFile).not.toContain('DERIVER_B_ROOT_SHARE_WIRE_SECRET');
  expect(deriverASecretFile).not.toContain('SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY');
  expect(deriverASecretFile).not.toContain('dev-only-generated');
  const signingWorkerSecretFile = readFileSync(runtime.configs[3].secretPath, 'utf8');
  const signingWorkerConfig = readFileSync(runtime.configs[3].configPath, 'utf8');
  const signingWorkerBaseVars = tomlSection(signingWorkerConfig, 'vars');
  expect(
    parseTomlJsonAssignment(signingWorkerBaseVars, 'ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON'),
  ).toEqual(ECDSA_COMMITMENT_REGISTRY);
  expect(signingWorkerSecretFile).toContain(
    'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY=hpke-x25519-server-output-private-v1:',
  );
  expect(signingWorkerSecretFile).not.toContain('DERIVER_A_ROOT_SHARE_WIRE_SECRET');
  expect(signingWorkerSecretFile).not.toContain('ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON');
  for (const config of runtime.configs) {
    expect(statSync(config.secretPath).mode & 0o777).toBe(0o600);
  }
});

function parseTomlJsonAssignment(config: string, key: string): Record<string, unknown> {
  for (const line of config.split(/\r?\n/)) {
    if (!line.startsWith(`${key} = `)) continue;
    const tomlString = JSON.parse(line.slice(line.indexOf('=') + 1).trim());
    return JSON.parse(tomlString) as Record<string, unknown>;
  }
  throw new Error(`Missing ${key}`);
}

function tomlSection(config: string, section: string): string {
  const lines = config.split(/\r?\n/);
  const header = `[${section}]`;
  const start = lines.findIndex((line) => line.trim() === header);
  if (start === -1) throw new Error(`Missing ${header}`);
  const nextSectionOffset = lines.slice(start + 1).findIndex((line) => line.trim().startsWith('['));
  const end = nextSectionOffset === -1 ? lines.length : start + 1 + nextSectionOffset;
  return lines.slice(start + 1, end).join('\n');
}

test('local Gateway startup rejects a generated MPCRouter/Deriver HPKE mismatch', () => {
  const fixture = createRuntimeFixture();
  const replacement = x25519Fixture();
  writeEnv(fixture.root, '.env.router-ab.deriver-b.local', {
    DERIVER_B_URL: 'http://127.0.0.1:9192',
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY: replacement.privateKeyHex,
  });

  expect(() =>
    prepareRouterAbD1LocalRuntimeConfig({
      repoRoot: repoRoot(),
      localEnvRoot: fixture.root,
      outputConfigPath: fixture.outputConfigPath,
      workerUrls: PRODUCTION_WORKER_URLS,
    }),
  ).toThrow('Deriver B input HPKE public/private keys do not match');
});

test('strict local runtime rejects a malformed SigningWorker commitment registry', () => {
  const fixture = createRuntimeFixture();
  const signingWorkerEnvPath = path.join(fixture.root, '.env.router-ab.signing-worker.local');
  const malformed = readFileSync(signingWorkerEnvPath, 'utf8').replace(
    /^ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON=.*$/m,
    'ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON=not-json',
  );
  writeFileSync(signingWorkerEnvPath, malformed);

  expect(() =>
    prepareRouterAbStrictLocalRuntimeConfigs({
      repoRoot: repoRoot(),
      localEnvRoot: fixture.root,
    }),
  ).toThrow('strict local runtime env ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON must be valid JSON');
});

test('strict local runtime preserves commitment registry integer literals', () => {
  const fixture = createRuntimeFixture();
  const signingWorkerEnvPath = path.join(fixture.root, '.env.router-ab.signing-worker.local');
  const exactRegistryJson =
    '{"policy":{"manifest":{"valid_until_ms":18446744073709551615}},"records":{}}';
  const source = readFileSync(signingWorkerEnvPath, 'utf8').replace(
    /^ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON=.*$/m,
    `ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON=${exactRegistryJson}`,
  );
  writeFileSync(signingWorkerEnvPath, source);

  const runtime = prepareRouterAbStrictLocalRuntimeConfigs({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
  });

  for (const configIndex of [0, 3]) {
    const config = readFileSync(runtime.configs[configIndex].configPath, 'utf8');
    const vars = tomlSection(config, 'vars');
    expect(parseTomlStringAssignment(vars, 'ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON')).toBe(
      exactRegistryJson,
    );
  }
});

function parseTomlStringAssignment(config: string, key: string): string {
  for (const line of config.split(/\r?\n/)) {
    if (!line.startsWith(`${key} = `)) continue;
    return JSON.parse(line.slice(line.indexOf('=') + 1).trim()) as string;
  }
  throw new Error(`Missing ${key}`);
}
