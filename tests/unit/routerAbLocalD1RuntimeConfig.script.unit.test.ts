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
const DERIVER_A_PEER_SIGNING_KEY = Buffer.from(DERIVER_A_PEER_KEY_HEX, 'hex').toString('base64url');
const DERIVER_B_PEER_SIGNING_KEY = Buffer.from(DERIVER_B_PEER_KEY_HEX, 'hex').toString('base64url');
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
    DERIVER_A_PEER_SIGNING_KEY: DERIVER_A_PEER_SIGNING_KEY,
    DERIVER_A_PEER_VERIFYING_KEY: localPeerVerifyingKeyHex(DERIVER_A_PEER_SIGNING_KEY),
    DERIVER_B_PEER_VERIFYING_KEY: localPeerVerifyingKeyHex(DERIVER_B_PEER_SIGNING_KEY),
  });
  writeEnv(root, '.env.router-ab.deriver-b.local', {
    DERIVER_B_URL: router.DERIVER_B_URL,
    DERIVER_B_ROOT_SHARE_WIRE_SECRET: `mpc-prf-root-share-wire-v1:${'44'.repeat(32)}`,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY: deriverB.privateKeyHex,
    DERIVER_B_PEER_SIGNING_KEY: DERIVER_B_PEER_SIGNING_KEY,
    DERIVER_A_PEER_VERIFYING_KEY: localPeerVerifyingKeyHex(DERIVER_A_PEER_SIGNING_KEY),
    DERIVER_B_PEER_VERIFYING_KEY: localPeerVerifyingKeyHex(DERIVER_B_PEER_SIGNING_KEY),
  });
  writeEnv(root, '.env.router-ab.signing-worker.local', {
    SIGNING_WORKER_URL: router.SIGNING_WORKER_URL,
    SIGNING_WORKER_ID: router.SIGNING_WORKER_ID,
    SIGNING_WORKER_KEY_EPOCH: 'signing-worker-epoch-7',
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: signingWorker.publicKey,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY: signingWorker.privateKeyHex,
  });
  const outputConfigPath = path.join(root, '.runtime/wrangler/wrangler.d1-local.toml');
  mkdirSync(path.dirname(outputConfigPath), { recursive: true });
  return { root, outputConfigPath, deriverA, deriverB, signingWorker };
}

function prepareStrictRuntime(fixture: RuntimeFixture) {
  const d1Runtime = prepareRouterAbD1LocalRuntimeConfig({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
    outputConfigPath: fixture.outputConfigPath,
  });
  return prepareRouterAbStrictLocalRuntimeConfigs({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
    ceremonyJwksJson: d1Runtime.ceremonyJwksJson,
  });
}

test('local Gateway startup projects the generated HPKE keyset into D1 Wrangler', () => {
  const fixture = createRuntimeFixture();

  const runtime = prepareRouterAbD1LocalRuntimeConfig({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
    outputConfigPath: fixture.outputConfigPath,
  });

  const config = readFileSync(fixture.outputConfigPath, 'utf8');
  expect(runtime.signingSessionPersistenceMode).toBe('sealed_refresh_v1');
  expect(runtime.signingSessionSealCurrentKeyVersion).toBe(
    parseTomlStringAssignment(config, 'SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION'),
  );
  expect(runtime.signingSessionSealGroupId).toBe('rfc2409-group2');
  expect(runtime.signingSessionSealAcceptedWarmKeyVersions).toBe(
    parseTomlStringAssignment(config, 'SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS'),
  );
  expect(config).toContain('SIGNING_SESSION_SEAL_ROOT_SECRET_B64U =');
  expect(config).not.toContain('SIGNING_SESSION_SHAMIR_P_B64U');
  expect(config).not.toContain('SIGNING_SESSION_SEAL_E_S_B64U');
  expect(config).not.toContain('SIGNING_SESSION_SEAL_D_S_B64U');
  expect(config).toContain(
    `DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY = ${JSON.stringify(fixture.deriverB.publicKey)}`,
  );
  expect(config).toContain(
    `DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.deriverB.publicKey)}`,
  );
  expect(config).not.toContain(
    'x25519:2222222222222222222222222222222222222222222222222222222222222222',
  );
  expect(config).toContain('binding = "MPC_ROUTER"');
  expect(config).toContain('service = "router-ab-mpc-router"');
  expect(config).not.toContain('binding = "DERIVER_A"');
  expect(config).not.toContain('binding = "DERIVER_B"');
  expect(config).toContain('binding = "SIGNING_WORKER"');
  expect(config).toContain('service = "router-ab-signing-worker"');
  expect(config).not.toContain('DERIVER_A_URL =');
  expect(config).not.toContain('DERIVER_B_URL =');
  expect(config).not.toContain('SIGNING_WORKER_URL =');
  expect(config).not.toContain('ROUTER_AB_SIGNING_WORKER_URL =');
  expect(config).not.toContain('GATEWAY_PUBLIC_URL =');
  expect(config).not.toContain('ROUTER_AB_MPC_ROUTER_URL =');
  const localConsoleOrganizationId = parseTomlStringAssignment(
    config,
    'SEAMS_LOCAL_CONSOLE_ORG_ID',
  );
  expect(localConsoleOrganizationId).toMatch(/^org_[a-z0-9]{12}$/);
  expect(config).toContain(
    `DERIVER_A_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(DERIVER_A_PEER_SIGNING_KEY)}"`,
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
  });
  expect(
    parseTomlJsonAssignment(
      readFileSync(fixture.outputConfigPath, 'utf8'),
      'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
    ),
  ).toEqual(ceremonyPrivateJwk);
  expect(
    parseTomlStringAssignment(
      readFileSync(fixture.outputConfigPath, 'utf8'),
      'SEAMS_LOCAL_CONSOLE_ORG_ID',
    ),
  ).toBe(localConsoleOrganizationId);

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
  const runtime = prepareStrictRuntime(fixture);

  expect(runtime.mpcRouterUrl).toBe('http://127.0.0.1:4102');
  expect(runtime.workerUrls).toEqual({
    mpcRouter: 'http://127.0.0.1:4102',
    deriverA: 'http://127.0.0.1:4103',
    deriverB: 'http://127.0.0.1:4104',
    signingWorker: 'http://127.0.0.1:4105',
  });
  expect(runtime.configs.map(({ role, port }) => ({ role, port }))).toEqual([
    { role: 'router', port: 4102 },
    { role: 'deriver-a', port: 4103 },
    { role: 'deriver-b', port: 4104 },
    { role: 'signing-worker', port: 4105 },
  ]);

  const routerConfig = readFileSync(runtime.configs[0].configPath, 'utf8');
  const routerVars = tomlSection(routerConfig, 'vars');
  expect(routerConfig).toContain('ROUTER_JWT_ISSUER = "http://127.0.0.1:9190"');
  expect(routerVars).toContain('ROUTER_JWT_ISSUER = "http://127.0.0.1:9190"');
  expect(routerVars).toContain('ROUTER_JWT_AUDIENCE = "router-ab"');
  const routerJwks = parseTomlJsonAssignment(routerVars, 'ROUTER_JWT_JWKS_JSON');
  expect(routerJwks).toMatchObject({
    keys: [{ alg: 'EdDSA', crv: 'Ed25519', kid: 'local-router-ab-r1', kty: 'OKP', use: 'sig' }],
  });
  expect(routerVars).toContain(
    `DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.deriverA.publicKey)}`,
  );
  expect(routerVars).toContain(
    `DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.deriverB.publicKey)}`,
  );
  expect(routerVars).toContain(
    `DERIVER_A_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(DERIVER_A_PEER_SIGNING_KEY)}"`,
  );
  expect(routerVars).toContain(
    `DERIVER_B_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(DERIVER_B_PEER_SIGNING_KEY)}"`,
  );
  expect(routerVars).toContain(
    `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.signingWorker.publicKey)}`,
  );
  expect(routerConfig).toContain('binding = "DERIVER_A"');
  expect(routerConfig).toContain('service = "router-ab-deriver-a"');
  expect(routerConfig).not.toContain('[build]');
  const localConsoleOrganizationId = runtime.localConsoleOrganizationId;
  expect(localConsoleOrganizationId).toMatch(/^org_[a-z0-9]{12}$/);

  const deriverASecretFile = readFileSync(runtime.configs[1].secretPath, 'utf8');
  expect(deriverASecretFile).toContain(
    'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:',
  );
  expect(deriverASecretFile).not.toContain('DERIVER_B_ROOT_SHARE_WIRE_SECRET');
  expect(deriverASecretFile).not.toContain('SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY');
  expect(deriverASecretFile).not.toContain('dev-only-generated');
  expect(deriverASecretFile).toContain(
    'DERIVER_A_ROLE_PRIVATE_D1_KEK=hpke-x25519-role-private-d1-private-v1:',
  );
  const deriverAConfig = readFileSync(runtime.configs[1].configPath, 'utf8');
  const deriverAVars = tomlSection(deriverAConfig, 'vars');
  expect(deriverAConfig).toContain('DERIVER_ROLE_PRIVATE_D1_KEK_VERSION = "local-epoch-1"');
  expect(deriverAConfig).toContain('DERIVER_ROLE_PRIVATE_D1_ENVIRONMENT = "local"');
  expect(deriverAConfig).toMatch(/DERIVER_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY = "x25519:[0-9a-f]{64}"/u);
  expect(deriverAVars).toContain(
    `DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.deriverA.publicKey)}`,
  );
  expect(deriverAVars).toContain(
    `DERIVER_A_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(DERIVER_A_PEER_SIGNING_KEY)}"`,
  );
  expect(deriverAVars).toContain(
    `DERIVER_B_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(DERIVER_B_PEER_SIGNING_KEY)}"`,
  );
  const deriverBConfig = readFileSync(runtime.configs[2].configPath, 'utf8');
  const deriverBVars = tomlSection(deriverBConfig, 'vars');
  expect(deriverBVars).toContain(
    `DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.deriverB.publicKey)}`,
  );
  expect(deriverBVars).toContain(
    `DERIVER_A_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(DERIVER_A_PEER_SIGNING_KEY)}"`,
  );
  expect(deriverBVars).toContain(
    `DERIVER_B_PEER_VERIFYING_KEY_HEX = "${localPeerVerifyingKeyHex(DERIVER_B_PEER_SIGNING_KEY)}"`,
  );
  const signingWorkerSecretFile = readFileSync(runtime.configs[3].secretPath, 'utf8');
  expect(signingWorkerSecretFile).toContain(
    'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY=hpke-x25519-server-output-private-v1:',
  );
  expect(signingWorkerSecretFile).not.toContain('DERIVER_A_ROOT_SHARE_WIRE_SECRET');
  expect(signingWorkerSecretFile).toContain(
    'SIGNING_WORKER_PRIVATE_D1_KEK=hpke-x25519-server-output-private-v1:',
  );
  const signingWorkerConfig = readFileSync(runtime.configs[3].configPath, 'utf8');
  const signingWorkerVars = tomlSection(signingWorkerConfig, 'vars');
  expect(signingWorkerConfig).toContain('SIGNING_WORKER_PRIVATE_D1_KEK_VERSION = "local-epoch-1"');
  expect(signingWorkerConfig).toContain('SIGNING_WORKER_PRIVATE_D1_ENVIRONMENT = "local"');
  expect(signingWorkerConfig).toMatch(
    /SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY = "x25519:[0-9a-f]{64}"/u,
  );
  expect(signingWorkerVars).toContain(
    `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY = ${JSON.stringify(fixture.signingWorker.publicKey)}`,
  );
  for (const config of runtime.configs) {
    if (!config.privateD1) continue;
    const generated = readFileSync(config.configPath, 'utf8');
    const relativeMigrationsDirectory = `migrations_dir = "migrations/${config.privateD1.migrationsDirectory}"`;
    const absoluteMigrationsDirectory = `migrations_dir = ${JSON.stringify(
      path.join(
        repoRoot(),
        'crates',
        'router-ab-cloudflare',
        'migrations',
        config.privateD1.migrationsDirectory,
      ),
    )}`;
    expect(generated).not.toContain(relativeMigrationsDirectory);
    expect(generated).toContain(absoluteMigrationsDirectory);
    // Miniflare keys local D1 storage by database_id. The rendered id must be
    // the role's pinned local id — never a deploy-lane placeholder, whose
    // renames would orphan all local signing/derivation state on restart.
    expect(generated).toContain(
      `database_id = ${JSON.stringify(config.privateD1.localDatabaseId)}`,
    );
    expect(tomlSection(generated, '[d1_databases]')).not.toContain('__');
  }
  expect(runtime.configs.map((config) => config.privateD1?.localDatabaseId)).toEqual([
    undefined,
    '00000000-0000-0000-0000-0000000094a1',
    '00000000-0000-0000-0000-0000000094b1',
    '00000000-0000-0000-0000-0000000094c1',
  ]);
  expect(runtime.configs[3].privateD1).toEqual({
    databaseName: 'router-ab-signing-worker-private',
    migrationsDirectory: 'signing-worker',
    localDatabaseId: '00000000-0000-0000-0000-0000000094c1',
  });
  expect(signingWorkerConfig).toContain(
    `migrations_dir = ${JSON.stringify(
      path.join(repoRoot(), 'crates', 'router-ab-cloudflare', 'migrations', 'signing-worker'),
    )}`,
  );
  for (const config of runtime.configs) {
    expect(statSync(config.secretPath).mode & 0o777).toBe(0o600);
  }
});

test('strict local mode serves pair commands through production Wrangler shims', () => {
  const fixture = createRuntimeFixture();
  const runtime = prepareStrictRuntime(fixture);

  for (const config of runtime.configs) {
    const generated = readFileSync(config.configPath, 'utf8');
    expect(generated).toMatch(new RegExp(`build/${config.role}/worker/shim\\.mjs`));
  }

  const launcher = readFileSync(
    path.join(repoRoot(), 'crates/router-ab-dev/scripts/dev-local-workers.mjs'),
    'utf8',
  );
  expect(launcher).toContain("'wrangler'");
  expect(launcher).toContain("'--local'");
  expect(launcher).toContain("'--config'");

  const deriverEntrypoint = readFileSync(
    path.join(repoRoot(), 'crates/router-ab-cloudflare/src/strict_worker/deriver.rs'),
    'utf8',
  );
  for (const route of [
    'CLOUDFLARE_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH',
    'CLOUDFLARE_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH',
    'CLOUDFLARE_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH',
    'CLOUDFLARE_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH',
    'CLOUDFLARE_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH',
    'CLOUDFLARE_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH',
    'CLOUDFLARE_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH',
  ]) {
    expect(deriverEntrypoint).toContain(route);
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

function parseTomlStringAssignment(config: string, key: string): string {
  for (const line of config.split(/\r?\n/)) {
    if (!line.startsWith(`${key} = `)) continue;
    return JSON.parse(line.slice(line.indexOf('=') + 1).trim()) as string;
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
    }),
  ).toThrow('Deriver B input HPKE public/private keys do not match');
});
