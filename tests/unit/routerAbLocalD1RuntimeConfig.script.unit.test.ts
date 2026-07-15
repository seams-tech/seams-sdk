import { expect, test } from '@playwright/test';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { prepareRouterAbD1LocalRuntimeConfig } from '../../crates/router-ab-dev/scripts/d1-local-runtime-config.mjs';

type X25519Fixture = {
  readonly publicKey: string;
  readonly privateKeyHex: string;
};

type RuntimeFixture = {
  readonly root: string;
  readonly outputConfigPath: string;
  readonly deriverB: X25519Fixture;
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
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-test-service-auth',
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: deriverA.publicKey,
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: deriverB.publicKey,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: signingWorker.publicKey,
  };
  writeEnv(root, '.env.router-ab.router.local', router);
  writeEnv(root, '.env.router-ab.deriver-a.local', {
    DERIVER_A_URL: router.DERIVER_A_URL,
    DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY: deriverA.privateKeyHex,
  });
  writeEnv(root, '.env.router-ab.deriver-b.local', {
    DERIVER_B_URL: router.DERIVER_B_URL,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY: deriverB.privateKeyHex,
  });
  writeEnv(root, '.env.router-ab.signing-worker.local', {
    SIGNING_WORKER_URL: router.SIGNING_WORKER_URL,
    SIGNING_WORKER_ID: router.SIGNING_WORKER_ID,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: signingWorker.publicKey,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY: signingWorker.privateKeyHex,
  });
  const outputConfigPath = path.join(root, '.runtime/wrangler/wrangler.d1-local.toml');
  mkdirSync(path.dirname(outputConfigPath), { recursive: true });
  return { root, outputConfigPath, deriverB };
}

test('local Router startup projects the generated HPKE keyset into D1 Wrangler', () => {
  const fixture = createRuntimeFixture();

  prepareRouterAbD1LocalRuntimeConfig({
    repoRoot: repoRoot(),
    localEnvRoot: fixture.root,
    outputConfigPath: fixture.outputConfigPath,
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
  expect(config).toContain('DERIVER_A_URL = "http://127.0.0.1:9191"');
  expect(config).toContain('DERIVER_B_URL = "http://127.0.0.1:9192"');
  expect(config).toContain('SIGNING_WORKER_URL = "http://127.0.0.1:9193"');
});

test('local Router startup rejects a generated Router/Deriver HPKE mismatch', () => {
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
