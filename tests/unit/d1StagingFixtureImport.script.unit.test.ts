import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(
  repoRoot,
  'packages/sdk-server-ts/scripts/d1-staging-fixture-import.mjs',
);

type FixtureImportPlan = {
  readonly mode: string;
  readonly commands: readonly string[];
  readonly fixtures: readonly {
    readonly logicalName: string;
    readonly sha256: string;
    readonly tablePrefix: string;
  }[];
};

type FixtureImportModule = {
  readonly buildD1StagingFixtureImportPlan: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly consoleFixturePath: string;
    readonly signerFixturePath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => FixtureImportPlan;
  readonly runD1StagingFixtureImport: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly consoleFixturePath: string;
    readonly signerFixturePath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run';
  }) => {
    readonly manifestPath: string;
    readonly manifest: FixtureImportPlan;
  };
};

async function loadFixtureImportModule(): Promise<FixtureImportModule> {
  return (await import(pathToFileURL(scriptPath).href)) as FixtureImportModule;
}

function writeTempFile(fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-staging-fixtures-'));
  const filePath = path.join(dir, fileName);
  fs.writeFileSync(filePath, source);
  return filePath;
}

function validConsoleStagingConfig(): string {
  return `
name = "seams-sdk-d1-console-staging"
main = "src/router/cloudflare/d1ConsoleStagingWorker.ts"
compatibility_date = "2026-04-17"
compatibility_flags = ["nodejs_compat"]

[[d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console-staging"
database_id = "11111111-1111-4111-8111-111111111111"
migrations_dir = "migrations/d1-console"

[vars]
SEAMS_TENANT_STORAGE_NAMESPACE = "seams-staging"
CONSOLE_SESSION_ISSUER = "seams-console-staging"
CONSOLE_SESSION_AUDIENCE = "seams-console-dashboard"

[secrets]
required = ["CONSOLE_SESSION_HMAC_SECRET"]
`;
}

function validRelayStagingConfig(): string {
  return `
name = "seams-sdk-d1-relay-staging"
main = "src/router/cloudflare/d1RouterApiStagingWorker.ts"
compatibility_date = "2026-04-17"
compatibility_flags = ["nodejs_compat"]

[[d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console-staging"
database_id = "11111111-1111-4111-8111-111111111111"
migrations_dir = "migrations/d1-console"

[[d1_databases]]
binding = "SIGNER_DB"
database_name = "seams-signer-staging"
database_id = "22222222-2222-4222-8222-222222222222"
migrations_dir = "migrations/d1-signer"

[[durable_objects.bindings]]
name = "THRESHOLD_STORE"
class_name = "ThresholdStoreDurableObject"

[[migrations]]
tag = "threshold-store-sqlite-v1"
new_sqlite_classes = ["ThresholdStoreDurableObject"]

[[secrets_store_secrets]]
binding = "SIGNING_ROOT_KEK_STAGING_R1"
store_id = "33333333333333333333333333333333"
secret_name = "signing-root-kek-staging-r1"

[vars]
SEAMS_TENANT_STORAGE_NAMESPACE = "seams-staging"
SEAMS_STAGING_ORG_ID = "org_staging"
SEAMS_STAGING_PROJECT_ID = "project_staging"
SEAMS_STAGING_ENV_ID = "staging"
ROUTER_AB_NORMAL_SIGNING_WORKER_ID = "seams-d1-relay-staging"
RELAYER_ACCOUNT_ID = "seams-relayer-staging.testnet"
RELAYER_PUBLIC_KEY = "ed25519:11111111111111111111111111111111"
RELAY_SESSION_ISSUER = "seams-relay-staging"
RELAY_SESSION_AUDIENCE = "seams-wallet-session"
SIGNING_ROOT_KEK_PROVIDER = "cloudflare_secrets_store"
SIGNING_ROOT_KEK_ENCODING = "base64url"
SIGNING_ROOT_KEK_IDS = "signing-root-kek-staging-r1"

[secrets]
required = ["RELAY_SESSION_HMAC_SECRET", "ACCOUNT_ID_DERIVATION_SECRET", "SPONSORED_EVM_EXECUTORS_JSON"]
`;
}

function validConsoleFixture(): string {
  return `
INSERT INTO console_organizations (org_id, display_name, created_at_ms, updated_at_ms)
VALUES ('org_staging', 'Create Staging Org', 1, 1);
`;
}

function validSignerFixture(): string {
  return `
INSERT INTO signer_wallets (tenant_storage_namespace, project_id, environment_id, wallet_id, created_at_ms, updated_at_ms)
VALUES ('seams-staging', 'project_staging', 'staging', 'wallet_staging', 1, 1);
`;
}

function buildValidInputs(): {
  readonly consoleConfigPath: string;
  readonly relayConfigPath: string;
  readonly consoleFixturePath: string;
  readonly signerFixturePath: string;
} {
  return {
    consoleConfigPath: writeTempFile('wrangler.d1-staging-console.toml', validConsoleStagingConfig()),
    relayConfigPath: writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig()),
    consoleFixturePath: writeTempFile('console.sql', validConsoleFixture()),
    signerFixturePath: writeTempFile('signer.sql', validSignerFixture()),
  };
}

test('D1 staging fixture import builds a dry-run plan from readiness-clean configs', async () => {
  const module = await loadFixtureImportModule();
  const plan = module.buildD1StagingFixtureImportPlan({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    mode: 'dry-run',
  });

  expect(plan.mode).toBe('dry-run');
  expect(plan.commands).toHaveLength(2);
  expect(plan.commands[0]).toContain('d1 execute seams-console-staging --remote --yes --file');
  expect(plan.commands[1]).toContain('d1 execute seams-signer-staging --remote --yes --file');
  expect(plan.fixtures).toEqual([
    expect.objectContaining({ logicalName: 'console', tablePrefix: 'console_' }),
    expect.objectContaining({ logicalName: 'signer', tablePrefix: 'signer_' }),
  ]);
});

test('D1 staging fixture import writes a dry-run manifest without touching Cloudflare', async () => {
  const module = await loadFixtureImportModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-fixture-import-${Date.now()}.json`);
  const result = module.runD1StagingFixtureImport({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'dry-run',
  });

  expect(result.manifestPath).toBe(manifestPath);
  expect(result.manifest.mode).toBe('dry-run');
  expect(fs.existsSync(manifestPath)).toBe(true);
  expect(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).commands).toHaveLength(2);
});

test('D1 staging fixture import rejects cross-domain fixture SQL', async () => {
  const module = await loadFixtureImportModule();
  const inputs = buildValidInputs();
  const badConsoleFixture = writeTempFile('console.sql', validSignerFixture());

  expect(() =>
    module.buildD1StagingFixtureImportPlan({
      ...inputs,
      consoleFixturePath: badConsoleFixture,
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'dry-run',
    }),
  ).toThrow(/console fixture touches signer_wallets/);
});

test('D1 staging fixture import rejects schema-changing fixture SQL', async () => {
  const module = await loadFixtureImportModule();
  const inputs = buildValidInputs();
  const badSignerFixture = writeTempFile('signer.sql', 'DROP TABLE signer_wallets;');

  expect(() =>
    module.buildD1StagingFixtureImportPlan({
      ...inputs,
      signerFixturePath: badSignerFixture,
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'dry-run',
    }),
  ).toThrow(/signer fixture contains schema DDL/);
});
