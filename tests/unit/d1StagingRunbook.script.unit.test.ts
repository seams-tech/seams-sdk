import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(repoRoot, 'packages/sdk-server-ts/scripts/d1-staging-runbook.mjs');

type RunbookModule = {
  readonly buildD1StagingRunbook: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly outputPath?: string;
    readonly generatedAtIso?: string;
    readonly operator?: string;
    readonly r2Bucket?: string;
    readonly consoleOrigin?: string;
    readonly relayOrigin?: string;
  }) => string;
  readonly writeD1StagingRunbook: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly outputPath: string;
    readonly generatedAtIso?: string;
    readonly operator?: string;
  }) => {
    readonly outputPath: string;
    readonly markdown: string;
  };
};

async function loadRunbookModule(): Promise<RunbookModule> {
  return (await import(pathToFileURL(scriptPath).href)) as RunbookModule;
}

function writeTempFile(fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-staging-runbook-'));
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

test('D1 staging runbook renders exact Phase 6 command sequence from readiness-clean configs', async () => {
  const consoleConfigPath = writeTempFile('wrangler.d1-staging-console.toml', validConsoleStagingConfig());
  const relayConfigPath = writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig());
  const module = await loadRunbookModule();

  const markdown = module.buildD1StagingRunbook({
    consoleConfigPath,
    relayConfigPath,
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    operator: 'staging-operator',
    r2Bucket: 'seams-staging-backups',
    consoleOrigin: 'https://console.staging.example',
    relayOrigin: 'https://relay.staging.example',
  });

  expect(markdown).toContain('Generated: 2026-06-28T00:00:00.000Z');
  expect(markdown).toContain('Operator: staging-operator');
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:resources');
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:kek-check');
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:migrate');
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:bookmark');
  expect(markdown).toContain('--purpose before_fixture_import');
  expect(markdown).toContain('--purpose before_route_switch');
  expect(markdown).toContain(
    'pnpm --dir packages/sdk-server-ts run d1:staging:r2-restore-drill',
  );
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:smoke');
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:reconcile');
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:signer-custody');
  expect(markdown).toContain('pnpm --dir packages/sdk-server-ts run d1:staging:evidence');
  expect(markdown).toContain('--bookmark-before-fixture-import "$BOOKMARK_BEFORE_FIXTURE_IMPORT_MANIFEST"');
  expect(markdown).toContain('SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT');
  expect(markdown).toContain('--console-origin https://console.staging.example');
  expect(markdown).toContain('Relay `/router-ab/ed25519/healthz` configured');
  expect(markdown).toContain('Relay `/router-ab/ecdsa-hss/healthz` configured');
  expect(markdown).toContain('Fixture-backed signer custody and KEK isolation');
});

test('D1 staging runbook writes the deployment log after readiness checks pass', async () => {
  const consoleConfigPath = writeTempFile('wrangler.d1-staging-console.toml', validConsoleStagingConfig());
  const relayConfigPath = writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig());
  const outputPath = path.join(os.tmpdir(), `seams-d1-staging-log-${Date.now()}.md`);
  const module = await loadRunbookModule();

  const result = module.writeD1StagingRunbook({
    consoleConfigPath,
    relayConfigPath,
    outputPath,
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    operator: 'staging-operator',
  });

  expect(result.outputPath).toBe(outputPath);
  expect(fs.readFileSync(outputPath, 'utf8')).toBe(result.markdown);
  expect(result.markdown).toContain('## Resource Inventory');
});

test('D1 staging runbook rejects configs that fail the staging readiness gate', async () => {
  const consoleConfigPath = writeTempFile('wrangler.d1-staging-console.toml', validRelayStagingConfig());
  const relayConfigPath = writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig());
  const module = await loadRunbookModule();

  expect(() =>
    module.buildD1StagingRunbook({
      consoleConfigPath,
      relayConfigPath,
      generatedAtIso: '2026-06-28T00:00:00.000Z',
    }),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});
