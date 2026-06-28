import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(
  repoRoot,
  'packages/sdk-server-ts/scripts/d1-staging-readiness-check.mjs',
);

type ReadinessResult = {
  readonly ok: boolean;
  readonly errors: readonly string[];
};

type StagingProfile = 'console' | 'relay';

type ReadinessModule = {
  readonly checkD1StagingReadiness: (input: {
    readonly configPath: string;
    readonly environmentName?: string;
    readonly profile?: StagingProfile;
  }) => ReadinessResult;
};

async function loadReadinessModule(): Promise<ReadinessModule> {
  return (await import(pathToFileURL(scriptPath).href)) as ReadinessModule;
}

async function checkConfig(source: string, profile: StagingProfile): Promise<ReadinessResult> {
  const filePath = writeTempConfig(source);
  const module = await loadReadinessModule();
  return module.checkD1StagingReadiness({ configPath: filePath, profile });
}

function writeTempConfig(source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-staging-'));
  const filePath = path.join(dir, 'wrangler.d1-staging.toml');
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

function validEnvRelayStagingConfig(): string {
  return `
name = "seams-sdk"
main = "src/router/cloudflare/devWorker.ts"
compatibility_date = "2026-04-17"

[env.staging]
name = "seams-sdk-d1-relay-staging"
main = "src/router/cloudflare/d1RouterApiStagingWorker.ts"

[[env.staging.d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console-staging"
database_id = "11111111-1111-4111-8111-111111111111"
migrations_dir = "migrations/d1-console"

[[env.staging.d1_databases]]
binding = "SIGNER_DB"
database_name = "seams-signer-staging"
database_id = "22222222-2222-4222-8222-222222222222"
migrations_dir = "migrations/d1-signer"

[[env.staging.durable_objects.bindings]]
name = "THRESHOLD_STORE"
class_name = "ThresholdStoreDurableObject"

[[env.staging.migrations]]
tag = "threshold-store-sqlite-v1"
new_sqlite_classes = ["ThresholdStoreDurableObject"]

[[env.staging.secrets_store_secrets]]
binding = "SIGNING_ROOT_KEK_STAGING_R1"
store_id = "33333333333333333333333333333333"
secret_name = "signing-root-kek-staging-r1"

[env.staging.vars]
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

[env.staging.secrets]
required = ["RELAY_SESSION_HMAC_SECRET", "ACCOUNT_ID_DERIVATION_SECRET", "SPONSORED_EVM_EXECUTORS_JSON"]
`;
}

function expectErrorContaining(result: ReadinessResult, expected: string): void {
  for (const error of result.errors) {
    if (error.includes(expected)) return;
  }
  expect(result.errors.join('\n')).toContain(expected);
}

test('D1 staging readiness check accepts the console-only staging shape', async () => {
  const result = await checkConfig(validConsoleStagingConfig(), 'console');
  expect(result.errors).toEqual([]);
  expect(result.ok).toBe(true);
});

test('D1 staging readiness check accepts the relay D1/DO/Secrets Store shape', async () => {
  const result = await checkConfig(validRelayStagingConfig(), 'relay');
  expect(result.errors).toEqual([]);
  expect(result.ok).toBe(true);
});

test('D1 staging readiness check supports env.staging Wrangler sections', async () => {
  const result = await checkConfig(validEnvRelayStagingConfig(), 'relay');
  expect(result.errors).toEqual([]);
  expect(result.ok).toBe(true);
});

test('D1 staging readiness check rejects the checked-in console placeholder template', async () => {
  const module = await loadReadinessModule();
  const result = module.checkD1StagingReadiness({
    configPath: path.join(
      repoRoot,
      'packages/sdk-server-ts/wrangler.d1-staging-console.toml.example',
    ),
    profile: 'console',
  });

  expect(result.ok).toBe(false);
  expectErrorContaining(result, 'CONSOLE_DB.database_id still contains a placeholder');
});

test('D1 staging readiness check rejects the checked-in relay placeholder template', async () => {
  const module = await loadReadinessModule();
  const result = module.checkD1StagingReadiness({
    configPath: path.join(
      repoRoot,
      'packages/sdk-server-ts/wrangler.d1-staging-relay.toml.example',
    ),
    profile: 'relay',
  });

  expect(result.ok).toBe(false);
  expectErrorContaining(result, 'CONSOLE_DB.database_id still contains a placeholder');
  expectErrorContaining(result, 'SIGNER_DB.database_id still contains a placeholder');
  expectErrorContaining(result, 'RELAYER_PUBLIC_KEY still contains a placeholder');
  expectErrorContaining(result, 'missing Cloudflare Secrets Store binding');
});

test('D1 staging readiness check rejects signer bindings in console profile', async () => {
  const result = await checkConfig(validRelayStagingConfig(), 'console');
  expect(result.ok).toBe(false);
  expectErrorContaining(result, 'console staging config must not reference SIGNER_DB');
  expectErrorContaining(result, 'console staging config must not reference THRESHOLD_STORE');
  expectErrorContaining(result, 'console staging config must not reference SIGNING_ROOT_KEK_PROVIDER');
});

test('D1 staging readiness check rejects the local development Worker config', async () => {
  const module = await loadReadinessModule();
  const result = module.checkD1StagingReadiness({
    configPath: path.join(repoRoot, 'packages/sdk-server-ts/wrangler.d1-local.toml'),
    profile: 'relay',
  });

  expect(result.ok).toBe(false);
  expectErrorContaining(result, 'staging must not use the local D1 development Worker entrypoint');
  expectErrorContaining(result, 'SPONSORED_EVM_EXECUTORS_JSON must not be configured');
  expectErrorContaining(result, 'ACCOUNT_ID_DERIVATION_SECRET must not be configured');
  expectErrorContaining(result, 'RELAY_SESSION_HMAC_SECRET must be declared');
  expectErrorContaining(result, 'SIGNING_ROOT_KEK_PROVIDER must be cloudflare_secrets_store');
});
