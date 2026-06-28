import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(
  repoRoot,
  'packages/sdk-server-ts/scripts/d1-staging-resource-inventory.mjs',
);

type ResourceInventoryPlan = {
  readonly mode: string;
  readonly resources: {
    readonly consoleWorker: {
      readonly name: string;
      readonly d1Databases: readonly unknown[];
      readonly durableObjects: readonly unknown[];
    };
    readonly relayWorker: {
      readonly name: string;
      readonly d1Databases: readonly unknown[];
      readonly durableObjects: readonly unknown[];
      readonly secretsStoreSecrets: readonly unknown[];
    };
  };
  readonly commands: readonly {
    readonly id: string;
    readonly target: string;
    readonly command: string;
  }[];
};

type ResourceInventoryModule = {
  readonly buildD1StagingResourceInventoryPlan: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => ResourceInventoryPlan;
  readonly runD1StagingResourceInventory: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly commandRunner?: (command: string) => {
      readonly command: string;
      readonly status: number;
      readonly stdout: string;
      readonly stderr: string;
    };
  }) => {
    readonly manifestPath: string;
    readonly manifest: ResourceInventoryPlan & {
      readonly checks: readonly unknown[];
    };
  };
};

async function loadResourceInventoryModule(): Promise<ResourceInventoryModule> {
  return (await import(pathToFileURL(scriptPath).href)) as ResourceInventoryModule;
}

function writeTempFile(fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-staging-resources-'));
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

function buildValidInputs(): {
  readonly consoleConfigPath: string;
  readonly relayConfigPath: string;
} {
  return {
    consoleConfigPath: writeTempFile('wrangler.d1-staging-console.toml', validConsoleStagingConfig()),
    relayConfigPath: writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig()),
  };
}

function resourceCommandRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return {
    command,
    status: 0,
    stdout: JSON.stringify({ command, ok: true }),
    stderr: '',
  };
}

test('D1 staging resource inventory records config-derived resource IDs', async () => {
  const module = await loadResourceInventoryModule();
  const plan = module.buildD1StagingResourceInventoryPlan({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    mode: 'dry-run',
  });

  expect(plan.resources.consoleWorker.name).toBe('seams-sdk-d1-console-staging');
  expect(plan.resources.consoleWorker.d1Databases).toEqual([
    {
      binding: 'CONSOLE_DB',
      databaseName: 'seams-console-staging',
      databaseId: '11111111-1111-4111-8111-111111111111',
      migrationsDir: 'migrations/d1-console',
    },
  ]);
  expect(plan.resources.consoleWorker.durableObjects).toEqual([]);
  expect(plan.resources.relayWorker.d1Databases).toHaveLength(2);
  expect(plan.resources.relayWorker.durableObjects).toEqual([
    {
      name: 'THRESHOLD_STORE',
      className: 'ThresholdStoreDurableObject',
    },
  ]);
  expect(plan.resources.relayWorker.secretsStoreSecrets).toEqual([
    {
      binding: 'SIGNING_ROOT_KEK_STAGING_R1',
      storeId: '33333333333333333333333333333333',
      secretName: 'signing-root-kek-staging-r1',
    },
  ]);
});

test('D1 staging resource inventory dry-run writes a manifest without remote commands', async () => {
  const module = await loadResourceInventoryModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-resources-${Date.now()}.json`);
  const result = module.runD1StagingResourceInventory({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'dry-run',
  });

  expect(result.manifest.checks).toEqual([]);
  expect(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).commands).toHaveLength(4);
});

test('D1 staging resource inventory remote mode records D1 and Worker JSON metadata', async () => {
  const module = await loadResourceInventoryModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-resources-remote-${Date.now()}.json`);
  const result = module.runD1StagingResourceInventory({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'remote',
    commandRunner: resourceCommandRunner,
  });

  expect(result.manifest.checks).toHaveLength(4);
  expect(result.manifest.checks[0]).toMatchObject({
    id: 'console_d1_info',
    target: 'console_d1',
  });
});

test('D1 staging resource inventory rejects configs that fail the readiness gate', async () => {
  const module = await loadResourceInventoryModule();
  expect(() =>
    module.buildD1StagingResourceInventoryPlan({
      consoleConfigPath: writeTempFile('wrangler.d1-staging-console.toml', validRelayStagingConfig()),
      relayConfigPath: writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig()),
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'dry-run',
    }),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});
