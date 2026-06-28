import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(repoRoot, 'packages/sdk-server-ts/scripts/d1-staging-migrate.mjs');

type MigrationStep = {
  readonly target: string;
  readonly databaseName: string;
  readonly action: string;
  readonly command: string;
};

type MigrationPlan = {
  readonly mode: string;
  readonly commands: readonly MigrationStep[];
  readonly targets: readonly {
    readonly logicalName: string;
    readonly databaseName: string;
    readonly migrationsDir: string;
    readonly files: readonly {
      readonly file: string;
      readonly bytes: number;
      readonly sha256: string;
    }[];
  }[];
};

type MigrationModule = {
  readonly buildD1StagingMigrationPlan: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => MigrationPlan;
  readonly runD1StagingMigration: (input: {
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
    readonly manifest: MigrationPlan & {
      readonly executed: readonly unknown[];
    };
  };
};

async function loadMigrationModule(): Promise<MigrationModule> {
  return (await import(pathToFileURL(scriptPath).href)) as MigrationModule;
}

function writeTempFile(fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-staging-migrate-'));
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

function successfulCommandRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return {
    command,
    status: 0,
    stdout: 'ok',
    stderr: '',
  };
}

test('D1 staging migration plan records migration hashes and noninteractive apply commands', async () => {
  const module = await loadMigrationModule();
  const plan = module.buildD1StagingMigrationPlan({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    mode: 'dry-run',
  });

  expect(plan.targets).toHaveLength(2);
  expect(plan.targets[0].migrationsDir).toBe('migrations/d1-console');
  expect(plan.targets[0].files.length).toBeGreaterThan(0);
  expect(plan.targets[0].files[0].sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(plan.commands).toHaveLength(6);
  expect(plan.commands[0]).toMatchObject({
    target: 'console',
    action: 'list_before',
    databaseName: 'seams-console-staging',
  });
  expect(plan.commands[1].command).toContain('CI=true pnpm --dir packages/sdk-server-ts exec wrangler');
  expect(plan.commands[1].command).toContain('d1 migrations apply seams-console-staging --remote');
  expect(plan.commands[4].command).toContain('d1 migrations apply seams-signer-staging --remote');
});

test('D1 staging migration dry-run writes a manifest without executing commands', async () => {
  const module = await loadMigrationModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-migrate-${Date.now()}.json`);
  const result = module.runD1StagingMigration({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'dry-run',
  });

  expect(result.manifest.executed).toEqual([]);
  expect(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).commands).toHaveLength(6);
});

test('D1 staging migration remote mode records list and apply command evidence', async () => {
  const module = await loadMigrationModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-migrate-remote-${Date.now()}.json`);
  const result = module.runD1StagingMigration({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'remote',
    commandRunner: successfulCommandRunner,
  });

  expect(result.manifest.executed).toHaveLength(6);
  expect(result.manifest.executed[1]).toMatchObject({
    target: 'console',
    action: 'apply',
    status: 0,
  });
});

test('D1 staging migration rejects configs that fail the staging readiness gate', async () => {
  const module = await loadMigrationModule();
  expect(() =>
    module.buildD1StagingMigrationPlan({
      consoleConfigPath: writeTempFile('wrangler.d1-staging-console.toml', validRelayStagingConfig()),
      relayConfigPath: writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig()),
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'dry-run',
    }),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});
