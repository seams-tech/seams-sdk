import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const packageRoot = path.join(repoRoot, 'packages/sdk-server-ts');
const scriptPath = path.join(
  repoRoot,
  'packages/sdk-server-ts/scripts/d1-staging-r2-restore-drill.mjs',
);

type R2RestoreDrillPlan = {
  readonly mode: string;
  readonly stamp: string;
  readonly commands: readonly string[];
  readonly artifacts: {
    readonly consoleObjectPath: string;
    readonly signerObjectPath: string;
    readonly consoleRestoreDatabaseName: string;
    readonly signerRestoreDatabaseName: string;
  };
};

type R2RestoreDrillModule = {
  readonly buildD1StagingR2RestoreDrillPlan: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly r2Bucket: string;
  }) => R2RestoreDrillPlan;
  readonly runD1StagingR2RestoreDrill: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly r2Bucket: string;
    readonly commandRunner?: (command: string) => {
      readonly command: string;
      readonly status: number;
      readonly stdout: string;
      readonly stderr: string;
    };
  }) => {
    readonly manifestPath: string;
    readonly manifest: R2RestoreDrillPlan & {
      readonly executed: readonly unknown[];
      readonly artifactEvidence: readonly unknown[];
    };
  };
};

async function loadDrillModule(): Promise<R2RestoreDrillModule> {
  return (await import(pathToFileURL(scriptPath).href)) as R2RestoreDrillModule;
}

function writeTempFile(fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-r2-drill-'));
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

function createArtifactCommandRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  writeCommandFile(command, /--output ([^ ]+)/);
  writeCommandFile(command, /--file ([^ ]+)/);
  return {
    command,
    status: 0,
    stdout: 'ok',
    stderr: '',
  };
}

function writeCommandFile(command: string, pattern: RegExp): void {
  const match = pattern.exec(command);
  if (!match) return;
  const filePath = unquoteShellToken(match[1] || '');
  if (!filePath.endsWith('.sql')) return;
  const absolutePath = path.join(packageRoot, filePath);
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  fs.writeFileSync(absolutePath, `-- fixture for ${filePath}\n`);
}

function unquoteShellToken(input: string): string {
  if (input.startsWith("'") && input.endsWith("'")) return input.slice(1, -1);
  return input;
}

test('D1 staging R2 restore drill builds timestamped export, R2, restore, and integrity commands', async () => {
  const module = await loadDrillModule();
  const plan = module.buildD1StagingR2RestoreDrillPlan({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    mode: 'dry-run',
    r2Bucket: 'seams-staging-backups',
  });

  expect(plan.stamp).toBe('20260628T000000Z');
  expect(plan.commands).toHaveLength(12);
  expect(plan.commands[0]).toContain('d1 export seams-console-staging --remote');
  expect(plan.commands[2]).toContain(
    'wrangler r2 object put seams-staging-backups/refactor-82/20260628T000000Z/seams-console-staging.sql',
  );
  expect(plan.commands[8]).toContain('d1 execute seams-console-staging-restore-drill-20260628t000000z');
  expect(plan.commands[10]).toContain('PRAGMA integrity_check;');
  expect(plan.artifacts.consoleRestoreDatabaseName).toBe(
    'seams-console-staging-restore-drill-20260628t000000z',
  );
});

test('D1 staging R2 restore drill dry-run writes a manifest without executing commands', async () => {
  const module = await loadDrillModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-r2-drill-${Date.now()}.json`);
  const result = module.runD1StagingR2RestoreDrill({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'dry-run',
    r2Bucket: 'seams-staging-backups',
  });

  expect(result.manifest.executed).toEqual([]);
  expect(result.manifest.artifactEvidence).toEqual([]);
  expect(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).commands).toHaveLength(12);
});

test('D1 staging R2 restore drill remote mode records command and artifact evidence', async () => {
  const module = await loadDrillModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-r2-drill-remote-${Date.now()}.json`);
  const result = module.runD1StagingR2RestoreDrill({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'remote',
    r2Bucket: 'seams-staging-backups',
    commandRunner: createArtifactCommandRunner,
  });

  expect(result.manifest.executed).toHaveLength(12);
  expect(result.manifest.artifactEvidence).toHaveLength(4);
});

test('D1 staging R2 restore drill rejects object paths as bucket names', async () => {
  const module = await loadDrillModule();
  expect(() =>
    module.buildD1StagingR2RestoreDrillPlan({
      ...buildValidInputs(),
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'dry-run',
      r2Bucket: 'seams-staging-backups/refactor-82',
    }),
  ).toThrow(/--r2-bucket must be a bucket name/);
});
