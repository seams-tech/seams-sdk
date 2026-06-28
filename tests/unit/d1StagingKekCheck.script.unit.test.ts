import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(repoRoot, 'packages/sdk-server-ts/scripts/d1-staging-kek-check.mjs');

type KekCheckPlan = {
  readonly mode: string;
  readonly commands: readonly string[];
  readonly keks: readonly {
    readonly kekId: string;
    readonly binding: string;
    readonly secretName: string;
    readonly storeId: string;
  }[];
};

type KekCheckModule = {
  readonly buildD1StagingKekCheckPlan: (input: {
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => KekCheckPlan;
  readonly runD1StagingKekCheck: (input: {
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
    readonly manifest: KekCheckPlan & {
      readonly checks: readonly unknown[];
    };
  };
};

async function loadKekCheckModule(): Promise<KekCheckModule> {
  return (await import(pathToFileURL(scriptPath).href)) as KekCheckModule;
}

function writeTempConfig(source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-kek-check-'));
  const filePath = path.join(dir, 'wrangler.d1-staging-relay.toml');
  fs.writeFileSync(filePath, source);
  return filePath;
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

function listedSecretRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return {
    command,
    status: 0,
    stdout: JSON.stringify([{ name: 'signing-root-kek-staging-r1' }]),
    stderr: '',
  };
}

function missingSecretRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return {
    command,
    status: 0,
    stdout: JSON.stringify([{ name: 'other-secret' }]),
    stderr: '',
  };
}

test('D1 staging KEK check builds metadata-only Secrets Store commands', async () => {
  const module = await loadKekCheckModule();
  const plan = module.buildD1StagingKekCheckPlan({
    relayConfigPath: writeTempConfig(validRelayStagingConfig()),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    mode: 'dry-run',
  });

  expect(plan.keks).toEqual([
    {
      kekId: 'signing-root-kek-staging-r1',
      binding: 'SIGNING_ROOT_KEK_STAGING_R1',
      secretName: 'signing-root-kek-staging-r1',
      storeId: '33333333333333333333333333333333',
    },
  ]);
  expect(plan.commands).toEqual([
    'pnpm --dir packages/sdk-server-ts exec wrangler secrets-store secret list 33333333333333333333333333333333 --remote --per-page 100',
  ]);
});

test('D1 staging KEK check writes a dry-run manifest without listing remote secrets', async () => {
  const module = await loadKekCheckModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-kek-check-${Date.now()}.json`);
  const result = module.runD1StagingKekCheck({
    relayConfigPath: writeTempConfig(validRelayStagingConfig()),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'dry-run',
  });

  expect(result.manifest.checks).toEqual([]);
  expect(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).keks).toHaveLength(1);
});

test('D1 staging KEK check remote mode records metadata presence without secret values', async () => {
  const module = await loadKekCheckModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-kek-check-remote-${Date.now()}.json`);
  const result = module.runD1StagingKekCheck({
    relayConfigPath: writeTempConfig(validRelayStagingConfig()),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'remote',
    commandRunner: listedSecretRunner,
  });

  expect(result.manifest.checks).toEqual([
    {
      storeId: '33333333333333333333333333333333',
      command:
        'pnpm --dir packages/sdk-server-ts exec wrangler secrets-store secret list 33333333333333333333333333333333 --remote --per-page 100',
      status: 0,
      presentSecretNames: ['signing-root-kek-staging-r1'],
    },
  ]);
});

test('D1 staging KEK check fails when the hosted KEK secret metadata is absent', async () => {
  const module = await loadKekCheckModule();
  expect(() =>
    module.runD1StagingKekCheck({
      relayConfigPath: writeTempConfig(validRelayStagingConfig()),
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      manifestPath: path.join(os.tmpdir(), `seams-d1-kek-check-fail-${Date.now()}.json`),
      mode: 'remote',
      commandRunner: missingSecretRunner,
    }),
  ).toThrow(/does not list required KEK secret signing-root-kek-staging-r1/);
});
