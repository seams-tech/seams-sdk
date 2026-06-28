import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPath = path.join(
  repoRoot,
  'packages/sdk-server-ts/scripts/d1-staging-reconciliation.mjs',
);

type ReconciliationPlan = {
  readonly mode: string;
  readonly tenant: {
    readonly namespace: string;
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  };
  readonly checks: readonly {
    readonly id: string;
    readonly target: string;
    readonly databaseName: string;
    readonly command: string;
  }[];
};

type ReconciliationModule = {
  readonly buildD1StagingReconciliationPlan: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => ReconciliationPlan;
  readonly runD1StagingReconciliation: (input: {
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
    readonly manifest: ReconciliationPlan & {
      readonly executed: readonly {
        readonly id: string;
        readonly rowCount: number;
      }[];
    };
  };
};

async function loadReconciliationModule(): Promise<ReconciliationModule> {
  return (await import(pathToFileURL(scriptPath).href)) as ReconciliationModule;
}

function writeTempFile(fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-staging-reconcile-'));
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

function emptyResultRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return {
    command,
    status: 0,
    stdout: JSON.stringify([{ results: [] }]),
    stderr: '',
  };
}

function mismatchResultRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  const rows = command.includes('console_billing_accounts')
    ? [{ namespace: 'seams-staging', org_id: 'org_staging', credit_balance_minor: 100, ledger_balance_minor: 0 }]
    : [];
  return {
    command,
    status: 0,
    stdout: JSON.stringify([{ results: rows }]),
    stderr: '',
  };
}

test('D1 staging reconciliation builds read-only console and signer checks', async () => {
  const module = await loadReconciliationModule();
  const plan = module.buildD1StagingReconciliationPlan({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    mode: 'dry-run',
  });

  expect(plan.tenant).toEqual({
    namespace: 'seams-staging',
    orgId: 'org_staging',
    projectId: 'project_staging',
    envId: 'staging',
  });
  expect(plan.checks.map((check) => check.id)).toEqual([
    'billing_account_balance_mismatch',
    'prepaid_reservation_summary_mismatch',
    'sponsored_call_missing_billing_links',
    'sponsored_call_settlement_amount_mismatch',
    'signer_share_unknown_kek',
    'signer_share_invalid_rotation_state',
  ]);
  expect(plan.checks[0].command).toContain('d1 execute seams-console-staging --remote --json');
  expect(plan.checks[4].command).toContain('d1 execute seams-signer-staging --remote --json');
  expect(plan.checks[4].command).toContain('signing-root-kek-staging-r1');
});

test('D1 staging reconciliation dry-run writes a manifest without executing commands', async () => {
  const module = await loadReconciliationModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-reconcile-${Date.now()}.json`);
  const result = module.runD1StagingReconciliation({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'dry-run',
  });

  expect(result.manifest.executed).toEqual([]);
  expect(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).checks).toHaveLength(6);
});

test('D1 staging reconciliation remote mode records zero-row evidence', async () => {
  const module = await loadReconciliationModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-reconcile-remote-${Date.now()}.json`);
  const result = module.runD1StagingReconciliation({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'remote',
    commandRunner: emptyResultRunner,
  });

  expect(result.manifest.executed).toHaveLength(6);
  expect(result.manifest.executed.every((check) => check.rowCount === 0)).toBe(true);
});

test('D1 staging reconciliation fails when a check returns mismatch rows', async () => {
  const module = await loadReconciliationModule();
  expect(() =>
    module.runD1StagingReconciliation({
      ...buildValidInputs(),
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      manifestPath: path.join(os.tmpdir(), `seams-d1-reconcile-fail-${Date.now()}.json`),
      mode: 'remote',
      commandRunner: mismatchResultRunner,
    }),
  ).toThrow(/billing_account_balance_mismatch: 1 mismatch row/);
});

test('D1 staging reconciliation rejects configs that fail the readiness gate', async () => {
  const module = await loadReconciliationModule();
  expect(() =>
    module.buildD1StagingReconciliationPlan({
      consoleConfigPath: writeTempFile('wrangler.d1-staging-console.toml', validRelayStagingConfig()),
      relayConfigPath: writeTempFile('wrangler.d1-staging-relay.toml', validRelayStagingConfig()),
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'dry-run',
    }),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});
