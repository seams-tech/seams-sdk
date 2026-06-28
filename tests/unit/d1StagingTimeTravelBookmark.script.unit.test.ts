import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const packageRoot = path.join(repoRoot, 'packages/sdk-server-ts');
const scriptPath = path.join(
  repoRoot,
  'packages/sdk-server-ts/scripts/d1-staging-time-travel-bookmark.mjs',
);

type BookmarkPlan = {
  readonly mode: string;
  readonly purpose: string;
  readonly stamp: string;
  readonly commands: readonly string[];
  readonly artifacts: {
    readonly consoleBookmarkPath: string;
    readonly signerBookmarkPath: string;
  };
};

type BookmarkModule = {
  readonly buildD1StagingTimeTravelBookmarkPlan: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly purpose: string;
    readonly timestampIso?: string;
  }) => BookmarkPlan;
  readonly runD1StagingTimeTravelBookmark: (input: {
    readonly consoleConfigPath: string;
    readonly relayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly purpose: string;
    readonly timestampIso?: string;
    readonly commandRunner?: (command: string) => {
      readonly command: string;
      readonly status: number;
      readonly stdout: string;
      readonly stderr: string;
    };
  }) => {
    readonly manifestPath: string;
    readonly manifest: BookmarkPlan & {
      readonly executed: readonly unknown[];
      readonly bookmarkEvidence: readonly unknown[];
    };
  };
};

async function loadBookmarkModule(): Promise<BookmarkModule> {
  return (await import(pathToFileURL(scriptPath).href)) as BookmarkModule;
}

function writeTempFile(fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-bookmark-'));
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

function bookmarkCommandRunner(command: string): {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  const match = /> ([^ ]+\.json)$/.exec(command);
  if (match) {
    const filePath = unquoteShellToken(match[1] || '');
    const absolutePath = path.join(packageRoot, filePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, JSON.stringify({ bookmark: `bookmark-for-${path.basename(filePath)}` }));
  }
  return {
    command,
    status: 0,
    stdout: '',
    stderr: '',
  };
}

function unquoteShellToken(input: string): string {
  if (input.startsWith("'") && input.endsWith("'")) return input.slice(1, -1);
  return input;
}

test('D1 staging Time Travel bookmark builds console and signer bookmark commands', async () => {
  const module = await loadBookmarkModule();
  const plan = module.buildD1StagingTimeTravelBookmarkPlan({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    mode: 'dry-run',
    purpose: 'before_fixture_import',
    timestampIso: '2026-06-28T00:00:00.000Z',
  });

  expect(plan.stamp).toBe('20260628T000000Z');
  expect(plan.commands).toHaveLength(2);
  expect(plan.commands[0]).toContain('d1 time-travel info seams-console-staging');
  expect(plan.commands[0]).toContain('console-before_fixture_import.json');
  expect(plan.commands[1]).toContain('d1 time-travel info seams-signer-staging');
  expect(plan.artifacts.signerBookmarkPath).toContain('signer-before_fixture_import.json');
});

test('D1 staging Time Travel bookmark dry-run writes a manifest without executing commands', async () => {
  const module = await loadBookmarkModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-bookmark-${Date.now()}.json`);
  const result = module.runD1StagingTimeTravelBookmark({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'dry-run',
    purpose: 'before_fixture_import',
    timestampIso: '2026-06-28T00:00:00.000Z',
  });

  expect(result.manifest.executed).toEqual([]);
  expect(result.manifest.bookmarkEvidence).toEqual([]);
  expect(JSON.parse(fs.readFileSync(manifestPath, 'utf8')).commands).toHaveLength(2);
});

test('D1 staging Time Travel bookmark remote mode records bookmark JSON evidence', async () => {
  const module = await loadBookmarkModule();
  const manifestPath = path.join(os.tmpdir(), `seams-d1-bookmark-remote-${Date.now()}.json`);
  const result = module.runD1StagingTimeTravelBookmark({
    ...buildValidInputs(),
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    manifestPath,
    mode: 'remote',
    purpose: 'before_route_switch',
    timestampIso: '2026-06-28T00:00:00.000Z',
    commandRunner: bookmarkCommandRunner,
  });

  expect(result.manifest.executed).toHaveLength(2);
  expect(result.manifest.bookmarkEvidence).toHaveLength(2);
});

test('D1 staging Time Travel bookmark rejects unsafe purpose names', async () => {
  const module = await loadBookmarkModule();
  expect(() =>
    module.buildD1StagingTimeTravelBookmarkPlan({
      ...buildValidInputs(),
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'dry-run',
      purpose: '../bad',
      timestampIso: '2026-06-28T00:00:00.000Z',
    }),
  ).toThrow(/--purpose must be lower_snake_case/);
});
