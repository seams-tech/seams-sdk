import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import {
  D1_STAGING_GENERATED_AT_ISO,
  loadD1StagingScriptModule,
  writeD1StagingTempFile,
  writeMisScopedConsoleD1StagingConfigFiles,
  writeValidD1StagingConfigFiles,
} from './helpers/d1StagingScriptFixtures';

type RunbookModule = {
  readonly buildD1StagingRunbook: (input: {
    readonly consoleConfigPath: string;
    readonly routerApiConfigPath: string;
    readonly outputPath?: string;
    readonly generatedAtIso?: string;
    readonly operator?: string;
    readonly r2Bucket?: string;
    readonly consoleOrigin?: string;
    readonly routerApiOrigin?: string;
  }) => string;
  readonly writeD1StagingRunbook: (input: {
    readonly consoleConfigPath: string;
    readonly routerApiConfigPath: string;
    readonly outputPath: string;
    readonly generatedAtIso?: string;
    readonly operator?: string;
    readonly r2Bucket?: string;
    readonly consoleOrigin?: string;
    readonly routerApiOrigin?: string;
  }) => {
    readonly outputPath: string;
    readonly markdown: string;
  };
};

const runbookModule = loadD1StagingScriptModule<RunbookModule>('d1-staging-runbook.mjs');
const runbookConfigPaths = writeValidD1StagingConfigFiles('seams-d1-staging-runbook-');
const runbookOptions = {
  ...runbookConfigPaths,
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
  operator: 'staging-operator',
  r2Bucket: 'seams-staging-backups',
  consoleOrigin: 'https://console.staging.example',
  routerApiOrigin: 'https://router-api.staging.example',
};
const finalEvidenceManifestFlags = [
  '--resources "$RESOURCE_INVENTORY_MANIFEST"',
  '--kek-check "$KEK_CHECK_MANIFEST"',
  '--migrations "$MIGRATIONS_MANIFEST"',
  '--bookmark-before-fixture-import "$BOOKMARK_BEFORE_FIXTURE_IMPORT_MANIFEST"',
  '--fixture-import "$FIXTURE_IMPORT_MANIFEST"',
  '--bookmark-before-route-switch "$BOOKMARK_BEFORE_ROUTE_SWITCH_MANIFEST"',
  '--smoke "$SMOKE_MANIFEST"',
  '--reconciliation "$RECONCILIATION_MANIFEST"',
  '--signer-custody "$SIGNER_CUSTODY_MANIFEST"',
  '--r2-restore-drill "$R2_RESTORE_DRILL_MANIFEST"',
] as const;

test('D1 staging runbook renders exact Phase 6 command sequence from readiness-clean configs', async () => {
  const module = await runbookModule;

  const markdown = module.buildD1StagingRunbook({
    ...runbookOptions,
  });

  expect(markdown).toContain('Generated: 2026-06-28T00:00:00.000Z');
  expect(markdown).toContain('Operator: staging-operator');
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:resources');
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:kek-check');
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:migrate');
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:bookmark');
  expect(markdown).toContain('--purpose before_fixture_import');
  expect(markdown).toContain('--purpose before_route_switch');
  expect(markdown).toContain(
    'pnpm --dir packages/console-server-ts run d1:staging:r2-restore-drill',
  );
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:smoke');
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:reconcile');
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:signer-custody');
  expect(markdown).toContain('pnpm --dir packages/console-server-ts run d1:staging:evidence');
  for (const flag of finalEvidenceManifestFlags) expect(markdown).toContain(flag);
  expect(markdown).toContain('--origin https://console.staging.example');
  expect(markdown).toContain('--wallet-session-jwt-env SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT');
  expect(markdown).toContain('SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT');
  expect(markdown).toContain('--missing-kek-fixture "$ECDSA_MISSING_KEK_EXPORT_SHARE_FIXTURE"');
  expect(markdown).toContain('--missing-kek-expected-status 503');
  expect(markdown).toContain('ecdsa_export_share_missing_kek_fail_closed');
  expect(markdown).toContain('--console-origin https://console.staging.example');
  expect(markdown).toContain('Router API `/router-ab/ed25519/healthz` configured');
  expect(markdown).toContain('Router API `/router-ab/ecdsa-hss/healthz` configured');
  expect(markdown).toContain('Fixture-backed signer custody, KEK isolation, and missing-KEK fail-closed');
  expect(markdown.indexOf('## Preflight')).toBeLessThan(
    markdown.indexOf('## Resource Inventory Capture'),
  );
  expect(markdown.indexOf('## Resource Inventory Capture')).toBeLessThan(
    markdown.indexOf('## Remote D1 Migrations'),
  );
});

test('D1 staging runbook writes the deployment log after readiness checks pass', async () => {
  const outputPath = writeD1StagingTempFile('seams-d1-staging-log-', 'runbook.md', '');
  const module = await runbookModule;

  const result = module.writeD1StagingRunbook({
    ...runbookOptions,
    outputPath,
  });

  expect(result.outputPath).toBe(outputPath);
  expect(fs.readFileSync(outputPath, 'utf8')).toBe(result.markdown);
  expect(result.markdown).toContain('## Resource Inventory');
});

test('D1 staging runbook rejects configs that fail the staging readiness gate', async () => {
  const module = await runbookModule;

  expect(() =>
    module.buildD1StagingRunbook({
      ...runbookOptions,
      ...writeMisScopedConsoleD1StagingConfigFiles('seams-d1-staging-runbook-'),
    }),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});

test('D1 staging runbook requires concrete HTTPS origins', async () => {
  const module = await runbookModule;

  expect(() =>
    module.buildD1StagingRunbook({
      ...runbookOptions,
      routerApiOrigin: 'http://router-api.staging.example',
    }),
  ).toThrow(/--router-api-origin must use https/);
});

test('D1 staging runbook rejects placeholder endpoint commands', async () => {
  const module = await runbookModule;

  expect(() =>
    module.buildD1StagingRunbook({
      ...runbookConfigPaths,
      generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
      operator: 'staging-operator',
      r2Bucket: 'seams-staging-backups',
    }),
  ).toThrow(/--console-origin is required/);
});

test('D1 staging runbook rejects R2 object paths as bucket names', async () => {
  const module = await runbookModule;

  expect(() =>
    module.buildD1StagingRunbook({
      ...runbookOptions,
      r2Bucket: 'seams-staging-backups/refactor-82',
    }),
  ).toThrow(/--r2-bucket must be a bucket name/);
});
