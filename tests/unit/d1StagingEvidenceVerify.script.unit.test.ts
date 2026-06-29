import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  loadD1StagingScriptModule,
  readD1StagingJsonFile,
} from './helpers/d1StagingScriptFixtures';

const missingKekSignerCustodyResultId = 'ecdsa_export_share_missing_kek_fail_closed';
const consoleRestoreDatabaseName = 'seams-console-staging-restore-drill-20260628t000000z';
const signerRestoreDatabaseName = 'seams-signer-staging-restore-drill-20260628t000000z';
const consoleIntegrityCommand = `integrity console ${consoleRestoreDatabaseName} PRAGMA integrity_check`;
const signerIntegrityCommand = `integrity signer ${signerRestoreDatabaseName} PRAGMA integrity_check`;
const signerIntegrityCommandWithConsoleDatabase =
  `integrity signer ${consoleRestoreDatabaseName} PRAGMA integrity_check`;

type EvidenceModule = {
  readonly verifyD1StagingEvidence: (input: Record<string, string>) => {
    readonly outputPath: string;
    readonly summary: {
      readonly ok: boolean;
      readonly evidence: readonly { readonly id: string; readonly path: string }[];
    };
  };
};

type PassingEvidenceFixture = {
  readonly module: EvidenceModule;
  readonly dir: string;
  readonly manifests: PassingEvidenceManifests;
};

type PassingEvidenceManifestKey =
  | 'resources'
  | 'kekCheck'
  | 'migrations'
  | 'bookmarkBeforeFixtureImport'
  | 'fixtureImport'
  | 'bookmarkBeforeRouteSwitch'
  | 'smoke'
  | 'reconciliation'
  | 'signerCustody'
  | 'r2RestoreDrill';

type PassingEvidenceManifests = Record<PassingEvidenceManifestKey, string>;

type EvidenceMutationCase = {
  readonly name: string;
  readonly mutate: (manifests: PassingEvidenceManifests) => void;
  readonly expectedError: RegExp;
};

const evidenceModule = loadD1StagingScriptModule<EvidenceModule>(
  'd1-staging-evidence-verify.mjs',
);

async function passingEvidenceFixture(): Promise<PassingEvidenceFixture> {
  const module = await evidenceModule;
  const dir = tempDir();
  return { module, dir, manifests: passingManifests(dir) };
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'seams-d1-staging-evidence-'));
}

function writeManifest(dir: string, name: string, manifest: Record<string, unknown>): string {
  const manifestPath = path.join(dir, `${name}.json`);
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifestPath;
}

function readManifest(manifestPath: string): Record<string, unknown> {
  return readD1StagingJsonFile(manifestPath);
}

function patchManifest(manifestPath: string, patch: Record<string, unknown>): void {
  fs.writeFileSync(
    manifestPath,
    `${JSON.stringify({ ...readManifest(manifestPath), ...patch }, null, 2)}\n`,
  );
}

function expectVerificationToThrow(
  module: EvidenceModule,
  dir: string,
  manifests: PassingEvidenceManifests,
  expectedError: RegExp,
): void {
  expect(() =>
    module.verifyD1StagingEvidence({
      ...manifests,
      outputPath: path.join(dir, 'verification.json'),
    }),
  ).toThrow(expectedError);
}

async function expectEvidenceMutationToThrow(testCase: EvidenceMutationCase): Promise<void> {
  const { module, dir, manifests } = await passingEvidenceFixture();
  testCase.mutate(manifests);
  expectVerificationToThrow(module, dir, manifests, testCase.expectedError);
}

function manifestRecords(
  manifest: Record<string, unknown>,
  fieldName: string,
): Record<string, unknown>[] {
  const value = manifest[fieldName];
  if (!Array.isArray(value)) return [];
  return value.filter(isRecord);
}

function patchManifestStringValue(
  manifestPath: string,
  fieldName: string,
  oldValue: string,
  newValue: string,
): void {
  const manifest = readManifest(manifestPath);
  const value = manifest[fieldName];
  if (!Array.isArray(value)) return;
  const nextValues: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') continue;
    if (item === oldValue) {
      nextValues.push(newValue);
    } else {
      nextValues.push(item);
    }
  }
  patchManifest(manifestPath, { [fieldName]: nextValues });
}

function replaceRecordForField(
  records: Record<string, unknown>[],
  fieldName: string,
  expectedValue: unknown,
  replacement: Record<string, unknown>,
): Record<string, unknown>[] {
  const nextRecords: Record<string, unknown>[] = [];
  for (const record of records) {
    if (record[fieldName] === expectedValue) {
      nextRecords.push({ ...record, ...replacement });
    } else {
      nextRecords.push(record);
    }
  }
  return nextRecords;
}

function patchManifestRecordByField(
  manifestPath: string,
  fieldName: string,
  matchFieldName: string,
  expectedValue: unknown,
  replacement: Record<string, unknown>,
): void {
  const manifest = readManifest(manifestPath);
  patchManifest(manifestPath, {
    [fieldName]: replaceRecordForField(
      manifestRecords(manifest, fieldName),
      matchFieldName,
      expectedValue,
      replacement,
    ),
  });
}

function patchManifestRecordById(
  manifestPath: string,
  fieldName: string,
  id: string,
  replacement: Record<string, unknown>,
): void {
  patchManifestRecordByField(manifestPath, fieldName, 'id', id, replacement);
}

function patchManifestRecordsById(
  manifestPath: string,
  fieldNames: readonly string[],
  id: string,
  replacement: Record<string, unknown>,
): void {
  const manifest = readManifest(manifestPath);
  const patch: Record<string, unknown> = {};
  for (const fieldName of fieldNames) {
    patch[fieldName] = replaceRecordForField(
      manifestRecords(manifest, fieldName),
      'id',
      id,
      replacement,
    );
  }
  patchManifest(manifestPath, patch);
}

function appendManifestRecords(
  manifestPath: string,
  additions: Record<string, Record<string, unknown>>,
): void {
  const manifest = readManifest(manifestPath);
  const patch: Record<string, unknown> = {};
  for (const [fieldName, record] of Object.entries(additions)) {
    patch[fieldName] = [...manifestRecords(manifest, fieldName), record];
  }
  patchManifest(manifestPath, patch);
}

function removeManifestRecordById(
  manifestPath: string,
  fieldName: string,
  id: string,
): void {
  const manifest = readManifest(manifestPath);
  patchManifest(manifestPath, {
    [fieldName]: removeManifestRecordForId(manifest, fieldName, id),
  });
}

function patchResourceWorker(
  manifestPath: string,
  workerName: string,
  replacement: Record<string, unknown>,
): void {
  const resources = readManifest(manifestPath);
  const resourceBody = resources.resources as Record<string, unknown>;
  const worker = resourceBody[workerName] as Record<string, unknown>;
  patchManifest(manifestPath, {
    resources: {
      ...resourceBody,
      [workerName]: {
        ...worker,
        ...replacement,
      },
    },
  });
}

function removeManifestRecordForId(
  manifest: Record<string, unknown>,
  fieldName: string,
  id: string,
): Record<string, unknown>[] {
  const records: Record<string, unknown>[] = [];
  for (const record of manifestRecords(manifest, fieldName)) {
    if (record.id !== id) records.push(record);
  }
  return records;
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}

function passingManifests(dir: string): PassingEvidenceManifests {
  const consoleConfigPath = 'packages/sdk-server-ts/wrangler.d1-staging-console.toml';
  const routerApiConfigPath = 'packages/sdk-server-ts/wrangler.d1-staging-router-api.toml';
  const environmentName = 'staging';
  const tenant = {
    namespace: 'tenant-route-staging',
    orgId: 'org_staging',
    projectId: 'project_staging',
    envId: 'env_staging',
  };
  return {
    resources: writeManifest(dir, 'resources', {
      version: 'seams_d1_staging_resource_inventory_v1',
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'remote',
      environmentName,
      consoleConfigPath,
      routerApiConfigPath,
      resources: {
        consoleWorker: {
          d1Databases: [
            { binding: 'CONSOLE_DB', databaseId: 'd1-console-id' },
          ],
          durableObjects: [],
          secretsStoreSecrets: [],
        },
        routerApiWorker: {
          d1Databases: [
            { binding: 'CONSOLE_DB', databaseId: 'd1-console-id' },
            { binding: 'SIGNER_DB', databaseId: 'd1-signer-id' },
          ],
          durableObjects: [
            { name: 'THRESHOLD_STORE', className: 'ThresholdStore' },
          ],
          secretsStoreSecrets: [
            {
              binding: 'SIGNING_ROOT_KEK_R1',
              storeId: 'secret-store',
              secretName: 'kek-r1',
            },
          ],
          stagingVars: {
            ...tenant,
            signingRootKekProvider: 'cloudflare-secrets-store',
            signingRootKekIds: ['kek-r1'],
          },
        },
      },
      commands: [
        { id: 'console_d1_info', command: 'resource console d1 info' },
        { id: 'signer_d1_info', command: 'resource signer d1 info' },
        { id: 'console_worker_deployment_status', command: 'resource console deployments status' },
        { id: 'router_api_worker_deployment_status', command: 'resource Router API deployments status' },
      ],
      checks: [
        {
          id: 'console_d1_info',
          status: 0,
          command: 'resource console d1 info',
          json: { uuid: 'd1-console-id' },
        },
        {
          id: 'signer_d1_info',
          status: 0,
          command: 'resource signer d1 info',
          json: { uuid: 'd1-signer-id' },
        },
        {
          id: 'console_worker_deployment_status',
          status: 0,
          command: 'resource console deployments status',
          json: { id: 'console-worker' },
        },
        {
          id: 'router_api_worker_deployment_status',
          status: 0,
          command: 'resource Router API deployments status',
          json: { id: 'router-api-worker' },
        },
      ],
    }),
    kekCheck: writeManifest(dir, 'kek-check', {
      version: 'seams_d1_staging_kek_check_v1',
      generatedAtIso: '2026-06-28T00:00:00.000Z',
      mode: 'remote',
      environmentName,
      routerApiConfigPath,
      keks: [{ kekId: 'kek-r1', storeId: 'secret-store', secretName: 'kek-r1' }],
      commands: ['secrets-store secret list secret-store'],
      checks: [
        {
          storeId: 'secret-store',
          command: 'secrets-store secret list secret-store',
          status: 0,
          presentSecretNames: ['kek-r1'],
        },
      ],
    }),
    migrations: writeManifest(dir, 'migrations', {
      version: 'seams_d1_staging_migration_v1',
      generatedAtIso: '2026-06-28T00:01:00.000Z',
      mode: 'remote',
      environmentName,
      consoleConfigPath,
      routerApiConfigPath,
      commands: [
        { target: 'console', action: 'list_before', command: 'migration console list before' },
        { target: 'console', action: 'apply', command: 'migration console apply' },
        { target: 'console', action: 'list_after', command: 'migration console list after' },
        { target: 'signer', action: 'list_before', command: 'migration signer list before' },
        { target: 'signer', action: 'apply', command: 'migration signer apply' },
        { target: 'signer', action: 'list_after', command: 'migration signer list after' },
      ],
      executed: [
        { target: 'console', action: 'list_before', status: 0, command: 'migration console list before' },
        { target: 'console', action: 'apply', status: 0, command: 'migration console apply' },
        { target: 'console', action: 'list_after', status: 0, command: 'migration console list after' },
        { target: 'signer', action: 'list_before', status: 0, command: 'migration signer list before' },
        { target: 'signer', action: 'apply', status: 0, command: 'migration signer apply' },
        { target: 'signer', action: 'list_after', status: 0, command: 'migration signer list after' },
      ],
    }),
    bookmarkBeforeFixtureImport: writeManifest(dir, 'bookmark-before-fixture-import', {
      version: 'seams_d1_staging_time_travel_bookmark_v1',
      generatedAtIso: '2026-06-28T00:02:00.000Z',
      mode: 'remote',
      purpose: 'before_fixture_import',
      timestampIso: '2026-06-28T00:02:00.000Z',
      consoleConfigPath,
      routerApiConfigPath,
      artifacts: {
        consoleBookmarkPath: 'bookmarks/console-before-fixture-import.json',
        signerBookmarkPath: 'bookmarks/signer-before-fixture-import.json',
      },
      commands: ['bookmark console', 'bookmark signer'],
      executed: [
        { command: 'bookmark console', status: 0 },
        { command: 'bookmark signer', status: 0 },
      ],
      bookmarkEvidence: [
        {
          logicalName: 'console',
          path: 'bookmarks/console-before-fixture-import.json',
          json: { bookmark: '00000085-0000024c-00004c6d-00000000' },
        },
        {
          logicalName: 'signer',
          path: 'bookmarks/signer-before-fixture-import.json',
          json: { bookmark: '00000086-0000024d-00004c6e-00000000' },
        },
      ],
    }),
    fixtureImport: writeManifest(dir, 'fixture-import', {
      version: 'seams_d1_staging_fixture_import_v1',
      generatedAtIso: '2026-06-28T00:03:00.000Z',
      mode: 'remote',
      environmentName,
      consoleConfigPath,
      routerApiConfigPath,
      fixtures: [{ logicalName: 'console' }, { logicalName: 'signer' }],
      commands: ['import console', 'import signer'],
      executed: [
        { command: 'import console', status: 0 },
        { command: 'import signer', status: 0 },
      ],
    }),
    bookmarkBeforeRouteSwitch: writeManifest(dir, 'bookmark-before-route-switch', {
      version: 'seams_d1_staging_time_travel_bookmark_v1',
      generatedAtIso: '2026-06-28T00:04:00.000Z',
      mode: 'remote',
      purpose: 'before_route_switch',
      timestampIso: '2026-06-28T00:04:00.000Z',
      consoleConfigPath,
      routerApiConfigPath,
      artifacts: {
        consoleBookmarkPath: 'bookmarks/console-before-route-switch.json',
        signerBookmarkPath: 'bookmarks/signer-before-route-switch.json',
      },
      commands: ['bookmark console', 'bookmark signer'],
      executed: [
        { command: 'bookmark console', status: 0 },
        { command: 'bookmark signer', status: 0 },
      ],
      bookmarkEvidence: [
        {
          logicalName: 'console',
          path: 'bookmarks/console-before-route-switch.json',
          json: { bookmark: '00000087-0000024e-00004c6f-00000000' },
        },
        {
          logicalName: 'signer',
          path: 'bookmarks/signer-before-route-switch.json',
          json: { bookmark: '00000088-0000024f-00004c70-00000000' },
        },
      ],
    }),
    smoke: writeManifest(dir, 'smoke', {
      version: 'seams_d1_staging_smoke_v1',
      generatedAtIso: '2026-06-28T00:05:00.000Z',
      mode: 'remote',
      endpoints: [
        {
          id: 'console_readyz',
          method: 'GET',
          url: 'https://console.staging.example/console/readyz',
          expectedStatus: 200,
        },
        {
          id: 'router_api_readyz',
          method: 'GET',
          url: 'https://router-api.staging.example/readyz',
          expectedStatus: 200,
        },
        {
          id: 'router_api_healthz',
          method: 'GET',
          url: 'https://router-api.staging.example/healthz',
          expectedStatus: 200,
        },
        {
          id: 'signer_custody_ed25519_healthz',
          method: 'GET',
          url: 'https://router-api.staging.example/router-ab/ed25519/healthz',
          expectedStatus: 200,
        },
        {
          id: 'signer_custody_ecdsa_hss_healthz',
          method: 'GET',
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/healthz',
          expectedStatus: 200,
        },
      ],
      checks: [
        { id: 'console_readyz', ok: true, status: 200, url: 'https://console.staging.example/console/readyz' },
        { id: 'router_api_readyz', ok: true, status: 200, url: 'https://router-api.staging.example/readyz' },
        { id: 'router_api_healthz', ok: true, status: 200, url: 'https://router-api.staging.example/healthz' },
        {
          id: 'signer_custody_ed25519_healthz',
          ok: true,
          status: 200,
          url: 'https://router-api.staging.example/router-ab/ed25519/healthz',
        },
        {
          id: 'signer_custody_ecdsa_hss_healthz',
          ok: true,
          status: 200,
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/healthz',
        },
      ],
    }),
    reconciliation: writeManifest(dir, 'reconciliation', {
      version: 'seams_d1_staging_reconciliation_v1',
      generatedAtIso: '2026-06-28T00:06:00.000Z',
      mode: 'remote',
      environmentName,
      consoleConfigPath,
      routerApiConfigPath,
      tenant,
      checks: [
        {
          id: 'billing_account_balance_mismatch',
          command: 'reconcile billing account balance',
        },
        {
          id: 'prepaid_reservation_summary_mismatch',
          command: 'reconcile prepaid reservation summary',
        },
        {
          id: 'sponsored_call_missing_billing_links',
          command: 'reconcile sponsored call billing links',
        },
        {
          id: 'sponsored_call_settlement_amount_mismatch',
          command: 'reconcile sponsored call settlement amount',
        },
        {
          id: 'signer_share_unknown_kek',
          command: 'reconcile signer share unknown kek',
        },
        {
          id: 'signer_share_invalid_rotation_state',
          command: 'reconcile signer share rotation state',
        },
      ],
      executed: [
        {
          id: 'billing_account_balance_mismatch',
          command: 'reconcile billing account balance',
          status: 0,
          rowCount: 0,
        },
        {
          id: 'prepaid_reservation_summary_mismatch',
          command: 'reconcile prepaid reservation summary',
          status: 0,
          rowCount: 0,
        },
        {
          id: 'sponsored_call_missing_billing_links',
          command: 'reconcile sponsored call billing links',
          status: 0,
          rowCount: 0,
        },
        {
          id: 'sponsored_call_settlement_amount_mismatch',
          command: 'reconcile sponsored call settlement amount',
          status: 0,
          rowCount: 0,
        },
        {
          id: 'signer_share_unknown_kek',
          command: 'reconcile signer share unknown kek',
          status: 0,
          rowCount: 0,
        },
        {
          id: 'signer_share_invalid_rotation_state',
          command: 'reconcile signer share rotation state',
          status: 0,
          rowCount: 0,
        },
      ],
    }),
    signerCustody: writeManifest(dir, 'signer-custody', {
      version: 'seams_d1_staging_signer_custody_v1',
      generatedAtIso: '2026-06-28T00:07:00.000Z',
      mode: 'remote',
      healthChecks: [
        {
          id: 'signer_custody_ed25519_healthz',
          method: 'GET',
          url: 'https://router-api.staging.example/router-ab/ed25519/healthz',
          expectedStatus: 200,
        },
        {
          id: 'signer_custody_ecdsa_hss_healthz',
          method: 'GET',
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/healthz',
          expectedStatus: 200,
        },
      ],
      checks: [
        {
          id: 'ecdsa_export_share_success',
          method: 'POST',
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/export/share',
          expectedStatus: 200,
        },
        {
          id: 'ecdsa_export_share_missing_kek_fail_closed',
          method: 'POST',
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/export/share',
          expectedStatus: 503,
        },
      ],
      results: [
        {
          id: 'signer_custody_ed25519_healthz',
          ok: true,
          status: 200,
          url: 'https://router-api.staging.example/router-ab/ed25519/healthz',
        },
        {
          id: 'signer_custody_ecdsa_hss_healthz',
          ok: true,
          status: 200,
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/healthz',
        },
        {
          id: 'ecdsa_export_share_success',
          ok: true,
          status: 200,
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/export/share',
        },
        {
          id: 'ecdsa_export_share_missing_kek_fail_closed',
          ok: true,
          status: 503,
          url: 'https://router-api.staging.example/router-ab/ecdsa-hss/export/share',
          body: { ok: false, code: 'missing_signing_root_kek' },
        },
      ],
    }),
    r2RestoreDrill: writeManifest(dir, 'r2-restore-drill', {
      version: 'seams_d1_staging_r2_restore_drill_v1',
      generatedAtIso: '2026-06-28T00:08:00.000Z',
      mode: 'remote',
      consoleConfigPath,
      routerApiConfigPath,
      artifacts: {
        consoleExportPath: 'console.sql',
        signerExportPath: 'signer.sql',
        consoleRestorePath: 'console-restore.sql',
        signerRestorePath: 'signer-restore.sql',
        consoleRestoreDatabaseName,
        signerRestoreDatabaseName,
      },
      commands: [
        'export console',
        'export signer',
        'r2 put console',
        'r2 put signer',
        'r2 get console',
        'r2 get signer',
        'create console restore database',
        'create signer restore database',
        'restore console',
        'restore signer',
        consoleIntegrityCommand,
        signerIntegrityCommand,
      ],
      executed: [
        { command: 'export console', status: 0 },
        { command: 'export signer', status: 0 },
        { command: 'r2 put console', status: 0 },
        { command: 'r2 put signer', status: 0 },
        { command: 'r2 get console', status: 0 },
        { command: 'r2 get signer', status: 0 },
        { command: 'create console restore database', status: 0 },
        { command: 'create signer restore database', status: 0 },
        { command: 'restore console', status: 0 },
        { command: 'restore signer', status: 0 },
        {
          command: consoleIntegrityCommand,
          status: 0,
          stdout: JSON.stringify([{ results: [{ integrity_check: 'ok' }] }]),
        },
        {
          command: signerIntegrityCommand,
          status: 0,
          stdout: JSON.stringify([{ results: [{ integrity_check: 'ok' }] }]),
        },
      ],
      artifactEvidence: [
        {
          path: 'console.sql',
          bytes: 128,
          sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
        {
          path: 'signer.sql',
          bytes: 256,
          sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
        {
          path: 'console-restore.sql',
          bytes: 128,
          sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
        {
          path: 'signer-restore.sql',
          bytes: 256,
          sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
      ],
    }),
  };
}

test('D1 staging evidence verifier writes a passing summary for remote manifests', async () => {
  const { module, dir, manifests } = await passingEvidenceFixture();
  const outputPath = path.join(dir, 'verification.json');
  const result = module.verifyD1StagingEvidence({
    ...manifests,
    generatedAtIso: '2026-06-28T00:00:00.000Z',
    outputPath,
  });

  expect(result.summary.ok).toBe(true);
  expect(result.summary.evidence.map((entry) => entry.id)).toEqual([
    'resource_inventory',
    'hosted_signer_kek_metadata',
    'remote_d1_migrations',
    'time_travel_before_fixture_import',
    'fixture_import',
    'time_travel_before_route_switch',
    'staging_smoke',
    'd1_reconciliation',
    'signer_custody',
    'r2_restore_drill',
  ]);
  expect(fs.existsSync(outputPath)).toBe(true);
});

const evidenceMutationCases: readonly EvidenceMutationCase[] = [
  {
    name: 'D1 staging evidence verifier rejects dry-run manifests',
    mutate: (m) => patchManifest(m.smoke, { mode: 'dry-run' }),
    expectedError: /staging_smoke: evidence must come from mode=remote/,
  },
  {
    name: 'D1 staging evidence verifier rejects reconciliation mismatch rows',
    mutate: (m) => patchManifest(m.reconciliation, { executed: [{ id: 'billing_account_balance_mismatch', status: 0, rowCount: 1 }] }),
    expectedError: /d1_reconciliation: billing_account_balance_mismatch returned 1 mismatch rows/,
  },
  {
    name: 'D1 staging evidence verifier rejects substituted reconciliation commands',
    mutate: (m) => patchManifestRecordById(m.reconciliation, 'executed', 'signer_share_unknown_kek', { command: 'reconcile signer shares against another database' }),
    expectedError: /d1_reconciliation: executed\[signer_share_unknown_kek\]\.command does not match planned command/,
  },
  {
    name: 'D1 staging evidence verifier rejects incomplete resource inventory evidence',
    mutate: (m) => patchManifest(m.resources, { checks: [{ id: 'console_d1_info', status: 0, json: { uuid: 'd1-console-id' } }] }),
    expectedError: /resource_inventory: missing signer_d1_info evidence in checks/,
  },
  {
    name: 'D1 staging evidence verifier rejects substituted resource inventory commands',
    mutate: (m) => patchManifestRecordById(m.resources, 'checks', 'signer_d1_info', { command: 'resource signer d1 info against another database' }),
    expectedError: /resource_inventory: executed\[signer_d1_info\]\.command does not match planned command/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing planned resource inventory commands',
    mutate: (m) => removeManifestRecordById(m.resources, 'commands', 'signer_d1_info'),
    expectedError: /resource_inventory: missing signer_d1_info evidence in commands/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing D1 binding IDs in resource inventory',
    mutate: (m) => patchManifest(m.resources, {
      resources: {
        routerApiWorker: {
          d1Databases: [
            { binding: 'CONSOLE_DB', databaseId: 'd1-console-id' },
            { binding: 'SIGNER_DB', databaseId: 'd1-signer-id' },
          ],
          stagingVars: {
            namespace: 'tenant-route-staging',
            orgId: 'org_staging',
            projectId: 'project_staging',
            envId: 'env_staging',
            signingRootKekProvider: 'cloudflare-secrets-store',
            signingRootKekIds: ['kek-r1'],
          },
        },
      },
    }),
    expectedError: /resource_inventory: resources\.consoleWorker must be present/,
  },
  {
    name: 'D1 staging evidence verifier rejects signer D1 bindings on the console Worker',
    mutate: (m) => patchResourceWorker(m.resources, 'consoleWorker', {
      d1Databases: [
        { binding: 'CONSOLE_DB', databaseId: 'd1-console-id' },
        { binding: 'SIGNER_DB', databaseId: 'd1-signer-id' },
      ],
    }),
    expectedError: /resource_inventory: resources\.consoleWorker\.d1Databases must not include signer-only binding SIGNER_DB/,
  },
  {
    name: 'D1 staging evidence verifier rejects signer Durable Objects on the console Worker',
    mutate: (m) => patchResourceWorker(m.resources, 'consoleWorker', { durableObjects: [{ name: 'THRESHOLD_STORE', className: 'ThresholdStore' }] }),
    expectedError: /resource_inventory: resources\.consoleWorker\.durableObjects must not include signer-only binding THRESHOLD_STORE/,
  },
  {
    name: 'D1 staging evidence verifier rejects signer KEK bindings on the console Worker',
    mutate: (m) => patchResourceWorker(m.resources, 'consoleWorker', {
      secretsStoreSecrets: [{ binding: 'SIGNING_ROOT_KEK_R1', storeId: 'secret-store', secretName: 'kek-r1' }],
    }),
    expectedError: /resource_inventory: resources\.consoleWorker\.secretsStoreSecrets must not include signer KEK binding SIGNING_ROOT_KEK_R1/,
  },
  {
    name: 'D1 staging evidence verifier rejects router-api resource inventory without signer DO binding',
    mutate: (m) => patchResourceWorker(m.resources, 'routerApiWorker', { durableObjects: [] }),
    expectedError: /resource_inventory: resources\.routerApiWorker\.durableObjects missing THRESHOLD_STORE/,
  },
  {
    name: 'D1 staging evidence verifier rejects router-api resource inventory without configured signer KEKs',
    mutate: (m) => patchResourceWorker(m.resources, 'routerApiWorker', { secretsStoreSecrets: [] }),
    expectedError: /resource_inventory: resources\.routerApiWorker\.secretsStoreSecrets missing signer KEK secret kek-r1/,
  },
  {
    name: 'D1 staging evidence verifier rejects mismatched remote D1 database evidence',
    mutate: (m) => patchManifest(m.resources, {
      checks: [
        { id: 'console_d1_info', status: 0, json: { uuid: 'other-console-d1-id' } },
        { id: 'signer_d1_info', status: 0, json: { uuid: 'd1-signer-id' } },
        { id: 'console_worker_deployment_status', status: 0, json: { id: 'console-worker' } },
        { id: 'router_api_worker_deployment_status', status: 0, json: { id: 'router-api-worker' } },
      ],
    }),
    expectedError: /checks\.console_d1_info\.json database id other-console-d1-id must match CONSOLE_DB d1-console-id/,
  },
  {
    name: 'D1 staging evidence verifier rejects Router API config pointed at a different console D1',
    mutate: (m) => patchResourceWorker(m.resources, 'routerApiWorker', {
      d1Databases: [
        { binding: 'CONSOLE_DB', databaseId: 'other-console-d1-id' },
        { binding: 'SIGNER_DB', databaseId: 'd1-signer-id' },
      ],
    }),
    expectedError: /routerApiWorker CONSOLE_DB databaseId other-console-d1-id must match consoleWorker CONSOLE_DB d1-console-id/,
  },
  {
    name: 'D1 staging evidence verifier rejects incomplete migration evidence',
    mutate: (m) => patchManifest(m.migrations, {
      executed: [
        { target: 'console', action: 'list_before', status: 0 },
        { target: 'console', action: 'apply', status: 0 },
        { target: 'console', action: 'list_after', status: 0 },
      ],
    }),
    expectedError: /remote_d1_migrations: missing signer:apply evidence in executed/,
  },
  {
    name: 'D1 staging evidence verifier rejects substituted remote commands',
    mutate: (m) => patchManifestRecordByField(m.migrations, 'executed', 'command', 'migration console apply', { command: 'migration console apply against the wrong database' }),
    expectedError: /remote_d1_migrations: executed\[1\]\.command does not match planned command/,
  },
  {
    name: 'D1 staging evidence verifier rejects duplicate migration target-action evidence',
    mutate: (m) => appendManifestRecords(m.migrations, {
      commands: { target: 'signer', action: 'apply', command: 'migration signer apply again' },
      executed: { target: 'signer', action: 'apply', status: 0, command: 'migration signer apply again' },
    }),
    expectedError: /remote_d1_migrations: executed\.signer:apply is duplicated/,
  },
  {
    name: 'D1 staging evidence verifier rejects one-sided fixture import evidence',
    mutate: (m) => patchManifest(m.fixtureImport, {
      fixtures: [{ logicalName: 'console' }],
      commands: ['import console', 'import signer'],
      executed: [{ command: 'import console', status: 0 }],
    }),
    expectedError: /fixture_import: missing signer evidence in fixtures/,
  },
  {
    name: 'D1 staging evidence verifier rejects incomplete Time Travel bookmark evidence',
    mutate: (m) => patchManifest(m.bookmarkBeforeFixtureImport, { bookmarkEvidence: [{ logicalName: 'console' }] }),
    expectedError: /time_travel_before_fixture_import: missing signer evidence in bookmarkEvidence/,
  },
  {
    name: 'D1 staging evidence verifier rejects Time Travel bookmark path mismatches',
    mutate: (m) => patchManifestRecordByField(m.bookmarkBeforeFixtureImport, 'bookmarkEvidence', 'logicalName', 'console', { path: 'bookmarks/other-console-bookmark.json' }),
    expectedError: /time_travel_before_fixture_import: bookmarkEvidence\.console\.path is bookmarks\/other-console-bookmark\.json, expected bookmarks\/console-before-fixture-import\.json/,
  },
  {
    name: 'D1 staging evidence verifier rejects Time Travel evidence without bookmark JSON',
    mutate: (m) => patchManifestRecordByField(m.bookmarkBeforeFixtureImport, 'bookmarkEvidence', 'logicalName', 'signer', { json: { bookmark: '<placeholder>' } }),
    expectedError: /time_travel_before_fixture_import: bookmarkEvidence\.signer\.json must include a bookmark/,
  },
  {
    name: 'D1 staging evidence verifier rejects incomplete smoke evidence',
    mutate: (m) => patchManifest(m.smoke, { checks: [{ id: 'router_api_readyz', ok: true }] }),
    expectedError: /staging_smoke: missing console_readyz evidence/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing planned smoke endpoints',
    mutate: (m) => removeManifestRecordById(m.smoke, 'endpoints', 'router_api_healthz'),
    expectedError: /staging_smoke: missing router_api_healthz evidence in endpoints/,
  },
  {
    name: 'D1 staging evidence verifier rejects smoke responses for unplanned URLs',
    mutate: (m) => patchManifestRecordById(m.smoke, 'endpoints', 'router_api_readyz', { url: 'https://router-api.staging.example/other-readyz' }),
    expectedError: /staging_smoke: checks\.router_api_readyz\.url does not match planned endpoints\.router_api_readyz\.url/,
  },
  {
    name: 'D1 staging evidence verifier rejects duplicate smoke response IDs',
    mutate: (m) => appendManifestRecords(m.smoke, {
      checks: { id: 'router_api_readyz', ok: true, status: 200, url: 'https://router-api.staging.example/readyz' },
    }),
    expectedError: /staging_smoke: checks\.router_api_readyz is duplicated/,
  },
  {
    name: 'D1 staging evidence verifier rejects HTTP smoke evidence URLs',
    mutate: (m) => patchManifestRecordById(m.smoke, 'checks', 'console_readyz', { url: 'http://console.staging.example/console/readyz' }),
    expectedError: /staging_smoke: checks.console_readyz.url must be an HTTPS URL/,
  },
  {
    name: 'D1 staging evidence verifier rejects shared console and Router API smoke origins',
    mutate: (m) => patchManifestRecordsById(m.smoke, ['endpoints', 'checks'], 'console_readyz', { url: 'https://router-api.staging.example/console/readyz' }),
    expectedError: /staging_smoke: console_readyz and router_api_readyz must use distinct Worker origins/,
  },
  {
    name: 'D1 staging evidence verifier rejects wrong smoke status codes',
    mutate: (m) => patchManifestRecordById(m.smoke, 'checks', 'console_readyz', { status: 503 }),
    expectedError: /staging_smoke: checks\.console_readyz\.status is 503, expected 200/,
  },
  {
    name: 'D1 staging evidence verifier rejects smoke evidence on wrong endpoint paths',
    mutate: (m) => patchManifestRecordById(m.smoke, 'checks', 'router_api_readyz', { url: 'https://router-api.staging.example/not-readyz' }),
    expectedError: /staging_smoke: checks\.router_api_readyz\.url uses path \/not-readyz, expected \/readyz/,
  },
  {
    name: 'D1 staging evidence verifier rejects incomplete signer custody evidence',
    mutate: (m) => patchManifest(m.signerCustody, { results: [{ id: 'ecdsa_export_share_success', ok: true }] }),
    expectedError: /signer_custody: missing signer_custody_ed25519_healthz evidence/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing signer custody missing-KEK evidence',
    mutate: (m) => removeManifestRecordById(m.signerCustody, 'results', missingKekSignerCustodyResultId),
    expectedError: /signer_custody: missing ecdsa_export_share_missing_kek_fail_closed evidence in results/,
  },
  {
    name: 'D1 staging evidence verifier rejects signer custody responses for unplanned URLs',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'checks', 'ecdsa_export_share_success', { url: 'https://router-api.staging.example/router-ab/ecdsa-hss/export/other-share' }),
    expectedError: /signer_custody: results\.ecdsa_export_share_success\.url does not match planned plannedChecks\.ecdsa_export_share_success\.url/,
  },
  {
    name: 'D1 staging evidence verifier rejects HTTP signer custody evidence URLs',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'results', 'ecdsa_export_share_success', { url: 'http://router-api.staging.example/router-ab/ecdsa-hss/export/share' }),
    expectedError: /signer_custody: results.ecdsa_export_share_success.url must be an HTTPS URL/,
  },
  {
    name: 'D1 staging evidence verifier rejects signer custody from a different Router API origin',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'results', 'signer_custody_ed25519_healthz', { url: 'https://other-router-api.staging.example/router-ab/ed25519/healthz' }),
    expectedError: /signer_custody: results\.signer_custody_ed25519_healthz\.url uses https:\/\/other-router-api\.staging\.example, expected https:\/\/router-api\.staging\.example from staging_smoke router_api_readyz/,
  },
  {
    name: 'D1 staging evidence verifier rejects wrong signer custody status codes',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'results', 'ecdsa_export_share_success', { status: 202 }),
    expectedError: /signer_custody: results\.ecdsa_export_share_success\.status is 202, expected 200/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing-KEK evidence that does not fail closed',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'results', missingKekSignerCustodyResultId, { status: 200, body: { ok: true } }),
    expectedError: /signer_custody: results\.ecdsa_export_share_missing_kek_fail_closed\.status must be a 4xx\/5xx fail-closed status, got 200/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing-KEK evidence with the wrong error code',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'results', missingKekSignerCustodyResultId, { body: { ok: false, code: 'internal_error' } }),
    expectedError: /signer_custody: results\.ecdsa_export_share_missing_kek_fail_closed\.body\.code must be missing_signing_root_kek/,
  },
  {
    name: 'D1 staging evidence verifier rejects signer custody evidence on wrong endpoint paths',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'results', 'ecdsa_export_share_success', { url: 'https://router-api.staging.example/router-ab/ecdsa-hss/export/share?debug=true' }),
    expectedError: /signer_custody: results\.ecdsa_export_share_success\.url uses path \/router-ab\/ecdsa-hss\/export\/share\?debug=true, expected \/router-ab\/ecdsa-hss\/export\/share/,
  },
  {
    name: 'D1 staging evidence verifier rejects unredacted signer custody response secrets',
    mutate: (m) => patchManifestRecordById(m.signerCustody, 'results', 'ecdsa_export_share_success', { body: { ok: true, value: { server_export_share_32_b64u: 'raw-server-share' } } }),
    expectedError: /signer_custody: results\.ecdsa_export_share_success\.body\.value\.server_export_share_32_b64u must be redacted/,
  },
  {
    name: 'D1 staging evidence verifier rejects incomplete reconciliation evidence',
    mutate: (m) => patchManifest(m.reconciliation, { executed: [{ id: 'billing_account_balance_mismatch', status: 0, rowCount: 0 }] }),
    expectedError: /d1_reconciliation: missing signer_share_unknown_kek evidence in executed/,
  },
  {
    name: 'D1 staging evidence verifier rejects duplicate reconciliation executed IDs',
    mutate: (m) => appendManifestRecords(m.reconciliation, {
      executed: { id: 'signer_share_unknown_kek', command: 'reconcile signer share unknown kek', status: 0, rowCount: 0 },
    }),
    expectedError: /d1_reconciliation: executed\.signer_share_unknown_kek is duplicated/,
  },
  {
    name: 'D1 staging evidence verifier rejects incomplete R2 restore artifact evidence',
    mutate: (m) => patchManifest(m.r2RestoreDrill, { artifactEvidence: [{ path: 'console.sql' }] }),
    expectedError: /r2_restore_drill: missing artifact evidence for signer.sql/,
  },
  {
    name: 'D1 staging evidence verifier rejects R2 artifacts without hash metadata',
    mutate: (m) => patchManifestRecordByField(m.r2RestoreDrill, 'artifactEvidence', 'path', 'console.sql', { bytes: 0, sha256: 'not-a-sha256' }),
    expectedError: /r2_restore_drill: artifactEvidence\.console\.sql\.bytes must be greater than zero/,
  },
  {
    name: 'D1 staging evidence verifier rejects duplicate R2 artifact evidence paths',
    mutate: (m) => appendManifestRecords(m.r2RestoreDrill, {
      artifactEvidence: { path: 'console.sql', bytes: 12, sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' },
    }),
    expectedError: /r2_restore_drill: artifactEvidence\.console\.sql is duplicated/,
  },
  {
    name: 'D1 staging evidence verifier rejects R2 restore hash mismatches',
    mutate: (m) => patchManifestRecordByField(m.r2RestoreDrill, 'artifactEvidence', 'path', 'signer-restore.sql', {
      sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    }),
    expectedError: /r2_restore_drill: signer restore artifact hash c{64} must match export artifact hash b{64}/,
  },
  {
    name: 'D1 staging evidence verifier rejects failed R2 restore integrity checks',
    mutate: (m) => patchManifestRecordByField(m.r2RestoreDrill, 'executed', 'command', signerIntegrityCommand, {
      stdout: JSON.stringify([{ results: [{ integrity_check: 'row 12 missing from index' }] }]),
    }),
    expectedError: /r2_restore_drill: executed\[11\]\.integrity_check is row 12 missing from index, expected ok/,
  },
  {
    name: 'D1 staging evidence verifier rejects R2 integrity checks that miss the signer restore database',
    mutate: (m) => {
      patchManifestStringValue(m.r2RestoreDrill, 'commands', signerIntegrityCommand, signerIntegrityCommandWithConsoleDatabase);
      patchManifestRecordByField(m.r2RestoreDrill, 'executed', 'command', signerIntegrityCommand, { command: signerIntegrityCommandWithConsoleDatabase });
    },
    expectedError: /r2_restore_drill: missing signer restore integrity-check command evidence/,
  },
  {
    name: 'D1 staging evidence verifier rejects mixed Router API config paths',
    mutate: (m) => patchManifest(m.fixtureImport, { routerApiConfigPath: 'packages/sdk-server-ts/wrangler.other-router-api.toml' }),
    expectedError: /routerApiConfigPath mismatch/,
  },
  {
    name: 'D1 staging evidence verifier rejects mixed tenant evidence',
    mutate: (m) => patchManifest(m.reconciliation, { tenant: { namespace: 'tenant-route-staging', orgId: 'org_other', projectId: 'project_staging', envId: 'env_staging' } }),
    expectedError: /tenant orgId mismatch/,
  },
  {
    name: 'D1 staging evidence verifier rejects out-of-order run manifests',
    mutate: (m) => patchManifest(m.fixtureImport, { generatedAtIso: '2026-06-28T00:01:30.000Z' }),
    expectedError: /evidence order mismatch/,
  },
  {
    name: 'D1 staging evidence verifier rejects resource inventory captured after migrations',
    mutate: (m) => patchManifest(m.resources, { generatedAtIso: '2026-06-28T00:02:00.000Z' }),
    expectedError: /evidence order mismatch: hosted_signer_kek_metadata/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing configured KEK evidence',
    mutate: (m) => patchManifest(m.kekCheck, { checks: [{ storeId: 'secret-store', status: 0, presentSecretNames: ['kek-other'] }] }),
    expectedError: /configured KEK kek-r1 was not found/,
  },
  {
    name: 'D1 staging evidence verifier rejects substituted hosted signer KEK commands',
    mutate: (m) => patchManifest(m.kekCheck, {
      checks: [{
        storeId: 'secret-store',
        command: 'secrets-store secret list other-secret-store',
        status: 0,
        presentSecretNames: ['kek-r1'],
      }],
    }),
    expectedError: /hosted_signer_kek_metadata: checks\[0\]\.command does not match planned command/,
  },
  {
    name: 'D1 staging evidence verifier rejects missing manifests',
    mutate: (m) => fs.unlinkSync(m.r2RestoreDrill),
    expectedError: /r2_restore_drill: manifest does not exist/,
  },
];

for (const testCase of evidenceMutationCases) {
  test(testCase.name, async () => {
    await expectEvidenceMutationToThrow(testCase);
  });
}
