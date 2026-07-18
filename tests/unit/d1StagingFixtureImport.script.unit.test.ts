import { expect, test } from '@playwright/test';
import {
  D1_STAGING_GENERATED_AT_ISO,
  d1StagingFailedCommandResult,
  d1StagingManifestPath,
  d1StagingOkCommandRunner,
  loadD1StagingScriptModule,
  readD1StagingJsonFile,
  type D1StagingCommandResult,
  type D1StagingCommandRunner,
  writeD1StagingTempFile,
  writeValidD1StagingConfigFiles,
} from './helpers/d1StagingScriptFixtures';

type FixtureImportPlan = {
  readonly mode: string;
  readonly commands: readonly string[];
  readonly fixtures: readonly {
    readonly logicalName: string;
    readonly sha256: string;
    readonly tableFamily: string;
    readonly touchedTables: readonly string[];
  }[];
};

type FixtureImportModule = {
  readonly buildD1StagingFixtureImportPlan: (input: {
    readonly consoleConfigPath: string;
    readonly gatewayConfigPath: string;
    readonly consoleFixturePath: string;
    readonly signerFixturePath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => FixtureImportPlan;
  readonly runD1StagingFixtureImport: (input: {
    readonly consoleConfigPath: string;
    readonly gatewayConfigPath: string;
    readonly consoleFixturePath: string;
    readonly signerFixturePath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly commandRunner?: D1StagingCommandRunner;
  }) => {
    readonly manifestPath: string;
    readonly manifest: FixtureImportPlan & {
      readonly executed: readonly D1StagingCommandResult[];
    };
  };
};

const fixtureImportModule = loadD1StagingScriptModule<FixtureImportModule>(
  'd1-staging-fixture-import.mjs',
);

const validConsoleFixtureSql = `
INSERT INTO organizations (org_id, display_name, created_at_ms, updated_at_ms)
VALUES ('org_staging', 'Create Staging Org', 1, 1);
`;

const validSignerFixtureSql = `
INSERT INTO wallets (tenant_storage_namespace, project_id, environment_id, wallet_id, created_at_ms, updated_at_ms)
VALUES ('seams-staging', 'project_staging', 'staging', 'wallet_staging', 1, 1);
`;

const fixtureImportInput = {
  ...writeValidD1StagingConfigFiles('seams-d1-staging-fixtures-'),
  consoleFixturePath: writeD1StagingTempFile(
    'seams-d1-staging-fixtures-',
    'console.sql',
    validConsoleFixtureSql,
  ),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
  signerFixturePath: writeD1StagingTempFile(
    'seams-d1-staging-fixtures-',
    'signer.sql',
    validSignerFixtureSql,
  ),
};

function failedCommandRunner(command: string): D1StagingCommandResult {
  return d1StagingFailedCommandResult(command, 'remote D1 execution failed', 'partial output');
}

test('D1 staging fixture import builds a dry-run plan from readiness-clean configs', async () => {
  const module = await fixtureImportModule;
  const plan = module.buildD1StagingFixtureImportPlan(fixtureImportInput);

  expect(plan.mode).toBe('dry-run');
  expect(plan.commands).toHaveLength(2);
  expect(plan.commands[0]).toContain('d1 execute seams-console-staging --remote --yes --file');
  expect(plan.commands[1]).toContain('d1 execute seams-signer-staging --remote --yes --file');
  expect(plan.fixtures).toEqual([
    expect.objectContaining({
      logicalName: 'console',
      tableFamily: 'console',
      touchedTables: ['organizations'],
    }),
    expect.objectContaining({
      logicalName: 'signer',
      tableFamily: 'signer',
      touchedTables: ['wallets'],
    }),
  ]);
});

test('D1 staging fixture import writes a dry-run manifest without touching Cloudflare', async () => {
  const module = await fixtureImportModule;
  const manifestPath = d1StagingManifestPath('seams-d1-fixture-import');
  module.runD1StagingFixtureImport({
    ...fixtureImportInput,
    manifestPath,
  });

  expect(readD1StagingJsonFile(manifestPath).commands).toHaveLength(2);
});

test('D1 staging fixture import remote mode records command evidence', async () => {
  const module = await fixtureImportModule;
  const manifestPath = d1StagingManifestPath('seams-d1-fixture-import-remote');
  const result = module.runD1StagingFixtureImport({
    ...fixtureImportInput,
    manifestPath,
    mode: 'remote',
    commandRunner: d1StagingOkCommandRunner,
  });

  expect(result.manifest.executed).toHaveLength(2);
  expect(result.manifest.executed[0]).toMatchObject({
    command: expect.stringContaining('d1 execute seams-console-staging --remote --yes --file'),
    status: 0,
  });
  expect(result.manifest.executed[1]).toMatchObject({
    command: expect.stringContaining('d1 execute seams-signer-staging --remote --yes --file'),
    status: 0,
  });
});

test('D1 staging fixture import remote mode rejects failed D1 commands', async () => {
  const module = await fixtureImportModule;
  const manifestPath = d1StagingManifestPath('seams-d1-fixture-import-failed');

  expect(() =>
    module.runD1StagingFixtureImport({
      ...fixtureImportInput,
      manifestPath,
      mode: 'remote',
      commandRunner: failedCommandRunner,
    }),
  ).toThrow(/Command failed: .*d1 execute seams-console-staging --remote --yes --file/);
});

test('D1 staging fixture import rejects cross-domain fixture SQL', async () => {
  const module = await fixtureImportModule;
  const badConsoleFixture = writeD1StagingTempFile(
    'seams-d1-staging-fixtures-',
    'console.sql',
    validSignerFixtureSql,
  );

  expect(() =>
    module.buildD1StagingFixtureImportPlan({
      ...fixtureImportInput,
      consoleFixturePath: badConsoleFixture,
    }),
  ).toThrow(/console fixture touches wallets/);
});

test('D1 staging fixture import rejects schema-changing fixture SQL', async () => {
  const module = await fixtureImportModule;
  const badSignerFixture = writeD1StagingTempFile(
    'seams-d1-staging-fixtures-',
    'signer.sql',
    'DROP TABLE wallets;',
  );

  expect(() =>
    module.buildD1StagingFixtureImportPlan({
      ...fixtureImportInput,
      signerFixturePath: badSignerFixture,
    }),
  ).toThrow(/signer fixture contains schema DDL/);
});
