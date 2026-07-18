import { expect, test } from '@playwright/test';
import {
  D1_STAGING_GENERATED_AT_ISO,
  d1StagingCommandResult,
  d1StagingFailedCommandResult,
  d1StagingManifestPath,
  d1StagingUnquoteShellToken,
  loadD1StagingScriptModule,
  readD1StagingJsonFile,
  type D1StagingCommandResult,
  type D1StagingCommandRunner,
  writeD1StagingPackageFile,
  writeValidD1StagingConfigFiles,
} from './helpers/d1StagingScriptFixtures';

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
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly r2Bucket: string;
  }) => R2RestoreDrillPlan;
  readonly runD1StagingR2RestoreDrill: (input: {
    readonly consoleConfigPath: string;
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly r2Bucket: string;
    readonly commandRunner?: D1StagingCommandRunner;
  }) => {
    readonly manifestPath: string;
    readonly manifest: R2RestoreDrillPlan & {
      readonly executed: readonly unknown[];
      readonly artifactEvidence: readonly unknown[];
    };
  };
};

const drillModule = loadD1StagingScriptModule<R2RestoreDrillModule>(
  'd1-staging-r2-restore-drill.mjs',
);
const r2DrillInput = {
  ...writeValidD1StagingConfigFiles('seams-d1-r2-drill-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
  r2Bucket: 'seams-staging-backups',
};

function createArtifactCommandRunner(command: string): D1StagingCommandResult {
  if (isIntegrityCheckCommand(command)) {
    return d1StagingCommandResult(command, {
      stdout: JSON.stringify([{ results: [{ integrity_check: 'ok' }] }]),
    });
  }
  writeCommandFile(command, /--output ([^ ]+)/);
  writeCommandFile(command, /--file ([^ ]+)/);
  return d1StagingCommandResult(command, { stdout: 'ok' });
}

function corruptIntegrityCommandRunner(command: string): D1StagingCommandResult {
  if (isIntegrityCheckCommand(command)) {
    return d1StagingCommandResult(command, {
      stdout: JSON.stringify([{ results: [{ integrity_check: 'row 12 missing from index' }] }]),
    });
  }
  return createArtifactCommandRunner(command);
}

function failedR2CommandRunner(command: string): D1StagingCommandResult {
  return d1StagingFailedCommandResult(command, 'remote backup export failed');
}

function isIntegrityCheckCommand(command: string): boolean {
  return command.includes('PRAGMA integrity_check');
}

function writeCommandFile(command: string, pattern: RegExp): void {
  const match = pattern.exec(command);
  if (!match) return;
  const filePath = d1StagingUnquoteShellToken(match[1] || '');
  if (!filePath.endsWith('.sql')) return;
  writeD1StagingPackageFile(filePath, `-- fixture for ${filePath}\n`);
}

test('D1 staging R2 restore drill builds timestamped export, R2, restore, and integrity commands', async () => {
  const module = await drillModule;
  const plan = module.buildD1StagingR2RestoreDrillPlan(r2DrillInput);

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
  const module = await drillModule;
  const manifestPath = d1StagingManifestPath('seams-d1-r2-drill');
  const result = module.runD1StagingR2RestoreDrill({
    ...r2DrillInput,
    manifestPath,
  });

  expect(result.manifest.executed).toEqual([]);
  expect(result.manifest.artifactEvidence).toEqual([]);
  expect(readD1StagingJsonFile(manifestPath).commands).toHaveLength(12);
});

test('D1 staging R2 restore drill remote mode records command and artifact evidence', async () => {
  const module = await drillModule;
  const manifestPath = d1StagingManifestPath('seams-d1-r2-drill-remote');
  const result = module.runD1StagingR2RestoreDrill({
    ...r2DrillInput,
    manifestPath,
    mode: 'remote',
    commandRunner: createArtifactCommandRunner,
  });

  expect(result.manifest.executed).toHaveLength(12);
  expect(result.manifest.artifactEvidence).toHaveLength(4);
});

test('D1 staging R2 restore drill remote mode rejects failed export commands', async () => {
  const module = await drillModule;

  expect(() =>
    module.runD1StagingR2RestoreDrill({
      ...r2DrillInput,
      manifestPath: d1StagingManifestPath('seams-d1-r2-drill-failed'),
      mode: 'remote',
      commandRunner: failedR2CommandRunner,
    }),
  ).toThrow(/Command failed: .*d1 export seams-console-staging --remote/);
});

test('D1 staging R2 restore drill rejects corrupt integrity-check output', async () => {
  const module = await drillModule;

  expect(() =>
    module.runD1StagingR2RestoreDrill({
      ...r2DrillInput,
      manifestPath: d1StagingManifestPath('seams-d1-r2-drill-corrupt-integrity'),
      mode: 'remote',
      commandRunner: corruptIntegrityCommandRunner,
    }),
  ).toThrow(/R2 restore drill integrity_check is row 12 missing from index, expected ok/);
});

test('D1 staging R2 restore drill rejects object paths as bucket names', async () => {
  const module = await drillModule;
  expect(() =>
    module.buildD1StagingR2RestoreDrillPlan({
      ...r2DrillInput,
      r2Bucket: 'seams-staging-backups/refactor-82',
    }),
  ).toThrow(/--r2-bucket must be a bucket name/);
});
