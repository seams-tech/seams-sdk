import { expect, test } from '@playwright/test';
import {
  D1_STAGING_GENERATED_AT_ISO,
  d1StagingFailedCommandResult,
  readD1StagingJsonFile,
  d1StagingManifestPath,
  d1StagingOkCommandRunner,
  loadD1StagingScriptModule,
  type D1StagingCommandResult,
  type D1StagingCommandRunner,
  writeMisScopedConsoleD1StagingConfigFiles,
  writeValidD1StagingConfigFiles,
} from './helpers/d1StagingScriptFixtures';

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
    readonly routerApiConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => MigrationPlan;
  readonly runD1StagingMigration: (input: {
    readonly consoleConfigPath: string;
    readonly routerApiConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly commandRunner?: D1StagingCommandRunner;
  }) => {
    readonly manifestPath: string;
    readonly manifest: MigrationPlan & {
      readonly executed: readonly unknown[];
    };
  };
};

const migrationModule = loadD1StagingScriptModule<MigrationModule>('d1-staging-migrate.mjs');
const migrationInput = {
  ...writeValidD1StagingConfigFiles('seams-d1-staging-migrate-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
};
const misScopedMigrationInput = {
  ...writeMisScopedConsoleD1StagingConfigFiles('seams-d1-staging-migrate-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
};

function failedCommandRunner(command: string): D1StagingCommandResult {
  return d1StagingFailedCommandResult(command, 'remote migration failed', 'not applied');
}

test('D1 staging migration plan records migration hashes and noninteractive apply commands', async () => {
  const module = await migrationModule;
  const plan = module.buildD1StagingMigrationPlan(migrationInput);

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
  const module = await migrationModule;
  const manifestPath = d1StagingManifestPath('seams-d1-migrate');
  const result = module.runD1StagingMigration({
    ...migrationInput,
    manifestPath,
  });

  expect(result.manifest.executed).toEqual([]);
  expect(readD1StagingJsonFile(manifestPath).commands).toHaveLength(6);
});

test('D1 staging migration remote mode records list and apply command evidence', async () => {
  const module = await migrationModule;
  const manifestPath = d1StagingManifestPath('seams-d1-migrate-remote');
  const result = module.runD1StagingMigration({
    ...migrationInput,
    manifestPath,
    mode: 'remote',
    commandRunner: d1StagingOkCommandRunner,
  });

  expect(result.manifest.executed).toHaveLength(6);
  expect(result.manifest.executed[1]).toMatchObject({
    target: 'console',
    action: 'apply',
    status: 0,
  });
});

test('D1 staging migration rejects failed remote migration commands', async () => {
  const module = await migrationModule;
  expect(() =>
    module.runD1StagingMigration({
      ...migrationInput,
      manifestPath: d1StagingManifestPath('seams-d1-migrate-fail'),
      mode: 'remote',
      commandRunner: failedCommandRunner,
    }),
  ).toThrow(/Command failed: pnpm --dir packages\/sdk-server-ts exec wrangler d1 migrations list/);
});

test('D1 staging migration rejects configs that fail the staging readiness gate', async () => {
  const module = await migrationModule;
  expect(() =>
    module.buildD1StagingMigrationPlan(misScopedMigrationInput),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});
