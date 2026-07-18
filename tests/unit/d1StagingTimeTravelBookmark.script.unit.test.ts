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
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly purpose: string;
    readonly timestampIso?: string;
  }) => BookmarkPlan;
  readonly runD1StagingTimeTravelBookmark: (input: {
    readonly consoleConfigPath: string;
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly purpose: string;
    readonly timestampIso?: string;
    readonly commandRunner?: D1StagingCommandRunner;
  }) => {
    readonly manifestPath: string;
    readonly manifest: BookmarkPlan & {
      readonly executed: readonly unknown[];
      readonly bookmarkEvidence: readonly unknown[];
    };
  };
};

const bookmarkModule = loadD1StagingScriptModule<BookmarkModule>(
  'd1-staging-time-travel-bookmark.mjs',
);
const bookmarkInput = {
  ...writeValidD1StagingConfigFiles('seams-d1-bookmark-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
  purpose: 'before_fixture_import',
  timestampIso: D1_STAGING_GENERATED_AT_ISO,
};

function bookmarkCommandRunner(command: string): D1StagingCommandResult {
  const match = /> ([^ ]+\.json)$/.exec(command);
  if (match) {
    const filePath = d1StagingUnquoteShellToken(match[1] || '');
    const fileName = filePath.split('/').pop() || filePath;
    writeD1StagingPackageFile(filePath, JSON.stringify({ bookmark: `bookmark-for-${fileName}` }));
  }
  return d1StagingCommandResult(command);
}

function failedBookmarkCommandRunner(command: string): D1StagingCommandResult {
  return d1StagingFailedCommandResult(command, 'bookmark capture failed');
}

function missingBookmarkCommandRunner(command: string): D1StagingCommandResult {
  const match = /> ([^ ]+\.json)$/.exec(command);
  if (match) {
    const filePath = d1StagingUnquoteShellToken(match[1] || '');
    writeD1StagingPackageFile(filePath, JSON.stringify({ result: 'ok' }));
  }
  return d1StagingCommandResult(command);
}

test('D1 staging Time Travel bookmark builds console and signer bookmark commands', async () => {
  const module = await bookmarkModule;
  const plan = module.buildD1StagingTimeTravelBookmarkPlan(bookmarkInput);

  expect(plan.stamp).toBe('20260628T000000Z');
  expect(plan.commands).toHaveLength(2);
  expect(plan.commands[0]).toContain('d1 time-travel info seams-console-staging');
  expect(plan.commands[0]).toContain('console-before_fixture_import.json');
  expect(plan.commands[1]).toContain('d1 time-travel info seams-signer-staging');
  expect(plan.artifacts.signerBookmarkPath).toContain('signer-before_fixture_import.json');
});

test('D1 staging Time Travel bookmark dry-run writes a manifest without executing commands', async () => {
  const module = await bookmarkModule;
  const manifestPath = d1StagingManifestPath('seams-d1-bookmark');
  const result = module.runD1StagingTimeTravelBookmark({
    ...bookmarkInput,
    manifestPath,
  });

  expect(result.manifest.executed).toEqual([]);
  expect(result.manifest.bookmarkEvidence).toEqual([]);
  expect(readD1StagingJsonFile(manifestPath).commands).toHaveLength(2);
});

test('D1 staging Time Travel bookmark remote mode records bookmark JSON evidence', async () => {
  const module = await bookmarkModule;
  const manifestPath = d1StagingManifestPath('seams-d1-bookmark-remote');
  const result = module.runD1StagingTimeTravelBookmark({
    ...bookmarkInput,
    manifestPath,
    mode: 'remote',
    purpose: 'before_route_switch',
    commandRunner: bookmarkCommandRunner,
  });

  expect(result.manifest.executed).toHaveLength(2);
  expect(result.manifest.bookmarkEvidence).toHaveLength(2);
});

test('D1 staging Time Travel bookmark remote mode rejects failed bookmark commands', async () => {
  const module = await bookmarkModule;

  expect(() =>
    module.runD1StagingTimeTravelBookmark({
      ...bookmarkInput,
      manifestPath: d1StagingManifestPath('seams-d1-bookmark-failed'),
      mode: 'remote',
      commandRunner: failedBookmarkCommandRunner,
    }),
  ).toThrow(/Command failed: .*d1 time-travel info seams-console-staging/);
});

test('D1 staging Time Travel bookmark rejects JSON without a usable bookmark', async () => {
  const module = await bookmarkModule;

  expect(() =>
    module.runD1StagingTimeTravelBookmark({
      ...bookmarkInput,
      manifestPath: d1StagingManifestPath('seams-d1-bookmark-missing-bookmark'),
      mode: 'remote',
      commandRunner: missingBookmarkCommandRunner,
    }),
  ).toThrow(/Time Travel bookmark JSON must include a usable bookmark/);
});

test('D1 staging Time Travel bookmark rejects unsafe purpose names', async () => {
  const module = await bookmarkModule;
  expect(() =>
    module.buildD1StagingTimeTravelBookmarkPlan({
      ...bookmarkInput,
      purpose: '../bad',
    }),
  ).toThrow(/--purpose must be lower_snake_case/);
});
