import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from '@playwright/test';

type MigrationSet = {
  readonly database?: string;
  readonly fingerprint: string;
  readonly migrations: readonly string[];
};

const repoRoot = path.resolve(import.meta.dirname, '../..');
const helperPath = path.join(repoRoot, 'scripts/migration-fingerprint.mjs');
const releasePath = path.join(repoRoot, 'scripts/deployment-release.mjs');
const applierPath = path.join(
  repoRoot,
  'packages/console-server-ts/scripts/apply-remote-d1-migrations.mjs',
);

test('migration fingerprint output is stable per database and uses sorted framed records', () => {
  const migrationsDir = writeMigrationDirectory();
  try {
    const helperOutput = runJsonCommand(helperPath, [
      '--database',
      'console',
      '--migrations-dir',
      migrationsDir,
      '--format',
      'json',
    ]);
    const releaseOutput = runJsonCommand(releasePath, [
      'migration-fingerprint',
      '--database',
      'console',
      '--migrations-dir',
      migrationsDir,
      '--format',
      'json',
    ]);

    const expectedHash = createHash('sha256');
    for (const [name, source] of [
      ['0001_first.sql', 'first\n'],
      ['0002_second.sql', 'second\n'],
    ]) {
      expectedHash.update(name);
      expectedHash.update('\0');
      expectedHash.update(source);
      expectedHash.update('\0');
    }

    expect(helperOutput).toEqual({
      database: 'console',
      fingerprint: expectedHash.digest('hex'),
      migrations: ['0001_first.sql', '0002_second.sql'],
    });
    expect(releaseOutput).toEqual(helperOutput);
  } finally {
    rmSync(migrationsDir, { recursive: true, force: true });
  }
});

test('remote migration applier rejects an unexpected fingerprint before Wrangler execution', () => {
  const migrationsDir = writeMigrationDirectory();
  try {
    const result = spawnSync(
      process.execPath,
      [
        applierPath,
        '--database',
        'CONSOLE_DB',
        '--config',
        path.join(migrationsDir, 'missing-wrangler.toml'),
        '--migrations-dir',
        migrationsDir,
        '--expected-fingerprint',
        'f'.repeat(64),
      ],
      { encoding: 'utf8' },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('D1 migration fingerprint mismatch');
    expect(result.stderr).not.toContain('Wrangler D1 command failed');
  } finally {
    rmSync(migrationsDir, { recursive: true, force: true });
  }
});

function writeMigrationDirectory() {
  const directory = mkdtempSync(path.join(tmpdir(), 'seams-migration-fingerprint-'));
  mkdirSync(path.join(directory, 'ignored'), { recursive: true });
  writeFileSync(path.join(directory, '0002_second.sql'), 'second\n');
  writeFileSync(path.join(directory, '0001_first.sql'), 'first\n');
  writeFileSync(path.join(directory, 'README.md'), 'ignored\n');
  return directory;
}

function runJsonCommand(command, args) {
  const output: MigrationSet = JSON.parse(
    execFileSync(process.execPath, [command, ...args], { encoding: 'utf8' }),
  );
  return output;
}
