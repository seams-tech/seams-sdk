import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import {
  assertAppliedMigrationSourcesUnchanged,
  digestMigrations,
  readMigrationFiles,
} from '../../scripts/migration-fingerprint.mjs';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

type MigrationSet = {
  readonly database?: string;
  readonly fingerprint: string;
  readonly migrations: readonly string[];
};

const repoRoot = path.resolve(import.meta.dirname, '../..');
const helperPath = path.join(repoRoot, 'scripts/migration-fingerprint.mjs');
const applierPath = path.join(
  repoRoot,
  'packages/console-server-ts/scripts/apply-remote-d1-migrations.mjs',
);
const consoleMigrationRoot = path.join(
  repoRoot,
  'packages/wallet-console-server-ts/migrations/d1-console',
);
const signerMigrationRoot = path.join(repoRoot, 'packages/wallet-server/migrations/d1-signer');

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

test('applied migration sources are immutable when a forward migration is added', () => {
  const appliedMigration = { name: '0001_initial.sql', source: 'initial\n' };
  const forwardMigration = { name: '0002_forward.sql', source: 'forward\n' };

  expect(() =>
    assertAppliedMigrationSourcesUnchanged({
      previousFingerprint: digestMigrations([appliedMigration]),
      appliedMigrationNames: new Set([appliedMigration.name]),
      migrations: [{ ...appliedMigration, source: 'rewritten\n' }, forwardMigration],
    }),
  ).toThrow(/add a new forward migration/u);

  expect(() =>
    assertAppliedMigrationSourcesUnchanged({
      previousFingerprint: digestMigrations([appliedMigration]),
      appliedMigrationNames: new Set([appliedMigration.name]),
      migrations: [appliedMigration, forwardMigration],
    }),
  ).not.toThrow();

  expect(() =>
    assertAppliedMigrationSourcesUnchanged({
      previousFingerprint: 'deployed-predecessor',
      appliedMigrationNames: new Set([appliedMigration.name, forwardMigration.name]),
      migrations: [appliedMigration, forwardMigration],
    }),
  ).toThrow(/add a new forward migration/u);
});

test('Signer applied migration prefix stays byte-for-byte immutable', () => {
  const signerMigrations = readMigrationFiles(signerMigrationRoot);
  const deployedPrefix = signerMigrations.slice(0, 8);

  expect(deployedPrefix.map((migration) => migration.name)).toEqual([
    '0001_signer_d1_initial.sql',
    '0002_signer_post_103_canonical_upgrade.sql',
    '0003_r107_wallet_authorization.sql',
    '0004_remove_legacy_email_recovery.sql',
    '0005_r103p8_linked_owner_auth_bindings.sql',
    '0006_r103p8_linked_device_custody_transfers.sql',
    '0007_r103p8_wallet_session_auth_method_provenance.sql',
    '0008_r103p8_linked_device_session_cas_guard.sql',
  ]);
  expect(digestMigrations(deployedPrefix)).toBe(
    'ded40767b23ce274355ab2f7cf8c57b7142d7125d74b80ae20ebc552bbe5c5f6',
  );
});

test('Console applied baseline stays immutable and upgrades to the fresh schema', async () => {
  const deployed = createTemporaryD1Database();
  const fresh = createTemporaryD1Database();
  try {
    const consoleMigrations = readMigrationFiles(consoleMigrationRoot);
    const migrationFiles = listD1MigrationFiles('d1-console');
    const migrationNames = consoleMigrations.map((migration) => migration.name);
    expect(migrationNames).toEqual([
      '0001_console_d1_initial.sql',
      '0026_console_canonical_baseline_bridge.sql',
      '0027_console_runtime_isolation.sql',
      '0028_wallet_balance_snapshots.sql',
      '0029_multichain_wallet_projection.sql',
    ]);
    expect(migrationFiles.map((file) => path.basename(file))).toEqual(migrationNames);
    expect(digestMigrations(consoleMigrations.slice(0, 2))).toBe(
      'bce6fa44b122a54ba8a97ab92d7b69e1c6bbbc8f5adeede119f37da8550f79f5',
    );
    const currentFingerprint = digestMigrations(consoleMigrations);
    const appliedMigrationNames = new Set(migrationNames);

    await applyD1MigrationFiles(deployed.database, migrationFiles.slice(0, 2));
    await deployed.database.exec(deployedConsoleFixtureSql);
    await applyD1MigrationFiles(deployed.database, migrationFiles.slice(2));
    await deployed.database.exec(`
      CREATE TABLE d1_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE d1_migration_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
      );
      INSERT INTO d1_migrations (name) VALUES ('${migrationNames.join("'),\n        ('")}');
      INSERT INTO d1_migration_metadata (key, value)
      VALUES ('schema_fingerprint', '${currentFingerprint}');
    `);

    const persistedFingerprint = await deployed.database
      .prepare(`SELECT value FROM d1_migration_metadata WHERE key = 'schema_fingerprint'`)
      .first<{ readonly value: string }>();
    expect(persistedFingerprint?.value).toBe(currentFingerprint);
    expect(() =>
      assertAppliedMigrationSourcesUnchanged({
        previousFingerprint: currentFingerprint,
        appliedMigrationNames,
        migrations: consoleMigrations,
      }),
    ).not.toThrow();

    const organization = await deployed.database
      .prepare(
        `SELECT name, slug
           FROM organizations
          WHERE namespace = 'namespace' AND id = 'org-1'`,
      )
      .first<{ readonly name: string; readonly slug: string }>();
    expect(organization).toEqual({ name: 'Acme', slug: 'acme' });

    const deployedSchema = await deployed.database
      .prepare(
        `SELECT type, name
           FROM sqlite_master
          WHERE name NOT LIKE 'sqlite_%'
            AND name NOT IN ('d1_migrations', 'd1_migration_metadata')
          ORDER BY type, name`,
      )
      .all<{ readonly type: string; readonly name: string }>();
    const historyRows = await deployed.database
      .prepare(`SELECT name FROM d1_migrations ORDER BY id`)
      .all<{ readonly name: string }>();
    expect(historyRows.results.map((row) => row.name)).toEqual(migrationNames);
    const rerunAppliedMigrationNames = new Set<string>();
    for (const row of historyRows.results) rerunAppliedMigrationNames.add(row.name);
    const missingOnRerun: string[] = [];
    for (const migration of consoleMigrations) {
      if (!rerunAppliedMigrationNames.has(migration.name)) missingOnRerun.push(migration.name);
    }
    expect(missingOnRerun).toEqual([]);
    expect(() =>
      assertAppliedMigrationSourcesUnchanged({
        previousFingerprint: currentFingerprint,
        appliedMigrationNames: rerunAppliedMigrationNames,
        migrations: consoleMigrations,
      }),
    ).not.toThrow();

    await applyD1MigrationFiles(fresh.database, migrationFiles);
    const freshSchema = await fresh.database
      .prepare(
        `SELECT type, name
           FROM sqlite_master
          WHERE name NOT LIKE 'sqlite_%'
          ORDER BY type, name`,
      )
      .all<{ readonly type: string; readonly name: string }>();
    expect(freshSchema.results).toEqual(deployedSchema.results);
    const organizationsTable = await fresh.database
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'organizations'`)
      .first<{ readonly name: string }>();
    expect(organizationsTable?.name).toBe('organizations');
  } finally {
    cleanupTemporaryD1Database(deployed.tempDir);
    cleanupTemporaryD1Database(fresh.tempDir);
  }
});

const deployedConsoleFixtureSql = `
INSERT INTO organizations (
  namespace,
  id,
  name,
  slug,
  created_by_user_id,
  status,
  created_at_ms,
  updated_at_ms
) VALUES ('namespace', 'org-1', 'Acme', 'acme', 'user-1', 'ACTIVE', 1, 1);
`;

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
