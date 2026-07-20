#!/usr/bin/env node
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const migrationNamePattern = /^[0-9]{4}_[a-z0-9_]+\.sql$/;

function main() {
  const options = parseArgs(process.argv.slice(2));
  ensureMigrationTable(options);
  const applied = readAppliedMigrationNames(options);
  const migrations = readMigrationFiles(options.migrationsDir);

  for (const migration of migrations) {
    if (applied.has(migration.name)) continue;
    applyMigration(options, migration);
  }

  verifyAppliedMigrations(options, migrations);
}

function parseArgs(args) {
  const database = readOption(args, '--database');
  const config = readOption(args, '--config');
  const migrationsDir = readOption(args, '--migrations-dir');
  if (!database || !config || !migrationsDir) {
    throw new Error(
      'Usage: apply-remote-d1-migrations.mjs --database <binding> --config <path> --migrations-dir <path>',
    );
  }
  return {
    database,
    config: resolve(config),
    migrationsDir: resolve(migrationsDir),
  };
}

function readOption(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function ensureMigrationTable(options) {
  runWrangler(options, [
    '--command',
    `CREATE TABLE IF NOT EXISTS d1_migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );`,
  ]);
}

function readAppliedMigrationNames(options) {
  const output = runWranglerJson(options, [
    '--command',
    'SELECT name FROM d1_migrations ORDER BY id ASC;',
  ]);
  const rows = readSingleResultRows(output, 'migration inventory');
  const names = new Set();
  for (const row of rows) {
    if (!row || typeof row !== 'object' || typeof row.name !== 'string') {
      throw new Error('D1 migration inventory returned an invalid row');
    }
    names.add(row.name);
  }
  return names;
}

function readMigrationFiles(migrationsDir) {
  const files = [];
  const names = readdirSync(migrationsDir).filter(isMigrationFile).sort();
  for (const name of names) {
    files.push(readMigrationFile(migrationsDir, name));
  }
  return files;
}

function isMigrationFile(name) {
  return migrationNamePattern.test(name);
}

function readMigrationFile(migrationsDir, name) {
  return {
    name,
    source: readFileSync(join(migrationsDir, name), 'utf8'),
  };
}

function applyMigration(options, migration) {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'seams-d1-migration-'));
  const migrationPath = join(temporaryDirectory, migration.name);
  const historyStatement = `\nINSERT INTO d1_migrations (name) VALUES (${sqlText(migration.name)});\n`;
  try {
    writeFileSync(migrationPath, `${migration.source.trimEnd()}\n${historyStatement}`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    process.stdout.write(`Applying ${migration.name}\n`);
    runWrangler(options, ['--yes', '--file', migrationPath]);
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function verifyAppliedMigrations(options, migrations) {
  const applied = readAppliedMigrationNames(options);
  const missing = findMissingMigrationNames(applied, migrations);
  if (missing.length > 0) {
    throw new Error(`D1 migrations were not recorded: ${missing.join(', ')}`);
  }
}

function findMissingMigrationNames(applied, migrations) {
  const missing = [];
  for (const migration of migrations) {
    if (!applied.has(migration.name)) {
      missing.push(migration.name);
    }
  }
  return missing;
}

function runWrangler(options, commandArgs) {
  const child = spawnWrangler(options, commandArgs, 'inherit');
  if (child.error) throw child.error;
  if (child.status !== 0) {
    throw new Error(`Wrangler D1 command failed with status ${String(child.status)}`);
  }
}

function runWranglerJson(options, commandArgs) {
  const child = spawnWrangler(options, [...commandArgs, '--json'], ['ignore', 'pipe', 'inherit']);
  if (child.error) throw child.error;
  if (child.status !== 0) {
    throw new Error(`Wrangler D1 JSON command failed with status ${String(child.status)}`);
  }
  try {
    return JSON.parse(child.stdout);
  } catch (error) {
    throw new Error(
      `Failed to parse Wrangler D1 JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function spawnWrangler(options, commandArgs, stdio) {
  return spawnSync(
    'pnpm',
    [
      'exec',
      'wrangler',
      'd1',
      'execute',
      options.database,
      '--remote',
      '--config',
      options.config,
      ...commandArgs,
    ],
    {
      cwd: process.cwd(),
      env: process.env,
      encoding: 'utf8',
      stdio,
    },
  );
}

function readSingleResultRows(output, label) {
  if (!Array.isArray(output) || output.length !== 1) {
    throw new Error(`D1 ${label} must return one result batch`);
  }
  const batch = output[0];
  if (!batch || typeof batch !== 'object' || batch.success !== true) {
    throw new Error(`D1 ${label} batch was not successful`);
  }
  if (!Array.isArray(batch.results)) {
    throw new Error(`D1 ${label} results must be an array`);
  }
  return batch.results;
}

function sqlText(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
