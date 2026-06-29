import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

import {
  isJsonRecord,
  packageRoot,
  parseFlagArgs,
  relativeToPackage,
  runCommandArgs,
  sha256File,
  sqlString,
  writeJsonManifest,
} from './d1-staging-config.mjs';

const persistRoot = path.join(packageRoot, '.wrangler/state/seams-d1');
const d1ObjectRoot = path.join(persistRoot, 'v3/d1/miniflare-D1DatabaseObject');
const drillRoot = path.join(packageRoot, '.wrangler/d1-local-restore-drills');

const expectedDatabases = Object.freeze([
  Object.freeze({
    logicalName: 'console',
    d1Name: 'seams-console',
    markerTable: 'organizations',
    expectedUserTableCount: 40,
  }),
  Object.freeze({
    logicalName: 'signer',
    d1Name: 'seams-signer',
    markerTable: 'wallets',
    expectedUserTableCount: 21,
  }),
]);

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.skipPrepare) runPackageScript('d1:local:prepare');

  const wranglerVersion = runCommandArgs('pnpm', ['exec', 'wrangler', '--version'], {
    cwd: packageRoot,
  }).stdout.trim();
  const sqliteVersion = runCommandArgs('sqlite3', ['--version'], { cwd: packageRoot }).stdout.trim();
  const outputDir = createDrillOutputDir(options);
  const databases = [];

  for (const expected of expectedDatabases) {
    const sourcePath = findLocalD1Database(expected);
    const result = drillDatabase({
      expected,
      sourcePath,
      outputDir,
    });
    databases.push(result);
  }

  const manifest = {
    version: 'seams_d1_local_restore_drill_v1',
    generatedAtIso: new Date().toISOString(),
    persistRoot: relativeToPackage(persistRoot),
    outputDir: relativeToPackage(outputDir),
    wranglerVersion,
    sqliteVersion,
    prepareRan: !options.skipPrepare,
    databases,
  };
  const manifestPath = path.join(outputDir, 'manifest.json');
  writeJsonManifest(manifestPath, manifest);
  console.log(`D1 local backup/restore drill passed: ${relativeToPackage(manifestPath)}`);
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    skipPrepare: false,
    outputDir: '',
  }, {
    '--skip-prepare': { kind: 'boolean', field: 'skipPrepare' },
    '--output-dir': {
      kind: 'string',
      field: 'outputDir',
      parse: resolveOutputDirArg,
    },
  });
}

function resolveOutputDirArg(value) {
  return path.resolve(packageRoot, value);
}

function runPackageScript(scriptName) {
  runCommandArgs('pnpm', ['run', scriptName], {
    cwd: packageRoot,
    input: null,
  });
}

function createDrillOutputDir(options) {
  const outputDir =
    options.outputDir ||
    path.join(drillRoot, new Date().toISOString().replace(/[:.]/g, '-'));
  rmSync(outputDir, { recursive: true, force: true });
  mkdirSync(outputDir, { recursive: true });
  return outputDir;
}

function findLocalD1Database(expected) {
  if (!existsSync(d1ObjectRoot)) {
    throw new Error(`Local D1 object directory does not exist: ${relativeToPackage(d1ObjectRoot)}`);
  }
  const matches = [];
  for (const fileName of readdirSync(d1ObjectRoot)) {
    if (!fileName.endsWith('.sqlite') || fileName === 'metadata.sqlite') continue;
    const candidate = path.join(d1ObjectRoot, fileName);
    if (sqliteTableExists(candidate, expected.markerTable)) matches.push(candidate);
  }
  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one local ${expected.d1Name} database with ${expected.markerTable}; found ${matches.length}`,
    );
  }
  return matches[0] || '';
}

function drillDatabase(input) {
  const databaseDir = path.join(input.outputDir, input.expected.logicalName);
  mkdirSync(databaseDir, { recursive: true });

  const backupPath = path.join(databaseDir, `${input.expected.d1Name}.sqlite`);
  const dumpPath = path.join(databaseDir, `${input.expected.d1Name}.sql`);
  const restoredPath = path.join(databaseDir, `${input.expected.d1Name}.restored.sqlite`);

  sqliteVacuumInto(input.sourcePath, backupPath);
  writeSqliteDump({
    sourcePath: backupPath,
    dumpPath,
  });
  restoreSqliteDump({
    dumpPath,
    restoredPath,
  });

  const sourceChecks = inspectSqliteDatabase(input.sourcePath);
  const backupChecks = inspectSqliteDatabase(backupPath);
  const restoreChecks = inspectSqliteDatabase(restoredPath);
  assertDatabaseChecks({
    label: `${input.expected.d1Name} source`,
    checks: sourceChecks,
    expected: input.expected,
  });
  assertDatabaseChecks({
    label: `${input.expected.d1Name} backup`,
    checks: backupChecks,
    expected: input.expected,
  });
  assertDatabaseChecks({
    label: `${input.expected.d1Name} restored`,
    checks: restoreChecks,
    expected: input.expected,
  });

  return {
    logicalName: input.expected.logicalName,
    d1Name: input.expected.d1Name,
    sourcePath: relativeToPackage(input.sourcePath),
    backupPath: relativeToPackage(backupPath),
    sqlDumpPath: relativeToPackage(dumpPath),
    restoredPath: relativeToPackage(restoredPath),
    backupSha256: sha256File(backupPath),
    sqlDumpSha256: sha256File(dumpPath),
    backupBytes: statSync(backupPath).size,
    sqlDumpBytes: statSync(dumpPath).size,
    source: sourceChecks,
    backup: backupChecks,
    restored: restoreChecks,
  };
}

function sqliteTableExists(databasePath, tableName) {
  const rows = sqliteJson(databasePath, [
    'SELECT name FROM sqlite_master WHERE type = ',
    sqlString('table'),
    ' AND name = ',
    sqlString(tableName),
    ' LIMIT 1;',
  ].join(''));
  return rows.length === 1;
}

function sqliteVacuumInto(sourcePath, backupPath) {
  rmSync(backupPath, { force: true });
  sqliteExec(sourcePath, `VACUUM INTO ${sqlString(backupPath)};`);
}

function writeSqliteDump(input) {
  const result = runCommandArgs('sqlite3', [input.sourcePath, '.dump'], {
    cwd: packageRoot,
    input: null,
  });
  writeFileSync(input.dumpPath, result.stdout);
}

function restoreSqliteDump(input) {
  rmSync(input.restoredPath, { force: true });
  runCommandArgs('sqlite3', [input.restoredPath], {
    cwd: packageRoot,
    input: readFileSync(input.dumpPath),
  });
}

function inspectSqliteDatabase(databasePath) {
  const integrityRows = sqliteJson(databasePath, 'PRAGMA integrity_check;');
  const integrityCheck = String(integrityRows[0]?.integrity_check || '');
  const userTableCount = sqliteInteger(
    databasePath,
    `SELECT COUNT(*) AS count
       FROM sqlite_master
      WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
        AND name NOT LIKE '_cf_%'
        AND name <> 'd1_migrations';`,
  );
  const migrationCount = sqliteInteger(
    databasePath,
    "SELECT COUNT(*) AS count FROM d1_migrations WHERE name IS NOT NULL;",
  );
  return {
    integrityCheck,
    userTableCount,
    migrationCount,
  };
}

function assertDatabaseChecks(input) {
  if (input.checks.integrityCheck !== 'ok') {
    throw new Error(`${input.label} integrity_check failed: ${input.checks.integrityCheck}`);
  }
  if (input.checks.userTableCount !== input.expected.expectedUserTableCount) {
    throw new Error(
      `${input.label} expected ${input.expected.expectedUserTableCount} user tables, got ${input.checks.userTableCount}`,
    );
  }
  if (input.checks.migrationCount <= 0) {
    throw new Error(`${input.label} has no recorded D1 migrations`);
  }
}

function sqliteInteger(databasePath, sql) {
  const rows = sqliteJson(databasePath, sql);
  const value = Number(rows[0]?.count);
  if (!Number.isSafeInteger(value)) {
    throw new Error(`Expected integer SQLite result for ${sql}`);
  }
  return value;
}

function sqliteJson(databasePath, sql) {
  const result = runCommandArgs('sqlite3', ['-json', databasePath, sql], {
    cwd: packageRoot,
    input: null,
  });
  const stdout = result.stdout.trim();
  if (!stdout) return [];
  const parsed = JSON.parse(stdout);
  if (!Array.isArray(parsed)) throw new Error(`sqlite3 JSON output was not an array: ${stdout}`);
  return parsed.filter(isJsonRecord);
}

function sqliteExec(databasePath, sql) {
  runCommandArgs('sqlite3', [databasePath, sql], {
    cwd: packageRoot,
    input: null,
  });
}

main();
