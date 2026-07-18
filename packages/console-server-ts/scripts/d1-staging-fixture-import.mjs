#!/usr/bin/env node
import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
} from 'node:fs';
import path from 'node:path';

import {
  d1StagingConfigManifestArgDefaults,
  d1StagingConfigManifestFlagFields,
  isDirectInvocation,
  normalizeConsoleGatewayD1StagingOptions,
  normalizeString,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  relativeToPackage,
  relativeToRepo,
  requireSuccessfulCommandResult,
  resolveRequiredPackagePath,
  sha256String,
  shellArg,
  writeD1StagingManifest,
  wranglerCommand,
} from './d1-staging-config.mjs';
import { requireConsoleAndGatewayD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-fixture-imports');
const importModes = Object.freeze(['dry-run', 'remote']);

const fixtureTargets = Object.freeze([
  Object.freeze({
    logicalName: 'console',
    tableFamily: 'console',
    profile: 'console',
    databaseName: 'seams-console-staging',
    configField: 'consoleConfigPath',
    fixtureField: 'consoleFixturePath',
    allowedTableNames: readD1MigrationTableNames('migrations/d1-console'),
  }),
  Object.freeze({
    logicalName: 'signer',
    tableFamily: 'signer',
    profile: 'gateway',
    databaseName: 'seams-signer-staging',
    configField: 'gatewayConfigPath',
    fixtureField: 'signerFixturePath',
    allowedTableNames: readD1MigrationTableNames('../sdk-server-ts/migrations/d1-signer'),
  }),
]);

export function buildD1StagingFixtureImportPlan(input = {}) {
  const options = normalizeOptions(input);
  requireConsoleAndGatewayD1StagingReadiness({
    label: 'fixture import',
    consoleConfigPath: options.consoleConfigPath,
    gatewayConfigPath: options.gatewayConfigPath,
    environmentName: options.environmentName,
  });

  const fixtures = [];
  const commands = [];
  for (const target of fixtureTargets) {
    const fixture = inspectFixture({
      target,
      fixturePath: options[target.fixtureField],
    });
    fixtures.push(fixture);
    commands.push(
      wranglerCommand(
        [
          'd1 execute',
          target.databaseName,
          '--remote',
          '--yes',
          '--file',
          shellArg(relativeToPackage(fixture.path)),
        ].join(' '),
        options[target.configField],
      ),
    );
  }

  return {
    version: 'seams_d1_staging_fixture_import_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    environmentName: options.environmentName,
    consoleConfigPath: relativeToRepo(options.consoleConfigPath),
    gatewayConfigPath: relativeToRepo(options.gatewayConfigPath),
    fixtures,
    commands,
  };
}

export function runD1StagingFixtureImport(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingFixtureImportPlan(options);
  const executed = [];

  if (options.mode === 'remote') {
    for (const command of plan.commands) {
      executed.push(requireSuccessfulCommandResult(command, options.commandRunner(command)));
    }
  }

  const manifest = {
    ...plan,
    executed,
  };
  return writeD1StagingManifest(options, defaultManifestRoot, manifest);
}

function main() {
  try {
    const result = runD1StagingFixtureImport(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging fixture import manifest', 'Dry run commands:', result.manifest.commands);
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    ...d1StagingConfigManifestArgDefaults,
    consoleFixturePath: '',
    signerFixturePath: '',
  }, {
    ...d1StagingConfigManifestFlagFields,
    '--console-fixture': 'consoleFixturePath',
    '--signer-fixture': 'signerFixturePath',
  });
}

function normalizeOptions(input) {
  return {
    ...normalizeConsoleGatewayD1StagingOptions(input, {
      modes: importModes,
      modeLabel: 'fixture import',
    }),
    consoleFixturePath: resolveRequiredPackagePath(input.consoleFixturePath, '--console-fixture'),
    signerFixturePath: resolveRequiredPackagePath(input.signerFixturePath, '--signer-fixture'),
  };
}

function inspectFixture(input) {
  const filePath = input.fixturePath;
  if (!existsSync(filePath)) {
    throw new Error(`${input.target.logicalName} fixture does not exist: ${relativeToRepo(filePath)}`);
  }
  const source = readFileSync(filePath, 'utf8');
  const touchedTables = validateFixtureSql({
    source,
    allowedTableNames: input.target.allowedTableNames,
    label: `${input.target.logicalName} fixture`,
    tableFamily: input.target.tableFamily,
  });
  return {
    logicalName: input.target.logicalName,
    path: filePath,
    relativePath: relativeToRepo(filePath),
    bytes: statSync(filePath).size,
    sha256: sha256String(source),
    tableFamily: input.target.tableFamily,
    touchedTables,
  };
}

function validateFixtureSql(input) {
  const sql = stripSqlComments(input.source);
  const errors = [];
  const touchedTables = collectTouchedTables(sql);
  if (!sql.trim()) errors.push(`${input.label} is empty`);
  checkForbiddenSql(sql, input.label, errors);
  checkTouchedTables({
    allowedTableNames: input.allowedTableNames,
    errors,
    label: input.label,
    tableFamily: input.tableFamily,
    tableNames: touchedTables,
  });
  if (errors.length > 0) throw new Error(errors.join('\n'));
  return touchedTables;
}

function checkForbiddenSql(sql, label, errors) {
  const schemaSql = stripSingleQuotedStringLiterals(sql);
  const forbiddenPatterns = [
    ['schema DDL', /\b(?:CREATE|ALTER|DROP|TRUNCATE|REINDEX|VACUUM|ATTACH|DETACH)\b/i, schemaSql],
    ['D1 migration table writes', /\bd1_migrations\b/i, schemaSql],
    ['SQLite internal schema writes', /\bsqlite_(?:master|schema|sequence)\b/i, schemaSql],
    ['Cloudflare internal table writes', /\b_cf_/i, schemaSql],
    ['writable schema changes', /\bPRAGMA\s+writable_schema\b/i, schemaSql],
    ['PEM private key material', /-----BEGIN [A-Z ]*PRIVATE KEY-----/i, sql],
    ['local plaintext KEK variables', /\bSEAMS_LOCAL_SIGNING_ROOT_KEK_B64U\b/i, sql],
  ];
  for (const pattern of forbiddenPatterns) {
    if (pattern[1].test(pattern[2])) errors.push(`${label} contains ${pattern[0]}`);
  }
}

function checkTouchedTables(input) {
  if (input.tableNames.length === 0) {
    input.errors.push(`${input.label} must contain INSERT, UPDATE, or DELETE statements`);
    return;
  }
  for (const tableName of input.tableNames) {
    if (input.allowedTableNames.includes(tableName)) continue;
    input.errors.push(`${input.label} touches ${tableName}; expected ${input.tableFamily} D1 tables only`);
  }
}

function readD1MigrationTableNames(relativeDir) {
  const migrationDir = path.join(packageRoot, relativeDir);
  const tableNames = new Set();
  for (const entry of readdirSync(migrationDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.sql')) continue;
    const source = readFileSync(path.join(migrationDir, entry.name), 'utf8');
    collectMigrationCreatedTables(source, tableNames);
  }
  return Object.freeze([...tableNames].filter(isFixtureImportTable).sort());
}

function collectMigrationCreatedTables(source, tableNames) {
  const pattern = /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/gi;
  let match = pattern.exec(source);
  while (match) {
    const tableName = normalizeString(match[1]);
    if (tableName) tableNames.add(tableName);
    match = pattern.exec(source);
  }
}

function isFixtureImportTable(tableName) {
  if (tableName.endsWith('_constraints')) return false;
  if (tableName.endsWith('_saved')) return false;
  if (tableName.endsWith('_required_idempotency')) return false;
  return true;
}

function collectTouchedTables(sql) {
  const tableNames = [];
  collectRegexTables({
    sql,
    tableNames,
    pattern: /\bINSERT\s+(?:OR\s+[A-Z]+\s+)?INTO\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/gi,
  });
  collectRegexTables({
    sql,
    tableNames,
    pattern: /\bUPDATE\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/gi,
  });
  collectRegexTables({
    sql,
    tableNames,
    pattern: /\bDELETE\s+FROM\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?/gi,
  });
  return tableNames;
}

function collectRegexTables(input) {
  let match = input.pattern.exec(input.sql);
  while (match) {
    const tableName = normalizeString(match[1]);
    if (tableName && !input.tableNames.includes(tableName)) input.tableNames.push(tableName);
    match = input.pattern.exec(input.sql);
  }
}

function stripSqlComments(source) {
  let output = '';
  let quote = '';
  let blockComment = false;
  let lineComment = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index] || '';
    const next = source[index + 1] || '';
    if (lineComment) {
      if (char === '\n') {
        lineComment = false;
        output += '\n';
      }
      continue;
    }
    if (blockComment) {
      if (char === '*' && next === '/') {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      output += char;
      if (char === quote && next === quote) {
        output += next;
        index += 1;
        continue;
      }
      if (char === quote) quote = '';
      continue;
    }
    if (char === '-' && next === '-') {
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === '/' && next === '*') {
      blockComment = true;
      index += 1;
      continue;
    }
    if (char === "'" || char === '"') quote = char;
    output += char;
  }
  return output;
}

function stripSingleQuotedStringLiterals(source) {
  let output = '';
  let singleQuote = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index] || '';
    const next = source[index + 1] || '';
    if (singleQuote) {
      output += ' ';
      if (char === "'" && next === "'") {
        output += ' ';
        index += 1;
        continue;
      }
      if (char === "'") singleQuote = false;
      continue;
    }
    if (char === "'") {
      singleQuote = true;
      output += ' ';
      continue;
    }
    output += char;
  }
  return output;
}

if (isDirectInvocation(import.meta.url)) main();
