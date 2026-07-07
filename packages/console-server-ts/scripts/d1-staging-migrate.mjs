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
  d1StagingCommandLines,
  isDirectInvocation,
  normalizeConsoleRouterApiD1StagingOptions,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  relativeToRepo,
  requireSuccessfulCommandResult,
  sha256String,
  writeD1StagingManifest,
  wranglerCommand,
} from './d1-staging-config.mjs';
import { requireConsoleAndRouterApiD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-migrations');
const migrationModes = Object.freeze(['dry-run', 'remote']);

const migrationTargets = Object.freeze([
  Object.freeze({
    logicalName: 'console',
    profile: 'console',
    databaseName: 'seams-console-staging',
    configField: 'consoleConfigPath',
    migrationsDir: 'migrations/d1-console',
  }),
  Object.freeze({
    logicalName: 'signer',
    profile: 'router-api',
    databaseName: 'seams-signer-staging',
    configField: 'routerApiConfigPath',
    migrationsDir: '../sdk-server-ts/migrations/d1-signer',
  }),
]);

export function buildD1StagingMigrationPlan(input = {}) {
  const options = normalizeOptions(input);
  requireConsoleAndRouterApiD1StagingReadiness({
    label: 'migration apply',
    consoleConfigPath: options.consoleConfigPath,
    routerApiConfigPath: options.routerApiConfigPath,
    environmentName: options.environmentName,
  });

  const targets = [];
  const commands = [];
  for (const target of migrationTargets) {
    targets.push(inspectMigrationTarget(target));
    collectTargetCommands({
      commands,
      target,
      configPath: options[target.configField],
    });
  }

  return {
    version: 'seams_d1_staging_migration_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    environmentName: options.environmentName,
    consoleConfigPath: relativeToRepo(options.consoleConfigPath),
    routerApiConfigPath: relativeToRepo(options.routerApiConfigPath),
    targets,
    commands,
  };
}

export function runD1StagingMigration(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingMigrationPlan(options);
  const executed = [];

  if (options.mode === 'remote') {
    for (const step of plan.commands) {
      const result = requireSuccessfulCommandResult(step.command, options.commandRunner(step.command));
      executed.push({
        target: step.target,
        action: step.action,
        ...result,
      });
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
    const result = runD1StagingMigration(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging migration manifest', 'Dry run commands:', d1StagingCommandLines(result.manifest.commands));
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, d1StagingConfigManifestArgDefaults, d1StagingConfigManifestFlagFields);
}

function normalizeOptions(input) {
  return normalizeConsoleRouterApiD1StagingOptions(input, {
    modes: migrationModes,
    modeLabel: 'staging migration',
  });
}

function inspectMigrationTarget(target) {
  const migrationsPath = path.join(packageRoot, target.migrationsDir);
  if (!existsSync(migrationsPath)) {
    throw new Error(`${target.logicalName} migrations directory does not exist: ${target.migrationsDir}`);
  }
  const files = listMigrationFiles(migrationsPath);
  if (files.length === 0) {
    throw new Error(`${target.logicalName} migrations directory is empty: ${target.migrationsDir}`);
  }
  return {
    logicalName: target.logicalName,
    databaseName: target.databaseName,
    migrationsDir: target.migrationsDir,
    files,
  };
}

function listMigrationFiles(migrationsPath) {
  const entries = readdirSync(migrationsPath).sort();
  const files = [];
  for (const entry of entries) {
    if (!entry.endsWith('.sql')) continue;
    files.push(inspectMigrationFile(path.join(migrationsPath, entry)));
  }
  return files;
}

function inspectMigrationFile(filePath) {
  const source = readFileSync(filePath, 'utf8');
  return {
    file: path.basename(filePath),
    bytes: statSync(filePath).size,
    sha256: sha256String(source),
  };
}

function collectTargetCommands(input) {
  input.commands.push(
    migrationCommand({
      target: input.target,
      action: 'list_before',
      command: wranglerCommand(
        `d1 migrations list ${input.target.databaseName} --remote`,
        input.configPath,
      ),
    }),
  );
  input.commands.push(
    migrationCommand({
      target: input.target,
      action: 'apply',
      command: wranglerCommand(
        `d1 migrations apply ${input.target.databaseName} --remote`,
        input.configPath,
        { ci: true },
      ),
    }),
  );
  input.commands.push(
    migrationCommand({
      target: input.target,
      action: 'list_after',
      command: wranglerCommand(
        `d1 migrations list ${input.target.databaseName} --remote`,
        input.configPath,
      ),
    }),
  );
}

function migrationCommand(input) {
  return {
    target: input.target.logicalName,
    databaseName: input.target.databaseName,
    action: input.action,
    command: input.command,
  };
}

if (isDirectInvocation(import.meta.url)) main();
