#!/usr/bin/env node
import path from 'node:path';

import {
  d1StagingConfigManifestArgDefaults,
  d1StagingConfigManifestFlagFields,
  d1StagingCommandLines,
  isDirectInvocation,
  arrayTableBodies,
  commaList,
  normalizeConsoleRouterApiD1StagingOptions,
  normalizeString,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  readArray,
  readSelectedWranglerConfig,
  readString,
  relativeToRepo,
  requireSuccessfulCommandResult,
  rootBody,
  tableBody,
  writeD1StagingManifest,
  wranglerCommand,
} from './d1-staging-config.mjs';
import { requireConsoleAndRouterApiD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-resource-inventory');
const inventoryModes = Object.freeze(['dry-run', 'remote']);

export function buildD1StagingResourceInventoryPlan(input = {}) {
  const options = normalizeOptions(input);
  requireConsoleAndRouterApiD1StagingReadiness({
    label: 'resource inventory',
    consoleConfigPath: options.consoleConfigPath,
    routerApiConfigPath: options.routerApiConfigPath,
    environmentName: options.environmentName,
  });
  const consoleConfig = readProfileInventory({
    profile: 'console',
    configPath: options.consoleConfigPath,
    environmentName: options.environmentName,
  });
  const routerApiConfig = readProfileInventory({
    profile: 'router-api',
    configPath: options.routerApiConfigPath,
    environmentName: options.environmentName,
  });
  const commands = inventoryCommands({
    consoleConfigPath: options.consoleConfigPath,
    routerApiConfigPath: options.routerApiConfigPath,
  });

  return {
    version: 'seams_d1_staging_resource_inventory_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    environmentName: options.environmentName,
    consoleConfigPath: relativeToRepo(options.consoleConfigPath),
    routerApiConfigPath: relativeToRepo(options.routerApiConfigPath),
    resources: {
      consoleWorker: consoleConfig,
      routerApiWorker: routerApiConfig,
    },
    commands,
  };
}

export function runD1StagingResourceInventory(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingResourceInventoryPlan(options);
  const checks = [];

  if (options.mode === 'remote') {
    for (const command of plan.commands) {
      const result = requireSuccessfulCommandResult(
        command.command,
        options.commandRunner(command.command),
      );
      checks.push({
        id: command.id,
        target: command.target,
        command: result.command,
        status: result.status,
        json: parseJsonOutput(result.stdout, command.id),
        stderr: result.stderr,
      });
    }
  }

  const manifest = {
    ...plan,
    checks,
  };
  return writeD1StagingManifest(options, defaultManifestRoot, manifest);
}

function main() {
  try {
    const result = runD1StagingResourceInventory(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging resource inventory manifest', 'Dry run commands:', d1StagingCommandLines(result.manifest.commands));
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, d1StagingConfigManifestArgDefaults, d1StagingConfigManifestFlagFields);
}

function normalizeOptions(input) {
  return normalizeConsoleRouterApiD1StagingOptions(input, {
    modes: inventoryModes,
    modeLabel: 'staging resource inventory',
  });
}

function readProfileInventory(input) {
  const source = readSelectedWranglerConfig({
    configPath: input.configPath,
    environmentName: input.environmentName,
    label: `${input.profile} profile`,
  });
  const root = rootBody(source);
  return {
    name: readString(root, 'name'),
    main: readString(root, 'main'),
    compatibilityDate: readString(root, 'compatibility_date'),
    d1Databases: readD1Databases(source),
    durableObjects: readDurableObjectBindings(source),
    durableObjectMigrations: readDurableObjectMigrations(source),
    secretsStoreSecrets: readSecretsStoreSecrets(source),
    requiredSecrets: readArray(tableBody(source, 'secrets'), 'required'),
    stagingVars: readStagingVars(source),
  };
}

function readD1Databases(source) {
  const databases = [];
  for (const block of arrayTableBodies(source, 'd1_databases')) {
    databases.push({
      binding: readString(block, 'binding'),
      databaseName: readString(block, 'database_name'),
      databaseId: readString(block, 'database_id'),
      migrationsDir: readString(block, 'migrations_dir'),
    });
  }
  return databases;
}

function readDurableObjectBindings(source) {
  const bindings = [];
  for (const block of arrayTableBodies(source, 'durable_objects.bindings')) {
    bindings.push({
      name: readString(block, 'name'),
      className: readString(block, 'class_name'),
    });
  }
  return bindings;
}

function readDurableObjectMigrations(source) {
  const migrations = [];
  for (const block of arrayTableBodies(source, 'migrations')) {
    migrations.push({
      tag: readString(block, 'tag'),
      newSqliteClasses: readArray(block, 'new_sqlite_classes'),
    });
  }
  return migrations;
}

function readSecretsStoreSecrets(source) {
  const secrets = [];
  for (const block of arrayTableBodies(source, 'secrets_store_secrets')) {
    secrets.push({
      binding: readString(block, 'binding'),
      storeId: readString(block, 'store_id'),
      secretName: readString(block, 'secret_name'),
    });
  }
  return secrets;
}

function readStagingVars(source) {
  const vars = tableBody(source, 'vars');
  return {
    namespace: readString(vars, 'SEAMS_TENANT_STORAGE_NAMESPACE'),
    orgId: readString(vars, 'SEAMS_STAGING_ORG_ID'),
    projectId: readString(vars, 'SEAMS_STAGING_PROJECT_ID'),
    envId: readString(vars, 'SEAMS_STAGING_ENV_ID'),
    signingRootKekProvider: readString(vars, 'SIGNING_ROOT_KEK_PROVIDER'),
    signingRootKekIds: commaList(readString(vars, 'SIGNING_ROOT_KEK_IDS')),
  };
}

function inventoryCommands(input) {
  return [
    inventoryCommand({
      id: 'console_d1_info',
      target: 'console_d1',
      command: wranglerCommand(
        'd1 info seams-console-staging --json',
        input.consoleConfigPath,
      ),
    }),
    inventoryCommand({
      id: 'signer_d1_info',
      target: 'signer_d1',
      command: wranglerCommand(
        'd1 info seams-signer-staging --json',
        input.routerApiConfigPath,
      ),
    }),
    inventoryCommand({
      id: 'console_worker_deployment_status',
      target: 'console_worker',
      command: wranglerCommand('deployments status --json', input.consoleConfigPath),
    }),
    inventoryCommand({
      id: 'router_api_worker_deployment_status',
      target: 'router_api_worker',
      command: wranglerCommand('deployments status --json', input.routerApiConfigPath),
    }),
  ];
}

function inventoryCommand(input) {
  return {
    id: input.id,
    target: input.target,
    command: input.command,
  };
}

function parseJsonOutput(stdout, commandId) {
  const source = normalizeString(stdout);
  if (!source) throw new Error(`${commandId} returned empty Wrangler JSON output`);
  try {
    return JSON.parse(source);
  } catch {
    throw new Error(`${commandId} returned non-JSON Wrangler output`);
  }
}

if (isDirectInvocation(import.meta.url)) main();
