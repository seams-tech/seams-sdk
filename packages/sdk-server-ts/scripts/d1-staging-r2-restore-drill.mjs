#!/usr/bin/env node
import { existsSync, mkdirSync, statSync } from 'node:fs';
import path from 'node:path';

import {
  d1IntegrityCheckValues,
  d1StagingConfigManifestArgDefaults,
  d1StagingConfigManifestFlagFields,
  isDirectInvocation,
  compactIsoStamp,
  normalizeConsoleRouterApiD1StagingOptions,
  normalizeString,
  normalizeR2BucketName,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  relativeToRepo,
  requireSuccessfulCommandResult,
  sha256File,
  shellArg,
  writeD1StagingManifest,
  wranglerCommand,
  wranglerR2Command,
} from './d1-staging-config.mjs';
import { requireConsoleAndRouterApiD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-r2-restore-drills');
const drillModes = Object.freeze(['dry-run', 'remote']);

export function buildD1StagingR2RestoreDrillPlan(input = {}) {
  const options = normalizeOptions(input);
  requireConsoleAndRouterApiD1StagingReadiness({
    label: 'R2 restore drill',
    consoleConfigPath: options.consoleConfigPath,
    routerApiConfigPath: options.routerApiConfigPath,
    environmentName: options.environmentName,
  });
  const paths = drillPaths(options);
  return {
    version: 'seams_d1_staging_r2_restore_drill_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    r2Bucket: options.r2Bucket,
    stamp: options.stamp,
    consoleConfigPath: relativeToRepo(options.consoleConfigPath),
    routerApiConfigPath: relativeToRepo(options.routerApiConfigPath),
    artifacts: drillArtifacts(paths),
    commands: drillCommands({
      options,
      paths,
    }),
  };
}

export function runD1StagingR2RestoreDrill(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingR2RestoreDrillPlan(options);
  const executed = [];
  let artifactEvidence = [];

  if (options.mode === 'remote') {
    mkdirSync(path.join(packageRoot, plan.artifacts.exportDir), { recursive: true });
    mkdirSync(path.join(packageRoot, plan.artifacts.restoreDir), { recursive: true });
    for (const command of plan.commands) {
      const result = requireSuccessfulCommandResult(command, options.commandRunner(command));
      assertIntegrityCheckResult(command, result);
      executed.push(result);
    }
    artifactEvidence = collectArtifactEvidence(plan);
  }

  const manifest = {
    ...plan,
    executed,
    artifactEvidence,
  };
  return writeD1StagingManifest(options, defaultManifestRoot, manifest, `${options.stamp}.json`);
}

function main() {
  try {
    const result = runD1StagingR2RestoreDrill(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging R2 restore drill manifest', 'Dry run commands:', result.manifest.commands);
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    ...d1StagingConfigManifestArgDefaults,
    r2Bucket: '',
  }, {
    ...d1StagingConfigManifestFlagFields,
    '--r2-bucket': 'r2Bucket',
  });
}

function normalizeOptions(input) {
  const base = normalizeConsoleRouterApiD1StagingOptions(input, {
    modes: drillModes,
    modeLabel: 'R2 restore drill',
  });
  return {
    ...base,
    r2Bucket: normalizeR2BucketName(input.r2Bucket),
    stamp: compactIsoStamp(base.generatedAtIso),
  };
}

function drillPaths(options) {
  const exportDir = `.wrangler/d1-staging-exports/${options.stamp}`;
  const restoreDir = `.wrangler/d1-staging-restore-drills/${options.stamp}`;
  return {
    exportDir,
    restoreDir,
    consoleExportPath: `${exportDir}/seams-console-staging.sql`,
    signerExportPath: `${exportDir}/seams-signer-staging.sql`,
    consoleRestorePath: `${restoreDir}/seams-console-staging.sql`,
    signerRestorePath: `${restoreDir}/seams-signer-staging.sql`,
    consoleObjectPath: `${options.r2Bucket}/refactor-82/${options.stamp}/seams-console-staging.sql`,
    signerObjectPath: `${options.r2Bucket}/refactor-82/${options.stamp}/seams-signer-staging.sql`,
    consoleRestoreDatabaseName: `seams-console-staging-restore-drill-${options.stamp.toLowerCase()}`,
    signerRestoreDatabaseName: `seams-signer-staging-restore-drill-${options.stamp.toLowerCase()}`,
  };
}

function drillArtifacts(paths) {
  return {
    exportDir: paths.exportDir,
    restoreDir: paths.restoreDir,
    consoleExportPath: paths.consoleExportPath,
    signerExportPath: paths.signerExportPath,
    consoleRestorePath: paths.consoleRestorePath,
    signerRestorePath: paths.signerRestorePath,
    consoleObjectPath: paths.consoleObjectPath,
    signerObjectPath: paths.signerObjectPath,
    consoleRestoreDatabaseName: paths.consoleRestoreDatabaseName,
    signerRestoreDatabaseName: paths.signerRestoreDatabaseName,
  };
}

function drillCommands(input) {
  return [
    wranglerCommand(
      `d1 export seams-console-staging --remote --output ${shellArg(input.paths.consoleExportPath)}`,
      input.options.consoleConfigPath,
    ),
    wranglerCommand(
      `d1 export seams-signer-staging --remote --output ${shellArg(input.paths.signerExportPath)}`,
      input.options.routerApiConfigPath,
    ),
    wranglerR2Command(
      `object put ${shellArg(input.paths.consoleObjectPath)} --remote --file ${shellArg(
        input.paths.consoleExportPath,
      )}`,
      input.options.routerApiConfigPath,
    ),
    wranglerR2Command(
      `object put ${shellArg(input.paths.signerObjectPath)} --remote --file ${shellArg(
        input.paths.signerExportPath,
      )}`,
      input.options.routerApiConfigPath,
    ),
    wranglerR2Command(
      `object get ${shellArg(input.paths.consoleObjectPath)} --remote --file ${shellArg(
        input.paths.consoleRestorePath,
      )}`,
      input.options.routerApiConfigPath,
    ),
    wranglerR2Command(
      `object get ${shellArg(input.paths.signerObjectPath)} --remote --file ${shellArg(
        input.paths.signerRestorePath,
      )}`,
      input.options.routerApiConfigPath,
    ),
    wranglerCommand(
      `d1 create ${shellArg(input.paths.consoleRestoreDatabaseName)}`,
      input.options.consoleConfigPath,
    ),
    wranglerCommand(
      `d1 create ${shellArg(input.paths.signerRestoreDatabaseName)}`,
      input.options.routerApiConfigPath,
    ),
    wranglerCommand(
      `d1 execute ${shellArg(input.paths.consoleRestoreDatabaseName)} --remote --yes --file ${shellArg(
        input.paths.consoleRestorePath,
      )}`,
      input.options.consoleConfigPath,
    ),
    wranglerCommand(
      `d1 execute ${shellArg(input.paths.signerRestoreDatabaseName)} --remote --yes --file ${shellArg(
        input.paths.signerRestorePath,
      )}`,
      input.options.routerApiConfigPath,
    ),
    wranglerCommand(
      `d1 execute ${shellArg(
        input.paths.consoleRestoreDatabaseName,
      )} --remote --json --command "PRAGMA integrity_check;"`,
      input.options.consoleConfigPath,
    ),
    wranglerCommand(
      `d1 execute ${shellArg(
        input.paths.signerRestoreDatabaseName,
      )} --remote --json --command "PRAGMA integrity_check;"`,
      input.options.routerApiConfigPath,
    ),
  ];
}

function collectArtifactEvidence(plan) {
  return [
    fileEvidence(plan.artifacts.consoleExportPath),
    fileEvidence(plan.artifacts.signerExportPath),
    fileEvidence(plan.artifacts.consoleRestorePath),
    fileEvidence(plan.artifacts.signerRestorePath),
  ];
}

function fileEvidence(relativePath) {
  const absolutePath = path.join(packageRoot, relativePath);
  if (!existsSync(absolutePath)) {
    throw new Error(`R2 restore drill artifact missing: ${relativePath}`);
  }
  return {
    path: relativePath,
    bytes: statSync(absolutePath).size,
    sha256: sha256File(absolutePath),
  };
}

function assertIntegrityCheckResult(command, result) {
  if (!isIntegrityCheckCommand(command)) return;
  const source = normalizeString(result.stdout);
  if (!source) {
    throw new Error(`R2 restore drill integrity_check returned empty Wrangler JSON output`);
  }
  const values = d1IntegrityCheckValues(parseIntegrityCheckJson(source));
  if (values.length === 0) {
    throw new Error(`R2 restore drill integrity_check output did not include an integrity_check result`);
  }
  for (const value of values) {
    if (value === 'ok') continue;
    throw new Error(`R2 restore drill integrity_check is ${value}, expected ok`);
  }
}

function isIntegrityCheckCommand(command) {
  return normalizeString(command).includes('PRAGMA integrity_check');
}

function parseIntegrityCheckJson(source) {
  try {
    return JSON.parse(source);
  } catch {
    throw new Error('R2 restore drill integrity_check returned non-JSON Wrangler output');
  }
}

if (isDirectInvocation(import.meta.url)) main();
