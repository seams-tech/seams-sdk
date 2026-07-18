#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import {
  d1TimeTravelBookmarkValue,
  d1StagingConfigManifestArgDefaults,
  d1StagingConfigManifestFlagFields,
  isDirectInvocation,
  compactIsoStamp,
  normalizeConsoleGatewayD1StagingOptions,
  normalizeOptionalIso,
  normalizeString,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  relativeToRepo,
  requireSuccessfulCommandResult,
  shellArg,
  writeD1StagingManifest,
  wranglerCommand,
} from './d1-staging-config.mjs';
import { requireConsoleAndGatewayD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultBookmarkRoot = path.join(packageRoot, '.wrangler/d1-staging-bookmarks');
const bookmarkModes = Object.freeze(['dry-run', 'remote']);
const purposePattern = /^[a-z][a-z0-9_]{2,63}$/;

export function buildD1StagingTimeTravelBookmarkPlan(input = {}) {
  const options = normalizeOptions(input);
  requireConsoleAndGatewayD1StagingReadiness({
    label: 'Time Travel bookmark capture',
    consoleConfigPath: options.consoleConfigPath,
    gatewayConfigPath: options.gatewayConfigPath,
    environmentName: options.environmentName,
  });
  const paths = bookmarkPaths(options);
  return {
    version: 'seams_d1_staging_time_travel_bookmark_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    purpose: options.purpose,
    timestampIso: options.timestampIso,
    stamp: options.stamp,
    consoleConfigPath: relativeToRepo(options.consoleConfigPath),
    gatewayConfigPath: relativeToRepo(options.gatewayConfigPath),
    artifacts: {
      bookmarkDir: paths.bookmarkDir,
      consoleBookmarkPath: paths.consoleBookmarkPath,
      signerBookmarkPath: paths.signerBookmarkPath,
    },
    commands: bookmarkCommands({
      options,
      paths,
    }),
  };
}

export function runD1StagingTimeTravelBookmark(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingTimeTravelBookmarkPlan(options);
  const executed = [];
  let bookmarkEvidence = [];

  if (options.mode === 'remote') {
    mkdirSync(path.join(packageRoot, plan.artifacts.bookmarkDir), { recursive: true });
    for (const command of plan.commands) {
      executed.push(requireSuccessfulCommandResult(command, options.commandRunner(command)));
    }
    bookmarkEvidence = collectBookmarkEvidence(plan);
  }

  const manifest = {
    ...plan,
    executed,
    bookmarkEvidence,
  };
  return writeD1StagingManifest(
    options,
    defaultBookmarkRoot,
    manifest,
    `${options.stamp}/${options.purpose}.manifest.json`,
  );
}

function main() {
  try {
    const result = runD1StagingTimeTravelBookmark(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging Time Travel bookmark manifest', 'Dry run commands:', result.manifest.commands);
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    ...d1StagingConfigManifestArgDefaults,
    purpose: '',
    timestampIso: '',
  }, {
    ...d1StagingConfigManifestFlagFields,
    '--purpose': 'purpose',
    '--timestamp': 'timestampIso',
  });
}

function normalizeOptions(input) {
  const base = normalizeConsoleGatewayD1StagingOptions(input, {
    modes: bookmarkModes,
    modeLabel: 'Time Travel bookmark',
  });
  const timestampIso = normalizeOptionalIso(input.timestampIso, '--timestamp') || base.generatedAtIso;
  return {
    ...base,
    purpose: normalizePurpose(input.purpose),
    timestampIso,
    stamp: compactIsoStamp(base.generatedAtIso),
  };
}

function normalizePurpose(input) {
  const value = normalizeString(input);
  if (!value) throw new Error('--purpose is required');
  if (!purposePattern.test(value)) {
    throw new Error('--purpose must be lower_snake_case with 3 to 64 characters');
  }
  return value;
}

function bookmarkPaths(options) {
  const bookmarkDir = `.wrangler/d1-staging-bookmarks/${options.stamp}`;
  return {
    bookmarkDir,
    consoleBookmarkPath: `${bookmarkDir}/console-${options.purpose}.json`,
    signerBookmarkPath: `${bookmarkDir}/signer-${options.purpose}.json`,
  };
}

function bookmarkCommands(input) {
  return [
    [
      wranglerCommand(
        `d1 time-travel info seams-console-staging --timestamp ${shellArg(
          input.options.timestampIso,
        )} --json`,
        input.options.consoleConfigPath,
      ),
      '>',
      shellArg(input.paths.consoleBookmarkPath),
    ].join(' '),
    [
      wranglerCommand(
        `d1 time-travel info seams-signer-staging --timestamp ${shellArg(
          input.options.timestampIso,
        )} --json`,
        input.options.gatewayConfigPath,
      ),
      '>',
      shellArg(input.paths.signerBookmarkPath),
    ].join(' '),
  ];
}

function collectBookmarkEvidence(plan) {
  return [
    bookmarkEvidence({
      logicalName: 'console',
      path: plan.artifacts.consoleBookmarkPath,
    }),
    bookmarkEvidence({
      logicalName: 'signer',
      path: plan.artifacts.signerBookmarkPath,
    }),
  ];
}

function bookmarkEvidence(input) {
  const absolutePath = path.join(packageRoot, input.path);
  if (!existsSync(absolutePath)) {
    throw new Error(`Time Travel bookmark artifact missing: ${input.path}`);
  }
  const parsed = parseBookmarkJson(readFileSync(absolutePath, 'utf8'), input.path);
  return {
    logicalName: input.logicalName,
    path: input.path,
    json: parsed,
  };
}

function parseBookmarkJson(source, label) {
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error(`Time Travel bookmark JSON is invalid: ${label}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Time Travel bookmark JSON must be an object: ${label}`);
  }
  if (!d1TimeTravelBookmarkValue(parsed)) {
    throw new Error(`Time Travel bookmark JSON must include a usable bookmark: ${label}`);
  }
  return parsed;
}

if (isDirectInvocation(import.meta.url)) main();
