import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  parseLocalConsoleOrganizationId,
  resolveLocalConsoleOrganizationId,
} from '../../../crates/router-ab-dev/scripts/local-console-identity.mjs';
import {
  ensureFriendlyD1DatabasePaths,
  resolveD1LocalFriendlyRoot,
  resolveD1LocalPersistRoot,
} from './d1-local-friendly-paths.mjs';

const packageRoot = fileURLToPath(new URL('../', import.meta.url));
const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

export function resolveD1LocalDevEnvFiles(input = {}) {
  const resolvedRepoRoot = input.repoRoot || repoRoot;
  const candidates = [path.join(resolvedRepoRoot, '.env.local')];
  const existing = [];
  for (const candidate of candidates) {
    if (existsSync(candidate)) existing.push(candidate);
  }
  return existing;
}

export function buildD1LocalDevWranglerArgs(input = {}) {
  const env = input.env || process.env;
  const config = env.SEAMS_D1_LOCAL_WRANGLER_CONFIG || 'wrangler.d1-local.toml';
  const persistTo = env.SEAMS_D1_LOCAL_PERSIST_TO || '.wrangler/state/seams-d1';
  const port = env.SEAMS_D1_LOCAL_PORT || '9090';
  const envFiles = input.envFiles || resolveD1LocalDevEnvFiles(input);
  const localConsoleOrganizationId = env.SEAMS_LOCAL_CONSOLE_ORG_ID
    ? parseLocalConsoleOrganizationId(env.SEAMS_LOCAL_CONSOLE_ORG_ID)
    : resolveLocalConsoleOrganizationId({ localEnvRoot: input.repoRoot || repoRoot });
  const args = [
    'dev',
    '--config',
    config,
    '--persist-to',
    persistTo,
    '--port',
    port,
    '--var',
    `SEAMS_LOCAL_CONSOLE_ORG_ID:${localConsoleOrganizationId}`,
  ];
  for (const envFile of envFiles) {
    args.push('--env-file', envFile);
  }
  return { args, envFiles, localConsoleOrganizationId };
}

export function runD1LocalDev(input = {}) {
  const resolvedPackageRoot = input.packageRoot || packageRoot;
  const env = input.env || process.env;
  const linkedDatabases = ensureFriendlyD1DatabasePaths({
    packageRoot: resolvedPackageRoot,
    repoRoot: input.repoRoot || repoRoot,
    env,
    persistRoot: resolveD1LocalPersistRoot({
      packageRoot: resolvedPackageRoot,
      env,
    }),
    friendlyRoot: resolveD1LocalFriendlyRoot({
      repoRoot: input.repoRoot || repoRoot,
      env,
    }),
  });
  printFriendlyPaths(linkedDatabases);
  const { args, envFiles } = buildD1LocalDevWranglerArgs({
    ...input,
    packageRoot: resolvedPackageRoot,
  });
  if (envFiles.length === 0) {
    console.warn('[d1-local] No root .env.local file found; local secrets are not configured.');
  } else {
    printEnvFiles(envFiles);
  }
  const child = spawn('wrangler', args, {
    cwd: resolvedPackageRoot,
    env,
    stdio: 'inherit',
  });
  child.once('error', handleSpawnError);
  child.once('exit', handleSpawnExit);
  return child;
}

function printFriendlyPaths(linkedDatabases) {
  for (const database of linkedDatabases) {
    console.log(`[d1-local] ${database.databaseName}: ${database.friendlyPath}`);
  }
}

function printEnvFiles(envFiles) {
  for (const envFile of envFiles) {
    console.log(`[d1-local] Loading local env file ${path.relative(repoRoot, envFile)}`);
  }
}

function handleSpawnError(error) {
  console.error(`[d1-local] Failed to start Wrangler: ${error.message}`);
  process.exit(1);
}

function handleSpawnExit(code, signal) {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
}

function isMainModule() {
  return process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
}

if (isMainModule()) {
  runD1LocalDev();
}
