import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const packageRoot = fileURLToPath(new URL('../', import.meta.url));
const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

export function resolveD1LocalDevEnvFiles(input = {}) {
  const resolvedPackageRoot = input.packageRoot || packageRoot;
  const resolvedRepoRoot = input.repoRoot || repoRoot;
  const candidates = [
    path.join(resolvedRepoRoot, 'packages/sdk-server-ts/.dev.vars'),
    path.join(resolvedPackageRoot, '.dev.vars'),
  ];
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
  const args = ['dev', '--config', config, '--persist-to', persistTo, '--port', port];
  for (const envFile of envFiles) {
    args.push('--env-file', envFile);
  }
  return { args, envFiles };
}

export function runD1LocalDev(input = {}) {
  const resolvedPackageRoot = input.packageRoot || packageRoot;
  const { args, envFiles } = buildD1LocalDevWranglerArgs({
    ...input,
    packageRoot: resolvedPackageRoot,
  });
  if (envFiles.length === 0) {
    console.warn(
      '[d1-local] No .dev.vars file found; private relayer-key routes will report not_configured.',
    );
  } else {
    printEnvFiles(envFiles);
  }
  const child = spawn('wrangler', args, {
    cwd: resolvedPackageRoot,
    env: input.env || process.env,
    stdio: 'inherit',
  });
  child.once('error', handleSpawnError);
  child.once('exit', handleSpawnExit);
  return child;
}

function printEnvFiles(envFiles) {
  for (const envFile of envFiles) {
    console.log(`[d1-local] Loading Wrangler env file ${path.relative(repoRoot, envFile)}`);
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
