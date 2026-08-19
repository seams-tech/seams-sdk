#!/usr/bin/env node
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const localEnvPath = path.join(repoRoot, '.env.local');

// The root local env is the sole authority shared by the site and console seed.
dotenv.config({ path: localEnvPath, override: true });

const child = spawn(
  'pnpm',
  ['-C', 'apps/seams-site', 'vite', '--host', 'localhost', '--port', '3600'],
  {
    cwd: repoRoot,
    env: localSiteEnvironment(process.env),
    stdio: 'inherit',
  },
);

forwardSignal('SIGINT', child);
forwardSignal('SIGTERM', child);
child.once('error', reportChildError);
child.once('exit', exitWithChildStatus);

function localSiteEnvironment(environment) {
  const publishableKey = firstNonEmptyString([
    environment.SEAMS_INTENDED_PUBLISHABLE_KEY,
    environment.VITE_SEAMS_PUBLISHABLE_KEY,
    'pk_local',
  ]);
  const projectEnvironmentId = firstNonEmptyString([
    environment.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID,
    environment.VITE_SEAMS_PROJECT_ENVIRONMENT_ID,
    'local-env',
  ]);
  return {
    ...environment,
    VITE_RELAYER_URL: firstNonEmptyString([
      environment.VITE_RELAYER_URL,
      'https://localhost:9444',
    ]),
    VITE_SEAMS_BROKER_URL: firstNonEmptyString([
      environment.VITE_SEAMS_BROKER_URL,
      'https://localhost:9444',
    ]),
    VITE_CONSOLE_BASE_URL: firstNonEmptyString([
      environment.VITE_CONSOLE_BASE_URL,
      'https://localhost:9444',
    ]),
    VITE_WALLET_ORIGIN: firstNonEmptyString([
      environment.VITE_WALLET_ORIGIN,
      'https://localhost:8443',
    ]),
    VITE_DOCS_ORIGIN: firstNonEmptyString([
      environment.VITE_DOCS_ORIGIN,
      'https://docs.localhost',
    ]),
    VITE_RP_ID_BASE: firstNonEmptyString([environment.VITE_RP_ID_BASE, 'localhost']),
    VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID: firstNonEmptyString([
      environment.VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID,
      'local-signing-worker',
    ]),
    VITE_SIGNING_SESSION_PERSISTENCE_MODE: firstNonEmptyString([
      environment.VITE_SIGNING_SESSION_PERSISTENCE_MODE,
      'sealed_refresh_v1',
    ]),
    VITE_SEAMS_PROJECT_ENVIRONMENT_ID: projectEnvironmentId,
    VITE_SEAMS_PUBLISHABLE_KEY: publishableKey,
  };
}

function firstNonEmptyString(values) {
  for (const value of values) {
    const normalized = String(value || '').trim();
    if (normalized) return normalized;
  }
  return '';
}

function forwardSignal(signal, processHandle) {
  process.once(signal, () => processHandle.kill(signal));
}

function reportChildError(error) {
  console.error(`[local-site] failed to start Vite: ${error.message}`);
  process.exitCode = 1;
}

function exitWithChildStatus(code, signal) {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exitCode = code ?? 1;
}
