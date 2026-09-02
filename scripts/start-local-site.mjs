#!/usr/bin/env node
import { spawn } from 'node:child_process';
import path from 'node:path';
import { stripVTControlCharacters } from 'node:util';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const localEnvPath = path.join(repoRoot, '.env.local');
const siteLinkColor = '1;38;5;214';
const localSites = [
  { label: 'Seams', url: 'http://localhost:4001/wallet' },
  { label: 'Dashboard', url: 'http://localhost:4001/dashboard' },
  { label: 'Docs', url: 'https://docs.localhost:4003' },
];

// The root local env is the sole authority shared by the site and console seed.
dotenv.config({ path: localEnvPath, override: true });

const child = spawn(
  'pnpm',
  ['-C', 'apps/seams-site', 'vite', '--host', '127.0.0.1', '--port', '4004'],
  {
    cwd: repoRoot,
    env: localSiteEnvironment(process.env),
    stdio: ['inherit', 'pipe', 'inherit'],
  },
);

let siteOutput = '';
let localLinksScheduled = false;
child.stdout.setEncoding('utf8');
child.stdout.on('data', forwardSiteOutput);

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
    VITE_RELAYER_URL: firstNonEmptyString([environment.VITE_RELAYER_URL, 'https://localhost:4101']),
    VITE_SEAMS_BROKER_URL: firstNonEmptyString([
      environment.VITE_SEAMS_BROKER_URL,
      'https://localhost:4101',
    ]),
    VITE_CONSOLE_BASE_URL: firstNonEmptyString([
      environment.VITE_CONSOLE_BASE_URL,
      'https://localhost:4101',
    ]),
    VITE_WALLET_ORIGIN: firstNonEmptyString([
      environment.VITE_WALLET_ORIGIN,
      'https://localhost:4002',
    ]),
    VITE_DOCS_ORIGIN: firstNonEmptyString([
      environment.VITE_DOCS_ORIGIN,
      'https://docs.localhost:4003',
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

function forwardSiteOutput(chunk) {
  process.stdout.write(chunk);
  if (localLinksScheduled) return;
  siteOutput = `${siteOutput}${stripVTControlCharacters(chunk)}`.slice(-4_096);
  if (!siteOutput.includes('Local:')) return;
  localLinksScheduled = true;
  setTimeout(printLocalSiteLinks, 1_000);
}

function printLocalSiteLinks() {
  const colorsEnabled = process.env.NO_COLOR === undefined;
  console.log(`\n${styleTerminalText('Local sites', siteLinkColor, colorsEnabled)}`);
  for (const site of localSites) printLocalSiteLink(site, colorsEnabled);
  console.log();
}

function printLocalSiteLink(site, colorsEnabled) {
  const label = styleTerminalText(site.label.padEnd(10), siteLinkColor, colorsEnabled);
  const url = styleTerminalText(site.url, `${siteLinkColor};4`, colorsEnabled);
  console.log(`  ${label} ${url}`);
}

function styleTerminalText(text, color, colorsEnabled) {
  return colorsEnabled ? `\u001b[${color}m${text}\u001b[0m` : text;
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
