import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

const TESTS_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(TESTS_ROOT, '..');
const LOCAL_SITE_ORIGIN = 'http://127.0.0.1:37994';
const EXPECTED_STAGING_ORIGINS = Object.freeze({
  gateway: 'https://staging.api.seams.sh',
  site: 'https://staging.seams.sh',
  wallet: 'https://staging.sign.seams.sh',
});
export const REFACTOR93_STAGING_RUNTIME_PATHS = Object.freeze({
  playwrightOutput: path.join(tmpdir(), 'seams-refactor93-staging-playwright'),
  viteCache: path.join(tmpdir(), 'seams-refactor93-staging-vite-cache'),
});

type Refactor93StagingCheckConfig = {
  readonly mode: 'check';
  readonly origins: typeof EXPECTED_STAGING_ORIGINS;
  readonly localSiteOrigin: typeof LOCAL_SITE_ORIGIN;
};

type Refactor93StagingLiveConfig = {
  readonly mode: 'live';
  readonly origins: typeof EXPECTED_STAGING_ORIGINS;
  readonly localSiteOrigin: typeof LOCAL_SITE_ORIGIN;
  readonly expectedSha: string;
  readonly projectEnvironmentId: string;
  readonly publishableKey: string;
  readonly signingSessionPersistenceMode: string;
};

export type Refactor93StagingConfig = Refactor93StagingCheckConfig | Refactor93StagingLiveConfig;

export function parseRefactor93StagingConfig(
  environment: NodeJS.ProcessEnv,
): Refactor93StagingConfig {
  rejectPrivateServiceAuth(environment);
  const origins = readStagingOrigins();
  const mode = requireMode(environment.SEAMS_REF93_STAGING_MODE);
  if (mode === 'check') {
    return { mode, origins, localSiteOrigin: LOCAL_SITE_ORIGIN };
  }
  return {
    mode,
    origins,
    localSiteOrigin: LOCAL_SITE_ORIGIN,
    expectedSha: requireCommitSha(environment.SEAMS_REF93_EXPECTED_SHA),
    projectEnvironmentId: requireEnvironmentValue(environment, 'VITE_SEAMS_PROJECT_ENVIRONMENT_ID'),
    publishableKey: requireEnvironmentValue(environment, 'VITE_SEAMS_PUBLISHABLE_KEY'),
    signingSessionPersistenceMode: requireEnvironmentValue(
      environment,
      'VITE_SIGNING_SESSION_PERSISTENCE_MODE',
    ),
  };
}

export const REFACTOR93_STAGING_CONFIG = parseRefactor93StagingConfig(process.env);

if (REFACTOR93_STAGING_CONFIG.mode === 'live') {
  installIntendedHarnessEnvironment(REFACTOR93_STAGING_CONFIG);
}

const webServer =
  REFACTOR93_STAGING_CONFIG.mode === 'live'
    ? {
        command:
          'pnpm -C .. build:sdk-full && pnpm -C ../apps/seams-site exec vite --host 127.0.0.1 --port 37994',
        url: LOCAL_SITE_ORIGIN,
        reuseExistingServer: false,
        gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 30_000 },
        timeout: 420_000,
        env: localSiteEnvironment(REFACTOR93_STAGING_CONFIG),
      }
    : undefined;

export default defineConfig({
  tsconfig: './tsconfig.intended.json',
  testDir: '.',
  testMatch: ['**/e2e/intended-behaviours/refactor93-staging-cohort.staging.test.ts'],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  globalTimeout: 600_000,
  timeout: 420_000,
  expect: { timeout: 15_000 },
  reporter: 'line',
  outputDir: REFACTOR93_STAGING_RUNTIME_PATHS.playwrightOutput,
  webServer,
  use: {
    baseURL: EXPECTED_STAGING_ORIGINS.site,
    ignoreHTTPSErrors: false,
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});

function readStagingOrigins(): typeof EXPECTED_STAGING_ORIGINS {
  const targetsPath = path.join(REPOSITORY_ROOT, 'deployment', 'targets.json');
  const parsed = JSON.parse(readFileSync(targetsPath, 'utf8')) as unknown;
  if (
    !isRecord(parsed) ||
    !isRecord(parsed.staging) ||
    !isRecord(parsed.staging.site) ||
    !isRecord(parsed.staging.lanes) ||
    !isRecord(parsed.staging.lanes.testnet)
  ) {
    throw new Error('deployment/targets.json is missing staging origins');
  }
  const origins = {
    gateway: parsed.staging.lanes.testnet.gatewayOrigin,
    site: parsed.staging.site.origin,
    wallet: parsed.staging.lanes.testnet.walletOrigin,
  };
  for (const name of ['gateway', 'site', 'wallet'] as const) {
    if (origins[name] !== EXPECTED_STAGING_ORIGINS[name]) {
      throw new Error(
        `Refactor 93 staging ${name} origin must be exactly ${EXPECTED_STAGING_ORIGINS[name]}`,
      );
    }
  }
  return EXPECTED_STAGING_ORIGINS;
}

function rejectPrivateServiceAuth(environment: NodeJS.ProcessEnv): void {
  if (!String(environment.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET || '').trim()) return;
  throw new Error('The staging browser cohort refuses private Router service-auth material');
}

function requireMode(value: string | undefined): Refactor93StagingConfig['mode'] {
  if (value === 'check' || value === 'live') return value;
  throw new Error('SEAMS_REF93_STAGING_MODE must be check or live');
}

function requireCommitSha(value: string | undefined): string {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (/^[0-9a-f]{40}$/u.test(normalized)) return normalized;
  throw new Error('SEAMS_REF93_EXPECTED_SHA must be a full 40-character commit SHA');
}

function requireEnvironmentValue(environment: NodeJS.ProcessEnv, name: string): string {
  const value = String(environment[name] || '').trim();
  if (value) return value;
  throw new Error(`${name} is required for the live Refactor 93 staging cohort`);
}

function localSiteEnvironment(config: Refactor93StagingLiveConfig): Record<string, string> {
  return {
    VITE_RELAYER_URL: config.origins.gateway,
    VITE_SEAMS_BROKER_URL: config.origins.gateway,
    VITE_CONSOLE_BASE_URL: config.origins.gateway,
    VITE_WALLET_ORIGIN: config.origins.wallet,
    VITE_DOCS_ORIGIN: config.origins.site,
    VITE_RP_ID_BASE: new URL(config.origins.wallet).hostname,
    VITE_ROR_ALLOWED_ORIGINS: config.origins.site,
    VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'router-ab-signing-worker-staging',
    VITE_SEAMS_PROJECT_ENVIRONMENT_ID: config.projectEnvironmentId,
    VITE_SEAMS_PUBLISHABLE_KEY: config.publishableKey,
    VITE_SIGNING_SESSION_PERSISTENCE_MODE: config.signingSessionPersistenceMode,
    VITE_ENABLE_INTENDED_E2E: '1',
    VITE_CACHE_DIR: REFACTOR93_STAGING_RUNTIME_PATHS.viteCache,
  };
}

function installIntendedHarnessEnvironment(config: Refactor93StagingLiveConfig): void {
  process.env.SEAMS_INTENDED_APP_URL = config.origins.site;
  process.env.SEAMS_INTENDED_ROUTER_URL = config.origins.gateway;
  process.env.SEAMS_INTENDED_WALLET_ORIGIN = config.origins.wallet;
  process.env.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID = config.projectEnvironmentId;
  process.env.SEAMS_INTENDED_PUBLISHABLE_KEY = config.publishableKey;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
