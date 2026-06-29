import { expect, test } from '@playwright/test';
import {
  D1_STAGING_CONSOLE_ORIGIN,
  D1_STAGING_GENERATED_AT_ISO,
  D1_STAGING_ROUTER_API_ORIGIN,
  d1StagingJsonResponse,
  d1StagingManifestPath,
  d1StagingRequestUrl,
  loadD1StagingScriptModule,
  readD1StagingJsonFile,
} from './helpers/d1StagingScriptFixtures';

type SmokeEndpoint = {
  readonly id: string;
  readonly method: string;
  readonly url: string;
};

type SmokePlan = {
  readonly mode: string;
  readonly endpoints: readonly SmokeEndpoint[];
};

type SmokeModule = {
  readonly buildD1StagingSmokePlan: (input: {
    readonly consoleOrigin: string;
    readonly routerApiOrigin: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => SmokePlan;
  readonly runD1StagingSmoke: (input: {
    readonly consoleOrigin: string;
    readonly routerApiOrigin: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly fetchImpl?: typeof fetch;
  }) => Promise<{
    readonly manifestPath: string;
    readonly manifest: SmokePlan & {
      readonly checks: readonly {
        readonly id: string;
        readonly status: number;
        readonly ok: boolean;
      }[];
    };
  }>;
};

const smokeModule = loadD1StagingScriptModule<SmokeModule>('d1-staging-smoke.mjs');
const smokeInput = {
  consoleOrigin: D1_STAGING_CONSOLE_ORIGIN,
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
  routerApiOrigin: D1_STAGING_ROUTER_API_ORIGIN,
};

function smokeEndpointTuple(endpoint: SmokeEndpoint): readonly [string, string, string] {
  return [endpoint.id, endpoint.method, endpoint.url];
}

async function smokeFetch(input: string | URL | Request): Promise<Response> {
  const url = d1StagingRequestUrl(input);
  if (url === `${D1_STAGING_CONSOLE_ORIGIN}/console/readyz`) {
    return d1StagingJsonResponse({ ok: true, service: 'console' }, 200);
  }
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/readyz`) {
    return d1StagingJsonResponse({ ok: true, thresholdEd25519: { configured: false } }, 200);
  }
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/healthz`) {
    return d1StagingJsonResponse({ ok: true }, 200);
  }
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ed25519/healthz`) {
    return d1StagingJsonResponse({ ok: true, configured: true }, 200);
  }
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ecdsa-hss/healthz`) {
    return d1StagingJsonResponse({ ok: true, configured: true }, 200);
  }
  return d1StagingJsonResponse({ ok: false }, 404);
}

async function failingSmokeFetch(_input: string | URL | Request): Promise<Response> {
  return d1StagingJsonResponse({ ok: false }, 503);
}

test('D1 staging smoke builds the actual console and router-api readiness endpoint plan', async () => {
  const module = await smokeModule;
  const plan = module.buildD1StagingSmokePlan(smokeInput);

  expect(plan.mode).toBe('dry-run');
  expect(plan.endpoints.map(smokeEndpointTuple)).toEqual([
    ['console_readyz', 'GET', `${D1_STAGING_CONSOLE_ORIGIN}/console/readyz`],
    ['router_api_readyz', 'GET', `${D1_STAGING_ROUTER_API_ORIGIN}/readyz`],
    ['router_api_healthz', 'GET', `${D1_STAGING_ROUTER_API_ORIGIN}/healthz`],
    ['signer_custody_ed25519_healthz', 'GET', `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ed25519/healthz`],
    ['signer_custody_ecdsa_hss_healthz', 'GET', `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ecdsa-hss/healthz`],
  ]);
});

test('D1 staging smoke writes remote evidence when readiness endpoints pass', async () => {
  const module = await smokeModule;
  const manifestPath = d1StagingManifestPath('seams-d1-staging-smoke');
  const result = await module.runD1StagingSmoke({
    ...smokeInput,
    manifestPath,
    mode: 'remote',
    fetchImpl: smokeFetch,
  });

  expect(result.manifest.checks).toHaveLength(5);
  expect(result.manifest.checks.map((check) => check.id)).toEqual([
    'console_readyz',
    'router_api_readyz',
    'router_api_healthz',
    'signer_custody_ed25519_healthz',
    'signer_custody_ecdsa_hss_healthz',
  ]);
  expect(readD1StagingJsonFile(manifestPath).checks).toHaveLength(5);
});

test('D1 staging smoke requires configured signer custody health routes', async () => {
  const module = await smokeModule;
  await expect(
    module.runD1StagingSmoke({
      ...smokeInput,
      manifestPath: d1StagingManifestPath('seams-d1-staging-smoke-unconfigured'),
      mode: 'remote',
      fetchImpl: unconfiguredSignerSmokeFetch,
    }),
  ).rejects.toThrow(/signer_custody_ed25519_healthz returned configured=false/);
});

test('D1 staging smoke rejects origins with paths', async () => {
  const module = await smokeModule;
  expect(() =>
    module.buildD1StagingSmokePlan({
      ...smokeInput,
      consoleOrigin: 'https://console.staging.example/console',
    }),
  ).toThrow(/--console-origin must not include a path/);
});

test('D1 staging smoke requires HTTPS origins in remote mode', async () => {
  const module = await smokeModule;
  expect(() =>
    module.buildD1StagingSmokePlan({
      ...smokeInput,
      consoleOrigin: 'http://console.staging.example',
      mode: 'remote',
    }),
  ).toThrow(/--console-origin must use https in remote mode/);
});

test('D1 staging smoke fails when a readiness endpoint is unhealthy', async () => {
  const module = await smokeModule;
  await expect(
    module.runD1StagingSmoke({
      ...smokeInput,
      manifestPath: d1StagingManifestPath('seams-d1-staging-smoke-fail'),
      mode: 'remote',
      fetchImpl: failingSmokeFetch,
    }),
  ).rejects.toThrow(/console_readyz returned HTTP 503/);
});

async function unconfiguredSignerSmokeFetch(input: string | URL | Request): Promise<Response> {
  const url = d1StagingRequestUrl(input);
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ed25519/healthz`) {
    return d1StagingJsonResponse({ ok: true, configured: false }, 200);
  }
  return smokeFetch(input);
}
