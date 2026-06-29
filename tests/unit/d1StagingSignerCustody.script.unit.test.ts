import { expect, test } from '@playwright/test';
import {
  D1_STAGING_GENERATED_AT_ISO,
  D1_STAGING_ROUTER_API_ORIGIN,
  d1StagingJsonResponse,
  d1StagingManifestPath,
  d1StagingRequestUrl,
  loadD1StagingScriptModule,
  readD1StagingJsonFile,
  writeD1StagingTempFile,
} from './helpers/d1StagingScriptFixtures';

type SignerCustodyPlan = {
  readonly mode: string;
  readonly healthChecks: readonly { readonly id: string; readonly url: string }[];
  readonly checks: readonly {
    readonly id: string;
    readonly url: string;
    readonly fixture: { readonly relativePath: string; readonly sha256: string };
    readonly walletSessionJwtEnvName: string;
  }[];
};

type SignerCustodyModule = {
  readonly buildD1StagingSignerCustodyPlan: (input: {
    readonly routerApiOrigin: string;
    readonly exportShareFixturePath: string;
    readonly generatedAtIso?: string;
    readonly missingKekExpectedCode?: string;
    readonly missingKekExpectedStatus?: string;
    readonly missingKekFixturePath?: string;
    readonly missingKekJwtEnvName?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly origin?: string;
  }) => SignerCustodyPlan;
  readonly runD1StagingSignerCustody: (input: {
    readonly routerApiOrigin: string;
    readonly exportShareFixturePath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly missingKekExpectedCode?: string;
    readonly missingKekExpectedStatus?: string;
    readonly missingKekFixturePath?: string;
    readonly missingKekJwtEnvName?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly fetchImpl?: typeof fetch;
    readonly env?: Record<string, string>;
    readonly origin?: string;
  }) => Promise<{
    readonly manifestPath: string;
    readonly manifest: SignerCustodyPlan & {
      readonly results: readonly {
        readonly id: string;
        readonly status: number;
        readonly ok: boolean;
        readonly body: unknown;
      }[];
    };
  }>;
};

const signerCustodyModule = loadD1StagingScriptModule<SignerCustodyModule>(
  'd1-staging-signer-custody.mjs',
);

type SignerCustodyPlanInput = Parameters<SignerCustodyModule['buildD1StagingSignerCustodyPlan']>[0];

const exportShareFixtureSource = `${JSON.stringify(
  {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId: 'wallet-fixture-1',
    walletKeyId: 'wallet-key-fixture-1',
    ecdsaThresholdKeyId: 'ecdsa-threshold-fixture-1',
    relayerKeyId: 'relayer-key-fixture-1',
  },
  null,
  2,
)}\n`;

function writeExportShareFixture(): string {
  return writeD1StagingTempFile(
    'seams-d1-staging-export-share-',
    'export-share.json',
    exportShareFixtureSource,
  );
}

function signerCustodyInput(): SignerCustodyPlanInput {
  return {
    exportShareFixturePath: writeExportShareFixture(),
    generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
    routerApiOrigin: D1_STAGING_ROUTER_API_ORIGIN,
  };
}

function dryRunSignerCustodyFetch(): Promise<Response> {
  throw new Error('dry-run signer custody must not call fetch');
}

function requestAuthorization(init?: RequestInit): string {
  const headers = init?.headers;
  if (headers instanceof Headers) return headers.get('authorization') || '';
  return String((headers as Record<string, string> | undefined)?.authorization || '');
}

async function signerCustodyFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = d1StagingRequestUrl(input);
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ed25519/healthz`) {
    return d1StagingJsonResponse({ ok: true, configured: true }, 200);
  }
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ecdsa-hss/healthz`) {
    return d1StagingJsonResponse({ ok: true, configured: true }, 200);
  }
  if (url === `${D1_STAGING_ROUTER_API_ORIGIN}/router-ab/ecdsa-hss/export/share`) {
    expect(init?.method).toBe('POST');
    const authorization = requestAuthorization(init);
    if (authorization === 'Bearer missing-kek-jwt') {
      return d1StagingJsonResponse({ ok: false, code: 'missing_signing_root_kek' }, 503);
    }
    expect(authorization).toBe('Bearer fixture-jwt');
    return d1StagingJsonResponse(
      {
        ok: true,
        value: {
          serverExportShare32B64u: 'server-share-secret',
          server_export_share_32_b64u: 'server-share-snake-secret',
          private_key_hex: 'private-key-secret',
          nested: {
            signing_share_32_b64u: 'signing-share-secret',
            authorization: 'Bearer body-token',
          },
          publicCheck: 'visible',
        },
      },
      200,
    );
  }
  return d1StagingJsonResponse({ ok: false }, 404);
}

test('D1 staging signer custody builds a fixture-backed production-route plan', async () => {
  const module = await signerCustodyModule;
  const plan = module.buildD1StagingSignerCustodyPlan(signerCustodyInput());

  expect(plan.mode).toBe('dry-run');
  expect(plan.healthChecks.map((check) => check.url)).toEqual([
    'https://router-api.staging.example/router-ab/ed25519/healthz',
    'https://router-api.staging.example/router-ab/ecdsa-hss/healthz',
  ]);
  expect(plan.checks).toEqual([
    expect.objectContaining({
      id: 'ecdsa_export_share_success',
      url: 'https://router-api.staging.example/router-ab/ecdsa-hss/export/share',
      walletSessionJwtEnvName: 'SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT',
    }),
  ]);
  expect(plan.checks[0]?.fixture.sha256).toMatch(/^[0-9a-f]{64}$/);
});

test('D1 staging signer custody writes dry-run evidence without calling fetch', async () => {
  const module = await signerCustodyModule;
  const manifestPath = d1StagingManifestPath('seams-d1-staging-signer-custody');
  await module.runD1StagingSignerCustody({
    ...signerCustodyInput(),
    manifestPath,
    fetchImpl: dryRunSignerCustodyFetch,
  });

  expect(readD1StagingJsonFile(manifestPath).results).toHaveLength(0);
});

test('D1 staging signer custody remote mode records redacted export-share evidence', async () => {
  const module = await signerCustodyModule;
  const manifestPath = d1StagingManifestPath('seams-d1-staging-signer-custody-remote');
  const result = await module.runD1StagingSignerCustody({
    ...signerCustodyInput(),
    manifestPath,
    mode: 'remote',
    fetchImpl: signerCustodyFetch,
    env: {
      SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT: 'fixture-jwt',
    },
  });

  expect(result.manifest.results.map((check) => check.id)).toEqual([
    'signer_custody_ed25519_healthz',
    'signer_custody_ecdsa_hss_healthz',
    'ecdsa_export_share_success',
  ]);
  const serialized = JSON.stringify(result.manifest);
  expect(serialized).not.toMatch(
    /fixture-jwt|server-share-secret|server-share-snake-secret|private-key-secret|signing-share-secret|Bearer body-token/,
  );
  expect(serialized).toContain('<redacted>');
});

test('D1 staging signer custody remote mode records fail-closed missing KEK evidence', async () => {
  const module = await signerCustodyModule;
  const manifestPath = d1StagingManifestPath('seams-d1-staging-signer-custody-missing-kek');
  const result = await module.runD1StagingSignerCustody({
    ...signerCustodyInput(),
    missingKekFixturePath: writeExportShareFixture(),
    missingKekExpectedStatus: '503',
    missingKekExpectedCode: 'missing_signing_root_kek',
    manifestPath,
    mode: 'remote',
    fetchImpl: signerCustodyFetch,
    env: {
      SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT: 'fixture-jwt',
      SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT: 'missing-kek-jwt',
    },
  });

  expect(result.manifest.results.map((check) => check.id)).toEqual([
    'signer_custody_ed25519_healthz',
    'signer_custody_ecdsa_hss_healthz',
    'ecdsa_export_share_success',
    'ecdsa_export_share_missing_kek_fail_closed',
  ]);
  expect(result.manifest.results[3]).toMatchObject({
    id: 'ecdsa_export_share_missing_kek_fail_closed',
    status: 503,
    ok: true,
    body: { ok: false, code: 'missing_signing_root_kek' },
  });
  expect(JSON.stringify(result.manifest)).not.toMatch(
    /fixture-jwt|missing-kek-jwt|server-share-secret/,
  );
});

test('D1 staging signer custody remote mode requires JWTs from env', async () => {
  const module = await signerCustodyModule;
  await expect(
    module.runD1StagingSignerCustody({
      ...signerCustodyInput(),
      manifestPath: d1StagingManifestPath('seams-d1-staging-signer-custody-missing-env'),
      mode: 'remote',
      fetchImpl: signerCustodyFetch,
      env: {},
    }),
  ).rejects.toThrow(/SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT is required/);
});

test('D1 staging signer custody requires HTTPS Router API origins in remote mode', async () => {
  const module = await signerCustodyModule;
  expect(() =>
    module.buildD1StagingSignerCustodyPlan({
      ...signerCustodyInput(),
      routerApiOrigin: 'http://router-api.staging.example',
      mode: 'remote',
    }),
  ).toThrow(/--router-api-origin must use https in remote mode/);
});

test('D1 staging signer custody requires HTTPS request origins in remote mode', async () => {
  const module = await signerCustodyModule;
  expect(() =>
    module.buildD1StagingSignerCustodyPlan({
      ...signerCustodyInput(),
      origin: 'http://console.staging.example',
      mode: 'remote',
    }),
  ).toThrow(/--origin must use https in remote mode/);
});
