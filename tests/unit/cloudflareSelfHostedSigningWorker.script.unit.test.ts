import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { ROUTER_AB_ED25519_HEALTH_PATH } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { SIGNING_ROOT_RECORD_VERSION_V1 } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootRecords';
import {
  createSelfHostedCloudflareSigningRouter,
  createSelfHostedCloudflareSigningWorker,
} from '../../packages/sdk-server-ts/src/router/cloudflare/createSelfHostedCloudflareSigningWorker';
import { createCloudflareRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';
import type { CfExecutionContext } from '../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import type { RouterApiServiceBag } from '../../packages/sdk-server-ts/src/router/authServicePort';

const fakeCtx = {} as CfExecutionContext;
const __dirname = dirname(fileURLToPath(import.meta.url));
const selfHostedRouterSourcePath = resolve(
  __dirname,
  '../../packages/sdk-server-ts/src/router/cloudflare/createSelfHostedCloudflareSigningWorker.ts',
);
const PROJECT_ID = 'project-alpha';
const ENV_ID = 'env-alpha';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;

function fakeRouterApiServiceBag(): RouterApiServiceBag {
  return {
    router: {
      getConfiguredRelayerAccount: () => 'self-host.testnet',
    },
    thresholdRuntime: {
      getRouterAbNormalSigningRuntime: () => null,
      getRouterAbEcdsaPresignRuntime: () => null,
    },
  } as unknown as RouterApiServiceBag;
}

function fakeRouterApiServiceBagForRouterHealth(): RouterApiServiceBag {
  return {
    router: {
      getConfiguredRelayerAccount: () => 'self-host.testnet',
    },
    thresholdRuntime: {
      getRouterAbNormalSigningRuntime: () => null,
      getRouterAbEcdsaPresignRuntime: () => null,
    },
  } as unknown as RouterApiServiceBag;
}

async function responseSnapshot(response: Response): Promise<{
  readonly status: number;
  readonly body: unknown;
}> {
  return {
    status: response.status,
    body: await response.json(),
  };
}

function createMemoryNamespace() {
  const objects = new Map<
    string,
    { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> }
  >();
  return {
    idFromName: (name: string) => name,
    get: (id: unknown) => {
      const key = String(id);
      const existing = objects.get(key);
      if (existing) return existing;

      const storageMap = new Map<string, unknown>();
      const durableObject = new ThresholdStoreDurableObject(
        {
          storage: {
            get: async (storageKey: string) => storageMap.get(storageKey) ?? null,
            put: async (storageKey: string, value: unknown) => {
              storageMap.set(storageKey, value);
            },
            delete: async (storageKey: string) => storageMap.delete(storageKey),
          },
        },
        {},
      );
      const stub = {
        fetch: (request: RequestInfo, init?: RequestInit) =>
          durableObject.fetch(request instanceof Request ? request : new Request(request, init)),
      };
      objects.set(key, stub);
      return stub;
    },
  };
}

function signingRootRecordFixture() {
  return {
    version: SIGNING_ROOT_RECORD_VERSION_V1,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    signingRootId: SIGNING_ROOT_ID,
    walletOrigin: 'https://wallet.example.test',
    authorityScope: { kind: 'passkey_rp', rpId: 'wallet.example.test' },
    signingRootVersion: 'root-v1',
    rootShareEpoch: 1,
    shareThreshold: 2,
    shareCount: 3,
    sealedSigningRootSecretShares: ([1, 2, 3] as const).map((shareId) => ({
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: 'root-v1',
      shareId,
      sealedShareB64u: base64UrlEncode(new Uint8Array([shareId, 0xaa, 0xbb])),
      kekId: 'kek-v1',
    })),
    derivationVersion: 1,
    createdAtMs: 10,
    updatedAtMs: 20,
    source: 'customer-import',
  };
}

test('self-host Cloudflare signing router exposes health without hosted Router API routes', async () => {
  const router = createSelfHostedCloudflareSigningRouter(fakeRouterApiServiceBag(), {
    healthz: true,
    readyz: true,
    corsOrigins: ['https://wallet.example.test'],
  });

  const health = await router(
    new Request('https://self-host.example.test/healthz', {
      headers: { origin: 'https://wallet.example.test' },
    }),
    {},
    fakeCtx,
  );
  await expect(health.json()).resolves.toMatchObject({
    ok: true,
    selfHosted: true,
    threshold: { configured: false },
  });
  expect(health.headers.get('access-control-allow-origin')).toBe('*');

  const hostedOnlyRoute = await router(
    new Request('https://self-host.example.test/sponsored-evm-call', { method: 'POST' }),
    {},
    fakeCtx,
  );
  expect(hostedOnlyRoute.status).toBe(404);
});

test('self-host Cloudflare signing worker creates per-request service and options', async () => {
  const calls: string[] = [];
  const worker = createSelfHostedCloudflareSigningWorker({
    createAuthService: ({ request }) => {
      calls.push(new URL(request.url).pathname);
      return fakeRouterApiServiceBag();
    },
    routerOptions: () => ({ healthz: true }),
  });

  const response = await worker.fetch(
    new Request('https://self-host.example.test/healthz'),
    {},
    fakeCtx,
  );

  expect(response.status).toBe(200);
  expect(calls).toEqual(['/healthz']);
});

test('hosted and self-host Cloudflare routers preserve threshold health route parity', async () => {
  const service = fakeRouterApiServiceBagForRouterHealth();
  const hosted = createCloudflareRouter(service, { logger: console });
  const selfHosted = createSelfHostedCloudflareSigningRouter(service, {
    logger: console,
  });

  for (const path of [ROUTER_AB_ED25519_HEALTH_PATH, ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH]) {
    const hostedResult = await responseSnapshot(
      await hosted(new Request(`https://hosted.example.test${path}`), {}, fakeCtx),
    );
    const selfHostedResult = await responseSnapshot(
      await selfHosted(new Request(`https://self-host.example.test${path}`), {}, fakeCtx),
    );

    expect(selfHostedResult).toEqual(hostedResult);
  }
});

test('self-host signing-root admin routes import status and delete through the threshold store DO', async () => {
  const namespace = createMemoryNamespace();
  const router = createSelfHostedCloudflareSigningRouter(
    fakeRouterApiServiceBag(),
    { healthz: true },
    {
      signingRootAdmin: {
        namespace,
        authenticate: ({ request }) => request.headers.get('authorization') === 'Bearer admin',
      },
    },
  );

  const unauthorized = await router(
    new Request('https://self-host.example.test/self-host/signing-root/import', {
      method: 'POST',
      body: JSON.stringify(signingRootRecordFixture()),
    }),
    {},
    fakeCtx,
  );
  expect(unauthorized.status).toBe(401);

  const imported = await router(
    new Request('https://self-host.example.test/self-host/signing-root/import', {
      method: 'POST',
      headers: {
        authorization: 'Bearer admin',
        'content-type': 'application/json',
      },
      body: JSON.stringify(signingRootRecordFixture()),
    }),
    {},
    fakeCtx,
  );
  await expect(imported.json()).resolves.toMatchObject({
    ok: true,
    value: {
      projectId: 'project-alpha',
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: 'root-v1',
      shareIds: [1, 2, 3],
    },
  });

  const status = await router(
    new Request(
      `https://self-host.example.test/self-host/signing-root/status?signingRootId=${encodeURIComponent(SIGNING_ROOT_ID)}&signingRootVersion=root-v1`,
      {
        headers: { authorization: 'Bearer admin' },
      },
    ),
    {},
    fakeCtx,
  );
  await expect(status.json()).resolves.toMatchObject({
    ok: true,
    value: {
      projectId: 'project-alpha',
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: 'root-v1',
      shareIds: [1, 2, 3],
    },
  });

  const deleted = await router(
    new Request('https://self-host.example.test/self-host/signing-root/delete', {
      method: 'POST',
      headers: {
        authorization: 'Bearer admin',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ signingRootId: SIGNING_ROOT_ID, signingRootVersion: 'root-v1' }),
    }),
    {},
    fakeCtx,
  );
  await expect(deleted.json()).resolves.toEqual({ ok: true, value: { deleted: true } });

  const staleRoute = await router(
    new Request(`https://self-host.example.test/self-host/${['project', 'root'].join('-')}/status`, {
      headers: { authorization: 'Bearer admin' },
    }),
    {},
    fakeCtx,
  );
  expect(staleRoute.status).toBe(404);
});

test('self-host Cloudflare signing router keeps hosted SaaS dependencies out of its direct boundary', () => {
  const source = readFileSync(selfHostedRouterSourcePath, 'utf8');
  for (const forbidden of [
    'createCloudflareRouter',
    'createCloudflareConsoleRouter',
    './routes/apiWallets',
    './routes/bootstrapGrants',
    './routes/sponsoredEvmCall',
    './routes/recoverEmail',
    './routes/emailRecovery',
    './routes/wellKnown',
    './routes/sessions',
    '@seams-internal/console-server',
    'bootstrapGrantBroker',
    'DerivationWalletId',
  ]) {
    expect(source, `forbidden self-host dependency: ${forbidden}`).not.toContain(forbidden);
  }
});
