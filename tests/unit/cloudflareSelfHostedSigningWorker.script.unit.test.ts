import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64UrlEncode } from '../../shared/src/utils/encoders';
import type { AuthService } from '../../server/src/core/AuthService';
import { SIGNING_ROOT_RECORD_VERSION_V1 } from '../../server/src/core/ThresholdService/signingRootRecords';
import {
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
  THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
} from '../../server/src/core/ThresholdService/schemes/schemeIds';
import type { ThresholdAnySchemeModule } from '../../server/src/core/ThresholdService/schemes/types';
import {
  createSelfHostedCloudflareSigningRouter,
  createSelfHostedCloudflareSigningWorker,
} from '../../server/src/router/cloudflare/createSelfHostedCloudflareSigningWorker';
import { createCloudflareRouter } from '../../server/src/router/cloudflare/createCloudflareRouter';
import { ThresholdStoreDurableObject } from '../../server/src/router/cloudflare/durableObjects/thresholdStore';
import type { CfExecutionContext } from '../../server/src/router/cloudflare/types';
import type { ThresholdSigningAdapter } from '../../server/src/router/relay';

const fakeCtx = {} as CfExecutionContext;
const __dirname = dirname(fileURLToPath(import.meta.url));
const selfHostedRouterSourcePath = resolve(
  __dirname,
  '../../server/src/router/cloudflare/createSelfHostedCloudflareSigningWorker.ts',
);
const PROJECT_ID = 'project-alpha';
const ENV_ID = 'env-alpha';
const SIGNING_ROOT_ID = `${PROJECT_ID}:${ENV_ID}`;

function fakeAuthService(): AuthService {
  return {
    getConfiguredRelayerAccount: () => 'self-host.testnet',
    getThresholdSigningService: () => null,
  } as unknown as AuthService;
}

function fakeAuthServiceWithThreshold(threshold: unknown): AuthService {
  return {
    getConfiguredRelayerAccount: () => 'self-host.testnet',
    getThresholdSigningService: () => threshold,
  } as unknown as AuthService;
}

function fixtureThresholdAdapter(): ThresholdSigningAdapter {
  const ed25519Scheme = {
    schemeId: THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    healthz: async () => ({ ok: true }),
    protocol: {
      signInit: async (request: unknown) => ({
        ok: false,
        code: 'ed25519_fixture',
        message: JSON.stringify(request),
      }),
      signFinalize: async (request: unknown) => ({
        ok: false,
        code: 'ed25519_finalize_fixture',
        message: JSON.stringify(request),
      }),
    },
    session: async (request: unknown) => ({
      ok: false,
      code: 'ed25519_session_fixture',
      message: JSON.stringify(request),
    }),
    authorize: async (input: unknown) => ({
      ok: false,
      code: 'ed25519_authorize_fixture',
      message: JSON.stringify(input),
    }),
    registration: {
      keygenFromRegistrationMaterial: async (request: unknown) => ({
        ok: false,
        code: 'ed25519_registration_fixture',
        message: JSON.stringify(request),
      }),
    },
  } as ThresholdAnySchemeModule;
  const ecdsaScheme = {
    schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    healthz: async () => ({ ok: true }),
    protocol: {
      signInit: async (request: unknown) => ({
        ok: false,
        code: 'ecdsa_fixture',
        message: JSON.stringify(request),
      }),
      signFinalize: async (request: unknown) => ({
        ok: false,
        code: 'ecdsa_finalize_fixture',
        message: JSON.stringify(request),
      }),
    },
    authorize: async (input: unknown) => ({
      ok: false,
      code: 'ecdsa_authorize_fixture',
      message: JSON.stringify(input),
    }),
    presign: {
      init: async (input: unknown) => ({
        ok: false,
        code: 'ecdsa_presign_init_fixture',
        message: JSON.stringify(input),
      }),
      step: async (input: unknown) => ({
        ok: false,
        code: 'ecdsa_presign_step_fixture',
        message: JSON.stringify(input),
      }),
    },
  } as ThresholdAnySchemeModule;
  return {
    getSchemeModule: (schemeId) => {
      if (schemeId === THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) return ed25519Scheme;
      if (schemeId === THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID) return ecdsaScheme;
      return null;
    },
  };
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
    rpId: 'wallet.example.test',
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

test('self-host Cloudflare signing router exposes health without hosted relay routes', async () => {
  const router = createSelfHostedCloudflareSigningRouter(fakeAuthService(), {
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
      return fakeAuthService();
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

test('hosted and self-host Cloudflare routers preserve threshold signing route parity', async () => {
  const threshold = fixtureThresholdAdapter();
  const hosted = createCloudflareRouter(fakeAuthService(), { threshold, logger: console });
  const selfHosted = createSelfHostedCloudflareSigningRouter(fakeAuthService(), {
    threshold,
    logger: console,
  });
  const requests = [
    {
      path: '/threshold-ed25519/sign/init',
      body: {
        mpcSessionId: 'mpc-alpha',
        relayerKeyId: 'relayer-alpha',
        nearAccountId: 'alice.near',
        signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    },
    {
      path: '/threshold-ecdsa/sign/init',
      body: {
        mpcSessionId: 'mpc-alpha',
        ecdsaThresholdKeyId: 'ecdsa-alpha',
        signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
    },
  ];

  for (const { path, body } of requests) {
    const init: RequestInit = {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    };
    const hostedResult = await responseSnapshot(
      await hosted(new Request(`https://hosted.example.test${path}`, init), {}, fakeCtx),
    );
    const selfHostedResult = await responseSnapshot(
      await selfHosted(new Request(`https://self-host.example.test${path}`, init), {}, fakeCtx),
    );

    expect(selfHostedResult).toEqual(hostedResult);
  }
});

test('hosted and self-host Cloudflare routers preserve threshold health route parity', async () => {
  const threshold = fixtureThresholdAdapter();
  const hosted = createCloudflareRouter(fakeAuthService(), { threshold, logger: console });
  const selfHosted = createSelfHostedCloudflareSigningRouter(fakeAuthService(), {
    threshold,
    logger: console,
  });

  for (const path of ['/threshold-ed25519/healthz', '/threshold-ecdsa/healthz']) {
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
    fakeAuthService(),
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

test('self-host signing-root verify-wallet route delegates to threshold signing-root verifier', async () => {
  const namespace = createMemoryNamespace();
  const calls: unknown[] = [];
  const threshold = {
    verifyEcdsaSigningRootWalletAddress: async (input: unknown) => {
      calls.push(input);
      return {
        ok: true,
        verified: true,
        canonicalEthereumAddress: `0x${'11'.repeat(20)}`,
      };
    },
  };
  const router = createSelfHostedCloudflareSigningRouter(
    fakeAuthServiceWithThreshold(threshold),
    { healthz: true },
    {
      signingRootAdmin: {
        namespace,
        authenticate: ({ request }) => request.headers.get('authorization') === 'Bearer admin',
      },
    },
  );

  const missingBody = await router(
    new Request('https://self-host.example.test/self-host/signing-root/verify-wallet', {
      method: 'POST',
      headers: { authorization: 'Bearer admin', 'content-type': 'application/json' },
      body: JSON.stringify({ signingRootId: SIGNING_ROOT_ID }),
    }),
    {},
    fakeCtx,
  );
  expect(missingBody.status).toBe(400);

  const verified = await router(
    new Request('https://self-host.example.test/self-host/signing-root/verify-wallet', {
      method: 'POST',
      headers: { authorization: 'Bearer admin', 'content-type': 'application/json' },
      body: JSON.stringify({
        signingRootId: SIGNING_ROOT_ID,
        signingRootVersion: 'root-v1',
        walletSessionUserId: 'wallet-user-alpha',
        subjectId: 'subject-alpha',
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 11155111 },
        ecdsaThresholdKeyId: 'ecdsa-alpha',
        walletSigningSessionId: 'wallet-signing-alpha',
        thresholdSessionId: 'threshold-alpha',
        rpId: 'wallet.example.test',
        clientRootShare32B64u: base64UrlEncode(new Uint8Array(32).fill(0x07)),
        expectedEthereumAddress: `0x${'11'.repeat(20)}`,
      }),
    }),
    {},
    fakeCtx,
  );

  expect(verified.status).toBe(200);
  await expect(verified.json()).resolves.toMatchObject({
    ok: true,
    verified: true,
    canonicalEthereumAddress: `0x${'11'.repeat(20)}`,
  });
  expect(calls).toEqual([
    {
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: 'root-v1',
      walletSessionUserId: 'wallet-user-alpha',
      subjectId: 'subject-alpha',
      chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 11155111 },
      ecdsaThresholdKeyId: 'ecdsa-alpha',
      walletSigningSessionId: 'wallet-signing-alpha',
      thresholdSessionId: 'threshold-alpha',
      rpId: 'wallet.example.test',
      clientRootShare32B64u: base64UrlEncode(new Uint8Array(32).fill(0x07)),
      expectedEthereumAddress: `0x${'11'.repeat(20)}`,
    },
  ]);
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
    '../console',
    'bootstrapGrantBroker',
  ]) {
    expect(source, `forbidden self-host dependency: ${forbidden}`).not.toContain(forbidden);
  }
});
