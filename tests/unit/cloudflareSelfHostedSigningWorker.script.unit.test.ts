import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { ROUTER_AB_ED25519_HEALTH_PATH } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import {
  createSelfHostedCloudflareSigningRouter,
  createSelfHostedCloudflareSigningWorker,
} from '../../packages/wallet-server/src/router/cloudflare/runtime/createSelfHostedCloudflareSigningWorker';
import { createCloudflareRouter } from '../../packages/wallet-server/src/router/cloudflare/runtime/createCloudflareRouter';
import type { CfExecutionContext } from '../../packages/wallet-server/src/router/cloudflare/runtime/cloudflare.types';
import type { RouterApiServiceBag } from '../../packages/wallet-server/src/router/framework/authServicePort';

const fakeCtx = {} as CfExecutionContext;
const __dirname = dirname(fileURLToPath(import.meta.url));
const selfHostedRouterSourcePath = resolve(
  __dirname,
  '../../packages/wallet-server/src/router/cloudflare/runtime/createSelfHostedCloudflareSigningWorker.ts',
);

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

test('self-host Cloudflare signing router keeps hosted SaaS dependencies out of its direct boundary', () => {
  const source = readFileSync(selfHostedRouterSourcePath, 'utf8');
  for (const forbidden of [
    'createCloudflareRouter',
    'createCloudflareConsoleRouter',
    './routes/apiWallets',
    './routes/sponsoredEvmCall',
    './routes/wellKnown',
    './routes/sessions',
    '@seams-internal/console-server',
    'DerivationWalletId',
  ]) {
    expect(source, `forbidden self-host dependency: ${forbidden}`).not.toContain(forbidden);
  }
});
