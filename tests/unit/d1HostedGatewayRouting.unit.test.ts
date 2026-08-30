import { expect, test } from '@playwright/test';
import type { FetchHandler } from '../../packages/wallet-server/src/router/cloudflare/runtime/cloudflare.types';
import { localHostedWalletOrigins } from '../../packages/wallet-console-server-ts/src/router/cloudflare/d1LocalDevWorker';
import {
  dispatchHostedGatewayRequest,
  readStagingHostedWalletOrigins,
  stagingSigningSessionSealOptions,
} from '../../packages/wallet-console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker';

const SIGNING_SESSION_SEAL_ENV = {
  SIGNING_SESSION_SEAL_ROOT_SECRET_B64U: Buffer.alloc(32, 0x42).toString('base64url'),
  SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION: 'signing-session-seal-staging-r2',
  SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS: 'signing-session-seal-staging-r2',
} as const;

function markerHandler(marker: string): FetchHandler {
  return buildMarkerResponse.bind(null, marker);
}

async function buildMarkerResponse(marker: string): Promise<Response> {
  return new Response(marker);
}

async function routePath(pathname: string): Promise<string> {
  const response = await dispatchHostedGatewayRequest(
    markerHandler('console'),
    markerHandler('router-api'),
    new Request(`https://gateway.example.test${pathname}`),
  );
  return await response.text();
}

test('hosted gateway dispatches console routes to the console router', async () => {
  await expect(routePath('/console/session')).resolves.toBe('console');
  await expect(routePath('/console/auth/google')).resolves.toBe('console');
  await expect(routePath('/console/auth/github')).resolves.toBe('console');
  await expect(routePath('/console/auth/revoke')).resolves.toBe('console');
  await expect(routePath('/console/billing/account')).resolves.toBe('console');
});

test('hosted gateway dispatches every non-console route to the request-scoped Router API', async () => {
  await expect(routePath('/session/exchange')).resolves.toBe('router-api');
  await expect(routePath('/wallets/register/setup')).resolves.toBe('router-api');
  await expect(routePath('/consolex')).resolves.toBe('router-api');
});

test('hosted gateway reuses one signing-session seal runtime per isolate', () => {
  const first = stagingSigningSessionSealOptions(SIGNING_SESSION_SEAL_ENV);
  const second = stagingSigningSessionSealOptions(SIGNING_SESSION_SEAL_ENV);

  expect(first).toBeDefined();
  expect(second).toBe(first);
});

test('staging hosted-wallet origins use their own required binding', () => {
  expect(
    readStagingHostedWalletOrigins({
      HOSTED_WALLET_ORIGINS: 'https://wallet-a.example.test, https://wallet-b.example.test',
    }),
  ).toEqual(['https://wallet-a.example.test', 'https://wallet-b.example.test']);
  expect(() => readStagingHostedWalletOrigins({})).toThrow('HOSTED_WALLET_ORIGINS is required');
});

test('local hosted-wallet origins contain only the configured wallet deployment', () => {
  expect(localHostedWalletOrigins()).toEqual(['https://localhost:4002']);
  expect(localHostedWalletOrigins()).not.toContain('https://localhost:4101');
  expect(localHostedWalletOrigins()).not.toContain('http://localhost:4001');
});
