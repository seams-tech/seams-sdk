import { expect, test } from '@playwright/test';
import { proxyNormalSigningRequestToMpcRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/routes/normalSigningRouterProxy';
import { handleSigningBudgetStatus } from '../../packages/sdk-server-ts/src/router/cloudflare/routes/sessions';
import { isRouterAbEd25519OperationInProgressResponse } from '../../packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519';
import type { CloudflareRouterApiContext } from '../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter';

test('normal-signing proxy preserves authorization and source-binding headers', async () => {
  let forwarded: Request | null = null;
  const request = new Request('https://gateway.example/router-ab/ecdsa-derivation/sign/prepare', {
    method: 'POST',
    headers: {
      authorization: 'Bearer wallet-session-jwt',
      'content-type': 'application/json',
      origin: 'https://sign.example',
      'cf-connecting-ip': '203.0.113.17',
      'cf-ray': 'ray-id-NRT',
      'x-seams-trace-id': 'trace-correlation-1',
      'x-router-ab-internal-service-auth': 'forged-client-secret',
    },
    body: JSON.stringify({ request_id: 'request-1' }),
  });

  const response = await proxyNormalSigningRequestToMpcRouter({
    request,
    proxy: {
      internalServiceAuthSecret: 'router-internal-secret',
      async fetch(input) {
        forwarded = input;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'server-timing': 'router;dur=12',
          },
        });
      },
    },
  });

  expect(forwarded).not.toBeNull();
  if (!forwarded) throw new Error('expected MPC Router request');
  expect(forwarded.url).toBe(request.url);
  expect(forwarded.method).toBe('POST');
  expect(forwarded.headers.get('authorization')).toBe('Bearer wallet-session-jwt');
  expect(forwarded.headers.get('origin')).toBe('https://sign.example');
  expect(forwarded.headers.get('cf-connecting-ip')).toBe('203.0.113.17');
  expect(forwarded.headers.get('cf-ray')).toBe('ray-id-NRT');
  expect(forwarded.headers.get('x-seams-trace-id')).toBe('trace-correlation-1');
  expect(forwarded.headers.get('x-router-ab-internal-service-auth')).toBe(
    'router-internal-secret',
  );
  expect(await forwarded.json()).toEqual({ request_id: 'request-1' });
  expect(response.status).toBe(200);
  expect(response.headers.get('server-timing')).toBe('router;dur=12');
  await expect(response.json()).resolves.toEqual({ ok: true });
});

test('normal-signing proxy fails closed when MPC Router transport is absent', async () => {
  const response = await proxyNormalSigningRequestToMpcRouter({
    request: new Request('https://gateway.example/router-ab/ed25519/sign', {
      method: 'POST',
      body: '{}',
    }),
    proxy: null,
  });

  expect(response.status).toBe(501);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'not_configured',
  });
});

test('Ed25519 SigningWorker in-progress conflict remains non-terminal at the Gateway', () => {
  expect(
    isRouterAbEd25519OperationInProgressResponse({
      status: 409,
      bodyText:
        'ReplayedLocalRequest: SigningWorker normal-signing effect is already in progress',
    }),
  ).toBe(true);
  expect(
    isRouterAbEd25519OperationInProgressResponse({
      status: 409,
      bodyText: 'ConflictingPair: SigningWorker request conflicts with existing work',
    }),
  ).toBe(false);
});

test('normal-signing proxy forwards the trusted body selected by the gateway', async () => {
  let forwardedBody: unknown = null;
  const request = new Request('https://gateway.example/router-ab/ed25519/sign', {
    method: 'POST',
    headers: { authorization: 'Bearer wallet-session-jwt' },
    body: JSON.stringify({ authorization_claim: { kind: 'untrusted' } }),
  });
  const response = await proxyNormalSigningRequestToMpcRouter({
    request,
    body: {
      authorization_claim: {
        kind: 'reusable_wallet_session_operation_claim_v1',
        use_id: 'use-1',
      },
    },
    proxy: {
      internalServiceAuthSecret: 'router-internal-secret',
      async fetch(input) {
        forwardedBody = await input.json();
        return Response.json({ ok: true });
      },
    },
  });

  expect(response.status).toBe(200);
  expect(forwardedBody).toEqual({
    authorization_claim: {
      kind: 'reusable_wallet_session_operation_claim_v1',
      use_id: 'use-1',
    },
  });
});

test('wallet-budget status is read from Router private D1 without Gateway session storage', async () => {
  let forwarded: Request | null = null;
  const request = new Request('https://gateway.example/router-ab/wallet-budget/status', {
    method: 'POST',
    headers: {
      authorization: 'Bearer wallet-session-jwt',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ signingGrantId: 'grant-1', thresholdSessionId: 'session-1' }),
  });
  const response = await handleSigningBudgetStatus({
    method: 'POST',
    pathname: '/router-ab/wallet-budget/status',
    request,
    opts: {
      routerAbNormalSigningRouterProxy: {
        internalServiceAuthSecret: 'router-internal-secret',
        async fetch(input) {
          forwarded = input;
          return Response.json({
            ok: true,
            signingGrantId: 'grant-1',
            thresholdSessionId: 'session-1',
            status: 'active',
            remainingUses: 3,
          });
        },
      },
    },
  } as CloudflareRouterApiContext);

  expect(response).not.toBeNull();
  if (!response || !forwarded) throw new Error('expected Router budget-status response');
  expect(forwarded.headers.get('authorization')).toBe('Bearer wallet-session-jwt');
  await expect(forwarded.json()).resolves.toEqual({
    signingGrantId: 'grant-1',
    thresholdSessionId: 'session-1',
  });
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    status: 'active',
    remainingUses: 3,
  });
});
