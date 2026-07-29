import { expect, test } from '@playwright/test';
import { proxyNormalSigningRequestToMpcRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/routes/normalSigningRouterProxy';

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
    },
    body: JSON.stringify({ request_id: 'request-1' }),
  });

  const response = await proxyNormalSigningRequestToMpcRouter({
    request,
    proxy: {
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
