import { expect, test } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
} from '@shared/utils/routerAbPublicKeyset';
import { callCf, fetchJson, makeFakeAuthService, startExpressRouter } from './helpers';

const ROUTER_AB_PUBLIC_KEYSET = parseRouterAbPublicKeysetV2({
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: 'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: {
      role: 'signer_a',
      verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    },
    deriver_b: {
      role: 'signer_b',
      verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'epoch-server',
    public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
  },
});

const ALLOWED_ORIGIN = 'https://app.example';

test.describe('Router A/B public keyset routes', () => {
  test('express: configured keyset is browser-readable with cache headers', async () => {
    const router = createRelayRouter(makeFakeAuthService(), {
      corsOrigins: [ALLOWED_ORIGIN],
      routerAbPublicKeyset: ROUTER_AB_PUBLIC_KEYSET,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/router-ab/keyset`, {
        method: 'GET',
        headers: { Origin: ALLOWED_ORIGIN },
      });
      expect(res.status).toBe(200);
      expect(res.json).toEqual(ROUTER_AB_PUBLIC_KEYSET);
      expect(res.headers.get('content-type')).toContain('application/json');
      expect(res.headers.get('cache-control')).toBe('max-age=60, stale-while-revalidate=600');
      expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
      expect(res.headers.get('vary')).toContain('Origin');

      const preflight = await fetchJson(`${srv.baseUrl}/v2/router-ab/keyset`, {
        method: 'OPTIONS',
        headers: {
          Origin: ALLOWED_ORIGIN,
          'Access-Control-Request-Method': 'GET',
        },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
      expect(preflight.headers.get('access-control-allow-methods')).toContain('GET');
    } finally {
      await srv.close();
    }
  });

  test('express: missing keyset returns browser-readable 404', async () => {
    const router = createRelayRouter(makeFakeAuthService(), {
      corsOrigins: [ALLOWED_ORIGIN],
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v2/router-ab/keyset`, {
        method: 'GET',
        headers: { Origin: ALLOWED_ORIGIN },
      });
      expect(res.status).toBe(404);
      expect(res.json?.code).toBe('router_ab_public_keyset_not_configured');
      expect(res.headers.get('content-type')).toContain('application/json');
      expect(res.headers.get('cache-control')).toBe('max-age=60, stale-while-revalidate=600');
      expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
    } finally {
      await srv.close();
    }
  });

  test('cloudflare self-host: configured keyset is browser-readable with cache headers', async () => {
    const handler = createCloudflareRouter(makeFakeAuthService(), {
      corsOrigins: [ALLOWED_ORIGIN],
      routerAbPublicKeyset: ROUTER_AB_PUBLIC_KEYSET,
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/.well-known/router-ab/keyset',
      origin: ALLOWED_ORIGIN,
    });
    expect(res.status).toBe(200);
    expect(res.json).toEqual(ROUTER_AB_PUBLIC_KEYSET);
    expect(res.headers.get('content-type')).toContain('application/json');
    expect(res.headers.get('cache-control')).toBe('max-age=60, stale-while-revalidate=600');
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
    expect(res.headers.get('vary')).toContain('Origin');

    const preflight = await callCf(handler, {
      method: 'OPTIONS',
      path: '/.well-known/router-ab/keyset',
      origin: ALLOWED_ORIGIN,
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
    expect(preflight.headers.get('access-control-allow-methods')).toContain('GET');
  });

  test('cloudflare self-host: missing keyset returns browser-readable 404', async () => {
    const handler = createCloudflareRouter(makeFakeAuthService(), {
      corsOrigins: [ALLOWED_ORIGIN],
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/v2/router-ab/keyset',
      origin: ALLOWED_ORIGIN,
    });
    expect(res.status).toBe(404);
    expect(res.json?.code).toBe('router_ab_public_keyset_not_configured');
    expect(res.headers.get('content-type')).toContain('application/json');
    expect(res.headers.get('cache-control')).toBe('max-age=60, stale-while-revalidate=600');
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
  });
});
