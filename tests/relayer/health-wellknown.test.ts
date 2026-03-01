import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, getPath, makeFakeAuthService, startExpressRouter } from './helpers';

function createStubPrfSessionSealOptionsWithCapabilities() {
  return {
    enabled: false,
    capabilities: {
      mode: 'sealed_refresh_v1' as const,
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
    },
    service: {
      applyServerSeal: async () => ({ ok: false as const, code: 'not_implemented', message: 'n/a' }),
      removeServerSeal: async () =>
        ({ ok: false as const, code: 'not_implemented', message: 'n/a' }),
    },
  };
}

test.describe('relayer health/ready + well-known', () => {
  test('express: GET /healthz includes threshold hints when enabled', async () => {
    const service = makeFakeAuthService({ getThresholdSigningService: () => ({}) as any });
    const router = createRelayRouter(service, { healthz: true, readyz: true });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/healthz`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(getPath(res.json, 'thresholdEd25519', 'configured')).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('express: GET /readyz returns 200 when relayer account is available', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { readyz: true });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/readyz`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('express: GET /readyz returns 503 when relayer account check fails', async () => {
    const service = makeFakeAuthService({
      getRelayerAccount: async () => {
        throw new Error('relayer not reachable');
      },
    });
    const router = createRelayRouter(service, { readyz: true });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/readyz`, { method: 'GET' });
      expect(res.status).toBe(503);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('relayer_unavailable');
    } finally {
      await srv.close();
    }
  });

  test('express: GET /.well-known/webauthn sets Cache-Control and returns origins', async () => {
    const calls: Array<{ rpId: string; host?: string }> = [];
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      ror: {
        rpId: 'wallet.example.localhost',
        provider: {
          getAllowedOrigins: async (input) => {
            calls.push(input);
            return [
              'https://wallet.example.localhost',
              'https://wallet.example.localhost',
              'http://invalid.example.localhost',
              'https://example.localhost',
            ];
          },
        },
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/.well-known/webauthn`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.headers.get('cache-control')).toContain('max-age=60');
      expect(res.json?.origins).toEqual([
        'https://wallet.example.localhost',
        'https://example.localhost',
      ]);
      expect((res.json?.capabilities as any)?.signingSessionSeal).toEqual({ mode: 'none' });
      expect(calls.length).toBe(1);
      expect(calls[0]).toEqual({ rpId: 'wallet.example.localhost', host: '127.0.0.1' });
    } finally {
      await srv.close();
    }
  });

  test('express: well-known includes sealed refresh capabilities when PRF seal is configured', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      prfSessionSeal: createStubPrfSessionSealOptionsWithCapabilities() as any,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/.well-known/webauthn`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect((res.json?.capabilities as any)?.signingSessionSeal).toEqual({
        mode: 'sealed_refresh_v1',
        keyVersion: 'kek-s-2026-02',
        shamirPrimeB64u: 'AQAB',
      });
    } finally {
      await srv.close();
    }
  });

  test('cloudflare: GET /healthz includes cors.allowedOrigins when enabled', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      healthz: true,
      corsOrigins: ['https://example.localhost'],
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/healthz',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
    expect(getPath(res.json, 'cors', 'allowedOrigins')).toEqual(['https://example.localhost']);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-allow-credentials')).toBe(null);
  });

  test('cloudflare: GET /readyz returns 200 when relayer account is available', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      readyz: true,
      corsOrigins: ['https://example.localhost'],
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/readyz',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);
  });

  test('cloudflare: GET /readyz returns 503 when relayer account check fails', async () => {
    const service = makeFakeAuthService({
      getRelayerAccount: async () => {
        throw new Error('relayer not reachable');
      },
    });
    const handler = createCloudflareRouter(service, {
      readyz: true,
      corsOrigins: ['https://example.localhost'],
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/readyz',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(503);
    expect(res.json?.ok).toBe(false);
    expect(res.json?.code).toBe('relayer_unavailable');
  });

  test('cloudflare: GET /.well-known/webauthn resolves rpId from host mapping and sets Cache-Control', async () => {
    const calls: Array<{ rpId: string; host?: string }> = [];
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      ror: {
        rpIdByHost: {
          'relay.test': 'wallet.example.localhost',
        },
        provider: {
          getAllowedOrigins: async (input) => {
            calls.push(input);
            return ['https://example.localhost'];
          },
        },
      },
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/.well-known/webauthn',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toContain('max-age=60');
    expect(res.json?.origins).toEqual(['https://example.localhost']);
    expect((res.json?.capabilities as any)?.signingSessionSeal).toEqual({ mode: 'none' });
    expect(calls.length).toBe(1);
    expect(calls[0]).toEqual({ rpId: 'wallet.example.localhost', host: 'relay.test' });
  });

  test('cloudflare: well-known includes sealed refresh capabilities when PRF seal is configured', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, {
      prfSessionSeal: createStubPrfSessionSealOptionsWithCapabilities() as any,
    });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/.well-known/webauthn',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(200);
    expect((res.json?.capabilities as any)?.signingSessionSeal).toEqual({
      mode: 'sealed_refresh_v1',
      keyVersion: 'kek-s-2026-02',
      shamirPrimeB64u: 'AQAB',
    });
  });
});
