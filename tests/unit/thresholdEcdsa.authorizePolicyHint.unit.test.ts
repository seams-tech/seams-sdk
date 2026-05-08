import { expect, test } from '@playwright/test';
import { authorizeEcdsaWithSession } from '@/core/signingEngine/threshold/ecdsa/authorize';

async function withMockedFetch<T>(mockFetch: typeof fetch, run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = mockFetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test.describe('threshold ECDSA authorize policy hint parsing', () => {
  test('returns optional presign pool policy hint when present', async () => {
    const mockFetch = (async () =>
      new Response(
        JSON.stringify({
          ok: true,
          mpcSessionId: 'mpc-1',
          expiresAt: '2030-01-01T00:00:00.000Z',
          presignPoolPolicy: {
            enabled: true,
            targetDepth: 3,
            lowWatermark: 1,
            maxRefillInFlight: 2,
            refillAttemptTimeoutMs: 45000,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )) as typeof fetch;

    await withMockedFetch(mockFetch, async () => {
      const result = await authorizeEcdsaWithSession({
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-hss-key-1',
        purpose: 'tempoTransaction',
        signingDigest32: new Uint8Array(32),
        sessionKind: 'cookie',
      });

      expect(result.ok).toBe(true);
      expect(result.mpcSessionId).toBe('mpc-1');
      expect(result.presignPoolPolicy).toEqual({
        enabled: true,
        targetDepth: 3,
        lowWatermark: 1,
        maxRefillInFlight: 2,
        refillAttemptTimeoutMs: 45000,
      });
    });
  });

  test('ignores invalid policy hint payloads', async () => {
    const mockFetch = (async () =>
      new Response(
        JSON.stringify({
          ok: true,
          mpcSessionId: 'mpc-2',
          presignPoolPolicy: {
            enabled: 'yes',
            targetDepth: '2',
            lowWatermark: null,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )) as typeof fetch;

    await withMockedFetch(mockFetch, async () => {
      const result = await authorizeEcdsaWithSession({
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-hss-key-1',
        purpose: 'tempoTransaction',
        signingDigest32: new Uint8Array(32),
        sessionKind: 'cookie',
      });

      expect(result.ok).toBe(true);
      expect(result.mpcSessionId).toBe('mpc-2');
      expect(result.presignPoolPolicy).toBeUndefined();
    });
  });
});
