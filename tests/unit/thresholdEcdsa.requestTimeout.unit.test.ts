import { expect, test } from '@playwright/test';
import { authorizeEcdsaWithSession } from '@/core/signingEngine/threshold/workflows/authorizeEcdsa';
import { ecdsaPresignInit } from '@/core/signingEngine/threshold/workflows/signEcdsa';

function createHangingAbortableFetch(): typeof fetch {
  return (async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    await new Promise<never>((_, reject) => {
      const signal = init?.signal;
      if (signal?.aborted) {
        reject(new Error('aborted'));
        return;
      }
      if (signal && typeof signal.addEventListener === 'function') {
        signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      }
    });
    throw new Error('unreachable');
  }) as typeof fetch;
}

async function withMockedFetch<T>(mockFetch: typeof fetch, run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = mockFetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test.describe('threshold ECDSA request timeout guards', () => {
  test('authorize returns network_error with timeout message', async () => {
    await withMockedFetch(createHangingAbortableFetch(), async () => {
      const result = await authorizeEcdsaWithSession({
        relayerUrl: 'https://relay.example.invalid',
        ecdsaThresholdKeyId: 'ecdsa-hss-key-1',
        purpose: 'tempoTransaction',
        signingDigest32: new Uint8Array(32).fill(7),
        sessionKind: 'cookie',
        requestTimeoutMs: 25,
      });

      expect(result.ok).toBe(false);
      expect(result.code).toBe('network_error');
      expect(String(result.message || '')).toMatch(/timed out/i);
    });
  });

  test('presign init returns network_error with timeout message', async () => {
    await withMockedFetch(createHangingAbortableFetch(), async () => {
      const result = await ecdsaPresignInit({
        relayerUrl: 'https://relay.example.invalid',
        ecdsaThresholdKeyId: 'ecdsa-hss-key-1',
        sessionKind: 'cookie',
        requestTimeoutMs: 25,
      });

      expect(result.ok).toBe(false);
      expect(result.code).toBe('network_error');
      expect(String(result.message || '')).toMatch(/timed out/i);
    });
  });
});
