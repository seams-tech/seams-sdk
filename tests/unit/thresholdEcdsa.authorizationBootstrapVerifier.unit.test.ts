import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/workflows/bootstrapEcdsaSession';

test.describe('threshold-ecdsa authorization bootstrap request shape', () => {
  test('authorization bootstrap prepares without sending an explicit verifier hint', async () => {
    const requests: Array<{ url: string; body: Record<string, unknown>; headers: Headers }> = [];
    const originalFetch = globalThis.fetch;
    const clientRootShare32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const clientRootShare32B64u = base64UrlEncode(clientRootShare32);

    globalThis.fetch = async (input, init) => {
      const url = String(input);
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      requests.push({
        url,
        body,
        headers: new Headers(init?.headers || {}),
      });
      return new Response(
        JSON.stringify({
          ok: false,
          code: 'unauthorized',
          message: 'stop after prepare',
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    };

    try {
      const result = await bootstrapEcdsaSession({
        indexedDB: {} as any,
        touchIdPrompt: {
          getRpId: () => 'wallet.example.test',
        } as any,
        relayerUrl: 'https://relay.example',
        userId: 'alice.testnet',
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-1',
        bootstrapAuth: { kind: 'app_session', jwt: 'app-session-jwt' },
        clientRootShare32B64u,
        workerCtx: {
          requestWorkerOperation: async () => {
            throw new Error('authorization bootstrap should not derive a local verifier hint');
          },
        },
      });

      expect(result.ok).toBe(false);
      expect(result.code).toBe('unauthorized');
      expect(requests).toHaveLength(1);
      expect(requests[0]?.url).toBe('https://relay.example/threshold-ecdsa/hss/prepare');
      expect(requests[0]?.headers.get('Authorization')).toBe('Bearer app-session-jwt');
      expect(requests[0]?.body).toMatchObject({
        userId: 'alice.testnet',
        rpId: 'wallet.example.test',
        operation: 'session_bootstrap',
        ecdsaThresholdKeyId: 'ecdsa-key-1',
      });
      expect(Object.prototype.hasOwnProperty.call(requests[0]?.body || {}, 'expectedClientVerifyingShareB64u')).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
