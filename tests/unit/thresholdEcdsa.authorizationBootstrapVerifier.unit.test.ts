import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/workflows/bootstrapEcdsaSession';

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('threshold-ecdsa authorization bootstrap request shape', () => {
  test('authorization bootstrap prepares without sending an explicit verifier hint', async () => {
    const requests: Array<{ url: string; body: Record<string, unknown>; headers: Headers }> = [];
    const originalFetch = globalThis.fetch;
    const clientRootShare32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const clientRootShare32B64u = base64UrlEncode(clientRootShare32);
    const appSessionJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

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
        walletSigningSessionId: 'wallet-session-1',
        bootstrapAuth: { kind: 'app_session', jwt: appSessionJwt },
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
      expect(requests[0]?.headers.get('Authorization')).toBe(`Bearer ${appSessionJwt}`);
      expect(requests[0]?.body).toMatchObject({
        walletSessionUserId: 'alice.testnet',
        rpId: 'wallet.example.test',
        operation: 'session_bootstrap',
        ecdsaThresholdKeyId: 'ecdsa-key-1',
      });
      expect(Object.prototype.hasOwnProperty.call(requests[0]?.body || {}, 'expectedClientVerifyingShareB64u')).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('authorization bootstrap does not spend managed registration grants on unlock warm-up', async () => {
    const requests: string[] = [];
    const originalFetch = globalThis.fetch;
    const clientRootShare32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const clientRootShare32B64u = base64UrlEncode(clientRootShare32);
    const appSessionJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    globalThis.fetch = async (input, init) => {
      const url = String(input);
      requests.push(url);
      return new Response(
        JSON.stringify({
          ok: false,
          code: 'unauthorized',
          message: 'stop after first network boundary',
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    };

    try {
      await bootstrapEcdsaSession({
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
        walletSigningSessionId: 'wallet-session-1',
        bootstrapAuth: { kind: 'app_session', jwt: appSessionJwt },
        runtimeScopeBootstrap: {
          environmentId: 'env-test',
          publishableKey: 'pk_test_should_not_be_spent',
        },
        clientRootShare32B64u,
        workerCtx: {
          requestWorkerOperation: async () => {
            throw new Error('authorization bootstrap should not derive a local verifier hint');
          },
        },
      });

      expect(requests.some((url) => url.includes('/v1/registration/bootstrap-grants'))).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
