import { expect, test } from '@playwright/test';
import { unlock } from '@/core/TatchiPasskey/login';
import { IndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';

const ACCOUNT_ID = toAccountId('alice.testnet');

function createBaseContext(args?: {
  signingEngine?: Record<string, unknown>;
  configs?: Record<string, unknown>;
}): any {
  const now = Date.now();
  return {
    signingEngine: {
      assertSealedRefreshStartupParity: async () => undefined,
      getUserByDevice: async () => ({
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        clientNearPublicKey: 'ed25519:alice',
      }),
      getLastUser: async () => ({
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        clientNearPublicKey: 'ed25519:alice',
      }),
      getAuthenticatorsByUser: async () => [{ credentialId: 'cred-1', deviceNumber: 1 }],
      connectEd25519Session: async () => ({
        ok: true,
        sessionId: 'session-1',
        jwt: 'jwt-ed25519',
        remainingUses: 3,
        expiresAtMs: now + 60_000,
        ecdsaClientVerifyingShareB64u: 'AQ',
      }),
      bootstrapEcdsaSession: async () => ({
        thresholdEcdsaKeyRef: {
          type: 'threshold-ecdsa-secp256k1',
          userId: 'alice.testnet',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          clientVerifyingShareB64u: 'AQ',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'session-1',
          thresholdSessionJwt: 'jwt-ecdsa',
        },
        keygen: {
          ok: true,
          relayerKeyId: 'rk-1',
          clientVerifyingShareB64u: 'AQ',
          participantIds: [1, 2],
        },
        session: {
          ok: true,
          sessionId: 'session-1',
          jwt: 'jwt-ecdsa',
          remainingUses: 3,
          expiresAtMs: now + 60_000,
          clientVerifyingShareB64u: 'AQ',
        },
      }),
      clearWarmSigningSessions: async () => undefined,
      getWarmSigningSessionStatus: async () => ({
        sessionId: 'session-1',
        status: 'active',
        remainingUses: 3,
        expiresAtMs: now + 60_000,
        createdAtMs: now,
      }),
      scheduleThresholdEcdsaLoginPresignPrefill: async () => ({
        status: 'scheduled',
        reason: 'scheduled',
      }),
      setLastUser: async () => undefined,
      updateLastLogin: async () => undefined,
      ...(args?.signingEngine || {}),
    },
    configs: {
      signing: {
        mode: { mode: 'threshold-signer' },
        sessionDefaults: { ttlMs: 60_000, remainingUses: 3 },
      },
      network: {
        relayer: { url: 'https://relay.example' },
      },
      ...(args?.configs || {}),
    },
  };
}

async function withMockedMostRecentProjection<T>(fn: () => Promise<T>): Promise<T> {
  const clientDb = IndexedDBManager.clientDB as { getMostRecentNearAccountProjection?: unknown };
  const nearDb = IndexedDBManager as { getNearThresholdKeyMaterial?: unknown };
  const original = clientDb.getMostRecentNearAccountProjection;
  const originalThreshold = nearDb.getNearThresholdKeyMaterial;
  clientDb.getMostRecentNearAccountProjection = async () => null;
  nearDb.getNearThresholdKeyMaterial = async () => ({
    kind: 'threshold_ed25519_2p_v1',
    publicKey: 'ed25519:threshold',
    relayerKeyId: 'rk-1',
    participants: [{ id: 1 }, { id: 2 }],
    wrapKeySalt: 'AQ',
  });
  try {
    return await fn();
  } finally {
    clientDb.getMostRecentNearAccountProjection = original;
    nearDb.getNearThresholdKeyMaterial = originalThreshold;
  }
}

test.describe('unlock threshold warm-session requirements', () => {
  test('returns active signingSession in threshold-signer warm mode', async () => {
    let bootstrapCalls = 0;
    let bootstrapArgs: Record<string, unknown> | null = null;
    const bootstrapChains: string[] = [];
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs = args;
          bootstrapChains.push(String(args.chain || ''));
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              thresholdSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
        scheduleThresholdEcdsaLoginPresignPrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });
    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect('thresholdEcdsaKeyRef' in (result as unknown as Record<string, unknown>)).toBe(false);
    expect(bootstrapCalls).toBe(2);
    expect(bootstrapChains).toEqual(['tempo', 'evm']);
    expect(String(bootstrapArgs?.['source'] || '')).toBe('login');
    expect(String(bootstrapArgs?.['sessionId'] || '')).toBe('session-1');
    expect(String(bootstrapArgs?.['authorizationJwt'] || '')).toBe('jwt-ed25519');
    expect(String(bootstrapArgs?.['clientVerifyingShareB64u'] || '')).toBe('AQ');
    expect(prefillCalls).toBe(0);
  });

  test('fails closed when threshold warm-up cannot connect Ed25519 session', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    let bootstrapCalls = 0;
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => ({
          ok: false,
          code: 'unauthorized',
          message: 'session bootstrap rejected',
        }),
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called');
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
        scheduleThresholdEcdsaLoginPresignPrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold Ed25519 warm-up failed');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
    expect(bootstrapCalls).toBe(0);
    expect(prefillCalls).toBe(0);
  });

  test('fails closed when threshold warm-up cannot bootstrap ECDSA session', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async () => {
          throw new Error('ecdsa bootstrap rejected');
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold ECDSA warm-up failed');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
  });

  test('login does not invoke ECDSA presign prefill automatically', async () => {
    let prefillCalls = 0;
    let prefillArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        scheduleThresholdEcdsaLoginPresignPrefill: async (args: Record<string, unknown>) => {
          prefillCalls += 1;
          prefillArgs = args;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(prefillCalls).toBe(0);
    expect(prefillArgs).toBeNull();
  });

  test('fails closed when one-prompt ECDSA bootstrap share is unavailable', async () => {
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => ({
          ok: true,
          sessionId: 'session-1',
          jwt: 'jwt-ed25519',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        }),
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain(
      'threshold ECDSA warm-up missing clientVerifyingShareB64u',
    );
    expect(bootstrapCalls).toBe(0);
  });

  test('login warm-up reuses canonical ECDSA threshold session id when available', async () => {
    let capturedConnectArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        getThresholdEcdsaSessionRecordForSigning: (_args: { chain: 'tempo' | 'evm' }) => ({
          thresholdSessionId: 'canonical-ecdsa-session-1',
          clientVerifyingShareB64u: 'AQ',
        }),
        connectEd25519Session: async (args: Record<string, unknown>) => {
          capturedConnectArgs = args;
          return {
            ok: true,
            sessionId: 'canonical-ecdsa-session-1',
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(capturedConnectArgs).not.toBeNull();
    expect(String(capturedConnectArgs?.['sessionId'] || '')).toBe('canonical-ecdsa-session-1');
  });

  test('fails fast when /session/exchange route is requested without session.exchange payload', async () => {
    const context = createBaseContext();

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          session: {
            kind: 'jwt',
            route: '/session/exchange',
          },
        }),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('session.exchange is required');
  });

  test('fails fast when server session is requested without exchange payload', async () => {
    const context = createBaseContext();

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          session: {
            kind: 'jwt',
          },
        }),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('session.exchange is required');
  });

  test('supports one-step passkey_assertion session exchange', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/options') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-1',
              challengeB64u: 'challenge-passkey-b64u-1',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-1',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: 'prf-first',
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            mode: { mode: 'local-signer' },
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-passkey-1');
      expect(captured).toHaveLength(2);
      expect(captured[0]!.url).toBe('https://relay.example/wallet/unlock/options');
      expect(captured[1]!.url).toBe('https://relay.example/session/exchange');

      const unlockOptionsBody = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      expect(unlockOptionsBody.user_id).toBe('alice.testnet');
      expect(unlockOptionsBody.rp_id).toBe('example.localhost');

      const exchangeBody = JSON.parse(String(captured[1]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      const exchange = (exchangeBody.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.challengeId).toBe('challenge-passkey-1');
      const credential = (exchange.webauthn_authentication || {}) as Record<string, unknown>;
      expect(credential.clientExtensionResults).toBeNull();
      expect(
        ((credential.response || {}) as Record<string, unknown>).clientExtensionResults,
      ).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('forwards passkey_assertion expectedOrigin override to session exchange', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/options') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-2',
              challengeB64u: 'challenge-passkey-b64u-2',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-2',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-2',
            rawId: 'cred-2',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: 'prf-first',
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            mode: { mode: 'local-signer' },
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: {
                type: 'passkey_assertion',
                expectedOrigin: 'https://wallet.example.localhost',
              },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-passkey-2');
      expect(captured).toHaveLength(2);

      const exchangeBody = JSON.parse(String(captured[1]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      const exchange = (exchangeBody.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.expected_origin).toBe('https://wallet.example.localhost');
      expect(captured[1]!.init?.credentials).toBe('omit');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('supports cookie-mode passkey_assertion exchange with include credentials', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/options') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-cookie',
              challengeB64u: 'challenge-passkey-cookie-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-cookie',
            rawId: 'cred-cookie',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: 'prf-first',
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            mode: { mode: 'local-signer' },
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'cookie',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBeUndefined();
      expect(captured).toHaveLength(2);
      expect(captured[1]!.url).toBe('https://relay.example/session/exchange');
      expect(captured[1]!.init?.credentials).toBe('include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
