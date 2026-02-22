import { expect, test } from '@playwright/test';
import { loginAndCreateSession } from '@/core/TatchiPasskey/login';
import { IndexedDBManager } from '@/core/indexedDB';

function createBaseContext(args?: {
  signingEngine?: Record<string, unknown>;
  configs?: Record<string, unknown>;
}): any {
  const now = Date.now();
  return {
    signingEngine: {
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
      bootstrapEcdsaSession: async () => ({
        thresholdEcdsaKeyRef: {
          type: 'threshold-ecdsa-secp256k1',
          userId: 'alice.testnet',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          clientVerifyingShareB64u: 'AQ',
          thresholdSessionId: 'session-1',
          thresholdSessionJwt: 'jwt-1',
          participantIds: [1, 2],
        },
      }),
      getWarmSigningSessionStatus: async () => ({
        sessionId: 'session-1',
        status: 'active',
        remainingUses: 3,
        expiresAtMs: now + 60_000,
        createdAtMs: now,
      }),
      setLastUser: async () => undefined,
      updateLastLogin: async () => undefined,
      ...(args?.signingEngine || {}),
    },
    configs: {
      signerMode: { mode: 'threshold-signer' },
      signingSessionDefaults: { ttlMs: 60_000, remainingUses: 3 },
      relayer: { url: 'https://relay.example' },
      ...(args?.configs || {}),
    },
  };
}

async function withMockedMostRecentProjection<T>(fn: () => Promise<T>): Promise<T> {
  const clientDb = IndexedDBManager.clientDB as { getMostRecentNearAccountProjection?: unknown };
  const original = clientDb.getMostRecentNearAccountProjection;
  clientDb.getMostRecentNearAccountProjection = async () => null;
  try {
    return await fn();
  } finally {
    clientDb.getMostRecentNearAccountProjection = original;
  }
}

test.describe('loginAndCreateSession threshold warm-session requirements', () => {
  test('returns active signingSession in threshold-signer warm mode', async () => {
    const result = await withMockedMostRecentProjection(async () =>
      await loginAndCreateSession(createBaseContext(), 'alice.testnet'),
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect('thresholdEcdsaKeyRef' in (result as Record<string, unknown>)).toBe(false);
  });

  test('fails closed when threshold warm-up returns incomplete session material', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async () => ({
          thresholdEcdsaKeyRef: {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
            thresholdSessionId: 'session-1',
            thresholdSessionJwt: '',
            participantIds: [1, 2],
          },
        }),
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(async () =>
      await loginAndCreateSession(context, 'alice.testnet'),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('valid threshold session keyRef');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
  });
});
