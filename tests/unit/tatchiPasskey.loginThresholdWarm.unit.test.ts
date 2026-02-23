import { expect, test } from '@playwright/test';
import { loginAndCreateSession } from '@/core/TatchiPasskey/login';
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
      scheduleThresholdEcdsaLoginPresignPrefill: async () => ({
        status: 'scheduled',
        reason: 'scheduled',
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
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        scheduleThresholdEcdsaLoginPresignPrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });
    const result = await withMockedMostRecentProjection(async () =>
      await loginAndCreateSession(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect('thresholdEcdsaKeyRef' in (result as unknown as Record<string, unknown>)).toBe(false);
    expect(prefillCalls).toBe(0);
  });

  test('fails closed when threshold warm-up returns incomplete session material', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    let prefillCalls = 0;
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
        scheduleThresholdEcdsaLoginPresignPrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });

    const result = await withMockedMostRecentProjection(async () =>
      await loginAndCreateSession(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('valid threshold session keyRef');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
    expect(prefillCalls).toBe(0);
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

    const result = await withMockedMostRecentProjection(async () =>
      await loginAndCreateSession(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(prefillCalls).toBe(0);
    expect(prefillArgs).toBeNull();
  });
});
