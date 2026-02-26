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
      connectEd25519Session: async () => ({
        ok: true,
        sessionId: 'session-1',
        jwt: 'jwt-ed25519',
        remainingUses: 3,
        expiresAtMs: now + 60_000,
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
      signerMode: { mode: 'threshold-signer' },
      signingSessionDefaults: { ttlMs: 60_000, remainingUses: 3 },
      relayer: { url: 'https://relay.example' },
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

  test('fails closed when threshold warm-up cannot connect Ed25519 session', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => ({
          ok: false,
          code: 'unauthorized',
          message: 'session bootstrap rejected',
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
    expect(String(result.error || '')).toContain('threshold Ed25519 warm-up failed');
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

  test('login warm-up reuses canonical ECDSA threshold session id when available', async () => {
    let capturedConnectArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        getThresholdEcdsaSessionRecordForSigning: () => ({
          thresholdSessionId: 'canonical-ecdsa-session-1',
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

    const result = await withMockedMostRecentProjection(async () =>
      await loginAndCreateSession(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(capturedConnectArgs).not.toBeNull();
    expect(String(capturedConnectArgs?.['sessionId'] || '')).toBe('canonical-ecdsa-session-1');
  });
});
