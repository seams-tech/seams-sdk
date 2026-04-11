import { expect, test } from '@playwright/test';
import {
  assertThresholdSigningSessionReady,
  isThresholdSigningSessionReady,
  readThresholdSigningSessionReadiness,
  resolveThresholdSigningAuthMode,
  THRESHOLD_SESSION_EXHAUSTED_ERROR,
  THRESHOLD_SESSION_MISSING_ERROR,
} from '@/core/signingEngine/orchestration/shared/thresholdSigningSessionPlanner';

test.describe('threshold signing session planner', () => {
  test('asserts ready when warm session cache is available', async () => {
    const ready = await assertThresholdSigningSessionReady({
      nearAccountId: 'planner.testnet',
      chain: 'evm',
      sessionId: 'session-1',
      usesNeeded: 2,
      warmSessionManager: {
        assertEcdsaSigningSessionReady: async () => ({
          ok: true,
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        }),
      },
    });

    expect(ready.ok).toBe(true);
    expect(ready.remainingUses).toBe(3);
  });

  test('fails with canonical missing-session error when sessionId is absent', async () => {
    await expect(
      assertThresholdSigningSessionReady({
        nearAccountId: 'planner.testnet',
        chain: 'evm',
        sessionId: '',
        warmSessionManager: {
          assertEcdsaSigningSessionReady: async () => {
            throw new Error('should not be called');
          },
        },
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_MISSING_ERROR);
  });

  test('fails with canonical exhausted error when remaining uses are insufficient', async () => {
    await expect(
      assertThresholdSigningSessionReady({
        nearAccountId: 'planner.testnet',
        chain: 'evm',
        sessionId: 'session-1',
        usesNeeded: 3,
        warmSessionManager: {
          assertEcdsaSigningSessionReady: async () => {
            throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
          },
        },
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_EXHAUSTED_ERROR);
  });

  test('normalizes cache miss errors to canonical reconnect message', async () => {
    await expect(
      assertThresholdSigningSessionReady({
        nearAccountId: 'planner.testnet',
        chain: 'evm',
        sessionId: 'session-1',
        warmSessionManager: {
          assertEcdsaSigningSessionReady: async () => {
            throw new Error(
              '[chains] threshold signingSession is not_found; reconnect threshold session before signing',
            );
          },
        },
      }),
    ).rejects.toThrow(
      '[chains] threshold signingSession is not_found; reconnect threshold session before signing',
    );
  });

  test('returns webauthn auth mode without touching warm-session cache when explicitly required', async () => {
    let statusReadCalls = 0;
    const authMode = await resolveThresholdSigningAuthMode({
      needsWebAuthn: true,
      sessionId: '',
      touchConfirm: {
        getWarmSessionStatus: async () => {
          statusReadCalls += 1;
          return { ok: false, code: 'not_found', message: 'na' } as const;
        },
      },
    });

    expect(authMode).toBe('webauthn');
    expect(statusReadCalls).toBe(0);
  });

  test('returns warm-session auth mode when cache is ready', async () => {
    const authMode = await resolveThresholdSigningAuthMode({
      needsWebAuthn: false,
      sessionId: 'session-1',
      touchConfirm: {
        getWarmSessionStatus: async () => ({
          ok: true,
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        }),
      },
    });

    expect(authMode).toBe('warmSession');
  });

  test('returns warm-session auth mode without pre-confirm warm-cache check', async () => {
    let statusReadCalls = 0;
    const authMode = await resolveThresholdSigningAuthMode({
      needsWebAuthn: false,
      sessionId: '',
      touchConfirm: {
        getWarmSessionStatus: async () => {
          statusReadCalls += 1;
          return {
            ok: false,
            code: 'not_found',
            message: 'missing',
          } as const;
        },
      },
    });

    expect(authMode).toBe('warmSession');
    expect(statusReadCalls).toBe(0);
  });

  test('readiness helper is false when session id is blank', async () => {
    let statusReadCalls = 0;
    const ready = await isThresholdSigningSessionReady({
      sessionId: '',
      touchConfirm: {
        getWarmSessionStatus: async () => {
          statusReadCalls += 1;
          return { ok: true, remainingUses: 5, expiresAtMs: Date.now() + 60_000 } as const;
        },
      },
    });

    expect(ready).toBe(false);
    expect(statusReadCalls).toBe(0);
  });

  test('surfaces status_unavailable when warm-session status cannot be read', async () => {
    const status = await readThresholdSigningSessionReadiness({
      sessionId: 'session-1',
      touchConfirm: {
        getWarmSessionStatus: async () =>
          ({
            ok: false,
            code: 'worker_error',
            message: 'worker down',
          }) as const,
      },
    });

    expect(status).toEqual({
      ok: false,
      code: 'status_unavailable',
      message:
        '[chains] threshold signingSession status is unavailable; retry after refreshing the signer runtime (worker_error)',
    });
  });
});
