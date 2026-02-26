import { expect, test } from '@playwright/test';
import {
  assertThresholdSigningSessionReady,
  isThresholdSigningSessionReady,
  resolveThresholdSigningAuthMode,
  THRESHOLD_SESSION_EXHAUSTED_ERROR,
  THRESHOLD_SESSION_MISSING_ERROR,
} from '@/core/signingEngine/orchestration/shared/thresholdSigningSessionPlanner';

test.describe('threshold signing session planner', () => {
  test('asserts ready when warm session cache is available', async () => {
    const ready = await assertThresholdSigningSessionReady({
      sessionId: 'session-1',
      usesNeeded: 2,
      touchConfirm: {
        peekPrfFirstForThresholdSession: async () => ({
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
        sessionId: '',
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({
            ok: true,
            remainingUses: 1,
            expiresAtMs: Date.now() + 60_000,
          }),
        },
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_MISSING_ERROR);
  });

  test('fails with canonical exhausted error when remaining uses are insufficient', async () => {
    await expect(
      assertThresholdSigningSessionReady({
        sessionId: 'session-1',
        usesNeeded: 3,
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({
            ok: true,
            remainingUses: 2,
            expiresAtMs: Date.now() + 60_000,
          }),
        },
      }),
    ).rejects.toThrow(THRESHOLD_SESSION_EXHAUSTED_ERROR);
  });

  test('normalizes cache miss errors to canonical reconnect message', async () => {
    await expect(
      assertThresholdSigningSessionReady({
        sessionId: 'session-1',
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({
            ok: false,
            code: 'not_found',
            message: 'worker-cache-miss',
          }),
        },
      }),
    ).rejects.toThrow(
      '[chains] threshold signingSession is not_found; reconnect threshold session before signing',
    );
  });

  test('returns webauthn auth mode without touching warm-session cache when explicitly required', async () => {
    let peekCalls = 0;
    const authMode = await resolveThresholdSigningAuthMode({
      needsWebAuthn: true,
      sessionId: '',
      touchConfirm: {
        peekPrfFirstForThresholdSession: async () => {
          peekCalls += 1;
          return { ok: false, code: 'not_found', message: 'na' } as const;
        },
      },
    });

    expect(authMode).toBe('webauthn');
    expect(peekCalls).toBe(0);
  });

  test('returns warm-session auth mode when cache is ready', async () => {
    const authMode = await resolveThresholdSigningAuthMode({
      needsWebAuthn: false,
      sessionId: 'session-1',
      touchConfirm: {
        peekPrfFirstForThresholdSession: async () => ({
          ok: true,
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        }),
      },
    });

    expect(authMode).toBe('warmSession');
  });

  test('returns warm-session auth mode without pre-confirm warm-cache check', async () => {
    let peekCalls = 0;
    const authMode = await resolveThresholdSigningAuthMode({
      needsWebAuthn: false,
      sessionId: '',
      touchConfirm: {
        peekPrfFirstForThresholdSession: async () => {
          peekCalls += 1;
          return {
            ok: false,
            code: 'not_found',
            message: 'missing',
          } as const;
        },
      },
    });

    expect(authMode).toBe('warmSession');
    expect(peekCalls).toBe(0);
  });

  test('readiness helper is false when session id is blank', async () => {
    let peekCalls = 0;
    const ready = await isThresholdSigningSessionReady({
      sessionId: '',
      touchConfirm: {
        peekPrfFirstForThresholdSession: async () => {
          peekCalls += 1;
          return { ok: true, remainingUses: 5, expiresAtMs: Date.now() + 60_000 } as const;
        },
      },
    });

    expect(ready).toBe(false);
    expect(peekCalls).toBe(0);
  });
});
