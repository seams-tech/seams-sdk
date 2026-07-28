import { expect, test } from '@playwright/test';
import {
  isThresholdSigningSessionReady,
  readThresholdSigningSessionReadiness,
} from '@/core/signingEngine/session/warmCapabilities/thresholdSigningSessionReadiness';

test.describe('threshold signing session readiness', () => {
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
