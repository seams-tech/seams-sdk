import { expect, test } from '@playwright/test';
import {
  DEFAULT_THRESHOLD_ECDSA_PROVISIONING_DEFAULTS,
  PASSKEY_MANAGER_DEFAULT_CONFIGS,
} from '../../packages/sdk-web/src/core/config/defaultConfigs';
import {
  applyWalletBudgetStatusToSigningSessionReadiness,
  warmClaimFromRecordPolicy,
} from '../../packages/sdk-web/src/core/signingEngine/session/availability/readiness';
import { durableRecordPolicyAdvisory } from '../../packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  clampThresholdSessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  DEFAULT_THRESHOLD_SESSION_TTL_MS,
  THRESHOLD_SESSION_POLICY_MAX_TTL_MS,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy';

const DAY_MS = 24 * 60 * 60_000;
const NOW_MS = 1_900_000_000_000;
const THRESHOLD_SESSION_ID =
  SigningSessionIds.thresholdEd25519Session('expiry-policy-session');

test.describe('signing session expiry policy', () => {
  test('uses a configurable 24-hour default bounded by the server maximum', () => {
    expect(DEFAULT_THRESHOLD_SESSION_TTL_MS).toBe(DAY_MS);
    expect(DEFAULT_THRESHOLD_SESSION_POLICY).toEqual({
      ttlMs: DAY_MS,
      remainingUses: 3,
    });
    expect(PASSKEY_MANAGER_DEFAULT_CONFIGS.signing.sessionDefaults).toEqual({
      ttlMs: DAY_MS,
      remainingUses: 3,
    });
    expect(DEFAULT_THRESHOLD_ECDSA_PROVISIONING_DEFAULTS.tempo.signingSession.ttlMs).toBe(
      DAY_MS,
    );
    expect(DEFAULT_THRESHOLD_ECDSA_PROVISIONING_DEFAULTS.evm.signingSession.ttlMs).toBe(
      DAY_MS,
    );

    const customTtlMs = 2 * 60 * 60_000;
    expect(
      clampThresholdSessionPolicy({ ttlMs: customTtlMs, remainingUses: 9 }),
    ).toEqual({ ttlMs: customTtlMs, remainingUses: 9 });
    expect(
      clampThresholdSessionPolicy({
        ttlMs: THRESHOLD_SESSION_POLICY_MAX_TTL_MS + 1,
        remainingUses: 9,
      }),
    ).toEqual({ ttlMs: THRESHOLD_SESSION_POLICY_MAX_TTL_MS, remainingUses: 9 });
  });

  test('classifies elapsed sessions as expired before considering exhaustion', () => {
    expect(
      applyWalletBudgetStatusToSigningSessionReadiness({
        status: 'ready',
        thresholdSessionId: THRESHOLD_SESSION_ID,
        expiresAtMs: NOW_MS,
        remainingUses: 0,
        nowMs: NOW_MS,
      }).readiness,
    ).toEqual({
      status: 'expired',
      thresholdSessionId: THRESHOLD_SESSION_ID,
      expiresAtMs: NOW_MS,
    });
  });

  test('classifies a temporally valid depleted session as exhausted', () => {
    const expiresAtMs = NOW_MS + 60_000;
    expect(
      applyWalletBudgetStatusToSigningSessionReadiness({
        status: 'ready',
        thresholdSessionId: THRESHOLD_SESSION_ID,
        expiresAtMs,
        remainingUses: 0,
        nowMs: NOW_MS,
      }).readiness,
    ).toEqual({
      status: 'exhausted',
      thresholdSessionId: THRESHOLD_SESSION_ID,
      remainingUses: 0,
      expiresAtMs,
    });
  });

  test('keeps unavailable distinct from expiry and exhaustion', () => {
    expect(
      applyWalletBudgetStatusToSigningSessionReadiness({
        status: 'ready',
        thresholdSessionId: THRESHOLD_SESSION_ID,
        expiresAtMs: NOW_MS + 60_000,
        remainingUses: 3,
        walletBudgetStatus: {
          sessionId: 'wallet-budget-session',
          status: 'unavailable',
          statusCode: 'service_unavailable',
        },
        nowMs: NOW_MS,
      }).readiness,
    ).toEqual({
      status: 'status_unavailable',
      thresholdSessionId: THRESHOLD_SESSION_ID,
    });
  });

  test('record policy gives elapsed time precedence over an empty budget', () => {
    expect(
      warmClaimFromRecordPolicy({
        sessionId: String(THRESHOLD_SESSION_ID),
        remainingUses: 0,
        expiresAtMs: 1,
      }),
    ).toEqual({
      state: 'expired',
      sessionId: String(THRESHOLD_SESSION_ID),
    });

    expect(
      durableRecordPolicyAdvisory({
        thresholdSessionId: String(THRESHOLD_SESSION_ID),
        remainingUses: 0,
        expiresAtMs: 1,
        state: 'ready',
      }),
    ).toEqual({
      kind: 'durable_policy',
      thresholdSessionId: String(THRESHOLD_SESSION_ID),
      remainingUses: 0,
      expiresAtMs: 1,
      state: 'expired',
    });
  });
});
