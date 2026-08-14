import { expect, test } from '@playwright/test';
import {
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  emailOtpRoutePath,
  normalizeEmailOtpRoutePlan,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const TEMPO_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});

test.describe('Email OTP auth lane route planning', () => {
  test('uses the unified operation-bound challenge route for fresh login', () => {
    const plan = buildEmailOtpRoutePlan({
      routeFamily: 'login',
      operation: 'wallet_unlock',
    });

    expect(emailOtpRoutePath(plan, 'challenge')).toBe('/wallet/email-otp/challenge');
  });

  test('keeps registration challenge routing separate', () => {
    const plan = buildEmailOtpRoutePlan({
      routeFamily: 'registration',
      operation: 'registration',
    });

    expect(emailOtpRoutePath(plan, 'challenge')).toBe(
      '/wallet/email-otp/registration/challenge',
    );
  });

  test('uses opaque Wallet Session auth for signing-session challenges', () => {
    const plan = buildEmailOtpRoutePlan({
      routeFamily: 'signing_session',
      operation: 'export_key',
      authLane: {
        kind: 'signing_session',
        walletSessionToken: 'opaque-wallet-session-token',
        thresholdSessionId: 'threshold-session',
        curve: 'ecdsa',
        chainTarget: TEMPO_CHAIN_TARGET,
      },
    });

    expect(emailOtpRoutePath(plan, 'challenge')).toBe('/wallet/email-otp/challenge');
    expect(authLaneToRouteAuth(plan.authLane)).toEqual({
      kind: 'opaque_wallet_session',
      walletSessionToken: 'opaque-wallet-session-token',
    });
  });

  test('normalizes the canonical opaque ECDSA route plan', () => {
    expect(
      normalizeEmailOtpRoutePlan({
        routeFamily: 'signing_session',
        operation: 'transaction_sign',
        authLane: {
          kind: 'signing_session',
          walletSessionToken: 'opaque-wallet-session-token',
          thresholdSessionId: 'threshold-session',
          curve: 'ecdsa',
          chainTarget: TEMPO_CHAIN_TARGET,
        },
      }),
    ).toEqual({
      routeFamily: 'signing_session',
      operation: 'transaction_sign',
      authLane: {
        kind: 'signing_session',
        walletSessionToken: 'opaque-wallet-session-token',
        thresholdSessionId: 'threshold-session',
        curve: 'ecdsa',
        chainTarget: TEMPO_CHAIN_TARGET,
      },
    });
  });

  test('rejects incomplete and malformed persisted route plans', () => {
    expect(
      normalizeEmailOtpRoutePlan({
        routeFamily: 'login',
      }),
    ).toBeUndefined();
    expect(
      normalizeEmailOtpRoutePlan({
        routeFamily: 'signing_session',
        operation: 'transaction_sign',
        authLane: {
          kind: 'signing_session',
          walletSessionToken: 'opaque-wallet-session-token',
          thresholdSessionId: 'threshold-session',
          curve: 'ecdsa',
          chainTarget: { kind: 'evm', namespace: 'eip155', chainId: -1 },
        },
      }),
    ).toBeUndefined();
  });
});
