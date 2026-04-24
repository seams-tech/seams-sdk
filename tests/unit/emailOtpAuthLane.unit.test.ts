import { expect, test } from '@playwright/test';
import {
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  emailOtpRoutePath,
  resolveEmailOtpAuthLane,
  routeFamilyForAuthLane,
} from '@/core/signingEngine/emailOtp/authLane';

test.describe('Email OTP auth lane route planning', () => {
  test('plans fresh login and registration from app-session auth', () => {
    const authLane = resolveEmailOtpAuthLane({ appSessionJwt: 'app-session-jwt' });
    expect(authLane).toEqual({ kind: 'app_session', jwt: 'app-session-jwt' });

    const login = buildEmailOtpRoutePlan({
      routeFamily: 'login',
      authLane,
      operation: 'wallet_unlock',
    });
    const registration = buildEmailOtpRoutePlan({
      routeFamily: 'registration',
      authLane,
      operation: 'wallet_unlock',
    });

    expect(emailOtpRoutePath(login, 'challenge')).toBe('/wallet/email-otp/login/challenge');
    expect(emailOtpRoutePath(registration, 'challenge')).toBe(
      '/wallet/email-otp/registration/challenge',
    );
    expect(authLaneToRouteAuth(authLane)).toEqual({
      kind: 'app_session',
      jwt: 'app-session-jwt',
    });
  });

  test('plans fresh login from cookie auth without bearer route auth', () => {
    const authLane = resolveEmailOtpAuthLane({ sessionKind: 'cookie' });
    const plan = buildEmailOtpRoutePlan({
      routeFamily: 'login',
      authLane,
      operation: 'wallet_unlock',
    });

    expect(plan.authLane).toEqual({ kind: 'cookie' });
    expect(authLaneToRouteAuth(authLane)).toBeUndefined();
    expect(emailOtpRoutePath(plan, 'verify')).toBe('/wallet/email-otp/login/verify');
    expect(emailOtpRoutePath(plan, 'verifyAndUnseal')).toBe(
      '/wallet/email-otp/login/verify-and-unseal',
    );
  });

  test('plans signing-session routes from restored threshold-session auth', () => {
    const authLane = resolveEmailOtpAuthLane({
      routeAuth: { kind: 'threshold_session', jwt: 'threshold-session-jwt' },
      thresholdSessionId: 'threshold-session',
      walletSigningSessionId: 'wallet-signing-session',
      curve: 'ecdsa',
      chain: 'tempo',
    });
    expect(routeFamilyForAuthLane({ authLane: authLane!, freshRouteFamily: 'login' })).toBe(
      'signing_session',
    );

    const plan = buildEmailOtpRoutePlan({
      routeFamily: 'signing_session',
      authLane,
      operation: 'export_key',
    });

    expect(emailOtpRoutePath(plan, 'challenge')).toBe(
      '/wallet/email-otp/signing-session/challenge',
    );
    expect(authLaneToRouteAuth(authLane)).toEqual({
      kind: 'threshold_session',
      jwt: 'threshold-session-jwt',
    });
  });

  test('fails closed for mismatched lane and route family', () => {
    const signingLane = resolveEmailOtpAuthLane({
      routeAuth: { kind: 'threshold_session', jwt: 'threshold-session-jwt' },
      thresholdSessionId: 'threshold-session',
      curve: 'ed25519',
    });
    const appLane = resolveEmailOtpAuthLane({ appSessionJwt: 'app-session-jwt' });

    expect(() => buildEmailOtpRoutePlan({ routeFamily: 'login', authLane: signingLane })).toThrow(
      /cannot use signing-session auth/,
    );
    expect(() =>
      buildEmailOtpRoutePlan({ routeFamily: 'signing_session', authLane: appLane }),
    ).toThrow(/require signing-session auth/);
  });
});
