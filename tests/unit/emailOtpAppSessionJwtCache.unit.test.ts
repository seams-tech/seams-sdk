import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  toWalletId,
  walletSessionRefFromSession,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  EmailOtpAppSessionJwtCache,
  emailOtpRefreshIdentity,
  refreshEmailOtpAppSessionJwt,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/appSessionJwtCache';
import { exactSigningLaneIdentity } from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { buildNearTransactionSigningLane } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { buildFreshStepUpRequiredFromEmailOtpRefreshRejection } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness';

function appSessionJwt(args?: { expSeconds?: number; sub?: string }): string {
  const payload = {
    kind: 'app_session_v1',
    sub: args?.sub || 'wallet.testnet',
    exp: args?.expSeconds || Math.floor(Date.now() / 1000) + 3600,
  };
  return [base64UrlJson({ alg: 'none', typ: 'JWT' }), base64UrlJson(payload), 'signature'].join(
    '.',
  );
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function makeIdentity() {
  const walletId = toAccountId('wallet.testnet');
  const lane = buildNearTransactionSigningLane({
    accountId: walletId,
    authMethod: 'email_otp',
    signingGrantId: SigningSessionIds.signingGrant('wallet-session-1'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session-1'),
  });
  return emailOtpRefreshIdentity({
    walletId,
    walletSessionUserId: String(walletId),
    operationId: SigningSessionIds.signingOperation('operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
    laneIdentity: exactSigningLaneIdentity(lane),
  });
}

test.describe('EmailOtpAppSessionJwtCache', () => {
  test('returns a typed cached success for an unexpired app-session JWT', async () => {
    const identity = makeIdentity();
    const jwt = appSessionJwt();
    const cache = new EmailOtpAppSessionJwtCache();
    cache.remember({
      walletSession: walletSessionRefFromSession({
        walletId: toWalletId(identity.walletId),
        walletSessionUserId: identity.walletSessionUserId,
      }),
      appSessionJwt: jwt,
    });

    const result = await cache.resolve({
      identity,
      relayUrl: 'https://relay.example.test',
    });

    expect(result).toEqual({
      kind: 'cached_email_otp_session',
      identity,
      appSessionJwt: jwt,
    });
  });

  test('returns a typed refresh success and remembers the refreshed JWT', async () => {
    const identity = makeIdentity();
    const refreshedJwt = appSessionJwt({ sub: 'refreshed-wallet.testnet' });
    const cache = new EmailOtpAppSessionJwtCache({
      refreshAppSessionJwt: async () => refreshedJwt,
    });

    const result = await cache.resolve({
      identity,
      relayUrl: 'https://relay.example.test',
    });

    expect(result.kind).toBe('refreshed_email_otp_session');
    expect(result.appSessionJwt).toBe(refreshedJwt);
    await expect(
      cache.resolve({ identity, relayUrl: 'https://relay.example.test' }),
    ).resolves.toMatchObject({
      kind: 'cached_email_otp_session',
      appSessionJwt: refreshedJwt,
    });
  });
});

test.describe('refreshEmailOtpAppSessionJwt', () => {
  test('returns typed 401 and 403 rejection results', async () => {
    const identity = makeIdentity();
    const originalFetch = globalThis.fetch;
    const statuses = [401, 403] as const;
    try {
      for (const status of statuses) {
        globalThis.fetch = (async () => ({
          ok: false,
          status,
          json: async () => ({ ok: false, message: 'unauthorized' }),
        })) as unknown as typeof fetch;

        const result = await refreshEmailOtpAppSessionJwt({
          identity,
          relayUrl: 'https://relay.example.test',
        });

        expect(result).toEqual({
          kind: 'email_otp_refresh_rejected',
          identity,
          reason: 'session_refresh_unauthorized',
          httpStatus: status,
        });
        expect(result.kind).toBe('email_otp_refresh_rejected');
        if (result.kind !== 'email_otp_refresh_rejected') {
          throw new Error('expected Email OTP refresh rejection');
        }
        const freshness = buildFreshStepUpRequiredFromEmailOtpRefreshRejection(result);
        expect(freshness.reason).toBe('email_otp_refresh_rejected');
        expect(freshness.projection).toEqual({
          kind: 'unavailable',
          reason: 'email_otp_refresh_rejected',
        });
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
