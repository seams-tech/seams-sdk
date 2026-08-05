import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  toWalletId,
  walletSessionRefFromSession,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { nearEd25519SigningKeyIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  EmailOtpAppSessionJwtCache,
  emailOtpAppSessionBindingFromJwt,
  emailOtpRefreshIdentity,
  refreshEmailOtpAppSessionJwt,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/appSessionJwtCache';
import { exactSigningLaneIdentityFromSelectedLane } from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { buildNearTransactionSigningLane } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { buildFreshStepUpRequiredFromEmailOtpRefreshRejection } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness';

function appSessionJwt(args?: {
  expSeconds?: number;
  sub?: string;
  providerSubject?: string;
  provider?: 'google' | 'email';
  walletId?: string;
}): string {
  const subject = args?.sub || 'google:wallet.testnet';
  const providerSubject = args?.providerSubject || subject;
  const provider = args?.provider || (providerSubject.startsWith('email:') ? 'email' : 'google');
  const payload = {
    kind: 'app_session_v1',
    sub: subject,
    provider,
    providerSubject,
    authSource: {
      kind: 'oidc_provider',
      providerId: provider === 'google' ? 'google_oidc' : 'oidc',
      providerSubject,
    },
    walletId: args?.walletId || 'wallet.testnet',
    exp: args?.expSeconds || Math.floor(Date.now() / 1000) + 3600,
  };
  return [base64UrlJson({ alg: 'none', typ: 'JWT' }), base64UrlJson(payload), 'signature'].join(
    '.',
  );
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

async function failUnexpectedAppSessionRefresh(): Promise<string> {
  throw new Error('app-session refresh should not run');
}

function makeIdentity() {
  const walletId = toWalletId('wallet.testnet');
  const nearAccountId = toAccountId('wallet.testnet');
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('scope-wallet-testnet');
  const lane = buildNearTransactionSigningLane({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: 1,
    auth: {
      kind: 'email_otp',
      providerSubjectId: 'google:wallet.testnet',
    },
    walletSessionId: SigningSessionIds.walletSession('wallet-session-1'),
    quotaId: SigningSessionIds.walletSessionQuota('wallet-quota-1'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session-1'),
  });
  return emailOtpRefreshIdentity({
    walletId,
    walletSessionUserId: String(walletId),
    operationId: SigningSessionIds.signingOperation('operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
    laneIdentity: exactSigningLaneIdentityFromSelectedLane(lane),
  });
}

test.describe('EmailOtpAppSessionJwtCache', () => {
  test('binds linked OIDC sessions by provider subject rather than principal', () => {
    const binding = emailOtpAppSessionBindingFromJwt({
      walletId: toWalletId('wallet.testnet'),
      appSessionJwt: appSessionJwt({
        sub: 'linked-principal',
        providerSubject: 'google:wallet.testnet',
      }),
    });

    expect(binding.providerSubject).toBe('google:wallet.testnet');
  });

  test('rejects a wallet-session JWT at the app-session boundary', () => {
    const identity = makeIdentity();
    const cache = new EmailOtpAppSessionJwtCache();
    const walletSessionJwt = [
      base64UrlJson({ alg: 'none', typ: 'JWT' }),
      base64UrlJson({
        kind: 'router_ab_ed25519_wallet_session_v1',
        sub: identity.walletSessionUserId,
      }),
      'signature',
    ].join('.');

    expect(() =>
      emailOtpAppSessionBindingFromJwt({
        walletId: identity.walletId,
        appSessionJwt: walletSessionJwt,
      }),
    ).toThrow('must be an app-session JWT');
  });

  test('rejects rebinding an initial registration wallet session to the finalized wallet', () => {
    const initialWalletJwt = appSessionJwt({ walletId: 'initial-wallet.testnet' });

    expect(() =>
      emailOtpAppSessionBindingFromJwt({
        walletId: toWalletId('final-wallet.testnet'),
        appSessionJwt: initialWalletJwt,
      }),
    ).toThrow('app-session wallet does not match the requested wallet binding');
  });

  test('requires the canonical OIDC auth source and exact provider claims', () => {
    const valid = appSessionJwt();
    const payload = JSON.parse(
      Buffer.from(valid.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    const withPayload = (overrides: Record<string, unknown>): string =>
      [
        base64UrlJson({ alg: 'none', typ: 'JWT' }),
        base64UrlJson({ ...payload, ...overrides }),
        'signature',
      ].join('.');

    expect(() =>
      emailOtpAppSessionBindingFromJwt({
        walletId: toWalletId('wallet.testnet'),
        appSessionJwt: withPayload({ authSource: undefined }),
      }),
    ).toThrow('OIDC provider source');
    expect(() =>
      emailOtpAppSessionBindingFromJwt({
        walletId: toWalletId('wallet.testnet'),
        appSessionJwt: withPayload({
          provider: 'email',
        }),
      }),
    ).toThrow('does not match its provider claims');
    expect(() =>
      emailOtpAppSessionBindingFromJwt({
        walletId: toWalletId('wallet.testnet'),
        appSessionJwt: withPayload({
          authSource: {
            kind: 'oidc_provider',
            providerId: 'google_oidc',
            providerSubject: 'google:other',
          },
        }),
      }),
    ).toThrow('does not match its provider subject');
  });

  test('returns a typed cached success for an unexpired app-session JWT', async () => {
    const identity = makeIdentity();
    const jwt = appSessionJwt();
    const cache = new EmailOtpAppSessionJwtCache();
    cache.remember(
      emailOtpAppSessionBindingFromJwt({
        walletId: toWalletId(identity.walletId),
        appSessionJwt: jwt,
      }),
    );

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

  test('returns the registration app-session JWT for export without refreshing', async () => {
    const identity = makeIdentity();
    const jwt = appSessionJwt({ sub: 'google:wallet.testnet' });
    const cache = new EmailOtpAppSessionJwtCache({
      refreshAppSessionJwt: failUnexpectedAppSessionRefresh,
    });
    const walletSession = walletSessionRefFromSession({
      walletId: identity.walletId,
      walletSessionUserId: identity.walletSessionUserId,
    });
    cache.remember(
      emailOtpAppSessionBindingFromJwt({
        walletId: identity.walletId,
        appSessionJwt: jwt,
      }),
    );

    await expect(
      cache.resolveJwt({ walletSession, relayUrl: 'https://relay.example.test' }),
    ).resolves.toBe(jwt);
  });

  test('resolves step-up authority by exact wallet and provider subject', async () => {
    const walletId = toWalletId('exact-wallet.testnet');
    const expectedJwt = appSessionJwt({
      walletId,
      sub: 'linked-principal',
      providerSubject: 'google:expected',
    });
    const otherJwt = appSessionJwt({
      walletId,
      sub: 'linked-principal',
      providerSubject: 'google:other',
    });
    const cache = new EmailOtpAppSessionJwtCache({
      refreshAppSessionJwt: failUnexpectedAppSessionRefresh,
    });
    cache.remember(emailOtpAppSessionBindingFromJwt({ walletId, appSessionJwt: otherJwt }));
    cache.remember(emailOtpAppSessionBindingFromJwt({ walletId, appSessionJwt: expectedJwt }));

    await expect(
      cache.resolveJwtForProviderSubject({
        walletId,
        providerSubject: 'google:expected',
        relayUrl: 'https://relay.example.test',
      }),
    ).resolves.toBe(expectedJwt);
  });

  test('returns a typed refresh success and remembers the refreshed JWT', async () => {
    const identity = makeIdentity();
    const refreshedJwt = appSessionJwt();
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
