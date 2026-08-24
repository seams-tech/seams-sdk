import { expect, test } from '@playwright/test';
import { handleWalletEmailOtpChallenge } from '../../packages/wallet-server/src/router/transport/fetch/routes/sessions';
import { parseWalletAuthMethodId } from '../../packages/shared-ts/src/utils/domainIds';
import { buildEmailOtpWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';

const WALLET_ID = 'alice.testnet';
const OTHER_WALLET_ID = 'bob.testnet';
const ORG_ID = 'org-a';
const PROVIDER_USER_ID = 'google:alice';
const EMAIL = 'alice@example.test';
const EMAIL_HASH_HEX = 'a'.repeat(64);
const WALLET_AUTH_METHOD_ID = 'email-otp-method-a';

type RouteState = {
  readonly walletLevelCalls: unknown[];
  readonly exactCalls: unknown[];
  readonly challengeCalls: unknown[];
  readonly walletLevelResolution: unknown;
  readonly exactResolution: unknown;
};

function selectedAuthority() {
  const parsedMethodId = parseWalletAuthMethodId(WALLET_AUTH_METHOD_ID);
  if (!parsedMethodId.ok) throw new Error(parsedMethodId.error.message);
  return {
    ...buildEmailOtpWalletAuthAuthority({
      walletId: WALLET_ID,
      provider: 'google',
      providerUserId: PROVIDER_USER_ID,
      emailHashHex: EMAIL_HASH_HEX,
    }),
    bindingId: parsedMethodId.value,
  };
}

function challengeResult() {
  return {
    ok: true,
    challenge: {
      challengeId: 'challenge-a',
      issuedAtMs: 1_000,
      expiresAtMs: 61_000,
      userId: PROVIDER_USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      otpChannel: 'email_otp',
      ownerProofBindingDigest: 'binding-a',
      action: 'wallet_email_otp_login',
      operation: 'wallet_unlock',
    },
    delivery: {
      kind: 'development',
      status: 'sent',
      mode: 'memory',
      emailHint: 'a***e@e***e.test',
    },
  };
}

function context(body: unknown, state: RouteState) {
  return {
    method: 'POST',
    pathname: '/wallet/email-otp/challenge',
    request: new Request('https://relay.localhost/wallet/email-otp/challenge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://app.example.localhost',
      },
      body: JSON.stringify(body),
    }),
    service: {
      authorizedOperations: { tenantId: ORG_ID },
      emailOtp: {
        readActiveEmailOtpEnrollment: async () => ({
          ok: true,
          enrollment: {
            providerUserId: PROVIDER_USER_ID,
            verifiedEmail: EMAIL,
          },
        }),
        createEmailOtpChallenge: async (input: unknown) => {
          state.challengeCalls.push(input);
          return challengeResult();
        },
      },
      walletAuthMethods: {
        resolveActiveEmailOtpAuthorityForVerifiedSubject: async (input: unknown) => {
          state.walletLevelCalls.push(input);
          return state.walletLevelResolution;
        },
      },
      walletUnlock: {
        resolveEmailOtpAuthorityForUnlock: async (input: unknown) => {
          state.exactCalls.push(input);
          return state.exactResolution;
        },
      },
    },
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

function state(overrides: Partial<RouteState> = {}): RouteState {
  return {
    walletLevelCalls: [],
    exactCalls: [],
    challengeCalls: [],
    walletLevelResolution: { ok: false, code: 'unused', message: 'unused' },
    exactResolution: { kind: 'rejected', code: 'unused', message: 'unused' },
    ...overrides,
  };
}

test('an exact Email OTP method selector reaches the exact unlock authority resolver', async () => {
  const routeState = state({
    exactResolution: {
      kind: 'wallet_registration',
      walletAuthAuthority: selectedAuthority(),
    },
  });
  const response = await handleWalletEmailOtpChallenge(
    context(
      {
        walletId: WALLET_ID,
        walletAuthMethodId: WALLET_AUTH_METHOD_ID,
        otpChannel: 'email_otp',
        operation: 'wallet_unlock',
      },
      routeState,
    ),
  );

  expect(response?.status).toBe(200);
  expect(routeState.walletLevelCalls).toEqual([]);
  expect(routeState.exactCalls).toEqual([
    {
      walletId: WALLET_ID,
      orgId: ORG_ID,
      walletAuthMethodId: WALLET_AUTH_METHOD_ID,
      providerUserId: PROVIDER_USER_ID,
    },
  ]);
  expect(routeState.challengeCalls).toHaveLength(1);
});

test('wrong-wallet, wrong-kind, and revoked exact methods are rejected before challenge creation', async () => {
  const rejectionCases = [
    {
      name: 'wrong wallet',
      walletId: OTHER_WALLET_ID,
      message: 'Selected Email OTP method belongs to another wallet',
    },
    {
      name: 'wrong kind',
      walletId: WALLET_ID,
      message: 'Selected wallet auth method is not Email OTP',
    },
    {
      name: 'revoked method',
      walletId: WALLET_ID,
      message: 'Selected Email OTP method is revoked',
    },
  ] as const;

  for (const rejectionCase of rejectionCases) {
    const routeState = state({
      exactResolution: {
        kind: 'rejected',
        code: 'unauthorized',
        message: rejectionCase.message,
      },
    });
    const response = await handleWalletEmailOtpChallenge(
      context(
        {
          walletId: rejectionCase.walletId,
          walletAuthMethodId: WALLET_AUTH_METHOD_ID,
          otpChannel: 'email_otp',
          operation: 'wallet_unlock',
        },
        routeState,
      ),
    );

    expect(response?.status, rejectionCase.name).toBe(403);
    await expect(response?.json(), rejectionCase.name).resolves.toMatchObject({
      ok: false,
      code: 'unauthorized',
      message: rejectionCase.message,
    });
    expect(routeState.challengeCalls, rejectionCase.name).toEqual([]);
    expect(routeState.walletLevelCalls, rejectionCase.name).toEqual([]);
  }
});

test('a wallet-level selector preserves the canonical current-authority behavior', async () => {
  const routeState = state({
    walletLevelResolution: {
      ok: true,
      authority: selectedAuthority(),
    },
  });
  const response = await handleWalletEmailOtpChallenge(
    context(
      {
        walletId: WALLET_ID,
        otpChannel: 'email_otp',
        operation: 'wallet_unlock',
      },
      routeState,
    ),
  );

  expect(response?.status).toBe(200);
  expect(routeState.exactCalls).toEqual([]);
  expect(routeState.walletLevelCalls).toEqual([
    {
      walletId: WALLET_ID,
      providerUserId: PROVIDER_USER_ID,
    },
  ]);
  expect(routeState.challengeCalls).toHaveLength(1);
});
