import { expect, test } from '@playwright/test';
import {
  beginGoogleEmailOtpWalletAuth,
  type GoogleEmailOtpLinkedUnlockSelection,
  type GoogleEmailOtpWalletAuthDeps,
} from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import { activeWalletSessionFixture } from './helpers/walletSessionReadProjection.fixtures';

function linkedEmailOtpDeps(args: {
  selection: GoogleEmailOtpLinkedUnlockSelection;
  calls: string[];
  challengeMethods: string[];
}): GoogleEmailOtpWalletAuthDeps {
  return {
    configs: {
      network: { chains: [] },
      signing: {
        thresholdEcdsa: {
          provisioningDefaults: {
            tempo: { enabled: false },
            evm: { enabled: false },
          },
        },
      },
    } as unknown as GoogleEmailOtpWalletAuthDeps['configs'],
    resolveGoogleEmailOtpProvider: async () => ({
      mode: 'existing_wallet',
      walletId: 'linked.testnet',
      providerSubject: 'google-linked-subject',
      email: 'linked@example.com',
      hasEmailOtpEnrollment: true,
    }),
    requestEmailOtpChallenge: async (challengeArgs) => {
      args.challengeMethods.push(String(challengeArgs.walletAuthMethodId || 'canonical'));
      return {
      challengeId: 'linked-challenge',
      otpChannel: 'email_otp',
      delivery: { kind: 'provider', status: 'sent', emailHint: 'linked@example.com' },
      emailHint: 'linked@example.com',
      };
    },
    prewarmEmailOtpYao: async () => undefined,
    registerWallet: async () => {
      throw new Error('registration is outside this test');
    },
    loginWithEmailOtpEcdsaCapability: async () => {
      throw new Error('linked login entered owner ECDSA unlock');
    },
    loginWithEmailOtpEd25519YaoCapability: async () => {
      throw new Error('linked login entered owner Ed25519 unlock');
    },
    resolveLinkedEmailOtpWalletAuth: async () => args.selection,
    loginWithLinkedEmailOtpWallet: async (loginArgs) => {
      args.calls.push(
        `${loginArgs.walletId}:${loginArgs.walletAuthMethodId}:${loginArgs.challengeId}:${loginArgs.otpCode}`,
      );
      return true;
    },
    getWalletSession: async (walletId) =>
      activeWalletSessionFixture({ walletId, nearAccountId: walletId }),
  };
}

test('linked Email OTP login carries the exact selected sibling method into challenge and unlock', async () => {
  const calls: string[] = [];
  const challengeMethods: string[] = [];
  const deps = linkedEmailOtpDeps({
    selection: {
      kind: 'selected',
      walletAuthMethodId: 'email-otp:linked-method-a',
      execution: 'linked',
    },
    calls,
    challengeMethods,
  });

  const started = await beginGoogleEmailOtpWalletAuth(deps, {
    idToken: 'google-id-token',
    mode: 'login',
    relayUrl: 'https://relay.example',
    sessionKind: 'jwt',
  });
  expect(started.ok).toBe(true);
  if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');

  const completed = await started.value.submit({ otpCode: '123456' });

  expect(completed.ok).toBe(true);
  expect(challengeMethods).toEqual(['email-otp:linked-method-a']);
  expect(calls).toEqual(['linked.testnet:email-otp:linked-method-a:linked-challenge:123456']);
});

test('linked Email OTP login keeps an exact sibling selection when method B is selected', async () => {
  const calls: string[] = [];
  const challengeMethods: string[] = [];
  const deps = linkedEmailOtpDeps({
    selection: {
      kind: 'selected',
      walletAuthMethodId: 'email-otp:linked-method-b',
      execution: 'linked',
    },
    calls,
    challengeMethods,
  });

  const started = await beginGoogleEmailOtpWalletAuth(deps, {
    idToken: 'google-id-token',
    mode: 'login',
    relayUrl: 'https://relay.example',
    sessionKind: 'jwt',
  });
  expect(started.ok).toBe(true);
  if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
  const completed = await started.value.submit({ otpCode: '654321' });

  expect(completed.ok).toBe(true);
  expect(challengeMethods).toEqual(['email-otp:linked-method-b']);
  expect(calls).toEqual(['linked.testnet:email-otp:linked-method-b:linked-challenge:654321']);
});

test('revoked selected Email OTP method rejects without falling back to a sibling', async () => {
  const calls: string[] = [];
  const challengeMethods: string[] = [];
  const deps = linkedEmailOtpDeps({
    selection: { kind: 'rejected', message: 'selected Email OTP method is revoked' },
    calls,
    challengeMethods,
  });

  const started = await beginGoogleEmailOtpWalletAuth(deps, {
    idToken: 'google-id-token',
    mode: 'login',
    relayUrl: 'https://relay.example',
    sessionKind: 'jwt',
  });

  expect(started.ok).toBe(false);
  expect(challengeMethods).toEqual([]);
  expect(calls).toEqual([]);
});
