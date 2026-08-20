import { expect, test } from '@playwright/test';
import {
  beginGoogleEmailOtpWalletAuth,
  type GoogleEmailOtpWalletAuthDeps,
} from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import { activeWalletSessionFixture } from './helpers/walletSessionReadProjection.fixtures';

test('linked Email OTP login bypasses the owner ECDSA unlock path', async () => {
  const calls: string[] = [];
  const deps: GoogleEmailOtpWalletAuthDeps = {
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
    requestEmailOtpChallenge: async () => ({
      challengeId: 'linked-challenge',
      otpChannel: 'email_otp',
      delivery: { kind: 'provider', status: 'sent', emailHint: 'linked@example.com' },
      emailHint: 'linked@example.com',
    }),
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
    loginWithLinkedDeviceEmailOtp: async (args) => {
      calls.push(`${args.walletId}:${args.challengeId}:${args.otpCode}`);
      return true;
    },
    getWalletSession: async (walletId) =>
      activeWalletSessionFixture({ walletId, nearAccountId: walletId }),
  };

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
  expect(calls).toEqual(['linked.testnet:linked-challenge:123456']);
});
