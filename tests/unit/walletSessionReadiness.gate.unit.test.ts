import { expect, test } from '@playwright/test';
import { isWalletSessionReadyForUi } from '@/react/context/walletSessionReadiness';
import type { WalletSession } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { buildNoCurrentWalletAuthMethod } from '@shared/utils/walletCapabilityBindings';

function makeLoginState(
  overrides?: Partial<WalletSession['login']>,
): WalletSession['login'] {
  return {
    isLoggedIn: true,
    walletId: walletIdFromString('alice.testnet'),
    nearAccountId: toAccountId('alice.testnet'),
    publicKey: 'ed25519:abc',
    userData: null,
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    ...(overrides || {}),
  };
}

function makeSession(overrides?: Partial<WalletSession>): WalletSession {
  return {
    login: makeLoginState(),
    signingSession: {
      sessionId: 'session-1',
      status: 'active',
      remainingUses: 3,
      expiresAtMs: Date.now() + 60_000,
    },
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    ...(overrides || {}),
  };
}

test.describe('wallet session readiness gate', () => {
  test('accepts wallet login without requiring NEAR or signing readiness', () => {
    expect(
      isWalletSessionReadyForUi({
        session: makeSession({ signingSession: null }),
      }),
    ).toBe(true);

    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          signingSession: { sessionId: 'session-1', status: 'expired' },
        }),
      }),
    ).toBe(true);

    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          login: makeLoginState({
            walletId: walletIdFromString('frost-vermillion-k7p9m2'),
            nearAccountId: null,
            publicKey: null,
            userData: null,
          }),
          signingSession: null,
        }),
      }),
    ).toBe(true);
  });

  test('requires a logged-in wallet snapshot', () => {
    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          login: makeLoginState({
            isLoggedIn: false,
            walletId: walletIdFromString('alice.testnet'),
            nearAccountId: toAccountId('alice.testnet'),
            publicKey: null,
            userData: null,
          }),
        }),
      }),
    ).toBe(false);

    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          login: makeLoginState({
            isLoggedIn: true,
            walletId: null,
            nearAccountId: null,
            publicKey: null,
            userData: null,
          }),
        }),
      }),
    ).toBe(false);
  });

  test('accepts an active ECDSA warm session without an Ed25519 public key', () => {
    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          login: makeLoginState({
            isLoggedIn: true,
            walletId: walletIdFromString('email-otp.testnet'),
            nearAccountId: toAccountId('email-otp.testnet'),
            publicKey: null,
            userData: null,
            thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
          }),
          signingSession: {
            sessionId: 'ecdsa-session-1',
            status: 'active',
          },
        }),
      }),
    ).toBe(true);
  });
});
