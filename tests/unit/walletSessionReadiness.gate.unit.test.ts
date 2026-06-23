import { expect, test } from '@playwright/test';
import { isWalletSessionReadyForUi } from '@/react/context/walletSessionReadiness';
import type { WalletSession } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';

function makeSession(overrides?: Partial<WalletSession>): WalletSession {
  return {
    login: {
      isLoggedIn: true,
      walletId: walletIdFromString('alice.testnet'),
      nearAccountId: toAccountId('alice.testnet'),
      publicKey: 'ed25519:abc',
      userData: null,
    },
    signingSession: {
      sessionId: 'session-1',
      status: 'active',
      remainingUses: 3,
      expiresAtMs: Date.now() + 60_000,
    },
    ...(overrides || {}),
  };
}

test.describe('wallet session readiness gate', () => {
  test('requires an active signing session', () => {
    expect(
      isWalletSessionReadyForUi({
        session: makeSession({ signingSession: null }),
      }),
    ).toBe(false);

    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          signingSession: { sessionId: 'session-1', status: 'expired' },
        }),
      }),
    ).toBe(false);

    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          signingSession: { sessionId: 'session-1', status: 'active' },
        }),
      }),
    ).toBe(true);
  });

  test('requires base logged-in snapshot regardless of signing-session status', () => {
    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          login: {
            isLoggedIn: false,
            walletId: walletIdFromString('alice.testnet'),
            nearAccountId: toAccountId('alice.testnet'),
            publicKey: null,
            userData: null,
          },
        }),
      }),
    ).toBe(false);

    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          login: {
            isLoggedIn: true,
            walletId: walletIdFromString('alice.testnet'),
            nearAccountId: null,
            publicKey: null,
            userData: null,
          },
        }),
      }),
    ).toBe(false);
  });

  test('accepts an active ECDSA warm session without an Ed25519 public key', () => {
    expect(
      isWalletSessionReadyForUi({
        session: makeSession({
          login: {
            isLoggedIn: true,
            walletId: walletIdFromString('email-otp.testnet'),
            nearAccountId: toAccountId('email-otp.testnet'),
            publicKey: null,
            userData: null,
            thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
          },
          signingSession: {
            sessionId: 'ecdsa-session-1',
            status: 'active',
          },
        }),
      }),
    ).toBe(true);
  });
});
