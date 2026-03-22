import { expect, test } from '@playwright/test';
import { isWalletSessionReadyForUi } from '@/react/context/walletSessionReadiness';
import type { WalletSession } from '@/core/types/tatchi';
import { toAccountId } from '@/core/types/accountIds';

function makeSession(overrides?: Partial<WalletSession>): WalletSession {
  return {
    login: {
      isLoggedIn: true,
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
            nearAccountId: null,
            publicKey: null,
            userData: null,
          },
        }),
      }),
    ).toBe(false);
  });
});
