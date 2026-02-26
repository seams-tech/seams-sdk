import { expect, test } from '@playwright/test';
import { isLoginSessionReadyForUi } from '@/react/context/loginReadiness';
import type { LoginSession } from '@/core/types/tatchi';
import { toAccountId } from '@/core/types/accountIds';

function makeSession(overrides?: Partial<LoginSession>): LoginSession {
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

test.describe('login readiness gate', () => {
  test('threshold-signer requires active signing session', () => {
    const signerMode = { mode: 'threshold-signer' };

    expect(
      isLoginSessionReadyForUi({
        session: makeSession({ signingSession: null }),
        signerMode,
      }),
    ).toBe(false);

    expect(
      isLoginSessionReadyForUi({
        session: makeSession({
          signingSession: { sessionId: 'session-1', status: 'expired' },
        }),
        signerMode,
      }),
    ).toBe(false);

    expect(
      isLoginSessionReadyForUi({
        session: makeSession({
          signingSession: { sessionId: 'session-1', status: 'active' },
        }),
        signerMode,
      }),
    ).toBe(true);
  });

  test('non-threshold signer mode does not require signing session readiness', () => {
    expect(
      isLoginSessionReadyForUi({
        session: makeSession({ signingSession: null }),
        signerMode: { mode: 'local-signer' },
      }),
    ).toBe(true);

    expect(
      isLoginSessionReadyForUi({
        session: makeSession({ signingSession: null }),
        signerMode: { mode: 'evm' },
      }),
    ).toBe(true);
  });

  test('unknown signer mode defaults to local-signer behavior', () => {
    expect(
      isLoginSessionReadyForUi({
        session: makeSession({ signingSession: null }),
        signerMode: undefined,
      }),
    ).toBe(true);
  });

  test('requires base logged-in snapshot regardless of signer mode', () => {
    expect(
      isLoginSessionReadyForUi({
        session: makeSession({
          login: {
            isLoggedIn: false,
            nearAccountId: toAccountId('alice.testnet'),
            publicKey: null,
            userData: null,
          },
        }),
        signerMode: { mode: 'threshold-signer' },
      }),
    ).toBe(false);

    expect(
      isLoginSessionReadyForUi({
        session: makeSession({
          login: {
            isLoggedIn: true,
            nearAccountId: null,
            publicKey: null,
            userData: null,
          },
        }),
        signerMode: { mode: 'local-signer' },
      }),
    ).toBe(false);
  });
});
