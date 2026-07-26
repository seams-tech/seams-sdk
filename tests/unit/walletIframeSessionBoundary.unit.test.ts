import { expect, test } from '@playwright/test';
import {
  exactSessionStateFromWalletSession,
  parseWalletIframeExactSessionState,
  parseWalletSessionFromBoundary,
} from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import {
  activeWalletSessionFixture,
  activeWalletSessionWithNonceDiagnosticsFixture,
  invalidWalletSessionFixture,
  missingWalletSessionFixture,
  restorableEcdsaWalletSessionFixture,
  unavailableWalletSessionFixture,
} from './helpers/walletSessionReadProjection.fixtures';

test.describe('wallet iframe Wallet Session boundary', () => {
  test('parses and reconstructs the requested active Wallet Session', () => {
    const input = activeWalletSessionWithNonceDiagnosticsFixture({
      walletId: 'iframe-wallet',
      walletSessionId: 'iframe-wallet-session',
    });

    expect(
      parseWalletSessionFromBoundary(
        {
          ...input,
          walletSessionJwt: 'must-not-cross',
          reusableWalletSession: {
            ...input.reusableWalletSession,
            privateKey: 'must-not-cross',
          },
        },
        'iframe-wallet',
      ),
    ).toEqual(input);
  });

  test('rejects a response for a different wallet', () => {
    const input = activeWalletSessionFixture({ walletId: 'returned-wallet' });

    expect(() => parseWalletSessionFromBoundary(input, 'requested-wallet')).toThrow(
      'does not match the requested wallet',
    );
  });

  test('rejects disagreement between app and reusable-session wallet identities', () => {
    const input = activeWalletSessionFixture({ walletId: 'canonical-wallet' });
    const corrupted = {
      ...input,
      reusableWalletSession: {
        ...input.reusableWalletSession,
        walletId: 'different-wallet',
      },
    };

    expect(() => parseWalletSessionFromBoundary(corrupted)).toThrow('wallet identities disagree');
  });

  test('keeps material restorable while rejecting reusable active_restorable', () => {
    expect(() =>
      parseWalletIframeExactSessionState({
        kind: 'active_session',
        status: 'active_restorable',
        walletId: 'iframe-wallet',
        walletSessionId: 'iframe-wallet-session',
        authMethod: 'passkey',
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrow('active session status is invalid');

    const parsed = parseWalletSessionFromBoundary(
      restorableEcdsaWalletSessionFixture({
        walletId: 'iframe-wallet',
        walletSessionId: 'iframe-wallet-session',
      }),
      'iframe-wallet',
    );
    expect(parsed.capabilityProjection.kind).toBe('resolved');
    if (parsed.capabilityProjection.kind !== 'resolved') return;
    const capability = parsed.capabilityProjection.capabilities[0];
    expect(capability.kind).toBe('evm_family_ecdsa');
    if (capability.kind !== 'evm_family_ecdsa') return;
    expect(capability.targets).toMatchObject({
      kind: 'configured_targets',
      lanes: [{ readiness: { kind: 'restorable' } }],
    });
  });

  test('preserves unavailable and invalid as distinct fail-closed exact states', () => {
    expect(exactSessionStateFromWalletSession(unavailableWalletSessionFixture())).toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'unavailable',
    });
    expect(exactSessionStateFromWalletSession(invalidWalletSessionFixture())).toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'invalid',
    });
    expect(exactSessionStateFromWalletSession(missingWalletSessionFixture())).toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'not_found',
    });
  });
});
