import { expect, test } from '@playwright/test';
import { parseWalletSessionFromBoundary } from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import { isWalletSessionReadyForUi } from '@/react/context/walletSessionReadiness';
import {
  activeWalletSessionFixture,
  invalidWalletSessionFixture,
  supersededWalletSessionFixture,
} from './helpers/walletSessionReadProjection.fixtures';

// R90-INV-010 across the public surface. A replaced reusable Wallet Session is
// stale, not broken: the wallet stays the user's and the caller re-resolves.
// It used to arrive as `invalid: 'lifecycle_mismatch'`, which sent a routine
// replacement down the same path as a corrupt session and logged the user out.

test.describe('superseded reusable Wallet Session', () => {
  test('crosses the iframe boundary as its own kind', () => {
    const input = supersededWalletSessionFixture({
      walletId: 'superseded-wallet',
      walletSessionId: 'superseded-wallet-session',
    });

    expect(parseWalletSessionFromBoundary(input, 'superseded-wallet')).toEqual(input);
  });

  test('carries the replaced session identity but no budget', () => {
    const parsed = parseWalletSessionFromBoundary(
      supersededWalletSessionFixture({ walletId: 'superseded-wallet' }),
    );
    const session = parsed.reusableWalletSession;

    expect(session.kind).toBe('superseded');
    if (session.kind !== 'superseded') throw new Error('expected a superseded session');
    expect(String(session.walletSessionId)).toBeTruthy();
    expect(session.authMethod).toBe('passkey');
    // Expiry and remaining uses belong to the session that replaced this one.
    expect(session.expiresAtMs).toBeUndefined();
    expect(session.remainingUses).toBeUndefined();
  });

  test('is no longer expressible as an invalid reason', () => {
    const invalid = invalidWalletSessionFixture({ walletId: 'lifecycle-wallet' });
    const withRetiredReason = {
      ...invalid,
      reusableWalletSession: {
        ...invalid.reusableWalletSession,
        reason: 'lifecycle_mismatch',
      },
    };

    expect(() => parseWalletSessionFromBoundary(withRetiredReason)).toThrow(
      'Invalid Wallet Session reason is invalid',
    );
  });

  test('keeps authenticated wallet UI available while authorization is stale', () => {
    const superseded = supersededWalletSessionFixture({});
    expect(isWalletSessionReadyForUi({ session: superseded })).toBe(true);
    expect(isWalletSessionReadyForUi({ session: activeWalletSessionFixture({}) })).toBe(true);
  });
});
