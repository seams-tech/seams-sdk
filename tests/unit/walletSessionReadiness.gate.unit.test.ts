import { expect, test } from '@playwright/test';
import { isWalletSessionReadyForUi } from '@/react/context/walletSessionReadiness';
import {
  activeWalletSessionFixture,
  anonymousWalletSessionFixture,
  exhaustedWalletSessionFixture,
  expiredWalletSessionFixture,
  missingWalletSessionFixture,
} from './helpers/walletSessionReadProjection.fixtures';

test.describe('wallet session readiness gate', () => {
  test('accepts active and exhausted reusable Wallet Sessions', () => {
    expect(
      isWalletSessionReadyForUi({
        session: activeWalletSessionFixture(),
      }),
    ).toBe(true);
    expect(
      isWalletSessionReadyForUi({
        session: exhaustedWalletSessionFixture(),
      }),
    ).toBe(true);
  });

  test('rejects anonymous, missing, and expired Wallet Sessions', () => {
    expect(
      isWalletSessionReadyForUi({
        session: anonymousWalletSessionFixture(),
      }),
    ).toBe(false);
    expect(
      isWalletSessionReadyForUi({
        session: missingWalletSessionFixture(),
      }),
    ).toBe(false);
    expect(
      isWalletSessionReadyForUi({
        session: expiredWalletSessionFixture(),
      }),
    ).toBe(false);
  });

  test('accepts an active ECDSA Wallet Session without NEAR identity', () => {
    expect(
      isWalletSessionReadyForUi({
        session: activeWalletSessionFixture({
          walletId: 'email-otp-wallet',
          nearAccountId: null,
          nearOperationalPublicKey: null,
          thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
        }),
      }),
    ).toBe(true);
  });
});
