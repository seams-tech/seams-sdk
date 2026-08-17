import { expect, test } from '@playwright/test';
import { isWalletSessionReadyForUi } from '@/react/context/walletSessionReadiness';
import {
  activeWalletSessionFixture,
  activeLinkedDeviceWalletSessionFixture,
  anonymousWalletSessionFixture,
  exhaustedWalletSessionFixture,
  expiredWalletSessionFixture,
  missingWalletSessionFixture,
} from './helpers/walletSessionReadProjection.fixtures';

test.describe('wallet authentication readiness gate', () => {
  test('accepts authenticated wallets independently of reusable authorization', () => {
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
    expect(
      isWalletSessionReadyForUi({
        session: missingWalletSessionFixture(),
      }),
    ).toBe(true);
    expect(
      isWalletSessionReadyForUi({
        session: expiredWalletSessionFixture(),
      }),
    ).toBe(true);
  });

  test('rejects a signed-out anonymous wallet', () => {
    expect(
      isWalletSessionReadyForUi({
        session: anonymousWalletSessionFixture(),
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

  test('accepts an active linked-device Wallet Session', () => {
    expect(
      isWalletSessionReadyForUi({
        session: activeLinkedDeviceWalletSessionFixture(),
      }),
    ).toBe(true);
  });
});
