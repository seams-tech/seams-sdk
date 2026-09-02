import { expect, test } from '@playwright/test';
import { isWalletSessionReadyForUi } from '@/react/context/walletSessionReadiness';
import {
  activeWalletSessionFixture,
  anonymousWalletSessionFixture,
} from './helpers/walletSessionReadProjection.fixtures';

test.describe('wallet authentication readiness gate', () => {
  test('accepts authenticated wallets independently of exact capability readiness', () => {
    expect(
      isWalletSessionReadyForUi({
        session: activeWalletSessionFixture(),
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
});
