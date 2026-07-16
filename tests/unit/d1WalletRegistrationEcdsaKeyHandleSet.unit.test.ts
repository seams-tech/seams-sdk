import { expect, test } from '@playwright/test';
import { hasEcdsaKeyHandleSetMismatch } from '../../packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService';

test.describe('D1 wallet registration ECDSA key-handle guard', () => {
  test('accepts repeated EVM-family key handles across chain targets', () => {
    expect(
      hasEcdsaKeyHandleSetMismatch(
        ['ederivation-key-shared', 'ederivation-key-shared'],
        ['ederivation-key-shared', 'ederivation-key-shared'],
      ),
    ).toBe(false);

    expect(hasEcdsaKeyHandleSetMismatch(['ederivation-key-shared'], ['ederivation-key-shared'])).toBe(false);
  });

  test('rejects genuinely different key handles', () => {
    expect(
      hasEcdsaKeyHandleSetMismatch(['ederivation-key-expected'], ['ederivation-key-actual']),
    ).toBe(true);
  });
});
