import { expect, test } from '@playwright/test';
import { hasEcdsaKeyHandleSetMismatch } from '../../packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService';

test.describe('D1 wallet registration ECDSA key-handle guard', () => {
  test('accepts repeated EVM-family key handles across chain targets', () => {
    expect(
      hasEcdsaKeyHandleSetMismatch(
        ['ehss-key-shared', 'ehss-key-shared'],
        ['ehss-key-shared', 'ehss-key-shared'],
      ),
    ).toBe(false);

    expect(hasEcdsaKeyHandleSetMismatch(['ehss-key-shared'], ['ehss-key-shared'])).toBe(false);
  });

  test('rejects genuinely different key handles', () => {
    expect(
      hasEcdsaKeyHandleSetMismatch(['ehss-key-expected'], ['ehss-key-actual']),
    ).toBe(true);
  });
});
