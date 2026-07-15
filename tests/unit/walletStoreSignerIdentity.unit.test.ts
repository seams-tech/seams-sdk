import { expect, test } from '@playwright/test';
import { buildWalletEd25519SignerId } from '../../packages/sdk-server-ts/src/core/WalletStore';

test('Ed25519 signer identity requires the exact backend signer slot', () => {
  expect(
    buildWalletEd25519SignerId({
      nearAccountId: 'alice.testnet',
      signerSlot: 3,
    }),
  ).toBe('ed25519:alice.testnet:3');

  expect(() =>
    buildWalletEd25519SignerId({
      nearAccountId: 'alice.testnet',
      signerSlot: 0,
    }),
  ).toThrow('requires an exact signerSlot');
});
