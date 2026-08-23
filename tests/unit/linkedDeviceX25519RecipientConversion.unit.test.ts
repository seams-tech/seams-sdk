import { expect, test } from '@playwright/test';
import { linkedDeviceX25519RecipientPublicKeyB64uV1 } from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSourceContributionPreparationPlanner';

test('converts the complete X25519 recipient payload', () => {
  expect(
    linkedDeviceX25519RecipientPublicKeyB64uV1(
      'x25519:ef0123456789abcdef102132435465768798a9bacbdcedfe0112233445566738',
    ),
  ).toBe('7wEjRWeJq83vECEyQ1RldoeYqbrL3O3-ARIjNEVWZzg');
});
