import { expect, test } from '@playwright/test';
import { addAuthMethodSourcePasskeyAllowCredentials } from '../../packages/wallet/src/SeamsWeb/operations/authMethods/sourcePasskeyProof';
import { activeRecoveryPasskeyMethodFixture } from './helpers/walletRecovery.fixtures';

test('add-auth-method proof allows only the passkey named as its source', () => {
  const source = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:selected-source',
    credentialIdB64u: 'selected-credential',
    rpId: 'wallet.example.test',
    createdAtMs: 1,
  });
  const sibling = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:sibling-source',
    credentialIdB64u: 'sibling-credential',
    rpId: 'wallet.example.test',
    createdAtMs: 2,
  });

  const allowCredentials = addAuthMethodSourcePasskeyAllowCredentials(source);

  expect(allowCredentials).toEqual([
    {
      id: source.credentialIdB64u,
      type: 'public-key',
      transports: [],
    },
  ]);
  expect(allowCredentials.map(({ id }) => id)).not.toContain(sibling.credentialIdB64u);
});
