import { expect, test } from '@playwright/test';
import { passkeySourceCredentialsForActiveMethods } from '../../packages/wallet/src/SeamsWeb/operations/authMethods/revokeAuthMethod';
import { buildRevokedLinkedDeviceAuthMethodV1 } from './helpers/linkedDeviceManagement.fixtures';
import { activeRecoveryPasskeyMethodFixture } from './helpers/walletRecovery.fixtures';
import { walletUnlockPasskeyAuthenticatorFixture } from './helpers/walletUnlockProfile.fixtures';

test('revoked first passkey stays out of the source prompt after a second is added', () => {
  const first = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:first-passkey',
    credentialIdB64u: 'first-credential',
    rpId: 'wallet.example.test',
    createdAtMs: 1,
  });
  const second = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:second-passkey',
    credentialIdB64u: 'second-credential',
    rpId: 'wallet.example.test',
    createdAtMs: 2,
  });
  const revokedFirst = buildRevokedLinkedDeviceAuthMethodV1(first, 3);
  const authenticators = [
    walletUnlockPasskeyAuthenticatorFixture({
      walletId: String(first.walletId),
      signerSlot: 1,
      credentialId: first.credentialIdB64u,
    }),
    walletUnlockPasskeyAuthenticatorFixture({
      walletId: String(second.walletId),
      signerSlot: 2,
      credentialId: second.credentialIdB64u,
    }),
  ];

  const allowCredentials = passkeySourceCredentialsForActiveMethods({
    walletId: first.walletId,
    authenticators,
    authMethods: [revokedFirst, second],
    excludeCredentialIdB64u: null,
  });

  expect(allowCredentials).toEqual([
    {
      id: second.credentialIdB64u,
      type: 'public-key',
      transports: ['internal'],
    },
  ]);
});
