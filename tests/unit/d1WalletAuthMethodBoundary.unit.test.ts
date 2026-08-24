import { expect, test } from '@playwright/test';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import type { RegistrationAuthority } from '../../packages/shared-ts/src/utils/registrationIntent';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import { walletAuthAuthorityFromRegistrationAuthority } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodBoundary';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

test('registration authority uses the exact prepared opaque wallet auth method id', () => {
  const walletId = required(parseWalletId('wallet-r103e-boundary'));
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u('credential-r103e-boundary'));
  const walletAuthMethodId = required(
    parseWalletAuthMethodId('wallet-auth-method:prepared-r103e-boundary'),
  );
  const authority: Extract<RegistrationAuthority, { readonly kind: 'passkey' }> = {
    kind: 'passkey',
    walletId,
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: 'credential-public-key-r103e-boundary',
    counter: 0,
    device: unknownWebAuthnAuthenticatorDeviceInfo(),
    registrationIntentDigestB64u: 'registration-intent-r103e-boundary',
  };

  const result = walletAuthAuthorityFromRegistrationAuthority({
    authority,
    walletAuthMethodId,
  });

  expect(result.bindingId).toBe(walletAuthMethodId);
  expect(result.bindingId).not.toBe(`passkey:${rpId}:${credentialIdB64u}`);
});
