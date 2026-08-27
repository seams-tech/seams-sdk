import { expect, test } from '@playwright/test';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { selectWalletRecoverySourcePasskey } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import {
  activeRecoveryEmailOtpMethodFixture,
  activeRecoveryPasskeyMethodFixture,
} from './helpers/walletRecovery.fixtures';

test('recovery selects the RP-matching Passkey when sibling methods are active', () => {
  const rpId = parseWebAuthnRpId('example.localhost');
  if (!rpId.ok) throw new Error('recovery source selection test RP ID is invalid');
  const selected = selectWalletRecoverySourcePasskey(
    [
      activeRecoveryEmailOtpMethodFixture({
        walletAuthMethodId: 'wallet-auth-method:email-sibling',
        createdAtMs: 2,
      }),
      activeRecoveryPasskeyMethodFixture({
        walletAuthMethodId: 'wallet-auth-method:source',
        credentialIdB64u: 'source-credential',
        rpId: 'example.localhost',
        createdAtMs: 1,
      }),
      activeRecoveryPasskeyMethodFixture({
        walletAuthMethodId: 'wallet-auth-method:other-rp',
        credentialIdB64u: 'other-rp-credential',
        rpId: 'other.example.localhost',
        createdAtMs: 0,
      }),
    ],
    rpId.value,
  );

  expect(selected?.walletAuthMethodId).toBe('wallet-auth-method:source');
});
