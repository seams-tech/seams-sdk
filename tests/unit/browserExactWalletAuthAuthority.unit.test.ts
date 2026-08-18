import { expect, test } from '@playwright/test';
import { resolveExactWalletAuthAuthority } from '@/SeamsWeb/assembly/browserSigningSurfaceAssembly';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

test('resolves the exact passkey authority from the canonical wallet auth method', async () => {
  const exactAuthority = buildPasskeyWalletAuthAuthority({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const authority = await resolveExactWalletAuthAuthority(authorityRef, {
    listWalletAuthMethodsForWallet: async () => [
      {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        localStatus: 'synced',
        walletId: exactAuthority.walletId,
        rpId: exactAuthority.verifier.rpId,
        credentialIdB64u: exactAuthority.factor.credentialIdB64u,
        credentialPublicKeyB64u: 'AQID',
        counter: 0,
        createdAtMs: 1,
        updatedAtMs: 1,
      },
    ],
  });

  expect(authority).toEqual(exactAuthority);
});

test('resolves the exact Email OTP authority from the canonical wallet auth method', async () => {
  const exactAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: 'registered-wallet',
    provider: 'email',
    providerUserId: 'email:registered-user',
    emailHashHex: 'email-hash',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const authority = await resolveExactWalletAuthAuthority(authorityRef, {
    listWalletAuthMethodsForWallet: async () => [
      {
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        localStatus: 'synced',
        walletId: exactAuthority.walletId,
        emailHashHex: exactAuthority.verifier.emailHashHex,
        registrationAuthorityId: 'registration-authority',
        authority: exactAuthority,
        createdAtMs: 1,
        updatedAtMs: 1,
      },
    ],
  });

  expect(authority).toEqual(exactAuthority);
  expect(await walletAuthAuthorityRef({ authority })).toEqual(authorityRef);
});

// R103C: the active auth-method store is the only resolution source. A wallet
// whose authority reference has no active auth method fails closed — sealed
// runtime restores and loose authenticator rows can no longer answer for it.
test('fails closed when no active wallet auth method matches the authority', async () => {
  const exactAuthority = buildPasskeyWalletAuthAuthority({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  await expect(
    resolveExactWalletAuthAuthority(authorityRef, {
      listWalletAuthMethodsForWallet: async () => [],
    }),
  ).rejects.toThrow('Exact wallet authentication authority is unavailable');
});

test('a revoked wallet auth method cannot resolve the active authority', async () => {
  const exactAuthority = buildPasskeyWalletAuthAuthority({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  await expect(
    resolveExactWalletAuthAuthority(authorityRef, {
      listWalletAuthMethodsForWallet: async () => [
        {
          version: 'wallet_auth_method_v1',
          kind: 'passkey',
          status: 'revoked',
          localStatus: 'synced',
          walletId: exactAuthority.walletId,
          rpId: exactAuthority.verifier.rpId,
          credentialIdB64u: exactAuthority.factor.credentialIdB64u,
          credentialPublicKeyB64u: 'AQID',
          counter: 0,
          createdAtMs: 1,
          updatedAtMs: 1,
        },
      ],
    }),
  ).rejects.toThrow('Exact wallet authentication authority is unavailable');
});
