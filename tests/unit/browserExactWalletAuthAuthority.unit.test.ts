import { expect, test } from '@playwright/test';
import { resolveExactWalletAuthAuthority } from '@/SeamsWeb/assembly/browserSigningSurfaceAssembly';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';

function required<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw new Error(String(result.error));
  return result.value;
}

function passkeyMethod(args: {
  walletId: string;
  rpId: string;
  credentialIdB64u: string;
  status?: 'active' | 'revoked';
}): WalletAuthMethodRecordV2 {
  const status = args.status || 'active';
  return {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: required(parseWalletAuthMethodId('wallet-auth-method:exact-test')),
    walletId: required(parseWalletId(args.walletId)),
    walletAuthorityId: required(parseWalletAuthorityId('wallet-authority:exact-test')),
    kind: 'passkey',
    status,
    rpId: required(parseWebAuthnRpId(args.rpId)),
    credentialIdB64u: required(parseWebAuthnCredentialIdB64u(args.credentialIdB64u)),
    credentialPublicKeyB64u: 'AQID',
    counter: 0,
    createdAtMs: 1,
    updatedAtMs: 1,
    activatedAtMs: 1,
    ...(status === 'revoked' ? { revokedAtMs: 2 } : {}),
  };
}

function passkeyAuthority(method: Extract<WalletAuthMethodRecordV2, { kind: 'passkey' }>) {
  return {
    walletId: method.walletId,
    factor: { kind: 'passkey' as const, credentialIdB64u: method.credentialIdB64u },
    verifier: { kind: 'webauthn' as const, rpId: method.rpId },
    bindingId: method.walletAuthMethodId,
  };
}

test('resolves the exact passkey authority from the canonical wallet auth method', async () => {
  const method = passkeyMethod({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  if (method.kind !== 'passkey') throw new Error('expected passkey method');
  const exactAuthority = passkeyAuthority(method);
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const authority = await resolveExactWalletAuthAuthority(authorityRef, {
    getWalletAuthMethodV2: async () => method,
  });

  expect(authority).toEqual(exactAuthority);
});

// R103C: the active auth-method store is the only resolution source. A wallet
// whose authority reference has no active auth method fails closed — sealed
// runtime restores and loose authenticator rows can no longer answer for it.
test('fails closed when no active wallet auth method matches the authority', async () => {
  const method = passkeyMethod({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  if (method.kind !== 'passkey') throw new Error('expected passkey method');
  const exactAuthority = passkeyAuthority(method);
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  await expect(
    resolveExactWalletAuthAuthority(authorityRef, {
      getWalletAuthMethodV2: async () => null,
    }),
  ).rejects.toThrow('Exact wallet authentication authority is unavailable');
});

test('a revoked wallet auth method cannot resolve the active authority', async () => {
  const method = passkeyMethod({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  if (method.kind !== 'passkey') throw new Error('expected passkey method');
  const exactAuthority = passkeyAuthority(method);
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  await expect(
    resolveExactWalletAuthAuthority(authorityRef, {
      getWalletAuthMethodV2: async () => ({ ...method, status: 'revoked', revokedAtMs: 2 }),
    }),
  ).rejects.toThrow('Exact wallet authentication authority is unavailable');
});
