import { expect, test } from '@playwright/test';
import {
  buildExactPasskeyOwnerLaneScope,
  isOwnerRelinkRequiredError,
  resolveOwnerLaneScope,
  type OwnerLaneScopeStores,
} from '@/core/signingEngine/session/identity/ownerLaneScope';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';

const WALLET_ID = 'owner-lane-scope-wallet';
const RP_ID = 'localhost';
const CREDENTIAL_ID = 'credential-owner-scope';

function required<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw new Error(String(result.error));
  return result.value;
}

function passkeyAuthMethod(args?: {
  credentialId?: string;
  rpId?: string;
}): WalletAuthMethodRecordV2 {
  return {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: required(parseWalletAuthMethodId('wallet-auth-method:owner-scope')),
    walletId: required(parseWalletId(WALLET_ID)),
    walletAuthorityId: required(parseWalletAuthorityId('wallet-authority:owner-scope')),
    kind: 'passkey',
    status: 'active',
    rpId: required(parseWebAuthnRpId(args?.rpId || RP_ID)),
    credentialIdB64u: required(parseWebAuthnCredentialIdB64u(args?.credentialId || CREDENTIAL_ID)),
    credentialPublicKeyB64u: 'AQID',
    counter: 0,
    createdAtMs: 1,
    updatedAtMs: 1,
    activatedAtMs: 1,
  };
}

function stores(args: {
  authMethod: WalletAuthMethodRecordV2 | null;
  authenticator?: { credentialId: string; signerSlot: number } | null;
}): OwnerLaneScopeStores {
  return {
    getWalletAuthMethodV2: async () => args.authMethod,
    listWalletAuthMethodsForWallet: async () => [],
    getWalletPasskeyAuthenticator: async () =>
      args.authenticator === undefined
        ? { credentialId: CREDENTIAL_ID, signerSlot: 2 }
        : args.authenticator,
  };
}

async function passkeyAuthorityRef() {
  const authMethod = passkeyAuthMethod();
  return await walletAuthAuthorityRef({
    authority: {
      walletId: authMethod.walletId,
      factor: { kind: 'passkey', credentialIdB64u: authMethod.credentialIdB64u },
      verifier: { kind: 'webauthn', rpId: authMethod.rpId },
      bindingId: authMethod.walletAuthMethodId,
    },
  });
}

test('builds an exact Passkey owner scope from the V2 method and parsed signer slot', () => {
  const authMethod = passkeyAuthMethod();
  if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') {
    throw new Error('expected an active Passkey auth method');
  }
  const signerSlot = parseSignerSlot(7, { min: 1 });
  if (signerSlot === null) throw new Error('expected a parsed signer slot');

  expect(buildExactPasskeyOwnerLaneScope({ authMethod, signerSlot })).toEqual({
    auth: { kind: 'passkey', rpId: RP_ID, credentialIdB64u: CREDENTIAL_ID },
    signerSlot: 7,
  });
});

test('derives the passkey owner scope with the slot of the credential-resolved authenticator', async () => {
  const scope = await resolveOwnerLaneScope({
    authorityRef: await passkeyAuthorityRef(),
    stores: stores({ authMethod: passkeyAuthMethod() }),
  });
  expect(scope).toMatchObject({
    auth: { kind: 'passkey', credentialIdB64u: CREDENTIAL_ID },
    signerSlot: 2,
  });
});

test('a missing canonical auth method is a typed relink requirement, not a generic failure', async () => {
  const error = await resolveOwnerLaneScope({
    authorityRef: await passkeyAuthorityRef(),
    stores: stores({ authMethod: null }),
  }).then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect(isOwnerRelinkRequiredError(error)).toBe(true);
  expect((error as Error).message).toContain('relink_required');
});

test('a revoked auth method resolves to the relink requirement', async () => {
  const active = passkeyAuthMethod();
  const error = await resolveOwnerLaneScope({
    authorityRef: await passkeyAuthorityRef(),
    stores: stores({ authMethod: { ...active, status: 'revoked', revokedAtMs: 2 } }),
  }).then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect(isOwnerRelinkRequiredError(error)).toBe(true);
});

test('an auth method that cannot reproduce the authority digest is an integrity failure', async () => {
  const activeMethod = passkeyAuthMethod();
  const activeAuthority = {
    walletId: activeMethod.walletId,
    factor: { kind: 'passkey' as const, credentialIdB64u: activeMethod.credentialIdB64u },
    verifier: { kind: 'webauthn' as const, rpId: activeMethod.rpId },
    bindingId: activeMethod.walletAuthMethodId,
  };
  const impostorMethod = passkeyAuthMethod({ credentialId: 'credential-owner-impostor' });

  const error = await resolveOwnerLaneScope({
    authorityRef: await walletAuthAuthorityRef({ authority: activeAuthority }),
    stores: stores({ authMethod: impostorMethod }),
  }).then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect((error as Error).name).toBe('OwnerLaneScopeIntegrityError');
  expect((error as Error).message).toContain('authority digest');
});

test('a passkey owner without its exact local authenticator fails closed', async () => {
  const error = await resolveOwnerLaneScope({
    authorityRef: await passkeyAuthorityRef(),
    stores: stores({ authMethod: passkeyAuthMethod(), authenticator: null }),
  }).then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect((error as Error).name).toBe('OwnerLaneScopeIntegrityError');
  expect((error as Error).message).toContain('no exact local authenticator');
});
