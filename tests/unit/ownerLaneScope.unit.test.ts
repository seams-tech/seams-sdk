import { expect, test } from '@playwright/test';
import {
  isOwnerRelinkRequiredError,
  resolveOwnerLaneScope,
  type OwnerLaneScopeStores,
} from '@/core/signingEngine/session/identity/ownerLaneScope';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { LocalWalletAuthMethodRecord } from '@/core/indexedDB/passkeyClientDB.types';
import {
  walletUnlockEmailOtpAuthMethodFixture,
  walletUnlockPasskeyAuthMethodFixture,
} from './helpers/walletUnlockProfile.fixtures';

const WALLET_ID = 'owner-lane-scope-wallet';
const RP_ID = 'localhost';
const CREDENTIAL_ID = 'credential-owner-scope';

function passkeyAuthMethod(): LocalWalletAuthMethodRecord {
  return walletUnlockPasskeyAuthMethodFixture({
    walletId: WALLET_ID,
    credentialId: CREDENTIAL_ID,
  });
}

function stores(args: {
  authMethods: readonly LocalWalletAuthMethodRecord[];
  authenticator?: { credentialId: string; signerSlot: number } | null;
}): OwnerLaneScopeStores {
  return {
    listWalletAuthMethodsForWallet: async () => args.authMethods,
    getWalletPasskeyAuthenticator: async () =>
      args.authenticator === undefined
        ? { credentialId: CREDENTIAL_ID, signerSlot: 2 }
        : args.authenticator,
  };
}

async function passkeyAuthorityRef() {
  return await walletAuthAuthorityRef({
    authority: buildPasskeyWalletAuthAuthority({
      walletId: WALLET_ID,
      rpId: RP_ID,
      credentialIdB64u: CREDENTIAL_ID,
    }),
  });
}

test('derives the passkey owner scope with the slot of the credential-resolved authenticator', async () => {
  const scope = await resolveOwnerLaneScope({
    authorityRef: await passkeyAuthorityRef(),
    stores: stores({ authMethods: [passkeyAuthMethod()] }),
  });
  expect(scope).toMatchObject({
    auth: { kind: 'passkey', credentialIdB64u: CREDENTIAL_ID },
    signerSlot: 2,
  });
});

test('a missing canonical auth method is a typed relink requirement, not a generic failure', async () => {
  const error = await resolveOwnerLaneScope({
    authorityRef: await passkeyAuthorityRef(),
    stores: stores({ authMethods: [] }),
  }).then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect(isOwnerRelinkRequiredError(error)).toBe(true);
  expect((error as Error).message).toContain('relink_required');
});

test('a revoked auth method resolves to the relink requirement', async () => {
  const active = passkeyAuthMethod();
  if (active.kind !== 'passkey') throw new Error('expected passkey auth method fixture');
  const error = await resolveOwnerLaneScope({
    authorityRef: await passkeyAuthorityRef(),
    stores: stores({ authMethods: [{ ...active, status: 'revoked' }] }),
  }).then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect(isOwnerRelinkRequiredError(error)).toBe(true);
});

test('an auth method that cannot reproduce the authority digest is an integrity failure', async () => {
  // Same wallet and emailHashHex (the method id inputs) but a different
  // provider subject: the id matches while the digest cannot.
  const activeAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: 'google:subject-active',
    emailHashHex: 'owner-scope-email-hash',
  });
  const impostorAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: 'google:subject-impostor',
    emailHashHex: 'owner-scope-email-hash',
  });
  const emailAuthMethod = walletUnlockEmailOtpAuthMethodFixture({
    walletId: WALLET_ID,
    providerSubjectId: 'google:subject-impostor',
    emailHashHex: 'owner-scope-email-hash',
  });
  expect(emailAuthMethod.authority).toEqual(impostorAuthority);

  const error = await resolveOwnerLaneScope({
    authorityRef: await walletAuthAuthorityRef({ authority: activeAuthority }),
    stores: stores({ authMethods: [emailAuthMethod] }),
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
    stores: stores({ authMethods: [passkeyAuthMethod()], authenticator: null }),
  }).then(
    () => null,
    (thrown: unknown) => thrown,
  );
  expect((error as Error).name).toBe('OwnerLaneScopeIntegrityError');
  expect((error as Error).message).toContain('no exact local authenticator');
});
