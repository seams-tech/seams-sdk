import { expect, test } from '@playwright/test';
import { resolveAddAuthMethodSourceClaimV1 } from '@/SeamsWeb/operations/authMethods/addAuthMethodSourceClaim';
import { IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

type SourceClaimFixture = Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>;

async function sourceClaimFixture(): Promise<SourceClaimFixture> {
  return await buildLinkedDeviceManagementAuthorityFixture({
    label: 'add-auth-method-source',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: 'wallet:add-auth-method-source',
      authorityId: 'authority:add-auth-method-source',
      walletAuthMethodId: 'auth-method:add-auth-method-source',
      rpId: 'wallet.example.test',
    },
  });
}

function resolvedSourceSelection(fixture: SourceClaimFixture) {
  return {
    kind: 'resolved' as const,
    selection: {
      kind: 'wallet_selection_v1' as const,
      walletId: fixture.authority.walletId,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked' as const,
      updatedAtMs: 1,
    },
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

test('add-method source claim reads the selected exact Wallet Session tuple', async () => {
  const fixture = await sourceClaimFixture();
  const originalResolve = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalRead = walletSessionAuthorizations.readExactWithOperationCredential;
  const exactReads: unknown[] = [];
  IndexedDBManager.resolveSelectedWalletAuthority = async () => resolvedSourceSelection(fixture);
  walletSessionAuthorizations.readExactWithOperationCredential = async (input) => {
    exactReads.push(input);
    return {
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    };
  };

  try {
    const result = await resolveAddAuthMethodSourceClaimV1(fixture.authority.walletId);

    expect(result).toEqual({
      kind: 'resolved',
      sourceAuthMethod: fixture.authMethod,
      source: {
        walletAuthorityId: fixture.authority.authorityId,
        walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
        walletSessionId: fixture.operationCredential.walletSessionId,
        authorityDigestB64u: fixture.authority.authorityDigestB64u,
        revocationEpoch: fixture.authority.revocationEpoch,
      },
    });
    expect(exactReads).toEqual([
      {
        walletId: fixture.authority.walletId,
        authorityId: fixture.authority.authorityId,
        authMethodId: fixture.authMethod.walletAuthMethodId,
      },
    ]);
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolve;
    walletSessionAuthorizations.readExactWithOperationCredential = originalRead;
  }
});

test('add-method source claim fails closed when the selected exact session is absent', async () => {
  const fixture = await sourceClaimFixture();
  const originalResolve = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalRead = walletSessionAuthorizations.readExactWithOperationCredential;
  IndexedDBManager.resolveSelectedWalletAuthority = async () => resolvedSourceSelection(fixture);
  walletSessionAuthorizations.readExactWithOperationCredential = async () => ({
    kind: 'missing',
  });

  try {
    await expect(resolveAddAuthMethodSourceClaimV1(fixture.authority.walletId)).resolves.toEqual({
      kind: 'unavailable',
      reason: 'exact Wallet Session is missing',
    });
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolve;
    walletSessionAuthorizations.readExactWithOperationCredential = originalRead;
  }
});

test('add-method source claims keep same-wallet sibling methods isolated', async () => {
  const primary = await sourceClaimFixture();
  const sibling = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'add-auth-method-source-sibling',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: String(primary.authority.walletId),
      authorityId: 'authority:add-auth-method-source-sibling',
      walletAuthMethodId: 'auth-method:add-auth-method-source-sibling',
      rpId: 'wallet.example.test',
    },
  });
  const originalResolve = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalRead = walletSessionAuthorizations.readExactWithOperationCredential;
  const exactReads: unknown[] = [];
  let selected = resolvedSourceSelection(primary);
  const sessionsByMethod = new Map([
    [String(primary.authMethod.walletAuthMethodId), primary],
    [String(sibling.authMethod.walletAuthMethodId), sibling],
  ]);
  IndexedDBManager.resolveSelectedWalletAuthority = async () => selected;
  walletSessionAuthorizations.readExactWithOperationCredential = async (input) => {
    exactReads.push(input);
    const fixture = sessionsByMethod.get(String(input.authMethodId));
    if (!fixture) return { kind: 'missing' as const };
    return {
      kind: 'found' as const,
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    };
  };

  try {
    const primaryResult = await resolveAddAuthMethodSourceClaimV1(primary.authority.walletId);
    selected = resolvedSourceSelection(sibling);
    const siblingResult = await resolveAddAuthMethodSourceClaimV1(sibling.authority.walletId);

    expect(primaryResult).toMatchObject({
      kind: 'resolved',
      sourceAuthMethod: primary.authMethod,
      source: {
        walletAuthorityId: primary.authMethod.walletAuthorityId,
        walletAuthMethodId: primary.authMethod.walletAuthMethodId,
        walletSessionId: primary.operationCredential.walletSessionId,
      },
    });
    expect(siblingResult).toMatchObject({
      kind: 'resolved',
      sourceAuthMethod: sibling.authMethod,
      source: {
        walletAuthorityId: sibling.authMethod.walletAuthorityId,
        walletAuthMethodId: sibling.authMethod.walletAuthMethodId,
        walletSessionId: sibling.operationCredential.walletSessionId,
      },
    });
    expect(exactReads).toEqual([
      {
        walletId: primary.authority.walletId,
        authorityId: primary.authority.authorityId,
        authMethodId: primary.authMethod.walletAuthMethodId,
      },
      {
        walletId: sibling.authority.walletId,
        authorityId: sibling.authority.authorityId,
        authMethodId: sibling.authMethod.walletAuthMethodId,
      },
    ]);
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolve;
    walletSessionAuthorizations.readExactWithOperationCredential = originalRead;
  }
});
