import { expect, test } from '@playwright/test';
import {
  BrowserSigningSurface,
  resolveExactNearEd25519WalletSessionTokenForStepUp,
} from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import { IndexedDBManager } from '@/core/indexedDB';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import {
  walletSessionAuthorizations,
  type WalletSessionAuthorizationExactActiveReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  linkedDevicePermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';

type ResolvedOwnerAuthority = Extract<
  ResolveSelectedWalletAuthorityResultV1,
  { readonly kind: 'resolved' }
>;

function createSurfaceForOwnerLaneResolution(): BrowserSigningSurface {
  return Object.create(BrowserSigningSurface.prototype) as BrowserSigningSurface;
}

function resolvedOwnerAuthority(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>,
): ResolvedOwnerAuthority {
  return {
    kind: 'resolved',
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

test('resolves the selected owner lane from its exact Wallet Session tuple', async () => {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner-lane-exact',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'device_link',
    keyFamily: 'ecdsa_secp256k1',
    expiresAtMs: Date.now() + 60_000,
  });
  const surface = createSurfaceForOwnerLaneResolution();
  const originalResolveSelected = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalReadExact = walletSessionAuthorizations.readExactActiveForWallet;
  let exactReadInput:
    | Parameters<typeof walletSessionAuthorizations.readExactActiveForWallet>[0]
    | null = null;
  try {
    IndexedDBManager.resolveSelectedWalletAuthority = async () => resolvedOwnerAuthority(fixture);
    walletSessionAuthorizations.readExactActiveForWallet = async (input) => {
      exactReadInput = input;
      return {
        kind: 'found',
        record: fixture.activeWalletSession,
        operationCredential: fixture.operationCredential,
      };
    };
    await expect(surface.resolveActiveOwnerLaneScope(fixture.authority.walletId)).resolves.toEqual({
      auth: {
        kind: 'passkey',
        rpId: fixture.authMethod.rpId,
        credentialIdB64u: fixture.authMethod.credentialIdB64u,
      },
      keyFamily: 'ecdsa',
    });
    expect(exactReadInput).toEqual({
      walletId: fixture.authority.walletId,
      authorityId: fixture.authority.authorityId,
      authMethodId: fixture.authMethod.walletAuthMethodId,
    });
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelected;
    walletSessionAuthorizations.readExactActiveForWallet = originalReadExact;
  }
});

test('fails closed for exact owner-session read states', async () => {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner-lane-failure',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'device_link',
    keyFamily: 'ecdsa_secp256k1',
    expiresAtMs: Date.now() + 60_000,
  });
  const surface = createSurfaceForOwnerLaneResolution();
  const originalResolveSelected = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalReadExact = walletSessionAuthorizations.readExactActiveForWallet;
  const cases: ReadonlyArray<{
    readonly read: WalletSessionAuthorizationExactActiveReadResult;
    readonly message: string;
  }> = [
    {
      read: { kind: 'missing' },
      message: 'selected Wallet Authority session is unavailable: missing',
    },
    {
      read: { kind: 'upgrade_required' },
      message: 'selected Wallet Authority Wallet Session requires a newer client',
    },
    {
      read: { kind: 'corrupt' },
      message: 'selected Wallet Authority session is unavailable: corrupt',
    },
    {
      read: { kind: 'persistence_unavailable' },
      message: 'selected Wallet Authority session is unavailable: persistence_unavailable',
    },
  ];
  let exactRead: WalletSessionAuthorizationExactActiveReadResult = cases[0].read;
  try {
    IndexedDBManager.resolveSelectedWalletAuthority = async () => resolvedOwnerAuthority(fixture);
    walletSessionAuthorizations.readExactActiveForWallet = async () => exactRead;

    for (const failureCase of cases) {
      exactRead = failureCase.read;
      await expect(surface.resolveActiveOwnerLaneScope(fixture.authority.walletId)).rejects.toThrow(
        failureCase.message,
      );
    }
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelected;
    walletSessionAuthorizations.readExactActiveForWallet = originalReadExact;
  }
});

test('does not infer an owner lane when the wallet selection is missing', async () => {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner-lane-no-selection',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'device_link',
    keyFamily: 'ecdsa_secp256k1',
    expiresAtMs: Date.now() + 60_000,
  });
  const surface = createSurfaceForOwnerLaneResolution();
  const originalResolveSelected = IndexedDBManager.resolveSelectedWalletAuthority;
  try {
    IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
      kind: 'missing_selection',
    });

    await expect(surface.resolveActiveOwnerLaneScope(fixture.authority.walletId)).rejects.toThrow(
      'selected Wallet Authority is missing_selection',
    );
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelected;
  }
});

test('resolves operation step-up from the selected exact Wallet Session credential', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const originalResolveSelected = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalReadExact = walletSessionAuthorizations.readExactWithOperationCredential;
  let exactReadInput:
    | Parameters<typeof walletSessionAuthorizations.readExactWithOperationCredential>[0]
    | null = null;
  try {
    IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
      kind: 'resolved',
      selection: fixture.selection,
      authMethod: fixture.authMethod,
      authority: fixture.authority,
      signerMaterials: fixture.signerMaterials,
      exportRoot: null,
    });
    walletSessionAuthorizations.readExactWithOperationCredential = async (input) => {
      exactReadInput = input;
      return {
        kind: 'found',
        record: fixture.activeWalletSession,
        operationCredential: fixture.operationCredential,
      };
    };
    await expect(
      resolveExactNearEd25519WalletSessionTokenForStepUp({
        walletId: fixture.walletId,
        proof: {
          kind: 'passkey',
          authority: fixture.factorAuthority,
          credential: fixture.credential,
        },
      }),
    ).resolves.toBe(fixture.operationCredential.token);
    expect(exactReadInput).toEqual({
      walletId: fixture.walletId,
      authorityId: fixture.authority.authorityId,
      authMethodId: fixture.authMethod.walletAuthMethodId,
    });
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelected;
    walletSessionAuthorizations.readExactWithOperationCredential = originalReadExact;
  }
});

test('fails closed when operation step-up has no selected exact Wallet Session', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const originalResolveSelected = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalReadExact = walletSessionAuthorizations.readExactWithOperationCredential;
  try {
    IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
      kind: 'resolved',
      selection: fixture.selection,
      authMethod: fixture.authMethod,
      authority: fixture.authority,
      signerMaterials: fixture.signerMaterials,
      exportRoot: null,
    });
    walletSessionAuthorizations.readExactWithOperationCredential = async () => ({
      kind: 'missing',
    });
    await expect(
      resolveExactNearEd25519WalletSessionTokenForStepUp({
        walletId: fixture.walletId,
        proof: {
          kind: 'passkey',
          authority: fixture.factorAuthority,
          credential: fixture.credential,
        },
      }),
    ).rejects.toThrow('exact Wallet Session is unavailable for operation step-up');
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelected;
    walletSessionAuthorizations.readExactWithOperationCredential = originalReadExact;
  }
});
