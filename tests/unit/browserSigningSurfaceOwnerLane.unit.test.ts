import { expect, test } from '@playwright/test';
import {
  BrowserSigningSurface,
  resolveBrowserNearEd25519EmailOtpAuthorityForMaterial,
  resolveExactNearEd25519WalletSessionOperationCredentialForStepUp,
} from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import { resolveBrowserNearEd25519PasskeyAuthorityForMaterial } from '@/SeamsWeb/assembly/browserSigningSurfaceAssembly';
import { IndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import {
  walletSessionAuthorizations,
  type WalletSessionAuthorizationExactActiveReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { nearEd25519SignerBindingFromBoundaryFields } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  extendFixtureAuthorityWithEcdsaSigner,
  linkedDevicePermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  buildPasskeyEd25519SealedSessionRecordFixture,
  buildPasskeyExactEd25519AuthorizationFixture,
  buildEmailOtpEd25519SealedSessionRecordFixture,
  buildEmailOtpExactEd25519AuthorizationFixture,
} from './helpers/sealedSigningSession.fixtures';
import { walletUnlockEmailOtpAuthMethodFixture } from './helpers/walletUnlockProfile.fixtures';

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
      resolveExactNearEd25519WalletSessionOperationCredentialForStepUp({
        walletId: fixture.walletId,
        proof: {
          kind: 'passkey',
          authority: fixture.factorAuthority,
          credential: fixture.credential,
        },
      }),
    ).resolves.toEqual(fixture.operationCredential);
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
      resolveExactNearEd25519WalletSessionOperationCredentialForStepUp({
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

test('resolves the selected Passkey factor for an exhausted sealed runtime without a session credential', async () => {
  const record = buildPasskeyEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('Passkey sealed runtime fixture is invalid');
  const authorization = buildPasskeyExactEd25519AuthorizationFixture(record);
  const selected = {
    kind: 'resolved' as const,
    selection: {
      kind: 'wallet_selection_v1' as const,
      walletId: authorization.selectedAuthority.walletId,
      walletAuthMethodId: authorization.selectedAuthMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked' as const,
      updatedAtMs: 2,
    },
    authMethod: authorization.selectedAuthMethod,
    authority: authorization.selectedAuthority,
    signerMaterials: [],
    exportRoot: null,
  };
  const originalResolveSelected = IndexedDBManager.resolveSelectedWalletAuthority;
  try {
    IndexedDBManager.resolveSelectedWalletAuthority = async () => selected;

    const resolved = await resolveBrowserNearEd25519PasskeyAuthorityForMaterial({
      walletId: authorization.selectedAuthority.walletId,
      runtime,
      authorizationRead: { kind: 'exhausted' },
    });
    expect(resolved).toEqual(
      await walletAuthAuthorityRef({ authority: authorization.selectedFactorAuthority }),
    );
    expect(resolved).not.toHaveProperty('operationCredential');

    const mismatchedRecord = buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: record.walletId,
      nearAccountId: record.ed25519Restore.nearAccountId,
      nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
      thresholdSessionId: 'ed25519-sealed-runtime-mismatched-factor',
      materialActivation: record.ed25519Restore.materialActivation,
      credentialIdB64u: 'ed25519-sealed-runtime-mismatched-credential',
    });
    const mismatchedRuntime = parseExactEd25519SealedSessionRuntime(mismatchedRecord);
    if (!mismatchedRuntime) throw new Error('mismatched Passkey runtime fixture is invalid');
    await expect(
      resolveBrowserNearEd25519PasskeyAuthorityForMaterial({
        walletId: authorization.selectedAuthority.walletId,
        runtime: mismatchedRuntime,
        authorizationRead: { kind: 'exhausted' },
      }),
    ).rejects.toThrow('exact Passkey authority changed');
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelected;
  }
});

test('resolves the selected Email OTP factor for exhausted Ed25519 step-up without a session credential', async () => {
  const record = buildEmailOtpEd25519SealedSessionRecordFixture();
  if (!('provider' in record.ed25519Restore)) {
    throw new Error('Email OTP sealed runtime fixture is invalid');
  }
  const authorization = buildEmailOtpExactEd25519AuthorizationFixture(record);
  const promotedAuthority = await extendFixtureAuthorityWithEcdsaSigner(
    authorization.selectedAuthority,
  );
  const restore = record.ed25519Restore;
  const identity = {
    kind: 'near_ed25519_material_identity' as const,
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: authorization.selectedAuthority.walletId,
      nearAccountId: restore.nearAccountId,
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(restore.nearEd25519SigningKeyId),
      signerSlot: restore.signerSlot,
    }),
    auth: {
      kind: 'email_otp' as const,
      providerSubjectId: restore.providerSubjectId,
    },
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      record.thresholdSessionIds.ed25519,
    ),
  };
  const localFactor = walletUnlockEmailOtpAuthMethodFixture({
    walletId: String(record.walletId),
    providerSubjectId: restore.providerSubjectId,
    emailHashHex: restore.emailHashHex,
  });
  const selected = {
    kind: 'resolved' as const,
    selection: {
      kind: 'wallet_selection_v1' as const,
      walletId: promotedAuthority.walletId,
      walletAuthMethodId: authorization.selectedAuthMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked' as const,
      updatedAtMs: 2,
    },
    authMethod: authorization.selectedAuthMethod,
    authority: promotedAuthority,
    signerMaterials: [],
    exportRoot: null,
  };
  const originalResolveSelected = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalListAuthMethods = IndexedDBManager.listWalletAuthMethodsForWallet;
  try {
    IndexedDBManager.resolveSelectedWalletAuthority = async () => selected;
    IndexedDBManager.listWalletAuthMethodsForWallet = async () => [localFactor];

    const resolved = await resolveBrowserNearEd25519EmailOtpAuthorityForMaterial({
      walletId: authorization.selectedAuthority.walletId,
      nearAccountId: toAccountId(restore.nearAccountId),
      identity,
      signerSlot: restore.signerSlot,
      materialActivation: restore.materialActivation,
      authorizationRead: { kind: 'exhausted' },
    });
    expect(resolved).not.toBeNull();
    if (!resolved) throw new Error('Email OTP factor authority was not resolved');
    expect(resolved).toEqual(
      await walletAuthAuthorityRef({ authority: authorization.selectedFactorAuthority }),
    );
    expect(promotedAuthority.authorityDigestB64u).not.toBe(resolved.authorityDigest);
    expect(resolved).not.toHaveProperty('operationCredential');

    const mismatchedMaterial = buildMpcMaterialActivationRefFixture(
      'email-otp-ed25519-mismatched-material',
      String(record.walletId),
    );
    await expect(
      resolveBrowserNearEd25519EmailOtpAuthorityForMaterial({
        walletId: authorization.selectedAuthority.walletId,
        nearAccountId: toAccountId(restore.nearAccountId),
        identity,
        signerSlot: restore.signerSlot,
        materialActivation: mismatchedMaterial,
        authorizationRead: { kind: 'exhausted' },
      }),
    ).resolves.toBeNull();

    const mismatchedIdentity = {
      kind: 'near_ed25519_material_identity' as const,
      signer: identity.signer,
      auth: {
        kind: 'email_otp' as const,
        providerSubjectId: 'google:email-otp-ed25519-mismatched',
      },
      thresholdSessionId: identity.thresholdSessionId,
    };
    await expect(
      resolveBrowserNearEd25519EmailOtpAuthorityForMaterial({
        walletId: authorization.selectedAuthority.walletId,
        nearAccountId: toAccountId(restore.nearAccountId),
        identity: mismatchedIdentity,
        signerSlot: restore.signerSlot,
        materialActivation: restore.materialActivation,
        authorizationRead: { kind: 'exhausted' },
      }),
    ).resolves.toBeNull();
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelected;
    IndexedDBManager.listWalletAuthMethodsForWallet = originalListAuthMethods;
  }
});
