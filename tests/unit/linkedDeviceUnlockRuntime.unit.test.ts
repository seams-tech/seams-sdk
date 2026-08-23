import { expect, test } from '@playwright/test';
import {
  resolveLinkedDevicePasskeyAuthoritySelection,
  unlockLinkedDevicePasskey,
} from '@/SeamsWeb/operations/auth/login';
import { BrowserSigningSurface } from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import type { LoginWebContext } from '@/SeamsWeb/signingSurface/types';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { configureIndexedDB, IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { MinimalNearClient } from '@/core/rpcClients/near/NearClient';
import type { NearEd25519YaoOperationMaterial } from '@/core/signingEngine/interfaces/near';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  Ed25519YaoActiveClientRegistry,
  type Ed25519YaoActiveClientIdentityV1,
} from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import {
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoActiveClientMetadataV1,
  type RouterAbEd25519YaoActiveClientV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  clearLinkedEcdsaHolderRuntimesV1,
  installLinkedEcdsaHolderRuntimeV1,
  listLinkedEcdsaHolderRuntimesV1,
  resolveLinkedEcdsaHolderRuntimeV1,
} from '@/core/signingEngine/session/material/linkedEcdsaHolderRuntime';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { base64UrlEncode } from '@shared/utils/base64';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';

configureIndexedDB({ mode: 'disabled' });

type FakeLinkedYaoClient = RouterAbEd25519YaoActiveClientV1 & {
  readonly disposeCount: () => number;
};

function fakeLinkedYaoClient(
  metadata: RouterAbEd25519YaoActiveClientMetadataV1,
): FakeLinkedYaoClient {
  let disposed = false;
  let disposeCount = 0;
  return {
    createSigningShare: async () => {
      throw new Error('linked runtime test does not sign');
    },
    metadata: () => metadata,
    status: () => (disposed ? { kind: 'disposed' } : { kind: 'active' }),
    dispose: () => {
      if (disposed) return;
      disposed = true;
      disposeCount += 1;
    },
    disposeCount: () => disposeCount,
  };
}

function linkedRuntimeIdentity(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceUnlockRuntimeFixture>>,
): Ed25519YaoActiveClientIdentityV1 {
  const ed25519Activation = fixture.authority.signerActivations.ed25519;
  if (!ed25519Activation) throw new Error('linked runtime fixture is missing Ed25519 activation');
  return {
    walletId: toWalletId(String(fixture.walletId)),
    nearAccountId: toAccountId(fixture.ed25519Session.nearAccountId),
    materialActivation: ed25519Activation.materialActivation,
  };
}

function createWorkerContext(args: {
  readonly storedHandles: string[];
  readonly disposedHandles: string[];
}): WorkerOperationContext {
  const requestWorkerOperation = async ({
    kind,
    request,
  }: {
    readonly kind: string;
    readonly request: { readonly type: number; readonly payload: unknown };
  }): Promise<unknown> => {
    if (kind !== 'ecdsaDerivationClient') {
      throw new Error(`unexpected worker kind: ${kind}`);
    }
    if (
      request.type === EcdsaDerivationClientCustomRequestType.StoreLinkedDeviceEcdsaHolderMaterial
    ) {
      const payload = request.payload as { readonly holderHandleId: string };
      args.storedHandles.push(payload.holderHandleId);
      return {
        type: EcdsaDerivationClientCustomResponseType.StoreLinkedDeviceEcdsaHolderMaterialSuccess,
        payload: { holderHandleId: payload.holderHandleId },
      };
    }
    if (
      request.type ===
      EcdsaDerivationClientCustomRequestType.DisposeLinkedDeviceEcdsaHolderMaterials
    ) {
      const payload = request.payload as
        | { readonly kind: 'one'; readonly holderHandleId: string }
        | { readonly kind: 'all' };
      if (payload.kind === 'one') args.disposedHandles.push(payload.holderHandleId);
      return {
        type: EcdsaDerivationClientCustomResponseType.DisposeLinkedDeviceEcdsaHolderMaterialsSuccess,
        payload,
      };
    }
    throw new Error(`unexpected ECDSA worker request: ${String(request.type)}`);
  };
  return { requestWorkerOperation } as unknown as WorkerOperationContext;
}

function buildLockSurface(args: {
  readonly activeClients: Ed25519YaoActiveClientRegistry;
  readonly workerContext: WorkerOperationContext;
}): BrowserSigningSurface {
  const surface = Object.create(BrowserSigningSurface.prototype) as BrowserSigningSurface;
  const internals = surface as unknown as {
    enginePorts: {
      ed25519YaoActiveClients: Ed25519YaoActiveClientRegistry;
    };
    warmCapabilitiesPublicDeps: {
      clearVolatileWarmSigningMaterial(walletId?: unknown): Promise<void>;
    };
    signerWorkerManager: {
      getContext(): WorkerOperationContext;
    };
  };
  internals.enginePorts = { ed25519YaoActiveClients: args.activeClients };
  internals.warmCapabilitiesPublicDeps = {
    clearVolatileWarmSigningMaterial: async () => {},
  };
  internals.signerWorkerManager = {
    getContext: () => args.workerContext,
  };
  return surface;
}

test('linked V2 unlock installs live owners, lock retires them, and exact re-unlock is idempotent', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const activeClients = new Ed25519YaoActiveClientRegistry();
  const storedHandles: string[] = [];
  const disposedHandles: string[] = [];
  const workerContext = createWorkerContext({ storedHandles, disposedHandles });
  const importedClients: FakeLinkedYaoClient[] = [];
  const originalInitializeBundled = RouterAbEd25519YaoClientV1.initializeBundled;
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalGetProfile = IndexedDBManager.getProfile;
  const originalWriteExact = walletSessionAuthorizations.writeExact;
  const originalWriteExactWithOperationCredential =
    walletSessionAuthorizations.writeExactWithOperationCredential;
  const originalUpsertActiveWithCurveMerge = walletSessionAuthorizations.upsertActiveWithCurveMerge;
  const originalFetch = globalThis.fetch;
  const writtenSessions: unknown[] = [];
  const projectionWrites: unknown[] = [];
  const authenticatedStates: unknown[] = [];
  const activatedMaterials: NearEd25519YaoOperationMaterial[] = [];
  const walletId = toWalletId(String(fixture.walletId));
  const identity = linkedRuntimeIdentity(fixture);
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('linked runtime fixture is missing ECDSA activation');

  Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', async () => ({
    importLinkedMaterial: (input: {
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    }) => {
      const client = fakeLinkedYaoClient(input.metadata);
      importedClients.push(client);
      return client;
    },
  }));
  const resolveSelectedAuthority = async () => ({
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: fixture.signerMaterials,
    exportRoot: null,
  });
  IndexedDBManager.resolveSelectedWalletAuthority = resolveSelectedAuthority;
  IndexedDBManager.getProfile = async () => {
    throw new Error('legacy profile rows are unavailable during linked V2 reload');
  };
  walletSessionAuthorizations.writeExact = async (record) => {
    writtenSessions.push(record);
    return record;
  };
  walletSessionAuthorizations.writeExactWithOperationCredential = async (input) => {
    writtenSessions.push(input);
    return input.record;
  };
  walletSessionAuthorizations.upsertActiveWithCurveMerge = async (args) => {
    projectionWrites.push(args.incoming);
    return args.incoming;
  };
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === '/wallet/unlock/challenge') {
      return new Response(
        JSON.stringify({
          ok: true,
          challengeId: 'challenge:linked-runtime',
          challengeB64u: base64UrlEncode(new Uint8Array(32).fill(5)),
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (path === '/wallet/unlock/verify') {
      return new Response(
        JSON.stringify({
          ok: true,
          walletSession: fixture.activeWalletSession,
          operationCredential: fixture.operationCredential,
          ed25519Session: fixture.ed25519Session,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    throw new Error(`unexpected unlock request: ${path}`);
  };

  const signingEngine = {
    getAuthenticationCredentialsSerialized: async () => fixture.credential,
    getSignerWorkerContext: () => workerContext,
    activateVerifiedNearEd25519YaoMaterial: async (material: NearEd25519YaoOperationMaterial) => {
      activatedMaterials.push(material);
      return await activeClients.activate(material);
    },
    clearVolatileWarmSigningMaterial: async () => {},
    markWalletSelectionUnlocked: async () => {},
    setWalletAuthenticated: (state: unknown) => authenticatedStates.push(state),
  } as unknown as LoginWebContext['signingEngine'];
  const context = {
    signingEngine,
    nearClient: new MinimalNearClient('https://rpc.testnet.near.org'),
    configs: buildConfigsFromEnv({
      relayer: { url: 'https://relay.example.test' },
      iframeWallet: { walletOrigin: 'https://wallet.example.test' },
    }),
    theme: 'dark' as const,
  } as LoginWebContext;

  try {
    const first = await unlockLinkedDevicePasskey(context, String(fixture.walletId), undefined);
    expect(first).toMatchObject({
      success: true,
      kind: 'near_wallet_unlocked',
      walletId: fixture.walletId,
    });
    expect(writtenSessions).toHaveLength(1);
    expect(projectionWrites).toHaveLength(1);
    expect(authenticatedStates).toHaveLength(1);
    expect(activatedMaterials).toHaveLength(1);
    expect(importedClients).toHaveLength(1);
    expect(storedHandles).toHaveLength(1);
    expect(
      resolveLinkedEcdsaHolderRuntimeV1({
        walletId,
        materialActivation: ecdsaActivation.materialActivation,
      })?.holderHandleId,
    ).toBe(storedHandles[0]);
    expect(listLinkedEcdsaHolderRuntimesV1(walletId)).toEqual([
      expect.objectContaining({
        walletId,
        authorityId: fixture.authority.authorityId,
        walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
        materialActivation: ecdsaActivation.materialActivation,
        holderHandleId: storedHandles[0],
      }),
    ]);
    expect(activeClients.resolve(identity)).not.toBeNull();

    const second = await unlockLinkedDevicePasskey(context, String(fixture.walletId), undefined);
    expect(second).toMatchObject({
      success: true,
      kind: 'near_wallet_unlocked',
      walletId: fixture.walletId,
    });
    expect(storedHandles).toHaveLength(1);
    expect(importedClients).toHaveLength(2);
    expect(importedClients[0]?.disposeCount()).toBe(1);
    expect(activatedMaterials).toHaveLength(2);
    expect(activeClients.resolve(identity)).not.toBeNull();

    const lockSurface = buildLockSurface({ activeClients, workerContext });
    await lockSurface.clearVolatileWarmSigningMaterial(walletId);
    expect(activeClients.resolve(identity)).toBeNull();
    expect(
      resolveLinkedEcdsaHolderRuntimeV1({
        walletId,
        materialActivation: ecdsaActivation.materialActivation,
      }),
    ).toBeNull();
    expect(disposedHandles).toEqual([storedHandles[0]]);
    expect(importedClients[1]?.disposeCount()).toBe(1);

    const reloadedSelection = await resolveLinkedDevicePasskeyAuthoritySelection(
      String(fixture.walletId),
    );
    expect(reloadedSelection).toMatchObject({
      kind: 'linked_device_passkey_authority_selection_v1',
      walletId: fixture.walletId,
      selection: fixture.selection,
      authMethod: fixture.authMethod,
      authority: fixture.authority,
      signerMaterials: fixture.signerMaterials,
    });

    const third = await unlockLinkedDevicePasskey(context, String(fixture.walletId), undefined);
    expect(third).toMatchObject({
      success: true,
      kind: 'near_wallet_unlocked',
      walletId: fixture.walletId,
    });
    expect(storedHandles).toHaveLength(2);
    expect(new Set(storedHandles).size).toBe(2);
    expect(importedClients).toHaveLength(3);
    expect(activeClients.resolve(identity)).not.toBeNull();
    expect(
      resolveLinkedEcdsaHolderRuntimeV1({
        walletId,
        materialActivation: ecdsaActivation.materialActivation,
      })?.holderHandleId,
    ).toBe(storedHandles[1]);
  } finally {
    clearLinkedEcdsaHolderRuntimesV1();
    activeClients.dispose();
    Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', originalInitializeBundled);
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    IndexedDBManager.getProfile = originalGetProfile;
    walletSessionAuthorizations.writeExact = originalWriteExact;
    walletSessionAuthorizations.writeExactWithOperationCredential =
      originalWriteExactWithOperationCredential;
    walletSessionAuthorizations.upsertActiveWithCurveMerge = originalUpsertActiveWithCurveMerge;
    globalThis.fetch = originalFetch;
  }
});

test('failed holder disposal retains the exact runtime for retry', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const walletId = toWalletId(String(fixture.walletId));
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('linked runtime fixture is missing ECDSA activation');
  const ecdsaMaterial = fixture.signerMaterials.find(
    (material) => material.keyFamily === 'ecdsa_secp256k1',
  );
  if (!ecdsaMaterial || ecdsaMaterial.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked runtime fixture is missing ECDSA material');
  }
  const holderHandleId = 'holder:retry';
  installLinkedEcdsaHolderRuntimeV1({
    kind: 'linked_ecdsa_holder_runtime_v1',
    walletId,
    authorityId: fixture.authority.authorityId,
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    materialActivation: ecdsaActivation.materialActivation,
    holderHandleId,
    ecdsaThresholdKeyId: ecdsaMaterial.ecdsaThresholdKeyId,
    activationReceipt: ecdsaMaterial.publicFacts.activationReceipt,
  });
  let disposalAttempts = 0;
  const workerContext = {
    requestWorkerOperation: async ({
      request,
    }: {
      readonly request: { readonly type: number };
    }) => {
      if (
        request.type !==
        EcdsaDerivationClientCustomRequestType.DisposeLinkedDeviceEcdsaHolderMaterials
      ) {
        throw new Error(`unexpected ECDSA worker request: ${String(request.type)}`);
      }
      disposalAttempts += 1;
      if (disposalAttempts === 1) throw new Error('simulated holder disposal failure');
      return {
        type: EcdsaDerivationClientCustomResponseType.DisposeLinkedDeviceEcdsaHolderMaterialsSuccess,
        payload: { kind: 'one', holderHandleId },
      };
    },
  } as unknown as WorkerOperationContext;
  const surface = buildLockSurface({
    activeClients: new Ed25519YaoActiveClientRegistry(),
    workerContext,
  });

  try {
    await expect(surface.clearVolatileWarmSigningMaterial(walletId)).rejects.toThrow(
      'simulated holder disposal failure',
    );
    expect(
      resolveLinkedEcdsaHolderRuntimeV1({
        walletId,
        materialActivation: ecdsaActivation.materialActivation,
      })?.holderHandleId,
    ).toBe(holderHandleId);

    await surface.clearVolatileWarmSigningMaterial(walletId);
    expect(
      resolveLinkedEcdsaHolderRuntimeV1({
        walletId,
        materialActivation: ecdsaActivation.materialActivation,
      }),
    ).toBeNull();
    expect(disposalAttempts).toBe(2);
  } finally {
    clearLinkedEcdsaHolderRuntimesV1();
  }
});
