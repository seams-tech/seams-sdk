import { expect, test } from '@playwright/test';
import {
  getRecentUnlocks,
  resolveLinkedDevicePasskeyAuthoritySelection,
  resolveLinkedDeviceUnlockSubjectSet,
  unlockLinkedDevicePasskey,
  unlockLinkedDeviceEmailOtpWallet,
  activateLinkedDeviceSignerRuntimesAfterLink,
} from '@/SeamsWeb/operations/auth/login';
import { loginAccountOptions } from '@/SeamsWeb/walletIframe/host/auth-menu/account-options';
import { BrowserSigningSurface } from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import type { LoginWebContext } from '@/SeamsWeb/signingSurface/types';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { configureIndexedDB, IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { MinimalNearClient } from '@/core/rpcClients/near/NearClient';
import type { NearEd25519YaoOperationMaterial } from '@/core/signingEngine/interfaces/near';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpAuthorityWalletUnlockResult } from '@/core/signingEngine/session/emailOtp/walletUnlock';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  Ed25519YaoActiveClientRegistry,
  type Ed25519YaoActiveClientIdentityV1,
} from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import { IndexedDbEd25519YaoPublicCapabilityReferenceStore } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
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
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  activeWalletAuthorityAvailableLaneFromProjection,
  readAvailableSigningLanes,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { resolveExactKeyExportLane } from '@/core/signingEngine/flows/recovery/exportLaneSelection';
import { buildActiveNearEd25519WalletSessionAuthorization } from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import {
  buildExactLinkedEmailOtpOwnerLaneScope,
  buildExactPasskeyOwnerLaneScope,
} from '@/core/signingEngine/session/identity/ownerLaneScope';
import { resolveActiveWalletAuthorityEcdsaRuntimeV1 } from '@/core/signingEngine/session/material/activeWalletAuthorityEcdsaRuntime';
import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseActiveWalletSessionV1 } from '@shared/device-linking/parsers';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  buildLinkedDeviceActiveNearSessionStatusFixture,
  buildLinkedDeviceEmailOtpUnlockRuntimeFixture,
  buildLinkedDeviceEd25519YaoCapabilityLaneFixture,
  buildLinkedDeviceUnlockRuntimeFixture,
} from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';

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

test('linked V2 install exposes exact inventory and unlock installs live owners idempotently', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const activeClients = new Ed25519YaoActiveClientRegistry();
  const storedHandles: string[] = [];
  const disposedHandles: string[] = [];
  const workerContext = createWorkerContext({ storedHandles, disposedHandles });
  const importedClients: FakeLinkedYaoClient[] = [];
  const originalInitializeBundled = RouterAbEd25519YaoClientV1.initializeBundled;
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalGetProfile = IndexedDBManager.getProfile;
  const originalIsDisabled = IndexedDBManager.isDisabled;
  const originalGetAppState = IndexedDBManager.getAppState;
  const originalListWalletSelections = IndexedDBManager.listWalletSelections;
  const originalWriteExact = walletSessionAuthorizations.writeExact;
  const originalWriteExactWithOperationCredential =
    walletSessionAuthorizations.writeExactWithOperationCredential;
  const originalFetch = globalThis.fetch;
  const writtenSessions: unknown[] = [];
  const authenticatedStates: unknown[] = [];
  const activatedMaterials: NearEd25519YaoOperationMaterial[] = [];
  const walletId = toWalletId(String(fixture.walletId));
  const identity = linkedRuntimeIdentity(fixture);
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('linked runtime fixture is missing ECDSA activation');
  const ecdsaMaterial = fixture.signerMaterials.find(
    (material) => material.keyFamily === 'ecdsa_secp256k1',
  );
  if (!ecdsaMaterial || ecdsaMaterial.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked runtime fixture is missing ECDSA material');
  }
  const appState = new Map<string, unknown>();
  const publicCapabilityStore = new IndexedDbEd25519YaoPublicCapabilityReferenceStore({
    isDisabled: () => false,
    getAppState: async <T>(key: string) => appState.get(key) as T | undefined,
    setAppState: async <T>(key: string, value: T) => {
      appState.set(key, value);
    },
  });
  await publicCapabilityStore.upsertLane(buildLinkedDeviceEd25519YaoCapabilityLaneFixture(fixture));

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
  Reflect.set(IndexedDBManager, 'isDisabled', () => false);
  Reflect.set(
    IndexedDBManager,
    'getAppState',
    async <T>(key: string): Promise<T | undefined> => appState.get(key) as T | undefined,
  );
  Reflect.set(IndexedDBManager, 'listWalletSelections', async () => [fixture.selection]);
  walletSessionAuthorizations.writeExact = async (record) => {
    writtenSessions.push(record);
    return record;
  };
  walletSessionAuthorizations.writeExactWithOperationCredential = async (input) => {
    writtenSessions.push(input);
    return input.record;
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
    getAllUsers: async () => [],
    getLastUser: async () => null,
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
  const recentUnlocksContext = {
    ...context,
    signingEngine: {
      ...context.signingEngine,
      getAllUsers: async () => [],
    },
  } satisfies Parameters<typeof getRecentUnlocks>[0];

  try {
    const expectedAuthorityRef = await walletAuthAuthorityRef({
      authority: fixture.factorAuthority,
    });
    const subjectSet = await resolveLinkedDeviceUnlockSubjectSet(String(fixture.walletId));
    expect(subjectSet).toEqual({
      kind: 'wallet_unlock_subject_set',
      walletId,
      subjects: [
        {
          kind: 'near_ed25519_wallet',
          walletId,
          nearAccountId: toAccountId(fixture.ed25519Session.nearAccountId),
          nearEd25519SigningKeyId: fixture.ed25519Session.nearEd25519SigningKeyId,
          signerSlot: 1,
        },
        {
          kind: 'evm_family_ecdsa_wallet',
          walletId,
          capability: ecdsaActivation.materialActivation.capability,
          authority: expectedAuthorityRef,
          ecdsaThresholdKeyId: ecdsaMaterial.ecdsaThresholdKeyId,
        },
      ],
    });
    const recentUnlocks = await getRecentUnlocks(recentUnlocksContext);
    expect(recentUnlocks.accounts).toEqual([
      expect.objectContaining({
        walletId: String(fixture.walletId),
        nearAccountId: fixture.ed25519Session.nearAccountId,
        displayName: String(fixture.walletId),
        signerSlot: 1,
        authMethod: 'passkey',
      }),
    ]);
    expect(loginAccountOptions(recentUnlocks)).toEqual([
      {
        walletId: String(fixture.walletId),
        displayName: String(fixture.walletId),
        authMethod: 'passkey',
      },
    ]);
    Reflect.set(IndexedDBManager, 'isDisabled', originalIsDisabled);
    Reflect.set(IndexedDBManager, 'getAppState', originalGetAppState);
    Reflect.set(IndexedDBManager, 'listWalletSelections', originalListWalletSelections);

    const first = await unlockLinkedDevicePasskey(context, String(fixture.walletId), undefined);
    expect(first.success, first.success ? undefined : first.error).toBe(true);
    expect(first).toMatchObject({
      success: true,
      kind: 'near_wallet_unlocked',
      walletId: fixture.walletId,
    });
    expect(writtenSessions).toHaveLength(1);
    expect(writtenSessions[0]).toMatchObject({
      record: expect.objectContaining({
        walletId,
        authorityId: fixture.authority.authorityId,
        authMethodId: fixture.authMethod.walletAuthMethodId,
      }),
      operationCredential: fixture.operationCredential,
    });
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
    expect(importedClients[0]?.metadata()).toMatchObject({
      applicationBinding: fixture.signerMaterials.find(
        (material) => material.keyFamily === 'ed25519',
      )?.publicFacts.applicationBinding,
      materialActivation: fixture.authority.signerActivations.ed25519?.materialActivation,
    });

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
    Reflect.set(IndexedDBManager, 'isDisabled', originalIsDisabled);
    Reflect.set(IndexedDBManager, 'getAppState', originalGetAppState);
    Reflect.set(IndexedDBManager, 'listWalletSelections', originalListWalletSelections);
    walletSessionAuthorizations.writeExact = originalWriteExact;
    walletSessionAuthorizations.writeExactWithOperationCredential =
      originalWriteExactWithOperationCredential;
    globalThis.fetch = originalFetch;
  }
});

test('linked V2 post-link activation resolves the exact export lane before any unlock', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const activeClients = new Ed25519YaoActiveClientRegistry();
  const storedHandles: string[] = [];
  const disposedHandles: string[] = [];
  const workerContext = createWorkerContext({ storedHandles, disposedHandles });
  const importedClients: FakeLinkedYaoClient[] = [];
  const originalInitializeBundled = RouterAbEd25519YaoClientV1.initializeBundled;
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalIsDisabled = IndexedDBManager.isDisabled;
  const originalGetAppState = IndexedDBManager.getAppState;
  const originalSetAppState = IndexedDBManager.setAppState;
  const originalWriteExactWithOperationCredential =
    walletSessionAuthorizations.writeExactWithOperationCredential;
  const originalFetch = globalThis.fetch;
  const unlockedSelections: unknown[] = [];
  const walletId = toWalletId(String(fixture.walletId));
  const ed25519Material = fixture.signerMaterials.find(
    (material) => material.keyFamily === 'ed25519',
  );
  if (!ed25519Material || ed25519Material.keyFamily !== 'ed25519') {
    throw new Error('linked runtime fixture is missing Ed25519 material');
  }
  const nearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(
    `ed25519:${base58Encode(new Uint8Array(ed25519Material.publicFacts.activationReceipt.registered_public_key))}`,
  );
  const identity = {
    ...linkedRuntimeIdentity(fixture),
    nearAccountId: toAccountId(nearAccountId),
  };
  const appState = new Map<string, unknown>();
  const publicCapabilityStore = new IndexedDbEd25519YaoPublicCapabilityReferenceStore({
    isDisabled: () => false,
    getAppState: async <T>(key: string) => appState.get(key) as T | undefined,
    setAppState: async <T>(key: string, value: T) => {
      appState.set(key, value);
    },
  });

  Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', async () => ({
    importLinkedMaterial: (input: {
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    }) => {
      const client = fakeLinkedYaoClient(input.metadata);
      importedClients.push(client);
      return client;
    },
  }));
  IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: fixture.signerMaterials,
    exportRoot: null,
  });
  Reflect.set(IndexedDBManager, 'isDisabled', () => false);
  Reflect.set(
    IndexedDBManager,
    'getAppState',
    async <T>(key: string): Promise<T | undefined> => appState.get(key) as T | undefined,
  );
  Reflect.set(IndexedDBManager, 'setAppState', async <T>(key: string, value: T) => {
    appState.set(key, value);
  });
  walletSessionAuthorizations.writeExactWithOperationCredential = async (input) => input.record;
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path.endsWith('/router-ab/ed25519/yao/recovery/bootstrap')) {
      return new Response(
        JSON.stringify({
          kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
          walletId: String(fixture.walletId),
          nearAccountId,
          nearEd25519SigningKeyId: fixture.ed25519Session.nearEd25519SigningKeyId,
          signingWorkerId: fixture.ed25519Session.relayerKeyId,
          thresholdSessionId: String(fixture.ed25519Session.thresholdSessionId),
          walletSessionId: String(fixture.ed25519Session.walletSessionId),
          quotaId: String(fixture.ed25519Session.quotaId),
          thresholdExpiresAtMs: fixture.ed25519Session.expiresAtMs,
          runtimePolicyScope: fixture.ed25519Session.runtimePolicyScope,
          routerAbNormalSigning: fixture.ed25519Session.routerAbNormalSigning,
          participantIds: fixture.ed25519Session.participantIds,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    throw new Error(`unexpected post-link activation request: ${path}`);
  };

  const signingEngine = {
    getSignerWorkerContext: () => workerContext,
    activateVerifiedNearEd25519YaoMaterial: async (material: NearEd25519YaoOperationMaterial) => {
      return await activeClients.activate(material);
    },
    markWalletSelectionUnlocked: async (input: unknown) => {
      unlockedSelections.push(input);
    },
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
  const factorSecret32 = base64UrlDecode(
    fixture.credential.clientExtensionResults.prf?.results.first || '',
  );

  try {
    await activateLinkedDeviceSignerRuntimesAfterLink({
      context,
      factor: { kind: 'passkey', walletId },
      walletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
      factorSecret32,
    });

    const status = buildLinkedDeviceActiveNearSessionStatusFixture(fixture);
    const authorization = buildActiveNearEd25519WalletSessionAuthorization({
      selectedAuthority: fixture.authority,
      selectedAuthMethod: fixture.authMethod,
      selectedFactorAuthority: fixture.factorAuthority,
      session: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
      status,
      nowMs: Date.now(),
    });
    const available = await readAvailableSigningLanes(
      {
        walletId,
        ecdsaChainTargets: [],
        ownerScope: buildExactPasskeyOwnerLaneScope({
          authMethod: fixture.authMethod,
          signerSlot: 1,
        }),
      },
      {
        listSealedRecordsForWallet: async () => [],
        listPublicCapabilityReferences: () => publicCapabilityStore.listLanes(),
        isPublicCapabilityActive: () => true,
        readActiveWalletSessionAuthorization: async () => ({
          kind: 'found',
          authorization,
        }),
      },
    );
    expect(available.lanes.ed25519.near).toMatchObject({
      source: 'public_capability_reference',
      state: 'ready',
      authorizationState: 'authorized',
      auth: { kind: 'passkey' },
    });

    const resolved = await resolveExactKeyExportLane(
      {
        readOwnerScopedAvailableSigningLanesForTargets: async () => available,
      },
      {
        kind: 'ed25519',
        walletSession: {
          walletId,
          walletSessionUserId: String(fixture.operationCredential.walletSessionId),
        },
        nearAccount: { kind: 'implicit', accountId: toAccountId(nearAccountId) },
      },
    );
    expect(resolved).toMatchObject({
      kind: 'ed25519',
      materialActivation: fixture.authority.signerActivations.ed25519?.materialActivation,
    });
    expect(unlockedSelections).toEqual([
      { walletId, walletAuthMethodId: fixture.authMethod.walletAuthMethodId },
    ]);
    expect(activeClients.resolve(identity)).not.toBeNull();
    expect(importedClients).toHaveLength(1);
  } finally {
    factorSecret32.fill(0);
    clearLinkedEcdsaHolderRuntimesV1();
    activeClients.dispose();
    Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', originalInitializeBundled);
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    Reflect.set(IndexedDBManager, 'isDisabled', originalIsDisabled);
    Reflect.set(IndexedDBManager, 'getAppState', originalGetAppState);
    Reflect.set(IndexedDBManager, 'setAppState', originalSetAppState);
    walletSessionAuthorizations.writeExactWithOperationCredential =
      originalWriteExactWithOperationCredential;
    globalThis.fetch = originalFetch;
  }
});

test('linked Email OTP target is immediately usable for both source-factor combinations', async () => {
  const fixture = await buildLinkedDeviceEmailOtpUnlockRuntimeFixture();
  const activeClients = new Ed25519YaoActiveClientRegistry();
  const storedHandles: string[] = [];
  const disposedHandles: string[] = [];
  const workerContext = createWorkerContext({ storedHandles, disposedHandles });
  const importedClients: FakeLinkedYaoClient[] = [];
  const originalInitializeBundled = RouterAbEd25519YaoClientV1.initializeBundled;
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalResolveWalletAuthorityForMethod = IndexedDBManager.resolveWalletAuthorityForMethod;
  const originalIsDisabled = IndexedDBManager.isDisabled;
  const originalGetAppState = IndexedDBManager.getAppState;
  const originalSetAppState = IndexedDBManager.setAppState;
  const originalListWalletSelections = IndexedDBManager.listWalletSelections;
  const originalWriteExactWithOperationCredential =
    walletSessionAuthorizations.writeExactWithOperationCredential;
  const originalReadExactWithOperationCredential =
    walletSessionAuthorizations.readExactWithOperationCredential;
  const originalFetch = globalThis.fetch;
  const unlockedSelections: unknown[] = [];
  const writtenSessions: unknown[] = [];
  const walletId = toWalletId(String(fixture.walletId));
  const ed25519Material = fixture.signerMaterials.find(
    (material) => material.keyFamily === 'ed25519',
  );
  if (!ed25519Material || ed25519Material.keyFamily !== 'ed25519') {
    throw new Error('linked Email OTP runtime fixture is missing Ed25519 material');
  }
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) {
    throw new Error('linked Email OTP runtime fixture is missing ECDSA activation');
  }
  const nearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(
    `ed25519:${base58Encode(new Uint8Array(ed25519Material.publicFacts.activationReceipt.registered_public_key))}`,
  );
  const appState = new Map<string, unknown>();
  const publicCapabilityStore = new IndexedDbEd25519YaoPublicCapabilityReferenceStore({
    isDisabled: () => false,
    getAppState: async <T>(key: string) => appState.get(key) as T | undefined,
    setAppState: async <T>(key: string, value: T) => {
      appState.set(key, value);
    },
  });
  const resolvedAuthority = {
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: fixture.signerMaterials,
    exportRoot: null,
  };

  Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', async () => ({
    importLinkedMaterial: (input: {
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    }) => {
      const client = fakeLinkedYaoClient(input.metadata);
      importedClients.push(client);
      return client;
    },
  }));
  IndexedDBManager.resolveSelectedWalletAuthority = async () => resolvedAuthority;
  IndexedDBManager.resolveWalletAuthorityForMethod = async () => resolvedAuthority;
  Reflect.set(IndexedDBManager, 'isDisabled', () => false);
  Reflect.set(
    IndexedDBManager,
    'getAppState',
    async <T>(key: string): Promise<T | undefined> => appState.get(key) as T | undefined,
  );
  Reflect.set(IndexedDBManager, 'setAppState', async <T>(key: string, value: T) => {
    appState.set(key, value);
  });
  Reflect.set(IndexedDBManager, 'listWalletSelections', async () => [fixture.selection]);
  walletSessionAuthorizations.writeExactWithOperationCredential = async (input) => {
    writtenSessions.push(input);
    return input.record;
  };
  walletSessionAuthorizations.readExactWithOperationCredential = async () => ({
    record: fixture.activeWalletSession,
    operationCredential: fixture.operationCredential,
  });
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path.endsWith('/router-ab/ed25519/yao/recovery/bootstrap')) {
      return new Response(
        JSON.stringify({
          kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
          walletId: String(fixture.walletId),
          nearAccountId,
          nearEd25519SigningKeyId: fixture.ed25519Session.nearEd25519SigningKeyId,
          signingWorkerId: fixture.ed25519Session.relayerKeyId,
          thresholdSessionId: String(fixture.ed25519Session.thresholdSessionId),
          walletSessionId: String(fixture.ed25519Session.walletSessionId),
          quotaId: String(fixture.ed25519Session.quotaId),
          thresholdExpiresAtMs: fixture.ed25519Session.expiresAtMs,
          runtimePolicyScope: fixture.ed25519Session.runtimePolicyScope,
          routerAbNormalSigning: fixture.ed25519Session.routerAbNormalSigning,
          participantIds: fixture.ed25519Session.participantIds,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    throw new Error(`unexpected Email OTP post-link activation request: ${path}`);
  };

  const signingEngine = {
    getAllUsers: async () => [],
    getLastUser: async () => null,
    getSignerWorkerContext: () => workerContext,
    activateVerifiedNearEd25519YaoMaterial: async (material: NearEd25519YaoOperationMaterial) => {
      return await activeClients.activate(material);
    },
    markWalletSelectionUnlocked: async (input: unknown) => {
      unlockedSelections.push(input);
    },
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
  const factorSecret32 = fixture.factorSecret32.slice();

  try {
    await activateLinkedDeviceSignerRuntimesAfterLink({
      context,
      factor: {
        kind: 'email_otp',
        walletId,
        walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
        emailHashHex: fixture.authMethod.emailHashHex,
        providerIdentity: fixture.providerIdentity,
      },
      walletSession: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
      factorSecret32,
    });

    expect(writtenSessions).toEqual([
      {
        record: fixture.activeWalletSession,
        operationCredential: fixture.operationCredential,
      },
    ]);
    expect(unlockedSelections).toEqual([
      { walletId, walletAuthMethodId: fixture.authMethod.walletAuthMethodId },
    ]);
    expect(importedClients).toHaveLength(1);
    expect(storedHandles).toHaveLength(1);
    expect(
      resolveLinkedEcdsaHolderRuntimeV1({
        walletId,
        materialActivation: ecdsaActivation.materialActivation,
      }),
    ).toMatchObject({
      walletId,
      authorityId: fixture.authority.authorityId,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      factorAuthority: fixture.factorAuthority,
      holderHandleId: storedHandles[0],
    });

    const recentUnlocks = await getRecentUnlocks({
      ...context,
      signingEngine: {
        ...context.signingEngine,
        getAllUsers: async () => [],
        getLastUser: async () => null,
      },
    });
    expect(recentUnlocks.accounts).toEqual([
      expect.objectContaining({
        walletId: String(walletId),
        nearAccountId,
        authMethod: 'email_otp',
      }),
    ]);
    expect(loginAccountOptions(recentUnlocks)).toEqual([
      {
        walletId: String(walletId),
        displayName: String(walletId),
        authMethod: 'email_otp',
      },
    ]);

    const status = buildLinkedDeviceActiveNearSessionStatusFixture(fixture);
    const nearAuthorization = buildActiveNearEd25519WalletSessionAuthorization({
      selectedAuthority: fixture.authority,
      selectedAuthMethod: fixture.authMethod,
      selectedFactorAuthority: fixture.factorAuthority,
      session: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
      status,
      nowMs: Date.now(),
    });
    const authorityRef = await walletAuthAuthorityRef({ authority: fixture.factorAuthority });
    const ownerScope = buildExactLinkedEmailOtpOwnerLaneScope({
      authMethod: fixture.authMethod,
      factorAuthority: fixture.factorAuthority,
      authorityRef,
    });
    const chainTarget = testEcdsaChainTarget('tempo');
    const ecdsaRuntime = await resolveActiveWalletAuthorityEcdsaRuntimeV1({
      ports: {
        resolveSelectedWalletAuthority: (selectedWalletId) =>
          IndexedDBManager.resolveSelectedWalletAuthority(selectedWalletId),
        readExactWithOperationCredential: (input) =>
          walletSessionAuthorizations.readExactWithOperationCredential(input),
      },
      input: { walletId, chainTarget },
    });
    expect(ecdsaRuntime.kind).toBe('resolved');
    if (ecdsaRuntime.kind !== 'resolved' || !ecdsaRuntime.lane) {
      throw new Error('linked Email OTP EVM runtime did not resolve');
    }
    const ecdsaLane = ecdsaRuntime.lane;
    const available = await readAvailableSigningLanes(
      {
        walletId,
        ecdsaChainTargets: [chainTarget],
        ownerScope,
      },
      {
        listSealedRecordsForWallet: async () => [],
        listPublicCapabilityReferences: () => publicCapabilityStore.listLanes(),
        isPublicCapabilityActive: () => true,
        readActiveWalletSessionAuthorization: async () => ({
          kind: 'found',
          authorization: nearAuthorization,
        }),
        listActiveWalletAuthorityEcdsaLanesForWallet: async () => [
          activeWalletAuthorityAvailableLaneFromProjection(ecdsaLane),
        ],
      },
    );
    expect(available.lanes.ed25519.near).toMatchObject({
      source: 'public_capability_reference',
      state: 'ready',
      authorizationState: 'authorized',
      auth: {
        kind: 'email_otp',
        providerSubjectId: fixture.providerIdentity.providerSubjectId,
      },
    });
    expect(available.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(chainTarget)]).toMatchObject({
      source: 'active_wallet_authority',
      state: 'deferred',
      authorizationState: 'authorization_required',
      auth: {
        kind: 'email_otp',
        providerSubjectId: fixture.providerIdentity.providerSubjectId,
      },
      runtime: {
        authorityId: fixture.authority.authorityId,
        walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
        session: fixture.activeWalletSession,
        operationCredential: fixture.operationCredential,
      },
    });

    const walletSession = {
      walletId,
      walletSessionUserId: String(fixture.operationCredential.walletSessionId),
    };
    const ed25519Export = await resolveExactKeyExportLane(
      { readOwnerScopedAvailableSigningLanesForTargets: async () => available },
      {
        kind: 'ed25519',
        walletSession,
        nearAccount: { kind: 'implicit', accountId: toAccountId(nearAccountId) },
      },
    );
    expect(ed25519Export).toMatchObject({
      kind: 'ed25519',
      materialActivation: fixture.authority.signerActivations.ed25519?.materialActivation,
    });
  } finally {
    factorSecret32.fill(0);
    fixture.factorSecret32.fill(0);
    clearLinkedEcdsaHolderRuntimesV1();
    activeClients.dispose();
    Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', originalInitializeBundled);
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    IndexedDBManager.resolveWalletAuthorityForMethod = originalResolveWalletAuthorityForMethod;
    Reflect.set(IndexedDBManager, 'isDisabled', originalIsDisabled);
    Reflect.set(IndexedDBManager, 'getAppState', originalGetAppState);
    Reflect.set(IndexedDBManager, 'setAppState', originalSetAppState);
    Reflect.set(IndexedDBManager, 'listWalletSelections', originalListWalletSelections);
    walletSessionAuthorizations.writeExactWithOperationCredential =
      originalWriteExactWithOperationCredential;
    walletSessionAuthorizations.readExactWithOperationCredential =
      originalReadExactWithOperationCredential;
    globalThis.fetch = originalFetch;
  }
});

test('ECDSA-only linked Email OTP reload derives the email provider from a bare subject', async () => {
  const fixture = await buildLinkedDeviceEmailOtpUnlockRuntimeFixture();
  const ecdsaMaterial = fixture.signerMaterials.find(
    (material) => material.keyFamily === 'ecdsa_secp256k1',
  );
  if (!ecdsaMaterial || ecdsaMaterial.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked Email OTP runtime fixture is missing ECDSA material');
  }
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) {
    throw new Error('linked Email OTP runtime fixture is missing ECDSA activation');
  }
  const ecdsaOnlyCapabilitySubjects = fixture.activeWalletSession.capabilitySubjects.filter(
    (subject) =>
      subject.kind === 'link_devices' ||
      subject.kind === 'revoke_devices' ||
      (subject.kind !== 'link_devices' &&
        subject.kind !== 'revoke_devices' &&
        subject.keyFamily === 'ecdsa_secp256k1'),
  );
  const ecdsaOnlyWalletSession = parseActiveWalletSessionV1({
    ...fixture.activeWalletSession,
    capabilitySubjects: ecdsaOnlyCapabilitySubjects,
  });
  const resolvedAuthority = {
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [ecdsaMaterial],
    exportRoot: null,
  };
  const verifiedAuthorityProjection = {
    kind: 'email_otp_verified_authority_projection_v1' as const,
    authority: fixture.authority,
    authMethod: fixture.authMethod,
  };
  const unlockResult: EmailOtpAuthorityWalletUnlockResult = {
    kind: 'email_otp_authority_wallet_unlock_v1',
    factorSecret32: fixture.factorSecret32.slice(),
    walletSession: ecdsaOnlyWalletSession,
    operationCredential: fixture.operationCredential,
    verifiedAuthorityProjection,
    walletCustodySeed: { kind: 'linked_device_seed_unavailable' },
    ed25519Activation: { kind: 'ed25519_activation_absent' },
  };
  const storedHandles: string[] = [];
  const disposedHandles: string[] = [];
  const ecdsaWorkerContext = createWorkerContext({ storedHandles, disposedHandles });
  let unlockPayload: unknown;
  const workerContext = {
    requestWorkerOperation: async ({
      kind,
      request,
    }: {
      readonly kind: string;
      readonly request: { readonly type: unknown; readonly payload: unknown };
    }): Promise<unknown> => {
      if (kind === 'emailOtp') {
        if (request.type !== 'unlockEmailOtpAuthorityWallet') {
          throw new Error(`unexpected Email OTP worker request: ${String(request.type)}`);
        }
        unlockPayload = request.payload;
        return unlockResult;
      }
      if (kind === 'ecdsaDerivationClient') {
        return await ecdsaWorkerContext.requestWorkerOperation({
          kind: 'ecdsaDerivationClient',
          request: request as never,
        });
      }
      throw new Error(`unexpected worker kind: ${kind}`);
    },
  } as unknown as WorkerOperationContext;
  const originalResolveWalletAuthorityForMethod = IndexedDBManager.resolveWalletAuthorityForMethod;
  const originalWriteExactWithOperationCredential =
    walletSessionAuthorizations.writeExactWithOperationCredential;
  const unlockedSelections: unknown[] = [];
  const authenticatedStates: unknown[] = [];
  IndexedDBManager.resolveWalletAuthorityForMethod = async () => resolvedAuthority;
  walletSessionAuthorizations.writeExactWithOperationCredential = async (input) => input.record;
  const context = {
    signingEngine: {
      getSignerWorkerContext: () => workerContext,
      markWalletSelectionUnlocked: async (input: unknown) => {
        unlockedSelections.push(input);
      },
      setWalletAuthenticated: (input: unknown) => {
        authenticatedStates.push(input);
      },
      clearVolatileWarmSigningMaterial: async () => {},
    },
    nearClient: new MinimalNearClient('https://rpc.testnet.near.org'),
    configs: buildConfigsFromEnv({
      relayer: { url: 'https://relay.example.test' },
      iframeWallet: { walletOrigin: 'https://wallet.example.test' },
    }),
    theme: 'dark' as const,
  } as unknown as LoginWebContext;

  try {
    await unlockLinkedDeviceEmailOtpWallet({
      context,
      walletIdInput: String(fixture.walletId),
      emailHashHex: fixture.authMethod.emailHashHex,
      walletAuthMethodId: String(fixture.authMethod.walletAuthMethodId),
      providerSubjectId: fixture.providerIdentity.providerSubjectId,
      challengeId: 'challenge:reload',
      otpCode: '123456',
      relayUrl: 'https://relay.example.test',
    });

    expect(unlockPayload).toMatchObject({
      walletId: String(fixture.walletId),
      walletAuthMethodId: String(fixture.authMethod.walletAuthMethodId),
      challengeId: 'challenge:reload',
      otpCode: '123456',
      ed25519: { kind: 'no_ed25519' },
    });
    expect(unlockedSelections).toEqual([
      { walletId: fixture.walletId, walletAuthMethodId: fixture.authMethod.walletAuthMethodId },
    ]);
    expect(authenticatedStates).toEqual([
      { kind: 'authenticated', walletId: fixture.walletId, authMethod: 'email_otp' },
    ]);
    const runtime = resolveLinkedEcdsaHolderRuntimeV1({
      walletId: fixture.walletId,
      materialActivation: ecdsaActivation.materialActivation,
    });
    expect(runtime).not.toBeNull();
    expect(runtime?.factorAuthority).toMatchObject({
      factor: {
        kind: 'email_otp',
        provider: 'email',
        providerUserId: fixture.providerIdentity.providerSubjectId,
      },
    });
  } finally {
    clearLinkedEcdsaHolderRuntimesV1();
    fixture.factorSecret32.fill(0);
    IndexedDBManager.resolveWalletAuthorityForMethod = originalResolveWalletAuthorityForMethod;
    walletSessionAuthorizations.writeExactWithOperationCredential =
      originalWriteExactWithOperationCredential;
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
    factorAuthority: fixture.factorAuthority,
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
