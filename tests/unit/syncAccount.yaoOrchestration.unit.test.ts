import { expect, test } from '@playwright/test';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../../packages/sdk-web/src/core/config/defaultConfigs';
import type { ClientUserData } from '../../packages/sdk-web/src/core/accountData/near/nearAccountData.types';
import { IndexedDBManager } from '../../packages/sdk-web/src/core/indexedDB';
import type {
  KeyMaterialKind,
  KeyMaterialRecord,
} from '../../packages/sdk-web/src/core/indexedDB/keyMaterial.types';
import type { NearEd25519YaoOperationMaterial } from '../../packages/sdk-web/src/core/signingEngine/interfaces/near';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
} from '../../packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../packages/sdk-web/src/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import {
  ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoSealableActiveClientV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';
import { MinimalNearClient } from '../../packages/sdk-web/src/core/rpcClients/near/NearClient';
import type {
  AccountSyncSigningSurface,
  AccountSyncWebContext,
} from '../../packages/sdk-web/src/SeamsWeb/signingSurface/types';
import type { Ed25519YaoPublicCapabilityLaneReferenceV1 } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { syncAccount } from '../../packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';
import type {
  SeamsConfigsReadonly,
  WalletAuthenticationState,
} from '../../packages/sdk-web/src/core/types/seams';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '../../packages/shared-ts/src/utils/sessionTokens';
import { isPlainObject } from '../../packages/shared-ts/src/utils/validation';
import { mpcMaterialActivationRefsEqual } from '../../packages/shared-ts/src/utils/domainIds';
import {
  routerAbMpcMaterialActivationRefFromWire,
  routerAbMpcMaterialActivationRefToWire,
} from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import type { WalletCustodyEvmFamilyPublicFacts } from '../../packages/shared-ts/src/passkey-custody/ceremonyCommitPayload';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { ecdsaCapabilityActivationFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { rawPasskeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';

const RELAYER_URL = 'https://router.example.test';
const RP_ID = 'wallet.example.test';
const DISCOVERED_WALLET_ID = 'discovered-wallet';
const REQUESTED_WALLET_ID = 'requested-wallet';
const NEAR_ACCOUNT_ID = 'discovered-wallet.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519ks_discovered_wallet';
const CREDENTIAL_ID = 'credential-id-b64u';
const SIGNER_SLOT = 3;
const THRESHOLD_SESSION_ID = 'threshold-session-sync-1';
const WALLET_SESSION_ID = 'wallet-session-sync-1';
const WALLET_SESSION_QUOTA_ID = 'wallet-session-quota-sync-1';
const SIGNING_WORKER_ID = 'signing-worker-sync-1';
const ROOT_SHARE_EPOCH = 'root-share-epoch-sync-1';
const REGISTERED_PUBLIC_KEY = new Uint8Array(32).fill(21);
const OPERATIONAL_PUBLIC_KEY = `ed25519:${base58Encode(REGISTERED_PUBLIC_KEY)}`;
const PRF_FIRST = new Uint8Array(32).fill(77);
const PRF_FIRST_B64U = base64UrlEncode(PRF_FIRST);
const MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'sync-account-yao',
  DISCOVERED_WALLET_ID,
  SIGNING_WORKER_ID,
  NEAR_SIGNING_KEY_ID,
);

type MockActiveClient = RouterAbEd25519YaoSealableActiveClientV1;

class YaoScenario {
  readonly activeClient: MockActiveClient;
  failRecovery = false;
  capturedPrfFirst: Uint8Array | null = null;
  initializeCalls = 0;
  disposeCalls = 0;
  disposed = false;

  constructor() {
    this.activeClient = createMockActiveClient(this);
  }
}

type FetchScenario = {
  readonly optionsWalletId: string | null;
  readonly verifiedWalletId: string;
  readonly ecdsaSigners: readonly Record<string, unknown>[];
  verifyRequest: Record<string, unknown> | null;
};

let activeYaoScenario: YaoScenario | null = null;
let activeFetchScenario: FetchScenario | null = null;
let activePersistenceFixture: SyncAccountPersistenceFixture | null = null;
const originalFetch = globalThis.fetch;
const originalInitializeBundled = RouterAbEd25519YaoClientV1.initializeBundled;

type IndexedDbPersistenceMethod =
  | 'getKeyMaterial'
  | 'storeKeyMaterial'
  | 'getAppState'
  | 'compareAndSwapAppState'
  | 'finalizeKeyMaterialRecovery';

const indexedDbPersistenceMethods = [
  'getKeyMaterial',
  'storeKeyMaterial',
  'getAppState',
  'compareAndSwapAppState',
  'finalizeKeyMaterialRecovery',
] as const satisfies readonly IndexedDbPersistenceMethod[];

const originalIndexedDbPersistenceMethods = new Map<IndexedDbPersistenceMethod, unknown>();

function keyMaterialMapKey(input: {
  profileId: string;
  signerSlot: number;
  chainIdKey: string;
  keyKind: string;
}): string {
  return [input.profileId, input.signerSlot, input.chainIdKey, input.keyKind].join('|');
}

class SyncAccountPersistenceFixture {
  readonly appState = new Map<string, unknown>();
  readonly keyMaterial = new Map<string, KeyMaterialRecord>();

  async getKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    return (
      this.keyMaterial.get(keyMaterialMapKey({ profileId, signerSlot, chainIdKey, keyKind })) ??
      null
    );
  }

  async storeKeyMaterial(record: KeyMaterialRecord): Promise<void> {
    this.keyMaterial.set(keyMaterialMapKey(record), record);
  }

  async getAppState<T = unknown>(key: string): Promise<T | undefined> {
    return this.appState.get(key) as T | undefined;
  }

  async compareAndSwapAppState(input: {
    key: string;
    expected: unknown | null;
    replacement: unknown;
  }): Promise<boolean> {
    const current = this.appState.get(input.key);
    const matches =
      input.expected === null
        ? current === undefined
        : JSON.stringify(current) === JSON.stringify(input.expected);
    if (!matches) return false;
    this.appState.set(input.key, input.replacement);
    return true;
  }

  async finalizeKeyMaterialRecovery(input: {
    journalKey: string;
    expectedJournal: unknown;
    replacement: KeyMaterialRecord;
    retire: {
      profileId: string;
      signerSlot: number;
      chainIdKey: string;
      keyKind: string;
    };
  }): Promise<void> {
    if (
      JSON.stringify(this.appState.get(input.journalKey)) !== JSON.stringify(input.expectedJournal)
    ) {
      throw new Error('syncAccount recovery journal changed before finalization');
    }
    this.keyMaterial.delete(keyMaterialMapKey(input.retire));
    await this.storeKeyMaterial(input.replacement);
    this.appState.delete(input.journalKey);
  }
}

function installPersistenceFixture(fixture: SyncAccountPersistenceFixture): void {
  const manager = IndexedDBManager as unknown as Record<string, unknown>;
  for (const method of indexedDbPersistenceMethods) {
    originalIndexedDbPersistenceMethods.set(method, manager[method]);
    const replacement = fixture[method].bind(fixture);
    if (!Reflect.set(manager, method, replacement)) {
      throw new Error(`failed to install IndexedDB ${method} fixture`);
    }
  }
}

function restorePersistenceFixture(): void {
  const manager = IndexedDBManager as unknown as Record<string, unknown>;
  for (const method of indexedDbPersistenceMethods) {
    const original = originalIndexedDbPersistenceMethods.get(method);
    if (!Reflect.set(manager, method, original)) {
      throw new Error(`failed to restore IndexedDB ${method}`);
    }
  }
  originalIndexedDbPersistenceMethods.clear();
}

function requireActiveYaoScenario(): YaoScenario {
  if (!activeYaoScenario) throw new Error('Yao test scenario is unavailable');
  return activeYaoScenario;
}

function requireActiveFetchScenario(): FetchScenario {
  if (!activeFetchScenario) throw new Error('fetch test scenario is unavailable');
  return activeFetchScenario;
}

function requireActivePersistenceFixture(): SyncAccountPersistenceFixture {
  if (!activePersistenceFixture) throw new Error('persistence test scenario is unavailable');
  return activePersistenceFixture;
}

function createMockActiveClient(scenario: YaoScenario): MockActiveClient {
  return {
    metadata() {
      return {
        kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
        scope: registrationAdmissionRequest(DISCOVERED_WALLET_ID).scope,
        applicationBinding: registrationAdmissionRequest(DISCOVERED_WALLET_ID).application_binding,
        participantIds: [1, 2],
        stateEpoch: 1n,
        registeredPublicKey: REGISTERED_PUBLIC_KEY.slice(),
        signingWorkerVerifyingShare: new Uint8Array(32).fill(15),
        transcript: new Uint8Array(32).fill(11),
        activeCapabilityBinding: new Array<number>(32).fill(8),
        materialActivation: MATERIAL_ACTIVATION,
      };
    },
    async createSigningShare() {
      throw new Error('signing is outside the syncAccount fixture');
    },
    sealLocalMaterial(input) {
      return {
        kind: 'router_ab_ed25519_yao_sealed_local_material_v1',
        nonce: input.nonce.slice(),
        ciphertext: new Uint8Array(48).fill(9),
      };
    },
    sealEmailOtpLocalMaterial() {
      throw new Error('Email OTP sealing is outside the syncAccount fixture');
    },
    status() {
      return { kind: scenario.disposed ? 'disposed' : 'active' };
    },
    dispose() {
      scenario.disposeCalls += 1;
      scenario.disposed = true;
    },
  };
}

function createYaoScenario(): YaoScenario {
  return new YaoScenario();
}

async function mockInitializeBundled(): Promise<unknown> {
  const scenario = requireActiveYaoScenario();
  scenario.initializeCalls += 1;
  return {
    openCustodyCache(input: { ownedFactorSecret: Uint8Array }) {
      scenario.capturedPrfFirst = input.ownedFactorSecret;
      input.ownedFactorSecret.fill(0);
      return scenario.activeClient;
    },
  };
}

function installYaoClientMock(): void {
  if (!Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', mockInitializeBundled)) {
    throw new Error('failed to install Yao Client test initializer');
  }
}

function restoreYaoClientInitializer(): void {
  if (!Reflect.set(RouterAbEd25519YaoClientV1, 'initializeBundled', originalInitializeBundled)) {
    throw new Error('failed to restore Yao Client initializer');
  }
}

function passkeyCredential(): WebAuthnAuthenticationCredential {
  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: 'client-data-json-b64u',
      authenticatorData: 'authenticator-data-b64u',
      signature: 'signature-b64u',
      userHandle: undefined,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: PRF_FIRST_B64U,
          second: undefined,
        },
      },
    },
  };
}

function walletBinding(walletId: string): Record<string, unknown> {
  return {
    walletId,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID,
    signerSlot: SIGNER_SLOT,
  };
}

function unsignedWalletSessionJwt(walletId: string): string {
  const header = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify({ alg: 'none', typ: 'JWT' })),
  );
  const payload = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
        authorizationKind: 'owner_wallet_session',
        walletId,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        walletSessionId: WALLET_SESSION_ID,
        quotaId: WALLET_SESSION_QUOTA_ID,
      }),
    ),
  );
  return `${header}.${payload}.test-signature`;
}

function syncOptionsResponse(scenario: FetchScenario): Record<string, unknown> {
  return {
    ok: true,
    challengeId: 'sync-challenge-id',
    challengeB64u: 'sync-challenge-b64u',
    credentialIds: scenario.optionsWalletId ? [CREDENTIAL_ID] : [],
    ...(scenario.optionsWalletId ? { walletBinding: walletBinding(scenario.optionsWalletId) } : {}),
  };
}

function syncVerifyResponse(
  walletId: string,
  ecdsaSigners: readonly Record<string, unknown>[],
): Record<string, unknown> {
  const admissionRequest = registrationAdmissionRequest(walletId);
  const admissionReceipt = registrationAdmissionReceipt(walletId);
  return {
    ok: true,
    verified: true,
    walletId,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    signerSlot: SIGNER_SLOT,
    publicKey: OPERATIONAL_PUBLIC_KEY,
    credentialIdB64u: CREDENTIAL_ID,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(9)),
    walletBinding: walletBinding(walletId),
    thresholdEd25519: {
      relayerKeyId: SIGNING_WORKER_ID,
      participantIds: [1, 2],
      session: {
        sessionKind: 'jwt',
        walletSessionJwt: unsignedWalletSessionJwt(walletId),
        walletId,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        walletSessionId: WALLET_SESSION_ID,
        quotaId: WALLET_SESSION_QUOTA_ID,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 4,
        runtimePolicyScope: {
          orgId: 'org-sync',
          projectId: 'project-sync',
          envId: 'test',
          signingRootVersion: ROOT_SHARE_EPOCH,
        },
        routerAbNormalSigning: {
          kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
          signingWorkerId: SIGNING_WORKER_ID,
        },
      },
    },
    ed25519YaoRecovery: {
      kind: 'router_ab_ed25519_yao_sync_recovery_v1',
      authorityRef: {
        kind: 'wallet_auth_authority_ref',
        walletId,
        authorityDigest: 'sync-account-authority-digest',
      },
      capability: {
        kind: 'router_ab_ed25519_yao_active_capability_v1',
        materialActivation: routerAbMpcMaterialActivationRefToWire(MATERIAL_ACTIVATION),
        activeCapabilityBinding: new Array<number>(32).fill(8),
        registeredPublicKey: [...REGISTERED_PUBLIC_KEY],
        nearAccountId: NEAR_ACCOUNT_ID,
        applicationBinding: {
          wallet_id: walletId,
          near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
          signing_root_id: 'project-sync:test',
          key_creation_signer_slot: SIGNER_SLOT,
        },
        participantIds: [1, 2],
        runtimePolicyScope: {
          orgId: 'org-sync',
          projectId: 'project-sync',
          envId: 'test',
          signingRootVersion: ROOT_SHARE_EPOCH,
        },
        lifecycle: {
          lifecycleId: 'sync-account-orchestration-lifecycle',
          rootShareEpoch: ROOT_SHARE_EPOCH,
          accountId: walletId,
          thresholdSessionId: THRESHOLD_SESSION_ID,
          signerSetId: 'signer-set-sync-1',
          signingWorkerId: SIGNING_WORKER_ID,
        },
        stateEpoch: 1,
        registrationContinuity: {
          kind: 'registration',
          admissionRequest,
          admissionReceipt,
          activationTranscript: new Array<number>(32).fill(11),
        },
      },
    },
    walletCustody: {
      kind: 'wallet_custody_sync_bootstrap_v1',
      envelope: rawPasskeyCustodyEnvelope({
        walletId,
        factor: {
          kind: 'passkey',
          rpId: RP_ID,
          credentialIdB64u: CREDENTIAL_ID,
          kekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
        },
      }),
      storeVersion: 'custody-store-version-1',
    },
    ecdsaCustody: {
      kind: 'wallet_custody_ecdsa_sync_continuity_v1',
      signers: ecdsaSigners,
    },
  };
}

function registrationAdmissionRequest(walletId: string) {
  return {
    scope: {
      lifecycle_id: 'sync-account-orchestration-lifecycle',
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: walletId,
      threshold_session_id: THRESHOLD_SESSION_ID,
      signer_set_id: 'signer-set-sync-1',
      signing_worker_id: SIGNING_WORKER_ID,
      material_activation: routerAbMpcMaterialActivationRefToWire(MATERIAL_ACTIVATION),
    },
    application_binding: {
      wallet_id: walletId,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: 'project-sync:test',
      key_creation_signer_slot: SIGNER_SLOT,
    },
    participant_ids: [1, 2] as const,
  };
}

function registrationAdmissionReceipt(walletId: string) {
  const request = registrationAdmissionRequest(walletId);
  return {
    binding: {
      lifecycle: {
        lifecycle_id: request.scope.lifecycle_id,
        work_kind: 'registration_prepare',
        primitive_request_kind: 'registration',
        root_share_epoch: request.scope.root_share_epoch,
        account_id: request.scope.account_id,
        session_id: request.scope.threshold_session_id,
        signer_set_id: request.scope.signer_set_id,
        selected_server_id: request.scope.signing_worker_id,
      },
      operation: 'registration',
      session_id: new Array<number>(32).fill(8),
      stable_key_context_binding: new Array<number>(32).fill(9),
      material_activation: request.scope.material_activation,
    },
    keyset: {
      deriver_a_input_public_key: new Array<number>(32).fill(1),
      deriver_b_input_public_key: new Array<number>(32).fill(2),
      signing_worker_recipient_public_key: new Array<number>(32).fill(3),
    },
  };
}

function requireRequestJson(init: RequestInit | undefined): Record<string, unknown> {
  if (typeof init?.body !== 'string') throw new Error('expected a JSON request body');
  const parsed: unknown = JSON.parse(init.body);
  if (!isPlainObject(parsed)) throw new Error('expected a JSON object request body');
  return parsed;
}

function jsonResponse(value: Record<string, unknown>): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function syncAccountFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const scenario = requireActiveFetchScenario();
  const url = input instanceof Request ? input.url : String(input);
  if (url === `${RELAYER_URL}/sync-account/options`) {
    return jsonResponse(syncOptionsResponse(scenario));
  }
  if (url === `${RELAYER_URL}/sync-account/verify`) {
    scenario.verifyRequest = requireRequestJson(init);
    return jsonResponse(syncVerifyResponse(scenario.verifiedWalletId, scenario.ecdsaSigners));
  }
  throw new Error(`unexpected syncAccount fetch: ${url}`);
}

function testConfigs(): SeamsConfigsReadonly {
  return {
    ...PASSKEY_MANAGER_DEFAULT_CONFIGS,
    network: {
      ...PASSKEY_MANAGER_DEFAULT_CONFIGS.network,
      relayer: {
        ...PASSKEY_MANAGER_DEFAULT_CONFIGS.network.relayer,
        url: RELAYER_URL,
      },
    },
    signing: {
      ...PASSKEY_MANAGER_DEFAULT_CONFIGS.signing,
      sessionDefaults: { ttlMs: 0, remainingUses: 0 },
    },
  };
}

class SyncAccountSigningSurfaceFixture implements AccountSyncSigningSurface {
  readonly credential = passkeyCredential();
  readonly activatedMaterials: NearEd25519YaoOperationMaterial[] = [];
  readonly activationQueueStates: boolean[] = [];
  readonly authenticatedWalletIds: string[] = [];
  readonly clearWalletIds: string[] = [];
  readonly hydratedSessionIds: string[] = [];
  readonly lastUserWalletIds: string[] = [];
  readonly sealedSessionIds: string[] = [];
  readonly sealedQueueStates: boolean[] = [];
  readonly queuedActivationIds: string[] = [];
  readonly laneReferences: Ed25519YaoPublicCapabilityLaneReferenceV1[] = [];
  readonly ecdsaRejoinInputs: Array<
    Parameters<AccountSyncSigningSurface['rejoinWalletCustodyEvmFamilyKeySet']>[0]
  > = [];
  readonly ecdsaRestoreInputs: Array<
    Parameters<AccountSyncSigningSurface['restoreWalletCustodyEcdsaContinuity']>[0]
  > = [];
  ecdsaRejoinPublicFacts: WalletCustodyEvmFamilyPublicFacts | null = null;
  private walletAuthenticationState: WalletAuthenticationState = { kind: 'signed_out' };
  private insideMaterialOwnerQueue = false;
  failAuthenticatedWalletActivation = false;
  storedUser: ClientUserData | null = null;

  getRpId(): string {
    return RP_ID;
  }

  readWalletAuthenticationState(): WalletAuthenticationState {
    return this.walletAuthenticationState;
  }

  async restoreWalletAuthenticationState(
    walletId: Parameters<AccountSyncSigningSurface['restoreWalletAuthenticationState']>[0],
    _auth: Parameters<AccountSyncSigningSurface['restoreWalletAuthenticationState']>[1],
  ): Promise<WalletAuthenticationState> {
    const resolvedWalletId = toWalletId(String(walletId || DISCOVERED_WALLET_ID));
    this.walletAuthenticationState = {
      kind: 'authenticated',
      walletId: resolvedWalletId,
      authMethod: 'passkey',
    };
    return this.walletAuthenticationState;
  }

  async assertSealedRefreshStartupParity(): Promise<void> {}

  getNonceCoordinator(): never {
    throw new Error('nonce coordinator is outside the syncAccount fixture');
  }

  async getUserBySignerSlot(): Promise<ClientUserData | null> {
    return this.storedUser;
  }

  async getLastUser(): Promise<ClientUserData | null> {
    return this.storedUser;
  }

  async nearAuthenticatorsByAccount(): Promise<[]> {
    return [];
  }

  async getWarmThresholdEd25519SessionStatus(): Promise<null> {
    return null;
  }

  async getWarmThresholdEcdsaSessionStatus(): Promise<null> {
    return null;
  }

  async listWarmThresholdEcdsaSessionStatuses(): Promise<[]> {
    return [];
  }

  async readPersistedAvailableSigningLanes(): Promise<never> {
    throw new Error('persisted lane snapshot is outside the syncAccount fixture');
  }

  async setLastUser(
    walletId: Parameters<AccountSyncSigningSurface['setLastUser']>[0],
  ): Promise<void> {
    this.lastUserWalletIds.push(String(walletId));
  }

  async activateAuthenticatedWalletState(
    input: Parameters<AccountSyncSigningSurface['activateAuthenticatedWalletState']>[0],
  ): Promise<void> {
    this.authenticatedWalletIds.push(String(input.walletId));
    if (this.failAuthenticatedWalletActivation) {
      throw new Error('mock authenticated wallet activation failed');
    }
  }

  async activateVerifiedNearEd25519YaoMaterial(
    material: NearEd25519YaoOperationMaterial,
  ): ReturnType<AccountSyncSigningSurface['activateVerifiedNearEd25519YaoMaterial']> {
    this.activationQueueStates.push(this.insideMaterialOwnerQueue);
    this.activatedMaterials.push(material);
    return {
      walletId: toWalletId(DISCOVERED_WALLET_ID),
      nearAccountId: toAccountId(NEAR_ACCOUNT_ID),
      materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
        material.activeClient.metadata(),
      ),
    };
  }

  async withExactEd25519MaterialOwner<T>(
    args: Parameters<AccountSyncSigningSurface['withExactEd25519MaterialOwner']>[0],
  ): Promise<T> {
    this.queuedActivationIds.push(String(args.materialActivation.activationId));
    if (this.insideMaterialOwnerQueue) {
      throw new Error('syncAccount fixture entered the material owner recursively');
    }
    this.insideMaterialOwnerQueue = true;
    try {
      return await args.task();
    } finally {
      this.insideMaterialOwnerQueue = false;
    }
  }

  async clearVolatileWarmSigningMaterial(
    walletId?: Parameters<AccountSyncSigningSurface['clearVolatileWarmSigningMaterial']>[0],
  ): Promise<void> {
    this.clearWalletIds.push(String(walletId || ''));
    const material = this.activatedMaterials[0];
    material?.activeClient.dispose();
  }

  async hydrateSigningSession(
    input: Parameters<AccountSyncSigningSurface['hydrateSigningSession']>[0],
  ): Promise<void> {
    this.hydratedSessionIds.push(input.thresholdSessionId);
  }

  async persistSigningSessionSealForThresholdSession(
    input: Parameters<AccountSyncSigningSurface['persistSigningSessionSealForThresholdSession']>[0],
  ): ReturnType<AccountSyncSigningSurface['persistSigningSessionSealForThresholdSession']> {
    this.sealedQueueStates.push(this.insideMaterialOwnerQueue);
    this.sealedSessionIds.push(input.thresholdSessionId);
    return {
      ok: true,
      sealedSecretB64u: 'sealed-session-refresh-secret',
      remainingUses: 4,
      expiresAtMs: Date.now() + 60_000,
    };
  }

  async upsertEd25519YaoPublicCapabilityLaneReference(
    reference: Parameters<
      AccountSyncSigningSurface['upsertEd25519YaoPublicCapabilityLaneReference']
    >[0],
  ): Promise<void> {
    this.laneReferences.push(reference);
  }

  async getAuthenticationCredentialsSerialized(): Promise<WebAuthnAuthenticationCredential> {
    return this.credential;
  }

  async storeUserData(
    input: Parameters<AccountSyncSigningSurface['storeUserData']>[0],
  ): Promise<void> {
    this.storedUser = {
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      loginDisplayName: input.loginDisplayName || input.walletId,
      signerSlot: input.signerSlot,
      operationalPublicKey: input.operationalPublicKey,
      passkeyCredential: input.passkeyCredential,
      version: input.version,
      lastUpdated: input.lastUpdated,
    };
  }

  async storeAuthenticator(): Promise<void> {}

  async rejoinWalletCustodyNearEd25519KeySet(
    args: Parameters<AccountSyncSigningSurface['rejoinWalletCustodyNearEd25519KeySet']>[0],
  ): ReturnType<AccountSyncSigningSurface['rejoinWalletCustodyNearEd25519KeySet']> {
    const scenario = requireActiveYaoScenario();
    const factorSecret = new Uint8Array(args.factorSecret);
    scenario.capturedPrfFirst = factorSecret;
    try {
      if (scenario.failRecovery) throw new Error('mock Yao recovery failed');
      const metadata = scenario.activeClient.metadata();
      return {
        commitPayload: {
          walletId: args.walletId,
          keySet: 'near_ed25519_v1',
          keyManifestDigestB64u: base64UrlEncode(new Uint8Array(32).fill(4)),
        },
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1',
          lifecycle_id: args.registrationCeremonyId,
          session_id: metadata.activeCapabilityBinding,
        },
        localMaterial: {
          b64u: base64UrlEncode(new Uint8Array(48).fill(5)),
          nonceB64u: base64UrlEncode(new Uint8Array(12).fill(6)),
          applicationBindingDigestB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
        },
        metadata,
      };
    } finally {
      factorSecret.fill(0);
    }
  }

  async rejoinWalletCustodyEvmFamilyKeySet(
    args: Parameters<AccountSyncSigningSurface['rejoinWalletCustodyEvmFamilyKeySet']>[0],
  ): ReturnType<AccountSyncSigningSurface['rejoinWalletCustodyEvmFamilyKeySet']> {
    this.ecdsaRejoinInputs.push(args);
    if (!this.ecdsaRejoinPublicFacts) {
      throw new Error('ECDSA custody rejoin is outside the Ed25519-only sync fixture');
    }
    return {
      readyStateBlobB64u: base64UrlEncode(new Uint8Array(64).fill(31)),
      publicFacts: this.ecdsaRejoinPublicFacts,
    };
  }

  async restoreWalletCustodyEcdsaContinuity(
    args: Parameters<AccountSyncSigningSurface['restoreWalletCustodyEcdsaContinuity']>[0],
  ): ReturnType<AccountSyncSigningSurface['restoreWalletCustodyEcdsaContinuity']> {
    this.ecdsaRestoreInputs.push(args);
    const materialActivation = routerAbMpcMaterialActivationRefFromWire(
      args.activationReceipt.ecdsa_activation.material_activation,
    );
    return {
      materialActivation,
      materialRef: {
        kind: 'ecdsa_role_local_persisted_material_ref_v1',
        durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef('sync-fixture-material'),
        bindingDigest: parseEcdsaRoleLocalBindingDigest(args.publicFacts.contextBinding32B64u),
        materialActivation,
      },
    };
  }

  async persistWalletCustodyEd25519Material(): Promise<void> {}
}

function createContext(surface: SyncAccountSigningSurfaceFixture): AccountSyncWebContext {
  return {
    signingEngine: surface,
    nearClient: new MinimalNearClient('https://rpc.testnet.near.org'),
    configs: testConfigs(),
    theme: 'light',
  };
}

function mixedWalletEcdsaSyncFixture(walletId: string): {
  readonly signers: readonly Record<string, unknown>[];
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
} {
  const targets = [
    { kind: 'evm', namespace: 'eip155', chainId: 8453, networkSlug: 'base' },
    { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-test' },
  ] as const;
  const fixture = ecdsaCapabilityActivationFixture({
    walletId: walletIdFromString(walletId),
    targetMemberships: targets,
    signingRootId: 'project-sync:test',
    signingRootVersion: ROOT_SHARE_EPOCH,
  });
  const binding = fixture.prepareInput.activationBinding;
  const roleFacts = fixture.sealInput.roleLocalPublicFacts;
  const receipt = fixture.serverCommit.protocolReceipt;
  const walletKey = {
    walletId,
    keyHandle: String(binding.roleLocalBinding.keyHandle),
    ecdsaThresholdKeyId: String(binding.roleLocalBinding.ecdsaThresholdKeyId),
    signingRootId: String(binding.signer.signingRootId),
    signingRootVersion: String(binding.signer.signingRootVersion),
    relayerKeyId: String(binding.roleLocalBinding.relayerKeyId),
    contextBinding32B64u: roleFacts.contextBinding32B64u,
    derivationClientSharePublicKey33B64u: roleFacts.derivationClientSharePublicKey33B64u,
    participantIds: [1, 2],
    publicCapability: roleFacts.publicCapability,
  };
  return {
    signers: targets.map((chainTarget, index) => ({
      chainTarget:
        index === 0
          ? { kind: 'evm', namespace: 'eip155', chainId: chainTarget.chainId }
          : chainTarget,
      walletKey,
      activationReceipt: receipt,
      runtimePolicyScope: fixture.sealInput.runtimePolicyScope,
    })),
    publicFacts: {
      contextBinding32B64u: roleFacts.contextBinding32B64u,
      derivationClientSharePublicKey33B64u: roleFacts.derivationClientSharePublicKey33B64u,
      clientVerifyingShare33B64u: roleFacts.derivationClientSharePublicKey33B64u,
      relayerPublicKey33B64u: roleFacts.relayerPublicKey33B64u,
      groupPublicKey33B64u: roleFacts.groupPublicKey33B64u,
      ethereumAddress: roleFacts.ethereumAddress,
      clientShareRetryCounter: receipt.ecdsa_activation.public_identity.client_share_retry_counter,
      relayerShareRetryCounter: receipt.ecdsa_activation.public_identity.server_share_retry_counter,
    },
  };
}

function configureTestScenario(input: {
  readonly optionsWalletId: string | null;
  readonly verifiedWalletId: string;
  readonly failRecovery?: boolean;
  readonly ecdsaSigners?: readonly Record<string, unknown>[];
}): YaoScenario {
  const yaoScenario = createYaoScenario();
  yaoScenario.failRecovery = input.failRecovery === true;
  activeYaoScenario = yaoScenario;
  activeFetchScenario = {
    optionsWalletId: input.optionsWalletId,
    verifiedWalletId: input.verifiedWalletId,
    ecdsaSigners: input.ecdsaSigners ?? [],
    verifyRequest: null,
  };
  return yaoScenario;
}

function setupSyncAccountTest(): void {
  activeYaoScenario = null;
  activeFetchScenario = null;
  activePersistenceFixture = new SyncAccountPersistenceFixture();
  globalThis.fetch = syncAccountFetch;
  installPersistenceFixture(activePersistenceFixture);
  installYaoClientMock();
}

function teardownSyncAccountTest(): void {
  activeYaoScenario = null;
  activeFetchScenario = null;
  activePersistenceFixture = null;
  globalThis.fetch = originalFetch;
  restorePersistenceFixture();
  restoreYaoClientInitializer();
}

test.beforeEach(setupSyncAccountTest);
test.afterEach(teardownSyncAccountTest);

test.describe('public syncAccount Yao orchestration', () => {
  test('discovery sends only the Yao recovery request and restores the verified identity', async () => {
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), null);

    expect(result, JSON.stringify(result)).toMatchObject({
      success: true,
      walletId: DISCOVERED_WALLET_ID,
      accountId: DISCOVERED_WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      publicKey: OPERATIONAL_PUBLIC_KEY,
    });
    const fetchScenario = requireActiveFetchScenario();
    expect(fetchScenario.verifyRequest).not.toBeNull();
    expect(fetchScenario.verifyRequest).not.toHaveProperty('threshold_ed25519');
    expect(fetchScenario.verifyRequest).toMatchObject({
      challengeId: 'sync-challenge-id',
      webauthn_authentication: { clientExtensionResults: null },
    });
    expect(surface.activatedMaterials).toHaveLength(1);
    expect(surface.queuedActivationIds).toEqual([String(MATERIAL_ACTIVATION.activationId)]);
    expect(surface.activationQueueStates).toEqual([true]);
    expect(surface.hydratedSessionIds).toEqual([THRESHOLD_SESSION_ID]);
    expect(surface.sealedSessionIds).toEqual([]);
    expect(surface.sealedQueueStates).toEqual([]);
    expect(surface.laneReferences).toHaveLength(1);
    const freshMaterialActivation = nearEd25519YaoMaterialActivationFromMetadata(
      surface.activatedMaterials[0]!.activeClient.metadata(),
    );
    expect(surface.laneReferences[0]).toMatchObject({
      walletId: DISCOVERED_WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      auth: { kind: 'passkey', rpId: RP_ID, credentialIdB64u: CREDENTIAL_ID },
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      signerSlot: SIGNER_SLOT,
    });
    expect(
      mpcMaterialActivationRefsEqual(
        surface.laneReferences[0]!.materialActivation,
        freshMaterialActivation,
      ),
    ).toBe(true);
    expect(freshMaterialActivation.materialOwner).toBe(MATERIAL_ACTIVATION.materialOwner);
    expect(freshMaterialActivation.keyBinding).toBe(MATERIAL_ACTIVATION.keyBinding);
    expect(freshMaterialActivation.signingWorker).toBe(MATERIAL_ACTIVATION.signingWorker);
    expect(freshMaterialActivation.activationId).toBe(MATERIAL_ACTIVATION.activationId);
    expect(surface.authenticatedWalletIds).toEqual([DISCOVERED_WALLET_ID, DISCOVERED_WALLET_ID]);
    expect(surface.lastUserWalletIds).toEqual([DISCOVERED_WALLET_ID]);
    expect(surface.clearWalletIds).toEqual([]);
    const persistence = requireActivePersistenceFixture();
    expect(persistence.appState.size).toBe(0);
    expect([...persistence.keyMaterial.values()].map((record) => record.keyKind)).toEqual([]);
  });

  test('mixed-wallet sync rejoins one ECDSA key and preserves its Router activation across targets', async () => {
    const ecdsa = mixedWalletEcdsaSyncFixture(DISCOVERED_WALLET_ID);
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      ecdsaSigners: ecdsa.signers,
    });
    const surface = new SyncAccountSigningSurfaceFixture();
    surface.ecdsaRejoinPublicFacts = ecdsa.publicFacts;

    const result = await syncAccount(createContext(surface), null);

    expect(result.success).toBe(true);
    expect(surface.ecdsaRejoinInputs).toHaveLength(1);
    expect(surface.ecdsaRestoreInputs).toHaveLength(1);
    expect(surface.ecdsaRejoinInputs[0]).toMatchObject({
      walletId: DISCOVERED_WALLET_ID,
      applicationBindingDigestB64u:
        surface.ecdsaRestoreInputs[0]!.publicCapability.context.application_binding_digest_b64u,
      registeredClientRootPublicKey33B64u: ecdsa.publicFacts.derivationClientSharePublicKey33B64u,
    });
    expect(
      new Uint8Array(surface.ecdsaRejoinInputs[0]!.factorSecret).every((byte) => byte === 0),
    ).toBe(true);
    expect(surface.ecdsaRestoreInputs[0]!.chainTargets).toEqual([
      { kind: 'evm', namespace: 'eip155', chainId: 8453, networkSlug: 'evm-8453' },
      { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-test' },
    ]);
    expect(surface.ecdsaRestoreInputs[0]!.activationReceipt).toEqual(
      ecdsa.signers[0]!.activationReceipt,
    );
    expect(surface.ecdsaRestoreInputs[0]!.readyStateBlobB64u).toBe(
      base64UrlEncode(new Uint8Array(64).fill(31)),
    );
  });

  test('rejects requested-wallet substitution and clears the recovered wallet capability', async () => {
    const yaoScenario = configureTestScenario({
      optionsWalletId: REQUESTED_WALLET_ID,
      verifiedWalletId: DISCOVERED_WALLET_ID,
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), REQUESTED_WALLET_ID);

    expect(result).toMatchObject({
      success: false,
      error: 'sync-account/verify returned mismatched wallet binding',
    });
    expect(surface.activatedMaterials).toEqual([]);
    expect(surface.clearWalletIds).toEqual([]);
    expect(yaoScenario.disposeCalls).toBe(1);
  });

  test('zeroizes PRF.first when the Yao recovery helper fails', async () => {
    const yaoScenario = configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      failRecovery: true,
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), null);

    expect(result).toMatchObject({ success: false, error: 'mock Yao recovery failed' });
    expect(yaoScenario.capturedPrfFirst).toEqual(new Uint8Array(32));
    expect(surface.activatedMaterials).toEqual([]);
    expect(surface.clearWalletIds).toEqual([]);
  });

  test('clears wallet-scoped volatile material after post-registry login failure', async () => {
    const yaoScenario = configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
    });
    const surface = new SyncAccountSigningSurfaceFixture();
    surface.failAuthenticatedWalletActivation = true;

    const result = await syncAccount(createContext(surface), null);

    expect(result).toMatchObject({
      success: false,
      error: 'mock authenticated wallet activation failed',
    });
    expect(surface.activatedMaterials).toHaveLength(1);
    expect(surface.clearWalletIds).toEqual([DISCOVERED_WALLET_ID]);
    expect(yaoScenario.disposeCalls).toBe(1);
  });
});
