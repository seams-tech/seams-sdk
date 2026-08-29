import { expect, test } from '@playwright/test';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../../packages/wallet/src/core/config/defaultConfigs';
import type { ClientUserData } from '../../packages/wallet/src/core/accountData/near/nearAccountData.types';
import {
  buildActiveWalletSessionV1,
  IndexedDBManager,
  walletSessionAuthorizations,
} from '../../packages/wallet/src/core/indexedDB';
import type {
  KeyMaterialKind,
  KeyMaterialRecord,
} from '../../packages/wallet/src/core/indexedDB/keyMaterial.types';
import type { NearEd25519YaoOperationMaterial } from '../../packages/wallet/src/core/signingEngine/interfaces/near';
import { toWalletId } from '../../packages/wallet/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '../../packages/wallet/src/core/signingEngine/workerManager/executeWorkerOperation';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
} from '../../packages/wallet/src/core/signingEngine/session/keyMaterialBrands';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../packages/wallet/src/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import {
  ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoSealableActiveClientV1,
} from '../../packages/wallet/src/core/signingEngine/threshold/ed25519/yaoClient';
import { MinimalNearClient } from '../../packages/wallet/src/core/rpcClients/near/NearClient';
import type {
  AccountSyncSigningSurface,
  AccountSyncWebContext,
} from '../../packages/wallet/src/SeamsWeb/signingSurface/types';
import type { Ed25519YaoPublicCapabilityLaneReferenceV1 } from '../../packages/wallet/src/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { syncAccount } from '../../packages/wallet/src/SeamsWeb/operations/recovery/syncAccount';
import type { WebAuthnAuthenticationCredential } from '../../packages/wallet/src/core/types/webauthn';
import type {
  SeamsConfigsReadonly,
  WalletAuthenticationState,
} from '../../packages/wallet/src/core/types/seams';
import { toAccountId } from '../../packages/wallet/src/core/types/accountIds';
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { isPlainObject } from '../../packages/shared-ts/src/utils/validation';
import { mpcMaterialActivationRefsEqual } from '../../packages/shared-ts/src/utils/domainIds';
import {
  routerAbMpcMaterialActivationRefFromWire,
  routerAbMpcMaterialActivationRefToWire,
} from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import type { WalletCustodyEvmFamilyPublicFacts } from '../../packages/shared-ts/src/passkey-custody/ceremonyCommitPayload';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWalletSessionAuthorizationId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import {
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefForAuthorityFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import { ecdsaCapabilityActivationFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';
import { rawPasskeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';

const RELAYER_URL = 'https://router.example.test';
const RP_ID = 'wallet.example.test';
const DISCOVERED_WALLET_ID = 'discovered-wallet';
const REQUESTED_WALLET_ID = 'requested-wallet';
const OTHER_CREDENTIAL_ID = base64UrlEncode(new Uint8Array(32).fill(37));
const NEAR_ACCOUNT_ID = 'discovered-wallet.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519ks_discovered_wallet';
const CREDENTIAL_ID = base64UrlEncode(new Uint8Array(32).fill(36));
const SIGNER_SLOT = 3;
const THRESHOLD_SESSION_ID = 'threshold-session-sync-1';
const WALLET_SESSION_ID = 'wallet-session-sync-1';
const WALLET_SESSION_QUOTA_ID = 'wallet-session-quota-sync-1';
const OPERATION_CREDENTIAL_TOKEN = `wst_${base64UrlEncode(new Uint8Array(32).fill(88))}`;
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
  readonly ecdsaSessionAuthorizationId?: string;
  readonly ecdsaSessionMaterialActivation?: Record<string, unknown>;
  readonly alreadyCommittedWalletId?: string;
  readonly alreadyCommittedWalletAuthMethodId?: string;
  readonly replacementCredentialIds?: readonly string[];
  verifyRequest: Record<string, unknown> | null;
  readonly alreadyCommittedBeforeSuccess: number;
  optionsCalls: number;
  verifyCalls: number;
  verifyRequests: Record<string, unknown>[];
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

type IndexedDbDirectMethod =
  | 'listWalletPasskeyAuthenticators'
  | 'persistFoundingWalletAuthority'
  | 'resolveProfileAccountContext'
  | 'isDisabled'
  | 'upsertProfile';

const indexedDbDirectMethods = [
  'listWalletPasskeyAuthenticators',
  'persistFoundingWalletAuthority',
  'resolveProfileAccountContext',
  'isDisabled',
  'upsertProfile',
] as const satisfies readonly IndexedDbDirectMethod[];

const originalIndexedDbDirectMethods = new Map<IndexedDbDirectMethod, unknown>();
const originalWriteExactWithOperationCredential =
  walletSessionAuthorizations.writeExactWithOperationCredential;
const originalUpsertActiveWithCurveMerge = walletSessionAuthorizations.upsertActiveWithCurveMerge;
type ExactWalletSessionWriteInput = Parameters<
  typeof walletSessionAuthorizations.writeExactWithOperationCredential
>[0];

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
  readonly profileSeeds: Array<Parameters<typeof IndexedDBManager.upsertProfile>[0]> = [];
  readonly exactWalletSessionWrites: ExactWalletSessionWriteInput[] = [];
  readonly legacyWalletSessionCurveWrites: Array<
    Parameters<typeof walletSessionAuthorizations.upsertActiveWithCurveMerge>[0]
  > = [];

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

  async listWalletPasskeyAuthenticators(): Promise<[]> {
    return [];
  }

  async persistFoundingWalletAuthority(): Promise<void> {}

  isDisabled(): boolean {
    return true;
  }

  async resolveProfileAccountContext(
    accountRef: Parameters<typeof IndexedDBManager.resolveProfileAccountContext>[0],
  ): ReturnType<typeof IndexedDBManager.resolveProfileAccountContext> {
    if (this.profileSeeds.length === 0) return null;
    return { profileId: 'sync-profile', accountRef };
  }

  async upsertProfile(
    input: Parameters<typeof IndexedDBManager.upsertProfile>[0],
  ): ReturnType<typeof IndexedDBManager.upsertProfile> {
    this.profileSeeds.push(input);
    return {
      profileId: input.profileId,
      defaultSignerSlot: input.defaultSignerSlot ?? 1,
      createdAt: 0,
      updatedAt: 0,
    };
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
  for (const method of indexedDbDirectMethods) {
    originalIndexedDbDirectMethods.set(method, manager[method]);
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
  for (const method of indexedDbDirectMethods) {
    const original = originalIndexedDbDirectMethods.get(method);
    if (!Reflect.set(manager, method, original)) {
      throw new Error(`failed to restore IndexedDB ${method}`);
    }
  }
  originalIndexedDbDirectMethods.clear();
  walletSessionAuthorizations.writeExactWithOperationCredential =
    originalWriteExactWithOperationCredential;
  walletSessionAuthorizations.upsertActiveWithCurveMerge = originalUpsertActiveWithCurveMerge;
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

function syncOptionsResponse(
  scenario: FetchScenario,
  requestedWalletId: string | null,
): Record<string, unknown> {
  const replacement = scenario.optionsCalls > 1;
  const optionsWalletId = scenario.optionsWalletId ?? requestedWalletId;
  const credentialIds = replacement && scenario.replacementCredentialIds
    ? scenario.replacementCredentialIds
    : optionsWalletId
      ? [CREDENTIAL_ID]
      : [];
  return {
    ok: true,
    challengeId: replacement ? 'sync-challenge-id-replacement' : 'sync-challenge-id',
    challengeB64u: replacement ? 'sync-challenge-b64u-replacement' : 'sync-challenge-b64u',
    credentialIds,
    ...(optionsWalletId ? { walletBinding: walletBinding(optionsWalletId) } : {}),
  };
}

function ecdsaSessionResponseForSync(
  ecdsaSigners: readonly Record<string, unknown>[],
  expiresAtMs: number,
): {
  readonly ecdsaSession: Record<string, unknown>;
  readonly ecdsaActivationReceipt: Record<string, unknown>;
} | null {
  const firstSigner = ecdsaSigners[0];
  if (!firstSigner) return null;
  if (!isPlainObject(firstSigner.walletKey) || !isPlainObject(firstSigner.activationReceipt)) {
    throw new Error('ECDSA sync fixture signer is incomplete');
  }
  const walletKey = firstSigner.walletKey;
  if (!isPlainObject(walletKey.publicCapability)) {
    throw new Error('ECDSA sync fixture public capability is incomplete');
  }
  const publicCapability = walletKey.publicCapability;
  if (!isPlainObject(publicCapability.signer_set)) {
    throw new Error('ECDSA sync fixture signer set is incomplete');
  }
  const signerSet = publicCapability.signer_set;
  if (!isPlainObject(signerSet.selected_server)) {
    throw new Error('ECDSA sync fixture selected server is incomplete');
  }
  if (!isPlainObject(firstSigner.activationReceipt.ecdsa_activation)) {
    throw new Error('ECDSA sync fixture activation is incomplete');
  }
  const activation = firstSigner.activationReceipt.ecdsa_activation;
  return {
    ecdsaSession: {
      kind: 'router_ab_ecdsa_credential_free_session_activated_v1',
      public_capability: publicCapability,
      session: {
        authorization_session_id: 'ecdsa-authorization-session-sync-1',
        authorization_id: 'authorization:sync-account-orchestration',
        threshold_session_id: 'threshold-ecdsa-session-sync-1',
        wallet_session_id: WALLET_SESSION_ID,
        quota_id: WALLET_SESSION_QUOTA_ID,
        expires_at_ms: expiresAtMs,
        remaining_uses: 4,
      },
      normal_signing: {
        kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
        scope: {
          wallet_id: String(walletKey.walletId),
          ecdsa_threshold_key_id: String(walletKey.ecdsaThresholdKeyId),
          signing_root_id: String(walletKey.signingRootId),
          signing_root_version: String(walletKey.signingRootVersion),
          context: activation.context,
          public_identity: publicCapability.public_identity,
          material_activation: publicCapability.material_activation,
          signing_worker: signerSet.selected_server,
          activation_epoch: publicCapability.activation_epoch,
        },
      },
    },
    ecdsaActivationReceipt: firstSigner.activationReceipt,
  };
}

async function syncVerifyResponse(scenario: FetchScenario): Promise<Record<string, unknown>> {
  const walletId = scenario.verifiedWalletId;
  const ecdsaSigners = scenario.ecdsaSigners;
  const founding = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'sync-account-orchestration',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    materialActivation: MATERIAL_ACTIVATION,
    identity: {
      walletId,
      authorityId: 'wallet-authority:sync-account-orchestration',
      walletAuthMethodId: 'wallet-auth-method:sync-account-orchestration',
      rpId: RP_ID,
    },
  });
  const expiresAtMs = Date.now() + 60_000;
  const ecdsaResponse = ecdsaSessionResponseForSync(ecdsaSigners, expiresAtMs);
  const ecdsaMaterialActivation = ecdsaSessionMaterialActivationForSync(ecdsaSigners);
  const authorityRef = buildWalletAuthAuthorityRefForAuthorityFixture({
    walletId: founding.authority.walletId,
    factor: {
      kind: 'passkey',
      credentialIdB64u: founding.authMethod.credentialIdB64u,
    },
    verifier: { kind: 'webauthn', rpId: founding.authMethod.rpId },
    bindingId: founding.authMethod.walletAuthMethodId,
  });
  const admissionRequest = registrationAdmissionRequest(walletId);
  const admissionReceipt = registrationAdmissionReceipt(walletId);
  const authorizationId = parseWalletSessionAuthorizationId(
    'authorization:sync-account-orchestration',
  );
  if (!authorizationId.ok) throw new Error(authorizationId.error.message);
  const walletSession = buildActiveWalletSessionV1({
    walletId: walletIdFromString(walletId),
    authorityId: founding.authority.authorityId,
    authMethodId: founding.authMethod.walletAuthMethodId,
    authorizationId: authorizationId.value,
    authorityDigestB64u: founding.authority.authorityDigestB64u,
    authorityRevocationEpoch: founding.authority.revocationEpoch,
    capabilitySubjects: [
      { kind: 'sign', keyFamily: 'ed25519', materialActivation: MATERIAL_ACTIVATION },
      { kind: 'export_keys', keyFamily: 'ed25519', materialActivation: MATERIAL_ACTIVATION },
      ...(ecdsaMaterialActivation
        ? [
            {
              kind: 'sign' as const,
              keyFamily: 'ecdsa_secp256k1' as const,
              materialActivation:
                scenario.ecdsaSessionMaterialActivation ?? ecdsaMaterialActivation,
            },
            {
              kind: 'export_keys' as const,
              keyFamily: 'ecdsa_secp256k1' as const,
              materialActivation:
                scenario.ecdsaSessionMaterialActivation ?? ecdsaMaterialActivation,
            },
          ]
        : []),
      { kind: 'link_devices' },
      { kind: 'revoke_devices' },
    ],
    issuedAtMs: Date.now() - 1_000,
    expiresAtMs,
  });
  const response = {
    ok: true,
    verified: true,
    walletId,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    signerSlot: SIGNER_SLOT,
    publicKey: OPERATIONAL_PUBLIC_KEY,
    credentialIdB64u: CREDENTIAL_ID,
    credentialPublicKeyB64u: founding.authMethod.credentialPublicKeyB64u,
    walletBinding: walletBinding(walletId),
    walletAuthMethodId: String(founding.authMethod.walletAuthMethodId),
    walletAuthorityId: String(founding.authority.authorityId),
    foundingAuthority: founding.authority,
    foundingAuthMethod: founding.authMethod,
    thresholdEd25519: {
      relayerKeyId: SIGNING_WORKER_ID,
      keyVersion: 'key-version-sync-1',
      participantIds: [1, 2],
      session: {
        walletId,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        walletSessionId: WALLET_SESSION_ID,
        quotaId: WALLET_SESSION_QUOTA_ID,
        expiresAtMs,
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
    walletSession,
    operationCredential: {
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: OPERATION_CREDENTIAL_TOKEN,
      walletSessionId: WALLET_SESSION_ID,
    },
    ed25519YaoRecovery: {
      kind: 'router_ab_ed25519_yao_sync_recovery_v1',
      authorityRef,
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
  if (ecdsaResponse) {
    if (scenario.ecdsaSessionAuthorizationId) {
      if (!isPlainObject(ecdsaResponse.ecdsaSession.session)) {
        throw new Error('ECDSA sync fixture session is incomplete');
      }
      ecdsaResponse.ecdsaSession.session.authorization_id = scenario.ecdsaSessionAuthorizationId;
    }
    response.ecdsaSession = ecdsaResponse.ecdsaSession;
    response.ecdsaActivationReceipt = ecdsaResponse.ecdsaActivationReceipt;
  }
  return response;
}

function ecdsaSessionMaterialActivationForSync(
  ecdsaSigners: readonly Record<string, unknown>[],
): Record<string, unknown> | null {
  const firstSigner = ecdsaSigners[0];
  if (!firstSigner || !isPlainObject(firstSigner.walletKey)) return null;
  if (!isPlainObject(firstSigner.walletKey.publicCapability)) return null;
  const materialActivation = firstSigner.walletKey.publicCapability.material_activation;
  return isPlainObject(materialActivation)
    ? routerAbMpcMaterialActivationRefFromWire(materialActivation)
    : null;
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

function jsonResponse(value: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function syncAccountFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const scenario = requireActiveFetchScenario();
  const url = input instanceof Request ? input.url : String(input);
  if (url === `${RELAYER_URL}/sync-account/options`) {
    scenario.optionsCalls += 1;
    const request = requireRequestJson(init);
    const requestedWalletId =
      typeof request.account_id === 'string' && request.account_id.trim()
        ? request.account_id
        : null;
    return jsonResponse(syncOptionsResponse(scenario, requestedWalletId));
  }
  if (url === `${RELAYER_URL}/sync-account/verify`) {
    const request = requireRequestJson(init);
    scenario.verifyCalls += 1;
    scenario.verifyRequests.push(request);
    scenario.verifyRequest = request;
    if (scenario.verifyCalls <= scenario.alreadyCommittedBeforeSuccess) {
      return jsonResponse(
        {
          ok: false,
          code: 'already_committed',
          kind: 'already_committed',
          next: 'unlock_exact_method',
          walletId: scenario.alreadyCommittedWalletId ?? scenario.verifiedWalletId,
          authorityId: 'wallet-authority:sync-account-orchestration',
          walletAuthMethodId:
            scenario.alreadyCommittedWalletAuthMethodId ??
            'wallet-auth-method:sync-account-orchestration',
          mintId: 'wallet-mint:sync-account-orchestration',
          authorizationId: 'authorization:sync-account-orchestration',
          walletSessionId: WALLET_SESSION_ID,
          quotaId: WALLET_SESSION_QUOTA_ID,
        },
        409,
      );
    }
    return jsonResponse(await syncVerifyResponse(scenario));
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
  authenticationCredentialCalls = 0;
  readonly authenticationChallengeB64us: string[] = [];
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

  getSignerWorkerContext(): WorkerOperationContext {
    return {
      requestWorkerOperation: async () => {
        throw new Error('worker operations are outside the syncAccount fixture');
      },
    };
  }

  async createWalletRecoveryReplacementCredential(
    _args: Parameters<AccountSyncSigningSurface['createWalletRecoveryReplacementCredential']>[0],
  ): Promise<never> {
    throw new Error('wallet recovery ceremony is outside the syncAccount fixture');
  }

  async recoverWalletCustodyManifest(
    _args: Parameters<AccountSyncSigningSurface['recoverWalletCustodyManifest']>[0],
  ): Promise<never> {
    throw new Error('wallet recovery ceremony is outside the syncAccount fixture');
  }

  async establishWalletCustodyNearEd25519KeySet(
    _args: Parameters<AccountSyncSigningSurface['establishWalletCustodyNearEd25519KeySet']>[0],
  ): Promise<never> {
    throw new Error('wallet custody ceremony is outside the syncAccount fixture');
  }

  async joinWalletCustodyNearEd25519KeySet(
    _args: Parameters<AccountSyncSigningSurface['joinWalletCustodyNearEd25519KeySet']>[0],
  ): Promise<never> {
    throw new Error('wallet custody ceremony is outside the syncAccount fixture');
  }

  async establishWalletCustodyEvmFamilyKeySet(
    _args: Parameters<AccountSyncSigningSurface['establishWalletCustodyEvmFamilyKeySet']>[0],
  ): Promise<never> {
    throw new Error('wallet custody ceremony is outside the syncAccount fixture');
  }

  async joinWalletCustodyEvmFamilyKeySet(
    _args: Parameters<AccountSyncSigningSurface['joinWalletCustodyEvmFamilyKeySet']>[0],
  ): Promise<never> {
    throw new Error('wallet custody ceremony is outside the syncAccount fixture');
  }

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

  async setWalletNearProvisioningState(
    _input: Parameters<AccountSyncSigningSurface['setWalletNearProvisioningState']>[0],
  ): Promise<void> {}

  async nearAuthenticatorsByAccount(): Promise<[]> {
    return [];
  }

  async getWarmThresholdEd25519SessionStatus(): Promise<null> {
    return null;
  }

  async getWarmThresholdEcdsaSessionStatus(): Promise<null> {
    return null;
  }

  async readReusableWalletSessionState(): Promise<never> {
    throw new Error('reusable wallet session state is outside the syncAccount fixture');
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

  async withExactEd25519MaterialOwner<T>(args: {
    readonly materialActivation: typeof MATERIAL_ACTIVATION;
    readonly nearAccountId: ReturnType<typeof toAccountId>;
    readonly task: () => Promise<T>;
  }): Promise<T> {
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

  async hydrateSigningSession(input: { readonly thresholdSessionId: string }): Promise<void> {
    this.hydratedSessionIds.push(input.thresholdSessionId);
  }

  async persistSigningSessionSealForThresholdSession(input: {
    readonly thresholdSessionId: string;
  }): Promise<{
    readonly ok: true;
    readonly sealedSecretB64u: string;
    readonly remainingUses: number;
    readonly expiresAtMs: number;
  }> {
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

  async getAuthenticationCredentialsSerialized(
    input: Parameters<AccountSyncSigningSurface['getAuthenticationCredentialsSerialized']>[0],
  ): Promise<WebAuthnAuthenticationCredential> {
    this.authenticationCredentialCalls += 1;
    this.authenticationChallengeB64us.push(input.challengeB64u);
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
    await IndexedDBManager.upsertProfile({
      profileId: input.walletId,
      defaultSignerSlot: input.signerSlot,
    });
  }

  async storeNearThresholdKeyMaterial(
    _input: Parameters<AccountSyncSigningSurface['storeNearThresholdKeyMaterial']>[0],
  ): Promise<void> {}

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

  async loadWalletCustodyEd25519Material(): Promise<{ readonly kind: 'absent' }> {
    return { kind: 'absent' };
  }

  async deleteWalletCustodyEd25519Material(): Promise<void> {}
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
  const receipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(
    fixture.serverCommit.protocolReceipt,
  );
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
  readonly ecdsaSessionAuthorizationId?: string;
  readonly ecdsaSessionMaterialActivation?: Record<string, unknown>;
  readonly alreadyCommittedWalletId?: string;
  readonly alreadyCommittedWalletAuthMethodId?: string;
  readonly replacementCredentialIds?: readonly string[];
  readonly alreadyCommittedBeforeSuccess?: number;
}): YaoScenario {
  const yaoScenario = createYaoScenario();
  yaoScenario.failRecovery = input.failRecovery === true;
  activeYaoScenario = yaoScenario;
  activeFetchScenario = {
    optionsWalletId: input.optionsWalletId,
    verifiedWalletId: input.verifiedWalletId,
    ecdsaSigners: input.ecdsaSigners ?? [],
    ecdsaSessionAuthorizationId: input.ecdsaSessionAuthorizationId,
    ecdsaSessionMaterialActivation: input.ecdsaSessionMaterialActivation,
    alreadyCommittedWalletId: input.alreadyCommittedWalletId,
    alreadyCommittedWalletAuthMethodId: input.alreadyCommittedWalletAuthMethodId,
    replacementCredentialIds: input.replacementCredentialIds,
    verifyRequest: null,
    alreadyCommittedBeforeSuccess: input.alreadyCommittedBeforeSuccess ?? 0,
    optionsCalls: 0,
    verifyCalls: 0,
    verifyRequests: [],
  };
  return yaoScenario;
}

function setupSyncAccountTest(): void {
  activeYaoScenario = null;
  activeFetchScenario = null;
  activePersistenceFixture = new SyncAccountPersistenceFixture();
  walletSessionAuthorizations.writeExactWithOperationCredential = async (input) => {
    activePersistenceFixture?.exactWalletSessionWrites.push(input);
  };
  walletSessionAuthorizations.upsertActiveWithCurveMerge = async (input) => {
    activePersistenceFixture?.legacyWalletSessionCurveWrites.push(input);
    return input.incoming;
  };
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
    expect(surface.authenticatedWalletIds).toEqual([DISCOVERED_WALLET_ID]);
    expect(surface.lastUserWalletIds).toEqual([]);
    expect(surface.clearWalletIds).toEqual([]);
    const persistence = requireActivePersistenceFixture();
    expect(persistence.appState.size).toBe(0);
    expect([...persistence.keyMaterial.values()].map((record) => record.keyKind)).toEqual([
      'router_ab_ed25519_yao_active_client_v1',
    ]);
    expect(persistence.exactWalletSessionWrites).toHaveLength(1);
    expect(persistence.exactWalletSessionWrites[0]).toMatchObject({
      record: {
        kind: 'active_wallet_session_v1',
        walletId: DISCOVERED_WALLET_ID,
        authorityRevocationEpoch: 0,
      },
      operationCredential: {
        kind: 'opaque_wallet_session_operation_credential_v1',
        walletSessionId: WALLET_SESSION_ID,
      },
    });
  });

  test('replaces one already-committed sync challenge with one fresh credential attempt', async () => {
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      alreadyCommittedBeforeSuccess: 1,
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), null);

    expect(result, JSON.stringify(result)).toMatchObject({ success: true });
    const fetchScenario = requireActiveFetchScenario();
    expect(fetchScenario.optionsCalls).toBe(2);
    expect(fetchScenario.verifyCalls).toBe(2);
    expect(fetchScenario.verifyRequests.map((request) => request.challengeId)).toEqual([
      'sync-challenge-id',
      'sync-challenge-id-replacement',
    ]);
    expect(surface.authenticationCredentialCalls).toBe(2);
    expect(surface.authenticationChallengeB64us).toEqual([
      'sync-challenge-b64u',
      'sync-challenge-b64u-replacement',
    ]);
    expect(surface.activatedMaterials).toHaveLength(1);
  });

  test('stops after a second already-committed sync response', async () => {
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      alreadyCommittedBeforeSuccess: 2,
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), null);

    expect(result).toEqual({
      success: false,
      error: 'sync-account/verify remained already committed after one replacement attempt',
    });
    const fetchScenario = requireActiveFetchScenario();
    expect(fetchScenario.optionsCalls).toBe(2);
    expect(fetchScenario.verifyCalls).toBe(2);
    expect(surface.authenticationCredentialCalls).toBe(2);
    expect(surface.activatedMaterials).toEqual([]);
  });

  test('rejects a noncanonical already-committed terminal identity before replacement', async () => {
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      alreadyCommittedBeforeSuccess: 1,
      alreadyCommittedWalletId: ` ${DISCOVERED_WALLET_ID}`,
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), null);

    expect(result).toEqual({ success: false, error: 'already_committed' });
    const fetchScenario = requireActiveFetchScenario();
    expect(fetchScenario.optionsCalls).toBe(1);
    expect(fetchScenario.verifyCalls).toBe(1);
    expect(surface.authenticationCredentialCalls).toBe(1);
    expect(surface.activatedMaterials).toEqual([]);
  });

  test('keeps one replacement bound to the committed auth method', async () => {
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      alreadyCommittedBeforeSuccess: 1,
      alreadyCommittedWalletAuthMethodId: 'wallet-auth-method:other',
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), null);

    expect(result).toEqual({
      success: false,
      error: 'recovered Yao capability does not match the verified wallet binding',
    });
    const fetchScenario = requireActiveFetchScenario();
    expect(fetchScenario.optionsCalls).toBe(2);
    expect(fetchScenario.verifyCalls).toBe(2);
    expect(surface.authenticationCredentialCalls).toBe(2);
    expect(surface.activatedMaterials).toEqual([]);
  });

  test('keeps one replacement bound to the committed passkey when discovery changes', async () => {
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      alreadyCommittedBeforeSuccess: 1,
      replacementCredentialIds: [OTHER_CREDENTIAL_ID],
    });
    const surface = new SyncAccountSigningSurfaceFixture();

    const result = await syncAccount(createContext(surface), null);

    expect(result).toEqual({
      success: false,
      error: 'replacement account-sync challenge changed the selected passkey',
    });
    const fetchScenario = requireActiveFetchScenario();
    expect(fetchScenario.optionsCalls).toBe(2);
    expect(fetchScenario.verifyCalls).toBe(1);
    expect(surface.authenticationCredentialCalls).toBe(1);
    expect(surface.activatedMaterials).toEqual([]);
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

    expect(result, JSON.stringify(result)).toMatchObject({ success: true });
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
    const persistence = requireActivePersistenceFixture();
    expect(persistence.exactWalletSessionWrites).toHaveLength(1);
    expect(persistence.exactWalletSessionWrites[0]?.operationCredential.token).toBe(
      OPERATION_CREDENTIAL_TOKEN,
    );
    expect(persistence.legacyWalletSessionCurveWrites).toEqual([]);
  });

  test('rejects a mixed-wallet ECDSA session whose authorization identity drifts', async () => {
    const ecdsa = mixedWalletEcdsaSyncFixture(DISCOVERED_WALLET_ID);
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      ecdsaSigners: ecdsa.signers,
      ecdsaSessionAuthorizationId: 'authorization:sync-account-drifted',
    });
    const surface = new SyncAccountSigningSurfaceFixture();
    surface.ecdsaRejoinPublicFacts = ecdsa.publicFacts;

    const result = await syncAccount(createContext(surface), null);

    expect(result).toEqual({
      success: false,
      error: 'sync-account ECDSA session changed the Wallet Session or custody identity',
    });
    expect(surface.ecdsaRejoinInputs).toEqual([]);
    expect(requireActivePersistenceFixture().exactWalletSessionWrites).toEqual([]);
  });

  test('rejects a mixed-wallet ECDSA session whose sign subject drifts from the exact session', async () => {
    const ecdsa = mixedWalletEcdsaSyncFixture(DISCOVERED_WALLET_ID);
    configureTestScenario({
      optionsWalletId: null,
      verifiedWalletId: DISCOVERED_WALLET_ID,
      ecdsaSigners: ecdsa.signers,
      ecdsaSessionMaterialActivation: MATERIAL_ACTIVATION,
    });
    const surface = new SyncAccountSigningSurfaceFixture();
    surface.ecdsaRejoinPublicFacts = ecdsa.publicFacts;

    const result = await syncAccount(createContext(surface), null);

    expect(result).toEqual({
      success: false,
      error: 'sync-account ECDSA session changed the Wallet Session or custody identity',
    });
    expect(surface.ecdsaRejoinInputs).toEqual([]);
    expect(requireActivePersistenceFixture().exactWalletSessionWrites).toEqual([]);
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
    expect(yaoScenario.disposeCalls).toBe(0);
    const persistence = requireActivePersistenceFixture();
    expect(persistence.profileSeeds).toEqual([]);
    expect(persistence.keyMaterial).toEqual(new Map());
    expect(persistence.exactWalletSessionWrites).toEqual([]);
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
