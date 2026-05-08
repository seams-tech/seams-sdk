import { IndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly, SigningSessionStatus, ThemeName } from '@/core/types/seams';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import type {
  EvmFamilySigningDeps,
  NearSigningApiDeps,
  PrivateKeyExportRecoveryDeps,
  RegistrationAccountLifecycleDeps,
  RegistrationSessionDeps,
} from '../../interfaces/operationDeps';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { NonceCoordinator } from '../../nonce/NonceCoordinator';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
} from '../../session/availability/availableSigningLanes';
import {
  THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES,
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
  ThresholdEcdsaKeyRefLookupResult,
} from '../../session/persistence/records';
import type { RestorePersistedSessionForSigningInput } from '../../session/restore/restoreCoordinator';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { SigningSessionBudgetStatusAuth } from '../../session/budget/budget';
import {
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaSessionRecordKey,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserPreferencesManager } from '../../session/userPreferences';
import { generateSessionId as generateSessionIdValue } from '../../session/warmSigning/prfCache';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../../session/warmSigning/types';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEd25519LifecycleDeps } from '../../threshold/ed25519/hssLifecycle';
import type {
  BootstrapEcdsaSessionArgs,
  ThresholdSessionActivationDeps,
} from '../../session/warmSigning/ecdsaBootstrap';
import type { UiConfirmRuntimeBridgePort, WarmSessionStatusResult } from '../../uiConfirm/types';
import { prewarmTxConfirmerUi } from '../../uiConfirm/ui/confirm-ui';
import type { SignerWorkerManager } from '../../workerManager/SignerWorkerManager';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupDeps,
} from '../warmup';

export type SignTempoPortInput = {
  nearAccountId: string;
  subjectId: WalletSubjectId;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type SigningEngineConveniencePorts = {
  signTempo: (args: SignTempoPortInput) => Promise<TempoSignedResult | EvmSignedResult>;
  prewarmSignerWorkers: () => void;
  warmCriticalResources: (nearAccountId?: string) => Promise<void>;
  getWarmThresholdEd25519SessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
};

export type CreateSigningEnginePortsArgs = {
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  touchConfirm: UiConfirmRuntimeBridgePort;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  consumeEmailOtpWarmSessionUses?: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  getWalletSigningBudgetStatus: (args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }) => Promise<SigningSessionStatus | null>;
  signerWorkerManager: SignerWorkerManager;
  getWorkerBaseOrigin: () => string;
  getTheme: () => ThemeName;
  signTempo: SigningEngineConveniencePorts['signTempo'];
  extractCosePublicKey: (attestationObjectBase64url: string) => Promise<Uint8Array>;
  initializeCurrentUser: WorkerResourceWarmupDeps['initializeCurrentUser'];
  persistThresholdEcdsaBootstrapChainAccount: ThresholdSessionActivationDeps['persistThresholdEcdsaBootstrapChainAccount'];
  upsertThresholdEcdsaSessionFromBootstrap: ThresholdSessionActivationDeps['upsertThresholdEcdsaSessionFromBootstrap'];
  listThresholdEcdsaKeyRefsForTarget: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaKeyRefLookupResult[];
  listThresholdEcdsaSessionRecordsForTarget: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord[];
  listThresholdEcdsaSessionRecordsForSubject: (args: {
    subjectId: WalletSubjectId;
  }) => ThresholdEcdsaSessionRecord[];
  getThresholdEcdsaSessionRecordByKey: (
    identity: ThresholdEcdsaSessionRecordKey,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEcdsaKeyRefByKey: (
    identity: ThresholdEcdsaSessionRecordKey,
  ) => ThresholdEcdsaKeyRefLookupResult | null;
  getEmailOtpThresholdEcdsaKeyRefForSigning: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => ThresholdEcdsaSecp256k1KeyRef;
  getEmailOtpThresholdEcdsaSessionRecordForSigning: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => ThresholdEcdsaSessionRecord;
  getPasskeyThresholdEcdsaKeyRefForSigning: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  }) => ThresholdEcdsaSecp256k1KeyRef;
  getPasskeyThresholdEcdsaSessionRecordForSigning: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  }) => ThresholdEcdsaSessionRecord;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    nearAccountId: AccountId | string;
    chain: 'near' | 'tempo' | 'evm';
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }>;
  isEmailOtpEd25519WarmupPending?: (args: { nearAccountId: AccountId | string }) => boolean;
  waitForPendingEmailOtpEd25519Warmup?: (args: {
    nearAccountId: AccountId | string;
  }) => Promise<boolean>;
  loginWithEmailOtpEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    remainingUses?: number;
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ sessionId: string }>;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  restorePersistedSessionForSigning: (
    args: RestorePersistedSessionForSigningInput,
  ) => Promise<unknown>;
  readAvailableSigningLanesForSigning: (
    args: ReadAvailableSigningLanesForSigningInput,
  ) => Promise<AvailableSigningLanes>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  }) => void;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId?: string;
    uses?: number;
  }) => void;
  clearThresholdEcdsaSessionRecordForLane: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => void;
  provisionThresholdEcdsaSession: (
    args: BootstrapEcdsaSessionArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  withThresholdEcdsaCommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
  withThresholdEd25519CommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
};

export type NearKeyOpsDeps = {
  signingKeyOps: Pick<
    NearSigningKeyOps,
    'extractCosePublicKey' | 'signTransactionWithKeyPair' | 'generateEphemeralNearKeypair'
  >;
};

export type SigningEnginePorts = {
  indexedDB: typeof IndexedDBManager;
  thresholdEd25519LifecycleDeps: ThresholdEd25519LifecycleDeps;
  nearSigningDeps: NearSigningApiDeps;
  tempoSigningDeps: EvmFamilySigningDeps;
  privateKeyExportRecoveryDeps: PrivateKeyExportRecoveryDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
  nearKeyOpsDeps: NearKeyOpsDeps;
  resolveCanonicalThresholdEcdsaSessionIdForChain: (
    nearAccountId: AccountId | string,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string | null;
  signingSessionCoordinator: SigningSessionCoordinator;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getManagerConveniencePorts: () => SigningEngineConveniencePorts;
};

export function resolveNearRpcUrl(args: CreateSigningEnginePortsArgs): string {
  return resolvePrimaryNearRpcUrl(args.seamsPasskeyConfigs.network.chains);
}

export function createResolveCanonicalThresholdEcdsaSessionIdForChain(
  args: CreateSigningEnginePortsArgs,
): SigningEnginePorts['resolveCanonicalThresholdEcdsaSessionIdForChain'] {
  return (nearAccountId, chainTarget) => {
    for (const source of THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES) {
      try {
        const keyRefs = args.listThresholdEcdsaKeyRefsForTarget({
          subjectId: toWalletSubjectId(nearAccountId),
          chainTarget,
          source,
        });
        if (keyRefs.length !== 1) continue;
        const keyRef = keyRefs[0]!.keyRef;
        const thresholdSessionId = String(keyRef.thresholdSessionId || '').trim();
        if (thresholdSessionId) return thresholdSessionId;
      } catch {}
    }
    return null;
  };
}

export function createGetOrCreateActiveThresholdEcdsaSessionId(): (
  nearAccountId: AccountId,
  chainTarget: ThresholdEcdsaChainTarget,
) => string {
  return (_nearAccountId, chainTarget) =>
    generateSessionIdValue(
      chainTarget.kind === 'tempo' ? 'threshold-ecdsa-tempo' : 'threshold-ecdsa-evm',
    );
}

export function createWorkerResourceWarmupDepsFactory(
  args: CreateSigningEnginePortsArgs,
): () => WorkerResourceWarmupDeps {
  return () => ({
    workerBaseOrigin: args.getWorkerBaseOrigin(),
    indexedDB: IndexedDBManager,
    nearClient: args.nearClient,
    nonceCoordinator: args.nonceCoordinator,
    prewarmWorkers: args.signerWorkerManager.prewarmWorkers.bind(args.signerWorkerManager),
    initializeUiConfirm: args.touchConfirm.initialize.bind(args.touchConfirm),
    prewarmUiConfirmUi: prewarmTxConfirmerUi,
    initializeCurrentUser: args.initializeCurrentUser,
  });
}

export function createManagerConveniencePortsFactory(args: {
  createArgs: CreateSigningEnginePortsArgs;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  getWarmThresholdEd25519SessionStatus: SigningEngineConveniencePorts['getWarmThresholdEd25519SessionStatus'];
}): () => SigningEngineConveniencePorts {
  const { createArgs, getWorkerResourceWarmupDeps, getWarmThresholdEd25519SessionStatus } = args;
  return () => ({
    signTempo: createArgs.signTempo,
    prewarmSignerWorkers: () => prewarmSignerWorkersValue(getWorkerResourceWarmupDeps()),
    warmCriticalResources: (nearAccountId?: string) =>
      warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), nearAccountId),
    getWarmThresholdEd25519SessionStatus,
  });
}
