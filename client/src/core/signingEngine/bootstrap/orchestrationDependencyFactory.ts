import { IndexedDBManager } from '@/core/indexedDB';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceManager } from '@/core/rpcClients/near/nonceManager';
import type { EvmNonceManager } from '@/core/rpcClients/evm/nonceManager';
import type { AccountId } from '@/core/types/accountIds';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SigningSessionStatus, ThemeName, TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { TouchConfirmRuntimeBridgePort } from '../touchConfirm/types';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';
import type { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManager } from '../workerManager';
import type { NearSigningApiDeps } from '../api/nearSigning';
import type { PrivateKeyExportRecoveryDeps } from '../api/recovery/privateKeyExportRecovery';
import type { RegistrationAccountLifecycleDeps } from '../api/registration/registrationAccountLifecycle';
import type { RegistrationSessionDeps } from '../api/registration/registrationSession';
import {
  generateSessionId as generateSessionIdValue,
  getOrCreateActiveSigningSessionIdForKind as getOrCreateActiveSigningSessionIdForKindValue,
  getWarmSigningSessionStatusForKind as getWarmSigningSessionStatusForKindValue,
  setActiveSigningSessionIdForKind as setActiveSigningSessionIdForKindValue,
  type ActiveSigningSessionKind,
  type SigningSessionStateDeps,
} from '../api/session/signingSessionState';
import type { TempoSigningDeps } from '../api/tempoSigning';
import type { ThresholdEd25519LifecycleDeps } from '../api/thresholdLifecycle/thresholdEd25519Lifecycle';
import { getStoredThresholdEd25519SessionRecordForAccount } from '../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdSessionActivationDeps } from '../api/thresholdLifecycle/thresholdSessionActivation';
import type { NearSigningKeyOps } from '../interfaces/nearKeyOps';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupDeps,
} from './workerResourceWarmup';
import type { UserPreferencesManager } from '../api/userPreferences';
import { prewarmTxConfirmerUi } from '../touchConfirm/ui/confirm-ui';

export type OrchestrationSignTempoInput = {
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type ManagerConvenienceDeps = {
  signTempo: (args: OrchestrationSignTempoInput) => Promise<TempoSignedResult | EvmSignedResult>;
  prewarmSignerWorkers: () => void;
  warmCriticalResources: (nearAccountId?: string) => Promise<void>;
  getWarmThresholdEd25519SessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
};

export type CreateOrchestrationDependencyBundleArgs = {
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  evmNonceManager: EvmNonceManager;
  touchConfirm: TouchConfirmRuntimeBridgePort;
  signerWorkerManager: SignerWorkerManager;
  getWorkerBaseOrigin: () => string;
  getTheme: () => ThemeName;
  signTempo: ManagerConvenienceDeps['signTempo'];
  extractCosePublicKey: RegistrationAccountLifecycleDeps['extractCosePublicKey'];
  initializeCurrentUser: WorkerResourceWarmupDeps['initializeCurrentUser'];
  persistThresholdEcdsaBootstrapChainAccount: ThresholdSessionActivationDeps['persistThresholdEcdsaBootstrapChainAccount'];
  upsertThresholdEcdsaSessionFromBootstrap: ThresholdSessionActivationDeps['upsertThresholdEcdsaSessionFromBootstrap'];
  getThresholdEcdsaKeyRefForSigning: (args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
  }) => ThresholdEcdsaSecp256k1KeyRef;
  bootstrapThresholdEcdsaSession: (args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
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

export type OrchestrationDependencyBundle = {
  indexedDB: UnifiedIndexedDBManager;
  thresholdEd25519LifecycleDeps: ThresholdEd25519LifecycleDeps;
  nearSigningDeps: NearSigningApiDeps;
  tempoSigningDeps: TempoSigningDeps;
  privateKeyExportRecoveryDeps: PrivateKeyExportRecoveryDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
  signingSessionStateDeps: SigningSessionStateDeps;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
  nearKeyOpsDeps: NearKeyOpsDeps;
  resolveCanonicalThresholdEcdsaSessionIdForChain: (
    nearAccountId: AccountId | string,
    chain: 'tempo' | 'evm',
  ) => string | null;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getManagerConvenienceDeps: () => ManagerConvenienceDeps;
};

export function createOrchestrationDependencyBundle(
  args: CreateOrchestrationDependencyBundleArgs,
): OrchestrationDependencyBundle {
  const nearRpcUrl = resolvePrimaryNearRpcUrl(args.tatchiPasskeyConfigs.network.chains);
  const activeSigningSessionIds = new Map<string, string>();
  const resolveCanonicalThresholdEcdsaSessionIdForChain = (
    nearAccountId: AccountId | string,
    chain: 'tempo' | 'evm',
  ): string | null => {
    try {
      const keyRef = args.getThresholdEcdsaKeyRefForSigning({ nearAccountId, chain });
      const thresholdSessionId = String(keyRef.thresholdSessionId || '').trim();
      return thresholdSessionId || null;
    } catch {
      return null;
    }
  };
  const resolveCanonicalSigningSessionIdForKind = ({
    nearAccountId,
    signerKind,
  }: {
    nearAccountId: AccountId | string;
    signerKind: ActiveSigningSessionKind;
  }): string | null => {
    if (signerKind === 'threshold-ed25519') {
      try {
        const ed25519Record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
        const thresholdSessionId = String(ed25519Record?.thresholdSessionId || '').trim();
        if (thresholdSessionId) return thresholdSessionId;
      } catch {}
      return null;
    }
    return resolveCanonicalThresholdEcdsaSessionIdForChain(
      nearAccountId,
      signerKind === 'threshold-ecdsa-tempo' ? 'tempo' : 'evm',
    );
  };
  const signingSessionStateDeps: SigningSessionStateDeps = {
    activeSigningSessionIds,
    touchConfirm: args.touchConfirm,
    createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    signingSessionDefaults: args.tatchiPasskeyConfigs.signing.sessionDefaults,
    resolveCanonicalSigningSessionIdForKind,
  };
  const getOrCreateActiveThresholdEd25519SessionId = (nearAccountId: AccountId): string =>
    getOrCreateActiveSigningSessionIdForKindValue(signingSessionStateDeps, {
      nearAccountId,
      signerKind: 'threshold-ed25519',
    });
  const getOrCreateActiveThresholdEcdsaSessionId = (
    nearAccountId: AccountId,
    chain: 'tempo' | 'evm',
  ): string =>
    getOrCreateActiveSigningSessionIdForKindValue(signingSessionStateDeps, {
      nearAccountId,
      signerKind: chain === 'tempo' ? 'threshold-ecdsa-tempo' : 'threshold-ecdsa-evm',
    });

  const nearSigningDeps: NearSigningApiDeps = {
    nearRpcUrl,
    resolveCanonicalThresholdEd25519SessionId: (nearAccountId: AccountId): string | null => {
      try {
        const record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
        const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
        return thresholdSessionId || null;
      } catch {
        return null;
      }
    },
    getOrCreateActiveThresholdEd25519SessionId,
    createSigningSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    withThresholdEd25519CommitQueue: (queueArgs) =>
      args.withThresholdEd25519CommitQueue(queueArgs),
  };

  const getWorkerResourceWarmupDeps = (): WorkerResourceWarmupDeps => ({
    workerBaseOrigin: args.getWorkerBaseOrigin(),
    indexedDB: IndexedDBManager,
    nearClient: args.nearClient,
    nonceManager: args.nonceManager,
    prewarmWorkers: args.signerWorkerManager.prewarmWorkers.bind(args.signerWorkerManager),
    initializeTouchConfirm: args.touchConfirm.initialize.bind(args.touchConfirm),
    prewarmTouchConfirmUi: prewarmTxConfirmerUi,
    initializeCurrentUser: args.initializeCurrentUser,
  });

  return {
    indexedDB: IndexedDBManager,
    thresholdEd25519LifecycleDeps: {
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    },
    nearSigningDeps: nearSigningDeps,
    tempoSigningDeps: {
      indexedDB: IndexedDBManager,
      tatchiPasskeyConfigs: args.tatchiPasskeyConfigs,
      evmNonceManager: args.evmNonceManager,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      getThresholdEcdsaKeyRefForSigning: ({ nearAccountId, chain }) =>
        args.getThresholdEcdsaKeyRefForSigning({ nearAccountId, chain }),
      bootstrapThresholdEcdsaSession: ({ nearAccountId, chain }) =>
        args.bootstrapThresholdEcdsaSession({ nearAccountId, chain }),
      withThresholdEcdsaCommitQueue: (queueArgs) => args.withThresholdEcdsaCommitQueue(queueArgs),
      touchConfirm: args.touchConfirm,
    },
    privateKeyExportRecoveryDeps: {
      indexedDB: IndexedDBManager,
      relayerUrl: args.tatchiPasskeyConfigs.network.relayer.url,
      getRpId: () => args.touchIdPrompt.getRpId(),
      requestExportPrivateKeysWithUi: (payload) =>
        args.signerWorkerManager.requestExportPrivateKeysWithUi(payload),
      getTheme: args.getTheme,
    },
    registrationAccountLifecycleDeps: {
      indexedDB: IndexedDBManager,
      userPreferencesManager: args.userPreferencesManager,
      nonceManager: args.nonceManager,
      extractCosePublicKey: args.extractCosePublicKey,
    },
    registrationSessionDeps: {
      nearRpcUrl,
      touchConfirm: args.touchConfirm,
      touchIdPrompt: args.touchIdPrompt,
    },
    signingSessionStateDeps: signingSessionStateDeps,
    thresholdSessionActivationDeps: {
      indexedDB: IndexedDBManager,
      touchIdPrompt: args.touchIdPrompt,
      touchConfirm: args.touchConfirm,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      getOrCreateActiveThresholdEd25519SessionId,
      setActiveThresholdEd25519SessionId: (nearAccountId, sessionId) =>
        setActiveSigningSessionIdForKindValue(signingSessionStateDeps, {
          nearAccountId,
          signerKind: 'threshold-ed25519',
          sessionId,
        }),
      getOrCreateActiveThresholdEcdsaSessionId: (nearAccountId, chain) =>
        getOrCreateActiveThresholdEcdsaSessionId(nearAccountId, chain),
      setActiveThresholdEcdsaSessionId: (nearAccountId, chain, sessionId) =>
        setActiveSigningSessionIdForKindValue(signingSessionStateDeps, {
          nearAccountId,
          signerKind: chain === 'tempo' ? 'threshold-ecdsa-tempo' : 'threshold-ecdsa-evm',
          sessionId,
        }),
      defaultRelayerUrl: args.tatchiPasskeyConfigs.network.relayer?.url || '',
      persistThresholdEcdsaBootstrapChainAccount: args.persistThresholdEcdsaBootstrapChainAccount,
      upsertThresholdEcdsaSessionFromBootstrap: args.upsertThresholdEcdsaSessionFromBootstrap,
    },
    nearKeyOpsDeps: {
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
    },
    resolveCanonicalThresholdEcdsaSessionIdForChain,
    getWorkerResourceWarmupDeps: getWorkerResourceWarmupDeps,
    getManagerConvenienceDeps: (): ManagerConvenienceDeps => ({
      signTempo: args.signTempo,
      prewarmSignerWorkers: () => prewarmSignerWorkersValue(getWorkerResourceWarmupDeps()),
      warmCriticalResources: (nearAccountId?: string) =>
        warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), nearAccountId),
      getWarmThresholdEd25519SessionStatus: (nearAccountId: AccountId | string) =>
        getWarmSigningSessionStatusForKindValue(signingSessionStateDeps, {
          nearAccountId,
          signerKind: 'threshold-ed25519',
        }),
    }),
  };
}
