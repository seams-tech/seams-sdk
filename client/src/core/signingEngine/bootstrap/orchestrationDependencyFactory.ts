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
import type { NearKeyDerivationDeps } from '../api/recovery/nearKeyDerivation';
import type { NearSigningApiDeps } from '../api/nearSigning';
import type { PrivateKeyExportRecoveryDeps } from '../api/recovery/privateKeyExportRecovery';
import type { RegistrationAccountLifecycleDeps } from '../api/registration/registrationAccountLifecycle';
import type { RegistrationSessionDeps } from '../api/registration/registrationSession';
import {
  generateSessionId as generateSessionIdValue,
  getOrCreateActiveSigningSessionId as getOrCreateActiveSigningSessionIdValue,
  getWarmSigningSessionStatus as getWarmSigningSessionStatusValue,
  setActiveSigningSessionId as setActiveSigningSessionIdValue,
  type SigningSessionStateDeps,
} from '../api/session/signingSessionState';
import type { TempoSigningDeps } from '../api/tempoSigning';
import type { ThresholdEd25519LifecycleDeps } from '../api/thresholdLifecycle/thresholdEd25519Lifecycle';
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
  getWarmSigningSessionStatus: (
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
  signTransactionsWithActions: ThresholdEd25519LifecycleDeps['signTransactionsWithActions'];
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
  nearKeyDerivationDeps: NearKeyDerivationDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
  signingSessionStateDeps: SigningSessionStateDeps;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
  nearKeyOpsDeps: NearKeyOpsDeps;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getManagerConvenienceDeps: () => ManagerConvenienceDeps;
};

export function createOrchestrationDependencyBundle(
  args: CreateOrchestrationDependencyBundleArgs,
): OrchestrationDependencyBundle {
  const nearRpcUrl = resolvePrimaryNearRpcUrl(args.tatchiPasskeyConfigs.network.chains);
  const activeSigningSessionIds = new Map<string, string>();
  const resolveCanonicalSigningSessionId = (nearAccountId: AccountId | string): string | null => {
    const chains: Array<'tempo' | 'evm'> = ['tempo', 'evm'];
    for (const chain of chains) {
      try {
        const keyRef = args.getThresholdEcdsaKeyRefForSigning({ nearAccountId, chain });
        const thresholdSessionId = String(keyRef.thresholdSessionId || '').trim();
        if (thresholdSessionId) {
          return thresholdSessionId;
        }
      } catch {}
    }
    return null;
  };
  const signingSessionStateDeps: SigningSessionStateDeps = {
    activeSigningSessionIds,
    touchConfirm: args.touchConfirm,
    createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    signingSessionDefaults: args.tatchiPasskeyConfigs.signing.sessionDefaults,
    resolveCanonicalSigningSessionId,
  };
  const getOrCreateActiveSigningSessionId = (nearAccountId: AccountId): string =>
    getOrCreateActiveSigningSessionIdValue(signingSessionStateDeps, nearAccountId);

  const nearSigningDeps: NearSigningApiDeps = {
    nearRpcUrl,
    getOrCreateActiveSigningSessionId: getOrCreateActiveSigningSessionId,
    createSigningSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
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
      indexedDB: IndexedDBManager,
      touchIdPrompt: args.touchIdPrompt,
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      getSignerWorkerRequestOperation: () =>
        args.signerWorkerManager.getContext().requestWorkerOperation,
      createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
      nearClient: args.nearClient,
      nonceManager: args.nonceManager,
      relayerUrl: args.tatchiPasskeyConfigs.network.relayer.url,
      nearRpcUrl,
      signTransactionsWithActions: args.signTransactionsWithActions,
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
      requestExportPrivateKeysWithUi: (payload) =>
        args.signerWorkerManager.requestExportPrivateKeysWithUi(payload),
      getTheme: args.getTheme,
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    },
    nearKeyDerivationDeps: {
      createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
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
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      touchConfirm: args.touchConfirm,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      getOrCreateActiveSigningSessionId: getOrCreateActiveSigningSessionId,
      setActiveSigningSessionId: (nearAccountId, sessionId) =>
        setActiveSigningSessionIdValue(signingSessionStateDeps, nearAccountId, sessionId),
      defaultRelayerUrl: args.tatchiPasskeyConfigs.network.relayer?.url || '',
      persistThresholdEcdsaBootstrapChainAccount: args.persistThresholdEcdsaBootstrapChainAccount,
      upsertThresholdEcdsaSessionFromBootstrap: args.upsertThresholdEcdsaSessionFromBootstrap,
    },
    nearKeyOpsDeps: {
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
    },
    getWorkerResourceWarmupDeps: getWorkerResourceWarmupDeps,
    getManagerConvenienceDeps: (): ManagerConvenienceDeps => ({
      signTempo: args.signTempo,
      prewarmSignerWorkers: () => prewarmSignerWorkersValue(getWorkerResourceWarmupDeps()),
      warmCriticalResources: (nearAccountId?: string) =>
        warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), nearAccountId),
      getWarmSigningSessionStatus: (nearAccountId: AccountId | string) =>
        getWarmSigningSessionStatusValue(signingSessionStateDeps, nearAccountId),
    }),
  };
}
