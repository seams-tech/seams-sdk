import { IndexedDBManager } from '@/core/indexedDB';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceManager } from '@/core/rpcClients/near/nonceManager';
import type { AccountId } from '@/core/types/accountIds';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SigningSessionStatus, ThemeName, TatchiConfigs } from '@/core/types/tatchi';
import type { SecureConfirmWorkerManager } from '../../secureConfirm';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { TouchIdPrompt } from '../../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManager } from '../../workers/signerWorkerManager';
import type { NearKeyDerivationDeps } from '../recovery/nearKeyDerivation';
import type { NearSigningApiDeps } from '../signing/nearSigning';
import type { PrivateKeyExportRecoveryDeps } from '../recovery/privateKeyExportRecovery';
import type { RegistrationAccountLifecycleDeps } from '../registration/registrationAccountLifecycle';
import type { RegistrationSessionDeps } from '../registration/registrationSession';
import type { SignerWorkerBridgeDeps } from '../signing/signerWorkerBridge';
import {
  generateSessionId as generateSessionIdValue,
  getOrCreateActiveSigningSessionId as getOrCreateActiveSigningSessionIdValue,
  getWarmSigningSessionStatus as getWarmSigningSessionStatusValue,
  resolveSigningSessionPolicy as resolveSigningSessionPolicyValue,
  type SigningSessionStateDeps,
} from '../signing/signingSessionState';
import type { TempoSigningDeps } from '../signing/tempoSigning';
import type { ThresholdEd25519LifecycleDeps } from '../thresholdLifecycle/thresholdEd25519Lifecycle';
import type { ThresholdSessionActivationDeps } from '../thresholdLifecycle/thresholdSessionActivation';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupDeps,
} from './workerResourceWarmup';
import type { UserPreferencesManager } from '../userPreferences';

export type OrchestrationSignTempoInput = {
  nearAccountId: string;
  request: TempoSigningRequest;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
};

export type ManagerConvenienceDeps = {
  signTempo: (args: OrchestrationSignTempoInput) => Promise<TempoSignedResult>;
  prewarmSignerWorkers: () => void;
  warmCriticalResources: (nearAccountId?: string) => Promise<void>;
  getWarmSigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
};

export type CreateOrchestrationDependencyBundleArgs = {
  tatchiPasskeyConfigs: TatchiConfigs;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  secureConfirmWorkerManager: SecureConfirmWorkerManager;
  signerWorkerManager: SignerWorkerManager;
  activeSigningSessionIds: Map<string, string>;
  getWorkerBaseOrigin: () => string;
  getTheme: () => ThemeName;
  signTempo: ManagerConvenienceDeps['signTempo'];
  signTransactionsWithActions: ThresholdEd25519LifecycleDeps['signTransactionsWithActions'];
  signNearWithIntent: NearSigningApiDeps['signNearWithIntent'];
  deriveNearKeypairFromCredentialViaWorker:
    PrivateKeyExportRecoveryDeps['deriveNearKeypairFromCredentialViaWorker'];
  extractCosePublicKey: RegistrationAccountLifecycleDeps['extractCosePublicKey'];
  initializeCurrentUser: WorkerResourceWarmupDeps['initializeCurrentUser'];
  persistThresholdEcdsaBootstrapChainAccount:
    ThresholdSessionActivationDeps['persistThresholdEcdsaBootstrapChainAccount'];
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
  signerWorkerBridgeDeps: SignerWorkerBridgeDeps;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getManagerConvenienceDeps: () => ManagerConvenienceDeps;
};

export function createOrchestrationDependencyBundle(
  args: CreateOrchestrationDependencyBundleArgs,
): OrchestrationDependencyBundle {
  const signingSessionStateDeps: SigningSessionStateDeps = {
    activeSigningSessionIds: args.activeSigningSessionIds,
    secureConfirmWorkerManager: args.secureConfirmWorkerManager,
    createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    signingSessionDefaults: args.tatchiPasskeyConfigs.signingSessionDefaults,
  };
  const getOrCreateActiveSigningSessionId = (nearAccountId: AccountId): string =>
    getOrCreateActiveSigningSessionIdValue(signingSessionStateDeps, nearAccountId);

  const nearSigningDeps: NearSigningApiDeps = {
    contractId: args.tatchiPasskeyConfigs.contractId,
    nearRpcUrl: args.tatchiPasskeyConfigs.nearRpcUrl,
    resolveSigningSessionPolicy: (policyArgs) =>
      resolveSigningSessionPolicyValue(signingSessionStateDeps, policyArgs),
    getOrCreateActiveSigningSessionId: getOrCreateActiveSigningSessionId,
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    signNearWithIntent: args.signNearWithIntent,
  };

  const getWorkerResourceWarmupDeps = (): WorkerResourceWarmupDeps => ({
    workerBaseOrigin: args.getWorkerBaseOrigin(),
    indexedDB: IndexedDBManager,
    nearClient: args.nearClient,
    nonceManager: args.nonceManager,
    preWarmWorkerPool: args.signerWorkerManager.preWarmWorkerPool.bind(args.signerWorkerManager),
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
      relayerUrl: args.tatchiPasskeyConfigs.relayer.url,
      contractId: args.tatchiPasskeyConfigs.contractId,
      nearRpcUrl: args.tatchiPasskeyConfigs.nearRpcUrl,
      signTransactionsWithActions: args.signTransactionsWithActions,
    },
    nearSigningDeps: nearSigningDeps,
    tempoSigningDeps: {
      indexedDB: IndexedDBManager,
      tatchiPasskeyConfigs: args.tatchiPasskeyConfigs,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
    },
    privateKeyExportRecoveryDeps: {
      indexedDB: IndexedDBManager,
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
      getTheme: args.getTheme,
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      deriveNearKeypairFromCredentialViaWorker:
        args.deriveNearKeypairFromCredentialViaWorker,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
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
      contractId: args.tatchiPasskeyConfigs.contractId,
      nearRpcUrl: args.tatchiPasskeyConfigs.nearRpcUrl,
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
      touchIdPrompt: args.touchIdPrompt,
    },
    signingSessionStateDeps: signingSessionStateDeps,
    thresholdSessionActivationDeps: {
      indexedDB: IndexedDBManager,
      touchIdPrompt: args.touchIdPrompt,
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      getOrCreateActiveSigningSessionId: getOrCreateActiveSigningSessionId,
      defaultRelayerUrl: args.tatchiPasskeyConfigs.relayer?.url || '',
      persistThresholdEcdsaBootstrapChainAccount:
        args.persistThresholdEcdsaBootstrapChainAccount,
    },
    signerWorkerBridgeDeps: {
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
    },
    getWorkerResourceWarmupDeps: getWorkerResourceWarmupDeps,
    getManagerConvenienceDeps: (): ManagerConvenienceDeps => ({
      signTempo: args.signTempo,
      prewarmSignerWorkers: () =>
        prewarmSignerWorkersValue(getWorkerResourceWarmupDeps()),
      warmCriticalResources: (nearAccountId?: string) =>
        warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), nearAccountId),
      getWarmSigningSessionStatus: (nearAccountId: AccountId | string) =>
        getWarmSigningSessionStatusValue(signingSessionStateDeps, nearAccountId),
    }),
  };
}
