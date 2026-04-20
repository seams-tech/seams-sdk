import { IndexedDBManager } from '@/core/indexedDB';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceManager } from '@/core/rpcClients/near/nonceManager';
import type { EvmNonceManager } from '@/core/rpcClients/evm/nonceManager';
import type { AccountId } from '@/core/types/accountIds';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SigningSessionStatus, ThemeName, TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { TouchConfirmRuntimeBridgePort, WarmSessionStatusResult } from '../touchConfirm/types';
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
import { generateSessionId as generateSessionIdValue } from '../api/session/signingSessionState';
import type { SigningSessionSealedStoreRecord } from '../api/session/signingSessionSealedStore';
import type { TempoSigningDeps } from '../api/tempoSigning';
import type { ThresholdEd25519LifecycleDeps } from '../api/thresholdLifecycle/thresholdEd25519Lifecycle';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type {
  BootstrapEcdsaSessionArgs,
  ThresholdSessionActivationDeps,
} from '../api/thresholdLifecycle/thresholdSessionActivation';
import type { NearSigningKeyOps } from '../interfaces/nearKeyOps';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupDeps,
} from './workerResourceWarmup';
import type { UserPreferencesManager } from '../api/userPreferences';
import { prewarmTxConfirmerUi } from '../touchConfirm/ui/confirm-ui';
import {
  createWarmSessionManager,
  type ProvisionWarmEd25519CapabilityArgs,
  type ProvisionWarmEd25519CapabilityResult,
} from '../session/WarmSessionManager';

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
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
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
  getThresholdEcdsaSessionRecordForSigning: (args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
  }) => ThresholdEcdsaSessionRecord;
  requestEmailOtpChallengeForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: 'near' | 'tempo' | 'evm';
    operation?: 'transaction_sign' | 'export_key';
    appSessionJwt?: string;
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
    operation?: 'transaction_sign' | 'export_key';
  }) => Promise<{ sessionId: string }>;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
    challengeId: string;
    otpCode: string;
    record: ThresholdEcdsaSessionRecord;
    operation?: 'transaction_sign' | 'export_key';
    appSessionJwt?: string;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?: (args: {
    sealedRecord: SigningSessionSealedStoreRecord;
    ecdsaRecord: ThresholdEcdsaSessionRecord;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    remainingUses: number;
    expiresAtMs: number;
  } | null>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
  }) => void;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId?: string;
  }) => void;
  clearThresholdEcdsaSessionRecordForLane: (args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
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

export type OrchestrationDependencyBundle = {
  indexedDB: UnifiedIndexedDBManager;
  thresholdEd25519LifecycleDeps: ThresholdEd25519LifecycleDeps;
  nearSigningDeps: NearSigningApiDeps;
  tempoSigningDeps: TempoSigningDeps;
  privateKeyExportRecoveryDeps: PrivateKeyExportRecoveryDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
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
  const getOrCreateActiveThresholdEcdsaSessionId = (
    _nearAccountId: AccountId,
    chain: 'tempo' | 'evm',
  ): string =>
    generateSessionIdValue(chain === 'tempo' ? 'threshold-ecdsa-tempo' : 'threshold-ecdsa-evm');

  const nearSigningDeps: NearSigningApiDeps = {
    nearRpcUrl,
    resolveThresholdEd25519SessionId: (nearAccountId: AccountId): string | null => {
      try {
        const record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
        const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
        return thresholdSessionId || null;
      } catch {
        return null;
      }
    },
    createSigningSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    requestEmailOtpChallengeForSigning: ({ nearAccountId, chain, operation, appSessionJwt }) =>
      args.requestEmailOtpChallengeForSigning?.({
        nearAccountId,
        chain,
        ...(operation ? { operation } : {}),
        ...(appSessionJwt ? { appSessionJwt } : {}),
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    isEmailOtpEd25519WarmupPending: ({ nearAccountId }) =>
      args.isEmailOtpEd25519WarmupPending?.({ nearAccountId }) === true,
    waitForPendingEmailOtpEd25519Warmup: ({ nearAccountId }) =>
      args.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId }) || Promise.resolve(false),
    loginWithEmailOtpEd25519CapabilityForSigning: ({
      nearAccountId,
      challengeId,
      otpCode,
      record,
      operation,
    }) =>
      args.loginWithEmailOtpEd25519CapabilityForSigning?.({
        nearAccountId,
        challengeId,
        otpCode,
        record,
        operation,
      }) || Promise.reject(new Error('Email OTP Ed25519 signing bootstrap is not configured')),
    reconnectPasskeyEd25519CapabilityForSigning: async ({
      nearAccountId,
      record,
      usesNeeded,
    }) => {
      const provisioned = await args.provisionThresholdEd25519Session({
        nearAccountId,
        relayerUrl: record.relayerUrl,
        relayerKeyId: record.relayerKeyId,
        ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
        participantIds: record.participantIds,
        sessionKind: record.thresholdSessionKind,
        remainingUses: Math.max(1, Math.floor(Number(usesNeeded) || 1) + 1),
      });
      if (!provisioned.ok || !provisioned.sessionId) {
        throw new Error(
          provisioned.message || provisioned.code || 'Passkey Ed25519 signing session reconnect failed',
        );
      }
      return { sessionId: provisioned.sessionId };
    },
    markThresholdEd25519EmailOtpSessionConsumedForAccount: ({
      nearAccountId,
      thresholdSessionId,
    }) =>
      args.markThresholdEd25519EmailOtpSessionConsumedForAccount?.({
        nearAccountId,
        thresholdSessionId,
      }),
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
    getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
      args.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
    rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: (restoreArgs) =>
      args.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?.(restoreArgs) ||
      Promise.reject(new Error('Email OTP sealed refresh restore is not configured')),
    clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
      args.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
    withThresholdEd25519CommitQueue: (queueArgs) => args.withThresholdEd25519CommitQueue(queueArgs),
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
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        args.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
      requestEmailOtpChallengeForSigning: ({ nearAccountId, chain, operation, appSessionJwt }) =>
        args.requestEmailOtpChallengeForSigning?.({
          nearAccountId,
          chain,
          ...(operation ? { operation } : {}),
          ...(appSessionJwt ? { appSessionJwt } : {}),
        }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
      loginWithEmailOtpEcdsaCapabilityForSigning: ({
        nearAccountId,
        chain,
        challengeId,
        otpCode,
        record,
        operation,
        appSessionJwt,
      }) =>
        args.loginWithEmailOtpEcdsaCapabilityForSigning?.({
          nearAccountId,
          chain,
          challengeId,
          otpCode,
          record,
          operation,
          ...(appSessionJwt ? { appSessionJwt } : {}),
        }) || Promise.reject(new Error('Email OTP signing bootstrap is not configured')),
      rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: (restoreArgs) =>
        args.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?.(restoreArgs) ||
        Promise.reject(new Error('Email OTP sealed refresh restore is not configured')),
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: ({ nearAccountId, chain }) =>
        args.markThresholdEcdsaEmailOtpSessionConsumedForAccount?.({ nearAccountId, chain }),
      getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        args.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      provisionThresholdEcdsaSession: (provisionArgs) =>
        args.provisionThresholdEcdsaSession(provisionArgs),
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
    thresholdSessionActivationDeps: {
      indexedDB: IndexedDBManager,
      touchIdPrompt: args.touchIdPrompt,
      touchConfirm: args.touchConfirm,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      getOrCreateActiveThresholdEcdsaSessionId: (nearAccountId, chain) =>
        getOrCreateActiveThresholdEcdsaSessionId(nearAccountId, chain),
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
        createWarmSessionManager({
          touchConfirm: args.touchConfirm,
        }).getEd25519SigningSessionStatus(nearAccountId),
    }),
  };
}
