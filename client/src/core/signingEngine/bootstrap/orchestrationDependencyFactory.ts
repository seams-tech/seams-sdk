import { IndexedDBManager } from '@/core/indexedDB';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type { AccountId } from '@/core/types/accountIds';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SigningSessionStatus, ThemeName, SeamsConfigsReadonly } from '@/core/types/seams';
import type { TouchConfirmRuntimeBridgePort, WarmSessionStatusResult } from '../touchConfirm/types';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManager } from '../workerManager';
import type { NearSigningApiDeps } from '../api/nearSigning';
import type { PrivateKeyExportRecoveryDeps } from '../api/recovery/privateKeyExportRecovery';
import type { RegistrationAccountLifecycleDeps } from '../api/registration/registrationAccountLifecycle';
import type { RegistrationSessionDeps } from '../api/registration/registrationSession';
import { generateSessionId as generateSessionIdValue } from '../api/session/signingSessionState';
import type { TempoSigningDeps } from '../api/tempoSigning';
import type { ThresholdEd25519LifecycleDeps } from '../api/thresholdLifecycle/thresholdEd25519Lifecycle';
import { resolveEvmFamilyTransactionAccountAuth } from '../api/evmFamily/accountAuth';
import {
  THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES,
  getStoredThresholdEd25519SessionRecordForAccount,
  type ConcreteThresholdEcdsaSessionRecord,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaKeyRefLookupResult,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreSource,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type {
  BootstrapEcdsaSessionArgs,
  ThresholdSessionActivationDeps,
} from '../api/thresholdLifecycle/thresholdSessionActivation';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';
import type { NearSigningKeyOps } from '../interfaces/nearKeyOps';
import type { EmailOtpAuthLane } from '../emailOtp/authLane';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupDeps,
} from './workerResourceWarmup';
import type { UserPreferencesManager } from '../api/userPreferences';
import { prewarmTxConfirmerUi } from '../touchConfirm/ui/confirm-ui';
import { createWarmSessionCapabilityReader } from '../session/warmSigning/capabilityReader';
import { createWarmSessionStatusReader } from '../session/warmSigning/statusReader';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../session/warmSigning/types';
import { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type { SigningSessionBudgetStatusAuth } from '../session/signingSession/budget';
import type {
  ThresholdEcdsaChainTarget,
  EcdsaLaneIdentity,
  WalletSubjectId,
} from '../session/signingSession/ecdsaChainTarget';
import { toWalletSubjectId } from '../session/signingSession/ecdsaChainTarget';
import type {
  ReadSigningSessionSnapshotForSigningInput,
  SigningSessionSnapshot,
} from '../session/snapshotReader';
import type { RestorePersistedSessionForSigningInput } from '../session/restoreCoordinator';

export type OrchestrationSignTempoInput = {
  nearAccountId: string;
  subjectId: WalletSubjectId;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
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
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: TouchConfirmRuntimeBridgePort;
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
  signTempo: ManagerConvenienceDeps['signTempo'];
  extractCosePublicKey: RegistrationAccountLifecycleDeps['extractCosePublicKey'];
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
  listConcreteThresholdEcdsaSessionRecordsForSubject: (args: {
    subjectId: WalletSubjectId;
  }) => ConcreteThresholdEcdsaSessionRecord[];
  getThresholdEcdsaSessionRecordByIdentity: (
    identity: EcdsaLaneIdentity,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEcdsaKeyRefByIdentity: (
    identity: EcdsaLaneIdentity,
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
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  restorePersistedSessionForSigning: (
    args: RestorePersistedSessionForSigningInput,
  ) => Promise<unknown>;
  readSigningSessionSnapshotForSigning: (
    args: ReadSigningSessionSnapshotForSigningInput,
  ) => Promise<SigningSessionSnapshot>;
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
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string | null;
  signingSessionCoordinator: SigningSessionCoordinator;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getManagerConvenienceDeps: () => ManagerConvenienceDeps;
};

export function createOrchestrationDependencyBundle(
  args: CreateOrchestrationDependencyBundleArgs,
): OrchestrationDependencyBundle {
  const nearRpcUrl = resolvePrimaryNearRpcUrl(args.seamsPasskeyConfigs.network.chains);
  const resolveCanonicalThresholdEcdsaSessionIdForChain = (
    nearAccountId: AccountId | string,
    chainTarget: ThresholdEcdsaChainTarget,
  ): string | null => {
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
  const getOrCreateActiveThresholdEcdsaSessionId = (
    _nearAccountId: AccountId,
    chainTarget: ThresholdEcdsaChainTarget,
  ): string =>
    generateSessionIdValue(
      chainTarget.kind === 'tempo' ? 'threshold-ecdsa-tempo' : 'threshold-ecdsa-evm',
    );
  const getEmailOtpWarmSessionStatus =
    args.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> => {
      if (typeof args.touchConfirm.getWarmSessionStatus === 'function') {
        return await args.touchConfirm.getWarmSessionStatus({ sessionId });
      }
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP warm-session status reader is unavailable',
      };
    });
  const signingSessionCoordinator = new SigningSessionCoordinator({
    getStatus: args.getWalletSigningBudgetStatus,
    touchConfirm: args.touchConfirm,
    listConcreteThresholdEcdsaSessionRecordsForSubject: (subjectArgs) =>
      args.listConcreteThresholdEcdsaSessionRecordsForSubject(subjectArgs),
    getEmailOtpWarmSessionStatus,
    consumeEmailOtpWarmSessionUses: args.consumeEmailOtpWarmSessionUses,
    clearThresholdEcdsaSessionRecordForLane: ({ subjectId, chainTarget, source }) =>
      args.clearThresholdEcdsaSessionRecordForLane({
        subjectId,
        chainTarget,
        ...(source ? { source } : {}),
      }),
    markThresholdEd25519EmailOtpSessionConsumedForAccount:
      args.markThresholdEd25519EmailOtpSessionConsumedForAccount,
  });

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
    requestEmailOtpTransactionSigningChallenge: ({ nearAccountId, chain, authLane }) =>
      args.requestEmailOtpTransactionSigningChallenge?.({
        nearAccountId,
        chain,
        ...(authLane ? { authLane } : {}),
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    resolveEmailOtpSigningSessionAuthLane: ({ thresholdSessionId, curve }) =>
      createWarmSessionCapabilityReader({
        touchConfirm: args.touchConfirm,
      }).resolveEmailOtpSigningSessionAuthLane({ thresholdSessionId, curve }),
    isEmailOtpEd25519WarmupPending: ({ nearAccountId }) =>
      args.isEmailOtpEd25519WarmupPending?.({ nearAccountId }) === true,
    waitForPendingEmailOtpEd25519Warmup: ({ nearAccountId }) =>
      args.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId }) || Promise.resolve(false),
    loginWithEmailOtpEd25519CapabilityForSigning: ({
      nearAccountId,
      challengeId,
      otpCode,
      record,
      remainingUses,
      authLane,
    }) =>
      args.loginWithEmailOtpEd25519CapabilityForSigning?.({
        nearAccountId,
        challengeId,
        otpCode,
        record,
        ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        ...(authLane ? { authLane } : {}),
      }) || Promise.reject(new Error('Email OTP Ed25519 signing bootstrap is not configured')),
    restorePersistedSessionForSigning: (restoreArgs) =>
      args.restorePersistedSessionForSigning(restoreArgs),
    readSigningSessionSnapshotForSigning: (snapshotArgs) =>
      args.readSigningSessionSnapshotForSigning(snapshotArgs),
    resolveAccountAuthMethodForSigning: async ({ nearAccountId }) => {
      const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
        deps: { indexedDB: IndexedDBManager },
        nearAccountId: String(nearAccountId),
        senderSignatureAlgorithm: 'secp256k1',
      });
      return accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
    },
    reconnectPasskeyEd25519CapabilityForSigning: async ({
      nearAccountId,
      record,
      localPrfCredential,
      remainingUses,
      sessionId,
      walletSigningSessionId,
    }) => {
      const reconnectRemainingUses = Math.max(1, Math.floor(Number(remainingUses) || 1));
      const provisioned = await args.provisionThresholdEd25519Session({
        nearAccountId,
        relayerUrl: record.relayerUrl,
        relayerKeyId: record.relayerKeyId,
        // The transaction confirmer already collected a WebAuthn assertion for the planned
        // session policy. Dropping it here regressed passkey reauth into a second TouchID prompt.
        localPrfCredential,
        ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
        participantIds: record.participantIds,
        sessionKind: record.thresholdSessionKind,
        ...(sessionId ? { sessionId } : {}),
        ...(walletSigningSessionId || record.walletSigningSessionId
          ? { walletSigningSessionId: walletSigningSessionId || record.walletSigningSessionId }
          : {}),
        remainingUses: reconnectRemainingUses,
      });
      if (!provisioned.ok || !provisioned.sessionId) {
        throw new Error(
          provisioned.message ||
            provisioned.code ||
            'Passkey Ed25519 signing session reconnect failed',
        );
      }
      const refreshedRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
      return {
        sessionId: provisioned.sessionId,
        ...(refreshedRecord ? { record: refreshedRecord } : {}),
      };
    },
    signingSessionCoordinator,
    getWarmThresholdEd25519SessionStatusForSession: ({ nearAccountId, thresholdSessionId }) =>
      createWarmSessionStatusReader({
        touchConfirm: args.touchConfirm,
        getEmailOtpWarmSessionStatus,
      }).getEd25519SigningSessionStatusForSession({ nearAccountId, thresholdSessionId }),
    withThresholdEd25519CommitQueue: (queueArgs) => args.withThresholdEd25519CommitQueue(queueArgs),
  };

  const getWorkerResourceWarmupDeps = (): WorkerResourceWarmupDeps => ({
    workerBaseOrigin: args.getWorkerBaseOrigin(),
    indexedDB: IndexedDBManager,
    nearClient: args.nearClient,
    nonceCoordinator: args.nonceCoordinator,
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
      seamsPasskeyConfigs: args.seamsPasskeyConfigs,
      nonceCoordinator: args.nonceCoordinator,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      getEmailOtpThresholdEcdsaKeyRefForSigning: ({ subjectId, chainTarget }) =>
        args.getEmailOtpThresholdEcdsaKeyRefForSigning({
          subjectId,
          chainTarget,
        }),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: ({ subjectId, chainTarget }) =>
        args.getEmailOtpThresholdEcdsaSessionRecordForSigning({
          subjectId,
          chainTarget,
        }),
      getPasskeyThresholdEcdsaKeyRefForSigning: ({ subjectId, chainTarget, source }) =>
        args.getPasskeyThresholdEcdsaKeyRefForSigning({
          subjectId,
          chainTarget,
          source,
        }),
      getPasskeyThresholdEcdsaSessionRecordForSigning: ({ subjectId, chainTarget, source }) =>
        args.getPasskeyThresholdEcdsaSessionRecordForSigning({
          subjectId,
          chainTarget,
          source,
        }),
      listThresholdEcdsaSessionRecordsForSigning: ({ subjectId, chainTarget, source }) =>
        args.listThresholdEcdsaSessionRecordsForTarget({
          subjectId,
          chainTarget,
          ...(source ? { source } : {}),
        }),
      listThresholdEcdsaKeyRefsForSigning: ({ subjectId, chainTarget, source }) =>
        args.listThresholdEcdsaKeyRefsForTarget({
          subjectId,
          chainTarget,
          ...(source ? { source } : {}),
        }),
      getThresholdEcdsaSessionRecordByIdentity: (identity) =>
        args.getThresholdEcdsaSessionRecordByIdentity(identity),
      getThresholdEcdsaKeyRefByIdentity: (identity) =>
        args.getThresholdEcdsaKeyRefByIdentity(identity),
      requestEmailOtpTransactionSigningChallenge: ({ nearAccountId, chain, authLane }) =>
        args.requestEmailOtpTransactionSigningChallenge?.({
          nearAccountId,
          chain,
          ...(authLane ? { authLane } : {}),
        }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
      resolveEmailOtpSigningSessionAuthLane: ({ thresholdSessionId, curve }) =>
        createWarmSessionCapabilityReader({
          touchConfirm: args.touchConfirm,
        }).resolveEmailOtpSigningSessionAuthLane({ thresholdSessionId, curve }),
      loginWithEmailOtpEcdsaCapabilityForSigning: ({
        nearAccountId,
        chainTarget,
        challengeId,
        otpCode,
        record,
        authLane,
      }) =>
        args.loginWithEmailOtpEcdsaCapabilityForSigning?.({
          nearAccountId,
          chainTarget,
          challengeId,
          otpCode,
          record,
          ...(authLane ? { authLane } : {}),
        }) || Promise.reject(new Error('Email OTP signing bootstrap is not configured')),
      restorePersistedSessionForSigning: (restoreArgs) =>
        args.restorePersistedSessionForSigning(restoreArgs),
      readSigningSessionSnapshotForSigning: (snapshotArgs) =>
        args.readSigningSessionSnapshotForSigning(snapshotArgs),
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: ({
        nearAccountId,
        chainTarget,
        uses,
      }) =>
        args.markThresholdEcdsaEmailOtpSessionConsumedForAccount?.({
          nearAccountId,
          chainTarget,
          uses,
        }),
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
      provisionThresholdEcdsaSession: (provisionArgs) =>
        args.provisionThresholdEcdsaSession(provisionArgs),
      withThresholdEcdsaCommitQueue: (queueArgs) => args.withThresholdEcdsaCommitQueue(queueArgs),
      touchConfirm: args.touchConfirm,
    },
    privateKeyExportRecoveryDeps: {
      indexedDB: IndexedDBManager,
      relayerUrl: args.seamsPasskeyConfigs.network.relayer.url,
      getRpId: () => args.touchIdPrompt.getRpId(),
      requestExportPrivateKeysWithUi: (payload) =>
        args.signerWorkerManager.requestExportPrivateKeysWithUi(payload),
      getTheme: args.getTheme,
    },
    registrationAccountLifecycleDeps: {
      indexedDB: IndexedDBManager,
      userPreferencesManager: args.userPreferencesManager,
      nonceCoordinator: args.nonceCoordinator,
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
      getOrCreateActiveThresholdEcdsaSessionId: (nearAccountId, chainTarget) =>
        getOrCreateActiveThresholdEcdsaSessionId(nearAccountId, chainTarget),
      defaultRelayerUrl: args.seamsPasskeyConfigs.network.relayer?.url || '',
      persistThresholdEcdsaBootstrapChainAccount: args.persistThresholdEcdsaBootstrapChainAccount,
      upsertThresholdEcdsaSessionFromBootstrap: args.upsertThresholdEcdsaSessionFromBootstrap,
    },
    nearKeyOpsDeps: {
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
    },
    resolveCanonicalThresholdEcdsaSessionIdForChain,
    signingSessionCoordinator,
    getWorkerResourceWarmupDeps: getWorkerResourceWarmupDeps,
    getManagerConvenienceDeps: (): ManagerConvenienceDeps => ({
      signTempo: args.signTempo,
      prewarmSignerWorkers: () => prewarmSignerWorkersValue(getWorkerResourceWarmupDeps()),
      warmCriticalResources: (nearAccountId?: string) =>
        warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), nearAccountId),
      getWarmThresholdEd25519SessionStatus: (nearAccountId: AccountId | string) =>
        createWarmSessionStatusReader({
          touchConfirm: args.touchConfirm,
          getEmailOtpWarmSessionStatus,
        }).getEd25519SigningSessionStatus(nearAccountId),
    }),
  };
}
