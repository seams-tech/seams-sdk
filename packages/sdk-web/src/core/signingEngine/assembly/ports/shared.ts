import type { RuntimePorts } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly, SigningSessionStatus, ThemeName } from '@/core/types/seams';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import type {
  EmailOtpEcdsaSigningBootstrapResult,
  EvmFamilySigningDeps,
  NearSigningApiDeps,
  PrivateKeyExportRecoveryDeps,
  RegistrationAccountLifecycleDeps,
  RegistrationSessionDeps,
} from '../../interfaces/operationDeps';
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
  ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ConsumeSingleUseEmailOtpEcdsaLaneResult,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
  ThresholdEcdsaKeyRefLookupResult,
} from '../../session/persistence/records';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/sealedRecovery.types';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { SigningSessionBudgetStatusCheck } from '../../session/budget/budget';
import {
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaSessionRecordKey,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserPreferencesManager } from '../../session/userPreferences';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../../session/warmCapabilities/types';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEd25519LifecycleDeps } from '../../threshold/ed25519/hssLifecycle';
import type { WalletSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import type { PersistEmailOtpThresholdEd25519LocalMetadataDeps } from '../../session/emailOtp/ed25519LocalMetadata';
import type { ThresholdEcdsaBootstrapStorePort } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import type { UiConfirmRuntimeBridgePort, WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import { prewarmTxConfirmerUi } from '../../uiConfirm/ui/confirm-ui';
import type { SignerWorkerManager } from '../../workerManager/SignerWorkerManager';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupDiagnostics,
  type WorkerResourceWarmupDeps,
  type WorkerResourceWarmupStorePort,
} from '../warmup';

export type SignTempoPortInput = {
  walletSession: WalletSessionRef;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export type SigningEngineConveniencePorts = {
  signTempo: (args: SignTempoPortInput) => Promise<TempoSignedResult | EvmSignedResult>;
  prewarmSignerWorkers: () => void;
  warmCriticalResources: (nearAccountId?: string) => Promise<WorkerResourceWarmupDiagnostics>;
  getWarmThresholdEd25519SessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
};

export type SigningEngineStorePorts = {
  walletProfileAndSignerRecords: {
    accountStore: RegistrationAccountLifecycleDeps['accountStore'];
    walletSignerStore: EvmFamilySigningDeps['walletSignerStore'];
    passkeyAuthenticatorStore: EvmFamilySigningDeps['passkeyAuthenticatorStore'];
    ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  };
  recoveryAndDeviceLinking: {
    credentialStore: WalletSessionActivationDeps['credentialStore'];
    keyMaterialStore: PrivateKeyExportRecoveryDeps['keyMaterialStore'];
    ed25519MetadataStore: PersistEmailOtpThresholdEd25519LocalMetadataDeps;
  };
  warmup: {
    store: WorkerResourceWarmupStorePort;
  };
};

export type CreateSigningEnginePortsArgs = {
  runtimePorts: RuntimePorts;
  stores: SigningEngineStorePorts;
  seamsWebConfigs: SeamsConfigsReadonly;
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
  getWalletSigningBudgetStatus: (
    args: SigningSessionBudgetStatusCheck,
  ) => Promise<SigningSessionStatus | null>;
  signerWorkerManager: SignerWorkerManager;
  getWorkerBaseOrigin: () => string;
  shouldPrewarmWorkers: WorkerResourceWarmupDeps['shouldPrewarmWorkers'];
  getTheme: () => ThemeName;
  signTempo: SigningEngineConveniencePorts['signTempo'];
  extractCosePublicKey: (attestationObjectBase64url: string) => Promise<Uint8Array>;
  activateAuthenticatedWalletState: WorkerResourceWarmupDeps['activateAuthenticatedWalletState'];
  persistThresholdEcdsaBootstrapForWalletTarget: WalletSessionActivationDeps['persistThresholdEcdsaBootstrapForWalletTarget'];
  upsertThresholdEcdsaSessionFromBootstrap: WalletSessionActivationDeps['upsertThresholdEcdsaSessionFromBootstrap'];
  listThresholdEcdsaKeyRefsForWalletTarget: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaKeyRefLookupResult[];
  listThresholdEcdsaSessionRecordsForWalletTarget: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord[];
  getThresholdEcdsaSessionRecordByKey: (
    identity: ThresholdEcdsaSessionRecordKey,
  ) => ThresholdEcdsaSessionRecord | null;
  getEmailOtpThresholdEcdsaSessionRecordForSigning: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => ThresholdEcdsaSessionRecord;
  getPasskeyThresholdEcdsaSessionRecordForSigning: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  }) => ThresholdEcdsaSessionRecord;
  requestEmailOtpTransactionSigningChallenge?: NearSigningApiDeps['requestEmailOtpTransactionSigningChallenge'] &
    EvmFamilySigningDeps['requestEmailOtpTransactionSigningChallenge'];
  isEmailOtpEd25519WarmupPending?: (args: { nearAccountId: AccountId }) => boolean;
  waitForPendingEmailOtpEd25519Warmup?: (args: { nearAccountId: AccountId }) => Promise<boolean>;
  loginWithEmailOtpEd25519CapabilityForSigning?: (args: {
    nearAccountId: AccountId;
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
    walletSession: WalletSessionRef;
    subjectId?: never;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
  }) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
  restorePersistedSessionForSigning: (
    args: RestorePersistedSessionForSigningInput,
  ) => Promise<unknown>;
  readAvailableSigningLanesForSigning: (
    args: ReadAvailableSigningLanesForSigningInput,
  ) => Promise<AvailableSigningLanes>;
  consumeSingleUseEmailOtpEcdsaLane?: (
    command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ) => ConsumeSingleUseEmailOtpEcdsaLaneResult;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId;
    thresholdSessionId?: string;
    uses?: number;
  }) => void;
  clearThresholdEcdsaSessionRecordForWalletTarget: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => void;
  provisionThresholdEcdsaSession: (
    args: import('../../session/passkey/ecdsaSessionProvision').ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  withThresholdEcdsaCommitQueue: <T>(args: {
    queueKey: string;
    walletId: WalletId;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
  withThresholdEd25519CommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: AccountId;
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
  thresholdEd25519LifecycleDeps: ThresholdEd25519LifecycleDeps;
  nearSigningDeps: NearSigningApiDeps;
  tempoSigningDeps: EvmFamilySigningDeps;
  privateKeyExportRecoveryDeps: PrivateKeyExportRecoveryDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
  walletSessionActivationDeps: WalletSessionActivationDeps;
  nearKeyOpsDeps: NearKeyOpsDeps;
  resolveCanonicalThresholdEcdsaSessionIdForWalletTarget: (
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string | null;
  signingSessionCoordinator: SigningSessionCoordinator;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getManagerConveniencePorts: () => SigningEngineConveniencePorts;
};

export function resolveNearRpcUrl(args: CreateSigningEnginePortsArgs): string {
  return resolvePrimaryNearRpcUrl(args.seamsWebConfigs.network.chains);
}

export function createResolveCanonicalThresholdEcdsaSessionIdForWalletTarget(
  args: CreateSigningEnginePortsArgs,
): SigningEnginePorts['resolveCanonicalThresholdEcdsaSessionIdForWalletTarget'] {
  return (walletId, chainTarget) => {
    for (const source of THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES) {
      try {
        const keyRefs = args.listThresholdEcdsaKeyRefsForWalletTarget({
          walletId,
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
  runtimeDeps: { warmupStore: WorkerResourceWarmupStorePort },
): () => WorkerResourceWarmupDeps {
  return () => ({
    workerBaseOrigin: args.getWorkerBaseOrigin(),
    store: runtimeDeps.warmupStore,
    nearClient: args.nearClient,
    nonceCoordinator: args.nonceCoordinator,
    prewarmWorkers: args.signerWorkerManager.prewarmWorkers.bind(args.signerWorkerManager),
    shouldPrewarmWorkers: args.shouldPrewarmWorkers,
    prewarmUiConfirmUi: async () => {
      await Promise.all([args.touchConfirm.initialize(), prewarmTxConfirmerUi()]);
    },
    activateAuthenticatedWalletState: args.activateAuthenticatedWalletState,
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
