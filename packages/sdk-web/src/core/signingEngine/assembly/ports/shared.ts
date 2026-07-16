import type { RuntimePorts } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AccountId } from '@/core/types/accountIds';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from '../../threshold/ed25519/yaoPublicCapabilityReferences';
import type { SeamsConfigsReadonly, SigningSessionStatus, ThemeMode } from '@/core/types/seams';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import type { EmailOtpEcdsaStepUpAuthority } from '../../flows/signEvmFamily/emailOtpSigningSession';
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
  ThresholdEcdsaSessionRecordLookupKey,
} from '../../session/persistence/records';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/sealedRecovery.types';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { SigningSessionBudgetStatusCheck } from '../../session/budget/budget';
import {
  type ThresholdEcdsaChainTarget,
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
import type { WalletSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import type { ThresholdEcdsaBootstrapStorePort } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import type { Ed25519YaoActiveClientRegistryPort } from '../../threshold/ed25519/yaoActiveClientRegistry';
import type {
  UiConfirmRuntimeBridgePort,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import { prewarmTxConfirmerUi } from '../../uiConfirm/ui/confirm-ui';

type RequestEmailOtpTransactionSigningChallengeArgs = Parameters<
  NonNullable<EvmFamilySigningDeps['requestEmailOtpTransactionSigningChallenge']>
>[0];
type RequestEmailOtpEd25519SigningChallengeArgs = Parameters<
  NonNullable<NearSigningApiDeps['requestEmailOtpEd25519SigningChallenge']>
>[0];
type RecoverEmailOtpEd25519CapabilityForSigningArgs = Parameters<
  NonNullable<NearSigningApiDeps['recoverEmailOtpEd25519CapabilityForSigning']>
>[0];
type RecoverPasskeyEd25519YaoCapabilityForSigning =
  NearSigningApiDeps['recoverPasskeyEd25519YaoCapabilityForSigning'];
type RecoverEmailOtpEd25519YaoCapabilitySilentlyForSigning =
  NearSigningApiDeps['recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning'];
import type { SignerWorkerManager } from '../../workerManager/SignerWorkerManager';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupAccountContext,
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
  warmCriticalResources: (
    accountContext?: WorkerResourceWarmupAccountContext,
  ) => Promise<WorkerResourceWarmupDiagnostics>;
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
  };
  warmup: {
    store: WorkerResourceWarmupStorePort;
  };
};

export type CreateSigningEnginePortsArgs = {
  runtimePorts: RuntimePorts;
  stores: SigningEngineStorePorts;
  ed25519YaoPublicCapabilityReferences: Ed25519YaoPublicCapabilityReferenceStorePort;
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
  workerWarmupPolicy: WorkerResourceWarmupDeps['workerWarmupPolicy'];
  getTheme: () => ThemeMode;
  signTempo: SigningEngineConveniencePorts['signTempo'];
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
    identity: ThresholdEcdsaSessionRecordLookupKey,
  ) => ThresholdEcdsaSessionRecord | null;
  getPasskeyThresholdEcdsaSessionRecordForSigning: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  }) => ThresholdEcdsaSessionRecord;
  requestEmailOtpTransactionSigningChallenge?: (
    args: RequestEmailOtpTransactionSigningChallengeArgs,
  ) => Promise<{ challengeId: string; emailHint?: string }>;
  requestEmailOtpEd25519SigningChallenge?: (
    args: RequestEmailOtpEd25519SigningChallengeArgs,
  ) => Promise<{ challengeId: string; emailHint?: string }>;
  recoverEmailOtpEd25519CapabilityForSigning?: (
    args: RecoverEmailOtpEd25519CapabilityForSigningArgs,
  ) => ReturnType<NonNullable<NearSigningApiDeps['recoverEmailOtpEd25519CapabilityForSigning']>>;
  recoverPasskeyEd25519YaoCapabilityForSigning: RecoverPasskeyEd25519YaoCapabilityForSigning;
  recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning: RecoverEmailOtpEd25519YaoCapabilitySilentlyForSigning;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    walletSession: WalletSessionRef;
    subjectId?: never;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    authority: EmailOtpEcdsaStepUpAuthority;
    remainingUses: number;
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
  markThresholdEd25519EmailOtpSessionConsumedForWallet?: (args: {
    walletId: WalletId;
    thresholdSessionId?: string;
    uses?: number;
  }) => void;
  clearThresholdEcdsaSessionRecordForExactIdentity: (
    identity: ExactEcdsaSigningLaneIdentity,
  ) => void;
  provisionThresholdEcdsaSession: (
    args: import('../../session/passkey/ecdsaSessionProvision').ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  withThresholdEcdsaSigningQueue: <T>(args: {
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

export type SigningEnginePorts = {
  ed25519YaoActiveClients: Ed25519YaoActiveClientRegistryPort;
  nearSigningDeps: NearSigningApiDeps;
  tempoSigningDeps: EvmFamilySigningDeps;
  privateKeyExportRecoveryDeps: PrivateKeyExportRecoveryDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
  walletSessionActivationDeps: WalletSessionActivationDeps;
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
    workerWarmupPolicy: args.workerWarmupPolicy,
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
    warmCriticalResources: (accountContext?: WorkerResourceWarmupAccountContext) =>
      warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), accountContext),
    getWarmThresholdEd25519SessionStatus,
  });
}
