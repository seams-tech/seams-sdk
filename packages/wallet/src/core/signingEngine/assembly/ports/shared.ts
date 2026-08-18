import type { WarmSessionMaterialOperationTarget } from '../../session/emailOtp/sealedRuntimePurpose';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';
import type { RuntimePorts } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { LocalWalletAuthMethodRecord } from '@/core/indexedDB';
import type { AccountId } from '@/core/types/accountIds';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from '../../threshold/ed25519/yaoPublicCapabilityReferences';
import type { SeamsConfigsReadonly, SigningSessionStatus, ThemeMode } from '@/core/types/seams';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import type {
  EvmFamilySigningDeps,
  NearSigningApiDeps,
  RegistrationAccountLifecycleDeps,
  RegistrationSessionDeps,
} from '../../interfaces/operationDeps';
import type { NonceCoordinator } from '../../nonce/NonceCoordinator';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
} from '../../session/availability/availableSigningLanes';
import type { ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/sealedRecovery.types';
import type { PersistedAvailableSigningLanesDeps } from '../../session/availability/persistedAvailableSigningLanes';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { SigningSessionStatusCheck } from '../../session/lifecycle/walletSessionStatus';
import {
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserPreferencesManager } from '../../session/userPreferences';
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
  PasskeyMpcExportPort,
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import { prewarmTxConfirmerUi } from '../../uiConfirm/ui/confirm-ui';
import {
  loadSecp256k1EngineCtor,
  loadSignEvmFamilyWithUiConfirmForTempo,
  loadSignEvmWithUiConfirm,
  loadWebAuthnP256EngineCtor,
} from '../../flows/signEvmFamily/signerLoader';

type RequestEmailOtpTransactionSigningChallengeArgs = Parameters<
  NonNullable<EvmFamilySigningDeps['requestEmailOtpTransactionSigningChallenge']>
>[0];
type RequestEmailOtpEd25519SigningChallengeArgs = Parameters<
  NonNullable<NearSigningApiDeps['requestEmailOtpEd25519SigningChallenge']>
>[0];
type PrepareNearEd25519YaoMaterialBoundary =
  NearSigningApiDeps['prepareNearEd25519YaoMaterialBoundary'];
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
};

export type SigningEngineStorePorts = {
  walletProfileAndSignerRecords: {
    accountStore: RegistrationAccountLifecycleDeps['accountStore'] & {
      listWalletAuthMethodsForWallet: (walletId: string) => Promise<LocalWalletAuthMethodRecord[]>;
      getWalletPasskeyAuthenticator: (args: {
        walletId: string;
        credentialId: string;
      }) => Promise<{ readonly credentialId: string; readonly signerSlot: number } | null>;
    };
    walletSignerStore: EvmFamilySigningDeps['walletSignerStore'];
    passkeyAuthenticatorStore: EvmFamilySigningDeps['passkeyAuthenticatorStore'];
    ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  };
  recoveryAndDeviceLinking: {
    credentialStore: WalletSessionActivationDeps['credentialStore'];
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
  resolveCanonicalEcdsaSigningCapability: EvmFamilySigningDeps['resolveCanonicalEcdsaSigningCapability'];
  resolveAuthorizedEcdsaSigningCapability: EvmFamilySigningDeps['resolveAuthorizedEcdsaSigningCapability'];
  resolveActiveEcdsaWalletSessionAuthorization: EvmFamilySigningDeps['resolveActiveEcdsaWalletSessionAuthorization'];
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  passkeyMpcExport: PasskeyMpcExportPort;
  getEmailOtpWarmSessionStatus?: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
  consumeEmailOtpWarmSessionUses?: (
    args: WarmSessionMaterialOperationTarget & {
      uses?: number;
    },
  ) => Promise<WarmSessionStatusResult>;
  clearEmailOtpWarmSessionMaterial: (thresholdSessionId: string) => Promise<void>;
  getWalletSessionStatus: (args: SigningSessionStatusCheck) => Promise<SigningSessionStatus | null>;
  signerWorkerManager: SignerWorkerManager;
  getWorkerBaseOrigin: () => string;
  workerWarmupPolicy: WorkerResourceWarmupDeps['workerWarmupPolicy'];
  getTheme: () => ThemeMode;
  signTempo: SigningEngineConveniencePorts['signTempo'];
  activateAuthenticatedWalletState: WorkerResourceWarmupDeps['activateAuthenticatedWalletState'];
  persistThresholdEcdsaBootstrapForWalletTarget: WalletSessionActivationDeps['persistThresholdEcdsaBootstrapForWalletTarget'];
  requestEmailOtpTransactionSigningChallenge?: (
    args: RequestEmailOtpTransactionSigningChallengeArgs,
  ) => Promise<EmailOtpTransactionSigningChallenge>;
  requestEmailOtpEd25519SigningChallenge?: (
    args: RequestEmailOtpEd25519SigningChallengeArgs,
  ) => Promise<EmailOtpTransactionSigningChallenge>;
  prepareNearEd25519YaoMaterialBoundary: PrepareNearEd25519YaoMaterialBoundary;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  restorePersistedSessionForSigning: (
    args: RestorePersistedSessionForSigningInput,
  ) => Promise<unknown>;
  readAvailableSigningLanesForSigning: (
    args: ReadAvailableSigningLanesForSigningInput,
  ) => Promise<AvailableSigningLanes>;
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
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
  walletSessionActivationDeps: WalletSessionActivationDeps;
  signingSessionCoordinator: SigningSessionCoordinator;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getManagerConveniencePorts: () => SigningEngineConveniencePorts;
};

export function resolveNearRpcUrl(args: CreateSigningEnginePortsArgs): string {
  return resolvePrimaryNearRpcUrl(args.seamsWebConfigs.network.chains);
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
      await Promise.all([
        args.touchConfirm.initialize(),
        args.passkeyMpcSession.prewarmShamir3Pass(),
        prewarmTxConfirmerUi(),
        /* Also warm the lazily-imported EVM-family signing flow chunks: the
           first sign after a page load otherwise pays these dynamic imports
           before the confirmation modal can open. */
        loadSignEvmFamilyWithUiConfirmForTempo().catch(() => {}),
        loadSignEvmWithUiConfirm().catch(() => {}),
        loadSecp256k1EngineCtor().catch(() => {}),
        loadWebAuthnP256EngineCtor().catch(() => {}),
      ]);
    },
    activateAuthenticatedWalletState: args.activateAuthenticatedWalletState,
  });
}

export function createManagerConveniencePortsFactory(args: {
  createArgs: CreateSigningEnginePortsArgs;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
}): () => SigningEngineConveniencePorts {
  const { createArgs, getWorkerResourceWarmupDeps } = args;
  return () => ({
    signTempo: createArgs.signTempo,
    prewarmSignerWorkers: () => prewarmSignerWorkersValue(getWorkerResourceWarmupDeps()),
    warmCriticalResources: (accountContext?: WorkerResourceWarmupAccountContext) =>
      warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), accountContext),
  });
}
