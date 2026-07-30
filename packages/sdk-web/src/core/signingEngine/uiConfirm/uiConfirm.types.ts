import type { WarmSessionLanePurpose } from '../session/emailOtp/sealedRuntimePurpose';
/**
 * UiConfirm specs (types + interfaces).
 */

import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { EvmFamilyPasskeyAuthenticatorStorePort } from '../interfaces/passkeyAuthenticatorStore';
import type { WebAuthnCredentialStorePort } from '../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type {
  UserConfirmDecision,
  UserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmProgressEvent } from '../stepUpConfirmation/types';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { AppearanceConfig, ThemeMode, SeamsChainConfig } from '../../types/seams';
import type { RegistrationCredentialConfirmationPayload } from '../workerManager/validation';
import type {
  OrchestrateNearSignatureOnlySigningConfirmationParams,
  OrchestrateNearTransactionSigningConfirmationParams,
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultSignatureOnly,
  NearTransactionSigningConfirmationResult,
} from '../stepUpConfirmation/confirmOperation';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  WarmSessionStatusBatchResult,
  WarmSessionRehydratePayload,
  WarmSessionRehydrateResult,
  WarmSessionSealAndPersistPayload,
  WarmSessionSealAndPersistResult,
} from '@/core/types/secure-confirm-worker';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
} from '../session/sealedRecovery/sealedRecovery.types';
import type {
  WarmSessionMaterialWriter,
  WarmSessionMaterialWriteDiagnostics,
} from '../session/passkey/warmSessionMaterialWriter';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { VolatileWarmSessionId } from '../session/warmCapabilities/volatileWarmSessionId';
import type { DurableRecordStore } from '@/core/platform';
import type { NearOperationStepUpPreparationPort } from '../interfaces/operationStepUpPreparation';

export type RequestUserConfirmationOptions = {
  onProgress?: (progress: UserConfirmProgressEvent) => void;
};

export type ExportPrivateKeysWithUiOptions = {
  onViewerLifecycle?: (event: 'opened' | 'closed') => void;
};

/** UiConfirm-owned host context passed into the concrete confirmation runtime. */
export interface UiConfirmContext {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  webauthnCredentialStore: WebAuthnCredentialStorePort;
  passkeyAuthenticatorStore: EvmFamilyPasskeyAuthenticatorStorePort;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  operationStepUpPreparation: NearOperationStepUpPreparationPort;
  relayerUrl: string;
  chains?: readonly SeamsChainConfig[];
  getTheme?: () => ThemeMode;
  getAppearance?: () => AppearanceConfig;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  loadEcdsaRoleLocalReadyRecord: DurableRecordStore['loadEcdsaRoleLocalReadyRecord'];
}

export type WarmSessionStatusResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type WarmSessionClaimResult =
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type RequestRegistrationCredentialConfirmationParams = {
  walletId: string;
  nearAccountId?: string;
  signerSlot: number;
  confirmerText?: { title?: string; body?: string };
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  challengeB64u?: string;
};

export type OpenRegistrationPreparationModalParams = {
  walletLabel: string;
  signerSlot: number;
};

export interface WarmSessionStatusReader {
  getWarmSessionStatus(args: { sessionId: string }): Promise<WarmSessionStatusResult>;
}

export interface WarmSessionStatusBatchReader {
  getWarmSessionStatuses(args: { sessionIds: string[] }): Promise<WarmSessionStatusBatchResult>;
}

export interface WarmSessionMaterialClaimer {
  claimWarmSessionMaterial(args: {
    purpose: WarmSessionLanePurpose;
    uses?: number;
    consume?: boolean;
  }): Promise<WarmSessionClaimResult>;
}

export interface WarmSessionMaterialConsumer {
  consumeWarmSessionUses(args: {
    purpose: WarmSessionLanePurpose;
    uses?: number;
  }): Promise<WarmSessionStatusResult>;
}

export type VolatileWarmSessionScope =
  | {
      kind: 'session';
      sessionId: VolatileWarmSessionId;
    }
  | {
      kind: 'all';
    };

export type ClearVolatileWarmMaterialCommand = {
  kind: 'clear_volatile_warm_material';
  scope: VolatileWarmSessionScope;
  durableRecord?: never;
  resolvedIdentity?: never;
  deleteReason?: never;
};

export type ClearVolatileWarmSessionMaterialCommand = ClearVolatileWarmMaterialCommand & {
  scope: Extract<VolatileWarmSessionScope, { kind: 'session' }>;
};

export type ClearAllVolatileWarmSessionMaterialCommand = ClearVolatileWarmMaterialCommand & {
  scope: Extract<VolatileWarmSessionScope, { kind: 'all' }>;
};

export interface VolatileWarmSessionMaterialClearer {
  clearVolatileWarmSessionMaterial(command: ClearVolatileWarmSessionMaterialCommand): Promise<void>;
}

export interface VolatileWarmSessionMaterialClearAll {
  clearAllVolatileWarmSessionMaterial(
    command: ClearAllVolatileWarmSessionMaterialCommand,
  ): Promise<void>;
}

export interface WarmSessionWorkerSealPort {
  sealAndPersistWarmSessionMaterial(
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult>;
}

export type PasskeyWarmSessionSealTransportInput = Exclude<
  WarmSessionSealTransportInput,
  { authMethod: 'email_otp' }
>;

export interface WarmSessionSealPersister {
  persistSigningSessionSealForThresholdSession(args: {
    sessionId: string;
    transport: PasskeyWarmSessionSealTransportInput;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<WarmSessionSealAndPersistResult>;
}

export interface WarmSessionRehydrator {
  rehydrateWarmSessionMaterial(
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult>;
}

type PasskeyPersistedSessionDiscoveryInput =
  DiscoverPersistedSessionsForWalletInput extends infer Input
    ? Input extends DiscoverPersistedSessionsForWalletInput
      ? Omit<Input, 'authMethod'>
      : never
    : never;

export interface WarmSessionPersistedDiscovery {
  discoverPersistedSessionsForWallet(
    args: PasskeyPersistedSessionDiscoveryInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult>;
}

export interface WarmSessionPersistedRestorer {
  restorePersistedSessionForSigning(
    args: Omit<RestorePersistedSessionForSigningInput, 'authMethod'>,
  ): Promise<RestorePersistedSessionForSigningResult>;
}

export type VolatileWarmMaterialPort = WarmSessionStatusReader &
  WarmSessionStatusBatchReader &
  WarmSessionMaterialClaimer &
  WarmSessionMaterialConsumer &
  VolatileWarmSessionMaterialClearer &
  VolatileWarmSessionMaterialClearAll;

export type PromptCapableBootstrapPort = UiConfirmContextPort &
  UiConfirmSigningPort &
  UiConfirmRegistrationPort &
  UiConfirmRequestConfirmationPort;

export type UiConfirmRuntimeBridgePort = PromptCapableBootstrapPort &
  UiConfirmWorkerLifecyclePort;

export interface PasskeyMpcSessionWorkerLifecyclePort {
  setWorkerBaseOrigin(origin: string | undefined): void;
  prewarmShamir3Pass(): Promise<void>;
}

export type PasskeyMpcSessionPort = WarmSessionMaterialWriter &
  VolatileWarmMaterialPort &
  WarmSessionSealPersister &
  WarmSessionWorkerSealPort &
  WarmSessionRehydrator &
  WarmSessionPersistedDiscovery &
  WarmSessionPersistedRestorer &
  PasskeyMpcSessionWorkerLifecyclePort;

export interface UiConfirmContextPort {
  getContext(): UiConfirmContext;
}

export interface UiConfirmSigningPort {
  orchestrateSigningConfirmation(
    params: Extract<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultIntentDigest>;
  orchestrateSigningConfirmation(
    params: OrchestrateNearTransactionSigningConfirmationParams,
  ): Promise<NearTransactionSigningConfirmationResult>;
  orchestrateSigningConfirmation(
    params: OrchestrateNearSignatureOnlySigningConfirmationParams,
  ): Promise<SigningConfirmationResultSignatureOnly>;
}

export interface UiConfirmRegistrationPort {
  openRegistrationPreparationModal(params: OpenRegistrationPreparationModalParams): Promise<void>;
  closeRegistrationPreparationModal(): void;
  requestRegistrationCredentialConfirmation(
    params: RequestRegistrationCredentialConfirmationParams,
  ): Promise<RegistrationCredentialConfirmationPayload>;
}

export interface UiConfirmWorkerLifecyclePort {
  initialize(): Promise<void>;
  setWorkerBaseOrigin(origin: string | undefined): void;
}

export interface UiConfirmRequestConfirmationPort {
  requestUserConfirmation(
    request: UserConfirmRequest,
    options?: RequestUserConfirmationOptions,
  ): Promise<UserConfirmDecision>;
}

export interface PasskeyMpcExportPort {
  setWorkerBaseOrigin(origin: string | undefined): void;
  exportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
    options?: ExportPrivateKeysWithUiOptions,
  ): Promise<ExportPrivateKeysWithUiWorkerResult>;
}

export interface UiConfirmManager
  extends PromptCapableBootstrapPort, UiConfirmWorkerLifecyclePort {}
