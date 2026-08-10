import type {
  WarmSessionLanePurpose,
  WarmSessionMaterialOperationTarget,
} from '../session/emailOtp/sealedRuntimePurpose';
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
import type { ThresholdSessionId } from '@shared/utils/domainIds';
import type { DurableRecordStore } from '@/core/platform';
import type { NearOperationStepUpPreparationPort } from '../interfaces/operationStepUpPreparation';
import type { NearImplicitAccountFundingPort } from '../interfaces/implicitAccountFunding';
import type { WalletIframeSurfaceMeasurement } from '@/SeamsWeb/walletIframe/shared/messages';
import type { WalletIframeRequestId } from '@/core/types/walletIframeIdentity';

export type RequestUserConfirmationOptions = {
  onProgress?: (progress: UserConfirmProgressEvent) => void;
};

export type ExportPrivateKeysWithUiOptions = {
  onViewerLifecycle?: (event: 'opened' | 'closed') => void;
};

export type UiConfirmSurfaceMeasurementBinding =
  | {
      kind: 'disabled';
    }
  | {
      kind: 'wallet_iframe';
      requestId: WalletIframeRequestId;
      postMeasurement: (measurement: WalletIframeSurfaceMeasurement) => void;
      /**
       * The variant the parent dressed the HOST BOX with, when it is pinned for
       * the whole request regardless of what each confirmation inside it
       * renders. Only key export needs this: its box is always a full-viewport
       * drawer (for the key viewer) while the Email OTP prompt inside that box
       * still follows the Confirmer UI setting and may be a modal.
       *
       * Omitted everywhere else, where the box variant and the confirmation
       * variant are the same value — both come from the confirmation config.
       */
      hostSurfaceVariant?: 'modal' | 'drawer';
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
  nearImplicitAccountFunding: NearImplicitAccountFundingPort;
  relayerUrl: string;
  chains?: readonly SeamsChainConfig[];
  getTheme?: () => ThemeMode;
  getAppearance?: () => AppearanceConfig;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  loadEcdsaRoleLocalReadyRecord: DurableRecordStore['loadEcdsaRoleLocalReadyRecord'];
  surfaceMeasurementBinding: UiConfirmSurfaceMeasurementBinding;
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

export type OpenTransactionPreparationModalParams = {
  walletLabel: string;
  chain: 'evm' | 'tempo';
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

export interface WarmSessionStatusReader {
  getWarmSessionStatus(args: { thresholdSessionId: string }): Promise<WarmSessionStatusResult>;
}

export interface WarmSessionStatusBatchReader {
  getWarmSessionStatuses(args: {
    thresholdSessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult>;
}

export interface WarmSessionMaterialClaimer {
  claimWarmSessionMaterial(args: WarmSessionMaterialOperationTarget & {
    uses?: number;
    consume?: boolean;
  }): Promise<WarmSessionClaimResult>;
}

export interface WarmSessionMaterialConsumer {
  consumeWarmSessionUses(args: WarmSessionMaterialOperationTarget & {
    uses?: number;
  }): Promise<WarmSessionStatusResult>;
}

export type VolatileWarmSessionScope =
  | {
      kind: 'session';
      thresholdSessionId: ThresholdSessionId;
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
    thresholdSessionId: string;
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
  openTransactionPreparationModal(params: OpenTransactionPreparationModalParams): Promise<void>;
  closeTransactionPreparationModal(): void;
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
