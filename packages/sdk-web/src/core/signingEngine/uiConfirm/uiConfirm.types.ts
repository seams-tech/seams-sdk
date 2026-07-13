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
  RegistrationActivationProof,
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
  WarmSessionEd25519UnsealAuthorizationClaimPayload,
  WarmSessionEd25519UnsealAuthorizationClaimResult,
  WarmSessionEd25519UnsealAuthorizationPutPayload,
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
import type { DeleteDurableSealedSessionCommand } from '../session/persistence/durableSealedSessionCommands';
import type { VolatileWarmSessionId } from '../session/warmCapabilities/volatileWarmSessionId';
import type { DurableRecordStore } from '@/core/platform';

export type RequestUserConfirmationOptions = {
  onProgress?: (progress: UserConfirmProgressEvent) => void;
};

/** UiConfirm-owned host context passed into the concrete confirmation runtime. */
export interface UiConfirmContext {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  webauthnCredentialStore: WebAuthnCredentialStorePort;
  passkeyAuthenticatorStore: EvmFamilyPasskeyAuthenticatorStorePort;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
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
  walletIframeActivation?: RegistrationActivationProof;
};

export interface WarmSessionStatusReader {
  getWarmSessionStatus(args: { sessionId: string }): Promise<WarmSessionStatusResult>;
}

export interface WarmSessionStatusBatchReader {
  getWarmSessionStatuses(args: { sessionIds: string[] }): Promise<WarmSessionStatusBatchResult>;
}

export interface WarmSessionMaterialClaimer {
  claimWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionClaimResult>;
}

export interface WarmSessionMaterialConsumer {
  consumeWarmSessionUses(args: {
    sessionId: string;
    uses?: number;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionStatusResult>;
}

export interface WarmSessionEd25519UnsealAuthorizationStore {
  putWarmSessionEd25519UnsealAuthorization(
    args: WarmSessionEd25519UnsealAuthorizationPutPayload,
  ): Promise<WarmSessionStatusResult>;
  claimWarmSessionEd25519UnsealAuthorization(
    args: WarmSessionEd25519UnsealAuthorizationClaimPayload,
  ): Promise<WarmSessionEd25519UnsealAuthorizationClaimResult>;
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

export interface WarmSessionSealPersister {
  sealAndPersistWarmSessionMaterial(
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult>;
  persistSigningSessionSealForThresholdSession(args: {
    sessionId: string;
    transport?: WarmSessionSealTransportInput;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<WarmSessionSealAndPersistResult>;
}

export interface WarmSessionRehydrator {
  rehydrateWarmSessionMaterial(
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult>;
}

export interface WarmSessionPersistedRestorer {
  discoverPersistedSessionsForWallet?(
    args: {
      authMethod?: 'passkey';
    } & DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult>;
  restorePersistedSessionForSigning(
    args: {
      authMethod: 'passkey';
    } & RestorePersistedSessionForSigningInput,
  ): Promise<RestorePersistedSessionForSigningResult>;
}

export interface DurableSealedSessionRecordDeleter {
  deleteDurableSealedSessionRecord(command: DeleteDurableSealedSessionCommand): Promise<void>;
}

export type VolatileWarmMaterialPort = WarmSessionStatusReader &
  WarmSessionStatusBatchReader &
  WarmSessionMaterialClaimer &
  WarmSessionMaterialConsumer &
  WarmSessionEd25519UnsealAuthorizationStore &
  VolatileWarmSessionMaterialClearer &
  VolatileWarmSessionMaterialClearAll;

export type DurableSealedSessionPort = WarmSessionSealPersister &
  WarmSessionRehydrator &
  WarmSessionPersistedRestorer &
  DurableSealedSessionRecordDeleter;

export type PromptCapableBootstrapPort = UiConfirmContextPort &
  UiConfirmSigningPort &
  UiConfirmRegistrationPort &
  UiConfirmSecureConfirmationPort;

export type WarmSessionMaterialPort = WarmSessionMaterialWriter &
  VolatileWarmMaterialPort &
  DurableSealedSessionPort;

export type UiConfirmSigningSessionPort = UiConfirmSigningPort &
  UiConfirmSecureConfirmationPort &
  WarmSessionMaterialPort;

export type UiConfirmSigningRuntimePort = UiConfirmContextPort & UiConfirmSigningSessionPort;

export type UiConfirmRuntimeBridgePort = PromptCapableBootstrapPort &
  WarmSessionMaterialPort &
  UiConfirmWorkerLifecyclePort;

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
  requestRegistrationCredentialConfirmation(
    params: RequestRegistrationCredentialConfirmationParams,
  ): Promise<RegistrationCredentialConfirmationPayload>;
}

export interface UiConfirmWorkerLifecyclePort {
  initialize(): Promise<void>;
  setWorkerBaseOrigin(origin: string | undefined): void;
}

export interface UiConfirmSecureConfirmationPort {
  requestUserConfirmation(
    request: UserConfirmRequest,
    options?: RequestUserConfirmationOptions,
  ): Promise<UserConfirmDecision>;
  exportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ): Promise<ExportPrivateKeysWithUiWorkerResult>;
}

export interface UiConfirmManager
  extends PromptCapableBootstrapPort, WarmSessionMaterialPort, UiConfirmWorkerLifecyclePort {}
