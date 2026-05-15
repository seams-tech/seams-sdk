/**
 * UiConfirm specs (types + interfaces).
 */

import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { UnifiedIndexedDBManager } from '../../indexedDB';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type {
  UserConfirmDecision,
  UserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmProgressEvent } from '../stepUpConfirmation/types';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { ThemeName, ThemeTokenOverridesInput, SeamsChainConfig } from '../../types/seams';
import type { RegistrationCredentialConfirmationPayload } from '../workerManager/validation';
import type {
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultWithTxContext,
} from '../stepUpConfirmation/confirmOperation';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  WarmSessionStatusBatchResult,
  WarmSessionDeletePersistedPayload,
  WarmSessionRehydratePayload,
  WarmSessionRehydrateResult,
  WarmSessionSealAndPersistPayload,
  WarmSessionSealAndPersistResult,
} from '@/core/types/secure-confirm-worker';
import type {
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
} from '../session/sealedRecovery/types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type RequestUserConfirmationOptions = {
  onProgress?: (progress: UserConfirmProgressEvent) => void;
};

/** UiConfirm-owned host context passed into the concrete confirmation runtime. */
export interface UiConfirmContext {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  chains?: readonly SeamsChainConfig[];
  getTheme?: () => ThemeName;
  getAppearanceTokens?: () => ThemeTokenOverridesInput | undefined;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
}

export type WarmSessionStatusResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type WarmSessionClaimResult =
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type RequestRegistrationCredentialConfirmationParams = {
  nearAccountId: string;
  signerSlot: number;
  confirmerText?: { title?: string; body?: string };
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  nearRpcUrl: string;
};

export interface WarmSessionMaterialWriter {
  putWarmSessionMaterial(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }): Promise<void>;
}

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

export interface WarmSessionMaterialClearer {
  clearWarmSessionMaterial(args: { sessionId: string }): Promise<void>;
}

export interface WarmSessionMaterialClearAll {
  clearAllWarmSessionMaterial(): Promise<void>;
}

export interface WarmSessionSealPersister {
  sealAndPersistWarmSessionMaterial(
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult>;
  persistSigningSessionSealForThresholdSession(args: {
    sessionId: string;
    transport?: WarmSessionSealTransportInput;
  }): Promise<WarmSessionSealAndPersistResult>;
}

export interface WarmSessionRehydrator {
  rehydrateWarmSessionMaterial(
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult>;
}

export interface WarmSessionPersistedRestorer {
  restorePersistedSessionsForWallet?(
    args: {
      authMethod?: 'passkey';
    } & RestorePersistedSessionsForWalletInput,
  ): Promise<RestorePersistedSessionsForWalletResult>;
  restorePersistedSessionForSigning(
    args: {
      authMethod: 'passkey';
    } & RestorePersistedSessionForSigningInput,
  ): Promise<{
    attempted: number;
    restored: number;
    deferred: number;
  }>;
}

export interface WarmSessionPersistedRecordDeleter {
  deletePersistedWarmSessionMaterial(args: WarmSessionDeletePersistedPayload): Promise<void>;
}

export type WarmSessionMaterialPort = WarmSessionMaterialWriter &
  WarmSessionStatusReader &
  WarmSessionStatusBatchReader &
  WarmSessionMaterialClaimer &
  WarmSessionMaterialConsumer &
  WarmSessionMaterialClearer &
  WarmSessionSealPersister &
  WarmSessionRehydrator &
  WarmSessionPersistedRestorer &
  WarmSessionPersistedRecordDeleter;

export type UiConfirmSigningSessionPort = UiConfirmSigningPort &
  UiConfirmSecureConfirmationPort &
  WarmSessionMaterialPort;

export type UiConfirmSigningRuntimePort = UiConfirmContextPort &
  UiConfirmSigningSessionPort;

export type UiConfirmRuntimeBridgePort = UiConfirmContextPort &
  UiConfirmSigningPort &
  UiConfirmRegistrationPort &
  UiConfirmSecureConfirmationPort &
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
    params: Exclude<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultWithTxContext>;
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
  extends
    UiConfirmContextPort,
    UiConfirmSigningPort,
    UiConfirmRegistrationPort,
    UiConfirmSecureConfirmationPort,
    WarmSessionMaterialPort,
    UiConfirmWorkerLifecyclePort {}
