/**
 * TouchConfirm specs (types + interfaces).
 */

import type { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { UnifiedIndexedDBManager } from '../../indexedDB';
import type { UserPreferencesManager } from '../api/userPreferences';
import type { NonceManager } from '../../rpcClients/near/nonceManager';
import type {
  UserConfirmDecision,
  UserConfirmProgressEvent,
  UserConfirmRequest,
} from './shared/confirmTypes';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { ThemeName, ThemeTokenOverridesInput, TatchiChainConfig } from '../../types/tatchi';
import type { RegistrationCredentialConfirmationPayload } from '../workerManager/validation';
import type {
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultWithTxContext,
} from './handlers/flowOrchestrator';
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

export type RequestUserConfirmationOptions = {
  onProgress?: (progress: UserConfirmProgressEvent) => void;
};

/** TouchConfirm-owned host context passed into the touchConfirm confirmation runtime. */
export interface TouchConfirmContext {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  chains?: readonly TatchiChainConfig[];
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
  deviceNumber: number;
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
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }): Promise<void>;
}

export interface WarmSessionStatusReader {
  getWarmSessionStatus(args: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult>;
}

export interface WarmSessionStatusBatchReader {
  getWarmSessionStatuses(args: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult>;
}

export interface WarmSessionMaterialClaimer {
  claimWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
  }): Promise<WarmSessionClaimResult>;
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
}

export interface WarmSessionRehydrator {
  rehydrateWarmSessionMaterial(
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult>;
}

export interface WarmSessionPersistedRecordDeleter {
  deletePersistedWarmSessionMaterial(
    args: WarmSessionDeletePersistedPayload,
  ): Promise<void>;
}

export type WarmSessionMaterialPort = WarmSessionMaterialWriter &
  WarmSessionStatusReader &
  WarmSessionStatusBatchReader &
  WarmSessionMaterialClaimer &
  WarmSessionMaterialClearer &
  WarmSessionSealPersister &
  WarmSessionRehydrator &
  WarmSessionPersistedRecordDeleter;

export type TouchConfirmSigningSessionPort = TouchConfirmSigningPort &
  TouchConfirmSecureConfirmationPort &
  WarmSessionMaterialPort;

export type TouchConfirmSigningRuntimePort = TouchConfirmContextPort &
  TouchConfirmSigningSessionPort;

export type TouchConfirmRuntimeBridgePort = TouchConfirmContextPort &
  TouchConfirmSigningPort &
  TouchConfirmRegistrationPort &
  TouchConfirmSecureConfirmationPort &
  WarmSessionMaterialPort &
  TouchConfirmWorkerLifecyclePort;

export interface TouchConfirmContextPort {
  getContext(): TouchConfirmContext;
}

export interface TouchConfirmSigningPort {
  orchestrateSigningConfirmation(
    params: Extract<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultIntentDigest>;
  orchestrateSigningConfirmation(
    params: Exclude<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultWithTxContext>;
}

export interface TouchConfirmRegistrationPort {
  requestRegistrationCredentialConfirmation(
    params: RequestRegistrationCredentialConfirmationParams,
  ): Promise<RegistrationCredentialConfirmationPayload>;
}

export interface TouchConfirmWorkerLifecyclePort {
  initialize(): Promise<void>;
  setWorkerBaseOrigin(origin: string | undefined): void;
}

export interface TouchConfirmSecureConfirmationPort {
  requestUserConfirmation(
    request: UserConfirmRequest,
    options?: RequestUserConfirmationOptions,
  ): Promise<UserConfirmDecision>;
  exportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ): Promise<ExportPrivateKeysWithUiWorkerResult>;
}

export interface TouchConfirmManager
  extends
    TouchConfirmContextPort,
    TouchConfirmSigningPort,
    TouchConfirmRegistrationPort,
    TouchConfirmSecureConfirmationPort,
    WarmSessionMaterialPort,
    TouchConfirmWorkerLifecyclePort {}
