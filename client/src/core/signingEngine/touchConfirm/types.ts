/**
 * TouchConfirm contracts (types + ports).
 */

import type { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { UnifiedIndexedDBManager } from '../../indexedDB';
import type { UserPreferencesManager } from '../api/userPreferences';
import type { NonceManager } from '../../rpcClients/near/nonceManager';
import type {
  SecureConfirmDecision,
  SecureConfirmProgressEvent,
  UserConfirmRequest,
} from './shared/confirmTypes';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { ThemeName, ThemeTokenOverridesInput } from '../../types/tatchi';
import type { RegistrationCredentialConfirmationPayload } from '../workerManager/validation';
import type {
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultWithTxContext,
} from './handlers/flowOrchestrator';

export type RequestUserConfirmationOptions = {
  onProgress?: (progress: SecureConfirmProgressEvent) => void;
};

/** TouchConfirm-owned host context passed into the touchConfirm confirmation runtime. */
export interface TouchConfirmContext {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  getTheme?: () => ThemeName;
  getAppearanceTokens?: () => ThemeTokenOverridesInput | undefined;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  requestUserConfirmation?: (
    request: UserConfirmRequest,
    options?: RequestUserConfirmationOptions,
  ) => Promise<SecureConfirmDecision>;
}

export type ThresholdPrfCachePeekResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type ThresholdPrfCacheDispenseResult =
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type RequestRegistrationCredentialConfirmationParams = {
  nearAccountId: string;
  deviceNumber: number;
  confirmerText?: { title?: string; body?: string };
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  contractId: string;
  nearRpcUrl: string;
};

export interface ThresholdPrfFirstCacheWriterPort {
  putPrfFirstForThresholdSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void>;
}

export interface ThresholdPrfFirstCachePeekPort {
  peekPrfFirstForThresholdSession(args: {
    sessionId: string;
  }): Promise<ThresholdPrfCachePeekResult>;
}

export interface ThresholdPrfFirstCacheDispensePort {
  dispensePrfFirstForThresholdSession(args: {
    sessionId: string;
    uses?: number;
  }): Promise<ThresholdPrfCacheDispenseResult>;
}

export interface ThresholdPrfFirstCacheClearPort {
  clearPrfFirstForThresholdSession(args: { sessionId: string }): Promise<void>;
}

export type ThresholdPrfFirstCachePort =
  & ThresholdPrfFirstCacheWriterPort
  & ThresholdPrfFirstCachePeekPort
  & ThresholdPrfFirstCacheDispensePort
  & ThresholdPrfFirstCacheClearPort;

export type TouchConfirmSigningSessionPort =
  & TouchConfirmSigningPort
  & TouchConfirmSecureConfirmationPort
  & ThresholdPrfFirstCachePort;

export type TouchConfirmSigningRuntimePort =
  & TouchConfirmContextPort
  & TouchConfirmSigningSessionPort;

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
  ): Promise<SecureConfirmDecision>;
}

export interface TouchConfirmManager
  extends
    TouchConfirmContextPort,
    TouchConfirmSigningPort,
    TouchConfirmRegistrationPort,
    TouchConfirmSecureConfirmationPort,
    ThresholdPrfFirstCachePort,
    TouchConfirmWorkerLifecyclePort {}
