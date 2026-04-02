/**
 * UserConfirm worker types
 *
 * The UserConfirm worker now hosts:
 * - the UserConfirm bridge (`awaitUserConfirmationV2`) used by confirmTxFlow, and
 * - a small PRF.first cache for threshold warm sessions.
 */
import type { SigningSessionPersistenceMode } from './tatchi';

export interface TouchConfirmManagerConfig {
  workerUrl?: string;
  workerTimeout?: number;
  debug?: boolean;
  signingSessionPersistenceMode?: SigningSessionPersistenceMode;
  prfSessionSealKeyVersion?: string;
  prfSessionSealShamirPrimeB64u?: string;
}

export type UserConfirmWorkerMessageType =
  | 'PING'
  | 'SECURE_CONFIRM_REQUEST'
  | 'EXPORT_PRIVATE_KEYS_WITH_UI'
  | 'THRESHOLD_PRF_FIRST_CACHE_PUT'
  | 'THRESHOLD_PRF_FIRST_CACHE_PEEK'
  | 'THRESHOLD_PRF_FIRST_CACHE_TRANSFER'
  | 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE'
  | 'THRESHOLD_PRF_FIRST_CACHE_CLEAR'
  | 'THRESHOLD_PRF_FIRST_CACHE_CLEAR_ALL'
  | 'THRESHOLD_PRF_FIRST_CACHE_SEAL_AND_PERSIST'
  | 'THRESHOLD_PRF_FIRST_CACHE_REHYDRATE'
  | 'THRESHOLD_PRF_FIRST_CACHE_DELETE_PERSISTED';

export interface ThresholdPrfSessionSealTransportInput {
  relayerUrl: string;
  thresholdSessionJwt?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
}

export interface ThresholdPrfFirstCacheSealAndPersistPayload {
  sessionId: string;
  transport: ThresholdPrfSessionSealTransportInput;
}

export interface ThresholdPrfFirstCacheRehydratePayload {
  sessionId: string;
  sealedPrfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  keyVersion?: string;
  transport: ThresholdPrfSessionSealTransportInput;
}

export interface ThresholdPrfFirstCacheDeletePersistedPayload {
  sessionId: string;
}

export interface ThresholdPrfFirstCacheTransferPayload {
  fromSessionId: string;
  toSessionId: string;
}

export type ThresholdPrfFirstCacheSealAndPersistResult =
  | {
      ok: true;
      sealedPrfFirstB64u: string;
      keyVersion?: string;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

export type ThresholdPrfFirstCacheRehydrateResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type ExportPrivateKeyScheme = 'ed25519' | 'secp256k1';
export type ExportKeypairChain = 'near' | 'evm' | 'tempo';
export type ThresholdEd25519ExportArtifactKind = 'near-ed25519-seed-v1';

type ExportPrivateKeysWithUiWorkerPayloadBase = {
  nearAccountId: string;
  deviceNumber: number;
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
};

export type ExportPrivateKeysWithUiWorkerPayload =
  | (ExportPrivateKeysWithUiWorkerPayloadBase & {
      chain: 'near';
      artifactKind: 'near-ed25519-seed-v1';
      expectedPublicKey: string;
      seedB64u: string;
    })
  | (ExportPrivateKeysWithUiWorkerPayloadBase & {
      chain: 'evm' | 'tempo';
    });

export interface ExportPrivateKeysWithUiWorkerResult {
  ok: boolean;
  cancelled?: boolean;
  accountId: string;
  exportedSchemes: ExportPrivateKeyScheme[];
  error?: string;
}

export interface UserConfirmWorkerMessage<TPayload = unknown> {
  type: UserConfirmWorkerMessageType;
  id?: string;
  payload?: TPayload;
}

export interface UserConfirmWorkerResponse<TData = unknown> {
  id?: string;
  success: boolean;
  data?: TData;
  error?: string;
}
