/**
 * UserConfirm worker types
 *
 * The UserConfirm worker now hosts:
 * - the UserConfirm bridge (`awaitUserConfirmationV2`) used by confirmTxFlow, and
 * - a small warm-session material store for threshold signing.
 */
import type { SigningSessionPersistenceMode } from './seams';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';

export type SigningSessionSealAuthMethod = 'passkey' | 'email_otp';

type WarmSessionSealTransportCommon = {
  walletId?: string;
  relayerUrl: string;
  signingGrantId?: string;
  walletSessionJwt?: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  shamirPrimeB64u?: string;
};

export interface UiConfirmManagerConfig {
  workerUrl?: string;
  workerTimeout?: number;
  debug?: boolean;
  signingSessionPersistenceMode?: SigningSessionPersistenceMode;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  signingSessionSealShamirPrimeB64u?: string;
}

export type UserConfirmWorkerMessageType =
  | 'PING'
  | 'SECURE_CONFIRM_REQUEST'
  | 'EXPORT_PRIVATE_KEYS_WITH_UI'
  | 'WARM_SESSION_MATERIAL_PUT'
  | 'WARM_SESSION_STATUS_READ'
  | 'WARM_SESSION_STATUS_BATCH_READ'
  | 'WARM_SESSION_MATERIAL_CLAIM'
  | 'WARM_SESSION_MATERIAL_CONSUME'
  | 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR'
  | 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR_ALL'
  | 'WARM_SESSION_SEAL_AND_PERSIST'
  | 'WARM_SESSION_REHYDRATE';

export type WarmSessionSealTransportInput =
  | (WarmSessionSealTransportCommon & {
      curve: 'ed25519';
      authMethod: 'email_otp';
      emailOtpRestore?: never;
    })
  | (WarmSessionSealTransportCommon & {
      curve: 'ed25519';
      authMethod?: 'passkey';
      emailOtpRestore?: never;
    })
  | (WarmSessionSealTransportCommon & {
      curve: 'ecdsa';
      authMethod?: SigningSessionSealAuthMethod;
      chainTarget: ThresholdEcdsaChainTarget;
      emailOtpRestore?: never;
    });

export interface WarmSessionSealAndPersistPayload {
  sessionId: string;
  transport: WarmSessionSealTransportInput;
}

export interface WarmSessionRehydratePayload {
  sessionId: string;
  sealedSecretB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  transport: WarmSessionSealTransportInput;
}

export interface WarmSessionStatusBatchReadPayload {
  sessionIds: string[];
}

export type WarmSessionStatusBatchResult = {
  results: Array<{
    sessionId: string;
    result:
      | { ok: true; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
  }>;
};

export type WarmSessionSealAndPersistResult =
  | {
      ok: true;
      sealedSecretB64u: string;
      keyVersion?: string;
      remainingUses: number;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

export type WarmSessionRehydrateResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type ExportPrivateKeyScheme = 'ed25519' | 'secp256k1';
export type ThresholdEd25519ExportArtifactKind = 'near-ed25519-seed-v1';
export type ThresholdEcdsaExportArtifactKind = 'ecdsa-hss-secp256k1-export';

type ExportPrivateKeysWithUiWorkerPayloadBase = {
  nearAccountId: string;
  signerSlot: number;
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
      chainTarget: ThresholdEcdsaChainTarget;
      artifactKind: 'ecdsa-hss-secp256k1-export';
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    })
  | (ExportPrivateKeysWithUiWorkerPayloadBase & {
      chainTarget: ThresholdEcdsaChainTarget;
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
