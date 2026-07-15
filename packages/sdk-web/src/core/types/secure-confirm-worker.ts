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
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoLifecycleScopeV1,
} from '@shared/utils/routerAbEd25519Yao';

export type SigningSessionSealAuthMethod = 'passkey' | 'email_otp';

type WarmSessionSealTransportCommon = {
  walletId?: string;
  relayerUrl: string;
  signingGrantId?: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  shamirPrimeB64u?: string;
};

type EmailOtpWarmSessionSealTransportCommon = WarmSessionSealTransportCommon & {
  walletSessionJwt: string;
};

type PasskeyWarmSessionSealTransportCommon = WarmSessionSealTransportCommon & {
  walletSessionJwt?: string;
  serverSealedSecretCacheScope?: {
    kind: 'passkey_registration';
    walletId: string;
    credentialIdB64u: string;
    signingGrantId: string;
  };
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
  | (EmailOtpWarmSessionSealTransportCommon & {
      curve: 'ed25519';
      authMethod: 'email_otp';
      emailOtpRestore?: never;
    })
  | (PasskeyWarmSessionSealTransportCommon & {
      curve: 'ed25519';
      authMethod?: 'passkey';
      emailOtpRestore?: never;
    })
  | (EmailOtpWarmSessionSealTransportCommon & {
      curve: 'ecdsa';
      authMethod: 'email_otp';
      chainTarget: ThresholdEcdsaChainTarget;
      emailOtpRestore?: never;
    })
  | (PasskeyWarmSessionSealTransportCommon & {
      curve: 'ecdsa';
      authMethod?: 'passkey';
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
      diagnostics?: WarmSessionSealAndPersistDiagnostics;
    }
  | { ok: false; code: string; message: string };

export type WarmSessionSealAndPersistDiagnostics = {
  runtimeSetupMs: number;
  clientSealMs: number;
  serverSealRouteMs: number;
  clientUnsealMs: number;
  policyUpdateMs: number;
};

export type WarmSessionRehydrateResult =
  | { ok: true; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string };

export type ExportPrivateKeyScheme = 'ed25519' | 'secp256k1';
export type ThresholdEcdsaExportArtifactKind = 'ecdsa-hss-secp256k1-export';
export const ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1 =
  'router-ab-ed25519-yao-seed-export-v1' as const;

export type RouterAbEd25519YaoExportWorkerPayloadV1 = ExportPrivateKeysWithUiWorkerPayloadBase & {
  walletId: string;
  nearAccountId: string;
  artifactKind: typeof ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1;
  relayerUrl: string;
  walletSessionJwt: string;
  flowId: string;
  viewerSessionId: string;
  exactLane: {
    nearEd25519SigningKeyId: string;
    signerSlot: number;
    credentialIdB64u: string;
    signingGrantId: string;
    thresholdSessionId: string;
  };
  capability: {
    scope: RouterAbEd25519YaoLifecycleScopeV1;
    applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
    participantIds: readonly [number, number];
    registeredPublicKey: RouterAbEd25519YaoBytes32V1;
    stateEpoch: number;
    activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
  };
  chainTarget?: never;
  publicKeyHex?: never;
  privateKeyHex?: never;
  ethereumAddress?: never;
};

type ExportPrivateKeysWithUiWorkerPayloadBase = {
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
};

export type ExportPrivateKeysWithUiWorkerPayload =
  | (ExportPrivateKeysWithUiWorkerPayloadBase & {
      walletId: string;
      chainTarget: ThresholdEcdsaChainTarget;
      artifactKind: 'ecdsa-hss-secp256k1-export';
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    })
  | (ExportPrivateKeysWithUiWorkerPayloadBase & {
      walletId: string;
      chainTarget: ThresholdEcdsaChainTarget;
    })
  | RouterAbEd25519YaoExportWorkerPayloadV1;

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
