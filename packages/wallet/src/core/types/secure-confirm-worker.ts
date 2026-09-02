/** User confirmation and Passkey MPC worker types. */
import type { SigningSessionPersistenceMode } from './seams';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoLifecycleScopeV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  RouterAbEd25519NormalSigningState,
  SealedSigningSessionEcdsaRestoreMetadata,
  SealedSigningSessionEd25519RestoreMetadata,
} from '@shared/utils/signingSessionSeal';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';

type WarmSessionSealTransportCommon = {
  walletId?: string;
  relayerUrl: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  groupId?: string;
};

type EmailOtpWarmSessionSealTransportCommon = WarmSessionSealTransportCommon & {
  walletSessionToken: string;
};

type PasskeyWarmSessionSealTransportCommon = WarmSessionSealTransportCommon & {
  walletSessionToken?: string;
  serverSealedSecretCacheScope?: {
    kind: 'passkey_registration';
    walletId: string;
    credentialIdB64u: string;
    walletSessionId: string;
    quotaId: string;
  };
};

export type PasskeyEd25519SealRestoreMetadata = Extract<
  SealedSigningSessionEd25519RestoreMetadata,
  { credentialIdB64u: string }
> & {
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export interface UiConfirmManagerConfig {
  workerUrl?: string;
  workerTimeout?: number;
  debug?: boolean;
  signingSessionPersistenceMode?: SigningSessionPersistenceMode;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  signingSessionSealGroupId?: string;
}

export type UserConfirmWorkerMessageType = 'PING' | 'SECURE_CONFIRM_REQUEST';

export type PasskeyMpcSessionWorkerMessageType =
  | 'PING'
  | 'PREWARM_SHAMIR3PASS'
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
      ecdsaRestore?: never;
      ed25519Restore?: never;
      emailOtpRestore?: never;
    })
  | (PasskeyWarmSessionSealTransportCommon & {
      curve: 'ed25519';
      authMethod: 'passkey';
      walletId: string;
      walletSessionToken: string;
      ecdsaRestore?: never;
      ed25519Restore: PasskeyEd25519SealRestoreMetadata;
      emailOtpRestore?: never;
    })
  | (EmailOtpWarmSessionSealTransportCommon & {
      curve: 'ecdsa';
      authMethod: 'email_otp';
      chainTarget: ThresholdEcdsaChainTarget;
      ecdsaRestore?: never;
      ed25519Restore?: never;
      emailOtpRestore?: never;
    })
  | (PasskeyWarmSessionSealTransportCommon & {
      curve: 'ecdsa';
      authMethod: 'passkey';
      walletId: string;
      chainTarget: ThresholdEcdsaChainTarget;
      ecdsaRestore: Exclude<SealedSigningSessionEcdsaRestoreMetadata, { source: 'email_otp' }>;
      ed25519Restore?: never;
      emailOtpRestore?: never;
    })
  | (PasskeyWarmSessionSealTransportCommon & {
      curve: 'linked_device';
      authMethod: 'passkey';
      walletId: string;
      walletSessionToken: string;
      enrollmentId: string;
      deviceId: string;
      credentialIdB64u: string;
      chainTarget?: never;
      ecdsaRestore?: never;
      ed25519Restore?: never;
      emailOtpRestore?: never;
    })
  | (EmailOtpWarmSessionSealTransportCommon & {
      curve: 'linked_device';
      authMethod: 'email_otp';
      walletId: string;
      walletSessionToken: string;
      enrollmentId: string;
      deviceId: string;
      walletAuthMethodId: string;
      chainTarget?: never;
      ecdsaRestore?: never;
      ed25519Restore?: never;
      emailOtpRestore?: never;
    });

export interface WarmSessionSealAndPersistPayload {
  thresholdSessionId: string;
  transport: WarmSessionSealTransportInput;
}

export interface WarmSessionRehydratePayload {
  thresholdSessionId: string;
  sealedSecretB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  transport: WarmSessionSealTransportInput;
}

export interface WarmSessionStatusBatchReadPayload {
  thresholdSessionIds: string[];
}

export type WarmSessionStatusBatchResult = {
  results: Array<{
    thresholdSessionId: string;
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
export type ThresholdEcdsaExportArtifactKind = 'ecdsa-derivation-secp256k1-export';
export const ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1 =
  'router-ab-ed25519-yao-seed-export-v1' as const;

/** Authorization is carried independently from the exact material lane. */
export type RouterAbEd25519YaoExportWorkerAuthorizationV1 = {
  readonly kind: 'opaque_wallet_session';
  readonly walletSessionToken: string;
};

export type RouterAbEd25519YaoExportWorkerPayloadV1 = ExportPrivateKeysWithUiWorkerPayloadBase & {
  walletId: string;
  nearAccountId: string;
  artifactKind: typeof ROUTER_AB_ED25519_YAO_EXPORT_ARTIFACT_KIND_V1;
  relayerUrl: string;
  authorization: RouterAbEd25519YaoExportWorkerAuthorizationV1;
  flowId: string;
  viewerSessionId: string;
  exactLane: {
    nearEd25519SigningKeyId: string;
    signerSlot: number;
    credentialIdB64u: string;
    materialActivation: MpcMaterialActivationRef;
  };
  walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
  capability: {
    scope: RouterAbEd25519YaoLifecycleScopeV1;
    applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
    participantIds: readonly [number, number];
    registeredPublicKey: RouterAbEd25519YaoBytes32V1;
    stateEpoch: number;
    activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
    materialActivation: MpcMaterialActivationRef;
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
      credentialIdB64u: string;
      chainTarget: ThresholdEcdsaChainTarget;
      artifactKind: 'ecdsa-derivation-secp256k1-export';
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    })
  | (ExportPrivateKeysWithUiWorkerPayloadBase & {
      walletId: string;
      credentialIdB64u: string;
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

export interface PasskeyMpcExportWorkerMessage {
  type: 'EXPORT_PRIVATE_KEYS_WITH_UI';
  id?: string;
  payload: ExportPrivateKeysWithUiWorkerPayload;
}

export interface PasskeyMpcSessionWorkerMessage<TPayload = unknown> {
  type: PasskeyMpcSessionWorkerMessageType;
  id?: string;
  payload?: TPayload;
}

export interface UserConfirmWorkerResponse<TData = unknown> {
  id?: string;
  success: boolean;
  data?: TData;
  error?: string;
}
