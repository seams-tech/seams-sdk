// === IMPORT AUTO-GENERATED WASM TYPES ===
// These are the source of truth generated from Rust structs via wasm-bindgen
// Import as instance types from the WASM module classes
import * as wasmModule from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  WorkerRequestType,
  WorkerResponseType,
} from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
export { WorkerRequestType, WorkerResponseType }; // Export the WASM enums directly

import type { StripFree } from './index.js';
import type { TransactionContext } from './rpc.js';
import type { ActionArgsWasm } from './actions.js';
import type {
  BuildEcdsaRoleLocalExportArtifactCommand as GeneratedBuildEcdsaRoleLocalExportArtifactCommand,
  BuildEcdsaRoleLocalExportArtifactOutput as GeneratedBuildEcdsaRoleLocalExportArtifactOutput,
  Ed25519DeleteSealedWorkerMaterialRequest as GeneratedEd25519DeleteSealedWorkerMaterialRequest,
  Ed25519DeleteSealedWorkerMaterialSuccess as GeneratedEd25519DeleteSealedWorkerMaterialSuccess,
  Ed25519HssClientOutputMaskTransport as GeneratedEd25519HssClientOutputMaskTransport,
  Ed25519SealedWorkerMaterialTransport as GeneratedEd25519SealedWorkerMaterialTransport,
  Ed25519WorkerMaterialBinding as GeneratedEd25519WorkerMaterialBinding,
  Ed25519WorkerMaterialCredentialAuthorization as GeneratedEd25519WorkerMaterialCredentialAuthorization,
  Ed25519WorkerMaterialFormatVersion as GeneratedEd25519WorkerMaterialFormatVersion,
  Ed25519WorkerMaterialSessionBinding as GeneratedEd25519WorkerMaterialSessionBinding,
  Ed25519PutSealedWorkerMaterialRequest as GeneratedEd25519PutSealedWorkerMaterialRequest,
  Ed25519PutSealedWorkerMaterialSuccess as GeneratedEd25519PutSealedWorkerMaterialSuccess,
  Ed25519ReadSealedWorkerMaterialRequest as GeneratedEd25519ReadSealedWorkerMaterialRequest,
  Ed25519ReadSealedWorkerMaterialSuccess as GeneratedEd25519ReadSealedWorkerMaterialSuccess,
  Ed25519RestoreWorkerMaterialRequest as GeneratedEd25519RestoreWorkerMaterialRequest,
  Ed25519WorkerMaterialFailure as GeneratedEd25519WorkerMaterialFailure,
  Ed25519WorkerMaterialStored as GeneratedEd25519WorkerMaterialStored,
  FinalizeEcdsaClientBootstrapCommand as GeneratedFinalizeEcdsaClientBootstrapCommand,
  FinalizeEcdsaClientBootstrapOutput as GeneratedFinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapCommand as GeneratedPrepareEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapOutput as GeneratedPrepareEcdsaClientBootstrapOutput,
} from '../platform/generated/signerCoreCommands.js';

export type WasmTransaction = wasmModule.WasmTransaction;
export type WasmSignature = wasmModule.WasmSignature;

export type ThresholdBehavior = 'strict' | 'fallback';
export const DEFAULT_THRESHOLD_BEHAVIOR: ThresholdBehavior = 'strict';

export function isThresholdBehavior(input: unknown): input is ThresholdBehavior {
  return input === 'fallback' || input === 'strict';
}

export function resolveThresholdBehavior(
  input?: ThresholdBehavior | null,
  fallback: ThresholdBehavior = DEFAULT_THRESHOLD_BEHAVIOR,
): ThresholdBehavior {
  return isThresholdBehavior(input) ? input : fallback;
}

export const NearSignerWorkerCustomRequestType = {
  ThresholdEd25519PrepareHssClientOutputMaskHandle:
    'thresholdEd25519PrepareHssClientOutputMaskHandle',
  ThresholdEd25519StoreWorkerMaterialFromHssOutput:
    'thresholdEd25519StoreWorkerMaterialFromHssOutput',
  ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization:
    'thresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization',
  ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization:
    'thresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization',
  ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization:
    'thresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization',
  ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization:
    'thresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization',
  ThresholdEd25519RestoreWorkerMaterial: 'thresholdEd25519RestoreWorkerMaterial',
  ThresholdEd25519ValidateWorkerMaterial: 'thresholdEd25519ValidateWorkerMaterial',
  ThresholdEd25519PutSealedWorkerMaterial: 'thresholdEd25519PutSealedWorkerMaterial',
  ThresholdEd25519ReadSealedWorkerMaterial: 'thresholdEd25519ReadSealedWorkerMaterial',
  ThresholdEd25519DeleteSealedWorkerMaterial: 'thresholdEd25519DeleteSealedWorkerMaterial',
  ThresholdEd25519ClientPresignCreateFromMaterialHandle:
    'thresholdEd25519ClientPresignCreateFromMaterialHandle',
  ThresholdEd25519ClientPresignSignFromMaterialHandle:
    'thresholdEd25519ClientPresignSignFromMaterialHandle',
  ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle:
    'thresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle',
  ThresholdEd25519ClientPresignBurn: 'thresholdEd25519ClientPresignBurn',
  ThresholdEd25519ComputeNep413SigningDigest: 'thresholdEd25519ComputeNep413SigningDigest',
  ThresholdEd25519ComputeDelegateSigningDigest: 'thresholdEd25519ComputeDelegateSigningDigest',
  ThresholdEd25519BuildDelegateSigningPayload: 'thresholdEd25519BuildDelegateSigningPayload',
  ThresholdEd25519FinalizeDelegateFromSignature: 'thresholdEd25519FinalizeDelegateFromSignature',
  ThresholdEd25519FinalizeNearTxFromSignature: 'thresholdEd25519FinalizeNearTxFromSignature',
  ThresholdEd25519BuildNearTxUnsignedBorsh: 'thresholdEd25519BuildNearTxUnsignedBorsh',
  ThresholdEd25519DecodeSignedNearTxBorsh: 'thresholdEd25519DecodeSignedNearTxBorsh',
} as const;

export type NearSignerWorkerCustomRequestType =
  (typeof NearSignerWorkerCustomRequestType)[keyof typeof NearSignerWorkerCustomRequestType];

export type SignerWorkerRequestType = WorkerRequestType | NearSignerWorkerCustomRequestType;
export type SignerWorkerResponseType = WorkerResponseType;

export interface ThresholdSignerConfig {
  /** Base URL of the Router API server (e.g. https://router-api.example.com) */
  relayerUrl: string;
  /** Identifies which relayer-held key share to use */
  relayerKeyId: string;
  /** FROST participant identifier used for the client share (2P only, optional). */
  clientParticipantId?: number;
  /** FROST participant identifier used for the relayer share (2P only, optional). */
  relayerParticipantId?: number;
  /** Optional participant ids (signer set) associated with this threshold key/session. */
  participantIds?: number[];
  /** Optional client-side policy for the Ed25519 background presign pool. */
  ed25519PresignPoolPolicy?: RouterAbEd25519PresignPoolPolicyConfig;
}

export type RouterAbEd25519PresignPoolPolicyConfig = {
  targetDepth?: number;
  lowWatermark?: number;
  maxAcceptedRefillCount?: number;
  ttlMs?: number;
};

export type RouterAbEd25519PresignPoolPolicy = {
  targetDepth: number;
  lowWatermark: number;
  maxAcceptedRefillCount: number;
  ttlMs: number;
};

export type ThresholdEd25519PresignCommitmentsWire = {
  hiding: string;
  binding: string;
};

export type ThresholdEd25519WorkerMaterialResult = {
  materialHandle: string;
  clientVerifyingShareB64u: string;
  bindingDigest: string;
};

export type ThresholdEd25519WorkerMaterialBinding = GeneratedEd25519WorkerMaterialBinding;
export type ThresholdEd25519WorkerMaterialFormatVersion =
  GeneratedEd25519WorkerMaterialFormatVersion;
export type ThresholdEd25519WorkerMaterialCredentialAuthorization =
  GeneratedEd25519WorkerMaterialCredentialAuthorization;
export type ThresholdEd25519WorkerMaterialSessionBinding =
  GeneratedEd25519WorkerMaterialSessionBinding;
export type ThresholdEd25519SealedWorkerMaterialTransport =
  GeneratedEd25519SealedWorkerMaterialTransport;

export type ThresholdEd25519WorkerMaterialStoredResult = {
  ok: true;
  materialHandle: string;
  materialBindingDigest: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  clientVerifyingShareB64u: string;
  materialFormatVersion: ThresholdEd25519WorkerMaterialFormatVersion;
  materialKeyId: string;
  signerSlot: number;
};

export type ThresholdEd25519StoreWorkerMaterialFromHssOutputRequest = {
  evaluatorDriverStateB64u: string;
  clientOutputMessageB64u: string;
  clientOutputMask: ThresholdEd25519HssClientOutputMaskTransport;
  expectedContextBindingB64u: string;
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
  participantIds: number[];
  createdAtMs: number;
  sealAuthorization: ThresholdEd25519WorkerMaterialSealAuthorization;
};

export type ThresholdEd25519HssClientOutputMaskTransport =
  GeneratedEd25519HssClientOutputMaskTransport;

export type ThresholdEd25519PrepareHssClientOutputMaskHandleRequest = {
  applicationBindingDigestB64u: string;
  participantIds: number[];
  contextBindingB64u: string;
  operation: string;
  relayerKeyId: string;
  clientRecoverableSecretB64u: string;
  expiresAtMs: number;
};

export type ThresholdEd25519PrepareHssClientOutputMaskHandleResult = {
  ok: true;
  clientOutputMaskHandle: string;
  contextBindingB64u: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type ThresholdEd25519StoreWorkerMaterialFromHssOutputResult =
  | ThresholdEd25519WorkerMaterialStoredResult
  | ThresholdEd25519WorkerMaterialFailure;

export type ThresholdEd25519RestoreWorkerMaterialRequest =
  GeneratedEd25519RestoreWorkerMaterialRequest;

export type ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest = {
  materialBindingDigest: string;
  rpId: string;
  credentialIdB64u: string;
  prfFirstBytes: Uint8Array;
  expiresAtMs: number;
};

export type ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier = {
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
  participantIds: number[];
  createdAtMs: number;
};

export type ThresholdEd25519WorkerMaterialSealAuthorization =
  | {
      kind: 'passkey_prf_material_seal_authorization_handle_v1';
      handle: string;
      rpId: string;
      credentialIdB64u: string;
      materialKeyId: string;
      expiresAtMs: number;
    }
  | {
      kind: 'recovery_code_material_seal_authorization_handle_v1';
      handle: string;
      authSubjectId: string;
      recoveryCodeBindingDigest: string;
      materialKeyId: string;
      expiresAtMs: number;
    };

export type ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest = {
  bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier;
  rpId: string;
  credentialIdB64u: string;
  prfFirstBytes: Uint8Array;
  expiresAtMs: number;
};

export type ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest = {
  bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier;
  authSubjectId: string;
  recoveryCodeBindingDigest: string;
  recoveryCodeSecret32: Uint8Array;
  expiresAtMs: number;
};

export type ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult = {
  ok: true;
  materialKeyId: string;
  sealAuthorization: ThresholdEd25519WorkerMaterialSealAuthorization;
  remainingUses: number;
};

export type ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest = {
  materialBindingDigest: string;
  authSubjectId: string;
  recoveryCodeBindingDigest: string;
  recoveryCodeSecret32: Uint8Array;
  expiresAtMs: number;
};

export type ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult = {
  ok: true;
  unsealAuthorization: ThresholdEd25519WorkerMaterialCredentialAuthorization;
  remainingUses: number;
};
export type ThresholdEd25519WorkerMaterialFailure = Omit<
  GeneratedEd25519WorkerMaterialFailure,
  'ok'
> & {
  ok: false;
};
export type ThresholdEd25519RestoreWorkerMaterialSuccess = Omit<
  GeneratedEd25519WorkerMaterialStored,
  'ok'
> & {
  ok: true;
  sealedWorkerMaterialB64u: string;
};
export type ThresholdEd25519RestoreWorkerMaterialResult =
  | ThresholdEd25519RestoreWorkerMaterialSuccess
  | ThresholdEd25519WorkerMaterialFailure;

export type ThresholdEd25519PutSealedWorkerMaterialRequest =
  GeneratedEd25519PutSealedWorkerMaterialRequest;
export type ThresholdEd25519PutSealedWorkerMaterialSuccess = Omit<
  GeneratedEd25519PutSealedWorkerMaterialSuccess,
  'ok'
> & {
  ok: true;
};
export type ThresholdEd25519PutSealedWorkerMaterialResult =
  | ThresholdEd25519PutSealedWorkerMaterialSuccess
  | ThresholdEd25519WorkerMaterialFailure;

export type ThresholdEd25519ReadSealedWorkerMaterialRequest =
  GeneratedEd25519ReadSealedWorkerMaterialRequest;
export type ThresholdEd25519ReadSealedWorkerMaterialSuccess = Omit<
  GeneratedEd25519ReadSealedWorkerMaterialSuccess,
  'ok'
> & {
  ok: true;
};
export type ThresholdEd25519ReadSealedWorkerMaterialResult =
  | ThresholdEd25519ReadSealedWorkerMaterialSuccess
  | ThresholdEd25519WorkerMaterialFailure;

export type ThresholdEd25519DeleteSealedWorkerMaterialRequest =
  GeneratedEd25519DeleteSealedWorkerMaterialRequest;
export type ThresholdEd25519DeleteSealedWorkerMaterialSuccess = Omit<
  GeneratedEd25519DeleteSealedWorkerMaterialSuccess,
  'ok'
> & {
  ok: true;
};
export type ThresholdEd25519DeleteSealedWorkerMaterialResult =
  | ThresholdEd25519DeleteSealedWorkerMaterialSuccess
  | ThresholdEd25519WorkerMaterialFailure;

export type ThresholdEd25519ValidateWorkerMaterialRequest = {
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
};

export type ThresholdEd25519ValidateWorkerMaterialResult =
  | ThresholdEd25519WorkerMaterialResult
  | ThresholdEd25519WorkerMaterialFailure;

export type ThresholdEd25519ClientPresignCreateFromMaterialHandleRequest = {
  clientParticipantId: number;
  relayerParticipantId: number;
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
  expectedSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  expectedSessionBindingDigest: string;
  groupPublicKey: string;
};

export type ThresholdEd25519ClientPresignCreateResult = {
  clientNonceHandleB64u: string;
  clientVerifyingShareB64u: string;
  clientCommitments: ThresholdEd25519PresignCommitmentsWire;
};

export type ThresholdEd25519ClientPresignSignFromMaterialHandleRequest = {
  clientParticipantId: number;
  relayerParticipantId: number;
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
  expectedSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  expectedSessionBindingDigest: string;
  groupPublicKey: string;
  signingDigestB64u: string;
  clientNonceHandleB64u: string;
  clientCommitments: ThresholdEd25519PresignCommitmentsWire;
  relayerCommitments: ThresholdEd25519PresignCommitmentsWire;
};

export type ThresholdEd25519ClientPresignSignResult = {
  clientSignatureShareB64u: string;
};

export type ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleRequest = {
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
  expectedSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  expectedSessionBindingDigest: string;
  groupPublicKey: string;
  serverVerifyingShareB64u: string;
  serverCommitments: ThresholdEd25519PresignCommitmentsWire;
  signingDigestB64u: string;
};

export type ThresholdEd25519RoleSeparatedNormalSigningClientShareResult = {
  clientCommitments: ThresholdEd25519PresignCommitmentsWire;
  clientVerifyingShareB64u: string;
  clientSignatureShareB64u: string;
};

export type ThresholdEd25519ClientPresignBurnRequest = {
  clientNonceHandleB64u: string;
};

export type ThresholdEd25519ClientPresignBurnResult = {
  burned: true;
};

export type ThresholdEd25519ComputeNep413SigningDigestRequest = {
  message: string;
  recipient: string;
  nonce: string;
  state?: string;
};

export type ThresholdEd25519ComputeSigningDigestResult = {
  signingDigestB64u: string;
};

export type ThresholdEd25519BuildDelegateSigningPayloadRequest = {
  delegate: DelegatePayload;
};

export type ThresholdEd25519BuildDelegateSigningPayloadResult = {
  canonicalDelegateBorshB64u: string;
  signingDigestB64u: string;
};

export type ThresholdEd25519FinalizeDelegateFromSignatureRequest = {
  delegate: DelegatePayload;
  signingDigestB64u: string;
  signatureB64u: string;
};

export type ThresholdEd25519FinalizeNearTxFromSignatureRequest = {
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
  signatureB64u: string;
  expectedNearAccountId: string;
  expectedSignerPublicKey: string;
};

export type ThresholdEd25519FinalizeNearTxFromSignatureResult = {
  signedTransactionBorshB64u: string;
  transactionHash: string;
};

export type ThresholdEd25519BuildNearTxUnsignedBorshRequest = {
  txSigningRequests: readonly TransactionPayload[];
  transactionContext: TransactionContext;
};

export type ThresholdEd25519NearTxUnsignedBorsh = {
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
};

export type ThresholdEd25519DecodeSignedNearTxBorshRequest = {
  signedTransactionBorshB64u: string;
};

export type ThresholdEd25519DecodeSignedNearTxBorshResult = {
  signedTransaction: WasmSignedTransaction;
  transactionHash: string;
};

export type ThresholdEd25519ClientPresignWorkerOffer = {
  clientPresignId: string;
  nonceHandle: string;
  clientVerifyingShareB64u: string;
  clientCommitments: ThresholdEd25519PresignCommitmentsWire;
  nonceSecretB64u?: never;
  hidingNonceB64u?: never;
  bindingNonceB64u?: never;
};

export type GetRouterAbEd25519PresignPoolStatusPayload = {
  kind: 'get_router_ab_ed25519_presign_pool_status_v1';
  scopeKey: string;
};

export type GetRouterAbEd25519PresignPoolStatusResult = {
  kind: 'get_router_ab_ed25519_presign_pool_status_result_v1';
  scopeKey: string;
  generation: number;
  offeredCount: number;
  readyCount: number;
  burnedCount: number;
  refillInFlight: boolean;
  nextExpiryAtMs: number | null;
};

export type ClearRouterAbEd25519PresignPoolPayload = {
  kind: 'clear_router_ab_ed25519_presign_pool_v1';
  scopeKey: string;
  generation: number;
  reason:
    | 'worker_restart'
    | 'page_reload'
    | 'logout'
    | 'account_switch'
    | 'signing_session_change'
    | 'wallet_signing_session_change'
    | 'relayer_key_change'
    | 'participant_change'
    | 'client_base_change';
};

export type ClearRouterAbEd25519PresignPoolResult = {
  ok: true;
  kind: 'clear_router_ab_ed25519_presign_pool_result_v1';
  scopeKey: string;
  previousGeneration: number;
  nextGeneration: number;
  clearedEntries: number;
};

export interface TransactionPayload {
  nearAccountId: string;
  receiverId: string;
  actions: ActionArgsWasm[];
}
export interface RpcCallPayload {
  nearRpcUrl: string;
  nearAccountId: string;
}
/**
 * RPC call parameters for NEAR operations
 * Used to pass essential parameters for background operations
 * export interface RpcCallPayload {
 *    nearRpcUrl: string;    // NEAR RPC endpoint URL
 *    nearAccountId: string; // Account ID for the current user/session
 * }
 */

type DirectPrfFields = {
  prfFirstB64u?: string;
  wrapKeySalt?: string;
};

export type WasmDeriveThresholdEd25519ClientVerifyingShareRequest =
  StripFree<wasmModule.DeriveThresholdEd25519ClientVerifyingShareRequest> & DirectPrfFields;
export interface WasmDeriveThresholdEd25519HssClientInputsRequest {
  applicationBindingDigestB64u: string;
  participantIds: number[];
  sessionId: string;
  prfFirstB64u?: string;
}
export interface WasmDeriveThresholdEd25519HssClientInputsResult {
  applicationBindingDigestB64u: string;
  participantIds: number[];
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
}
export interface WasmPrepareThresholdEd25519HssSessionRequest {
  applicationBindingDigestB64u: string;
  participantIds: number[];
}
export interface WasmPrepareThresholdEd25519HssSessionResult {
  applicationBindingDigestB64u: string;
  participantIds: number[];
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
}

export type WasmThresholdEd25519HssWorkerSessionSource =
  | {
      sessionSource: 'worker_handle';
      workerSessionHandle: string;
      evaluatorDriverStateB64u?: never;
    }
  | {
      sessionSource: 'serialized_state';
      evaluatorDriverStateB64u: string;
      workerSessionHandle?: never;
    };

export type WasmThresholdEd25519HssSerializedSessionSource = Extract<
  WasmThresholdEd25519HssWorkerSessionSource,
  { sessionSource: 'serialized_state' }
>;

export type WasmPrepareThresholdEd25519HssClientRequestRequest =
  WasmThresholdEd25519HssSerializedSessionSource & {
    clientOtOfferMessageB64u: string;
    yClientB64u: string;
    tauClientB64u: string;
  };
export interface WasmPrepareThresholdEd25519HssClientRequestResult {
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u: string;
  workerSessionHandle?: string;
}
export interface WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactResult {
  contextBindingB64u: string;
  stagedEvaluatorArtifactB64u: string;
  addStageRequestMessageB64u: string;
  timings?: Record<string, number>;
}
export type WasmOpenThresholdEd25519HssSeedOutputRequest =
  WasmThresholdEd25519HssSerializedSessionSource & {
    seedOutputMessageB64u: string;
  };
export interface WasmOpenThresholdEd25519HssSeedOutputResult {
  contextBindingB64u: string;
  canonicalSeedB64u: string;
}
export interface WasmBuildThresholdEd25519SeedExportArtifactRequest {
  seedB64u: string;
  expectedPublicKey: string;
}
export interface WasmBuildThresholdEd25519SeedExportArtifactResult {
  artifactKind: string;
  seedB64u: string;
  publicKey: string;
  privateKey: string;
}
export type WasmThresholdEd25519RoleSeparatedNormalSigningCommitments = {
  hidingB64u: string;
  bindingB64u: string;
};
export type WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapRequest =
  GeneratedPrepareEcdsaClientBootstrapCommand;
export type WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapResult =
  GeneratedPrepareEcdsaClientBootstrapOutput;
export type WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapRequest =
  GeneratedFinalizeEcdsaClientBootstrapCommand;
export type WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapResult =
  GeneratedFinalizeEcdsaClientBootstrapOutput;
export type WasmBuildThresholdEcdsaHssRoleLocalExportArtifactRequest =
  GeneratedBuildEcdsaRoleLocalExportArtifactCommand;
export type WasmBuildThresholdEcdsaHssRoleLocalExportArtifactResult =
  GeneratedBuildEcdsaRoleLocalExportArtifactOutput;
export interface WasmSignTransactionsWithActionsRequest {
  rpcCall: RpcCallPayload;
  sessionId: string;
  createdAt?: number;
  threshold: ThresholdSignerConfig;
  txSigningRequests: TransactionPayload[];
  intentDigest?: string;
  transactionContext?: TransactionContext;
  credential?: string;
}

export interface WasmSignDelegateActionRequest {
  rpcCall: RpcCallPayload;
  sessionId: string;
  createdAt?: number;
  threshold: ThresholdSignerConfig;
  delegate: DelegatePayload;
  intentDigest?: string;
  transactionContext?: TransactionContext;
  credential?: string;
}
export interface DelegatePayload {
  senderId: string;
  receiverId: string;
  actions: ActionArgsWasm[];
  nonce: string;
  maxBlockHeight: string;
  publicKey: string;
}
export interface WasmSignNep413MessageRequest {
  sessionId: string;
  accountId: string;
  nearPublicKey: string;
  threshold: ThresholdSignerConfig;
  message: string;
  recipient: string;
  nonce: string;
  state?: string;
  credential?: string;
}
export type WasmRequestPayload =
  | WasmDeriveThresholdEd25519ClientVerifyingShareRequest
  | WasmDeriveThresholdEd25519HssClientInputsRequest
  | WasmPrepareThresholdEd25519HssSessionRequest
  | WasmPrepareThresholdEd25519HssClientRequestRequest
  | WasmOpenThresholdEd25519HssSeedOutputRequest
  | WasmBuildThresholdEd25519SeedExportArtifactRequest
  | WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapRequest
  | WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapRequest
  | WasmBuildThresholdEcdsaHssRoleLocalExportArtifactRequest
  | WasmSignTransactionsWithActionsRequest
  | WasmSignDelegateActionRequest
  | WasmSignNep413MessageRequest;

// WASM Worker Response Types
export type WasmSignedTransaction = InstanceType<typeof wasmModule.WasmSignedTransaction>;
export type WasmSignedDelegate = wasmModule.WasmSignedDelegate;
export type WasmDelegateAction = wasmModule.WasmDelegateAction;
export type WasmTransactionSignResult = InstanceType<typeof wasmModule.TransactionSignResult>;
export type WasmDelegateSignResult = wasmModule.DelegateSignResult;
// wasm-bindgen may generate classes with private constructors, which breaks
// `InstanceType<typeof Class>`. Use the class name directly for the instance type.
export type WasmDeriveThresholdEd25519ClientVerifyingShareResult =
  wasmModule.DeriveThresholdEd25519ClientVerifyingShareResult;

// === WORKER REQUEST TYPE MAPPING ===
// Define the complete type mapping for each worker request
export interface WorkerRequestTypeMap {
  [WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare]: {
    type: WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare;
    request: WasmDeriveThresholdEd25519ClientVerifyingShareRequest;
    result: WasmDeriveThresholdEd25519ClientVerifyingShareResult;
  };
  [WorkerRequestType.DeriveThresholdEd25519HssClientInputs]: {
    type: WorkerRequestType.DeriveThresholdEd25519HssClientInputs;
    request: WasmDeriveThresholdEd25519HssClientInputsRequest;
    result: WasmDeriveThresholdEd25519HssClientInputsResult;
  };
  [WorkerRequestType.PrepareThresholdEd25519HssSession]: {
    type: WorkerRequestType.PrepareThresholdEd25519HssSession;
    request: WasmPrepareThresholdEd25519HssSessionRequest;
    result: WasmPrepareThresholdEd25519HssSessionResult;
  };
  [WorkerRequestType.PrepareThresholdEd25519HssClientRequest]: {
    type: WorkerRequestType.PrepareThresholdEd25519HssClientRequest;
    request: WasmPrepareThresholdEd25519HssClientRequestRequest;
    result: WasmPrepareThresholdEd25519HssClientRequestResult;
  };
  [WorkerRequestType.OpenThresholdEd25519HssSeedOutput]: {
    type: WorkerRequestType.OpenThresholdEd25519HssSeedOutput;
    request: WasmOpenThresholdEd25519HssSeedOutputRequest;
    result: WasmOpenThresholdEd25519HssSeedOutputResult;
  };
  [WorkerRequestType.BuildThresholdEd25519SeedExportArtifact]: {
    type: WorkerRequestType.BuildThresholdEd25519SeedExportArtifact;
    request: WasmBuildThresholdEd25519SeedExportArtifactRequest;
    result: WasmBuildThresholdEd25519SeedExportArtifactResult;
  };
  [WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap]: {
    type: WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap;
    request: WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapRequest;
    result: WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapResult;
  };
  [WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap]: {
    type: WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap;
    request: WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapRequest;
    result: WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapResult;
  };
  [WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact]: {
    type: WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact;
    request: WasmBuildThresholdEcdsaHssRoleLocalExportArtifactRequest;
    result: WasmBuildThresholdEcdsaHssRoleLocalExportArtifactResult;
  };
  [WorkerRequestType.SignTransactionsWithActions]: {
    type: WorkerRequestType.SignTransactionsWithActions;
    request: WasmSignTransactionsWithActionsRequest;
    result: WasmTransactionSignResult;
  };
  [WorkerRequestType.SignDelegateAction]: {
    type: WorkerRequestType.SignDelegateAction;
    request: WasmSignDelegateActionRequest;
    result: WasmDelegateSignResult;
  };
  [WorkerRequestType.SignNep413Message]: {
    type: WorkerRequestType.SignNep413Message;
    request: WasmSignNep413MessageRequest;
    result: wasmModule.SignNep413Result;
  };
}

/**
 * Validation rules for ConfirmationConfig to ensure behavior conforms to UI mode:
 *
 * - uiMode: 'none' → behavior is ignored, autoProceedDelay is ignored
 * - uiMode: 'modal' | 'drawer' → behavior: 'requireClick' | 'skipClick', autoProceedDelay only used with 'skipClick'
 *
 * The WASM worker automatically validates and overrides these settings:
 * - For 'none' mode: behavior is set to 'skipClick' with autoProceedDelay: 0
 * - For 'modal' and 'drawer' modes: behavior and autoProceedDelay are used as specified
 *
 * The actual type would be the following, but we use the flat interface for simplicity:
 * export interface ConfirmationConfig {
 *   uiMode: 'none' | 'modal' | 'drawer'
 *
 * }
 */
export type ConfirmationUIMode = 'none' | 'modal' | 'drawer';
export type ConfirmationBehavior = 'requireClick' | 'skipClick';
export interface ConfirmationConfig {
  /** Type of UI to display for confirmation: 'none' | 'modal' | 'drawer' */
  uiMode: ConfirmationUIMode;
  /** How the confirmation UI behaves: 'requireClick' | 'skipClick' */
  behavior: ConfirmationBehavior;
  /** Delay in milliseconds before auto-proceeding (only used with skipClick) */
  autoProceedDelay?: number;
}

export const DEFAULT_CONFIRMATION_CONFIG: ConfirmationConfig = {
  uiMode: 'modal',
  behavior: 'requireClick',
  autoProceedDelay: 0,
};

const WASM_CONFIRMATION_UI_MODE = {
  Skip: 0,
  Modal: 1,
  Drawer: 2,
} as const;

const WASM_CONFIRMATION_BEHAVIOR = {
  RequireClick: 0,
  AutoProceed: 1,
} as const;

// WASM enum values for confirmation configuration.
export type WasmConfirmationUIMode =
  (typeof WASM_CONFIRMATION_UI_MODE)[keyof typeof WASM_CONFIRMATION_UI_MODE];
export type WasmConfirmationBehavior =
  (typeof WASM_CONFIRMATION_BEHAVIOR)[keyof typeof WASM_CONFIRMATION_BEHAVIOR];

function assertNeverSignerWorkerConfirmation(value: never): never {
  throw new Error(`Unsupported confirmation option: ${String(value)}`);
}

// Mapping functions to convert string literals to numeric enum values
export const mapUIModeToWasm = (uiMode: ConfirmationUIMode): number => {
  switch (uiMode) {
    case 'none':
      return WASM_CONFIRMATION_UI_MODE.Skip;
    case 'modal':
      return WASM_CONFIRMATION_UI_MODE.Modal;
    // Drawer now has a dedicated WASM enum variant
    case 'drawer':
      return WASM_CONFIRMATION_UI_MODE.Drawer;
    default:
      return assertNeverSignerWorkerConfirmation(uiMode);
  }
};

export const mapBehaviorToWasm = (behavior: ConfirmationBehavior): number => {
  switch (behavior) {
    case 'requireClick':
      return WASM_CONFIRMATION_BEHAVIOR.RequireClick;
    case 'skipClick':
      return WASM_CONFIRMATION_BEHAVIOR.AutoProceed;
    default:
      return assertNeverSignerWorkerConfirmation(behavior);
  }
};
export type WasmRequestResult =
  | WasmSignedTransaction
  | WasmSignedDelegate
  | WasmTransactionSignResult
  | WasmDelegateSignResult;

export interface SignerWorkerMessage<
  T extends SignerWorkerRequestType,
  R extends WasmRequestPayload,
> {
  type: T;
  payload: R;
}

/**
 * =============================
 * Worker Progress Message Types
 * =============================
 *
 * 1. PROGRESS MESSAGES (During Operation):
 *    Rust WASM → send_typed_progress_message() → TypeScript sendProgressMessage() → postMessage() → Main Thread
 *    - Used for real-time updates during long operations
 *    - Multiple progress messages can be sent per operation
 *    - Does not affect the final result
 *    - Types: ProgressMessageType, ProgressStep, ProgressStatus (auto-generated from Rust)
 *
 * 2. FINAL RESULTS (Operation Complete):
 *    Rust WASM → return value from handle_signer_message() → TypeScript worker → postMessage() → Main Thread
 *    - Contains the actual operation result (success/error)
 *    - Only one result message per operation
 *    - This is what the main thread awaits for completion
 */

// === PROGRESS MESSAGE TYPES ===

// Basic interface for development - actual types are auto-generated from Rust
export type ProgressMessage = wasmModule.WorkerProgressMessage;

// Type guard for basic progress message validation during development
export function isProgressMessage(obj: unknown): obj is ProgressMessage {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof (obj as { message_type?: unknown }).message_type === 'string' &&
    typeof (obj as { step?: unknown }).step === 'string' &&
    typeof (obj as { message?: unknown }).message === 'string' &&
    typeof (obj as { status?: unknown }).status === 'string'
  );
}

export enum ProgressMessageType {
  REGISTRATION_PROGRESS = 'REGISTRATION_PROGRESS',
  REGISTRATION_COMPLETE = 'REGISTRATION_COMPLETE',
  EXECUTE_ACTIONS_PROGRESS = 'EXECUTE_ACTIONS_PROGRESS',
  EXECUTE_ACTIONS_COMPLETE = 'EXECUTE_ACTIONS_COMPLETE',
}

// Step identifiers for progress tracking
// This enum exactly matches the Rust WASM ProgressStep enum from:
// packages/passkey/wasm/near_signer/src/types/progress.rs
// The string values come from the progress_step_name() function in that file
export enum ProgressStep {
  PREPARATION = 'preparation', // Rust: Preparation
  WEBAUTHN_AUTHENTICATION = 'webauthn-authentication', // Rust: WebauthnAuthentication
  AUTHENTICATION_COMPLETE = 'authentication-complete', // Rust: AuthenticationComplete
  TRANSACTION_SIGNING_PROGRESS = 'transaction-signing-progress', // Rust: TransactionSigningProgress
  TRANSACTION_SIGNING_COMPLETE = 'transaction-signing-complete', // Rust: TransactionSigningComplete
  ERROR = 'error', // Rust: Error
}

export type NearWorkerProgressStatus = 'progress' | 'success' | 'error';

export interface NearWorkerProgressEvent {
  step: number;
  phase: string;
  status: NearWorkerProgressStatus;
  message: string;
  data?: Record<string, unknown>;
  logs?: string[];
}

export interface ProgressStepMap {
  [wasmModule.ProgressStep.Preparation]: ProgressStep.PREPARATION;
  [wasmModule.ProgressStep.WebauthnAuthentication]: ProgressStep.WEBAUTHN_AUTHENTICATION;
  [wasmModule.ProgressStep.AuthenticationComplete]: ProgressStep.AUTHENTICATION_COMPLETE;
  [wasmModule.ProgressStep.TransactionSigningProgress]: ProgressStep.TRANSACTION_SIGNING_PROGRESS;
  [wasmModule.ProgressStep.TransactionSigningComplete]: ProgressStep.TRANSACTION_SIGNING_COMPLETE;
  [wasmModule.ProgressStep.Error]: ProgressStep.ERROR;
}

// === RESPONSE MESSAGE INTERFACES ===

// Base interface for all worker responses
export interface BaseWorkerResponse<TPayload = unknown> {
  type: SignerWorkerResponseType;
  payload: TPayload;
}

// Map request types to their expected success response payloads (WASM types)
export interface RequestResponseMap {
  [WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare]: WasmDeriveThresholdEd25519ClientVerifyingShareResult;
  [WorkerRequestType.DeriveThresholdEd25519HssClientInputs]: WasmDeriveThresholdEd25519HssClientInputsResult;
  [WorkerRequestType.PrepareThresholdEd25519HssSession]: WasmPrepareThresholdEd25519HssSessionResult;
  [WorkerRequestType.PrepareThresholdEd25519HssClientRequest]: WasmPrepareThresholdEd25519HssClientRequestResult;
  [WorkerRequestType.OpenThresholdEd25519HssSeedOutput]: WasmOpenThresholdEd25519HssSeedOutputResult;
  [WorkerRequestType.BuildThresholdEd25519SeedExportArtifact]: WasmBuildThresholdEd25519SeedExportArtifactResult;
  [WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap]: WasmPrepareThresholdEcdsaHssRoleLocalClientBootstrapResult;
  [WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap]: WasmFinalizeThresholdEcdsaHssRoleLocalClientBootstrapResult;
  [WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact]: WasmBuildThresholdEcdsaHssRoleLocalExportArtifactResult;
  [WorkerRequestType.SignTransactionsWithActions]: WasmTransactionSignResult;
  [WorkerRequestType.SignDelegateAction]: WasmDelegateSignResult;
  [WorkerRequestType.SignNep413Message]: wasmModule.SignNep413Result;
}

export type RequestTypeKey = keyof RequestResponseMap;

// Generic success response type that uses WASM types
export interface WorkerSuccessResponse<T extends RequestTypeKey> extends BaseWorkerResponse<
  RequestResponseMap[T]
> {
  type: SignerWorkerResponseType;
  diagnostics?: WorkerResponseDiagnostics;
}

export type WorkerResponseDiagnostics = {
  kind: 'worker_response_diagnostics_v1';
  worker: 'hssClient';
  requestType: number;
  queueWaitMs: number;
  wasmInitWaitMs: number;
  wasmCallMs: number;
  totalMs: number;
  requestPayloadBytes: number;
  responsePayloadBytes: number;
  requestPayloadBreakdown: Record<string, number>;
  responsePayloadBreakdown: Record<string, number>;
  wasmOperationTimings?: Record<string, number>;
};

// Generic error response type
export interface WorkerErrorResponse extends BaseWorkerResponse<{
  error: string;
  errorCode?: WorkerErrorCode;
  context?: Record<string, unknown>;
}> {
  type: SignerWorkerResponseType;
}

export enum WorkerErrorCode {
  WASM_INIT_FAILED = 'WASM_INIT_FAILED',
  INVALID_REQUEST = 'INVALID_REQUEST',
  TIMEOUT = 'TIMEOUT',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  SIGNING_FAILED = 'SIGNING_FAILED',
  STORAGE_FAILED = 'STORAGE_FAILED',
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

export interface WorkerProgressResponse extends BaseWorkerResponse<NearWorkerProgressEvent> {
  type: SignerWorkerResponseType;
}

// === MAIN RESPONSE TYPE ===

export type WorkerResponseForRequest<T extends RequestTypeKey> =
  | WorkerSuccessResponse<T>
  | WorkerErrorResponse
  | WorkerProgressResponse;

// === CONVENIENCE TYPE ALIASES ===

export type TransactionResponse = WorkerResponseForRequest<
  typeof WorkerRequestType.SignTransactionsWithActions
>;
export type DelegateSignResponse = WorkerResponseForRequest<
  typeof WorkerRequestType.SignDelegateAction
>;
export type Nep413SigningResponse = WorkerResponseForRequest<
  typeof WorkerRequestType.SignNep413Message
>;

// === TYPE GUARDS FOR GENERIC RESPONSES ===

export function isWorkerProgress<T extends RequestTypeKey>(
  response: WorkerResponseForRequest<T>,
): response is WorkerProgressResponse {
  return (
    response.type === WorkerResponseType.RegistrationProgress ||
    response.type === WorkerResponseType.RegistrationComplete ||
    response.type === WorkerResponseType.ExecuteActionsProgress ||
    response.type === WorkerResponseType.ExecuteActionsComplete
  );
}

export function isWorkerSuccess<T extends RequestTypeKey>(
  response: WorkerResponseForRequest<T>,
): response is WorkerSuccessResponse<T> {
  return (
    response.type === WorkerResponseType.SignTransactionsWithActionsSuccess ||
    response.type === WorkerResponseType.SignDelegateActionSuccess ||
    response.type === WorkerResponseType.SignNep413MessageSuccess ||
    response.type === WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareSuccess ||
    response.type === WorkerResponseType.DeriveThresholdEd25519HssClientInputsSuccess ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess ||
    response.type === WorkerResponseType.OpenThresholdEd25519HssSeedOutputSuccess ||
    response.type === WorkerResponseType.BuildThresholdEd25519SeedExportArtifactSuccess ||
    response.type === WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess ||
    response.type === WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess ||
    response.type === WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess
  );
}

export function isWorkerError<T extends RequestTypeKey>(
  response: WorkerResponseForRequest<T>,
): response is WorkerErrorResponse {
  return (
    response.type === WorkerResponseType.SignTransactionsWithActionsFailure ||
    response.type === WorkerResponseType.SignDelegateActionFailure ||
    response.type === WorkerResponseType.SignNep413MessageFailure ||
    response.type === WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareFailure ||
    response.type === WorkerResponseType.DeriveThresholdEd25519HssClientInputsFailure ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssSessionFailure ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssClientRequestFailure ||
    response.type === WorkerResponseType.OpenThresholdEd25519HssSeedOutputFailure ||
    response.type === WorkerResponseType.BuildThresholdEd25519SeedExportArtifactFailure ||
    response.type === WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapFailure ||
    response.type === WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapFailure ||
    response.type === WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactFailure
  );
}

// === SPECIFIC TYPE GUARDS FOR COMMON OPERATIONS ===

export function isSignTransactionsWithActionsSuccess(
  response: TransactionResponse,
): response is WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions> {
  return response.type === WorkerResponseType.SignTransactionsWithActionsSuccess;
}

export function isSignDelegateActionSuccess(
  response: DelegateSignResponse,
): response is WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction> {
  return response.type === WorkerResponseType.SignDelegateActionSuccess;
}

export function isSignNep413MessageSuccess(
  response: Nep413SigningResponse,
): response is WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message> {
  return response.type === WorkerResponseType.SignNep413MessageSuccess;
}
