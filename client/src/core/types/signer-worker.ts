// === IMPORT AUTO-GENERATED WASM TYPES ===
// These are the source of truth generated from Rust structs via wasm-bindgen
// Import as instance types from the WASM module classes
import * as wasmModule from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  WorkerRequestType,
  WorkerResponseType,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
export { WorkerRequestType, WorkerResponseType }; // Export the WASM enums directly

import type { StripFree } from './index.js';
import type { TransactionContext } from './rpc.js';
import type { ActionArgsWasm } from './actions.js';

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

export type SignerWorkerRequestType = WorkerRequestType;
export type SignerWorkerResponseType = WorkerResponseType;

export interface ThresholdSignerConfig {
  /** Base URL of the relayer server (e.g. https://relay.example.com) */
  relayerUrl: string;
  /** Identifies which relayer-held key share to use */
  relayerKeyId: string;
  /** Client base share reconstructed from the single-key ed25519-hss ceremony. */
  xClientBaseB64u?: string;
  /** FROST participant identifier used for the client share (2P only, optional). */
  clientParticipantId?: number;
  /** FROST participant identifier used for the relayer share (2P only, optional). */
  relayerParticipantId?: number;
  /** Optional participant ids (signer set) associated with this threshold key/session. */
  participantIds?: number[];
  /**
   * Optional short-lived authorization token returned by `/threshold-ed25519/authorize`.
   * When omitted, the signer worker will call `/threshold-ed25519/authorize` on-demand per signature.
   */
  mpcSessionId?: string;
  /**
   * Optional session policy JSON (serialized) used to mint a relayer threshold session token.
   * When provided alongside a WebAuthn credential whose challenge is `sessionPolicyDigest32`,
   * the signer worker may call `/threshold-ed25519/session` to obtain a JWT/cookie for session-style signing.
   */
  thresholdSessionPolicyJson?: string;
  /**
   * Optional bearer token returned by `POST /threshold-ed25519/session`.
   * When present, the signer worker uses it to authenticate `/threshold-ed25519/authorize` requests.
   */
  thresholdSessionAuthToken?: string;
  /**
   * Preferred session token delivery mechanism for `/threshold-ed25519/session`.
   * - `jwt` (default): return token in JSON and use Authorization: Bearer on subsequent requests.
   * - `cookie`: set HttpOnly cookie (same-site only).
   */
  thresholdSessionKind?: 'jwt' | 'cookie';
}

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
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  sessionId: string;
  prfFirstB64u?: string;
}
export interface WasmDeriveThresholdEd25519HssClientInputsResult {
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
}
export interface WasmPrepareThresholdEd25519HssSessionRequest {
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
}
export interface WasmPrepareThresholdEd25519HssSessionResult {
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
}
export interface WasmPrepareThresholdEd25519HssClientRequestRequest {
  evaluatorDriverStateB64u: string;
  clientOtOfferMessageB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
}
export interface WasmPrepareThresholdEd25519HssClientRequestResult {
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u: string;
}
export interface WasmDeriveThresholdEd25519HssClientOutputMaskRequest {
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  contextBindingB64u: string;
  operation: string;
  relayerKeyId: string;
  clientRecoverableSecretB64u: string;
}
export interface WasmDeriveThresholdEd25519HssClientOutputMaskResult {
  clientOutputMaskB64u: string;
}
export interface WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest {
  evaluatorDriverStateB64u: string;
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u: string;
  serverInputDeliveryB64u: string;
  clientOutputMaskB64u: string;
}
export interface WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactResult {
  contextBindingB64u: string;
  stagedEvaluatorArtifactB64u: string;
}
export interface WasmOpenThresholdEd25519HssClientOutputRequest {
  evaluatorDriverStateB64u: string;
  clientOutputMessageB64u: string;
  clientOutputMaskB64u: string;
}
export interface WasmOpenThresholdEd25519HssClientOutputResult {
  contextBindingB64u: string;
  xClientBaseB64u: string;
}
export interface WasmOpenThresholdEd25519HssSeedOutputRequest {
  evaluatorDriverStateB64u: string;
  seedOutputMessageB64u: string;
}
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
export interface WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapRequest {
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
}
export interface WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapResult {
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
  contextBinding32B64u: string;
  clientShare32B64u: string;
  clientPublicKey33B64u: string;
  clientShareRetryCounter: number;
  mappedPrivateShare32B64u: string;
  verifyingShare33B64u: string;
}
export interface WasmBuildThresholdEcdsaHssRoleLocalExportArtifactRequest {
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  serverExportShare32B64u: string;
  contextBinding32B64u: string;
  clientPublicKey33B64u: string;
  relayerPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
  clientShareRetryCounter: number;
}
export interface WasmBuildThresholdEcdsaHssRoleLocalExportArtifactResult {
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}
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

export type WasmGenerateEphemeralNearKeypairRequest = Record<string, never>;

export interface WasmGenerateEphemeralNearKeypairResult {
  publicKey: string;
  privateKey: string;
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
export type WasmExtractCosePublicKeyRequest = StripFree<wasmModule.ExtractCoseRequest>;
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
export interface WasmSignTransactionWithKeyPairRequest {
  nearPrivateKey: string;
  signerAccountId: string;
  receiverId: string;
  nonce: string;
  blockHash: string;
  actions: ActionArgsWasm[];
}

export type WasmRequestPayload =
  | WasmDeriveThresholdEd25519ClientVerifyingShareRequest
  | WasmDeriveThresholdEd25519HssClientInputsRequest
  | WasmPrepareThresholdEd25519HssSessionRequest
  | WasmPrepareThresholdEd25519HssClientRequestRequest
  | WasmDeriveThresholdEd25519HssClientOutputMaskRequest
  | WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest
  | WasmOpenThresholdEd25519HssClientOutputRequest
  | WasmOpenThresholdEd25519HssSeedOutputRequest
  | WasmBuildThresholdEd25519SeedExportArtifactRequest
  | WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapRequest
  | WasmBuildThresholdEcdsaHssRoleLocalExportArtifactRequest
  | WasmSignTransactionsWithActionsRequest
  | WasmGenerateEphemeralNearKeypairRequest
  | WasmSignDelegateActionRequest
  | WasmExtractCosePublicKeyRequest
  | WasmSignNep413MessageRequest
  | WasmSignTransactionWithKeyPairRequest;

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
  [WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask]: {
    type: WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask;
    request: WasmDeriveThresholdEd25519HssClientOutputMaskRequest;
    result: WasmDeriveThresholdEd25519HssClientOutputMaskResult;
  };
  [WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact]: {
    type: WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact;
    request: WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest;
    result: WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactResult;
  };
  [WorkerRequestType.OpenThresholdEd25519HssClientOutput]: {
    type: WorkerRequestType.OpenThresholdEd25519HssClientOutput;
    request: WasmOpenThresholdEd25519HssClientOutputRequest;
    result: WasmOpenThresholdEd25519HssClientOutputResult;
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
  [WorkerRequestType.BuildThresholdEcdsaHssRoleLocalClientBootstrap]: {
    type: WorkerRequestType.BuildThresholdEcdsaHssRoleLocalClientBootstrap;
    request: WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapRequest;
    result: WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapResult;
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
  [WorkerRequestType.GenerateEphemeralNearKeypair]: {
    type: WorkerRequestType.GenerateEphemeralNearKeypair;
    request: WasmGenerateEphemeralNearKeypairRequest;
    result: WasmGenerateEphemeralNearKeypairResult;
  };
  [WorkerRequestType.SignDelegateAction]: {
    type: WorkerRequestType.SignDelegateAction;
    request: WasmSignDelegateActionRequest;
    result: WasmDelegateSignResult;
  };
  [WorkerRequestType.ExtractCosePublicKey]: {
    type: WorkerRequestType.ExtractCosePublicKey;
    request: WasmExtractCosePublicKeyRequest;
    result: wasmModule.CoseExtractionResult;
  };
  [WorkerRequestType.SignTransactionWithKeyPair]: {
    type: WorkerRequestType.SignTransactionWithKeyPair;
    request: WasmSignTransactionWithKeyPairRequest;
    result: WasmTransactionSignResult;
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
      return WASM_CONFIRMATION_UI_MODE.Modal;
  }
};

export const mapBehaviorToWasm = (behavior: ConfirmationBehavior): number => {
  switch (behavior) {
    case 'requireClick':
      return WASM_CONFIRMATION_BEHAVIOR.RequireClick;
    case 'skipClick':
      return WASM_CONFIRMATION_BEHAVIOR.AutoProceed;
    default:
      return WASM_CONFIRMATION_BEHAVIOR.RequireClick;
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
  [WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask]: WasmDeriveThresholdEd25519HssClientOutputMaskResult;
  [WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact]: WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactResult;
  [WorkerRequestType.OpenThresholdEd25519HssClientOutput]: WasmOpenThresholdEd25519HssClientOutputResult;
  [WorkerRequestType.OpenThresholdEd25519HssSeedOutput]: WasmOpenThresholdEd25519HssSeedOutputResult;
  [WorkerRequestType.BuildThresholdEd25519SeedExportArtifact]: WasmBuildThresholdEd25519SeedExportArtifactResult;
  [WorkerRequestType.BuildThresholdEcdsaHssRoleLocalClientBootstrap]: WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapResult;
  [WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact]: WasmBuildThresholdEcdsaHssRoleLocalExportArtifactResult;
  [WorkerRequestType.SignTransactionsWithActions]: WasmTransactionSignResult;
  [WorkerRequestType.GenerateEphemeralNearKeypair]: WasmGenerateEphemeralNearKeypairResult;
  [WorkerRequestType.SignDelegateAction]: WasmDelegateSignResult;
  [WorkerRequestType.ExtractCosePublicKey]: wasmModule.CoseExtractionResult;
  [WorkerRequestType.SignTransactionWithKeyPair]: WasmTransactionSignResult;
  [WorkerRequestType.SignNep413Message]: wasmModule.SignNep413Result;
}

export type RequestTypeKey = keyof RequestResponseMap;

// Generic success response type that uses WASM types
export interface WorkerSuccessResponse<T extends RequestTypeKey> extends BaseWorkerResponse<
  RequestResponseMap[T]
> {
  type: SignerWorkerResponseType;
}

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
export type CoseExtractionResponse = WorkerResponseForRequest<
  typeof WorkerRequestType.ExtractCosePublicKey
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
    response.type === WorkerResponseType.ExtractCosePublicKeySuccess ||
    response.type === WorkerResponseType.SignTransactionWithKeyPairSuccess ||
    response.type === WorkerResponseType.SignNep413MessageSuccess ||
    response.type === WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareSuccess ||
    response.type === WorkerResponseType.DeriveThresholdEd25519HssClientInputsSuccess ||
    response.type === WorkerResponseType.GenerateEphemeralNearKeypairSuccess ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess ||
    response.type === WorkerResponseType.DeriveThresholdEd25519HssClientOutputMaskSuccess ||
    response.type === WorkerResponseType.OpenThresholdEd25519HssClientOutputSuccess ||
    response.type === WorkerResponseType.OpenThresholdEd25519HssSeedOutputSuccess ||
    response.type === WorkerResponseType.BuildThresholdEd25519SeedExportArtifactSuccess ||
    response.type === WorkerResponseType.BuildThresholdEcdsaHssRoleLocalClientBootstrapSuccess ||
    response.type === WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess ||
    response.type === WorkerResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess
  );
}

export function isWorkerError<T extends RequestTypeKey>(
  response: WorkerResponseForRequest<T>,
): response is WorkerErrorResponse {
  return (
    response.type === WorkerResponseType.SignTransactionsWithActionsFailure ||
    response.type === WorkerResponseType.SignDelegateActionFailure ||
    response.type === WorkerResponseType.ExtractCosePublicKeyFailure ||
    response.type === WorkerResponseType.SignTransactionWithKeyPairFailure ||
    response.type === WorkerResponseType.SignNep413MessageFailure ||
    response.type === WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareFailure ||
    response.type === WorkerResponseType.DeriveThresholdEd25519HssClientInputsFailure ||
    response.type === WorkerResponseType.GenerateEphemeralNearKeypairFailure ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssSessionFailure ||
    response.type === WorkerResponseType.PrepareThresholdEd25519HssClientRequestFailure ||
    response.type === WorkerResponseType.DeriveThresholdEd25519HssClientOutputMaskFailure ||
    response.type === WorkerResponseType.OpenThresholdEd25519HssClientOutputFailure ||
    response.type === WorkerResponseType.OpenThresholdEd25519HssSeedOutputFailure ||
    response.type === WorkerResponseType.BuildThresholdEd25519SeedExportArtifactFailure ||
    response.type === WorkerResponseType.BuildThresholdEcdsaHssRoleLocalClientBootstrapFailure ||
    response.type === WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactFailure ||
    response.type === WorkerResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFailure
  );
}

// === SPECIFIC TYPE GUARDS FOR COMMON OPERATIONS ===

export function isSignTransactionsWithActionsSuccess(
  response: TransactionResponse,
): response is WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions> {
  return response.type === WorkerResponseType.SignTransactionsWithActionsSuccess;
}

export function isGenerateEphemeralNearKeypairSuccess(
  response: WorkerResponseForRequest<typeof WorkerRequestType.GenerateEphemeralNearKeypair>,
): response is WorkerSuccessResponse<typeof WorkerRequestType.GenerateEphemeralNearKeypair> {
  return response.type === WorkerResponseType.GenerateEphemeralNearKeypairSuccess;
}

export function isSignDelegateActionSuccess(
  response: DelegateSignResponse,
): response is WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction> {
  return response.type === WorkerResponseType.SignDelegateActionSuccess;
}

export function isExtractCosePublicKeySuccess(
  response: CoseExtractionResponse,
): response is WorkerSuccessResponse<typeof WorkerRequestType.ExtractCosePublicKey> {
  return response.type === WorkerResponseType.ExtractCosePublicKeySuccess;
}

export function isSignNep413MessageSuccess(
  response: Nep413SigningResponse,
): response is WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message> {
  return response.type === WorkerResponseType.SignNep413MessageSuccess;
}
