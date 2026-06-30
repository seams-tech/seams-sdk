/**
 * Enhanced WASM Signer Worker (v2)
 * This worker uses Rust-based message handling for better type safety and performance
 * Similar to the UserConfirm worker architecture
 *
 * MESSAGING FLOW DOCUMENTATION:
 * =============================
 *
 * 1. PROGRESS MESSAGES (During Operation):
 *    Rust WASM calls send_typed_progress_message() →
 *    calls global sendProgressMessage() (defined below) →
 *    postMessage() to main thread with progress update
 *
 *    - Multiple progress messages per operation
 *    - Real-time updates for UX (e.g., "Verifying payload...", "Signing transaction...")
 *    - Does not affect final result
 *
 * 2. FINAL RESULTS (Operation Complete):
 *    Rust WASM returns result from handle_signer_message() →
 *    TypeScript receives return value →
 *    postMessage() to main thread with final result
 *
 *    - One result message per operation
 *    - Contains success/error and actual operation data
 *    - Main thread awaits this for completion
 *
 * TYPE SAFETY:
 * ============
 * All message types are auto-generated from Rust using wasm-bindgen:
 * - ProgressMessageType: VERIFICATION_PROGRESS, SIGNING_PROGRESS, etc.
 * - ProgressStep: preparation, payload_verification, transaction_signing, etc.
 * - ProgressStatus: progress, success, error
 * - WorkerProgressMessage: Complete message structure
 */

import {
  NearSignerWorkerCustomRequestType,
  WorkerRequestType,
  WorkerResponseType,
  type SignerWorkerRequestType,
  type ThresholdEd25519WorkerMaterialFailure,
  WasmRequestPayload,
} from '@/core/types/signer-worker';
// Import WASM binary directly
import init, {
  handle_signer_message,
  threshold_ed25519_build_delegate_signing_payload,
  threshold_ed25519_client_presign_burn,
  threshold_ed25519_client_presign_create_from_worker_material,
  threshold_ed25519_client_presign_sign_from_worker_material,
  threshold_ed25519_role_separated_normal_signing_client_share_from_worker_material,
  threshold_ed25519_sealed_worker_material_delete,
  threshold_ed25519_sealed_worker_material_put,
  threshold_ed25519_sealed_worker_material_read,
  threshold_ed25519_worker_material_restore,
  threshold_ed25519_worker_material_store_from_hss_output,
  threshold_ed25519_worker_material_validate,
  threshold_ed25519_build_near_tx_unsigned_borsh,
  threshold_ed25519_compute_delegate_signing_digest,
  threshold_ed25519_compute_nep413_signing_digest,
  threshold_ed25519_decode_signed_near_tx_borsh,
  threshold_ed25519_finalize_delegate_from_signature,
  threshold_ed25519_finalize_near_tx_from_signature,
  threshold_ed25519_prepare_hss_client_output_mask_handle,
  threshold_ed25519_prepare_passkey_prf_worker_material_seal_authorization,
  threshold_ed25519_prepare_passkey_prf_worker_material_unseal_authorization,
  threshold_ed25519_prepare_recovery_code_worker_material_seal_authorization,
  threshold_ed25519_prepare_recovery_code_worker_material_unseal_authorization,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlEncode } from '@shared/utils/encoders';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import { WorkerControlMessage } from '../workerTypes';

/**
 * WASM Asset Path Resolution for Signer Worker
 *
 * Uses centralized path resolution strategy from walletRuntimePaths/wasm-loader.ts
 * See walletRuntimePaths/wasm-loader.ts for detailed documentation on how paths work across:
 * - SDK building (Rolldown)
 * - Playwright E2E tests
 * - Frontend dev installing from npm
 */

// Resolve WASM URL using the centralized resolution strategy
const wasmUrl = resolveWasmUrl('wasm_signer_worker_bg.wasm', 'Signer Worker');
// UserConfirm bridge removed: signer no longer initiates confirmations

let wasmInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();
let activeRequestId: string | null = null;

/**
 * Function called by WASM to send progress messages
 * This is imported into the WASM module as sendProgressMessage
 *
 * Now receives both numeric enum values AND message string names from Rust
 *
 * @param messageType - Numeric ProgressMessageType enum value
 * @param messageTypeName - String name of the message type for debugging
 * @param step - Numeric ProgressStep enum value
 * @param stepName - String name of the step for debugging
 * @param message - Human-readable progress message
 * @param data - JSON string containing structured data
 * @param logs - Optional JSON string containing array of log messages
 */
function sendProgressMessage(
  messageType: number,
  messageTypeName: string,
  step: number,
  stepName: string,
  message: string,
  data: unknown,
  logs?: unknown,
): void {
  try {
    // Parse structured data and logs using helper if they are strings
    const parsedData = typeof data === 'string' ? safeJsonParse(data, {}) : data || {};
    const parsedLogs = typeof logs === 'string' ? safeJsonParse(logs || '', []) : logs || [];

    // Create a worker-internal progress payload.
    const progressPayload = {
      step: step,
      phase: stepName,
      status:
        messageTypeName === 'REGISTRATION_COMPLETE' ||
        messageTypeName === 'EXECUTE_ACTIONS_COMPLETE'
          ? 'success'
          : 'progress',
      message: message,
      data: parsedData,
      logs: parsedLogs,
    };

    if (!activeRequestId) {
      console.warn('[signer-worker]: Dropping progress message without active request id');
      return;
    }

    self.postMessage({
      id: activeRequestId,
      progress: true,
      payload: progressPayload,
    });
  } catch (error: unknown) {
    console.error('[signer-worker]: Failed to send progress message:', errorLogSummary(error));
    if (!activeRequestId) return;
    self.postMessage({
      id: activeRequestId,
      ok: false,
      error: `Progress message failed: ${safeErrorMessage(error)}`,
      code: 'WORKER_PROTOCOL_ERROR',
    });
  }
}

// Important: Make sendProgressMessage available globally for WASM to call
type NearSignerWorkerGlobal = typeof globalThis & {
  sendProgressMessage?: typeof sendProgressMessage;
};
(globalThis as NearSignerWorkerGlobal).sendProgressMessage = sendProgressMessage;

/**
 * Initialize WASM module
 */
async function initializeWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    try {
      const startedAt = Date.now();
      await init({ module_or_path: wasmUrl });
      console.info('[signer-worker]: WASM initialized', {
        durationMs: Date.now() - startedAt,
        wasmUrl: String(wasmUrl),
      });
    } catch (error: unknown) {
      // Allow retry if init fails (e.g., transient path/config issues during dev).
      wasmInitPromise = null;
      console.error('[signer-worker]: WASM initialization failed:', errorLogSummary(error));
      throw new Error(`WASM initialization failed: ${safeErrorMessage(error)}`);
    }
  })();
  return wasmInitPromise;
}

// Signal readiness so the main thread can health-check persisted worker availability.
// Delay one tick to allow listener registration on main thread
setTimeout(() => {
  self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

/**
 * Process a WASM worker message (main operation)
 */
async function processWorkerMessage(event: MessageEvent): Promise<void> {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    throw new Error('Signer worker request is missing RPC id');
  }

  activeRequestId = requestId;

  try {
    const startedAt = Date.now();
    const requestType = (event.data as { type?: unknown })?.type;
    // Guardrail: raw PRF fields must never traverse into signer payloads
    assertNoPrfSecretsInSignerPayload(event.data);
    await initializeWasm();
    const response =
      typeof requestType === 'string'
        ? await handleCustomNearSignerRequest(
            requestType,
            (event.data as { payload?: unknown }).payload,
          )
        : await handle_signer_message(event.data);
    self.postMessage({
      id: requestId,
      ok: true,
      result: response,
    });
    console.info('[signer-worker]: request complete', {
      requestId,
      requestType,
      durationMs: Date.now() - startedAt,
    });
  } catch (error: unknown) {
    console.error('[signer-worker]: Message processing failed:', errorLogSummary(error));
    self.postMessage({
      id: requestId,
      ok: false,
      error: safeErrorMessage(error),
      code: 'WORKER_RUNTIME_ERROR',
    });
  } finally {
    activeRequestId = null;
  }
}

type SignerWorkerRpcRequest = {
  id: string;
  type: SignerWorkerRequestType;
  payload: WasmRequestPayload | unknown;
};

self.onmessage = async (event: MessageEvent<SignerWorkerRpcRequest>): Promise<void> => {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[signer-worker]: Ignoring message without request id');
    return;
  }
  const eventType = event.data?.type;

  if (typeof eventType !== 'number' && typeof eventType !== 'string') {
    console.warn('[signer-worker]: Ignoring message with invalid type:', eventType);
    return;
  }

  // Serialize worker operations to keep WASM state predictable and to avoid
  // overlapping accesses to PRF-derived material and relayer state.
  messageQueue = messageQueue.catch(() => undefined).then(() => processWorkerMessage(event));
  await messageQueue;
};

async function handleCustomNearSignerRequest(type: string, payload: unknown): Promise<unknown> {
  switch (type) {
    case NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareHssClientOutputMaskHandle:
      return prepareThresholdEd25519HssClientOutputMaskHandle(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519StoreWorkerMaterialFromHssOutput:
      return storeThresholdEd25519WorkerMaterialFromHssOutput(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization:
      return prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization:
      return prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization:
      return prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorization(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization:
      return prepareThresholdEd25519RecoveryCodeWorkerMaterialUnsealAuthorization(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519RestoreWorkerMaterial:
      return restoreThresholdEd25519WorkerMaterial(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519ValidateWorkerMaterial:
      return validateThresholdEd25519WorkerMaterial(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519PutSealedWorkerMaterial:
      return putThresholdEd25519SealedWorkerMaterial(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519ReadSealedWorkerMaterial:
      return readThresholdEd25519SealedWorkerMaterial(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519DeleteSealedWorkerMaterial:
      return deleteThresholdEd25519SealedWorkerMaterial(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreateFromMaterialHandle:
      return createOpaqueClientPresignFromMaterialHandle(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSignFromMaterialHandle:
      return signWithOpaqueClientPresignHandleFromMaterialHandle(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle:
      return createRoleSeparatedNormalSigningClientShareFromMaterialHandle(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn:
      return burnOpaqueClientPresignHandle(payload);
    case NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest:
      return {
        signingDigestB64u: base64UrlEncode(
          threshold_ed25519_compute_nep413_signing_digest(payload),
        ),
      };
    case NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeDelegateSigningDigest:
      return {
        signingDigestB64u: base64UrlEncode(
          threshold_ed25519_compute_delegate_signing_digest(payload),
        ),
      };
    case NearSignerWorkerCustomRequestType.ThresholdEd25519BuildDelegateSigningPayload:
      return requireDelegateSigningPayloadOutput(
        threshold_ed25519_build_delegate_signing_payload(payload),
      );
    case NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature:
      return requireSignedDelegateOutput(
        threshold_ed25519_finalize_delegate_from_signature(payload),
      );
    case NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeNearTxFromSignature:
      return requireFinalizeNearTxFromSignatureOutput(
        threshold_ed25519_finalize_near_tx_from_signature(payload),
      );
    case NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh:
      return requireNearTxUnsignedBorshOutput(
        threshold_ed25519_build_near_tx_unsigned_borsh(payload),
      );
    case NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh:
      return requireSignedNearTxOutput(threshold_ed25519_decode_signed_near_tx_borsh(payload));
    default:
      throw new Error(`Unsupported near signer custom request type: ${type}`);
  }
}

function secretB64uField(prefix: string): string {
  return `${prefix}B64u`;
}

function prepareThresholdEd25519HssClientOutputMaskHandle(payload: unknown): {
  ok: true;
  clientOutputMaskHandle: string;
  contextBindingB64u: string;
  expiresAtMs: number;
  remainingUses: number;
} {
  return threshold_ed25519_prepare_hss_client_output_mask_handle(payload) as {
    ok: true;
    clientOutputMaskHandle: string;
    contextBindingB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  };
}

function storeThresholdEd25519WorkerMaterialFromHssOutput(payload: unknown):
  | {
      ok: true;
      materialHandle: string;
      materialBindingDigest: string;
      sealedWorkerMaterialRef: string;
      sealedWorkerMaterialB64u: string;
      clientVerifyingShareB64u: string;
      materialFormatVersion: string;
      materialKeyId: string;
      signerSlot: number;
    }
  | ThresholdEd25519WorkerMaterialFailure {
  return runMaterialCommand(
    payload,
    threshold_ed25519_worker_material_store_from_hss_output,
    requireStoredMaterialOutput,
  );
}

function restoreThresholdEd25519WorkerMaterial(payload: unknown):
  | {
      ok: true;
      materialHandle: string;
      materialBindingDigest: string;
      clientVerifyingShareB64u: string;
      sealedWorkerMaterialRef: string;
      sealedWorkerMaterialB64u: string;
      materialFormatVersion: string;
      materialKeyId: string;
      signerSlot: number;
    }
  | ThresholdEd25519WorkerMaterialFailure {
  return runMaterialCommand(
    payload,
    threshold_ed25519_worker_material_restore,
    requireRestoredMaterialOutput,
  );
}

function prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorization(payload: unknown): {
  ok: true;
  unsealAuthorization: unknown;
  remainingUses: number;
} {
  return requirePreparedMaterialUnsealAuthorizationOutput(
    threshold_ed25519_prepare_passkey_prf_worker_material_unseal_authorization(payload),
  );
}

function prepareThresholdEd25519RecoveryCodeWorkerMaterialUnsealAuthorization(payload: unknown): {
  ok: true;
  unsealAuthorization: unknown;
  remainingUses: number;
} {
  return requirePreparedMaterialUnsealAuthorizationOutput(
    threshold_ed25519_prepare_recovery_code_worker_material_unseal_authorization(payload),
  );
}

function prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(payload: unknown): {
  ok: true;
  materialKeyId: string;
  sealAuthorization: unknown;
  remainingUses: number;
} {
  return requirePreparedMaterialSealAuthorizationOutput(
    threshold_ed25519_prepare_passkey_prf_worker_material_seal_authorization(payload),
  );
}

function prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization(payload: unknown): {
  ok: true;
  materialKeyId: string;
  sealAuthorization: unknown;
  remainingUses: number;
} {
  return requirePreparedMaterialSealAuthorizationOutput(
    threshold_ed25519_prepare_recovery_code_worker_material_seal_authorization(payload),
  );
}

function validateThresholdEd25519WorkerMaterial(payload: unknown):
  | {
      materialHandle: string;
      clientVerifyingShareB64u: string;
      bindingDigest: string;
    }
  | ThresholdEd25519WorkerMaterialFailure {
  return runMaterialCommand(
    payload,
    threshold_ed25519_worker_material_validate,
    requireValidatedMaterialOutput,
  );
}

function putThresholdEd25519SealedWorkerMaterial(payload: unknown):
  | {
      ok: true;
      sealedWorkerMaterialRef: string;
      materialBindingDigest: string;
    }
  | ThresholdEd25519WorkerMaterialFailure {
  return runMaterialCommand(
    payload,
    threshold_ed25519_sealed_worker_material_put,
    requirePutSealedMaterialOutput,
  );
}

function readThresholdEd25519SealedWorkerMaterial(payload: unknown):
  | {
      ok: true;
      sealedMaterial: unknown;
    }
  | ThresholdEd25519WorkerMaterialFailure {
  return runMaterialCommand(
    payload,
    threshold_ed25519_sealed_worker_material_read,
    requireReadSealedMaterialOutput,
  );
}

function deleteThresholdEd25519SealedWorkerMaterial(payload: unknown):
  | {
      ok: true;
      deleted: boolean;
    }
  | ThresholdEd25519WorkerMaterialFailure {
  return runMaterialCommand(
    payload,
    threshold_ed25519_sealed_worker_material_delete,
    requireDeleteSealedMaterialOutput,
  );
}

function runMaterialCommand<T>(
  payload: unknown,
  wasmOperation: (payload: unknown) => unknown,
  parseOutput: (output: unknown) => T,
): T | ThresholdEd25519WorkerMaterialFailure {
  try {
    return parseOutput(wasmOperation(payload));
  } catch (error: unknown) {
    const failure = materialFailureFromError(error);
    if (failure) return failure;
    throw error;
  }
}

function materialFailureFromError(error: unknown): ThresholdEd25519WorkerMaterialFailure | null {
  const message = materialErrorMessage(error).trim();
  const code = materialErrorCodeFromMessage(message);
  if (!code) return null;
  return { ok: false, code, message };
}

function materialErrorMessage(error: unknown): string {
  if (typeof error === 'string') return safeErrorMessage(error);
  if (error instanceof Error) return safeErrorMessage(error);
  const maybeMessage = (error as { message?: unknown } | null)?.message;
  if (typeof maybeMessage === 'string') return safeErrorMessage(maybeMessage);
  return safeErrorMessage(error);
}

function materialErrorCodeFromMessage(
  message: string,
): ThresholdEd25519WorkerMaterialFailure['code'] | null {
  const prefix = message.split(':', 1)[0]?.trim();
  switch (prefix) {
    case 'material_restore_required':
    case 'material_seal_authorization_required':
    case 'material_unseal_authorization_required':
    case 'material_restore_expired':
    case 'material_binding_mismatch':
    case 'material_scope_mismatch':
    case 'material_handle_not_loaded':
    case 'material_corrupt':
    case 'worker_unavailable':
      return prefix;
    case 'Ed25519 worker material handle is not loaded in this worker':
      return 'material_handle_not_loaded';
    case 'Ed25519 worker material handle binding mismatch':
    case 'Ed25519 worker material binding digest mismatch':
    case 'Ed25519 worker material verifying-share binding mismatch':
    case 'Ed25519 sealed worker material binding digest mismatch':
      return 'material_binding_mismatch';
    default:
      return null;
  }
}

function requirePreparedMaterialUnsealAuthorizationOutput(output: unknown): {
  ok: true;
  unsealAuthorization: unknown;
  remainingUses: number;
} {
  const parsed = output as {
    ok?: unknown;
    unsealAuthorization?: unknown;
    remainingUses?: unknown;
  };
  const remainingUses = Math.floor(Number(parsed?.remainingUses) || 0);
  if (
    parsed?.ok !== true ||
    !parsed.unsealAuthorization ||
    typeof parsed.unsealAuthorization !== 'object' ||
    remainingUses <= 0
  ) {
    throw new Error(
      'threshold_ed25519_prepare_material_unseal_authorization returned invalid output',
    );
  }
  return { ok: true, unsealAuthorization: parsed.unsealAuthorization, remainingUses };
}

function requirePreparedMaterialSealAuthorizationOutput(output: unknown): {
  ok: true;
  materialKeyId: string;
  sealAuthorization: unknown;
  remainingUses: number;
} {
  const parsed = output as {
    ok?: unknown;
    materialKeyId?: unknown;
    sealAuthorization?: unknown;
    remainingUses?: unknown;
  };
  const materialKeyId = String(parsed?.materialKeyId || '').trim();
  const remainingUses = Math.floor(Number(parsed?.remainingUses) || 0);
  if (
    parsed?.ok !== true ||
    !materialKeyId ||
    !parsed.sealAuthorization ||
    typeof parsed.sealAuthorization !== 'object' ||
    remainingUses <= 0
  ) {
    throw new Error(
      'threshold_ed25519_prepare_worker_material_seal_authorization returned invalid output',
    );
  }
  return {
    ok: true,
    materialKeyId,
    sealAuthorization: parsed.sealAuthorization,
    remainingUses,
  };
}

function createOpaqueClientPresignFromMaterialHandle(payload: unknown): {
  clientNonceHandleB64u: string;
  clientVerifyingShareB64u: string;
  clientCommitments: { hiding: string; binding: string };
} {
  return requireClientPresignCreateOutput(
    threshold_ed25519_client_presign_create_from_worker_material(payload),
  );
}

function signWithOpaqueClientPresignHandleFromMaterialHandle(payload: unknown): {
  clientSignatureShareB64u: string;
} {
  return requireClientPresignSignOutput(
    threshold_ed25519_client_presign_sign_from_worker_material(payload),
  );
}

function createRoleSeparatedNormalSigningClientShareFromMaterialHandle(payload: unknown): {
  clientCommitments: { hiding: string; binding: string };
  clientVerifyingShareB64u: string;
  clientSignatureShareB64u: string;
} {
  return requireRoleSeparatedNormalSigningClientShareOutput(
    threshold_ed25519_role_separated_normal_signing_client_share_from_worker_material(payload),
  );
}

function burnOpaqueClientPresignHandle(payload: unknown): { burned: true } {
  threshold_ed25519_client_presign_burn(payload);
  return { burned: true };
}

function requireClientPresignCreateOutput(output: unknown): {
  clientNonceHandleB64u: string;
  clientVerifyingShareB64u: string;
  clientCommitments: { hiding: string; binding: string };
} {
  const parsed = output as {
    clientNonceHandleB64u?: unknown;
    clientVerifyingShareB64u?: unknown;
    clientCommitments?: { hiding?: unknown; binding?: unknown };
  };
  const clientNonceHandleB64u = String(parsed?.clientNonceHandleB64u || '').trim();
  const clientVerifyingShareB64u = String(parsed?.clientVerifyingShareB64u || '').trim();
  const hiding = String(parsed?.clientCommitments?.hiding || '').trim();
  const binding = String(parsed?.clientCommitments?.binding || '').trim();
  if (!clientNonceHandleB64u || !clientVerifyingShareB64u || !hiding || !binding) {
    throw new Error(
      'threshold_ed25519_client_presign_create_from_worker_material returned invalid output',
    );
  }
  return {
    clientNonceHandleB64u,
    clientVerifyingShareB64u,
    clientCommitments: { hiding, binding },
  };
}

function requireStoredMaterialOutput(output: unknown): {
  ok: true;
  materialHandle: string;
  materialBindingDigest: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  clientVerifyingShareB64u: string;
  materialFormatVersion: string;
  materialKeyId: string;
  signerSlot: number;
} {
  const parsed = output as {
    ok?: unknown;
    materialHandle?: unknown;
    materialBindingDigest?: unknown;
    sealedWorkerMaterialRef?: unknown;
    sealedWorkerMaterialB64u?: unknown;
    clientVerifyingShareB64u?: unknown;
    materialFormatVersion?: unknown;
    materialKeyId?: unknown;
    signerSlot?: unknown;
  };
  const materialHandle = String(parsed?.materialHandle || '').trim();
  const materialBindingDigest = String(parsed?.materialBindingDigest || '').trim();
  const sealedWorkerMaterialRef = String(parsed?.sealedWorkerMaterialRef || '').trim();
  const sealedWorkerMaterialB64u = String(parsed?.sealedWorkerMaterialB64u || '').trim();
  const clientVerifyingShareB64u = String(parsed?.clientVerifyingShareB64u || '').trim();
  const materialFormatVersion = String(parsed?.materialFormatVersion || '').trim();
  const materialKeyId = String(parsed?.materialKeyId || '').trim();
  const signerSlot = Math.floor(Number(parsed?.signerSlot) || 0);
  if (
    parsed?.ok !== true ||
    !materialHandle ||
    !materialBindingDigest ||
    !sealedWorkerMaterialRef ||
    !sealedWorkerMaterialB64u ||
    !clientVerifyingShareB64u ||
    !materialFormatVersion ||
    !materialKeyId ||
    signerSlot <= 0
  ) {
    throw new Error('threshold_ed25519_worker_material returned invalid output');
  }
  return {
    ok: true,
    materialHandle,
    materialBindingDigest,
    sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u,
    clientVerifyingShareB64u,
    materialFormatVersion,
    materialKeyId,
    signerSlot,
  };
}

function requireValidatedMaterialOutput(output: unknown): {
  materialHandle: string;
  clientVerifyingShareB64u: string;
  bindingDigest: string;
} {
  const parsed = output as {
    materialHandle?: unknown;
    clientVerifyingShareB64u?: unknown;
    bindingDigest?: unknown;
  };
  const materialHandle = String(parsed?.materialHandle || '').trim();
  const clientVerifyingShareB64u = String(parsed?.clientVerifyingShareB64u || '').trim();
  const bindingDigest = String(parsed?.bindingDigest || '').trim();
  if (!materialHandle || !clientVerifyingShareB64u || !bindingDigest) {
    throw new Error('threshold_ed25519_worker_material_validate returned invalid output');
  }
  return { materialHandle, clientVerifyingShareB64u, bindingDigest };
}

function requireRestoredMaterialOutput(output: unknown): {
  ok: true;
  materialHandle: string;
  materialBindingDigest: string;
  clientVerifyingShareB64u: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: string;
  materialKeyId: string;
  signerSlot: number;
} {
  const parsed = output as {
    ok?: unknown;
    materialHandle?: unknown;
    materialBindingDigest?: unknown;
    clientVerifyingShareB64u?: unknown;
    sealedWorkerMaterialRef?: unknown;
    sealedWorkerMaterialB64u?: unknown;
    materialFormatVersion?: unknown;
    materialKeyId?: unknown;
    signerSlot?: unknown;
  };
  const materialHandle = String(parsed?.materialHandle || '').trim();
  const materialBindingDigest = String(parsed?.materialBindingDigest || '').trim();
  const clientVerifyingShareB64u = String(parsed?.clientVerifyingShareB64u || '').trim();
  const sealedWorkerMaterialRef = String(parsed?.sealedWorkerMaterialRef || '').trim();
  const sealedWorkerMaterialB64u = String(parsed?.sealedWorkerMaterialB64u || '').trim();
  const materialFormatVersion = String(parsed?.materialFormatVersion || '').trim();
  const materialKeyId = String(parsed?.materialKeyId || '').trim();
  const signerSlot = Math.floor(Number(parsed?.signerSlot) || 0);
  if (
    parsed?.ok !== true ||
    !materialHandle ||
    !materialBindingDigest ||
    !clientVerifyingShareB64u ||
    !sealedWorkerMaterialRef ||
    !sealedWorkerMaterialB64u ||
    !materialFormatVersion ||
    !materialKeyId ||
    signerSlot <= 0
  ) {
    throw new Error('threshold_ed25519_worker_material_restore returned invalid output');
  }
  return {
    ok: true,
    materialHandle,
    materialBindingDigest,
    clientVerifyingShareB64u,
    sealedWorkerMaterialRef,
    sealedWorkerMaterialB64u,
    materialFormatVersion,
    materialKeyId,
    signerSlot,
  };
}

function requirePutSealedMaterialOutput(output: unknown): {
  ok: true;
  sealedWorkerMaterialRef: string;
  materialBindingDigest: string;
} {
  const parsed = output as {
    ok?: unknown;
    sealedWorkerMaterialRef?: unknown;
    materialBindingDigest?: unknown;
  };
  const sealedWorkerMaterialRef = String(parsed?.sealedWorkerMaterialRef || '').trim();
  const materialBindingDigest = String(parsed?.materialBindingDigest || '').trim();
  if (parsed?.ok !== true || !sealedWorkerMaterialRef || !materialBindingDigest) {
    throw new Error('threshold_ed25519_sealed_worker_material_put returned invalid output');
  }
  return { ok: true, sealedWorkerMaterialRef, materialBindingDigest };
}

function requireReadSealedMaterialOutput(output: unknown): {
  ok: true;
  sealedMaterial: unknown;
} {
  const parsed = output as { ok?: unknown; sealedMaterial?: unknown };
  if (parsed?.ok !== true || !parsed.sealedMaterial || typeof parsed.sealedMaterial !== 'object') {
    throw new Error('threshold_ed25519_sealed_worker_material_read returned invalid output');
  }
  return { ok: true, sealedMaterial: parsed.sealedMaterial };
}

function requireDeleteSealedMaterialOutput(output: unknown): {
  ok: true;
  deleted: boolean;
} {
  const parsed = output as { ok?: unknown; deleted?: unknown };
  if (parsed?.ok !== true || typeof parsed.deleted !== 'boolean') {
    throw new Error('threshold_ed25519_sealed_worker_material_delete returned invalid output');
  }
  return { ok: true, deleted: parsed.deleted };
}

function requireClientPresignSignOutput(output: unknown): { clientSignatureShareB64u: string } {
  const clientSignatureShareB64u = String(
    (output as { clientSignatureShareB64u?: unknown })?.clientSignatureShareB64u || '',
  ).trim();
  if (!clientSignatureShareB64u) {
    throw new Error(
      'threshold_ed25519_client_presign_sign_from_worker_material returned invalid output',
    );
  }
  return { clientSignatureShareB64u };
}

function requireRoleSeparatedNormalSigningClientShareOutput(output: unknown): {
  clientCommitments: { hiding: string; binding: string };
  clientVerifyingShareB64u: string;
  clientSignatureShareB64u: string;
} {
  const parsed = output as {
    clientCommitments?: { hiding?: unknown; binding?: unknown };
    clientVerifyingShareB64u?: unknown;
    clientSignatureShareB64u?: unknown;
  };
  const hiding = String(parsed?.clientCommitments?.hiding || '').trim();
  const binding = String(parsed?.clientCommitments?.binding || '').trim();
  const clientVerifyingShareB64u = String(parsed?.clientVerifyingShareB64u || '').trim();
  const clientSignatureShareB64u = String(parsed?.clientSignatureShareB64u || '').trim();
  if (!hiding || !binding || !clientVerifyingShareB64u || !clientSignatureShareB64u) {
    throw new Error('threshold_ed25519_role_separated_normal_signing returned invalid output');
  }
  return {
    clientCommitments: { hiding, binding },
    clientVerifyingShareB64u,
    clientSignatureShareB64u,
  };
}

function requireSignedDelegateOutput(output: unknown): unknown {
  const parsed = output as { delegateAction?: unknown; signature?: unknown; borshBytes?: unknown };
  if (!parsed?.delegateAction || !parsed.signature || !parsed.borshBytes) {
    throw new Error('threshold_ed25519_finalize_delegate_from_signature returned invalid output');
  }
  return output;
}

function requireDelegateSigningPayloadOutput(output: unknown): {
  canonicalDelegateBorshB64u: string;
  signingDigestB64u: string;
} {
  const parsed = output as {
    canonicalDelegateBorshB64u?: unknown;
    signingDigestB64u?: unknown;
  };
  const canonicalDelegateBorshB64u = String(parsed?.canonicalDelegateBorshB64u || '').trim();
  const signingDigestB64u = String(parsed?.signingDigestB64u || '').trim();
  if (!canonicalDelegateBorshB64u || !signingDigestB64u) {
    throw new Error('threshold_ed25519_build_delegate_signing_payload returned invalid output');
  }
  return { canonicalDelegateBorshB64u, signingDigestB64u };
}

function requireFinalizeNearTxFromSignatureOutput(output: unknown): {
  signedTransactionBorshB64u: string;
  transactionHash: string;
} {
  const parsed = output as {
    signedTransactionBorshB64u?: unknown;
    transactionHash?: unknown;
  };
  const signedTransactionBorshB64u = String(parsed?.signedTransactionBorshB64u || '').trim();
  const transactionHash = String(parsed?.transactionHash || '').trim();
  if (!signedTransactionBorshB64u || !transactionHash) {
    throw new Error('threshold_ed25519_finalize_near_tx_from_signature returned invalid output');
  }
  return { signedTransactionBorshB64u, transactionHash };
}

function requireNearTxUnsignedBorshOutput(output: unknown): {
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
}[] {
  if (!Array.isArray(output)) {
    throw new Error('threshold_ed25519_build_near_tx_unsigned_borsh returned invalid output');
  }
  return output.map((item) => {
    const parsed = item as {
      unsignedTransactionBorshB64u?: unknown;
      signingDigestB64u?: unknown;
    };
    const unsignedTransactionBorshB64u = String(parsed?.unsignedTransactionBorshB64u || '').trim();
    const signingDigestB64u = String(parsed?.signingDigestB64u || '').trim();
    if (!unsignedTransactionBorshB64u || !signingDigestB64u) {
      throw new Error('threshold_ed25519_build_near_tx_unsigned_borsh returned invalid item');
    }
    return { unsignedTransactionBorshB64u, signingDigestB64u };
  });
}

function requireSignedNearTxOutput(output: unknown): unknown {
  const parsed = output as {
    signedTransaction?: { transaction?: unknown; signature?: unknown; borshBytes?: unknown };
    transactionHash?: unknown;
  };
  if (
    !parsed?.signedTransaction?.transaction ||
    !parsed.signedTransaction.signature ||
    !parsed.signedTransaction.borshBytes ||
    !String(parsed.transactionHash || '').trim()
  ) {
    throw new Error('threshold_ed25519_decode_signed_near_tx_borsh returned invalid output');
  }
  return output;
}

function assertNoPrfSecretsInSignerPayload(data: unknown): void {
  const payload =
    data && typeof data === 'object' ? (data as { payload?: unknown }).payload : undefined;
  if (!payload || typeof payload !== 'object') return;
  const payloadRecord = payload as Record<string, unknown>;
  const forbiddenKeys = [
    'prfOutput',
    'prf_output',
    'prfFirst',
    'prf_first',
    secretB64uField('prfFirst'),
    'prf_first_b64u',
    'prf',
    'nearPrivateKey',
    'privateKey',
    secretB64uField('xClientBase'),
    secretB64uField('clientOutputMask'),
    secretB64uField('canonicalSeed'),
    secretB64uField('seed'),
    secretB64uField('signingShare32'),
  ];
  for (const key of forbiddenKeys) {
    if (payloadRecord[key] !== undefined) {
      throw new Error(`Forbidden secret field in signer payload: ${key}`);
    }
  }
}

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[signer-worker]: error:', {
    message: safeErrorMessage(typeof message === 'string' ? message : 'Unknown error'),
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: errorLogSummary(error),
  });
};

self.onunhandledrejection = (event) => {
  console.error('[signer-worker]: Unhandled promise rejection:', errorLogSummary(event.reason));
  event.preventDefault();
};

/**
 * Helper function to safely parse JSON with fallback
 */
function safeJsonParse(jsonString: string, fallback: unknown = {}): unknown {
  try {
    return jsonString ? JSON.parse(jsonString) : fallback;
  } catch (error: unknown) {
    console.warn('[signer-worker]: Failed to parse JSON:', errorLogSummary(error));
    return Array.isArray(fallback) ? [jsonString] : { rawData: jsonString };
  }
}
