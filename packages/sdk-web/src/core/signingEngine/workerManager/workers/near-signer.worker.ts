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
  type SignerWorkerRequestType,
  WasmRequestPayload,
} from '@/core/types/signer-worker';
// Import WASM binary directly
import init, {
  handle_signer_message,
  threshold_ed25519_build_delegate_signing_payload,
  threshold_ed25519_build_near_tx_unsigned_borsh,
  threshold_ed25519_compute_delegate_signing_digest,
  threshold_ed25519_compute_nep413_signing_digest,
  threshold_ed25519_decode_signed_near_tx_borsh,
  threshold_ed25519_finalize_delegate_from_signature,
  threshold_ed25519_finalize_near_tx_from_signature,
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
      await init({ module_or_path: wasmUrl });
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
    const requestType = (event.data as { type?: unknown })?.type;
    // Guardrail: raw PRF fields must never traverse into signer payloads
    assertNoPrfSecretsInSignerPayload(event.data, requestType);
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

function assertNoPrfSecretsInSignerPayload(data: unknown, requestType: unknown): void {
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
  const requestForbiddenKeys =
    requestType === WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare
      ? forbiddenKeys.filter((key) => key !== secretB64uField('prfFirst'))
      : forbiddenKeys;
  for (const key of requestForbiddenKeys) {
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
