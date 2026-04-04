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
  type SignerWorkerRequestType,
  WasmRequestPayload,
  WorkerRequestType,
  WorkerResponseType,
} from '@/core/types/signer-worker';
// Import WASM binary directly
import init, {
  handle_signer_message,
} from '../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import initHssClientSigner, {
  derive_threshold_ed25519_hss_client_inputs,
  threshold_ed25519_hss_evaluate_result,
  threshold_ed25519_hss_open_client_output,
  threshold_ed25519_hss_open_seed_output,
  threshold_ed25519_hss_prepare_client_request,
  threshold_ed25519_hss_prepare_session,
  threshold_ed25519_hss_public_key_from_base_shares,
  threshold_ed25519_seed_export_artifact_from_seed,
} from '../../../../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorMessage } from '@shared/utils/errors';
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
const hssClientSignerWasmUrl = resolveWasmUrl('hss_client_signer_bg.wasm', 'HSS Client Signer');
// UserConfirm bridge removed: signer no longer initiates confirmations

let wasmInitPromise: Promise<void> | null = null;
let hssClientSignerInitPromise: Promise<void> | null = null;
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

    // Create onProgressEvents-compatible payload
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
    console.error('[signer-worker]: Failed to send progress message:', error);
    if (!activeRequestId) return;
    self.postMessage({
      id: activeRequestId,
      ok: false,
      error: `Progress message failed: ${errorMessage(error)}`,
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
      console.error('[signer-worker]: WASM initialization failed:', error);
      throw new Error(`WASM initialization failed: ${errorMessage(error)}`);
    }
  })();
  return wasmInitPromise;
}

async function initializeHssClientSignerWasm(): Promise<void> {
  if (hssClientSignerInitPromise) return hssClientSignerInitPromise;
  hssClientSignerInitPromise = (async () => {
    try {
      const startedAt = Date.now();
      await initHssClientSigner({ module_or_path: hssClientSignerWasmUrl });
      console.info('[signer-worker]: HSS client WASM initialized', {
        durationMs: Date.now() - startedAt,
        wasmUrl: String(hssClientSignerWasmUrl),
      });
    } catch (error: unknown) {
      hssClientSignerInitPromise = null;
      console.error('[signer-worker]: HSS client WASM initialization failed:', error);
      throw new Error(`HSS client WASM initialization failed: ${errorMessage(error)}`);
    }
  })();
  return hssClientSignerInitPromise;
}

function isHssClientRequestType(requestType: number): requestType is WorkerRequestType {
  return (
    requestType === WorkerRequestType.DeriveThresholdEd25519HssClientInputs ||
    requestType === WorkerRequestType.PrepareThresholdEd25519HssSession ||
    requestType === WorkerRequestType.PrepareThresholdEd25519HssClientRequest ||
    requestType === WorkerRequestType.EvaluateThresholdEd25519HssResult ||
    requestType === WorkerRequestType.OpenThresholdEd25519HssClientOutput ||
    requestType === WorkerRequestType.OpenThresholdEd25519HssSeedOutput ||
    requestType === WorkerRequestType.DeriveThresholdEd25519HssPublicKey ||
    requestType === WorkerRequestType.BuildThresholdEd25519SeedExportArtifact
  );
}

async function handleHssClientMessage(data: unknown): Promise<{
  type: WorkerResponseType;
  payload: unknown;
}> {
  const request = data as { type?: unknown; payload?: unknown };
  const requestType = Number(request?.type);
  const payload = request?.payload;
  await initializeHssClientSignerWasm();

  switch (requestType) {
    case WorkerRequestType.DeriveThresholdEd25519HssClientInputs:
      return {
        type: WorkerResponseType.DeriveThresholdEd25519HssClientInputsSuccess,
        payload: derive_threshold_ed25519_hss_client_inputs(payload),
      };
    case WorkerRequestType.PrepareThresholdEd25519HssSession:
      return {
        type: WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess,
        payload: threshold_ed25519_hss_prepare_session(payload),
      };
    case WorkerRequestType.PrepareThresholdEd25519HssClientRequest:
      return {
        type: WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess,
        payload: threshold_ed25519_hss_prepare_client_request(payload),
      };
    case WorkerRequestType.EvaluateThresholdEd25519HssResult:
      return {
        type: WorkerResponseType.EvaluateThresholdEd25519HssResultSuccess,
        payload: threshold_ed25519_hss_evaluate_result(payload),
      };
    case WorkerRequestType.OpenThresholdEd25519HssClientOutput:
      return {
        type: WorkerResponseType.OpenThresholdEd25519HssClientOutputSuccess,
        payload: threshold_ed25519_hss_open_client_output(payload),
      };
    case WorkerRequestType.OpenThresholdEd25519HssSeedOutput:
      return {
        type: WorkerResponseType.OpenThresholdEd25519HssSeedOutputSuccess,
        payload: threshold_ed25519_hss_open_seed_output(payload),
      };
    case WorkerRequestType.DeriveThresholdEd25519HssPublicKey:
      return {
        type: WorkerResponseType.DeriveThresholdEd25519HssPublicKeySuccess,
        payload: threshold_ed25519_hss_public_key_from_base_shares(payload),
      };
    case WorkerRequestType.BuildThresholdEd25519SeedExportArtifact:
      return {
        type: WorkerResponseType.BuildThresholdEd25519SeedExportArtifactSuccess,
        payload: threshold_ed25519_seed_export_artifact_from_seed(payload),
      };
    default:
      throw new Error(`Unsupported HSS client request type: ${requestType}`);
  }
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
    const requestType = Number((event.data as { type?: unknown })?.type);
    // Guardrail: raw PRF fields must never traverse into signer payloads
    assertNoPrfSecretsInSignerPayload(event.data);
    const response = isHssClientRequestType(requestType)
      ? await handleHssClientMessage(event.data)
      : await (async () => {
          await initializeWasm();
          return handle_signer_message(event.data);
        })();
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
    console.error('[signer-worker]: Message processing failed:', error);
    self.postMessage({
      id: requestId,
      ok: false,
      error: errorMessage(error),
      code: 'WORKER_RUNTIME_ERROR',
    });
  } finally {
    activeRequestId = null;
  }
}

type SignerWorkerRpcRequest = {
  id: string;
  type: SignerWorkerRequestType;
  payload: WasmRequestPayload;
};

self.onmessage = async (event: MessageEvent<SignerWorkerRpcRequest>): Promise<void> => {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[signer-worker]: Ignoring message without request id');
    return;
  }
  const eventType = event.data?.type;

  if (typeof eventType !== 'number') {
    console.warn('[signer-worker]: Ignoring message with invalid non-numeric type:', eventType);
    return;
  }

  // Serialize worker operations to keep WASM state predictable and to avoid
  // overlapping accesses to PRF-derived material and relayer state.
  messageQueue = messageQueue.catch(() => undefined).then(() => processWorkerMessage(event));
  await messageQueue;
};

function assertNoPrfSecretsInSignerPayload(data: unknown): void {
  const payload =
    data && typeof data === 'object' ? (data as { payload?: unknown }).payload : undefined;
  if (!payload || typeof payload !== 'object') return;
  const payloadRecord = payload as Record<string, unknown>;
  const forbiddenKeys = ['prfOutput', 'prf_output', 'prfFirst', 'prf_first', 'prf'];
  for (const key of forbiddenKeys) {
    if (payloadRecord[key] !== undefined) {
      throw new Error(`Forbidden secret field in signer payload: ${key}`);
    }
  }
}

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[signer-worker]: error:', {
    message: typeof message === 'string' ? message : 'Unknown error',
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: error,
  });
};

self.onunhandledrejection = (event) => {
  console.error('[signer-worker]: Unhandled promise rejection:', event.reason);
  event.preventDefault();
};

/**
 * Helper function to safely parse JSON with fallback
 */
function safeJsonParse(jsonString: string, fallback: unknown = {}): unknown {
  try {
    return jsonString ? JSON.parse(jsonString) : fallback;
  } catch (error) {
    console.warn('[signer-worker]: Failed to parse JSON:', error);
    return Array.isArray(fallback) ? [jsonString] : { rawData: jsonString };
  }
}
