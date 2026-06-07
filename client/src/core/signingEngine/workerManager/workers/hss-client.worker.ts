import {
  type SignerWorkerRequestType,
  type WasmRequestPayload,
  type WorkerResponseDiagnostics,
  WorkerRequestType,
  WorkerResponseType,
} from '@/core/types/signer-worker';
import initHssClientSigner, {
  build_ecdsa_role_local_export_artifact_v1,
  finalize_ecdsa_client_bootstrap_v1,
  open_ecdsa_role_local_signing_share_v1,
  prepare_ecdsa_client_bootstrap_v1,
  derive_threshold_ed25519_hss_client_inputs,
  threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact,
  threshold_ed25519_hss_derive_client_output_mask,
  threshold_ed25519_hss_open_client_output,
  threshold_ed25519_hss_open_seed_output,
  threshold_ed25519_hss_prepare_client_request,
  threshold_ed25519_hss_prepare_session,
  threshold_ed25519_seed_export_artifact_from_seed,
} from '../../../../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorMessage } from '@shared/utils/errors';
import { WorkerControlMessage } from '../workerTypes';

const hssClientSignerWasmUrl = resolveWasmUrl('hss_client_signer_bg.wasm', 'HSS Client Signer');

let hssClientSignerInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();
const DIAGNOSTIC_BREAKDOWN_MAX_DEPTH = 2;
const DIAGNOSTIC_BREAKDOWN_MAX_FIELDS = 64;

type HssWorkerResponse = {
  type: WorkerResponseType;
  payload: unknown;
};

type HssWorkerCommandResult = HssWorkerResponse & {
  wasmInitWaitMs: number;
  wasmCallMs: number;
};

function nowMs(): number {
  return performance.now();
}

function roundMs(value: number): number {
  return Math.max(0, Math.round(value));
}

function collectSizeBreakdown(input: {
  value: unknown;
  out: Record<string, number>;
  path: string;
  depth: number;
}): void {
  if (!input.value || typeof input.value !== 'object' || Array.isArray(input.value)) return;
  if (Object.keys(input.out).length >= DIAGNOSTIC_BREAKDOWN_MAX_FIELDS) return;

  for (const [key, entry] of Object.entries(input.value as Record<string, unknown>)) {
    if (Object.keys(input.out).length >= DIAGNOSTIC_BREAKDOWN_MAX_FIELDS) return;
    const fieldPath = input.path ? `${input.path}.${key}` : key;
    if (typeof entry === 'string') {
      input.out[`${fieldPath}Bytes`] = entry.length;
    } else if (Array.isArray(entry)) {
      input.out[`${fieldPath}Count`] = entry.length;
    } else if (input.depth > 0 && entry && typeof entry === 'object') {
      collectSizeBreakdown({
        value: entry,
        out: input.out,
        path: fieldPath,
        depth: input.depth - 1,
      });
    }
  }
}

function sizeBreakdown(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  collectSizeBreakdown({
    value,
    out,
    path: '',
    depth: DIAGNOSTIC_BREAKDOWN_MAX_DEPTH,
  });
  return out;
}

function totalBreakdownBytes(breakdown: Record<string, number>): number {
  return Object.entries(breakdown).reduce(
    (total, [key, value]) => (key.endsWith('Bytes') ? total + value : total),
    0,
  );
}

function operationTimingsFromPayload(payload: unknown): Record<string, number> | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const timings = (payload as { timings?: unknown }).timings;
  if (!timings || typeof timings !== 'object' || Array.isArray(timings)) return null;
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(timings)) {
    const numberValue = Number(value);
    if (Number.isFinite(numberValue)) out[key] = roundMs(numberValue);
  }
  return Object.keys(out).length ? out : null;
}

function workerDiagnostics(input: {
  requestType: number;
  queuedAt: number;
  startedAt: number;
  completedAt: number;
  command: HssWorkerCommandResult;
  requestPayload: unknown;
}): WorkerResponseDiagnostics {
  const requestPayloadBreakdown = sizeBreakdown(input.requestPayload);
  const responsePayloadBreakdown = sizeBreakdown(input.command.payload);
  const wasmOperationTimings = operationTimingsFromPayload(input.command.payload);
  return {
    kind: 'worker_response_diagnostics_v1',
    worker: 'hssClient',
    requestType: input.requestType,
    queueWaitMs: roundMs(input.startedAt - input.queuedAt),
    wasmInitWaitMs: input.command.wasmInitWaitMs,
    wasmCallMs: input.command.wasmCallMs,
    totalMs: roundMs(input.completedAt - input.queuedAt),
    requestPayloadBytes: totalBreakdownBytes(requestPayloadBreakdown),
    responsePayloadBytes: totalBreakdownBytes(responsePayloadBreakdown),
    requestPayloadBreakdown,
    responsePayloadBreakdown,
    ...(wasmOperationTimings ? { wasmOperationTimings } : {}),
  };
}

function isHssWasmInitFailureMessage(message: string): boolean {
  return /hss client wasm initialization failed|wasm initialization failed|failed to instantiate|module_or_path|webassembly/i.test(
    message,
  );
}

function classifyHssWorkerFailure(error: unknown): {
  message: string;
  code: string;
  coreCode?: string;
} {
  if (error && typeof error === 'object') {
    const message =
      typeof (error as { message?: unknown }).message === 'string'
        ? String((error as { message?: string }).message).trim()
        : '';
    const code =
      typeof (error as { code?: unknown }).code === 'string'
        ? String((error as { code?: string }).code).trim()
        : '';
    const coreCode =
      typeof (error as { coreCode?: unknown }).coreCode === 'string'
        ? String((error as { coreCode?: string }).coreCode).trim()
        : '';
    const resolvedMessage = message || errorMessage(error);
    if (isHssWasmInitFailureMessage(resolvedMessage)) {
      return {
        message: resolvedMessage,
        code: 'WORKER_RUNTIME_ERROR',
        coreCode: 'HSS_WASM_INIT_FAILURE',
      };
    }
    if (code) {
      return {
        message: resolvedMessage,
        code,
        ...(coreCode ? { coreCode } : {}),
      };
    }
    return {
      message: resolvedMessage,
      code: 'SIGNER_CRYPTO_ERROR',
      coreCode: 'HSS_COMMAND_FAILURE',
    };
  }
  const message = errorMessage(error);
  if (isHssWasmInitFailureMessage(message)) {
    return {
      message,
      code: 'WORKER_RUNTIME_ERROR',
      coreCode: 'HSS_WASM_INIT_FAILURE',
    };
  }
  return {
    message,
    code: 'SIGNER_CRYPTO_ERROR',
    coreCode: 'HSS_COMMAND_FAILURE',
  };
}

async function initializeHssClientSignerWasm(): Promise<void> {
  if (hssClientSignerInitPromise) return hssClientSignerInitPromise;
  hssClientSignerInitPromise = (async () => {
    try {
      const startedAt = Date.now();
      await initHssClientSigner({ module_or_path: hssClientSignerWasmUrl });
      console.info('[hss-client-worker]: HSS client WASM initialized', {
        durationMs: Date.now() - startedAt,
        wasmUrl: String(hssClientSignerWasmUrl),
      });
    } catch (error: unknown) {
      hssClientSignerInitPromise = null;
      console.error('[hss-client-worker]: HSS client WASM initialization failed:', error);
      throw new Error(`HSS client WASM initialization failed: ${errorMessage(error)}`);
    }
  })();
  return hssClientSignerInitPromise;
}

async function handleHssClientMessage(data: unknown): Promise<HssWorkerCommandResult> {
  const request = data as { type?: unknown; payload?: unknown };
  const requestType = Number(request?.type);
  const payload = request?.payload;
  const initStartedAt = nowMs();
  await initializeHssClientSignerWasm();
  const wasmInitWaitMs = roundMs(nowMs() - initStartedAt);
  const wasmCallStartedAt = nowMs();

  const response: HssWorkerResponse = (() => {
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
      case WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask:
        return {
          type: WorkerResponseType.DeriveThresholdEd25519HssClientOutputMaskSuccess,
          payload: threshold_ed25519_hss_derive_client_output_mask(payload),
        };
      case WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess,
          payload: threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(payload),
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
      case WorkerRequestType.BuildThresholdEd25519SeedExportArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEd25519SeedExportArtifactSuccess,
          payload: threshold_ed25519_seed_export_artifact_from_seed(payload),
        };
      case WorkerRequestType.OpenThresholdEcdsaHssRoleLocalSigningShare:
        return {
          type: WorkerResponseType.OpenThresholdEcdsaHssRoleLocalSigningShareSuccess,
          payload: open_ecdsa_role_local_signing_share_v1(payload),
        };
      case WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap:
        return {
          type: WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
          payload: JSON.parse(prepare_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
        };
      case WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap:
        return {
          type: WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
          payload: JSON.parse(finalize_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
        };
      case WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess,
          payload: JSON.parse(build_ecdsa_role_local_export_artifact_v1(JSON.stringify(payload))),
        };
      default:
        throw new Error(`Unsupported HSS client request type: ${requestType}`);
    }
  })();
  return {
    ...response,
    wasmInitWaitMs,
    wasmCallMs: roundMs(nowMs() - wasmCallStartedAt),
  };
}

setTimeout(() => {
  self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

async function processWorkerMessage(event: MessageEvent): Promise<void> {
  const eventData = event.data as HssClientWorkerRpcRequest & { queuedAtMs?: unknown };
  const requestId = String(eventData.id || '').trim();
  if (!requestId) {
    throw new Error('HSS client worker request is missing RPC id');
  }

  try {
    const startedAt = nowMs();
    const requestType = Number(eventData.type);
    assertNoPrfSecretsInSignerPayload(eventData);
    const response = await handleHssClientMessage(eventData);
    const completedAt = nowMs();
    self.postMessage({
      id: requestId,
      ok: true,
      result: {
        type: response.type,
        payload: response.payload,
        diagnostics: workerDiagnostics({
          requestType,
          queuedAt: Number(eventData.queuedAtMs ?? startedAt),
          startedAt,
          completedAt,
          command: response,
          requestPayload: eventData.payload,
        }),
      },
    });
    console.info('[hss-client-worker]: request complete', {
      requestId,
      requestType,
      durationMs: roundMs(completedAt - startedAt),
    });
  } catch (error: unknown) {
    console.error('[hss-client-worker]: Message processing failed:', error);
    const failure = classifyHssWorkerFailure(error);
    self.postMessage({
      id: requestId,
      ok: false,
      error: failure.message,
      code: failure.code,
      ...(failure.coreCode ? { coreCode: failure.coreCode } : {}),
    });
  }
}

type HssClientWorkerRpcRequest = {
  id: string;
  type: SignerWorkerRequestType;
  payload: WasmRequestPayload;
};

self.onmessage = async (event: MessageEvent<HssClientWorkerRpcRequest>): Promise<void> => {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[hss-client-worker]: Ignoring message without request id');
    return;
  }

  const eventType = event.data?.type;
  if (typeof eventType !== 'number') {
    console.warn('[hss-client-worker]: Ignoring message with invalid non-numeric type:', eventType);
    return;
  }

  const queuedAtMs = nowMs();
  const queuedEvent = {
    ...event,
    data: {
      ...event.data,
      queuedAtMs,
    },
  } as MessageEvent<HssClientWorkerRpcRequest & { queuedAtMs: number }>;
  messageQueue = messageQueue.catch(() => undefined).then(() => processWorkerMessage(queuedEvent));
  await messageQueue;
};

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[hss-client-worker]: error:', {
    message: typeof message === 'string' ? message : 'Unknown error',
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error,
  });
};

self.onunhandledrejection = (event) => {
  console.error('[hss-client-worker]: Unhandled promise rejection:', event.reason);
  event.preventDefault();
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
