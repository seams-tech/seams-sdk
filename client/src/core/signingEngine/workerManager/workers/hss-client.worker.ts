import {
  type SignerWorkerRequestType,
  type WasmRequestPayload,
  WorkerRequestType,
  WorkerResponseType,
} from '@/core/types/signer-worker';
import initHssClientSigner, {
  threshold_ecdsa_hss_role_local_client_bootstrap,
  threshold_ecdsa_hss_role_local_export_artifact,
  threshold_ecdsa_hss_role_local_finalize_client_bootstrap,
  threshold_ecdsa_hss_role_local_prepare_client_bootstrap,
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
    case WorkerRequestType.BuildThresholdEcdsaHssRoleLocalClientBootstrap:
      return {
        type: WorkerResponseType.BuildThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
        payload: threshold_ecdsa_hss_role_local_client_bootstrap(payload),
      };
    case WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap:
      return {
        type: WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
        payload: threshold_ecdsa_hss_role_local_prepare_client_bootstrap(payload),
      };
    case WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap:
      return {
        type: WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
        payload: threshold_ecdsa_hss_role_local_finalize_client_bootstrap(payload),
      };
    case WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact:
      return {
        type: WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess,
        payload: threshold_ecdsa_hss_role_local_export_artifact(payload),
      };
    default:
      throw new Error(`Unsupported HSS client request type: ${requestType}`);
  }
}

setTimeout(() => {
  self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

async function processWorkerMessage(event: MessageEvent): Promise<void> {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    throw new Error('HSS client worker request is missing RPC id');
  }

  try {
    const startedAt = Date.now();
    assertNoPrfSecretsInSignerPayload(event.data);
    const response = await handleHssClientMessage(event.data);
    self.postMessage({
      id: requestId,
      ok: true,
      result: response,
    });
    console.info('[hss-client-worker]: request complete', {
      requestId,
      requestType: Number((event.data as { type?: unknown })?.type),
      durationMs: Date.now() - startedAt,
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

  messageQueue = messageQueue.catch(() => undefined).then(() => processWorkerMessage(event));
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
