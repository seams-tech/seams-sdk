import { type WorkerResponseDiagnostics } from '@/core/types/signer-worker';
import initEcdsaDerivationClient, {
  build_ecdsa_role_local_export_artifact_v1,
  finalize_ecdsa_client_bootstrap_v1,
  open_ecdsa_role_local_signing_share_v1,
  prepare_ecdsa_client_bootstrap_v1,
} from '../../../../../../../wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode } from '@shared/utils/base64';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
  WorkerControlMessage,
  type EcdsaDerivationWorkerOperationType,
} from '../workerTypes';
import {
  isAttachEcdsaDerivationToPresignPort,
  type EcdsaDerivationAdditiveShareRequest,
  type EcdsaDerivationAdditiveShareResponse,
} from '../ecdsaClientWorkerChannels';

const ecdsaDerivationClientWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_derivation_client_bg.wasm',
  'ECDSA Derivation Client',
);
let ecdsaDerivationClientInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();
let presignPort: MessagePort | null = null;
const DIAGNOSTIC_BREAKDOWN_MAX_DEPTH = 2;
const DIAGNOSTIC_BREAKDOWN_MAX_FIELDS = 64;
type StoredEcdsaRoleLocalSigningMaterial = {
  materialHandle: string;
  stateBlobB64u: string;
  bindingDigest: string;
};

const ecdsaRoleLocalSigningMaterialStore = new Map<string, StoredEcdsaRoleLocalSigningMaterial>();

type EcdsaDerivationWorkerResponse = {
  type: EcdsaDerivationClientCustomResponseType;
  payload: unknown;
};

type EcdsaDerivationWorkerCommandResult = EcdsaDerivationWorkerResponse & {
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

function readNonEmptyString(record: Record<string, unknown>, key: string): string {
  const parsed = String(record[key] || '').trim();
  if (!parsed) {
    throw new Error(`ECDSA DERIVATION client worker request is missing ${key}`);
  }
  return parsed;
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function secretB64uField(prefix: string): string {
  return `${prefix}B64u`;
}

function requireRecordPayload(payload: unknown): Record<string, unknown> {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('ECDSA DERIVATION client worker request payload must be an object');
  }
  return payload as Record<string, unknown>;
}

function storeEcdsaRoleLocalSigningMaterial(payload: unknown): StoredEcdsaRoleLocalSigningMaterial {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const bindingDigest = readNonEmptyString(record, 'bindingDigest');
  const stateBlobRecord = requireRecordPayload(record.stateBlob);
  const stateBlobB64u = readNonEmptyString(stateBlobRecord, 'stateBlobB64u');
  const stored = {
    materialHandle,
    stateBlobB64u,
    bindingDigest,
  };
  ecdsaRoleLocalSigningMaterialStore.set(materialHandle, stored);
  return stored;
}

function openEcdsaRoleLocalAdditiveShareFromHandle(payload: unknown): unknown {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const expectedBindingDigest = readNonEmptyString(record, 'expectedBindingDigest');
  const stored = ecdsaRoleLocalSigningMaterialStore.get(materialHandle);
  if (!stored) {
    throw new Error('ECDSA role-local signing material handle is not loaded in this worker');
  }
  if (stored.bindingDigest !== expectedBindingDigest) {
    throw new Error('ECDSA role-local signing material binding mismatch');
  }
  return open_ecdsa_role_local_signing_share_v1({
    stateBlobB64u: stored.stateBlobB64u,
  });
}

function openEcdsaRoleLocalAdditiveShare32FromHandle(payload: unknown): Uint8Array {
  const result = openEcdsaRoleLocalAdditiveShareFromHandle(payload) as {
    signingShare32B64u?: unknown;
  };
  const additiveShare32 = base64UrlDecode(String(result.signingShare32B64u || '').trim());
  if (additiveShare32.length !== 32) {
    zeroizeBytes(additiveShare32);
    throw new Error('ECDSA role-local signing material must decode to 32 bytes');
  }
  return additiveShare32;
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
  command: EcdsaDerivationWorkerCommandResult;
  requestPayload: unknown;
}): WorkerResponseDiagnostics {
  const requestPayloadBreakdown = sizeBreakdown(input.requestPayload);
  const responsePayloadBreakdown = sizeBreakdown(input.command.payload);
  const wasmOperationTimings = operationTimingsFromPayload(input.command.payload);
  return {
    kind: 'worker_response_diagnostics_v1',
    worker: 'ecdsaDerivationClient',
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

function isDerivationWasmInitFailureMessage(message: string): boolean {
  return /derivation client wasm initialization failed|wasm initialization failed|failed to instantiate|module_or_path|webassembly/i.test(
    message,
  );
}

function classifyEcdsaDerivationWorkerFailure(error: unknown): {
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
    const resolvedMessage = message || safeErrorMessage(error);
    if (isDerivationWasmInitFailureMessage(resolvedMessage)) {
      return {
        message: resolvedMessage,
        code: 'WORKER_RUNTIME_ERROR',
        coreCode: 'ECDSA_DERIVATION_WASM_INIT_FAILURE',
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
      coreCode: 'ECDSA_DERIVATION_COMMAND_FAILURE',
    };
  }
  const message = safeErrorMessage(error);
  if (isDerivationWasmInitFailureMessage(message)) {
    return {
      message,
      code: 'WORKER_RUNTIME_ERROR',
      coreCode: 'ECDSA_DERIVATION_WASM_INIT_FAILURE',
    };
  }
  return {
    message,
    code: 'SIGNER_CRYPTO_ERROR',
    coreCode: 'ECDSA_DERIVATION_COMMAND_FAILURE',
  };
}

async function initializeEcdsaDerivationClientWasm(): Promise<void> {
  if (ecdsaDerivationClientInitPromise) return ecdsaDerivationClientInitPromise;
  ecdsaDerivationClientInitPromise = (async () => {
    try {
      const startedAt = Date.now();
      await initEcdsaDerivationClient({ module_or_path: ecdsaDerivationClientWasmUrl });
      console.info('[derivation-client-worker]: ECDSA client WASM initialized', {
        durationMs: Date.now() - startedAt,
        wasmUrl: String(ecdsaDerivationClientWasmUrl),
      });
    } catch (error: unknown) {
      ecdsaDerivationClientInitPromise = null;
      console.error(
        '[derivation-client-worker]: ECDSA client WASM initialization failed:',
        errorLogSummary(error),
      );
      throw new Error(`ECDSA client WASM initialization failed: ${safeErrorMessage(error)}`);
    }
  })();
  return ecdsaDerivationClientInitPromise;
}

function executeEcdsaDerivationRequest(
  requestType: EcdsaDerivationWorkerOperationType,
  payload: unknown,
): EcdsaDerivationWorkerResponse {
  switch (requestType) {
    case EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial: {
      const stored = storeEcdsaRoleLocalSigningMaterial(payload);
      return {
        type: EcdsaDerivationClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess,
        payload: {
          materialHandle: stored.materialHandle,
          bindingDigest: stored.bindingDigest,
        },
      };
    }
    case EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap:
      return {
        type: EcdsaDerivationClientCustomResponseType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess,
        payload: JSON.parse(prepare_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
      };
    case EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap:
      return {
        type: EcdsaDerivationClientCustomResponseType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess,
        payload: JSON.parse(finalize_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
      };
    case EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact:
      return {
        type: EcdsaDerivationClientCustomResponseType.BuildThresholdEcdsaDerivationRoleLocalExportArtifactSuccess,
        payload: JSON.parse(build_ecdsa_role_local_export_artifact_v1(JSON.stringify(payload))),
      };
  }
  requestType satisfies never;
  throw new Error(`Unsupported DERIVATION client request type: ${requestType}`);
}

function parseEcdsaDerivationOperationType(value: unknown): EcdsaDerivationWorkerOperationType {
  switch (value) {
    case EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial:
    case EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact:
      return value;
    default:
      throw new Error(`Unsupported DERIVATION client request type: ${String(value)}`);
  }
}

async function handleEcdsaDerivationClientMessage(
  data: unknown,
): Promise<EcdsaDerivationWorkerCommandResult> {
  const request = data as { type?: unknown; payload?: unknown };
  const requestType = request?.type;
  const payload = request?.payload;
  const initStartedAt = nowMs();
  await initializeEcdsaDerivationClientWasm();
  const wasmInitWaitMs = roundMs(nowMs() - initStartedAt);
  const wasmCallStartedAt = nowMs();

  const operationType = parseEcdsaDerivationOperationType(requestType);
  const response = executeEcdsaDerivationRequest(operationType, payload);
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
  const eventData = event.data as EcdsaDerivationClientWorkerRpcRequest & { queuedAtMs?: unknown };
  const requestId = String(eventData.id || '').trim();
  if (!requestId) {
    throw new Error('ECDSA DERIVATION client worker request is missing RPC id');
  }
  const requestType = Number(eventData.type);

  try {
    const startedAt = nowMs();
    assertNoPrfSecretsInSignerPayload(eventData);
    const response = await handleEcdsaDerivationClientMessage(eventData);
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
    console.info('[derivation-client-worker]: request complete', {
      requestId,
      requestType,
      durationMs: roundMs(completedAt - startedAt),
    });
  } catch (error: unknown) {
    console.error('[derivation-client-worker]: Message processing failed:', errorLogSummary(error));
    const failure = classifyEcdsaDerivationWorkerFailure(error);
    self.postMessage({
      id: requestId,
      ok: false,
      error: failure.message,
      code: failure.code,
      ...(failure.coreCode ? { coreCode: failure.coreCode } : {}),
    });
  }
}

type EcdsaDerivationClientWorkerRpcRequest = {
  id: string;
  type: EcdsaDerivationWorkerOperationType;
  payload: unknown;
};

function sendAdditiveShareFailure(requestId: string, error: unknown): void {
  if (!presignPort) return;
  const response: EcdsaDerivationAdditiveShareResponse = {
    kind: 'ecdsa_derivation_additive_share_result_v1',
    requestId,
    ok: false,
    error: safeErrorMessage(error),
  };
  presignPort.postMessage(response);
}

function handleAdditiveShareRequest(
  event: MessageEvent<EcdsaDerivationAdditiveShareRequest>,
): void {
  if (!presignPort) return;
  const request = event.data;
  if (request.kind !== 'ecdsa_derivation_additive_share_request_v1') return;
  try {
    const additiveShare32 = openEcdsaRoleLocalAdditiveShare32FromHandle({
      materialHandle: request.materialHandle,
      expectedBindingDigest: request.expectedBindingDigest,
    });
    const shareBuffer = additiveShare32.buffer;
    const response: EcdsaDerivationAdditiveShareResponse = {
      kind: 'ecdsa_derivation_additive_share_result_v1',
      requestId: request.requestId,
      ok: true,
      additiveShare32: shareBuffer,
    };
    presignPort.postMessage(response, [shareBuffer]);
  } catch (error: unknown) {
    sendAdditiveShareFailure(request.requestId, error);
  }
}

function attachPresignChannel(value: unknown): boolean {
  if (!isAttachEcdsaDerivationToPresignPort(value)) return false;
  presignPort?.close();
  presignPort = value.port;
  presignPort.onmessage = handleAdditiveShareRequest;
  presignPort.start();
  return true;
}

self.onmessage = async (
  event: MessageEvent<EcdsaDerivationClientWorkerRpcRequest>,
): Promise<void> => {
  if (attachPresignChannel(event.data)) return;
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[derivation-client-worker]: Ignoring message without request id');
    return;
  }

  const eventType = event.data?.type;
  if (typeof eventType !== 'number') {
    console.warn(
      '[derivation-client-worker]: Ignoring message with invalid non-numeric type:',
      eventType,
    );
    return;
  }

  const queuedAtMs = nowMs();
  const queuedEvent = {
    ...event,
    data: {
      ...event.data,
      queuedAtMs,
    },
  } as MessageEvent<EcdsaDerivationClientWorkerRpcRequest & { queuedAtMs: number }>;
  messageQueue = messageQueue.catch(() => undefined).then(() => processWorkerMessage(queuedEvent));
  await messageQueue;
};

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[derivation-client-worker]: error:', {
    message: safeErrorMessage(typeof message === 'string' ? message : 'Unknown error'),
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: errorLogSummary(error),
  });
};

self.onunhandledrejection = (event) => {
  console.error(
    '[derivation-client-worker]: Unhandled promise rejection:',
    errorLogSummary(event.reason),
  );
  event.preventDefault();
};

function forbiddenSecretFieldsForEcdsaDerivationWorkerRequest(): string[] {
  return [
    'prfOutput',
    'prf_output',
    'prfFirst',
    'prf_first',
    secretB64uField('prfFirst'),
    'prf_first_b64u',
    'prf',
    'nearPrivateKey',
    'privateKey',
    secretB64uField('signingShare32'),
  ];
}

function assertNoPrfSecretsInSignerPayload(data: unknown): void {
  const payload =
    data && typeof data === 'object' ? (data as { payload?: unknown }).payload : undefined;
  if (!payload || typeof payload !== 'object') return;
  const payloadRecord = payload as Record<string, unknown>;
  for (const key of forbiddenSecretFieldsForEcdsaDerivationWorkerRequest()) {
    if (payloadRecord[key] !== undefined) {
      throw new Error(`Forbidden secret field in signer payload: ${key}`);
    }
  }
}
