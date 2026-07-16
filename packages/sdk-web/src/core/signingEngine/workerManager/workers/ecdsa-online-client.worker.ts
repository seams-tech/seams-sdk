import initOnlineClient, {
  compute_client_signature_share,
  init_router_ab_ecdsa_online_client,
} from '../../../../../../../wasm/router_ab_ecdsa_online_client/pkg/router_ab_ecdsa_online_client.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { safeErrorMessage } from '@shared/utils/errors';
import { WorkerDeferred } from '../workerDeferred';
import {
  EcdsaOnlineClientRequestType,
  EcdsaOnlineClientResponseType,
  WorkerControlMessage,
  type EcdsaOnlineClientOperationMap,
} from '../workerTypes';
import {
  isAttachEcdsaPresignToOnlinePort,
  type EcdsaPresignMaterialResponse,
} from '../ecdsaClientWorkerChannels';

type OnlineOperationType = keyof EcdsaOnlineClientOperationMap;
type OnlineRpcRequest = {
  [T in OnlineOperationType]: {
    readonly id: string;
    readonly type: T;
    readonly payload: EcdsaOnlineClientOperationMap[T]['payload'];
  };
}[OnlineOperationType];

type PresignMaterial = {
  readonly bigR33: Uint8Array;
  readonly kShare32: Uint8Array;
  readonly sigmaShare32: Uint8Array;
};

type PendingPresignMaterial = {
  readonly resolve: (material: PresignMaterial) => void;
  readonly reject: (error: Error) => void;
};

const onlineWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_online_client_bg.wasm',
  'ECDSA online client',
);
const pendingMaterials = new Map<string, PendingPresignMaterial>();
let presignPort: MessagePort | null = null;
let wasmInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();

function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}

function randomRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let suffix = '';
  for (const byte of bytes) suffix += byte.toString(16).padStart(2, '0');
  return `ecdsa-online-material-${suffix}`;
}

function requireString(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireBytes(value: unknown, length: number, label: string): Uint8Array {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : null;
  if (!bytes || bytes.length !== length) throw new Error(`${label} must be ${length} bytes`);
  return bytes;
}

async function initializeOnlineWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = initializeWasm({
    workerName: 'ECDSA online client',
    wasmUrl: onlineWasmUrl,
    initFunction: initOnlineClient as unknown as (wasmModule?: unknown) => Promise<void>,
    validateFunction: init_router_ab_ecdsa_online_client,
  });
  return wasmInitPromise;
}

function handlePresignMaterialResponse(event: MessageEvent<EcdsaPresignMaterialResponse>): void {
  const response = event.data;
  if (response.kind !== 'ecdsa_presign_material_result_v1') return;
  const pending = pendingMaterials.get(response.requestId);
  if (!pending) return;
  pendingMaterials.delete(response.requestId);
  if (!response.ok) {
    pending.reject(new Error(response.error));
    return;
  }
  pending.resolve({
    bigR33: new Uint8Array(response.bigR33),
    kShare32: new Uint8Array(response.kShare32),
    sigmaShare32: new Uint8Array(response.sigmaShare32),
  });
}

function requestPresignMaterial(input: {
  materialHandle: string;
  requestBinding: string;
  reservationId: string;
  groupPublicKey33: Uint8Array;
  expectedBigR33: Uint8Array;
}): Promise<PresignMaterial> {
  if (!presignPort) throw new Error('ECDSA online client has no presign material channel');
  const requestId = randomRequestId();
  const deferred = new WorkerDeferred<PresignMaterial>();
  pendingMaterials.set(requestId, deferred);
  const groupPublicKey33 = input.groupPublicKey33.slice().buffer;
  const expectedBigR33 = input.expectedBigR33.slice().buffer;
  try {
    presignPort.postMessage(
      {
        kind: 'ecdsa_presign_material_request_v1',
        requestId,
        materialHandle: input.materialHandle,
        requestBinding: input.requestBinding,
        reservationId: input.reservationId,
        groupPublicKey33,
        expectedBigR33,
      },
      [groupPublicKey33, expectedBigR33],
    );
  } catch (error: unknown) {
    pendingMaterials.delete(requestId);
    throw error;
  }
  return deferred.promise;
}

function attachPresignPort(value: unknown): boolean {
  if (!isAttachEcdsaPresignToOnlinePort(value)) return false;
  presignPort?.close();
  presignPort = value.port;
  presignPort.onmessage = handlePresignMaterialResponse;
  presignPort.start();
  return true;
}

async function computeSignatureShare(
  payload: EcdsaOnlineClientOperationMap[typeof EcdsaOnlineClientRequestType.ComputeSignatureShare]['payload'],
): Promise<ArrayBuffer> {
  const groupPublicKey33 = requireBytes(payload.groupPublicKey33, 33, 'groupPublicKey33');
  const expectedBigR33 = requireBytes(payload.expectedPresignBigR33, 33, 'expectedPresignBigR33');
  const digest32 = requireBytes(payload.digest32, 32, 'digest32');
  const entropy32 = requireBytes(payload.entropy32, 32, 'entropy32');
  let material: PresignMaterial | null = null;
  try {
    material = await requestPresignMaterial({
      materialHandle: requireString(payload.materialHandle, 'materialHandle'),
      requestBinding: requireString(payload.requestBinding, 'requestBinding'),
      reservationId: requireString(payload.reservationId, 'reservationId'),
      groupPublicKey33,
      expectedBigR33,
    });
    await initializeOnlineWasm();
    const share = compute_client_signature_share(
      groupPublicKey33,
      material.bigR33,
      expectedBigR33,
      material.kShare32,
      material.sigmaShare32,
      digest32,
      entropy32,
    );
    return share.slice().buffer;
  } finally {
    if (material) {
      zeroize(material.bigR33);
      zeroize(material.kShare32);
      zeroize(material.sigmaShare32);
    }
    zeroize(digest32);
    zeroize(entropy32);
  }
}

async function handleRpcRequest(request: OnlineRpcRequest): Promise<void> {
  try {
    switch (request.type) {
      case EcdsaOnlineClientRequestType.ComputeSignatureShare: {
        const signatureShare = await computeSignatureShare(request.payload);
        self.postMessage(
          {
            id: request.id,
            ok: true,
            result: {
              type: EcdsaOnlineClientResponseType.ComputeSignatureShareSuccess,
              payload: signatureShare,
            },
          },
          { transfer: [signatureShare] },
        );
        return;
      }
    }
    throw new Error(`Unsupported ECDSA online request type: ${String(request.type)}`);
  } catch (error: unknown) {
    self.postMessage({ id: request.id, ok: false, error: safeErrorMessage(error) });
  }
}

function processMessage(event: MessageEvent): void {
  if (attachPresignPort(event.data)) return;
  const request = event.data as OnlineRpcRequest;
  messageQueue = messageQueue.then(() => handleRpcRequest(request));
}

self.addEventListener('message', processMessage);
self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
