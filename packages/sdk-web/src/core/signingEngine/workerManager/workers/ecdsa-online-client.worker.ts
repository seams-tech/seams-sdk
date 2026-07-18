import initOnlineClient, {
  compute_client_signature_share,
  init_router_ab_ecdsa_online_client,
} from '../../../../../../../wasm/router_ab_ecdsa_online_client/pkg/router_ab_ecdsa_online_client.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { safeErrorMessage } from '@shared/utils/errors';
import {
  EcdsaOnlineClientRequestType,
  EcdsaOnlineClientResponseType,
  WorkerControlMessage,
  type EcdsaOnlineClientOperationMap,
} from '../workerTypes';
import { parseEcdsaClientPresignPoolIdentity } from '../ecdsaPresignPoolIdentity';
import {
  IndexedDbClientPresignMaterialStore,
  type DurableClientPresignMaterial,
} from './ecdsaPresignMaterialStore';

type OnlineOperationType = keyof EcdsaOnlineClientOperationMap;
type OnlineRpcRequest = {
  [T in OnlineOperationType]: {
    readonly id: string;
    readonly type: T;
    readonly payload: EcdsaOnlineClientOperationMap[T]['payload'];
  };
}[OnlineOperationType];

const onlineWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_online_client_bg.wasm',
  'ECDSA online client',
);
const materialStore = new IndexedDbClientPresignMaterialStore();
let wasmInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();

function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
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

function assertNeverOnlineRequest(value: never): never {
  throw new Error(`Unsupported ECDSA online request: ${String(value)}`);
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

async function takePresignMaterial(input: {
  materialHandle: string;
  poolIdentity: unknown;
  requestBinding: string;
  reservationId: string;
  groupPublicKey33: Uint8Array;
  expectedBigR33: Uint8Array;
}): Promise<DurableClientPresignMaterial> {
  const result = await materialStore.takeForOnline({
    materialHandle: input.materialHandle,
    poolIdentity: parseEcdsaClientPresignPoolIdentity(input.poolIdentity),
    requestBinding: input.requestBinding,
    reservationId: input.reservationId,
    groupPublicKey33: input.groupPublicKey33,
    expectedBigR33: input.expectedBigR33,
    nowMs: Date.now(),
  });
  if (!result.ok) {
    throw new Error(`ECDSA Client presign material unavailable: ${result.code}`);
  }
  return result.material;
}

async function computeSignatureShare(
  payload: EcdsaOnlineClientOperationMap[typeof EcdsaOnlineClientRequestType.ComputeSignatureShare]['payload'],
): Promise<ArrayBuffer> {
  const groupPublicKey33 = requireBytes(payload.groupPublicKey33, 33, 'groupPublicKey33');
  const expectedBigR33 = requireBytes(payload.expectedPresignBigR33, 33, 'expectedPresignBigR33');
  const digest32 = requireBytes(payload.digest32, 32, 'digest32');
  const clientRerandomizationContribution32 = requireBytes(
    payload.clientRerandomizationContribution32,
    32,
    'clientRerandomizationContribution32',
  );
  const signingWorkerRerandomizationContribution32 = requireBytes(
    payload.signingWorkerRerandomizationContribution32,
    32,
    'signingWorkerRerandomizationContribution32',
  );
  let material: DurableClientPresignMaterial | null = null;
  try {
    material = await takePresignMaterial({
      materialHandle: requireString(payload.materialHandle, 'materialHandle'),
      poolIdentity: payload.poolIdentity,
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
      clientRerandomizationContribution32,
      signingWorkerRerandomizationContribution32,
    );
    return share.slice().buffer;
  } finally {
    if (material) {
      zeroize(material.bigR33);
      zeroize(material.kShare32);
      zeroize(material.sigmaShare32);
    }
    zeroize(digest32);
    zeroize(clientRerandomizationContribution32);
    zeroize(signingWorkerRerandomizationContribution32);
  }
}

async function retirePresignaturePool(
  payload: EcdsaOnlineClientOperationMap[typeof EcdsaOnlineClientRequestType.RetirePool]['payload'],
) {
  const poolIdentity = parseEcdsaClientPresignPoolIdentity(payload.poolIdentity);
  if (payload.reason !== 'key_epoch_retired' && payload.reason !== 'activation_epoch_retired') {
    throw new Error('ECDSA Client presign pool retirement reason is invalid');
  }
  const retiredCount = await materialStore.retirePool(poolIdentity, payload.reason, Date.now());
  return {
    kind: 'ecdsa_client_presignature_pool_retired_v1' as const,
    poolIdentity,
    reason: payload.reason,
    retiredCount,
  };
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
      case EcdsaOnlineClientRequestType.RetirePool:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaOnlineClientResponseType.RetirePoolSuccess,
            payload: await retirePresignaturePool(request.payload),
          },
        });
        return;
    }
    assertNeverOnlineRequest(request);
  } catch (error: unknown) {
    self.postMessage({ id: request.id, ok: false, error: safeErrorMessage(error) });
  }
}

function processMessage(event: MessageEvent): void {
  const request = event.data as OnlineRpcRequest;
  messageQueue = messageQueue.then(() => handleRpcRequest(request));
}

self.addEventListener('message', processMessage);
self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
