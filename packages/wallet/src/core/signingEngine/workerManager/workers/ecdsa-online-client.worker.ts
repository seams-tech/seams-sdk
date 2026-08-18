import { safeErrorMessage } from '@shared/utils/errors';
import {
  EcdsaOnlineClientRequestType,
  WorkerControlMessage,
  type EcdsaOnlineClientOperationMap,
} from '../workerTypes';
import { isAttachPresignToOnlinePort } from '../ecdsaClientWorkerChannels';
import { WorkerDeferred } from '../workerDeferred';

type OnlineOperationType = keyof EcdsaOnlineClientOperationMap;
type OnlineRpcRequest = {
  [T in OnlineOperationType]: {
    readonly id: string;
    readonly type: T;
    readonly payload: EcdsaOnlineClientOperationMap[T]['payload'];
  };
}[OnlineOperationType];

type OnlineRpcResponse =
  | { readonly id: string; readonly ok: true; readonly result: unknown }
  | { readonly id: string; readonly ok: false; readonly error: string };

const pending = new Map<string, WorkerDeferred<unknown>>();
let presignPort: MessagePort | null = null;

function handlePresignResponse(event: MessageEvent<OnlineRpcResponse>): void {
  const response = event.data;
  const deferred = pending.get(response.id);
  if (!deferred) return;
  pending.delete(response.id);
  if (response.ok) deferred.resolve(response.result);
  else deferred.reject(new Error(response.error));
}

function attachPresignPort(port: MessagePort): void {
  presignPort?.close();
  for (const deferred of pending.values()) {
    deferred.reject(new Error('ECDSA presign authority channel was replaced'));
  }
  pending.clear();
  presignPort = port;
  port.onmessage = handlePresignResponse;
  port.onmessageerror = () => rejectPending('ECDSA presign authority channel failed');
  port.start();
}

function rejectPending(message: string): void {
  for (const deferred of pending.values()) deferred.reject(new Error(message));
  pending.clear();
}

async function forwardRequest(request: OnlineRpcRequest): Promise<void> {
  try {
    const port = presignPort;
    if (!port) throw new Error('ECDSA online client has no opaque presign authority channel');
    if (pending.has(request.id)) throw new Error('ECDSA online request id is already pending');
    const deferred = new WorkerDeferred<unknown>();
    pending.set(request.id, deferred);
    const transfer =
      request.type === EcdsaOnlineClientRequestType.ComputeSignatureShare
        ? [
            request.payload.groupPublicKey33,
            request.payload.expectedPresignBigR33,
            request.payload.digest32,
            request.payload.clientRerandomizationContribution32,
            request.payload.signingWorkerRerandomizationContribution32,
          ]
        : [];
    try {
      port.postMessage(request, transfer);
    } catch (error) {
      pending.delete(request.id);
      throw error;
    }
    self.postMessage({ id: request.id, ok: true, result: await deferred.promise });
  } catch (error) {
    self.postMessage({ id: request.id, ok: false, error: safeErrorMessage(error) });
  }
}

function processMessage(event: MessageEvent<unknown>): void {
  if (isAttachPresignToOnlinePort(event.data)) {
    attachPresignPort(event.data.port);
    return;
  }
  void forwardRequest(event.data as OnlineRpcRequest);
}

self.addEventListener('message', processMessage);
self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
