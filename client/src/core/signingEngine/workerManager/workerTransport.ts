import { errorMessage } from '@shared/utils/errors';
import { isObject } from '@shared/utils/validation';
import type { onProgressEvents } from '@/core/types/sdkSentEvents';
import {
  type WorkerErrorResponse,
  type WorkerProgressResponse,
  type WorkerResponseForRequest,
  isWorkerError,
  isWorkerProgress,
  isWorkerSuccess,
} from '@/core/types/signer-worker';
import { SIGNER_WORKER_MANAGER_CONFIG } from '@/config';
import {
  resolveMultichainWorkerUrl,
  type MultichainWorkerKind,
} from '@/core/walletRuntimePaths/multichainWorkers';
import { resolveWorkerUrl } from '@/core/walletRuntimePaths';
import { withSessionId } from './session';
import type {
  MultichainOperationType,
  MultichainWorkerOperationRequest,
  MultichainWorkerOperationResult,
  NearWorkerOperationRequest,
  NearWorkerOperationResult,
  NearWorkerOperationType,
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
  SignerWorkerTransportProtocol,
} from './workerTypes';
import {
  SignerWorkerOperationError,
  WorkerControlMessage,
} from './workerTypes';

type RpcOk<T = unknown> = { id: string; ok: true; result: T };
type RpcErr = { id: string; ok: false; error: string; code?: string; coreCode?: string };

type NearRpcProgressFrame = {
  id: string;
  progress: true;
  payload: onProgressEvents;
};

type NearRpcSuccessFrame = {
  id: string;
  ok: true;
  result: WorkerResponseForRequest<NearWorkerOperationType>;
};

type NearRpcErrorFrame = {
  id: string;
  ok: false;
  error: string;
  code?: string;
  coreCode?: string;
};

type PendingEntry = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  onEvent?: (update: onProgressEvents) => void;
  timeoutId?: ReturnType<typeof setTimeout>;
};

type NearWorkerOperationArgs<T extends NearWorkerOperationType = NearWorkerOperationType> = {
  kind: 'nearSigner';
  request: NearWorkerOperationRequest<T>;
};

type MultichainWorkerOperationArgs<
  K extends MultichainWorkerKind = MultichainWorkerKind,
  T extends MultichainOperationType<K> = MultichainOperationType<K>,
> = {
  kind: K;
  request: MultichainWorkerOperationRequest<K, T>;
};

type AnyWorkerOperationArgs =
  | NearWorkerOperationArgs
  | {
      [K in MultichainWorkerKind]: MultichainWorkerOperationArgs<K, MultichainOperationType<K>>;
    }[MultichainWorkerKind];

const SIGNER_WORKER_KINDS: readonly SignerWorkerKind[] = [
  'nearSigner',
  'ethSigner',
  'tempoSigner',
];
const MULTICHAIN_WORKER_DEFAULT_TIMEOUT_MS = 20_000;

function makeId(prefix: string): string {
  const c = globalThis.crypto;
  if (c?.randomUUID && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function isReadyFrame(value: unknown): boolean {
  return (value as { type?: unknown })?.type === WorkerControlMessage.WORKER_READY
    || (value as { ready?: unknown })?.ready === true;
}

function isNearRpcProgressFrame(value: unknown): value is NearRpcProgressFrame {
  return !!value
    && typeof value === 'object'
    && typeof (value as { id?: unknown }).id === 'string'
    && (value as { progress?: unknown }).progress === true;
}

function isNearRpcSuccessFrame(value: unknown): value is NearRpcSuccessFrame {
  return !!value
    && typeof value === 'object'
    && typeof (value as { id?: unknown }).id === 'string'
    && (value as { ok?: unknown }).ok === true
    && 'result' in (value as object);
}

function isNearRpcErrorFrame(value: unknown): value is NearRpcErrorFrame {
  return !!value
    && typeof value === 'object'
    && typeof (value as { id?: unknown }).id === 'string'
    && (value as { ok?: unknown }).ok === false
    && typeof (value as { error?: unknown }).error === 'string';
}

function isRpcSuccessFrame(value: unknown): value is RpcOk {
  return !!value
    && typeof value === 'object'
    && typeof (value as { id?: unknown }).id === 'string'
    && (value as { ok?: unknown }).ok === true
    && 'result' in (value as object);
}

function isRpcErrorFrame(value: unknown): value is RpcErr {
  return !!value
    && typeof value === 'object'
    && typeof (value as { id?: unknown }).id === 'string'
    && (value as { ok?: unknown }).ok === false
    && typeof (value as { error?: unknown }).error === 'string';
}

export class WorkerTransport implements SignerWorkerTransportProtocol {
  private workerBaseOrigin: string | undefined;
  private readonly workers = new Map<SignerWorkerKind, Worker>();
  private readonly pendingByKind = new Map<SignerWorkerKind, Map<string, PendingEntry>>();
  private readonly messageHandlers = new Map<SignerWorkerKind, (event: MessageEvent) => void>();
  private readonly errorHandlers = new Map<SignerWorkerKind, (event: ErrorEvent) => void>();

  setWorkerBaseOrigin(origin: string | undefined): void {
    if (this.workerBaseOrigin === origin) return;
    this.workerBaseOrigin = origin;
    for (const kind of Array.from(this.workers.keys())) {
      this.resetWorker(kind);
    }
  }

  async prewarmWorkers(): Promise<void> {
    for (const kind of SIGNER_WORKER_KINDS) {
      this.getOrCreateWorker(kind);
    }
  }

  requestOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
  requestOperation<T extends NearWorkerOperationType>(args: {
    kind: 'nearSigner';
    request: NearWorkerOperationRequest<T>;
  }): Promise<NearWorkerOperationResult<T>>;
  requestOperation<
    K extends MultichainWorkerKind,
    T extends MultichainOperationType<K>,
  >(args: {
    kind: K;
    request: MultichainWorkerOperationRequest<K, T>;
  }): Promise<MultichainWorkerOperationResult<K, T>>;
  async requestOperation(
    args: AnyWorkerOperationArgs,
  ): Promise<
    | NearWorkerOperationResult<NearWorkerOperationType>
    | MultichainWorkerOperationResult<
        MultichainWorkerKind,
        MultichainOperationType<MultichainWorkerKind>
      >
  > {
    if (args.kind === 'nearSigner') {
      return await this.requestNearOperation(args.request);
    }
    if (args.kind === 'ethSigner') {
      return await this.requestMultichainOperation('ethSigner', args.request);
    }
    return await this.requestMultichainOperation('tempoSigner', args.request);
  }

  private async requestNearOperation<T extends NearWorkerOperationType>({
    sessionId,
    type,
    payload,
    onEvent,
    timeoutMs = SIGNER_WORKER_MANAGER_CONFIG.TIMEOUTS.DEFAULT,
    transfer,
  }: NearWorkerOperationRequest<T>): Promise<NearWorkerOperationResult<T>> {
    const payloadSessionId = (payload as { sessionId?: unknown })?.sessionId;
    if (sessionId && payloadSessionId && payloadSessionId !== sessionId) {
      throw new Error(
        `requestOperation: payload.sessionId (${payloadSessionId}) does not match provided sessionId (${sessionId})`,
      );
    }

    const effectiveSessionId =
      sessionId || (typeof payloadSessionId === 'string' ? payloadSessionId : undefined);
    const finalPayload = effectiveSessionId
      ? withSessionId(effectiveSessionId, payload)
      : payload;

    const worker = this.getOrCreateWorker('nearSigner');
    const requestId = makeId('nearSigner');

    return await new Promise<NearWorkerOperationResult<T>>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.rejectRequest(
          'nearSigner',
          requestId,
          new SignerWorkerOperationError({
            message: `Worker operation timed out after ${timeoutMs}ms`,
            code: 'TIMEOUT',
            workerKind: 'nearSigner',
          }),
        );
        this.resetWorker('nearSigner');
        try {
          const seconds = Math.round(timeoutMs / 1000);
          window.postMessage(
            { type: 'MODAL_TIMEOUT', payload: `Timed out after ${seconds}s, try again` },
            '*',
          );
        } catch {}
      }, timeoutMs);

      this.getPendingMap('nearSigner').set(requestId, {
        resolve: (value) => resolve(value as NearWorkerOperationResult<T>),
        reject,
        onEvent,
        timeoutId,
      });

      try {
        worker.postMessage(
          { id: requestId, type, payload: finalPayload },
          transfer || [],
        );
      } catch (error) {
        this.rejectRequest(
          'nearSigner',
          requestId,
          new SignerWorkerOperationError({
            message: `[nearSigner] failed to postMessage: ${errorMessage(error)}`,
            code: 'WORKER_POSTMESSAGE_ERROR',
            workerKind: 'nearSigner',
          }),
        );
      }
    });
  }

  private async requestMultichainOperation<
    K extends MultichainWorkerKind,
    T extends MultichainOperationType<K>,
  >(
    kind: K,
    request: MultichainWorkerOperationRequest<K, T>,
  ): Promise<MultichainWorkerOperationResult<K, T>> {
    const worker = this.getOrCreateWorker(kind);
    const requestId = makeId(kind);
    const parsedTimeoutMs = Math.floor(Number(request.timeoutMs));
    const timeoutMs = Number.isFinite(parsedTimeoutMs) && parsedTimeoutMs > 0
      ? parsedTimeoutMs
      : MULTICHAIN_WORKER_DEFAULT_TIMEOUT_MS;

    return await new Promise<MultichainWorkerOperationResult<K, T>>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.rejectRequest(
          kind,
          requestId,
          new SignerWorkerOperationError({
            message: `Worker operation timed out after ${timeoutMs}ms`,
            code: 'TIMEOUT',
            workerKind: kind,
          }),
        );
        this.resetWorker(kind);
      }, timeoutMs);

      this.getPendingMap(kind).set(requestId, {
        resolve: (value) => resolve(value as MultichainWorkerOperationResult<K, T>),
        reject,
        timeoutId,
      });

      try {
        worker.postMessage(
          { id: requestId, type: request.type, payload: request.payload },
          request.transfer || [],
        );
      } catch (error) {
        this.rejectRequest(
          kind,
          requestId,
          new SignerWorkerOperationError({
            message: `[${kind}] failed to postMessage: ${errorMessage(error)}`,
            code: 'WORKER_POSTMESSAGE_ERROR',
            workerKind: kind,
          }),
        );
      }
    });
  }

  private getOrCreateWorker(kind: SignerWorkerKind): Worker {
    const existing = this.workers.get(kind);
    if (existing) return existing;

    const worker = this.createWorker(kind);
    const messageHandler = (event: MessageEvent): void => {
      this.handleWorkerMessage(kind, event);
    };
    const errorHandler = (event: ErrorEvent): void => {
      this.handleWorkerError(kind, event);
    };

    worker.addEventListener('message', messageHandler);
    worker.addEventListener('error', errorHandler);

    this.workers.set(kind, worker);
    this.messageHandlers.set(kind, messageHandler);
    this.errorHandlers.set(kind, errorHandler);
    return worker;
  }

  private createWorker(kind: SignerWorkerKind): Worker {
    try {
      if (kind === 'nearSigner') {
        const workerUrl = resolveWorkerUrl(SIGNER_WORKER_MANAGER_CONFIG.WORKER.URL, {
          worker: 'signer',
          baseOrigin: this.workerBaseOrigin,
        });
        return new Worker(workerUrl, {
          type: SIGNER_WORKER_MANAGER_CONFIG.WORKER.TYPE,
          name: SIGNER_WORKER_MANAGER_CONFIG.WORKER.NAME,
        });
      }

      const workerUrl = resolveMultichainWorkerUrl(kind, {
        baseOrigin: this.workerBaseOrigin,
      });
      return new Worker(workerUrl, { type: 'module', name: `${kind}-worker` });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to create ${kind} worker: ${msg}`);
    }
  }

  private handleWorkerMessage(kind: SignerWorkerKind, event: MessageEvent): void {
    const data = event.data as unknown;
    if (isReadyFrame(data)) return;

    if (kind === 'nearSigner') {
      this.handleNearWorkerMessage(data);
      return;
    }

    if (isRpcSuccessFrame(data)) {
      this.resolveRequest(kind, data.id, data.result);
      return;
    }

    if (isRpcErrorFrame(data)) {
      this.rejectRequest(
        kind,
        data.id,
        new SignerWorkerOperationError({
          message: data.error || `[${kind}] worker error`,
          code: data.code,
          coreCode: data.coreCode,
          workerKind: kind,
        }),
      );
      return;
    }

    const requestId = isObject(data) && typeof (data as { id?: unknown }).id === 'string'
      ? (data as { id: string }).id
      : undefined;
    if (requestId && this.getPendingMap(kind).has(requestId)) {
      this.rejectRequest(
        kind,
        requestId,
        new SignerWorkerOperationError({
          message: `Malformed worker response frame for request ${requestId}`,
          code: 'WORKER_PROTOCOL_ERROR',
          workerKind: kind,
        }),
      );
      return;
    }

    if (this.getPendingMap(kind).size === 0) return;
    this.rejectAllPending(
      kind,
      new SignerWorkerOperationError({
        message: `Unknown worker response frame: ${JSON.stringify(data)}`,
        code: 'WORKER_PROTOCOL_ERROR',
        workerKind: kind,
      }),
    );
    this.resetWorker(kind);
  }

  private handleNearWorkerMessage(data: unknown): void {
    if (isNearRpcProgressFrame(data)) {
      const pending = this.getPendingMap('nearSigner').get(data.id);
      if (!pending) return;
      pending.onEvent?.(data.payload);
      return;
    }

    if (isNearRpcSuccessFrame(data)) {
      this.resolveNearResponse(data.id, data.result);
      return;
    }

    if (isNearRpcErrorFrame(data)) {
      this.rejectRequest(
        'nearSigner',
        data.id,
        new SignerWorkerOperationError({
          message: data.error,
          code: data.code,
          coreCode: data.coreCode,
          workerKind: 'nearSigner',
        }),
      );
      return;
    }

    const requestId = isObject(data) && typeof (data as { id?: unknown }).id === 'string'
      ? (data as { id: string }).id
      : undefined;
    if (requestId && this.getPendingMap('nearSigner').has(requestId)) {
      this.rejectRequest(
        'nearSigner',
        requestId,
        new SignerWorkerOperationError({
          message: `Malformed worker response frame for request ${requestId}`,
          code: 'WORKER_PROTOCOL_ERROR',
          workerKind: 'nearSigner',
        }),
      );
      return;
    }

    if (this.getPendingMap('nearSigner').size === 0) return;
    this.rejectAllPending(
      'nearSigner',
      new SignerWorkerOperationError({
        message: `Unknown worker response frame: ${JSON.stringify(data)}`,
        code: 'WORKER_PROTOCOL_ERROR',
        workerKind: 'nearSigner',
      }),
    );
    this.resetWorker('nearSigner');
  }

  private resolveNearResponse(
    requestId: string,
    response: WorkerResponseForRequest<NearWorkerOperationType>,
  ): void {
    const pending = this.getPendingMap('nearSigner').get(requestId);
    if (!pending) return;

    if (isWorkerProgress(response)) {
      const progressResponse = response as WorkerProgressResponse;
      pending.onEvent?.(progressResponse.payload);
      return;
    }

    if (isWorkerError(response)) {
      const errorResponse = response as WorkerErrorResponse;
      this.rejectRequest(
        'nearSigner',
        requestId,
        new SignerWorkerOperationError({
          message: errorResponse.payload.error,
          code: String(errorResponse.payload.errorCode || '').trim() || undefined,
          workerKind: 'nearSigner',
        }),
      );
      return;
    }

    if (isWorkerSuccess(response)) {
      this.resolveRequest('nearSigner', requestId, response);
      return;
    }

    if (isObject(response) && 'message' in response && 'stack' in response) {
      const message = String((response as { message?: unknown }).message ?? 'Unknown error');
      this.rejectRequest(
        'nearSigner',
        requestId,
        new SignerWorkerOperationError({
          message: `Worker sent generic error: ${message}`,
          code: 'WORKER_PROTOCOL_ERROR',
          workerKind: 'nearSigner',
        }),
      );
      return;
    }

    this.rejectRequest(
      'nearSigner',
      requestId,
      new SignerWorkerOperationError({
        message: `Unknown worker response format: ${JSON.stringify(response)}`,
        code: 'WORKER_PROTOCOL_ERROR',
        workerKind: 'nearSigner',
      }),
    );
  }

  private handleWorkerError(kind: SignerWorkerKind, event: ErrorEvent): void {
    const runtimeError = new SignerWorkerOperationError({
      message: `[${kind}] worker runtime error: ${event.message || 'unknown error'}`,
      code: 'WORKER_RUNTIME_ERROR',
      workerKind: kind,
    });
    this.rejectAllPending(kind, runtimeError);
    this.resetWorker(kind);
  }

  private getPendingMap(kind: SignerWorkerKind): Map<string, PendingEntry> {
    const existing = this.pendingByKind.get(kind);
    if (existing) return existing;
    const next = new Map<string, PendingEntry>();
    this.pendingByKind.set(kind, next);
    return next;
  }

  private resolveRequest(kind: SignerWorkerKind, requestId: string, value: unknown): void {
    const pending = this.getPendingMap(kind).get(requestId);
    if (!pending) return;
    this.clearRequest(kind, requestId);
    pending.resolve(value);
  }

  private rejectRequest(kind: SignerWorkerKind, requestId: string, error: Error): void {
    const pending = this.getPendingMap(kind).get(requestId);
    if (!pending) return;
    this.clearRequest(kind, requestId);
    pending.reject(error);
  }

  private rejectAllPending(kind: SignerWorkerKind, error: Error): void {
    const requestIds = Array.from(this.getPendingMap(kind).keys());
    for (const requestId of requestIds) {
      this.rejectRequest(kind, requestId, error);
    }
  }

  private clearRequest(kind: SignerWorkerKind, requestId: string): void {
    const pending = this.getPendingMap(kind).get(requestId);
    if (!pending) return;
    if (pending.timeoutId) clearTimeout(pending.timeoutId);
    this.getPendingMap(kind).delete(requestId);
  }

  private resetWorker(kind: SignerWorkerKind): void {
    const worker = this.workers.get(kind);
    if (!worker) return;

    const messageHandler = this.messageHandlers.get(kind);
    const errorHandler = this.errorHandlers.get(kind);
    if (messageHandler) worker.removeEventListener('message', messageHandler);
    if (errorHandler) worker.removeEventListener('error', errorHandler);
    worker.terminate();

    this.workers.delete(kind);
    this.messageHandlers.delete(kind);
    this.errorHandlers.delete(kind);
  }
}

const workerTransport = new WorkerTransport();

export function getWorkerTransport(): WorkerTransport {
  return workerTransport;
}

export async function requestWorkerOperation<
  K extends SignerWorkerKind,
  T extends SignerWorkerOperationType<K>,
>(args: {
  kind: K;
  request: SignerWorkerOperationRequest<K, T>;
}): Promise<SignerWorkerOperationResult<K, T>> {
  return await workerTransport.requestOperation(args);
}
