import { errorMessage } from '@shared/utils/errors';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { isObject } from '@shared/utils/validation';
import {
  type NearWorkerProgressEvent,
  type WorkerErrorResponse,
  type WorkerProgressResponse,
  type RequestResponseMap,
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
import { resolveEmailOtpWorkerUrl } from '@/core/walletRuntimePaths/emailOtpWorker';
import { withSessionId } from './session';
import type {
  HssWorkerOperationRequest,
  HssWorkerOperationResult,
  HssWorkerOperationType,
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
import { SignerWorkerOperationError, WorkerControlMessage } from './workerTypes';

type RpcOk<T = unknown> = { id: string; ok: true; result: T };
type RpcErr = { id: string; ok: false; error: string; code?: string; coreCode?: string };
type RpcProgressFrame = { id: string; progress: true; payload: unknown };

type NearRpcProgressFrame = {
  id: string;
  progress: true;
  payload: NearWorkerProgressEvent;
};

type NearRpcSuccessFrame = {
  id: string;
  ok: true;
  result: NearWorkerOperationResult<NearWorkerOperationType>;
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
  onEvent?: (update: unknown) => void;
  timeoutId?: ReturnType<typeof setTimeout>;
  nearDirectResult?: boolean;
};

type NearWorkerOperationArgs<T extends NearWorkerOperationType = NearWorkerOperationType> = {
  kind: 'nearSigner';
  request: NearWorkerOperationRequest<T>;
};

type HssWorkerOperationArgs<T extends HssWorkerOperationType = HssWorkerOperationType> = {
  kind: 'hssClient';
  request: HssWorkerOperationRequest<T>;
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
  | HssWorkerOperationArgs
  | {
      [K in MultichainWorkerKind]: MultichainWorkerOperationArgs<K, MultichainOperationType<K>>;
    }[MultichainWorkerKind]
  | {
      kind: 'emailOtp';
      request: SignerWorkerOperationRequest<'emailOtp', SignerWorkerOperationType<'emailOtp'>>;
    };

const SIGNER_WORKER_KINDS: readonly SignerWorkerKind[] = [
  'nearSigner',
  'hssClient',
  'ethSigner',
  'tempoSigner',
  'emailOtp',
];
const MULTICHAIN_WORKER_DEFAULT_TIMEOUT_MS = 20_000;

function makeId(prefix: string): string {
  return secureRandomId(prefix, 32, 'signer worker request IDs');
}

function isReadyFrame(value: unknown): boolean {
  return (
    (value as { type?: unknown })?.type === WorkerControlMessage.WORKER_READY ||
    (value as { ready?: unknown })?.ready === true
  );
}

function isNearRpcProgressFrame(value: unknown): value is NearRpcProgressFrame {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as { id?: unknown }).id === 'string' &&
    (value as { progress?: unknown }).progress === true
  );
}

function isNearRpcSuccessFrame(value: unknown): value is NearRpcSuccessFrame {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as { id?: unknown }).id === 'string' &&
    (value as { ok?: unknown }).ok === true &&
    'result' in (value as object)
  );
}

function isNearRpcErrorFrame(value: unknown): value is NearRpcErrorFrame {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as { id?: unknown }).id === 'string' &&
    (value as { ok?: unknown }).ok === false &&
    typeof (value as { error?: unknown }).error === 'string'
  );
}

function isRpcSuccessFrame(value: unknown): value is RpcOk {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as { id?: unknown }).id === 'string' &&
    (value as { ok?: unknown }).ok === true &&
    'result' in (value as object)
  );
}

function isRpcErrorFrame(value: unknown): value is RpcErr {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as { id?: unknown }).id === 'string' &&
    (value as { ok?: unknown }).ok === false &&
    typeof (value as { error?: unknown }).error === 'string'
  );
}

function isRpcProgressFrame(value: unknown): value is RpcProgressFrame {
  return (
    !!value &&
    typeof value === 'object' &&
    typeof (value as { id?: unknown }).id === 'string' &&
    (value as { progress?: unknown }).progress === true &&
    'payload' in (value as object)
  );
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

  requestOperation<K extends SignerWorkerKind, T extends SignerWorkerOperationType<K>>(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
  requestOperation<T extends NearWorkerOperationType>(args: {
    kind: 'nearSigner';
    request: NearWorkerOperationRequest<T>;
  }): Promise<NearWorkerOperationResult<T>>;
  requestOperation<T extends HssWorkerOperationType>(args: {
    kind: 'hssClient';
    request: HssWorkerOperationRequest<T>;
  }): Promise<HssWorkerOperationResult<T>>;
  requestOperation<K extends MultichainWorkerKind, T extends MultichainOperationType<K>>(args: {
    kind: K;
    request: MultichainWorkerOperationRequest<K, T>;
  }): Promise<MultichainWorkerOperationResult<K, T>>;
  async requestOperation(
    args: AnyWorkerOperationArgs,
  ): Promise<
    | NearWorkerOperationResult<NearWorkerOperationType>
    | HssWorkerOperationResult<HssWorkerOperationType>
    | SignerWorkerOperationResult<'emailOtp', SignerWorkerOperationType<'emailOtp'>>
    | MultichainWorkerOperationResult<
        MultichainWorkerKind,
        MultichainOperationType<MultichainWorkerKind>
      >
  > {
    if (args.kind === 'nearSigner') {
      return await this.requestNearOperation(args.request);
    }
    if (args.kind === 'hssClient') {
      return await this.requestHssOperation(args.request);
    }
    if (args.kind === 'ethSigner') {
      return await this.requestRpcOperation('ethSigner', args.request);
    }
    if (args.kind === 'tempoSigner') {
      return await this.requestRpcOperation('tempoSigner', args.request);
    }
    return await this.requestRpcOperation('emailOtp', args.request);
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
      ? withSessionId(effectiveSessionId, payload as Record<string, unknown>)
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
        onEvent: onEvent ? (update) => onEvent(update as NearWorkerProgressEvent) : undefined,
        timeoutId,
        nearDirectResult: typeof type === 'string',
      });

      try {
        worker.postMessage({ id: requestId, type, payload: finalPayload }, transfer || []);
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

  private async requestHssOperation<T extends HssWorkerOperationType>({
    sessionId,
    type,
    payload,
    timeoutMs = SIGNER_WORKER_MANAGER_CONFIG.TIMEOUTS.DEFAULT,
    transfer,
  }: HssWorkerOperationRequest<T>): Promise<HssWorkerOperationResult<T>> {
    const payloadSessionId = (payload as { sessionId?: unknown })?.sessionId;
    if (sessionId && payloadSessionId && payloadSessionId !== sessionId) {
      throw new Error(
        `requestOperation: payload.sessionId (${payloadSessionId}) does not match provided sessionId (${sessionId})`,
      );
    }

    const effectiveSessionId =
      sessionId || (typeof payloadSessionId === 'string' ? payloadSessionId : undefined);
    const finalPayload = effectiveSessionId
      ? withSessionId(effectiveSessionId, payload as Record<string, unknown>)
      : payload;

    const worker = this.getOrCreateWorker('hssClient');
    const requestId = makeId('hssClient');

    return await new Promise<HssWorkerOperationResult<T>>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.rejectRequest(
          'hssClient',
          requestId,
          new SignerWorkerOperationError({
            message: `Worker operation timed out after ${timeoutMs}ms`,
            code: 'TIMEOUT',
            workerKind: 'hssClient',
          }),
        );
        this.resetWorker('hssClient');
      }, timeoutMs);

      this.getPendingMap('hssClient').set(requestId, {
        resolve: (value) => resolve(value as HssWorkerOperationResult<T>),
        reject,
        timeoutId,
      });

      try {
        worker.postMessage({ id: requestId, type, payload: finalPayload }, transfer || []);
      } catch (error) {
        this.rejectRequest(
          'hssClient',
          requestId,
          new SignerWorkerOperationError({
            message: `[hssClient] failed to postMessage: ${errorMessage(error)}`,
            code: 'WORKER_POSTMESSAGE_ERROR',
            workerKind: 'hssClient',
          }),
        );
      }
    });
  }

  private async requestRpcOperation<
    K extends Extract<SignerWorkerKind, 'ethSigner' | 'tempoSigner' | 'emailOtp'>,
    T extends SignerWorkerOperationType<K>,
  >(
    kind: K,
    request: SignerWorkerOperationRequest<K, T>,
  ): Promise<SignerWorkerOperationResult<K, T>> {
    const worker = this.getOrCreateWorker(kind);
    const requestId = makeId(kind);
    const parsedTimeoutMs = Math.floor(Number(request.timeoutMs));
    const timeoutMs =
      Number.isFinite(parsedTimeoutMs) && parsedTimeoutMs > 0
        ? parsedTimeoutMs
        : MULTICHAIN_WORKER_DEFAULT_TIMEOUT_MS;

    return await new Promise<SignerWorkerOperationResult<K, T>>((resolve, reject) => {
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
        resolve: (value) => resolve(value as SignerWorkerOperationResult<K, T>),
        reject,
        onEvent: (request as { onEvent?: (update: unknown) => void }).onEvent,
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
      if (kind === 'hssClient') {
        const workerUrl = resolveWorkerUrl(SIGNER_WORKER_MANAGER_CONFIG.HSS_CLIENT_WORKER.URL, {
          worker: 'hssClient',
          baseOrigin: this.workerBaseOrigin,
        });
        return new Worker(workerUrl, {
          type: SIGNER_WORKER_MANAGER_CONFIG.HSS_CLIENT_WORKER.TYPE,
          name: SIGNER_WORKER_MANAGER_CONFIG.HSS_CLIENT_WORKER.NAME,
        });
      }
      if (kind === 'emailOtp') {
        const workerUrl = resolveEmailOtpWorkerUrl({
          baseOrigin: this.workerBaseOrigin,
        });
        return new Worker(workerUrl, { type: 'module', name: 'email-otp-worker' });
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
    if (kind === 'hssClient') {
      this.handleHssWorkerMessage(data);
      return;
    }

    if (isRpcProgressFrame(data)) {
      const pending = this.getPendingMap(kind).get(data.id);
      if (!pending) return;
      pending.onEvent?.(data.payload);
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

    const requestId =
      isObject(data) && typeof (data as { id?: unknown }).id === 'string'
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

    const requestId =
      isObject(data) && typeof (data as { id?: unknown }).id === 'string'
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

  private handleHssWorkerMessage(data: unknown): void {
    if (isRpcSuccessFrame(data)) {
      this.resolveRequest('hssClient', data.id, data.result);
      return;
    }

    if (isRpcErrorFrame(data)) {
      this.rejectRequest(
        'hssClient',
        data.id,
        new SignerWorkerOperationError({
          message: data.error || '[hssClient] worker error',
          code: data.code,
          coreCode: data.coreCode,
          workerKind: 'hssClient',
        }),
      );
      return;
    }

    const requestId =
      isObject(data) && typeof (data as { id?: unknown }).id === 'string'
        ? (data as { id: string }).id
        : undefined;
    if (requestId && this.getPendingMap('hssClient').has(requestId)) {
      this.rejectRequest(
        'hssClient',
        requestId,
        new SignerWorkerOperationError({
          message: `Malformed worker response frame for request ${requestId}`,
          code: 'WORKER_PROTOCOL_ERROR',
          workerKind: 'hssClient',
        }),
      );
      return;
    }

    if (this.getPendingMap('hssClient').size === 0) return;
    this.rejectAllPending(
      'hssClient',
      new SignerWorkerOperationError({
        message: `Unknown worker response frame: ${JSON.stringify(data)}`,
        code: 'WORKER_PROTOCOL_ERROR',
        workerKind: 'hssClient',
      }),
    );
    this.resetWorker('hssClient');
  }

  private resolveNearResponse(
    requestId: string,
    response: NearWorkerOperationResult<NearWorkerOperationType>,
  ): void {
    const pending = this.getPendingMap('nearSigner').get(requestId);
    if (!pending) return;

    if (pending.nearDirectResult) {
      this.resolveRequest('nearSigner', requestId, response);
      return;
    }

    const workerResponse = response as WorkerResponseForRequest<keyof RequestResponseMap>;

    if (isWorkerProgress(workerResponse)) {
      const progressResponse = workerResponse as WorkerProgressResponse;
      pending.onEvent?.(progressResponse.payload);
      return;
    }

    if (isWorkerError(workerResponse)) {
      const errorResponse = workerResponse as WorkerErrorResponse;
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

    if (isWorkerSuccess(workerResponse)) {
      this.resolveRequest('nearSigner', requestId, workerResponse);
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
