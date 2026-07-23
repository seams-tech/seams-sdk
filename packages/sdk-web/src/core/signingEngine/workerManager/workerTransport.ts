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
import { EcdsaClientWorkerControlKind } from './ecdsaClientWorkerChannels';
import type {
  EcdsaDerivationWorkerOperationRequest,
  EcdsaDerivationWorkerOperationResult,
  EcdsaDerivationWorkerOperationType,
  EmailOtpYaoPrewarmRequest,
  EmailOtpYaoPrewarmOutcome,
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
  EcdsaPresignClientRequestType,
  SignerWorkerOperationError,
  WorkerControlMessage,
} from './workerTypes';
import { clearEcdsaRoleLocalWorkerRuntimeState } from '../session/material/ecdsaRoleLocalMaterialResolver';

type RpcOk<T = unknown> = { id: string; ok: true; result: T };
type RpcErr = { id: string; ok: false; error: string; code?: string; coreCode?: string };
type RpcProgressFrame = { id: string; progress: true; payload: unknown };

function roundWorkerDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function assertNeverWorkerPrewarmResult(value: never): never {
  throw new Error(`Unsupported Email OTP Yao prewarm result: ${String(value)}`);
}

function assertNeverWorkerPrewarmRequest(value: never): never {
  throw new Error(`Unsupported Email OTP Yao prewarm request: ${String(value)}`);
}

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

type EcdsaDerivationWorkerOperationArgs<
  T extends EcdsaDerivationWorkerOperationType = EcdsaDerivationWorkerOperationType,
> = {
  kind: 'ecdsaDerivationClient';
  request: EcdsaDerivationWorkerOperationRequest<T>;
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
  | EcdsaDerivationWorkerOperationArgs
  | {
      [K in MultichainWorkerKind]: MultichainWorkerOperationArgs<K, MultichainOperationType<K>>;
    }[MultichainWorkerKind]
  | {
      kind: 'emailOtp';
      request: SignerWorkerOperationRequest<'emailOtp', SignerWorkerOperationType<'emailOtp'>>;
    }
  | {
      kind: 'ecdsaPresignClient';
      request: SignerWorkerOperationRequest<
        'ecdsaPresignClient',
        SignerWorkerOperationType<'ecdsaPresignClient'>
      >;
    }
  | {
      kind: 'ecdsaOnlineClient';
      request: SignerWorkerOperationRequest<
        'ecdsaOnlineClient',
        SignerWorkerOperationType<'ecdsaOnlineClient'>
      >;
    };

const SIGNER_WORKER_KINDS: readonly SignerWorkerKind[] = [
  'nearSigner',
  'ecdsaDerivationClient',
  'evmCrypto',
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
  private derivationPresignConnected = false;
  private emailOtpPresignConnected = false;
  private emailOtpYaoPrewarmPromise: Promise<EmailOtpYaoPrewarmOutcome> | null = null;

  setWorkerBaseOrigin(origin: string | undefined): void {
    if (this.workerBaseOrigin === origin) return;
    this.workerBaseOrigin = origin;
    this.emailOtpYaoPrewarmPromise = null;
    for (const kind of Array.from(this.workers.keys())) {
      this.resetWorker(kind);
    }
  }

  async prewarmWorkers(): Promise<void> {
    for (const kind of SIGNER_WORKER_KINDS) {
      this.getOrCreateWorker(kind);
    }
  }

  async prewarmEmailOtpYao(
    request: EmailOtpYaoPrewarmRequest = { kind: 'requested' },
  ): Promise<EmailOtpYaoPrewarmOutcome> {
    switch (request.kind) {
      case 'not_requested':
        return {
          kind: 'not_requested',
          elapsedMs: 0,
          workerPrewarmMs: 0,
          yaoWasmInitMs: 0,
        };
      case 'requested':
        break;
      default:
        return assertNeverWorkerPrewarmRequest(request);
    }

    const existing = this.emailOtpYaoPrewarmPromise;
    if (existing) return await existing;

    const prewarmPromise = this.requestEmailOtpYaoPrewarm();
    this.emailOtpYaoPrewarmPromise = prewarmPromise;
    const outcome = await prewarmPromise;
    if (outcome.kind === 'failed' && this.emailOtpYaoPrewarmPromise === prewarmPromise) {
      this.emailOtpYaoPrewarmPromise = null;
    }
    return outcome;
  }

  private async requestEmailOtpYaoPrewarm(): Promise<EmailOtpYaoPrewarmOutcome> {
    const startedAt = performance.now();
    try {
      const result = await this.requestOperation({
        kind: 'emailOtp',
        request: {
          type: 'prewarmEmailOtpRegistrationCrypto',
          payload: {},
        },
      });
      const workerPrewarmMs = roundWorkerDurationMs(startedAt);
      switch (result.kind) {
        case 'succeeded':
          return {
            kind: 'succeeded',
            elapsedMs: workerPrewarmMs,
            workerPrewarmMs,
            yaoWasmInitMs: result.elapsedMs,
          };
        case 'failed':
          return {
            kind: 'failed',
            elapsedMs: workerPrewarmMs,
            workerPrewarmMs,
            yaoWasmInitMs: result.elapsedMs,
            failureStage: result.failureStage,
          };
        default:
          return assertNeverWorkerPrewarmResult(result);
      }
    } catch {
      const workerPrewarmMs = roundWorkerDurationMs(startedAt);
      return {
        kind: 'failed',
        elapsedMs: workerPrewarmMs,
        workerPrewarmMs,
        yaoWasmInitMs: 0,
        failureStage: 'worker_ready',
      };
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
  requestOperation<T extends EcdsaDerivationWorkerOperationType>(args: {
    kind: 'ecdsaDerivationClient';
    request: EcdsaDerivationWorkerOperationRequest<T>;
  }): Promise<EcdsaDerivationWorkerOperationResult<T>>;
  requestOperation<K extends MultichainWorkerKind, T extends MultichainOperationType<K>>(args: {
    kind: K;
    request: MultichainWorkerOperationRequest<K, T>;
  }): Promise<MultichainWorkerOperationResult<K, T>>;
  async requestOperation(
    args: AnyWorkerOperationArgs,
  ): Promise<
    | NearWorkerOperationResult<NearWorkerOperationType>
    | EcdsaDerivationWorkerOperationResult<EcdsaDerivationWorkerOperationType>
    | SignerWorkerOperationResult<'emailOtp', SignerWorkerOperationType<'emailOtp'>>
    | MultichainWorkerOperationResult<
        MultichainWorkerKind,
        MultichainOperationType<MultichainWorkerKind>
      >
  > {
    if (args.kind === 'nearSigner') {
      return await this.requestNearOperation(args.request);
    }
    if (args.kind === 'ecdsaDerivationClient') {
      return await this.requestDerivationOperation(args.request);
    }
    if (args.kind === 'ecdsaPresignClient') {
      this.connectPresignAuthorityChannel(args.request);
      return await this.requestRpcOperation('ecdsaPresignClient', args.request);
    }
    if (args.kind === 'ecdsaOnlineClient') {
      return await this.requestRpcOperation('ecdsaOnlineClient', args.request);
    }
    if (args.kind === 'evmCrypto') {
      return await this.requestRpcOperation('evmCrypto', args.request);
    }
    if (args.kind === 'tempoSigner') {
      return await this.requestRpcOperation('tempoSigner', args.request);
    }
    return await this.requestRpcOperation(args.kind, args.request);
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

  private async requestDerivationOperation<T extends EcdsaDerivationWorkerOperationType>({
    sessionId,
    type,
    payload,
    timeoutMs = SIGNER_WORKER_MANAGER_CONFIG.TIMEOUTS.DEFAULT,
    transfer,
  }: EcdsaDerivationWorkerOperationRequest<T>): Promise<EcdsaDerivationWorkerOperationResult<T>> {
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

    const worker = this.getOrCreateWorker('ecdsaDerivationClient');
    const requestId = makeId('ecdsaDerivationClient');

    return await new Promise<EcdsaDerivationWorkerOperationResult<T>>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.rejectRequest(
          'ecdsaDerivationClient',
          requestId,
          new SignerWorkerOperationError({
            message: `Worker operation timed out after ${timeoutMs}ms`,
            code: 'TIMEOUT',
            workerKind: 'ecdsaDerivationClient',
          }),
        );
        this.resetWorker('ecdsaDerivationClient');
      }, timeoutMs);

      this.getPendingMap('ecdsaDerivationClient').set(requestId, {
        resolve: (value) => resolve(value as EcdsaDerivationWorkerOperationResult<T>),
        reject,
        timeoutId,
      });

      try {
        worker.postMessage({ id: requestId, type, payload: finalPayload }, transfer || []);
      } catch (error) {
        this.rejectRequest(
          'ecdsaDerivationClient',
          requestId,
          new SignerWorkerOperationError({
            message: `[ecdsaDerivationClient] failed to postMessage: ${errorMessage(error)}`,
            code: 'WORKER_POSTMESSAGE_ERROR',
            workerKind: 'ecdsaDerivationClient',
          }),
        );
      }
    });
  }

  private async requestRpcOperation<
    K extends Exclude<SignerWorkerKind, 'nearSigner' | 'ecdsaDerivationClient'>,
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

  private connectPresignAuthorityChannel(
    request: SignerWorkerOperationRequest<
      'ecdsaPresignClient',
      SignerWorkerOperationType<'ecdsaPresignClient'>
    >,
  ): void {
    if (request.type !== EcdsaPresignClientRequestType.SessionInit) return;
    const presignWorker = this.getOrCreateWorker('ecdsaPresignClient');
    const authorityKind = this.parsePresignAuthorityKind(request.payload);
    switch (authorityKind) {
      case 'role_local_derivation_handle':
        this.connectDerivationPresignChannel(presignWorker);
        return;
      case 'email_otp_worker_session':
        this.connectEmailOtpPresignChannel(presignWorker);
        return;
      default:
        authorityKind satisfies never;
    }
  }

  private parsePresignAuthorityKind(
    payload: unknown,
  ): 'role_local_derivation_handle' | 'email_otp_worker_session' {
    if (!isObject(payload) || !isObject(payload.authority)) {
      throw new Error('ECDSA presign init authority is required');
    }
    switch (payload.authority.kind) {
      case 'role_local_derivation_handle':
      case 'email_otp_worker_session':
        return payload.authority.kind;
      default:
        throw new Error('ECDSA presign init authority kind is invalid');
    }
  }

  private connectDerivationPresignChannel(presignWorker: Worker): void {
    if (this.derivationPresignConnected) return;
    const derivationWorker = this.getOrCreateWorker('ecdsaDerivationClient');
    const channel = new MessageChannel();
    derivationWorker.postMessage(
      {
        kind: EcdsaClientWorkerControlKind.AttachDerivationToPresign,
        port: channel.port1,
      },
      [channel.port1],
    );
    presignWorker.postMessage(
      {
        kind: EcdsaClientWorkerControlKind.AttachDerivationToPresign,
        port: channel.port2,
      },
      [channel.port2],
    );
    this.derivationPresignConnected = true;
  }

  private connectEmailOtpPresignChannel(presignWorker: Worker): void {
    if (this.emailOtpPresignConnected) return;
    const emailOtpWorker = this.getOrCreateWorker('emailOtp');
    const channel = new MessageChannel();
    emailOtpWorker.postMessage(
      {
        kind: EcdsaClientWorkerControlKind.AttachEmailOtpToPresign,
        port: channel.port1,
      },
      [channel.port1],
    );
    presignWorker.postMessage(
      {
        kind: EcdsaClientWorkerControlKind.AttachEmailOtpToPresign,
        port: channel.port2,
      },
      [channel.port2],
    );
    this.emailOtpPresignConnected = true;
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
      if (kind === 'ecdsaDerivationClient') {
        const workerUrl = resolveWorkerUrl(
          SIGNER_WORKER_MANAGER_CONFIG.ECDSA_DERIVATION_CLIENT_WORKER.URL,
          {
            worker: 'ecdsaDerivationClient',
            baseOrigin: this.workerBaseOrigin,
          },
        );
        return new Worker(workerUrl, {
          type: SIGNER_WORKER_MANAGER_CONFIG.ECDSA_DERIVATION_CLIENT_WORKER.TYPE,
          name: SIGNER_WORKER_MANAGER_CONFIG.ECDSA_DERIVATION_CLIENT_WORKER.NAME,
        });
      }
      if (kind === 'ecdsaPresignClient') {
        const workerUrl = resolveWorkerUrl(
          SIGNER_WORKER_MANAGER_CONFIG.ECDSA_PRESIGN_CLIENT_WORKER.URL,
          { worker: 'ecdsaPresignClient', baseOrigin: this.workerBaseOrigin },
        );
        return new Worker(workerUrl, {
          type: SIGNER_WORKER_MANAGER_CONFIG.ECDSA_PRESIGN_CLIENT_WORKER.TYPE,
          name: SIGNER_WORKER_MANAGER_CONFIG.ECDSA_PRESIGN_CLIENT_WORKER.NAME,
        });
      }
      if (kind === 'ecdsaOnlineClient') {
        const workerUrl = resolveWorkerUrl(
          SIGNER_WORKER_MANAGER_CONFIG.ECDSA_ONLINE_CLIENT_WORKER.URL,
          { worker: 'ecdsaOnlineClient', baseOrigin: this.workerBaseOrigin },
        );
        return new Worker(workerUrl, {
          type: SIGNER_WORKER_MANAGER_CONFIG.ECDSA_ONLINE_CLIENT_WORKER.TYPE,
          name: SIGNER_WORKER_MANAGER_CONFIG.ECDSA_ONLINE_CLIENT_WORKER.NAME,
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
    if (kind === 'ecdsaDerivationClient') {
      this.handleEcdsaDerivationWorkerMessage(data);
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

  private handleEcdsaDerivationWorkerMessage(data: unknown): void {
    if (isRpcSuccessFrame(data)) {
      this.resolveRequest('ecdsaDerivationClient', data.id, data.result);
      return;
    }

    if (isRpcErrorFrame(data)) {
      this.rejectRequest(
        'ecdsaDerivationClient',
        data.id,
        new SignerWorkerOperationError({
          message: data.error || '[ecdsaDerivationClient] worker error',
          code: data.code,
          coreCode: data.coreCode,
          workerKind: 'ecdsaDerivationClient',
        }),
      );
      return;
    }

    const requestId =
      isObject(data) && typeof (data as { id?: unknown }).id === 'string'
        ? (data as { id: string }).id
        : undefined;
    if (requestId && this.getPendingMap('ecdsaDerivationClient').has(requestId)) {
      this.rejectRequest(
        'ecdsaDerivationClient',
        requestId,
        new SignerWorkerOperationError({
          message: `Malformed worker response frame for request ${requestId}`,
          code: 'WORKER_PROTOCOL_ERROR',
          workerKind: 'ecdsaDerivationClient',
        }),
      );
      return;
    }

    if (this.getPendingMap('ecdsaDerivationClient').size === 0) return;
    this.rejectAllPending(
      'ecdsaDerivationClient',
      new SignerWorkerOperationError({
        message: `Unknown worker response frame: ${JSON.stringify(data)}`,
        code: 'WORKER_PROTOCOL_ERROR',
        workerKind: 'ecdsaDerivationClient',
      }),
    );
    this.resetWorker('ecdsaDerivationClient');
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
    if (kind === 'ecdsaDerivationClient') {
      clearEcdsaRoleLocalWorkerRuntimeState();
      this.derivationPresignConnected = false;
      this.resetWorker('ecdsaPresignClient');
    } else if (kind === 'ecdsaPresignClient') {
      this.derivationPresignConnected = false;
      this.emailOtpPresignConnected = false;
    } else if (kind === 'emailOtp') {
      this.emailOtpPresignConnected = false;
      this.resetWorker('ecdsaPresignClient');
    }
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
