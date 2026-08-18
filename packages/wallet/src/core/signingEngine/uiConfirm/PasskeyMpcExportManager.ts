import { BUILD_PATHS } from '../../../../build-paths';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  PasskeyMpcExportWorkerMessage,
  UserConfirmWorkerResponse,
} from '../../types/secure-confirm-worker';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import {
  UserConfirmMessageType,
  UserConfirmationType,
  type UserConfirmPromptEnvelope,
  type UserConfirmRequest,
} from '../stepUpConfirmation/channel/confirmTypes';
import { handlePromptFromWorker } from './handlers/handlePromptFromWorker';
import { validateUserConfirmRequest } from './handlers/flows/adapters/request';
import type {
  ExportPrivateKeysWithUiOptions,
  PasskeyMpcExportPort,
  UiConfirmContext,
} from './uiConfirm.types';

type PendingExportWorkerRequest = {
  id: string;
  timeoutId: ReturnType<typeof setTimeout>;
  resolve: (response: UserConfirmWorkerResponse) => void;
  reject: (error: Error) => void;
};

const PASSKEY_MPC_EXPORT_TIMEOUT_MS = 60_000;

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function parseExportPrivateKeysWithUiWorkerResult(
  data: unknown,
): ExportPrivateKeysWithUiWorkerResult | null {
  if (!isObjectRecord(data)) return null;
  if (typeof data.ok !== 'boolean') return null;
  if (typeof data.accountId !== 'string') return null;
  const rawSchemes = Array.isArray(data.exportedSchemes) ? data.exportedSchemes : null;
  if (!rawSchemes) return null;
  const exportedSchemes = rawSchemes.filter(
    (value): value is 'ed25519' | 'secp256k1' => value === 'ed25519' || value === 'secp256k1',
  );
  if (exportedSchemes.length !== rawSchemes.length) return null;
  return {
    ok: data.ok,
    accountId: data.accountId,
    exportedSchemes,
    ...(typeof data.cancelled === 'boolean' ? { cancelled: data.cancelled } : {}),
    ...(typeof data.error === 'string' ? { error: data.error } : {}),
  };
}

class PasskeyMpcExportManagerImpl implements PasskeyMpcExportPort {
  private worker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private workerBaseOrigin: string | undefined;
  private messageId = 0;
  private readonly pendingRequests = new Map<string, PendingExportWorkerRequest>();
  private readonly viewerLifecycleBySessionId = new Map<
    string,
    (event: 'opened' | 'closed') => void
  >();
  private readonly boundHandleWorkerMessage = this.handleWorkerMessage.bind(this);
  private readonly boundHandleWorkerError = this.handleWorkerError.bind(this);

  constructor(private readonly context: UiConfirmContext) {}

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerBaseOrigin = origin;
  }

  async exportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
    options?: ExportPrivateKeysWithUiOptions,
  ): Promise<ExportPrivateKeysWithUiWorkerResult> {
    await this.ensureWorkerReady();
    const viewerSessionId =
      'viewerSessionId' in payload ? String(payload.viewerSessionId || '').trim() : '';
    if (viewerSessionId && options?.onViewerLifecycle) {
      this.viewerLifecycleBySessionId.set(viewerSessionId, options.onViewerLifecycle);
    }
    try {
      const response = await this.sendMessage({
        type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
        id: this.generateMessageId(),
        payload,
      });
      if (!response.success) {
        throw new Error(String(response.error || 'Export private keys request failed'));
      }
      const parsed = parseExportPrivateKeysWithUiWorkerResult(response.data);
      if (!parsed) {
        throw new Error('Export private keys request failed: invalid worker response payload');
      }
      return parsed;
    } finally {
      if (viewerSessionId) {
        this.viewerLifecycleBySessionId.delete(viewerSessionId);
      }
    }
  }

  private async ensureWorkerReady(): Promise<void> {
    if (this.worker) return;
    if (!this.initializationPromise) {
      this.initializationPromise = this.createWorker().catch((error) => {
        this.initializationPromise = null;
        throw error;
      });
    }
    await this.initializationPromise;
    if (!this.worker) {
      throw new Error('Passkey MPC export worker failed to initialize');
    }
  }

  private async createWorker(): Promise<void> {
    const workerUrl = resolveWorkerUrl(BUILD_PATHS.RUNTIME.PASSKEY_MPC_EXPORT_WORKER, {
      worker: 'passkeyMpcExport',
      baseOrigin: this.workerBaseOrigin,
    });
    const worker = new Worker(workerUrl, {
      type: 'module',
      name: 'PasskeyMpcExportWorker',
    });
    worker.addEventListener('message', this.boundHandleWorkerMessage);
    worker.addEventListener('error', this.boundHandleWorkerError);
    this.worker = worker;
  }

  private normalizePromptEnvelope(payload: unknown): UserConfirmPromptEnvelope | null {
    if (!isObjectRecord(payload)) return null;
    if (payload.type !== UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD) return null;
    if (!isObjectRecord(payload.data)) return null;
    let request: UserConfirmRequest;
    try {
      request = validateUserConfirmRequest(payload.data);
    } catch {
      return null;
    }
    const requestId = typeof payload.requestId === 'string' ? payload.requestId.trim() : '';
    const dataRequestId = typeof request.requestId === 'string' ? request.requestId.trim() : '';
    const channelToken =
      typeof payload.channelToken === 'string' ? payload.channelToken.trim() : '';
    if (!requestId || requestId !== dataRequestId || !channelToken) return null;
    return {
      type: UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
      requestId,
      channelToken,
      data: this.restoreViewerLifecycle(request),
    };
  }

  private restoreViewerLifecycle(request: UserConfirmRequest): UserConfirmRequest {
    if (request.type !== UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI) return request;
    const payload = isObjectRecord(request.payload) ? request.payload : null;
    if (!payload) return request;
    const viewerSessionId =
      'viewerSessionId' in payload ? String(payload.viewerSessionId || '').trim() : '';
    if (!viewerSessionId) return request;
    const onLifecycle = this.viewerLifecycleBySessionId.get(viewerSessionId);
    if (!onLifecycle) return request;
    Object.assign(payload, { onLifecycle });
    return request;
  }

  private postPromptEnvelopeError(
    worker: Worker,
    requestId: string,
    channelToken: string,
  ): void {
    worker.postMessage({
      type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE,
      requestId,
      channelToken,
      data: {
        requestId,
        confirmed: false,
        error: 'Secure confirmation failed',
      },
    });
  }

  private handleWorkerMessage(event: MessageEvent): void {
    if (event.currentTarget !== this.worker || event.target !== this.worker) return;
    const promptEnvelope = this.normalizePromptEnvelope(event.data);
    if (promptEnvelope) {
      const worker = event.currentTarget as Worker;
      void handlePromptFromWorker(this.context, promptEnvelope, worker).catch((error) => {
        console.error('[PasskeyMpcExportWorker] failed to handle export prompt:', error);
        this.postPromptEnvelopeError(
          worker,
          promptEnvelope.requestId,
          promptEnvelope.channelToken || '',
        );
      });
      return;
    }
    if (
      isObjectRecord(event.data) &&
      event.data.type === UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD
    ) {
      console.error('[PasskeyMpcExportWorker] rejected malformed prompt envelope');
      return;
    }
    const response = event.data as UserConfirmWorkerResponse;
    const responseId = typeof response.id === 'string' ? response.id.trim() : '';
    if (!responseId) return;
    const pending = this.pendingRequests.get(responseId);
    if (!pending) return;
    clearTimeout(pending.timeoutId);
    this.pendingRequests.delete(responseId);
    pending.resolve(response);
  }

  private handleWorkerError(event: Event): void {
    if (event.currentTarget !== this.worker || event.target !== this.worker) return;
    const errorEvent = event as ErrorEvent;
    const error = new Error(
      `Passkey MPC export worker failed: ${String(
        errorEvent.message || 'unknown worker error',
      )}`,
    );
    const failedWorker = this.worker;
    if (failedWorker) {
      failedWorker.removeEventListener('message', this.boundHandleWorkerMessage);
      failedWorker.removeEventListener('error', this.boundHandleWorkerError);
      failedWorker.terminate();
    }
    this.worker = null;
    this.initializationPromise = null;
    for (const pending of this.pendingRequests.values()) {
      clearTimeout(pending.timeoutId);
      pending.reject(error);
    }
    this.pendingRequests.clear();
  }

  private sendMessage(message: PasskeyMpcExportWorkerMessage): Promise<UserConfirmWorkerResponse> {
    return new Promise((resolve, reject) => {
      const worker = this.worker;
      if (!worker) {
        reject(new Error('Passkey MPC export worker not available'));
        return;
      }
      const requestId =
        typeof message.id === 'string' && message.id.trim()
          ? message.id.trim()
          : this.generateMessageId();
      if (this.pendingRequests.has(requestId)) {
        reject(new Error(`Duplicate Passkey MPC export request id: ${requestId}`));
        return;
      }
      const timeoutId = setTimeout(() => {
        const pending = this.pendingRequests.get(requestId);
        if (!pending) return;
        this.pendingRequests.delete(requestId);
        pending.reject(
          new Error(`Passkey MPC export request timed out (${PASSKEY_MPC_EXPORT_TIMEOUT_MS}ms)`),
        );
      }, PASSKEY_MPC_EXPORT_TIMEOUT_MS);
      this.pendingRequests.set(requestId, {
        id: requestId,
        timeoutId,
        resolve,
        reject,
      });
      try {
        worker.postMessage({ ...message, id: requestId });
      } catch (error: unknown) {
        clearTimeout(timeoutId);
        this.pendingRequests.delete(requestId);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  private generateMessageId(): string {
    return `mpc_export_${Date.now()}_${++this.messageId}`;
  }
}

export function createPasskeyMpcExportManager(context: UiConfirmContext): PasskeyMpcExportPort {
  return new PasskeyMpcExportManagerImpl(context);
}
