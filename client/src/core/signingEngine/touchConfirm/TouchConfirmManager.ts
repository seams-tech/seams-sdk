/**
 * TouchConfirm Manager implementation.
 *
 * Owns the worker/main-thread handshake for touchConfirm UI orchestration
 * and the PRF.first warm-session cache.
 */

import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  TouchConfirmManagerConfig,
  UserConfirmWorkerMessage,
  UserConfirmWorkerResponse,
} from '../../types/secure-confirm-worker';
import { BUILD_PATHS } from '../../../../../sdk/build-paths';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import {
  UserConfirmMessageType,
  type UserConfirmDecision,
  type UserConfirmProgressEvent,
  type UserConfirmPromptEnvelope,
  type UserConfirmRequest,
} from './shared/confirmTypes';
import { handlePromptFromWorker } from './handlers/handlePromptFromWorker';
import {
  orchestrateSigningConfirmation,
  type OrchestrateSigningConfirmationParams,
  type SigningConfirmationResultIntentDigest,
  type SigningConfirmationResultWithTxContext,
} from './handlers/flowOrchestrator';
import {
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationFlow,
} from './handlers/flows/requestRegistrationCredentialConfirmation';
import type {
  RequestRegistrationCredentialConfirmationParams,
  RequestUserConfirmationOptions,
  ThresholdPrfCacheDispenseResult,
  ThresholdPrfCachePeekResult,
  TouchConfirmContext,
  TouchConfirmManager,
} from './types';

type PendingWorkerRequest = {
  id: string;
  messageType: string;
  timeoutId: ReturnType<typeof setTimeout>;
  settle?: () => void;
  resolve: (response: UserConfirmWorkerResponse) => void;
  reject: (error: Error) => void;
};

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function parseThresholdPrfCachePeekResult(data: unknown): ThresholdPrfCachePeekResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message: typeof data.message === 'string' ? data.message : 'PRF.first cache peek failed',
    };
  }
  if (typeof data.remainingUses !== 'number' || typeof data.expiresAtMs !== 'number') return null;
  return {
    ok: true,
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
  };
}

function parseThresholdPrfCacheDispenseResult(data: unknown): ThresholdPrfCacheDispenseResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message: typeof data.message === 'string' ? data.message : 'PRF.first cache dispense failed',
    };
  }
  if (
    typeof data.prfFirstB64u !== 'string'
    || typeof data.remainingUses !== 'number'
    || typeof data.expiresAtMs !== 'number'
  ) {
    return null;
  }
  return {
    ok: true,
    prfFirstB64u: data.prfFirstB64u,
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
  };
}

function parseUserConfirmProgressEvent(data: unknown): UserConfirmProgressEvent | null {
  if (!isObjectRecord(data)) return null;
  const requestId = typeof data.requestId === 'string' ? data.requestId.trim() : '';
  const step = typeof data.step === 'number' ? data.step : Number.NaN;
  const phase = typeof data.phase === 'string' ? data.phase : '';
  const status = data.status;
  if (
    !requestId
    || !Number.isFinite(step)
    || !phase
    || (status !== 'progress' && status !== 'success' && status !== 'error')
  ) {
    return null;
  }
  return {
    requestId,
    step,
    phase,
    status,
    ...(typeof data.message === 'string' ? { message: data.message } : {}),
    ...('data' in data ? { data: data.data } : {}),
  };
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

/**
 * Concrete implementation for the touchConfirm worker manager ports.
 */
class TouchConfirmWorkerManagerImpl implements TouchConfirmManager {
  private worker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private messageId = 0;
  private config: TouchConfirmManagerConfig;
  private workerBaseOrigin: string | undefined;
  private context: TouchConfirmContext;
  private readonly pendingWorkerRequests = new Map<string, PendingWorkerRequest>();
  private readonly userConfirmProgressListeners = new Map<string, (progress: UserConfirmProgressEvent) => void>();
  private readonly boundHandleWorkerMessage = this.handleWorkerMessage.bind(this);
  private readonly boundHandleWorkerError = this.handleWorkerError.bind(this);

  constructor(config: TouchConfirmManagerConfig, context: TouchConfirmContext) {
    this.config = {
      // Default to client-hosted worker file using centralized config
      workerUrl: BUILD_PATHS.RUNTIME.TOUCH_CONFIRM_WORKER,
      workerTimeout: 60_000,
      debug: false,
      ...config
    };
    this.context = {
      ...context,
      requestUserConfirmation: this.requestUserConfirmation.bind(this),
    };
  }

  /** Context used by touchConfirm confirmation flows. */
  getContext(): TouchConfirmContext {
    return this.context;
  }

  async putPrfFirstForThresholdSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void> {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_PUT',
      id: this.generateMessageId(),
      payload: args,
    });
    if (!res?.success) {
      throw new Error(String(res?.error || 'Failed to cache PRF.first for threshold session'));
    }
  }

  async peekPrfFirstForThresholdSession(args: {
    sessionId: string;
  }): Promise<ThresholdPrfCachePeekResult> {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_PEEK',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseThresholdPrfCachePeekResult(res?.data);
    if (res?.success !== true || !parsed) {
      return { ok: false, code: 'worker_error', message: String(res?.error || 'PRF.first cache peek failed') };
    }
    return parsed;
  }

  async dispensePrfFirstForThresholdSession(args: {
    sessionId: string;
    uses?: number;
  }): Promise<ThresholdPrfCacheDispenseResult> {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseThresholdPrfCacheDispenseResult(res?.data);
    if (res?.success !== true || !parsed) {
      return { ok: false, code: 'worker_error', message: String(res?.error || 'PRF.first cache dispense failed') };
    }
    return parsed;
  }

  async clearPrfFirstForThresholdSession(args: { sessionId: string }): Promise<void> {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_CLEAR',
      id: this.generateMessageId(),
      payload: args,
    });
    if (!res?.success) {
      throw new Error(String(res?.error || 'Failed to clear PRF.first cache for threshold session'));
    }
  }

  async requestUserConfirmation(
    request: UserConfirmRequest,
    options?: RequestUserConfirmationOptions,
  ): Promise<UserConfirmDecision> {
    const requestId = typeof request?.requestId === 'string' ? request.requestId.trim() : '';
    if (!requestId) {
      throw new Error('Invalid secure confirmation request: missing requestId');
    }

    await this.ensureWorkerReady(false);
    if (options?.onProgress) {
      this.userConfirmProgressListeners.set(requestId, options.onProgress);
    }

    try {
      const response = await this.sendMessage({
        type: 'SECURE_CONFIRM_REQUEST',
        id: this.generateMessageId(),
        payload: { request },
      });
      if (!response?.success) {
        throw new Error(String(response?.error || 'Secure confirmation request failed'));
      }
      const decision = response?.data as UserConfirmDecision;
      if (!decision || typeof decision !== 'object') {
        throw new Error('Secure confirmation request failed: invalid worker response payload');
      }
      if (String(decision.requestId || '').trim() !== requestId) {
        throw new Error('Secure confirmation request failed: response requestId mismatch');
      }
      return decision;
    } finally {
      this.userConfirmProgressListeners.delete(requestId);
    }
  }

  async exportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ): Promise<ExportPrivateKeysWithUiWorkerResult> {
    await this.ensureWorkerReady(false);
    const response = await this.sendMessage({
      type: 'EXPORT_PRIVATE_KEYS_WITH_UI',
      id: this.generateMessageId(),
      payload,
    });
    if (!response?.success) {
      throw new Error(String(response?.error || 'Export private keys request failed'));
    }
    const parsed = parseExportPrivateKeysWithUiWorkerResult(response.data);
    if (!parsed) {
      throw new Error('Export private keys request failed: invalid worker response payload');
    }
    return parsed;
  }

  /**
   * TouchConfirm orchestration helper for signing confirmation flows.
   * Runs touchConfirm confirmation flows on the main thread and returns artifacts needed by the signer worker.
   */
  async orchestrateSigningConfirmation(
    params: Extract<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultIntentDigest>;
  async orchestrateSigningConfirmation(
    params: Exclude<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultWithTxContext>;
  async orchestrateSigningConfirmation(
    params: OrchestrateSigningConfirmationParams,
  ): Promise<SigningConfirmationResultWithTxContext | SigningConfirmationResultIntentDigest> {
    return orchestrateSigningConfirmation(params);
  }

  /**
   * UserConfirm helper for registration confirmation.
   * Runs touchConfirm confirmation flows on the main thread and returns registration artifacts.
   */
  async requestRegistrationCredentialConfirmation(
    params: RequestRegistrationCredentialConfirmationParams,
  ) {
    return requestRegistrationCredentialConfirmationFlow({
      ctx: this.getContext(),
      nearAccountId: params.nearAccountId,
      deviceNumber: params.deviceNumber,
      confirmerText: params.confirmerText,
      nearRpcUrl: params.nearRpcUrl,
      confirmationConfig: params.confirmationConfigOverride,
    });
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerBaseOrigin = origin;
  }

  /**
   * Ensure the UserConfirm worker is ready for operations
   * @param requireHealthCheck - Whether to perform health check after initialization
   */
  private async ensureWorkerReady(requireHealthCheck = false): Promise<void> {
    if (this.initializationPromise) {
      await this.initializationPromise;
    } else if (!this.worker) {
      await this.initialize();
    }
    if (!this.worker) {
      throw new Error('UserConfirm worker failed to initialize');
    }
    // Optional health check for critical operations
    if (requireHealthCheck) {
      try {
        const healthResponse = await this.sendMessage({
          type: 'PING',
          id: this.generateMessageId(),
          payload: {}
        }, 3000);

        if (!healthResponse.success) {
          throw new Error('UserConfirm worker failed health check');
        }
      } catch (error) {
        console.error('[UserConfirmWorker] health check failed:', error);
        throw new Error('UserConfirm worker failed health check');
      }
    }
  }

  /**
   * Initialize the UserConfirm worker.
   */
  async initialize(): Promise<void> {
    if (this.initializationPromise) {
      return this.initializationPromise;
    }
    if (this.worker) {
      return;
    }
    // =============================================================
    // This improved error handling ensures that:
    // 1. Initialization failures are properly logged with full details
    // 2. Errors are re-thrown to callers (no silent swallowing)
    // 3. Failed initialization promise is reset for retry
    // 4. Debug logs actually appear in test output
    this.initializationPromise = this.createUserConfirmWorker().catch(error => {
      console.error('[UserConfirmWorker] initialization failed:', error);
      console.error('[UserConfirmWorker] error details:', {
        message: error.message,
        stack: error.stack,
        name: error.name
      });
      // Reset promise so initialization can be retried
      this.initializationPromise = null;
      throw error; // Re-throw so callers know it failed
    });

    const result = await this.initializationPromise;
    return result;
  }

  /** Initialize the UserConfirm worker (client-hosted bundle). */
  private async createUserConfirmWorker(): Promise<void> {
    try {
      if (this.worker) {
        this.detachWorkerRouter(this.worker);
        this.worker.terminate();
        this.worker = null;
      }
      this.rejectAllPendingWorkerRequests(new Error('UserConfirm worker was restarted'));

      const relativePath = this.config.workerUrl || BUILD_PATHS.RUNTIME.TOUCH_CONFIRM_WORKER;
      const workerUrlStr = resolveWorkerUrl(relativePath, { worker: 'touchConfirm', baseOrigin: this.workerBaseOrigin });
      console.debug('[UserConfirmWorker] Worker URL:', workerUrlStr);
      const worker = new Worker(workerUrlStr, {
        type: 'module',
        name: 'Web3AuthnSecureConfirmWorker'
      });
      this.attachWorkerRouter(worker);
      this.worker = worker;
      // Test communication with the Web Worker
      await this.testWebWorkerCommunication();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`UserConfirm worker initialization failed: ${message}`);
    }
  }

  private attachWorkerRouter(worker: Worker): void {
    worker.addEventListener('message', this.boundHandleWorkerMessage);
    worker.addEventListener('error', this.boundHandleWorkerError);
  }

  private detachWorkerRouter(worker: Worker): void {
    worker.removeEventListener('message', this.boundHandleWorkerMessage);
    worker.removeEventListener('error', this.boundHandleWorkerError);
  }

  private isFromActiveWorker(event: Event): boolean {
    return !!this.worker
      && event.currentTarget === this.worker
      && event.target === this.worker;
  }

  private normalizePromptEnvelope(payload: unknown): UserConfirmPromptEnvelope | null {
    if (!payload || typeof payload !== 'object') {
      return null;
    }
    const typedPayload = payload as {
      type?: unknown;
      requestId?: unknown;
      channelToken?: unknown;
      data?: unknown;
    };
    if (typedPayload.type !== UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD) {
      return null;
    }
    if (!typedPayload.data || typeof typedPayload.data !== 'object') {
      return null;
    }
    const request = typedPayload.data as UserConfirmRequest;
    const dataRequestId = typeof request?.requestId === 'string' ? request.requestId.trim() : '';
    const requestId = typeof typedPayload.requestId === 'string' ? typedPayload.requestId.trim() : '';
    if (!dataRequestId || !requestId || requestId !== dataRequestId) {
      return null;
    }
    const channelToken = typeof typedPayload.channelToken === 'string'
      ? typedPayload.channelToken.trim()
      : '';
    if (!channelToken) {
      return null;
    }
    return {
      type: UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
      requestId,
      channelToken,
      data: request,
    };
  }

  private postPromptEnvelopeError(requestId: string, channelToken: string, message: string): void {
    if (!this.worker) {
      return;
    }
    this.worker.postMessage({
      type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE,
      requestId,
      channelToken,
      data: {
        requestId,
        confirmed: false,
        error: message,
      },
    });
  }

  private dispatchUserConfirmProgress(payload: { requestId?: unknown; data?: unknown }): void {
    const progressEvent = parseUserConfirmProgressEvent(payload.data);
    const requestId = typeof payload.requestId === 'string' && payload.requestId.trim()
      ? payload.requestId.trim()
      : (typeof progressEvent?.requestId === 'string' ? progressEvent.requestId.trim() : '');
    if (!requestId || !progressEvent) {
      return;
    }
    const listener = this.userConfirmProgressListeners.get(requestId);
    if (!listener) {
      return;
    }
    try {
      listener(progressEvent);
    } catch (error) {
      console.error('[UserConfirmWorker] progress listener failed:', error);
    }
  }

  private handleWorkerMessage(event: MessageEvent): void {
    if (!this.isFromActiveWorker(event)) {
      return;
    }

    const payload = event.data as UserConfirmWorkerResponse | {
      type?: unknown;
      requestId?: unknown;
      data?: unknown;
    };

    if ((payload as { type?: unknown }).type === UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS) {
      this.dispatchUserConfirmProgress(payload as { requestId?: unknown; data?: unknown });
      return;
    }

    // Intercept UserConfirm handshake messages from the worker and
    // dispatch them through touchConfirm confirmation flows on the main thread. The decision
    // is sent back to the worker as USER_PASSKEY_CONFIRM_RESPONSE and
    // consumed by awaitUserConfirmationV2; this should not resolve the
    // original request promise.
    const promptEnv = this.normalizePromptEnvelope(payload);
    if (promptEnv) {
      const ctx = this.getContext();
      if (!this.worker) {
        console.error('[UserConfirmWorker] missing worker for PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD');
        return;
      }
      void handlePromptFromWorker(ctx, promptEnv, this.worker).catch((error) => {
        console.error('[UserConfirmWorker] failed to handle confirmation prompt:', error);
        this.postPromptEnvelopeError(promptEnv.requestId, promptEnv.channelToken || '', 'Secure confirmation failed');
      });
      return;
    }

    if ((payload as { type?: unknown }).type === UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD) {
      console.error('[UserConfirmWorker] rejected malformed prompt envelope');
      return;
    }

    const response = payload as UserConfirmWorkerResponse;
    const responseId = typeof response?.id === 'string' ? response.id.trim() : '';
    if (!responseId) {
      return;
    }
    this.resolvePendingWorkerRequest(responseId, response);
  }

  private handleWorkerError(event: Event): void {
    if (!this.isFromActiveWorker(event)) {
      return;
    }
    const errorEvent = event as ErrorEvent;
    const message = String(errorEvent?.message || 'UserConfirm worker encountered an unknown error');
    const error = new Error(`UserConfirm worker failed: ${message}`);
    console.error('[UserConfirmWorker] error:', errorEvent);
    this.rejectAllPendingWorkerRequests(error);
  }

  private resolvePendingWorkerRequest(id: string, response: UserConfirmWorkerResponse): void {
    const pending = this.pendingWorkerRequests.get(id);
    if (!pending) {
      return;
    }
    clearTimeout(pending.timeoutId);
    pending.settle?.();
    this.pendingWorkerRequests.delete(id);
    pending.resolve(response);
  }

  private rejectPendingWorkerRequest(id: string, error: Error): void {
    const pending = this.pendingWorkerRequests.get(id);
    if (!pending) {
      return;
    }
    clearTimeout(pending.timeoutId);
    pending.settle?.();
    this.pendingWorkerRequests.delete(id);
    pending.reject(error);
  }

  private rejectAllPendingWorkerRequests(error: Error): void {
    if (!this.pendingWorkerRequests.size) {
      return;
    }
    const pending = Array.from(this.pendingWorkerRequests.values());
    this.pendingWorkerRequests.clear();
    for (const req of pending) {
      clearTimeout(req.timeoutId);
      req.settle?.();
      req.reject(error);
    }
  }

  /**
   * Send message to Web Worker and wait for response
   */
  private async sendMessage<TPayload = unknown>(
    message: UserConfirmWorkerMessage<TPayload>,
    customTimeout?: number,
    signal?: AbortSignal,
  ): Promise<UserConfirmWorkerResponse> {
    return new Promise((resolve, reject) => {
      const worker = this.worker;
      if (!worker) {
        reject(new Error('UserConfirm worker not available'));
        return;
      }

      const abortedError = () => new Error(`UserConfirm worker request aborted for message type: ${message.type}`);
      if (signal?.aborted) {
        reject(abortedError());
        return;
      }

      const requestId = typeof message.id === 'string' && message.id.trim().length
        ? message.id.trim()
        : this.generateMessageId();
      if (this.pendingWorkerRequests.has(requestId)) {
        reject(new Error(`Duplicate UserConfirm worker request id: ${requestId}`));
        return;
      }

      const timeoutMs = (customTimeout ?? this.config.workerTimeout ?? 60_000);
      const timeoutId = setTimeout(() => {
        this.rejectPendingWorkerRequest(
          requestId,
          new Error(`UserConfirm worker communication timeout (${timeoutMs}ms) for message type: ${message.type}`)
        );
      }, timeoutMs);

      let settle: (() => void) | undefined;
      if (signal) {
        const abortHandler = () => {
          this.rejectPendingWorkerRequest(requestId, abortedError());
        };
        signal.addEventListener('abort', abortHandler, { once: true });
        settle = () => {
          signal.removeEventListener('abort', abortHandler);
        };
      }

      this.pendingWorkerRequests.set(requestId, {
        id: requestId,
        messageType: message.type,
        timeoutId,
        settle,
        resolve,
        reject,
      });

      try {
        worker.postMessage({ ...message, id: requestId });
      } catch (error: unknown) {
        const normalizedError = error instanceof Error ? error : new Error(String(error));
        this.rejectPendingWorkerRequest(requestId, normalizedError);
      }
    });
  }

  /**
   * Generate unique message ID
   */
  private generateMessageId(): string {
    return `sc_${Date.now()}_${++this.messageId}`;
  }

  /**
   * Test Web Worker communication
   */
  private async testWebWorkerCommunication(): Promise<void> {
    try {
      const timeoutMs = 2000;
      const pingResponse = await this.sendMessage({
        type: 'PING',
        id: this.generateMessageId(),
        payload: {}
      }, timeoutMs);
      if (!pingResponse.success) {
        throw new Error(`UserConfirm worker PING failed: ${pingResponse.error}`);
      }
      return;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('[UserConfirmWorker] testWebWorkerCommunication failed:', message);
    }
  }
}

export function createTouchConfirmManager(
  config: TouchConfirmManagerConfig,
  context: TouchConfirmContext,
): TouchConfirmManager {
  return new TouchConfirmWorkerManagerImpl(config, context);
}
