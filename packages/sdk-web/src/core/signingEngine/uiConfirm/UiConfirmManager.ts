/**
 * UiConfirm Manager
 * Owns the worker/main-thread handshake for uiConfirm UI orchestration
 * and the warm-session material cache.
 */

import type {
  UiConfirmManagerConfig,
  UserConfirmWorkerMessage,
  UserConfirmWorkerResponse,
} from '../../types/secure-confirm-worker';
import { BUILD_PATHS } from '../../../../build-paths';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import {
  UserConfirmMessageType,
  UserConfirmationType,
  type UserConfirmDecision,
  type UserConfirmPromptEnvelope,
  type UserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmProgressEvent } from '../stepUpConfirmation/types';
import { handlePromptFromWorker } from './handlers/handlePromptFromWorker';
import { orchestrateSigningConfirmation } from './handlers/flowOrchestrator';
import type {
  OrchestrateNearSignatureOnlySigningConfirmationParams,
  OrchestrateNearTransactionSigningConfirmationParams,
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultSignatureOnly,
  NearTransactionSigningConfirmationResult,
} from '../stepUpConfirmation/confirmOperation';
import { requestRegistrationCredentialConfirmationOnMainThread } from './handlers/flows/requestRegistrationCredentialConfirmation';
import {
  mountConfirmUI,
  type ConfirmUISurfaceSource,
  type MountedConfirmUIHandle,
} from './ui/confirm-ui';
import type {
  OpenRegistrationPreparationModalParams,
  OpenTransactionPreparationModalParams,
  RequestRegistrationCredentialConfirmationParams,
  RequestUserConfirmationOptions,
  UiConfirmContext,
  UiConfirmManager,
} from './uiConfirm.types';
import { normalizeConfirmationConfig } from '@/core/types/confirmationConfig';

type PendingWorkerRequest = {
  id: string;
  messageType: string;
  worker: Worker;
  timeoutId: ReturnType<typeof setTimeout>;
  settle?: () => void;
  resolve: (response: UserConfirmWorkerResponse) => void;
  reject: (error: Error) => void;
};

type RegistrationPreparationModalState =
  | { kind: 'closed'; generation: number }
  | { kind: 'opening'; generation: number }
  | { kind: 'open'; generation: number; handle: MountedConfirmUIHandle };

type TransactionPreparationModalState =
  | { kind: 'closed'; generation: number }
  | { kind: 'opening'; generation: number }
  | { kind: 'open'; generation: number; handle: MountedConfirmUIHandle };

const USER_CONFIRM_WORKER_STARTUP_PING_TIMEOUT_MS = 15_000;

function roundUiConfirmDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function assertNever(value: never): never {
  throw new Error(`Unexpected UI confirmation state: ${String(value)}`);
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function stripFunctionsForWorkerMessage<T>(value: T): T {
  if (typeof value === 'function') {
    return undefined as T;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => stripFunctionsForWorkerMessage(entry)) as T;
  }
  if (!isObjectRecord(value)) {
    return value;
  }
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'function') continue;
    output[key] = stripFunctionsForWorkerMessage(entry);
  }
  return output as T;
}

function maybeCopyEmailOtpResendHandler(args: {
  targetPrompt: unknown;
  sourcePrompt: unknown;
}): unknown {
  if (!isObjectRecord(args.targetPrompt) || !isObjectRecord(args.sourcePrompt)) {
    return args.targetPrompt;
  }
  const onResend = args.sourcePrompt.onResend;
  if (typeof onResend !== 'function') {
    return args.targetPrompt;
  }
  return {
    ...args.targetPrompt,
    onResend,
  };
}

function parseUserConfirmProgressEvent(data: unknown): UserConfirmProgressEvent | null {
  if (!isObjectRecord(data)) return null;
  const requestId = typeof data.requestId === 'string' ? data.requestId.trim() : '';
  const step = typeof data.step === 'number' ? data.step : Number.NaN;
  const phase = typeof data.phase === 'string' ? data.phase : '';
  const status = data.status;
  if (
    !requestId ||
    !Number.isFinite(step) ||
    !phase ||
    (status !== 'running' && status !== 'succeeded' && status !== 'failed')
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

/**
 * Concrete implementation for the uiConfirm worker manager ports.
 */
class UiConfirmWorkerManagerImpl implements UiConfirmManager {
  private worker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private messageId = 0;
  private config: UiConfirmManagerConfig;
  private workerBaseOrigin: string | undefined;
  private context: UiConfirmContext;
  private readonly pendingWorkerRequests = new Map<string, PendingWorkerRequest>();
  private readonly userConfirmProgressListeners = new Map<
    string,
    (progress: UserConfirmProgressEvent) => void
  >();
  private readonly pendingFunctionBearingConfirmRequests = new Map<string, UserConfirmRequest>();
  private readonly boundHandleWorkerMessage = this.handleWorkerMessage.bind(this);
  private readonly boundHandleWorkerError = this.handleWorkerError.bind(this);
  private registrationPreparationModalState: RegistrationPreparationModalState = {
    kind: 'closed',
    generation: 0,
  };
  private transactionPreparationModalState: TransactionPreparationModalState = {
    kind: 'closed',
    generation: 0,
  };
  constructor(
    config: UiConfirmManagerConfig,
    context: UiConfirmContext,
  ) {
    this.config = {
      // Default to client-hosted worker file using centralized config
      workerUrl: BUILD_PATHS.RUNTIME.TOUCH_CONFIRM_WORKER,
      workerTimeout: 60_000,
      debug: false,
      signingSessionPersistenceMode: 'none',
      ...config,
    };
    this.context = {
      ...context,
    };
  }

  /** Context used by uiConfirm confirmation flows. */
  getContext(): UiConfirmContext {
    return this.context;
  }

  async requestUserConfirmation(
    request: UserConfirmRequest,
    options?: RequestUserConfirmationOptions,
  ): Promise<UserConfirmDecision> {
    const requestId = typeof request?.requestId === 'string' ? request.requestId.trim() : '';
    if (!requestId) {
      throw new Error('Invalid secure confirmation request: missing requestId');
    }

    const workerReadyStartedAt = performance.now();
    await this.ensureWorkerReady(false);
    const workerReadyMs = roundUiConfirmDurationMs(workerReadyStartedAt);
    if (options?.onProgress) {
      this.userConfirmProgressListeners.set(requestId, options.onProgress);
    }
    this.pendingFunctionBearingConfirmRequests.set(requestId, request);
    const workerSafeRequest = stripFunctionsForWorkerMessage(request);

    try {
      const requestRoundTripStartedAt = performance.now();
      const response = await this.sendMessage({
        type: 'SECURE_CONFIRM_REQUEST',
        id: this.generateMessageId(),
        payload: { request: workerSafeRequest },
      });
      const workerRequestRoundTripMs = roundUiConfirmDurationMs(requestRoundTripStartedAt);
      const responseValidationStartedAt = performance.now();
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
      const workerResponseValidationMs = roundUiConfirmDurationMs(responseValidationStartedAt);
      if (decision.registrationDiagnostics?.kind !== 'registration_confirmation_diagnostics_v1') {
        return decision;
      }
      return {
        ...decision,
        registrationDiagnostics: {
          ...decision.registrationDiagnostics,
          workerReadyMs,
          workerRequestRoundTripMs,
          workerResponseValidationMs,
        },
      };
    } finally {
      this.userConfirmProgressListeners.delete(requestId);
      this.pendingFunctionBearingConfirmRequests.delete(requestId);
    }
  }

  /**
   * UiConfirm orchestration helper for signing confirmation flows.
   * Runs uiConfirm confirmation flows on the main thread and returns artifacts needed by the signer worker.
   */
  async orchestrateSigningConfirmation(
    params: Extract<OrchestrateSigningConfirmationParams, { kind: 'intentDigest' }>,
  ): Promise<SigningConfirmationResultIntentDigest>;
  async orchestrateSigningConfirmation(
    params: OrchestrateNearTransactionSigningConfirmationParams,
  ): Promise<NearTransactionSigningConfirmationResult>;
  async orchestrateSigningConfirmation(
    params: OrchestrateNearSignatureOnlySigningConfirmationParams,
  ): Promise<SigningConfirmationResultSignatureOnly>;
  async orchestrateSigningConfirmation(
    params: OrchestrateSigningConfirmationParams,
  ): Promise<
    | NearTransactionSigningConfirmationResult
    | SigningConfirmationResultIntentDigest
    | SigningConfirmationResultSignatureOnly
  > {
    return orchestrateSigningConfirmation(params);
  }

  async openTransactionPreparationModal(
    params: OpenTransactionPreparationModalParams,
  ): Promise<void> {
    const walletLabel = String(params.walletLabel || '').trim();
    if (!walletLabel) {
      throw new Error('Transaction preparation modal requires a wallet label');
    }

    this.closeTransactionPreparationModal();
    const storedConfig = this.context.userPreferencesManager.getConfirmationConfig();
    const override = Object.fromEntries(
      Object.entries(params.confirmationConfigOverride || {}).filter(
        ([, value]) => value !== undefined && value !== null,
      ),
    );
    const confirmationConfig = normalizeConfirmationConfig({ ...storedConfig, ...override });
    if (confirmationConfig.kind === 'silent') return;
    const rpId = String(this.context.touchIdPrompt.getRpId() || '').trim();

    const generation = this.transactionPreparationModalState.generation + 1;
    this.transactionPreparationModalState = { kind: 'opening', generation };
    const handle = await mountConfirmUI({
      ctx: this.getContext(),
      summary: { title: 'Confirm transaction' },
      model: params.model,
      securityContext: rpId ? { rpId } : undefined,
      loading: true,
      theme: this.context.getTheme?.() ?? 'dark',
      uiMode: confirmationConfig.uiMode,
      nearAccountIdOverride: walletLabel,
    });
    const state = this.transactionPreparationModalState;
    if (state.kind !== 'opening' || state.generation !== generation) {
      handle.close(false);
      return;
    }
    this.transactionPreparationModalState = { kind: 'open', generation, handle };
  }

  closeTransactionPreparationModal(): void {
    const state = this.transactionPreparationModalState;
    this.transactionPreparationModalState = {
      kind: 'closed',
      generation: state.generation,
    };
    if (state.kind === 'open') {
      state.handle.close(false);
    }
  }

  private takeTransactionConfirmationSurface(): ConfirmUISurfaceSource {
    const state = this.transactionPreparationModalState;
    switch (state.kind) {
      case 'closed':
        return { kind: 'mount_new' };
      case 'opening':
        throw new Error('Transaction confirmation started before its preparation modal opened');
      case 'open':
        this.transactionPreparationModalState = {
          kind: 'closed',
          generation: state.generation,
        };
        return { kind: 'reuse_mounted', handle: state.handle };
      default:
        return assertNever(state);
    }
  }

  /**
   * UserConfirm helper for registration confirmation.
   * Runs uiConfirm confirmation flows on the main thread and returns registration artifacts.
   */
  async requestRegistrationCredentialConfirmation(
    params: RequestRegistrationCredentialConfirmationParams,
  ) {
    const surface = this.takeRegistrationConfirmationSurface();
    try {
      return await requestRegistrationCredentialConfirmationOnMainThread({
        ctx: this.getContext(),
        surface,
        walletId: params.walletId,
        nearAccountId: params.nearAccountId,
        signerSlot: params.signerSlot,
        confirmerText: params.confirmerText,
        confirmationConfig: params.confirmationConfigOverride,
        challengeB64u: params.challengeB64u,
      });
    } catch (error) {
      if (surface.kind === 'reuse_mounted') {
        surface.handle.close(false);
      }
      throw error;
    }
  }

  private takeRegistrationConfirmationSurface(): ConfirmUISurfaceSource {
    const state = this.registrationPreparationModalState;
    switch (state.kind) {
      case 'closed':
        return { kind: 'mount_new' };
      case 'opening':
        throw new Error('Registration confirmation started before its preparation modal opened');
      case 'open':
        this.registrationPreparationModalState = {
          kind: 'closed',
          generation: state.generation,
        };
        return { kind: 'reuse_mounted', handle: state.handle };
      default:
        return assertNever(state);
    }
  }

  async openRegistrationPreparationModal(
    params: OpenRegistrationPreparationModalParams,
  ): Promise<void> {
    const walletLabel = String(params.walletLabel || '').trim();
    if (!walletLabel) {
      throw new Error('Registration preparation modal requires a wallet label');
    }
    if (!Number.isInteger(params.signerSlot) || params.signerSlot < 1) {
      throw new Error('Registration preparation modal requires a positive signer slot');
    }
    const rpId = String(this.context.touchIdPrompt.getRpId() || '').trim();
    if (!rpId) {
      throw new Error('Registration preparation modal requires an RP ID');
    }

    this.closeRegistrationPreparationModal();
    const generation = this.registrationPreparationModalState.generation + 1;
    this.registrationPreparationModalState = { kind: 'opening', generation };
    const handle = await mountConfirmUI({
      ctx: this.getContext(),
      summary: {
        title: 'Create your passkey',
        body: 'Preparing secure registration…',
      },
      securityContext: {
        rpId,
        passkeyRegistration: {
          kind: 'passkey_registration_confirm_display_v1',
          intendedUserName: walletLabel,
          accountId: walletLabel,
          rpId,
          signerSlot: params.signerSlot,
        },
      },
      loading: true,
      theme: this.context.getTheme?.() ?? 'dark',
      uiMode: 'modal',
      nearAccountIdOverride: walletLabel,
    });
    const state = this.registrationPreparationModalState;
    if (state.kind !== 'opening' || state.generation !== generation) {
      handle.close(false);
      return;
    }
    this.registrationPreparationModalState = { kind: 'open', generation, handle };
  }

  closeRegistrationPreparationModal(): void {
    const state = this.registrationPreparationModalState;
    this.registrationPreparationModalState = {
      kind: 'closed',
      generation: state.generation,
    };
    if (state.kind === 'open') {
      state.handle.close(false);
    }
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
        const healthResponse = await this.sendMessage(
          {
            type: 'PING',
            id: this.generateMessageId(),
            payload: {},
          },
          3000,
        );

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
    this.initializationPromise = this.createUserConfirmWorker().catch((error) => {
      console.error('[UserConfirmWorker] initialization failed:', error);
      console.error('[UserConfirmWorker] error details:', {
        message: error.message,
        stack: error.stack,
        name: error.name,
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
        const restartedWorker = this.worker;
        this.detachWorkerRouter(restartedWorker);
        restartedWorker.terminate();
        this.worker = null;
        this.rejectPendingWorkerRequestsForWorker(
          restartedWorker,
          new Error('UserConfirm worker was restarted'),
        );
      }

      const relativePath = this.config.workerUrl || BUILD_PATHS.RUNTIME.TOUCH_CONFIRM_WORKER;
      const workerUrlStr = resolveWorkerUrl(relativePath, {
        worker: 'touchConfirm',
        baseOrigin: this.workerBaseOrigin,
      });
      if (this.config.debug) {
        console.debug('[UserConfirmWorker] Worker URL:', workerUrlStr);
      }
      const worker = new Worker(workerUrlStr, {
        type: 'module',
        name: 'Web3AuthnSecureConfirmWorker',
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
    const source = event.currentTarget;
    return source === this.worker && event.target === this.worker;
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
    const requestId =
      typeof typedPayload.requestId === 'string' ? typedPayload.requestId.trim() : '';
    if (!dataRequestId || !requestId || requestId !== dataRequestId) {
      return null;
    }
    const channelToken =
      typeof typedPayload.channelToken === 'string' ? typedPayload.channelToken.trim() : '';
    if (!channelToken) {
      return null;
    }
    const restoredRequest = this.restoreFunctionBearingConfirmRequestFields(requestId, request);
    return {
      type: UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD,
      requestId,
      channelToken,
      data: restoredRequest,
    };
  }

  private restoreFunctionBearingConfirmRequestFields(
    requestId: string,
    request: UserConfirmRequest,
  ): UserConfirmRequest {
    const original = this.pendingFunctionBearingConfirmRequests.get(requestId);
    if (!original) return request;
    const requestWithUnknownPayload = request as unknown as { payload?: unknown };
    const originalWithUnknownPayload = original as unknown as { payload?: unknown };
    const payload = isObjectRecord(requestWithUnknownPayload.payload)
      ? { ...requestWithUnknownPayload.payload }
      : null;
    const originalPayload = isObjectRecord(originalWithUnknownPayload.payload)
      ? originalWithUnknownPayload.payload
      : null;
    if (!payload || !originalPayload) return request;

    if (payload.emailOtpPrompt || originalPayload.emailOtpPrompt) {
      payload.emailOtpPrompt = maybeCopyEmailOtpResendHandler({
        targetPrompt: payload.emailOtpPrompt,
        sourcePrompt: originalPayload.emailOtpPrompt,
      });
    }

    if (
      typeof originalPayload.onLifecycle === 'function' &&
      typeof payload.onLifecycle !== 'function'
    ) {
      payload.onLifecycle = originalPayload.onLifecycle;
    }

    const signingAuthPlan = payload.signingAuthPlan;
    const originalSigningAuthPlan = originalPayload.signingAuthPlan;
    if (isObjectRecord(signingAuthPlan) && isObjectRecord(originalSigningAuthPlan)) {
      const restoredSigningAuthPlan: Record<string, unknown> = { ...signingAuthPlan };
      restoredSigningAuthPlan.emailOtpPrompt = maybeCopyEmailOtpResendHandler({
        targetPrompt: signingAuthPlan.emailOtpPrompt,
        sourcePrompt: originalSigningAuthPlan.emailOtpPrompt,
      });
      payload.signingAuthPlan = restoredSigningAuthPlan;
    }

    return {
      ...(request as object),
      payload,
    } as unknown as UserConfirmRequest;
  }

  private postPromptEnvelopeError(
    worker: Worker,
    requestId: string,
    channelToken: string,
    message: string,
  ): void {
    worker.postMessage({
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
    const requestId =
      typeof payload.requestId === 'string' && payload.requestId.trim()
        ? payload.requestId.trim()
        : typeof progressEvent?.requestId === 'string'
          ? progressEvent.requestId.trim()
          : '';
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

    const payload = event.data as
      | UserConfirmWorkerResponse
      | {
          type?: unknown;
          requestId?: unknown;
          data?: unknown;
        };

    if (
      (payload as { type?: unknown }).type === UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS
    ) {
      this.dispatchUserConfirmProgress(payload as { requestId?: unknown; data?: unknown });
      return;
    }

    // Intercept UserConfirm handshake messages from the worker and
    // dispatch them through uiConfirm confirmation flows on the main thread. The decision
    // is sent back to the worker as USER_PASSKEY_CONFIRM_RESPONSE and
    // consumed by awaitUserConfirmationV2; this should not resolve the
    // original request promise.
    const promptEnv = this.normalizePromptEnvelope(payload);
    if (promptEnv) {
      const ctx = this.getContext();
      const sourceWorker = event.currentTarget as Worker | null;
      if (!sourceWorker) {
        console.error(
          '[UserConfirmWorker] missing worker for PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD',
        );
        return;
      }
      const signingSurface =
        promptEnv.data.type === UserConfirmationType.SIGN_TRANSACTION ||
        promptEnv.data.type === UserConfirmationType.SIGN_NEP413_MESSAGE ||
        promptEnv.data.type === UserConfirmationType.SIGN_INTENT_DIGEST
          ? this.takeTransactionConfirmationSurface()
          : { kind: 'mount_new' as const };
      void handlePromptFromWorker(ctx, promptEnv, sourceWorker, { signingSurface }).catch(
        (error) => {
        console.error('[UserConfirmWorker] failed to handle confirmation prompt:', error);
        this.postPromptEnvelopeError(
          sourceWorker,
          promptEnv.requestId,
          promptEnv.channelToken || '',
          'Secure confirmation failed',
        );
        },
      );
      return;
    }

    if (
      (payload as { type?: unknown }).type ===
      UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD
    ) {
      console.error('[UserConfirmWorker] rejected malformed prompt envelope');
      return;
    }

    const response = payload as UserConfirmWorkerResponse;
    const responseId = typeof response?.id === 'string' ? response.id.trim() : '';
    if (!responseId) {
      return;
    }
    const sourceWorker = event.currentTarget as Worker;
    this.resolvePendingWorkerRequest(sourceWorker, responseId, response);
  }

  private handleWorkerError(event: Event): void {
    if (!this.isFromActiveWorker(event)) {
      return;
    }
    const errorEvent = event as ErrorEvent;
    const message = String(
      errorEvent?.message || 'UserConfirm worker encountered an unknown error',
    );
    const error = new Error(`UserConfirm worker failed: ${message}`);
    console.error('[UserConfirmWorker] error:', errorEvent);
    const failedWorker = event.currentTarget;
    if (failedWorker === this.worker && this.worker) {
      this.detachWorkerRouter(this.worker);
      this.worker.terminate();
      this.worker = null;
      this.initializationPromise = null;
    }
    this.rejectPendingWorkerRequestsForWorker(failedWorker as Worker, error);
  }

  private resolvePendingWorkerRequest(
    sourceWorker: Worker,
    id: string,
    response: UserConfirmWorkerResponse,
  ): void {
    const pending = this.pendingWorkerRequests.get(id);
    if (!pending || pending.worker !== sourceWorker) {
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

  private rejectPendingWorkerRequestsForWorker(worker: Worker, error: Error): void {
    for (const req of this.pendingWorkerRequests.values()) {
      if (req.worker !== worker) continue;
      this.pendingWorkerRequests.delete(req.id);
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

      const abortedError = () =>
        new Error(`UserConfirm worker request aborted for message type: ${message.type}`);
      if (signal?.aborted) {
        reject(abortedError());
        return;
      }

      const requestId =
        typeof message.id === 'string' && message.id.trim().length
          ? message.id.trim()
          : this.generateMessageId();
      if (this.pendingWorkerRequests.has(requestId)) {
        reject(new Error(`Duplicate UserConfirm worker request id: ${requestId}`));
        return;
      }

      const timeoutMs = customTimeout ?? this.config.workerTimeout ?? 60_000;
      const timeoutId = setTimeout(() => {
        this.rejectPendingWorkerRequest(
          requestId,
          new Error(
            `UserConfirm worker communication timeout (${timeoutMs}ms) for message type: ${message.type}`,
          ),
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
        worker,
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
      const pingResponse = await this.sendMessage(
        {
          type: 'PING',
          id: this.generateMessageId(),
          payload: {},
        },
        USER_CONFIRM_WORKER_STARTUP_PING_TIMEOUT_MS,
      );
      if (!pingResponse.success) {
        throw new Error(`UserConfirm worker PING failed: ${pingResponse.error}`);
      }
      return;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn('[UserConfirmWorker] testWebWorkerCommunication failed:', message);
      if (this.worker) {
        this.detachWorkerRouter(this.worker);
        this.worker.terminate();
        this.worker = null;
      }
      throw error;
    }
  }
}

export function createUiConfirmManager(
  config: UiConfirmManagerConfig,
  context: UiConfirmContext,
): UiConfirmManager {
  return new UiConfirmWorkerManagerImpl(config, context);
}
