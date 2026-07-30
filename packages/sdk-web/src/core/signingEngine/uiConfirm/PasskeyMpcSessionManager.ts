import { BUILD_PATHS } from '../../../../build-paths';
import type {
  PasskeyMpcSessionWorkerMessage,
  UserConfirmWorkerResponse,
  WarmSessionRehydratePayload,
  WarmSessionRehydrateResult,
  WarmSessionSealAndPersistPayload,
  WarmSessionSealAndPersistResult,
  WarmSessionStatusBatchResult,
} from '../../types/secure-confirm-worker';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import type { WarmSessionLanePurpose } from '../session/emailOtp/sealedRuntimePurpose';
import type {
  WarmSessionMaterialWriteDiagnosticBucket,
  WarmSessionMaterialWriteDiagnostics,
} from '../session/passkey/warmSessionMaterialWriter';
import { parseClearVolatileWarmMaterialCommand } from '../session/warmCapabilities/volatileWarmMaterialCommands';
import type {
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  PasskeyMpcSessionPort,
  WarmSessionPersistedDiscovery,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from './uiConfirm.types';
import { listExactSealedSessionsForWallet } from '../session/persistence/sealedSessionStore';
import { discoverPersistedSessionsForWalletCommand } from '../session/sealedRecovery/restoreCoordinator';
import type { DiscoverPersistedSessionsForWalletResult } from '../session/sealedRecovery/sealedRecovery.types';

type PendingPasskeyMpcSessionRequest = {
  id: string;
  timeoutId: ReturnType<typeof setTimeout>;
  resolve: (response: UserConfirmWorkerResponse) => void;
  reject: (error: Error) => void;
};

export interface PasskeyMpcSessionDurableWorkerPort {
  sealAndPersistWarmSessionMaterial(
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult>;
  rehydrateWarmSessionMaterial(
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult>;
}

export type PasskeyMpcSessionManagerPort = PasskeyMpcSessionPort &
  PasskeyMpcSessionDurableWorkerPort;

type PasskeyMpcSessionManagerDeps = {
  signingSessionPersistenceMode: 'none' | 'sealed_refresh_v1';
  persistSigningSessionSealForThresholdSession(args: {
    sessionId: string;
    transport: NonNullable<
      Parameters<PasskeyMpcSessionPort['putWarmSessionMaterial']>[0]['transport']
    >;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<WarmSessionSealAndPersistResult | null>;
  onPolicyResult(
    purpose: WarmSessionLanePurpose,
    result: WarmSessionStatusResult | WarmSessionClaimResult,
  ): Promise<void>;
};

const PASSKEY_MPC_SESSION_TIMEOUT_MS = 60_000;
const PASSKEY_MPC_SESSION_STARTUP_TIMEOUT_MS = 15_000;

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function parseWarmSessionStatusResult(data: unknown): WarmSessionStatusResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message: typeof data.message === 'string' ? data.message : 'Warm-session status read failed',
    };
  }
  if (typeof data.remainingUses !== 'number' || typeof data.expiresAtMs !== 'number') return null;
  return {
    ok: true,
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
  };
}

function parseWarmSessionStatusBatchResult(data: unknown): WarmSessionStatusBatchResult | null {
  if (!isObjectRecord(data) || !Array.isArray(data.results)) return null;
  const results: WarmSessionStatusBatchResult['results'] = [];
  for (const entry of data.results) {
    if (!isObjectRecord(entry) || typeof entry.sessionId !== 'string') return null;
    const result = parseWarmSessionStatusResult(entry.result);
    if (!result) return null;
    results.push({ sessionId: entry.sessionId, result });
  }
  return { results };
}

function parseWarmSessionClaimResult(data: unknown): WarmSessionClaimResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message: typeof data.message === 'string' ? data.message : 'Warm-session claim failed',
    };
  }
  if (
    typeof data.prfFirstB64u !== 'string' ||
    typeof data.remainingUses !== 'number' ||
    typeof data.expiresAtMs !== 'number'
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

function parseWarmSessionSealAndPersistResult(
  data: unknown,
): WarmSessionSealAndPersistResult | null {
  if (!isObjectRecord(data) || typeof data.ok !== 'boolean') return null;
  if (!data.ok) {
    return {
      ok: false,
      code: typeof data.code === 'string' ? data.code : 'worker_error',
      message:
        typeof data.message === 'string' ? data.message : 'Signing-session seal and persist failed',
    };
  }
  if (
    typeof data.sealedSecretB64u !== 'string' ||
    typeof data.remainingUses !== 'number' ||
    typeof data.expiresAtMs !== 'number'
  ) {
    return null;
  }
  const diagnostics = isObjectRecord(data.diagnostics)
    ? {
        runtimeSetupMs: positiveInteger(data.diagnostics.runtimeSetupMs),
        clientSealMs: positiveInteger(data.diagnostics.clientSealMs),
        serverSealRouteMs: positiveInteger(data.diagnostics.serverSealRouteMs),
        clientUnsealMs: positiveInteger(data.diagnostics.clientUnsealMs),
        policyUpdateMs: positiveInteger(data.diagnostics.policyUpdateMs),
      }
    : undefined;
  return {
    ok: true,
    sealedSecretB64u: data.sealedSecretB64u,
    ...(typeof data.keyVersion === 'string' && data.keyVersion.trim()
      ? { keyVersion: data.keyVersion.trim() }
      : {}),
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
    ...(diagnostics ? { diagnostics } : {}),
  };
}

function roundDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function recordDiagnosticDuration(args: {
  diagnostics: WarmSessionMaterialWriteDiagnostics | undefined;
  bucket: WarmSessionMaterialWriteDiagnosticBucket;
  startedAt: number;
}): void {
  args.diagnostics?.recordDuration(args.bucket, roundDurationMs(args.startedAt));
}

class PasskeyMpcSessionManagerImpl implements PasskeyMpcSessionManagerPort {
  private worker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private workerBaseOrigin: string | undefined;
  private messageId = 0;
  private readonly pendingRequests = new Map<string, PendingPasskeyMpcSessionRequest>();
  private readonly boundHandleWorkerMessage = this.handleWorkerMessage.bind(this);
  private readonly boundHandleWorkerError = this.handleWorkerError.bind(this);

  constructor(private readonly deps: PasskeyMpcSessionManagerDeps) {}

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerBaseOrigin = origin;
  }

  async prewarmShamir3Pass(): Promise<void> {
    try {
      await this.sendMessage(
        {
          type: 'PREWARM_SHAMIR3PASS',
          id: this.generateMessageId(),
          payload: {},
        },
        PASSKEY_MPC_SESSION_STARTUP_TIMEOUT_MS,
      );
    } catch {
      // Prewarming is best-effort; the first real operation retries initialization.
    }
  }

  putWarmSessionMaterial = async (
    args: Parameters<PasskeyMpcSessionPort['putWarmSessionMaterial']>[0],
  ): Promise<void> => {
    const { diagnostics, ...workerPayload } = args;
    const workerReadyStartedAt = performance.now();
    await this.ensureWorkerReady();
    recordDiagnosticDuration({
      diagnostics,
      bucket: 'worker_ready',
      startedAt: workerReadyStartedAt,
    });
    const workerPutStartedAt = performance.now();
    const response = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_PUT',
      id: this.generateMessageId(),
      payload: workerPayload,
    });
    if (!response.success) {
      throw new Error(String(response.error || 'Failed to cache warm-session material'));
    }
    const parsed = parseWarmSessionStatusResult(response.data);
    if (!parsed) {
      throw new Error('Warm-session cache returned an invalid response');
    }
    if (!parsed.ok) {
      throw new Error(`Warm-session cache failed (${parsed.code}): ${parsed.message}`);
    }
    recordDiagnosticDuration({
      diagnostics,
      bucket: 'worker_put',
      startedAt: workerPutStartedAt,
    });
    const persistStartedAt = performance.now();
    const persisted = args.transport
      ? await this.deps.persistSigningSessionSealForThresholdSession({
          sessionId: args.sessionId,
          transport: args.transport,
          ...(diagnostics ? { diagnostics } : {}),
        })
      : null;
    recordDiagnosticDuration({
      diagnostics,
      bucket: 'sealed_record_persist',
      startedAt: persistStartedAt,
    });
    if (persisted && !persisted.ok) {
      throw new Error(
        `Warm-session cache could not persist sealed refresh material (${persisted.code}): ${persisted.message}`,
      );
    }
  };

  getWarmSessionStatus = async (args: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> => await this.readWarmSessionStatus(args);

  discoverPersistedSessionsForWallet = async (
    args: Parameters<WarmSessionPersistedDiscovery['discoverPersistedSessionsForWallet']>[0],
  ): Promise<DiscoverPersistedSessionsForWalletResult> => {
    if (this.deps.signingSessionPersistenceMode !== 'sealed_refresh_v1') {
      return { listed: 0, discovered: 0, truncated: 0 };
    }
    return await discoverPersistedSessionsForWalletCommand(
      { ...args, authMethod: 'passkey' },
      {
        listExactSealedSessionsForWallet: async (filter) =>
          await listExactSealedSessionsForWallet({
            walletId: filter.walletId,
            filter:
              filter.curve === 'ecdsa'
                ? {
                    authMethod: 'passkey',
                    curve: 'ecdsa',
                    chainTarget: filter.chainTarget,
                  }
                : { authMethod: 'passkey', curve: 'ed25519' },
          }),
        onListError: ({ walletId, error }) => {
          console.warn('[PasskeyMpcSession] persisted-session discovery list failed', {
            walletId,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
        onRejectedRecord: ({ walletId, rejection }) => {
          console.warn('[PasskeyMpcSession] persisted-session discovery rejected record', {
            walletId,
            rejection,
          });
        },
      },
    );
  };

  getWarmSessionStatuses = async (args: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    const sessionIds = Array.from(
      new Set(args.sessionIds.map((value) => String(value || '').trim()).filter(Boolean)),
    );
    if (!sessionIds.length) return { results: [] };
    const response = await this.sendMessage({
      type: 'WARM_SESSION_STATUS_BATCH_READ',
      id: this.generateMessageId(),
      payload: { sessionIds },
    });
    const parsed = parseWarmSessionStatusBatchResult(response.data);
    if (response.success && parsed) return parsed;
    return {
      results: sessionIds.map((sessionId) => ({
        sessionId,
        result: {
          ok: false,
          code: 'worker_error',
          message: String(response.error || 'Warm-session batch status read failed'),
        },
      })),
    };
  };

  claimWarmSessionMaterial = async (args: {
    purpose: WarmSessionLanePurpose;
    uses?: number;
    consume?: boolean;
  }): Promise<WarmSessionClaimResult> => {
    const response = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CLAIM',
      id: this.generateMessageId(),
      payload: {
        sessionId: args.purpose.thresholdSessionId,
        ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
        ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
        curve: args.purpose.curve,
      },
    });
    const parsed = parseWarmSessionClaimResult(response.data);
    if (!response.success || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(response.error || 'Warm-session claim failed'),
      };
    }
    await this.deps.onPolicyResult(args.purpose, parsed);
    return parsed;
  };

  consumeWarmSessionUses = async (args: {
    purpose: WarmSessionLanePurpose;
    uses?: number;
  }): Promise<WarmSessionStatusResult> => {
    const response = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CONSUME',
      id: this.generateMessageId(),
      payload: {
        sessionId: args.purpose.thresholdSessionId,
        ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
        curve: args.purpose.curve,
      },
    });
    const parsed = parseWarmSessionStatusResult(response.data);
    if (!response.success || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(response.error || 'Warm-session consume failed'),
      };
    }
    await this.deps.onPolicyResult(args.purpose, parsed);
    return parsed;
  };

  clearVolatileWarmSessionMaterial = async (
    args: ClearVolatileWarmSessionMaterialCommand,
  ): Promise<void> => {
    const command = parseClearVolatileWarmMaterialCommand(args);
    if (command?.scope.kind !== 'session') return;
    if (!this.worker && !this.initializationPromise) return;
    const response = await this.sendMessage({
      type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR',
      id: this.generateMessageId(),
      payload: command,
    });
    if (!response.success) {
      throw new Error(String(response.error || 'Failed to clear volatile warm-session material'));
    }
  };

  clearAllVolatileWarmSessionMaterial = async (
    args: ClearAllVolatileWarmSessionMaterialCommand,
  ): Promise<void> => {
    const command = parseClearVolatileWarmMaterialCommand(args);
    if (command?.scope.kind !== 'all') return;
    if (!this.worker && !this.initializationPromise) return;
    const response = await this.sendMessage({
      type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR_ALL',
      id: this.generateMessageId(),
      payload: command,
    });
    if (!response.success) {
      throw new Error(
        String(response.error || 'Failed to clear all volatile warm-session material entries'),
      );
    }
  };

  async sealAndPersistWarmSessionMaterial(
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult> {
    if (this.deps.signingSessionPersistenceMode !== 'sealed_refresh_v1') {
      return {
        ok: false,
        code: 'not_enabled',
        message: 'Passkey MPC session sealing requires sealed refresh mode',
      };
    }
    const response = await this.sendMessage({
      type: 'WARM_SESSION_SEAL_AND_PERSIST',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseWarmSessionSealAndPersistResult(response.data);
    if (response.success && parsed) return parsed;
    return {
      ok: false,
      code: 'worker_error',
      message: String(response.error || 'Signing-session seal and persist failed'),
    };
  }

  async rehydrateWarmSessionMaterial(
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult> {
    if (this.deps.signingSessionPersistenceMode !== 'sealed_refresh_v1') {
      return {
        ok: false,
        code: 'not_enabled',
        message: 'Passkey MPC session rehydration requires sealed refresh mode',
      };
    }
    const response = await this.sendMessage({
      type: 'WARM_SESSION_REHYDRATE',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseWarmSessionStatusResult(response.data);
    if (response.success && parsed) return parsed;
    return {
      ok: false,
      code: 'worker_error',
      message: String(response.error || 'Warm-session rehydrate failed'),
    };
  }

  private async readWarmSessionStatus(args: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> {
    const response = await this.sendMessage({
      type: 'WARM_SESSION_STATUS_READ',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseWarmSessionStatusResult(response.data);
    if (response.success && parsed) return parsed;
    return {
      ok: false,
      code: 'worker_error',
      message: String(response.error || 'Warm-session status read failed'),
    };
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
      throw new Error('Passkey MPC session worker failed to initialize');
    }
  }

  private async createWorker(): Promise<void> {
    const workerUrl = resolveWorkerUrl(BUILD_PATHS.RUNTIME.PASSKEY_MPC_SESSION_WORKER, {
      worker: 'passkeyMpcSession',
      baseOrigin: this.workerBaseOrigin,
    });
    const worker = new Worker(workerUrl, {
      type: 'module',
      name: 'PasskeyMpcSessionWorker',
    });
    worker.addEventListener('message', this.boundHandleWorkerMessage);
    worker.addEventListener('error', this.boundHandleWorkerError);
    this.worker = worker;
  }

  private async sendMessage(
    message: PasskeyMpcSessionWorkerMessage,
    timeoutMs = PASSKEY_MPC_SESSION_TIMEOUT_MS,
  ): Promise<UserConfirmWorkerResponse> {
    await this.ensureWorkerReady();
    const worker = this.worker;
    if (!worker) {
      throw new Error('Passkey MPC session worker not available');
    }
    const id = String(message.id || this.generateMessageId());
    if (this.pendingRequests.has(id)) {
      throw new Error(`Duplicate Passkey MPC session worker request id: ${id}`);
    }
    return await new Promise<UserConfirmWorkerResponse>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.rejectPendingRequest(
          id,
          new Error(
            `Passkey MPC session worker communication timeout (${timeoutMs}ms) for ${message.type}`,
          ),
        );
      }, timeoutMs);
      this.pendingRequests.set(id, { id, timeoutId, resolve, reject });
      try {
        worker.postMessage({ ...message, id });
      } catch (error) {
        this.rejectPendingRequest(
          id,
          error instanceof Error ? error : new Error(String(error)),
        );
      }
    });
  }

  private handleWorkerMessage(event: MessageEvent): void {
    if (event.currentTarget !== this.worker || event.target !== this.worker) return;
    const response = event.data as UserConfirmWorkerResponse;
    const id = typeof response?.id === 'string' ? response.id.trim() : '';
    if (!id) return;
    const pending = this.pendingRequests.get(id);
    if (!pending) return;
    clearTimeout(pending.timeoutId);
    this.pendingRequests.delete(id);
    pending.resolve(response);
  }

  private handleWorkerError(event: Event): void {
    if (event.currentTarget !== this.worker || event.target !== this.worker) return;
    const worker = this.worker;
    this.worker = null;
    this.initializationPromise = null;
    worker?.removeEventListener('message', this.boundHandleWorkerMessage);
    worker?.removeEventListener('error', this.boundHandleWorkerError);
    worker?.terminate();
    const errorEvent = event as ErrorEvent;
    const error = new Error(
      `Passkey MPC session worker failed: ${String(errorEvent.message || 'unknown error')}`,
    );
    for (const pending of this.pendingRequests.values()) {
      clearTimeout(pending.timeoutId);
      pending.reject(error);
    }
    this.pendingRequests.clear();
  }

  private rejectPendingRequest(id: string, error: Error): void {
    const pending = this.pendingRequests.get(id);
    if (!pending) return;
    clearTimeout(pending.timeoutId);
    this.pendingRequests.delete(id);
    pending.reject(error);
  }

  private generateMessageId(): string {
    return `passkey_mpc_session_${Date.now()}_${++this.messageId}`;
  }
}

export function createPasskeyMpcSessionManager(
  deps: PasskeyMpcSessionManagerDeps,
): PasskeyMpcSessionManagerPort {
  return new PasskeyMpcSessionManagerImpl(deps);
}
