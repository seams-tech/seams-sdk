/**
 * TouchConfirm Manager implementation.
 *
 * Owns the worker/main-thread handshake for touchConfirm UI orchestration
 * and the PRF.first warm-session cache.
 */

import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  WarmSessionSealTransportInput,
  WarmSessionStatusBatchResult,
  WarmSessionDeletePersistedPayload,
  WarmSessionRehydratePayload,
  WarmSessionRehydrateResult,
  WarmSessionSealAndPersistPayload,
  WarmSessionSealAndPersistResult,
  TouchConfirmManagerConfig,
  UserConfirmWorkerMessage,
  UserConfirmWorkerResponse,
} from '../../types/secure-confirm-worker';
import { BUILD_PATHS } from '../../../../../sdk/build-paths';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import {
  clearAllPrfSessionSealedRecords,
  deletePrfSessionSealedRecord,
  readPrfSessionSealedRecord,
  updatePrfSessionSealedRecordPolicy,
  writePrfSessionSealedRecord,
} from '../api/session/prfSessionSealedStore';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
} from '../api/thresholdLifecycle/thresholdSessionStore';
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
import { requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationFlow } from './handlers/flows/requestRegistrationCredentialConfirmation';
import type {
  RequestRegistrationCredentialConfirmationParams,
  RequestUserConfirmationOptions,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
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
    results.push({
      sessionId: entry.sessionId,
      result,
    });
  }
  return { results };
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
        typeof data.message === 'string' ? data.message : 'PRF.first seal and persist failed',
    };
  }
  if (
    typeof data.sealedPrfFirstB64u !== 'string' ||
    typeof data.remainingUses !== 'number' ||
    typeof data.expiresAtMs !== 'number'
  ) {
    return null;
  }
  return {
    ok: true,
    sealedPrfFirstB64u: data.sealedPrfFirstB64u,
    ...(typeof data.keyVersion === 'string' && data.keyVersion.trim()
      ? { keyVersion: data.keyVersion.trim() }
      : {}),
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
  };
}

function parseWarmSessionClaimResult(
  data: unknown,
): WarmSessionClaimResult | null {
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
    (status !== 'progress' && status !== 'success' && status !== 'error')
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

const thresholdPrfRehydrateSingleFlight = new Map<
  string,
  Promise<WarmSessionStatusResult | null>
>();
const thresholdPrfSealPersistSingleFlight = new Map<
  string,
  Promise<WarmSessionSealAndPersistResult>
>();
const thresholdPrfSealDeleteSingleFlight = new Map<string, Promise<void>>();

function makeWarmSessionSingleFlightKey(args: {
  operation: 'rehydrate' | 'persist' | 'delete';
  thresholdSessionId: string;
}): string {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return '';
  return `${args.operation}|${thresholdSessionId}`;
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
  private readonly userConfirmProgressListeners = new Map<
    string,
    (progress: UserConfirmProgressEvent) => void
  >();
  private readonly boundHandleWorkerMessage = this.handleWorkerMessage.bind(this);
  private readonly boundHandleWorkerError = this.handleWorkerError.bind(this);

  constructor(config: TouchConfirmManagerConfig, context: TouchConfirmContext) {
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

  /** Context used by touchConfirm confirmation flows. */
  getContext(): TouchConfirmContext {
    return this.context;
  }

  private isSealedRefreshModeEnabled(): boolean {
    return this.config.signingSessionPersistenceMode === 'sealed_refresh_v1';
  }

  private getSealedRefreshNotEnabledError(context: string): {
    ok: false;
    code: string;
    message: string;
  } {
    return {
      ok: false,
      code: 'not_enabled',
      message: `[TouchConfirm] ${context} requires signingSessionPersistenceMode="sealed_refresh_v1"`,
    };
  }

  private resolveSealTransportInput(
    thresholdSessionIdRaw: string,
    explicitTransport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    } | null,
  ): WarmSessionSealTransportInput | null {
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const sealedRecord = readPrfSessionSealedRecord(thresholdSessionId);
    const ed25519Record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
      thresholdSessionId,
    );
    const ecdsaRecord = getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
      thresholdSessionId,
    );
    const relayerUrl = String(
      explicitTransport?.relayerUrl ||
        sealedRecord?.relayerUrl ||
        ed25519Record?.relayerUrl ||
        ecdsaRecord?.relayerUrl ||
        '',
    ).trim();
    if (!relayerUrl) return null;
    const thresholdSessionJwt = String(
      explicitTransport?.thresholdSessionJwt ||
        sealedRecord?.thresholdSessionJwt ||
        ed25519Record?.thresholdSessionJwt ||
        ecdsaRecord?.thresholdSessionJwt ||
        '',
    ).trim();
    const keyVersion = String(
      explicitTransport?.keyVersion ||
        sealedRecord?.keyVersion ||
        ecdsaRecord?.signingSessionSealKeyVersion ||
        this.config.prfSessionSealKeyVersion ||
        '',
    ).trim();
    const shamirPrimeB64u = String(
      explicitTransport?.shamirPrimeB64u ||
        sealedRecord?.shamirPrimeB64u ||
        ecdsaRecord?.signingSessionSealShamirPrimeB64u ||
        this.config.prfSessionSealShamirPrimeB64u ||
        '',
    ).trim();
    const curve =
      explicitTransport?.curve || sealedRecord?.curve || (ed25519Record ? 'ed25519' : undefined) || (ecdsaRecord ? 'ecdsa' : undefined);
    return {
      ...(curve ? { curve } : {}),
      relayerUrl,
      ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
      ...(keyVersion ? { keyVersion } : {}),
      ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    };
  }

  private async ensureSealedRecordPersistedBestEffort(
    thresholdSessionIdRaw: string,
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    } | null,
  ): Promise<void> {
    if (!this.isSealedRefreshModeEnabled()) return;
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return;
    await this.persistPrfFirstSealForThresholdSession({
      sessionId: thresholdSessionId,
      ...(transport ? { transport } : {}),
    }).catch(() => undefined);
  }

  private async tryRehydrateFromSealedRecord(
    thresholdSessionIdRaw: string,
  ): Promise<WarmSessionStatusResult | null> {
    if (!this.isSealedRefreshModeEnabled()) return null;
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const singleFlightKey = makeWarmSessionSingleFlightKey({
      operation: 'rehydrate',
      thresholdSessionId,
    });

    const inFlight = thresholdPrfRehydrateSingleFlight.get(singleFlightKey);
    if (inFlight) return await inFlight;

    const task = (async (): Promise<WarmSessionStatusResult | null> => {
      const sealedRecord = readPrfSessionSealedRecord(thresholdSessionId);
      if (!sealedRecord) return null;
      if (sealedRecord.remainingUses <= 0 || Date.now() >= sealedRecord.expiresAtMs) {
        deletePrfSessionSealedRecord(thresholdSessionId);
        return {
          ok: false,
          code: 'expired',
          message: 'Warm-session material expired for threshold session',
        };
      }

      const transport = this.resolveSealTransportInput(thresholdSessionId);
      if (!transport) return null;
      const shamirPrimeB64u = String(
        sealedRecord.shamirPrimeB64u || transport.shamirPrimeB64u || '',
      ).trim();
      if (!shamirPrimeB64u) return null;

      const rehydrated = await this.rehydrateWarmSessionMaterial({
        sessionId: thresholdSessionId,
        sealedPrfFirstB64u: sealedRecord.sealedPrfFirstB64u,
        keyVersion: sealedRecord.keyVersion,
        expiresAtMs: sealedRecord.expiresAtMs,
        remainingUses: sealedRecord.remainingUses,
        transport: {
          ...transport,
          shamirPrimeB64u,
        },
      });
      if (!rehydrated.ok) {
        deletePrfSessionSealedRecord(thresholdSessionId);
        return { ok: false, code: rehydrated.code, message: rehydrated.message };
      }

      updatePrfSessionSealedRecordPolicy({
        thresholdSessionId,
        expiresAtMs: rehydrated.expiresAtMs,
        remainingUses: rehydrated.remainingUses,
        updatedAtMs: Date.now(),
      });

      const rehydratedPeek = await this.sendMessage({
        type: 'WARM_SESSION_STATUS_READ',
        id: this.generateMessageId(),
        payload: { sessionId: thresholdSessionId },
      });
      const parsed = parseWarmSessionStatusResult(rehydratedPeek?.data);
      if (rehydratedPeek?.success !== true || !parsed) {
        return {
          ok: false,
          code: 'worker_error',
          message: String(rehydratedPeek?.error || 'Warm-session status read failed after rehydrate'),
        };
      }
      return parsed;
    })().finally(() => {
      thresholdPrfRehydrateSingleFlight.delete(singleFlightKey);
    });

    thresholdPrfRehydrateSingleFlight.set(singleFlightKey, task);
    return await task;
  }

  putWarmSessionMaterial = async (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }): Promise<void> => {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_PUT',
      id: this.generateMessageId(),
      payload: args,
    });
    if (!res?.success) {
      throw new Error(String(res?.error || 'Failed to cache PRF.first for threshold session'));
    }
    const parsed = parseWarmSessionStatusResult(res?.data);
    if (!parsed) {
      throw new Error('Warm-session cache returned an invalid response');
    }
    if (!parsed.ok) {
      throw new Error(
        `Warm-session cache failed (${parsed.code}): ${parsed.message}`,
      );
    }
    await this.ensureSealedRecordPersistedBestEffort(args.sessionId, args.transport || null);
  };

  sealAndPersistWarmSessionMaterial = async (
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('PRF.first seal and persist');
    }
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_SEAL_AND_PERSIST',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseWarmSessionSealAndPersistResult(res?.data);
    if (res?.success !== true || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(res?.error || 'PRF.first seal and persist failed'),
      };
    }
    return parsed;
  };

  rehydrateWarmSessionMaterial = async (
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('PRF.first rehydrate');
    }
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_REHYDRATE',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseWarmSessionStatusResult(res?.data);
    if (res?.success !== true || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(res?.error || 'PRF.first rehydrate failed'),
      };
    }
    return parsed;
  };

  getWarmSessionStatus = async (args: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> => {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_STATUS_READ',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseWarmSessionStatusResult(res?.data);
    if (res?.success !== true || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(res?.error || 'Warm-session status read failed'),
      };
    }
    if (parsed.ok) {
      // Guarantee refresh persistence before returning warm-session readiness.
      // A fire-and-forget seal can race with page refresh and lose warm-session continuity.
      await this.ensureSealedRecordPersistedBestEffort(args.sessionId).catch(() => undefined);
      return parsed;
    }
    if (parsed.code !== 'not_found') {
      if (parsed.code === 'expired' || parsed.code === 'exhausted') {
        deletePrfSessionSealedRecord(args.sessionId);
      }
      return parsed;
    }

    const rehydrated = await this.tryRehydrateFromSealedRecord(args.sessionId);
    if (rehydrated) {
      if (!rehydrated.ok && (rehydrated.code === 'expired' || rehydrated.code === 'exhausted')) {
        deletePrfSessionSealedRecord(args.sessionId);
      }
      return rehydrated;
    }
    return parsed;
  };

  getWarmSessionStatuses = async (args: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    await this.ensureWorkerReady(false);
    const normalizedSessionIds = Array.from(
      new Set(
        (Array.isArray(args.sessionIds) ? args.sessionIds : [])
          .map((value) => String(value || '').trim())
          .filter(Boolean),
      ),
    );
    if (!normalizedSessionIds.length) {
      return { results: [] };
    }
    const res = await this.sendMessage({
      type: 'WARM_SESSION_STATUS_BATCH_READ',
      id: this.generateMessageId(),
      payload: { sessionIds: normalizedSessionIds },
    });
    const parsed = parseWarmSessionStatusBatchResult(res?.data);
    if (res?.success !== true || !parsed) {
      return {
        results: normalizedSessionIds.map((sessionId) => ({
          sessionId,
          result: {
            ok: false,
            code: 'worker_error',
            message: String(res?.error || 'Warm-session batch status read failed'),
          },
        })),
      };
    }
    const results = await Promise.all(
      parsed.results.map(async (entry) => {
        if (entry.result.ok || entry.result.code !== 'not_found') return entry;
        const rehydrated = await this.tryRehydrateFromSealedRecord(entry.sessionId);
        if (!rehydrated) return entry;
        if (!rehydrated.ok && (rehydrated.code === 'expired' || rehydrated.code === 'exhausted')) {
          deletePrfSessionSealedRecord(entry.sessionId);
        }
        return { sessionId: entry.sessionId, result: rehydrated };
      }),
    );
    return { results };
  };

  persistPrfFirstSealForThresholdSession = async (args: {
    sessionId: string;
    transport?: {
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }): Promise<WarmSessionSealAndPersistResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('PRF.first seal persistence');
    }
    const thresholdSessionId = String(args?.sessionId || '').trim();
    if (!thresholdSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
    }
    const singleFlightKey = makeWarmSessionSingleFlightKey({
      operation: 'persist',
      thresholdSessionId,
    });
    const inFlight = thresholdPrfSealPersistSingleFlight.get(singleFlightKey);
    if (inFlight) return await inFlight;

    const task = (async (): Promise<WarmSessionSealAndPersistResult> => {
      const existingRecord = readPrfSessionSealedRecord(thresholdSessionId);
      if (existingRecord) {
        return {
          ok: true,
          sealedPrfFirstB64u: existingRecord.sealedPrfFirstB64u,
          ...(existingRecord.keyVersion ? { keyVersion: existingRecord.keyVersion } : {}),
          remainingUses: existingRecord.remainingUses,
          expiresAtMs: existingRecord.expiresAtMs,
        };
      }

      const inferredTransport =
        this.resolveSealTransportInput(thresholdSessionId, args?.transport || null) || null;
      const relayerUrl = String(
        args?.transport?.relayerUrl || inferredTransport?.relayerUrl || '',
      ).trim();
      const thresholdSessionJwt = String(
        args?.transport?.thresholdSessionJwt || inferredTransport?.thresholdSessionJwt || '',
      ).trim();
      const keyVersion = String(
        args?.transport?.keyVersion ||
          inferredTransport?.keyVersion ||
          this.config.prfSessionSealKeyVersion ||
          '',
      ).trim();
      const shamirPrimeB64u = String(
        args?.transport?.shamirPrimeB64u ||
          inferredTransport?.shamirPrimeB64u ||
          this.config.prfSessionSealShamirPrimeB64u ||
          '',
      ).trim();

      if (!relayerUrl) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing relayerUrl for PRF session seal persistence',
        };
      }
      if (!shamirPrimeB64u) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing shamirPrimeB64u for PRF session seal persistence',
        };
      }

      const sealed = await this.sealAndPersistWarmSessionMaterial({
        sessionId: thresholdSessionId,
        transport: {
          relayerUrl,
          ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
          ...(keyVersion ? { keyVersion } : {}),
          shamirPrimeB64u,
        },
      });
      if (!sealed.ok) return sealed;

      writePrfSessionSealedRecord({
        thresholdSessionId,
        sealedPrfFirstB64u: sealed.sealedPrfFirstB64u,
        curve: inferredTransport?.curve,
        relayerUrl,
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
        keyVersion: sealed.keyVersion,
        shamirPrimeB64u,
        expiresAtMs: sealed.expiresAtMs,
        remainingUses: sealed.remainingUses,
        updatedAtMs: Date.now(),
      });
      const persistedRecord = readPrfSessionSealedRecord(thresholdSessionId);
      if (!persistedRecord) {
        return {
          ok: false,
          code: 'local_persist_failed',
          message: 'Failed to persist sealed PRF.first record locally',
        };
      }
      return sealed;
    })().finally(() => {
      thresholdPrfSealPersistSingleFlight.delete(singleFlightKey);
    });

    thresholdPrfSealPersistSingleFlight.set(singleFlightKey, task);
    return await task;
  };

  claimWarmSessionMaterial = async (args: {
    sessionId: string;
    uses?: number;
  }): Promise<WarmSessionClaimResult> => {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CLAIM',
      id: this.generateMessageId(),
      payload: args,
    });
    const parsed = parseWarmSessionClaimResult(res?.data);
    if (res?.success !== true || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(res?.error || 'Warm-session claim failed'),
      };
    }
    if (!parsed.ok && parsed.code === 'not_found') {
      const rehydrated = await this.tryRehydrateFromSealedRecord(args.sessionId);
      if (rehydrated?.ok) {
        const retry = await this.sendMessage({
          type: 'WARM_SESSION_MATERIAL_CLAIM',
          id: this.generateMessageId(),
          payload: args,
        });
        const retryParsed = parseWarmSessionClaimResult(retry?.data);
        if (retry?.success !== true || !retryParsed) {
          return {
            ok: false,
            code: 'worker_error',
            message: String(retry?.error || 'Warm-session claim failed after rehydrate'),
          };
        }
        return retryParsed;
      }
      if (rehydrated && !rehydrated.ok && (rehydrated.code === 'expired' || rehydrated.code === 'exhausted')) {
        deletePrfSessionSealedRecord(args.sessionId);
      }
      return parsed;
    }
    if (parsed.ok) {
      if (parsed.remainingUses <= 0 || Date.now() >= parsed.expiresAtMs) {
        deletePrfSessionSealedRecord(args.sessionId);
      } else {
        updatePrfSessionSealedRecordPolicy({
          thresholdSessionId: args.sessionId,
          expiresAtMs: parsed.expiresAtMs,
          remainingUses: parsed.remainingUses,
          updatedAtMs: Date.now(),
        });
      }
    } else if (parsed.code === 'expired' || parsed.code === 'exhausted') {
      deletePrfSessionSealedRecord(args.sessionId);
    }
    return parsed;
  };

  clearWarmSessionMaterial = async (args: { sessionId: string }): Promise<void> => {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CLEAR',
      id: this.generateMessageId(),
      payload: args,
    });
    if (!res?.success) {
      throw new Error(
        String(res?.error || 'Failed to clear warm-session material for threshold session'),
      );
    }
    deletePrfSessionSealedRecord(args.sessionId);
  };

  deletePersistedWarmSessionMaterial = async (
    args: WarmSessionDeletePersistedPayload,
  ): Promise<void> => {
    const thresholdSessionId = String(args.sessionId || '').trim();
    if (!thresholdSessionId) return;

    if (!this.isSealedRefreshModeEnabled()) {
      deletePrfSessionSealedRecord(thresholdSessionId);
      return;
    }
    const singleFlightKey = makeWarmSessionSingleFlightKey({
      operation: 'delete',
      thresholdSessionId,
    });
    const inFlight = thresholdPrfSealDeleteSingleFlight.get(singleFlightKey);
    if (inFlight) return await inFlight;

    const task = (async (): Promise<void> => {
      await this.ensureWorkerReady(false);
      const res = await this.sendMessage({
        type: 'WARM_SESSION_DELETE_PERSISTED',
        id: this.generateMessageId(),
        payload: { ...args, sessionId: thresholdSessionId },
      });
      if (!res?.success) {
        throw new Error(String(res?.error || 'Failed to delete persisted PRF.first session seal'));
      }
      const data = isObjectRecord(res.data) ? res.data : null;
      if (data && data.ok === false) {
        const message =
          typeof data.message === 'string'
            ? data.message
            : 'Failed to delete persisted PRF.first session seal';
        throw new Error(message);
      }
      deletePrfSessionSealedRecord(thresholdSessionId);
    })().finally(() => {
      thresholdPrfSealDeleteSingleFlight.delete(singleFlightKey);
    });

    thresholdPrfSealDeleteSingleFlight.set(singleFlightKey, task);
    return await task;
  };

  clearAllWarmSessionMaterial = async (): Promise<void> => {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CLEAR_ALL',
      id: this.generateMessageId(),
      payload: {},
    });
    if (!res?.success) {
      throw new Error(String(res?.error || 'Failed to clear all warm-session material entries'));
    }
    clearAllPrfSessionSealedRecords();
  };

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
      touchConfirm: this,
      nearAccountId: params.nearAccountId,
      signerSlot: params.signerSlot,
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
        this.detachWorkerRouter(this.worker);
        this.worker.terminate();
        this.worker = null;
      }
      this.rejectAllPendingWorkerRequests(new Error('UserConfirm worker was restarted'));

      const relativePath = this.config.workerUrl || BUILD_PATHS.RUNTIME.TOUCH_CONFIRM_WORKER;
      const workerUrlStr = resolveWorkerUrl(relativePath, {
        worker: 'touchConfirm',
        baseOrigin: this.workerBaseOrigin,
      });
      console.debug('[UserConfirmWorker] Worker URL:', workerUrlStr);
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
    return !!this.worker && event.currentTarget === this.worker && event.target === this.worker;
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
    // dispatch them through touchConfirm confirmation flows on the main thread. The decision
    // is sent back to the worker as USER_PASSKEY_CONFIRM_RESPONSE and
    // consumed by awaitUserConfirmationV2; this should not resolve the
    // original request promise.
    const promptEnv = this.normalizePromptEnvelope(payload);
    if (promptEnv) {
      const ctx = this.getContext();
      if (!this.worker) {
        console.error(
          '[UserConfirmWorker] missing worker for PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD',
        );
        return;
      }
      void handlePromptFromWorker(ctx, promptEnv, this.worker).catch((error) => {
        console.error('[UserConfirmWorker] failed to handle confirmation prompt:', error);
        this.postPromptEnvelopeError(
          promptEnv.requestId,
          promptEnv.channelToken || '',
          'Secure confirmation failed',
        );
      });
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
    this.resolvePendingWorkerRequest(responseId, response);
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
      const pingResponse = await this.sendMessage(
        {
          type: 'PING',
          id: this.generateMessageId(),
          payload: {},
        },
        timeoutMs,
      );
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
