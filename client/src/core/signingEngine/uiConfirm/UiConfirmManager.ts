 /**
  * UiConfirm Manager
 * Owns the worker/main-thread handshake for uiConfirm UI orchestration
 * and the warm-session material cache.
 */

import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
  WarmSessionSealTransportInput,
  WarmSessionStatusBatchResult,
  WarmSessionRehydratePayload,
  WarmSessionRehydrateResult,
  WarmSessionSealAndPersistPayload,
  WarmSessionSealAndPersistResult,
  UiConfirmManagerConfig,
  UserConfirmWorkerMessage,
  UserConfirmWorkerResponse,
} from '../../types/secure-confirm-worker';
import { BUILD_PATHS } from '../../../../../sdk/build-paths';
import { toAccountId } from '../../types/accountIds';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import {
  acquireSigningSessionRestoreLease,
  buildCurrentSealedSessionRecord,
  deleteDurableSealedSessionRecord as deleteDurableSealedSessionRecordFromStore,
  deleteExactSealedSession,
  listExactSealedSessionsForWallet,
  readExactSealedSession,
  releaseSigningSessionRestoreLease,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
  type BuildCurrentSealedSessionRecordInput,
  type SigningSessionSealedStoreRecord,
  type SigningSessionSealedRecordFilter,
} from '../session/persistence/sealedSessionStore';
import {
  createDeleteDurableSealedSessionCommand,
  type DeleteDurableSealedSessionCommand,
  type DurableSealedSessionDeleteReason,
} from '../session/persistence/durableSealedSessionCommands';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  thresholdEcdsaRecordRpId,
} from '../session/persistence/records';
import { normalizeThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import {
  UserConfirmMessageType,
  type UserConfirmDecision,
  type UserConfirmPromptEnvelope,
  type UserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { UserConfirmProgressEvent } from '../stepUpConfirmation/types';
import { handlePromptFromWorker } from './handlers/handlePromptFromWorker';
import { orchestrateSigningConfirmation } from './handlers/flowOrchestrator';
import type {
  OrchestrateSigningConfirmationParams,
  SigningConfirmationResultIntentDigest,
  SigningConfirmationResultWithTxContext,
} from '../stepUpConfirmation/confirmOperation';
import { requestRegistrationCredentialConfirmationOnMainThread } from './handlers/flows/requestRegistrationCredentialConfirmation';
import type {
  RequestRegistrationCredentialConfirmationParams,
  RequestUserConfirmationOptions,
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
  UiConfirmContext,
  UiConfirmManager,
} from './types';
import {
  restorePersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '../session/sealedRecovery/restoreCoordinator';
import { parseClearVolatileWarmMaterialCommand } from '../session/warmCapabilities/volatileWarmMaterialCommands';
import { restorePasskeyEcdsaSealedRecordForWallet } from '../session/passkey/ecdsaRecovery';
import { restorePasskeyEd25519SealedRecordForAccount } from '../session/passkey/ed25519Recovery';
import type {
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestoreSealedRecordResult,
} from '../session/sealedRecovery/types';
import type {
  SealedRecoveryRecord,
} from '../session/sealedRecovery/recoveryRecord';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../session/identity/laneIdentity';

type PendingWorkerRequest = {
  id: string;
  messageType: string;
  timeoutId: ReturnType<typeof setTimeout>;
  settle?: () => void;
  resolve: (response: UserConfirmWorkerResponse) => void;
  reject: (error: Error) => void;
};

const USER_CONFIRM_WORKER_STARTUP_PING_TIMEOUT_MS = 15_000;

function roundUiConfirmDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

type PasskeySealedRecordAccountMetadata = {
  walletId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  ecdsaRestore?: SigningSessionSealedStoreRecord['ecdsaRestore'];
  ed25519Restore?: SigningSessionSealedStoreRecord['ed25519Restore'];
};

type SigningSessionSealedAuthMethod = 'passkey' | 'email_otp';

type WarmSessionSealAuthMethodInput =
  | {
      thresholdSessionId: string;
      curve: 'ed25519';
      chainTarget?: never;
    }
  | {
      thresholdSessionId: string;
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

function assertNever(value: never): never {
  throw new Error(`Unexpected warm-session seal auth source: ${String(value)}`);
}

function sealedAuthMethodForThresholdEd25519Source(
  source: ThresholdEd25519SessionStoreSource,
): SigningSessionSealedAuthMethod {
  switch (source) {
    case 'email_otp':
      return 'email_otp';
    case 'login':
    case 'registration':
    case 'manual-connect':
    case 'bootstrap':
      return 'passkey';
    default:
      return assertNever(source);
  }
}

function sealedAuthMethodForThresholdEcdsaSource(
  source: ThresholdEcdsaSessionStoreSource,
): SigningSessionSealedAuthMethod {
  switch (source) {
    case 'email_otp':
      return 'email_otp';
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return 'passkey';
    default:
      return assertNever(source);
  }
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
  return {
    ok: true,
    sealedSecretB64u: data.sealedSecretB64u,
    ...(typeof data.keyVersion === 'string' && data.keyVersion.trim()
      ? { keyVersion: data.keyVersion.trim() }
      : {}),
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
  };
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

const signingSessionRehydrateSingleFlight = new Map<
  string,
  Promise<WarmSessionStatusResult | null>
>();
const signingSessionSealPersistSingleFlight = new Map<
  string,
  Promise<WarmSessionSealAndPersistResult>
>();
const signingSessionSealDeleteSingleFlight = new Map<string, Promise<void>>();

function makeWarmSessionSingleFlightKey(args: {
  operation: 'rehydrate' | 'persist' | 'delete';
  thresholdSessionId: string;
  authMethod?: 'passkey' | 'email_otp';
  curve?: 'ed25519' | 'ecdsa';
  walletId?: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  walletSigningSessionId?: string;
}): string {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return '';
  return [
    args.operation,
    String(args.authMethod || '').trim(),
    String(args.curve || '').trim(),
    String(args.walletId || '').trim(),
    args.chainTarget ? thresholdEcdsaChainTargetKey(args.chainTarget) : '',
    String(args.walletSigningSessionId || '').trim(),
    thresholdSessionId,
  ].join('|');
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

  constructor(config: UiConfirmManagerConfig, context: UiConfirmContext) {
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
      message: `[UiConfirm] ${context} requires signingSessionPersistenceMode="sealed_refresh_v1"`,
    };
  }

  private resolvePasskeySealedRecordPurpose(
    thresholdSessionIdRaw: string,
    explicitCurve?: 'ed25519' | 'ecdsa',
    explicitChainTarget?: ThresholdEcdsaChainTarget,
  ): SigningSessionSealedRecordFilter | null {
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const curve =
      explicitCurve ||
      (getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId)
        ? 'ed25519'
        : undefined) ||
      (explicitChainTarget ? 'ecdsa' : undefined) ||
      (getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId) ? 'ecdsa' : undefined);
    if (!curve) {
      console.warn('[UiConfirm] cannot resolve sealed refresh purpose for passkey session', {
        thresholdSessionId,
      });
      return null;
    }
    if (curve === 'ecdsa') {
      if (!explicitChainTarget) {
        console.warn('[UiConfirm] cannot resolve ECDSA sealed refresh purpose without chain target', {
          thresholdSessionId,
        });
        return null;
      }
      return { authMethod: 'passkey', curve, chainTarget: explicitChainTarget };
    }
    return { authMethod: 'passkey', curve };
  }

  private async readPasskeySealedRecord(
    thresholdSessionId: string,
    curve?: 'ed25519' | 'ecdsa',
    chainTarget?: ThresholdEcdsaChainTarget,
  ) {
    const purpose = this.resolvePasskeySealedRecordPurpose(thresholdSessionId, curve, chainTarget);
    if (!purpose) return null;
    return await readExactSealedSession(thresholdSessionId, purpose).catch((error) => {
      console.warn('[UiConfirm] failed to read passkey sealed refresh record', {
        thresholdSessionId,
        purpose,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
      return null;
    });
  }

  private resolveWarmSessionSealAuthMethod(
    args: WarmSessionSealAuthMethodInput,
  ): SigningSessionSealedAuthMethod {
    if (args.curve === 'ed25519') {
      const ed25519Record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(
        args.thresholdSessionId,
      );
      if (!ed25519Record) {
        throw new Error('[UiConfirm] cannot resolve Ed25519 sealed refresh auth without session record');
      }
      return sealedAuthMethodForThresholdEd25519Source(ed25519Record.source);
    }
    const ecdsaRecord = getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
      thresholdSessionId: args.thresholdSessionId,
      chainTarget: args.chainTarget,
    });
    if (!ecdsaRecord) {
      throw new Error('[UiConfirm] cannot resolve ECDSA sealed refresh auth without session record');
    }
    return sealedAuthMethodForThresholdEcdsaSource(ecdsaRecord.source);
  }

  private buildPasskeyDurableDeleteCommand(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    deleteReason: DurableSealedSessionDeleteReason;
    preserveResolvedIdentity: boolean;
  }): DeleteDurableSealedSessionCommand | null {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;
    const purpose = this.resolvePasskeySealedRecordPurpose(
      thresholdSessionId,
      args.curve,
      args.chainTarget,
    );
    if (!purpose) return null;
    if (purpose.curve === 'ed25519') {
      return createDeleteDurableSealedSessionCommand({
        durableRecord: {
          authMethod: 'passkey',
          curve: 'ed25519',
          thresholdSessionId,
        },
        deleteReason: args.deleteReason,
        preserveResolvedIdentity: args.preserveResolvedIdentity,
      });
    }
    return createDeleteDurableSealedSessionCommand({
      durableRecord: {
        authMethod: 'passkey',
        curve: 'ecdsa',
        thresholdSessionId,
        chainTarget: purpose.chainTarget,
      },
      deleteReason: args.deleteReason,
      preserveResolvedIdentity: args.preserveResolvedIdentity,
    });
  }

  private async runDurableSealedSessionDelete(
    command: DeleteDurableSealedSessionCommand,
  ): Promise<void> {
    const singleFlightKey =
      command.durableRecord.curve === 'ecdsa'
        ? makeWarmSessionSingleFlightKey({
            operation: 'delete',
            thresholdSessionId: command.durableRecord.thresholdSessionId,
            authMethod: command.durableRecord.authMethod,
            curve: 'ecdsa',
            chainTarget: command.durableRecord.chainTarget,
          })
        : makeWarmSessionSingleFlightKey({
            operation: 'delete',
            thresholdSessionId: command.durableRecord.thresholdSessionId,
            authMethod: command.durableRecord.authMethod,
            curve: 'ed25519',
          });
    const inFlight = signingSessionSealDeleteSingleFlight.get(singleFlightKey);
    if (inFlight) return await inFlight;

    const task = deleteDurableSealedSessionRecordFromStore(command).finally(() => {
      signingSessionSealDeleteSingleFlight.delete(singleFlightKey);
    });
    signingSessionSealDeleteSingleFlight.set(singleFlightKey, task);
    return await task;
  }

  private async deletePasskeyDurableSealedSessionRecord(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    deleteReason: DurableSealedSessionDeleteReason;
    preserveResolvedIdentity: boolean;
  }): Promise<void> {
    const command = this.buildPasskeyDurableDeleteCommand(args);
    if (!command) return;
    await this.runDurableSealedSessionDelete(command).catch(() => undefined);
  }

  private async updatePasskeySealedRecordPolicy(args: {
    thresholdSessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void> {
    const purpose = this.resolvePasskeySealedRecordPurpose(
      args.thresholdSessionId,
      args.curve,
      args.chainTarget,
    );
    if (!purpose) return;
    const existing = await readExactSealedSession(args.thresholdSessionId, purpose).catch(
      () => null,
    );
    if (!existing) return;
    const refreshedMetadata = this.mergePasskeySealedRecordMetadata({
      existing,
      refreshed: this.buildPasskeySealedRecordAccountMetadata({
        thresholdSessionId: args.thresholdSessionId,
        curve: purpose.curve,
        ...(purpose.curve === 'ecdsa' ? { chainTarget: purpose.chainTarget } : {}),
      }),
    });
    const refreshedCurve = existing.curve || purpose.curve;
    if (refreshedCurve === 'ecdsa') {
      const walletId = String(refreshedMetadata.walletId || '').trim();
      const relayerUrl = String(existing.relayerUrl || '').trim();
      if (!walletId || !relayerUrl || !refreshedMetadata.ecdsaRestore) {
        throw new Error('[SigningSessionSealedStore] invalid ECDSA sealed session refresh metadata');
      }
      await this.registerSigningSession({
        thresholdSessionId: args.thresholdSessionId,
        sealedSecretB64u: existing.sealedSecretB64u,
        curve: 'ecdsa',
        authMethod: 'passkey',
        walletSigningSessionId: existing.walletSigningSessionId,
        thresholdSessionIds: existing.thresholdSessionIds,
        walletId,
        relayerUrl,
        keyVersion: existing.keyVersion,
        shamirPrimeB64u: existing.shamirPrimeB64u,
        ecdsaRestore: refreshedMetadata.ecdsaRestore,
        ...(refreshedMetadata.ed25519Restore
          ? { ed25519Restore: refreshedMetadata.ed25519Restore }
          : {}),
        issuedAtMs: existing.issuedAtMs,
        expiresAtMs: args.expiresAtMs,
        remainingUses: args.remainingUses,
        updatedAtMs: Date.now(),
      });
    } else {
      const walletId = String(refreshedMetadata.walletId || '').trim();
      const relayerUrl = String(existing.relayerUrl || '').trim();
      if (!walletId || !relayerUrl || !refreshedMetadata.ed25519Restore) {
        throw new Error('[SigningSessionSealedStore] invalid Ed25519 sealed session refresh metadata');
      }
      await this.registerSigningSession({
        thresholdSessionId: args.thresholdSessionId,
        sealedSecretB64u: existing.sealedSecretB64u,
        curve: 'ed25519',
        authMethod: 'passkey',
        walletSigningSessionId: existing.walletSigningSessionId,
        thresholdSessionIds: existing.thresholdSessionIds,
        walletId,
        ...(refreshedMetadata.signingRootId
          ? { signingRootId: refreshedMetadata.signingRootId }
          : {}),
        ...(refreshedMetadata.signingRootVersion
          ? { signingRootVersion: refreshedMetadata.signingRootVersion }
          : {}),
        relayerUrl,
        keyVersion: existing.keyVersion,
        shamirPrimeB64u: existing.shamirPrimeB64u,
        ...(refreshedMetadata.ecdsaRestore
          ? { ecdsaRestore: refreshedMetadata.ecdsaRestore }
          : {}),
        ed25519Restore: refreshedMetadata.ed25519Restore,
        issuedAtMs: existing.issuedAtMs,
        expiresAtMs: args.expiresAtMs,
        remainingUses: args.remainingUses,
        updatedAtMs: Date.now(),
      });
    }
  }

  private async recordSessionPolicyResult(args: {
    sessionId: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    result: WarmSessionStatusResult | WarmSessionClaimResult;
  }): Promise<void> {
    const result = args.result;
    if (result.ok) {
      if (result.remainingUses <= 0 || Date.now() >= result.expiresAtMs) {
        if (result.remainingUses <= 0) {
          await this.updatePasskeySealedRecordPolicy({
            thresholdSessionId: args.sessionId,
            curve: args.curve,
            chainTarget: args.chainTarget,
            expiresAtMs: result.expiresAtMs,
            remainingUses: 0,
          });
          return;
        }
        await this.deletePasskeyDurableSealedSessionRecord({
          thresholdSessionId: args.sessionId,
          curve: args.curve,
          chainTarget: args.chainTarget,
          deleteReason: 'expired',
          preserveResolvedIdentity: true,
        });
        return;
      }
      await this.updatePasskeySealedRecordPolicy({
        thresholdSessionId: args.sessionId,
        curve: args.curve,
        chainTarget: args.chainTarget,
        expiresAtMs: result.expiresAtMs,
        remainingUses: result.remainingUses,
      });
      return;
    }
    if (result.code === 'expired') {
      await this.deletePasskeyDurableSealedSessionRecord({
        thresholdSessionId: args.sessionId,
        curve: args.curve,
        chainTarget: args.chainTarget,
        deleteReason: 'expired',
        preserveResolvedIdentity: true,
      });
    }
  }

  private async recordSessionMaterialRestored(
    sessionId: string,
    result: WarmSessionStatusResult,
    curve?: 'ed25519' | 'ecdsa',
    chainTarget?: ThresholdEcdsaChainTarget,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result, curve, chainTarget });
  }

  private async recordSessionMaterialClaimed(
    sessionId: string,
    result: WarmSessionClaimResult,
    curve?: 'ed25519' | 'ecdsa',
    chainTarget?: ThresholdEcdsaChainTarget,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result, curve, chainTarget });
  }

  private async recordSessionUseConsumed(
    sessionId: string,
    result: WarmSessionStatusResult,
    curve?: 'ed25519' | 'ecdsa',
    chainTarget?: ThresholdEcdsaChainTarget,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result, curve, chainTarget });
  }

  private async registerSigningSession(
    record: BuildCurrentSealedSessionRecordInput,
  ): Promise<void> {
    const currentRecord = buildCurrentSealedSessionRecord(record);
    if (!currentRecord) {
      throw new Error('[SigningSessionSealedStore] invalid sealed session record write input');
    }
    await writeExactSealedSession(currentRecord);
  }

  private mergePasskeySealedRecordMetadata(args: {
    existing?: SigningSessionSealedStoreRecord | null;
    refreshed: PasskeySealedRecordAccountMetadata;
  }): PasskeySealedRecordAccountMetadata {
    const existing = args.existing;
    return {
      ...(args.refreshed.walletId || existing?.walletId
        ? { walletId: args.refreshed.walletId || existing?.walletId }
        : {}),
      ...(args.refreshed.signingRootId || existing?.signingRootId
        ? { signingRootId: args.refreshed.signingRootId || existing?.signingRootId }
        : {}),
      ...(args.refreshed.signingRootVersion || existing?.signingRootVersion
        ? {
            signingRootVersion:
              args.refreshed.signingRootVersion || existing?.signingRootVersion,
          }
        : {}),
      ...(args.refreshed.ecdsaRestore || existing?.ecdsaRestore
        ? { ecdsaRestore: args.refreshed.ecdsaRestore || existing?.ecdsaRestore }
        : {}),
      ...(args.refreshed.ed25519Restore || existing?.ed25519Restore
        ? { ed25519Restore: args.refreshed.ed25519Restore || existing?.ed25519Restore }
        : {}),
    };
  }

  private async resolveSealTransportInput(
    thresholdSessionIdRaw: string,
    explicitTransport?: {
      curve?: 'ed25519' | 'ecdsa';
      walletId?: string;
      chainTarget?: ThresholdEcdsaChainTarget;
      relayerUrl?: string;
      walletSigningSessionId?: string;
      thresholdSessionAuthToken?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    } | null,
    sealedRecordInput?: SigningSessionSealedStoreRecord | null,
  ): Promise<WarmSessionSealTransportInput | null> {
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const ed25519Record =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
    const ecdsaRecord =
      explicitTransport?.chainTarget
        ? getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
            thresholdSessionId,
            chainTarget: explicitTransport.chainTarget,
          })
        : getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    const curve =
      explicitTransport?.curve ||
      sealedRecordInput?.curve ||
      (ed25519Record ? 'ed25519' : undefined) ||
      (ecdsaRecord ? 'ecdsa' : undefined);
    const sealedRecord =
      sealedRecordInput ||
      (await this.readPasskeySealedRecord(
        thresholdSessionId,
        curve,
        explicitTransport?.chainTarget,
      ));
    const relayerUrl = String(
      explicitTransport?.relayerUrl ||
        sealedRecord?.relayerUrl ||
        ed25519Record?.relayerUrl ||
        ecdsaRecord?.relayerUrl ||
        '',
    ).trim();
    if (!relayerUrl) return null;
    const thresholdSessionAuthToken = String(
      explicitTransport?.thresholdSessionAuthToken ||
        (curve === 'ed25519' ? sealedRecord?.ed25519Restore?.thresholdSessionAuthToken : '') ||
        (curve === 'ecdsa' ? sealedRecord?.ecdsaRestore?.thresholdSessionAuthToken : '') ||
        ed25519Record?.thresholdSessionAuthToken ||
        ecdsaRecord?.thresholdSessionAuthToken ||
        '',
    ).trim();
    const walletSigningSessionId = String(
      explicitTransport?.walletSigningSessionId ||
        sealedRecord?.walletSigningSessionId ||
        ed25519Record?.walletSigningSessionId ||
        ecdsaRecord?.walletSigningSessionId ||
        '',
    ).trim();
    const walletId = String(
      explicitTransport?.walletId ||
        sealedRecord?.walletId ||
        ed25519Record?.nearAccountId ||
        ecdsaRecord?.walletId ||
        '',
    ).trim();
    const keyVersion = String(
      explicitTransport?.keyVersion ||
        sealedRecord?.keyVersion ||
        ecdsaRecord?.signingSessionSealKeyVersion ||
        this.config.signingSessionSealKeyVersion ||
        '',
    ).trim();
    const shamirPrimeB64u = String(
      explicitTransport?.shamirPrimeB64u ||
        sealedRecord?.shamirPrimeB64u ||
        ecdsaRecord?.signingSessionSealShamirPrimeB64u ||
        this.config.signingSessionSealShamirPrimeB64u ||
        '',
    ).trim();
    if (curve === 'ecdsa') {
      const chainTarget = explicitTransport?.chainTarget || ecdsaRecord?.chainTarget;
      if (!chainTarget) return null;
      return {
        curve,
        ...(walletId ? { walletId } : {}),
        chainTarget,
        relayerUrl,
        ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
        ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
        ...(keyVersion ? { keyVersion } : {}),
        ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
      };
    }
    if (curve !== 'ed25519') return null;
    return {
      curve,
      ...(walletId ? { walletId } : {}),
      relayerUrl,
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
      ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
      ...(keyVersion ? { keyVersion } : {}),
      ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    };
  }

  private buildPasskeySealedRecordAccountMetadata(args: {
    thresholdSessionId: string;
    curve: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    walletId?: string;
  }): PasskeySealedRecordAccountMetadata {
    const ed25519Record =
      args.curve === 'ed25519'
        ? getStoredThresholdEd25519SessionRecordByThresholdSessionId(args.thresholdSessionId)
        : null;
    const ecdsaRecord =
      args.curve === 'ecdsa'
        ? args.chainTarget
          ? getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
              thresholdSessionId: args.thresholdSessionId,
              chainTarget: args.chainTarget,
            })
          : null
        : null;
    const accountId = String(
      ed25519Record?.nearAccountId || ecdsaRecord?.walletId || args.walletId || '',
    ).trim();
    const ethereumAddress = String(ecdsaRecord?.ethereumAddress || '')
      .trim()
      .toLowerCase();
    const ecdsaRestore =
      ecdsaRecord &&
      ecdsaRecord.chainTarget &&
      /^0x[0-9a-f]{40}$/.test(ethereumAddress)
        ? {
            chainTarget: ecdsaRecord.chainTarget,
            rpId: thresholdEcdsaRecordRpId(ecdsaRecord),
            ...(ecdsaRecord.thresholdSessionAuthToken
              ? { thresholdSessionAuthToken: ecdsaRecord.thresholdSessionAuthToken }
              : {}),
            sessionKind: ecdsaRecord.thresholdSessionKind,
            keyHandle: ecdsaRecord.keyHandle,
            ecdsaThresholdKeyId: ecdsaRecord.ecdsaThresholdKeyId,
            ethereumAddress,
            relayerKeyId: ecdsaRecord.relayerKeyId,
            clientVerifyingShareB64u: ecdsaRecord.clientVerifyingShareB64u,
            ...(ecdsaRecord.thresholdEcdsaPublicKeyB64u
              ? { thresholdEcdsaPublicKeyB64u: ecdsaRecord.thresholdEcdsaPublicKeyB64u }
              : {}),
            participantIds: ecdsaRecord.participantIds,
            ...(ecdsaRecord.runtimePolicyScope
              ? { runtimePolicyScope: ecdsaRecord.runtimePolicyScope }
              : {}),
          }
        : undefined;
    const ed25519XClientBaseB64u = String(ed25519Record?.xClientBaseB64u || '').trim();
    const ed25519Restore = ed25519Record
      ? {
          rpId: ed25519Record.rpId,
          relayerKeyId: ed25519Record.relayerKeyId,
          participantIds: ed25519Record.participantIds,
          ...(ed25519Record.thresholdSessionAuthToken
            ? { thresholdSessionAuthToken: ed25519Record.thresholdSessionAuthToken }
            : {}),
          sessionKind: ed25519Record.thresholdSessionKind,
          ...(ed25519Record.runtimePolicyScope
            ? { runtimePolicyScope: ed25519Record.runtimePolicyScope }
            : {}),
          ...(ed25519XClientBaseB64u ? { xClientBaseB64u: ed25519XClientBaseB64u } : {}),
        }
      : undefined;
    return {
      ...(accountId ? { walletId: accountId } : {}),
      ...(ecdsaRestore ? { ecdsaRestore } : {}),
      ...(ed25519Restore ? { ed25519Restore } : {}),
    };
  }

  private async ensureSealedRecordPersisted(
    thresholdSessionIdRaw: string,
    transport?: WarmSessionSealTransportInput | null,
  ): Promise<WarmSessionSealAndPersistResult | null> {
    if (!this.isSealedRefreshModeEnabled()) return null;
    const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
    if (!thresholdSessionId) return null;
    const resolvedTransport = await this.resolveSealTransportInput(
      thresholdSessionId,
      transport || null,
    );
    if (!resolvedTransport) return null;
    return await this.persistSigningSessionSealForThresholdSession({
      sessionId: thresholdSessionId,
      transport: resolvedTransport,
    });
  }

  private async restorePasskeySealedRecordForWallet(args: {
    walletId: string;
    record: SealedRecoveryRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordResult> {
    if (!this.isSealedRefreshModeEnabled()) return 'deferred';
    if (args.purpose.authMethod !== 'passkey') return 'deferred';
    const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return 'deferred';
    if (args.record.authMethod !== 'passkey') return 'deferred';
    const curve = args.purpose.curve;
    const chainTarget = curve === 'ecdsa' ? args.purpose.chainTarget : undefined;
    if (curve === 'ecdsa') {
      if (!chainTarget || args.record.curve !== 'ecdsa') return 'deferred';
      if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, chainTarget)) {
        return 'deferred';
      }
    } else if (args.record.curve !== 'ed25519') {
      return 'deferred';
    }
    const singleFlightKey = makeWarmSessionSingleFlightKey({
      operation: 'rehydrate',
      thresholdSessionId,
      authMethod: 'passkey',
      curve,
      ...(chainTarget ? { chainTarget } : {}),
      walletSigningSessionId: args.purpose.walletSigningSessionId,
    });

    const inFlight = signingSessionRehydrateSingleFlight.get(singleFlightKey);
    if (inFlight) {
      const result = await inFlight;
      return result?.ok ? 'ready' : 'deferred';
    }

    const task = (async (): Promise<WarmSessionStatusResult | null> => {
      const purpose =
        curve === 'ecdsa'
          ? {
              authMethod: 'passkey' as const,
              curve: 'ecdsa' as const,
              chainTarget: chainTarget!,
            }
          : { authMethod: 'passkey' as const, curve: 'ed25519' as const };
      const sealedRecordFilter: SigningSessionSealedRecordFilter = purpose;
      const deleteInvalidPersistedRecord = async (): Promise<void> => {
        if (curve === 'ecdsa') {
          if (!chainTarget) return;
          await this.deletePasskeyDurableSealedSessionRecord({
            thresholdSessionId,
            curve: 'ecdsa',
            chainTarget,
            deleteReason: 'invalid_persisted_record',
            preserveResolvedIdentity: false,
          });
          return;
        }
        await this.deletePasskeyDurableSealedSessionRecord({
          thresholdSessionId,
          curve: 'ed25519',
          deleteReason: 'invalid_persisted_record',
          preserveResolvedIdentity: false,
        });
      };
      const lease = await acquireSigningSessionRestoreLease({
        thresholdSessionId,
        ...purpose,
      });
      if (!lease) return null;
      try {
        const transport = await this.resolveSealTransportInput(
          thresholdSessionId,
          {
            curve,
            walletId: args.walletId,
            ...(chainTarget ? { chainTarget } : {}),
            relayerUrl: args.record.relayerUrl,
            walletSigningSessionId: args.purpose.walletSigningSessionId,
            keyVersion: args.record.keyVersion,
            shamirPrimeB64u: args.record.shamirPrimeB64u,
            ...(args.record.thresholdSessionAuthToken
              ? { thresholdSessionAuthToken: args.record.thresholdSessionAuthToken }
              : {}),
          },
        );
        if (!transport) return null;
        const shamirPrimeB64u = String(
          args.record.shamirPrimeB64u || transport.shamirPrimeB64u || '',
        ).trim();
        if (!shamirPrimeB64u) return null;

        return curve === 'ecdsa' &&
          chainTarget &&
          args.purpose.curve === 'ecdsa' &&
          args.purpose.authMethod === 'passkey' &&
          args.record.authMethod === 'passkey' &&
          args.record.curve === 'ecdsa'
          ? await restorePasskeyEcdsaSealedRecordForWallet({
              walletId: args.walletId,
              record: args.record,
              purpose: { ...args.purpose, authMethod: 'passkey' },
              transport,
              shamirPrimeB64u,
              rehydrateWarmSessionMaterial: (rehydrateArgs) =>
                this.rehydrateWarmSessionMaterial(rehydrateArgs),
              deletePersistedRecord: deleteInvalidPersistedRecord,
              recordSessionMaterialRestored: async (status) =>
                await this.recordSessionMaterialRestored(
                  thresholdSessionId,
                  status,
                  curve,
                  chainTarget,
                ),
              readWarmSessionStatusFromWorker: async (sessionId) => {
                const rehydratedPeek = await this.sendMessage({
                  type: 'WARM_SESSION_STATUS_READ',
                  id: this.generateMessageId(),
                  payload: { sessionId },
                });
                const parsed = parseWarmSessionStatusResult(rehydratedPeek?.data);
                if (rehydratedPeek?.success !== true || !parsed) {
                  return {
                    ok: false,
                    code: 'worker_error',
                    message: String(
                      rehydratedPeek?.error ||
                        'Warm-session status read failed after rehydrate',
                    ),
                  };
                }
                return parsed;
              },
              updatePersistedPolicy: async (policy) =>
                await updateExactSealedSessionPolicy({
                  thresholdSessionId,
                  filter: sealedRecordFilter,
                  ...policy,
                }),
            })
          : curve === 'ed25519' &&
              args.purpose.curve === 'ed25519' &&
              args.purpose.authMethod === 'passkey' &&
              args.record.authMethod === 'passkey' &&
              args.record.curve === 'ed25519'
            ? await restorePasskeyEd25519SealedRecordForAccount({
                accountId: args.walletId,
                record: args.record,
                purpose: { ...args.purpose, authMethod: 'passkey' },
                transport,
                shamirPrimeB64u,
                rehydrateWarmSessionMaterial: (rehydrateArgs) =>
                  this.rehydrateWarmSessionMaterial(rehydrateArgs),
                deletePersistedRecord: deleteInvalidPersistedRecord,
                recordSessionMaterialRestored: async (status) =>
                  await this.recordSessionMaterialRestored(
                    thresholdSessionId,
                    status,
                    curve,
                    chainTarget,
                  ),
                readWarmSessionStatusFromWorker: async (sessionId) => {
                  const rehydratedPeek = await this.sendMessage({
                    type: 'WARM_SESSION_STATUS_READ',
                    id: this.generateMessageId(),
                    payload: { sessionId },
                  });
                  const parsed = parseWarmSessionStatusResult(rehydratedPeek?.data);
                  if (rehydratedPeek?.success !== true || !parsed) {
                    return {
                      ok: false,
                      code: 'worker_error',
                      message: String(
                        rehydratedPeek?.error ||
                          'Warm-session status read failed after rehydrate',
                      ),
                    };
                  }
                  return parsed;
                },
                updatePersistedPolicy: async (policy) =>
                  await updateExactSealedSessionPolicy({
                    thresholdSessionId,
                    filter: sealedRecordFilter,
                    ...policy,
                  }),
              })
            : null;
      } finally {
        await releaseSigningSessionRestoreLease(lease);
      }
    })().finally(() => {
      signingSessionRehydrateSingleFlight.delete(singleFlightKey);
    });

    signingSessionRehydrateSingleFlight.set(singleFlightKey, task);
    const result = await task;
    return result?.ok ? 'restored' : 'deferred';
  }

  putWarmSessionMaterial = async (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }): Promise<void> => {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_PUT',
      id: this.generateMessageId(),
      payload: args,
    });
    if (!res?.success) {
      throw new Error(String(res?.error || 'Failed to cache warm-session material'));
    }
    const parsed = parseWarmSessionStatusResult(res?.data);
    if (!parsed) {
      throw new Error('Warm-session cache returned an invalid response');
    }
    if (!parsed.ok) {
      throw new Error(`Warm-session cache failed (${parsed.code}): ${parsed.message}`);
    }
    const persisted = await this.ensureSealedRecordPersisted(
      args.sessionId,
      args.transport || null,
    );
    if (persisted && !persisted.ok) {
      throw new Error(
        `Warm-session cache could not persist sealed refresh material (${persisted.code}): ${persisted.message}`,
      );
    }
  };

  sealAndPersistWarmSessionMaterial = async (
    args: WarmSessionSealAndPersistPayload,
  ): Promise<WarmSessionSealAndPersistResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('signing-session seal and persist');
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
        message: String(res?.error || 'Signing-session seal and persist failed'),
      };
    }
    return parsed;
  };

  rehydrateWarmSessionMaterial = async (
    args: WarmSessionRehydratePayload,
  ): Promise<WarmSessionRehydrateResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('signing-session rehydrate');
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
        message: String(res?.error || 'Signing-session rehydrate failed'),
      };
    }
    return parsed;
  };

  restorePersistedSessionForSigning = async (args: {
    authMethod: 'passkey';
  } & RestorePersistedSessionForSigningInput): Promise<RestorePersistedSessionForSigningResult> => {
    if (args.authMethod !== 'passkey' || !this.isSealedRefreshModeEnabled()) {
      return { attempted: 0, restored: 0, deferred: 0 };
    }
    return await restorePersistedSessionForSigningCommand(args, {
      listExactSealedSessionsForWallet: async (filter) => {
        return await listExactSealedSessionsForWallet({
          walletId: filter.walletId,
            filter:
              filter.curve === 'ecdsa'
              ? {
                  authMethod: filter.authMethod,
                  curve: 'ecdsa',
                  chainTarget: filter.chainTarget,
                }
              : { authMethod: filter.authMethod, curve: 'ed25519' },
        });
      },
      restoreSealedRecordForWallet: (restoreArgs) =>
        this.restorePasskeySealedRecordForWallet({
          walletId: restoreArgs.walletId,
          record: restoreArgs.record,
          purpose: restoreArgs.purpose,
        }),
      onListError: ({ walletId, target, reason, error }) => {
        console.warn('[UiConfirm] passkey signing-session restore list failed', {
          walletId,
          target,
          reason,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      },
    });
  };

  restorePersistedSessionsForWallet = async (
    args: {
      authMethod?: 'passkey';
    } & RestorePersistedSessionsForWalletInput,
  ): Promise<RestorePersistedSessionsForWalletResult> => {
    if (args.authMethod && args.authMethod !== 'passkey') {
      return { listed: 0, attempted: 0, restored: 0, deferred: 0, skipped: 0, truncated: 0 };
    }
    if (!this.isSealedRefreshModeEnabled()) {
      return { listed: 0, attempted: 0, restored: 0, deferred: 0, skipped: 0, truncated: 0 };
    }
    return await restorePersistedSessionsForWalletCommand(
      {
        ...args,
        authMethod: 'passkey',
      },
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
        restoreSealedRecordForWallet: (restoreArgs) =>
          this.restorePasskeySealedRecordForWallet({
            walletId: restoreArgs.walletId,
            record: restoreArgs.record,
            purpose: restoreArgs.purpose,
          }),
        onListError: ({ walletId, error }) => {
          console.warn('[UiConfirm] passkey account signing-session restore list failed', {
            walletId,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
        onRejectedRecord: ({ walletId, rejection }) => {
          console.warn('[UiConfirm] passkey account signing-session restore rejected record', {
            walletId,
            rejection,
          });
        },
      },
    );
  };

  private async readWarmSessionStatusFromWorker(args: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> {
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
    return parsed;
  }

  private async readWarmSessionStatusesFromWorker(args: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> {
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
    return parsed;
  }

  readWarmSessionStatusOnly = async (args: {
    sessionId: string;
  }): Promise<WarmSessionStatusResult> => await this.readWarmSessionStatusFromWorker(args);

  readWarmSessionStatusesOnly = async (args: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => await this.readWarmSessionStatusesFromWorker(args);

  getWarmSessionStatus = async (args: { sessionId: string }): Promise<WarmSessionStatusResult> => {
    return await this.readWarmSessionStatusFromWorker(args);
  };

  getWarmSessionStatuses = async (args: {
    sessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    return await this.readWarmSessionStatusesFromWorker(args);
  };

  persistSigningSessionSealForThresholdSession = async (args: {
    sessionId: string;
    transport?: WarmSessionSealTransportInput;
  }): Promise<WarmSessionSealAndPersistResult> => {
    if (!this.isSealedRefreshModeEnabled()) {
      return this.getSealedRefreshNotEnabledError('signing-session seal persistence');
    }
    const thresholdSessionId = String(args?.sessionId || '').trim();
    if (!thresholdSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
    }
    const inferredTransport =
      (await this.resolveSealTransportInput(thresholdSessionId, args?.transport || null)) || null;
    const curve = args?.transport?.curve || inferredTransport?.curve;
    if (!curve) {
      console.warn('[UiConfirm] cannot persist sealed refresh without passkey curve', {
        thresholdSessionId,
      });
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing curve for signing-session seal persistence',
      };
    }
    const walletSigningSessionId = String(
      args?.transport?.walletSigningSessionId || inferredTransport?.walletSigningSessionId || '',
    ).trim();
    if (!walletSigningSessionId) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing walletSigningSessionId for signing-session seal persistence',
      };
    }
    let ecdsaTransportChainTarget: ThresholdEcdsaChainTarget | undefined;
    if (curve === 'ecdsa') {
      if (args.transport?.curve === 'ecdsa') {
        ecdsaTransportChainTarget = args.transport.chainTarget;
      } else if (inferredTransport?.curve === 'ecdsa') {
        ecdsaTransportChainTarget = inferredTransport.chainTarget;
      }
    }
    const recordMetadata = this.buildPasskeySealedRecordAccountMetadata({
      thresholdSessionId,
      curve,
      ...(ecdsaTransportChainTarget ? { chainTarget: ecdsaTransportChainTarget } : {}),
      ...(args.transport?.walletId || inferredTransport?.walletId
        ? { walletId: args.transport?.walletId || inferredTransport?.walletId }
        : {}),
    });
    const chainTarget = curve === 'ecdsa' ? recordMetadata.ecdsaRestore?.chainTarget : undefined;
    if (curve === 'ecdsa' && !chainTarget) {
      const transportChainTargetKey = ecdsaTransportChainTarget
        ? thresholdEcdsaChainTargetKey(ecdsaTransportChainTarget)
        : 'missing';
      return {
        ok: false,
        code: 'invalid_args',
        message: `Missing concrete ECDSA chain target for signing-session seal persistence (thresholdSessionId=${thresholdSessionId}, transportChainTarget=${transportChainTargetKey})`,
      };
    }
    let purpose: SigningSessionSealedRecordFilter;
    let authMethod: SigningSessionSealedAuthMethod;
    if (curve === 'ecdsa') {
      if (!chainTarget) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing concrete ECDSA chain target for signing-session seal persistence',
        };
      }
      authMethod = this.resolveWarmSessionSealAuthMethod({
        thresholdSessionId,
        curve: 'ecdsa',
        chainTarget,
      });
      purpose = { authMethod, curve: 'ecdsa', chainTarget };
    } else {
      authMethod = this.resolveWarmSessionSealAuthMethod({
        thresholdSessionId,
        curve: 'ed25519',
      });
      purpose = { authMethod, curve: 'ed25519' };
    }
    const singleFlightKey = makeWarmSessionSingleFlightKey({
      operation: 'persist',
      thresholdSessionId,
      authMethod,
      curve,
      ...(chainTarget ? { chainTarget } : {}),
      walletSigningSessionId,
    });
    const inFlight = signingSessionSealPersistSingleFlight.get(singleFlightKey);
    if (inFlight) {
      console.debug('[UiConfirm] joined in-flight sealed refresh persistence', {
        thresholdSessionId,
        authMethod,
        curve,
        walletSigningSessionId,
      });
      return await inFlight;
    }

    const task = (async (): Promise<WarmSessionSealAndPersistResult> => {
      const existingRecord = await readExactSealedSession(thresholdSessionId, purpose).catch(
        (error) => {
          console.warn('[UiConfirm] failed to read sealed refresh record', {
            thresholdSessionId,
            purpose,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
          return null;
        },
      );
      if (existingRecord) {
        const currentPolicy = await this.getWarmSessionStatus({ sessionId: thresholdSessionId }).catch(
          () => null,
        );
        const nextExpiresAtMs = currentPolicy?.ok
          ? currentPolicy.expiresAtMs
          : existingRecord.expiresAtMs;
        const nextRemainingUses = currentPolicy?.ok
          ? currentPolicy.remainingUses
          : existingRecord.remainingUses;
        const refreshedMetadata = this.mergePasskeySealedRecordMetadata({
          existing: existingRecord,
          refreshed: recordMetadata,
        });
        const persistedCurve = existingRecord.curve || curve;
        if (persistedCurve === 'ecdsa') {
          const walletId = String(refreshedMetadata.walletId || '').trim();
          const relayerUrl = String(existingRecord.relayerUrl || '').trim();
          if (!walletId || !relayerUrl || !refreshedMetadata.ecdsaRestore) {
            throw new Error('[SigningSessionSealedStore] invalid ECDSA persisted-session refresh metadata');
          }
          await this.registerSigningSession({
            thresholdSessionId,
            sealedSecretB64u: existingRecord.sealedSecretB64u,
            curve: 'ecdsa',
            authMethod,
            walletSigningSessionId,
            thresholdSessionIds: existingRecord.thresholdSessionIds,
            walletId,
            relayerUrl,
            keyVersion: existingRecord.keyVersion,
            shamirPrimeB64u: existingRecord.shamirPrimeB64u,
            ecdsaRestore: refreshedMetadata.ecdsaRestore,
            ...(refreshedMetadata.ed25519Restore
              ? { ed25519Restore: refreshedMetadata.ed25519Restore }
              : {}),
            issuedAtMs: existingRecord.issuedAtMs,
            expiresAtMs: nextExpiresAtMs,
            remainingUses: nextRemainingUses,
            updatedAtMs: Date.now(),
          });
        } else {
          const walletId = String(refreshedMetadata.walletId || '').trim();
          const relayerUrl = String(existingRecord.relayerUrl || '').trim();
          if (!walletId || !relayerUrl || !refreshedMetadata.ed25519Restore) {
            throw new Error('[SigningSessionSealedStore] invalid Ed25519 persisted-session refresh metadata');
          }
          await this.registerSigningSession({
            thresholdSessionId,
            sealedSecretB64u: existingRecord.sealedSecretB64u,
            curve: 'ed25519',
            authMethod,
            walletSigningSessionId,
            thresholdSessionIds: existingRecord.thresholdSessionIds,
            walletId,
            ...(refreshedMetadata.signingRootId
              ? { signingRootId: refreshedMetadata.signingRootId }
              : {}),
            ...(refreshedMetadata.signingRootVersion
              ? { signingRootVersion: refreshedMetadata.signingRootVersion }
              : {}),
            relayerUrl,
            keyVersion: existingRecord.keyVersion,
            shamirPrimeB64u: existingRecord.shamirPrimeB64u,
            ...(refreshedMetadata.ecdsaRestore
              ? { ecdsaRestore: refreshedMetadata.ecdsaRestore }
              : {}),
            ed25519Restore: refreshedMetadata.ed25519Restore,
            issuedAtMs: existingRecord.issuedAtMs,
            expiresAtMs: nextExpiresAtMs,
            remainingUses: nextRemainingUses,
            updatedAtMs: Date.now(),
          });
        }
        return {
          ok: true,
          sealedSecretB64u: existingRecord.sealedSecretB64u,
          ...(existingRecord.keyVersion ? { keyVersion: existingRecord.keyVersion } : {}),
          remainingUses: nextRemainingUses,
          expiresAtMs: nextExpiresAtMs,
        };
      }
      const relayerUrl = String(
        args?.transport?.relayerUrl || inferredTransport?.relayerUrl || '',
      ).trim();
      const thresholdSessionAuthToken = String(
        args?.transport?.thresholdSessionAuthToken || inferredTransport?.thresholdSessionAuthToken || '',
      ).trim();
      const keyVersion = String(
        args?.transport?.keyVersion ||
          inferredTransport?.keyVersion ||
          this.config.signingSessionSealKeyVersion ||
          '',
      ).trim();
      const shamirPrimeB64u = String(
        args?.transport?.shamirPrimeB64u ||
          inferredTransport?.shamirPrimeB64u ||
          this.config.signingSessionSealShamirPrimeB64u ||
          '',
      ).trim();

      if (!relayerUrl) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing relayerUrl for signing-session seal persistence',
        };
      }
      if (!shamirPrimeB64u) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing shamirPrimeB64u for signing-session seal persistence',
        };
      }

      const transport =
        curve === 'ecdsa'
          ? {
              curve,
              chainTarget: chainTarget!,
              relayerUrl,
              walletSigningSessionId,
              ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
              ...(keyVersion ? { keyVersion } : {}),
              shamirPrimeB64u,
            }
          : {
              curve,
              relayerUrl,
              walletSigningSessionId,
              ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
              ...(keyVersion ? { keyVersion } : {}),
              shamirPrimeB64u,
            };
      const sealed = await this.sealAndPersistWarmSessionMaterial({
        sessionId: thresholdSessionId,
        transport,
      });
      if (!sealed.ok) return sealed;

      if (curve === 'ecdsa') {
        const walletId = String(recordMetadata.walletId || '').trim();
        if (!walletId || !recordMetadata.ecdsaRestore) {
          throw new Error('[SigningSessionSealedStore] missing ECDSA seal metadata');
        }
        await this.registerSigningSession({
          thresholdSessionId,
          sealedSecretB64u: sealed.sealedSecretB64u,
          curve: 'ecdsa',
          authMethod,
          walletSigningSessionId,
          walletId,
          ecdsaRestore: recordMetadata.ecdsaRestore,
          ...(recordMetadata.ed25519Restore
            ? { ed25519Restore: recordMetadata.ed25519Restore }
            : {}),
          thresholdSessionIds: { ecdsa: thresholdSessionId },
          relayerUrl,
          keyVersion: sealed.keyVersion,
          shamirPrimeB64u,
          expiresAtMs: sealed.expiresAtMs,
          remainingUses: sealed.remainingUses,
          updatedAtMs: Date.now(),
        });
      } else {
        const walletId = String(recordMetadata.walletId || '').trim();
        if (!walletId || !recordMetadata.ed25519Restore) {
          throw new Error('[SigningSessionSealedStore] missing Ed25519 seal metadata');
        }
        await this.registerSigningSession({
          thresholdSessionId,
          sealedSecretB64u: sealed.sealedSecretB64u,
          curve: 'ed25519',
          authMethod,
          walletSigningSessionId,
          walletId,
          ...(recordMetadata.signingRootId
            ? { signingRootId: recordMetadata.signingRootId }
            : {}),
          ...(recordMetadata.signingRootVersion
            ? { signingRootVersion: recordMetadata.signingRootVersion }
            : {}),
          ...(recordMetadata.ecdsaRestore
            ? { ecdsaRestore: recordMetadata.ecdsaRestore }
            : {}),
          ed25519Restore: recordMetadata.ed25519Restore,
          thresholdSessionIds: { ed25519: thresholdSessionId },
          relayerUrl,
          keyVersion: sealed.keyVersion,
          shamirPrimeB64u,
          expiresAtMs: sealed.expiresAtMs,
          remainingUses: sealed.remainingUses,
          updatedAtMs: Date.now(),
        });
      }
      const persistedRecord = await readExactSealedSession(thresholdSessionId, purpose).catch(
        () => null,
      );
      if (!persistedRecord) {
        return {
          ok: false,
          code: 'local_persist_failed',
          message: 'Failed to persist sealed signing-session record locally',
        };
      }
      return sealed;
    })().finally(() => {
      signingSessionSealPersistSingleFlight.delete(singleFlightKey);
    });

    signingSessionSealPersistSingleFlight.set(singleFlightKey, task);
    return await task;
  };

  claimWarmSessionMaterial = async (args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionClaimResult> => {
    await this.ensureWorkerReady(false);
    const { chainTarget, ...workerPayload } = args;
    const res = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CLAIM',
      id: this.generateMessageId(),
      payload: workerPayload,
    });
    const parsed = parseWarmSessionClaimResult(res?.data);
    if (res?.success !== true || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(res?.error || 'Warm-session claim failed'),
      };
    }
    await this.recordSessionMaterialClaimed(
      args.sessionId,
      parsed,
      args.curve,
      chainTarget,
    );
    return parsed;
  };

  consumeWarmSessionUses = async (args: {
    sessionId: string;
    uses?: number;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionStatusResult> => {
    await this.ensureWorkerReady(false);
    const { chainTarget, ...workerPayload } = args;
    const res = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CONSUME',
      id: this.generateMessageId(),
      payload: workerPayload,
    });
    const parsed = parseWarmSessionStatusResult(res?.data);
    if (res?.success !== true || !parsed) {
      return {
        ok: false,
        code: 'worker_error',
        message: String(res?.error || 'Warm-session consume failed'),
      };
    }
    await this.recordSessionUseConsumed(
      args.sessionId,
      parsed,
      args.curve,
      chainTarget,
    );
    return parsed;
  };

  clearVolatileWarmSessionMaterial = async (
    args: ClearVolatileWarmSessionMaterialCommand,
  ): Promise<void> => {
    const command = parseClearVolatileWarmMaterialCommand(args);
    if (command?.scope.kind !== 'session') return;
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR',
      id: this.generateMessageId(),
      payload: command,
    });
    if (!res?.success) {
      throw new Error(
        String(res?.error || 'Failed to clear volatile warm-session material'),
      );
    }
  };

  deleteDurableSealedSessionRecord = async (
    command: DeleteDurableSealedSessionCommand,
  ): Promise<void> => {
    await this.runDurableSealedSessionDelete(command);
  };

  clearAllVolatileWarmSessionMaterial = async (
    args: ClearAllVolatileWarmSessionMaterialCommand,
  ): Promise<void> => {
    const command = parseClearVolatileWarmMaterialCommand(args);
    if (command?.scope.kind !== 'all') return;
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR_ALL',
      id: this.generateMessageId(),
      payload: command,
    });
    if (!res?.success) {
      throw new Error(
        String(res?.error || 'Failed to clear all volatile warm-session material entries'),
      );
    }
  };

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
   * UiConfirm orchestration helper for signing confirmation flows.
   * Runs uiConfirm confirmation flows on the main thread and returns artifacts needed by the signer worker.
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
   * Runs uiConfirm confirmation flows on the main thread and returns registration artifacts.
   */
  async requestRegistrationCredentialConfirmation(
    params: RequestRegistrationCredentialConfirmationParams,
  ) {
    return requestRegistrationCredentialConfirmationOnMainThread({
      ctx: this.getContext(),
      nearAccountId: params.nearAccountId,
      signerSlot: params.signerSlot,
      confirmerText: params.confirmerText,
      confirmationConfig: params.confirmationConfigOverride,
      challengeB64u: params.challengeB64u,
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
      data: this.restoreFunctionBearingConfirmRequestFields(requestId, request),
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
    // dispatch them through uiConfirm confirmation flows on the main thread. The decision
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
    if (this.worker) {
      this.detachWorkerRouter(this.worker);
      this.worker.terminate();
      this.worker = null;
    }
    this.initializationPromise = null;
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
