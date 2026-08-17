import { BUILD_PATHS } from '../../../../build-paths';
import type {
  PasskeyMpcSessionWorkerMessage,
  UserConfirmWorkerResponse,
  WarmSessionSealTransportInput,
  WarmSessionRehydratePayload,
  WarmSessionRehydrateResult,
  WarmSessionSealAndPersistPayload,
  WarmSessionSealAndPersistResult,
  WarmSessionStatusBatchResult,
} from '../../types/secure-confirm-worker';
import { resolveWorkerUrl } from '../../walletRuntimePaths';
import {
  warmSessionProtocolSessionId,
  type WarmSessionLanePurpose,
  type WarmSessionMaterialOperationTarget,
} from '../session/emailOtp/sealedRuntimePurpose';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';
import type {
  WarmSessionMaterialWriteDiagnosticBucket,
  WarmSessionMaterialWriteDiagnostics,
} from '../session/passkey/warmSessionMaterialWriter';
import { parseClearVolatileWarmMaterialCommand } from '../session/warmCapabilities/volatileWarmMaterialCommands';
import type {
  ClearAllVolatileWarmSessionMaterialCommand,
  ClearVolatileWarmSessionMaterialCommand,
  PasskeyWarmSessionSealTransportInput,
  PasskeyMpcSessionPort,
  WarmSessionPersistedDiscovery,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from './uiConfirm.types';
import {
  acquireSigningSessionRestoreLease,
  deleteDurableSealedSessionRecord,
  listExactSealedSessionsForWallet,
  releaseSigningSessionRestoreLease,
} from '../session/persistence/sealedSessionStore';
import { createDeleteDurableSealedSessionCommand } from '../session/persistence/durableSealedSessionCommands';
import {
  discoverPersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '../session/sealedRecovery/restoreCoordinator';
import type {
  DiscoverPersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestoreSealedRecordResult,
} from '../session/sealedRecovery/sealedRecovery.types';
import { materialActivationKey } from '../session/sealedRecovery/materialActivationKey';
import type { SealedRecoveryRecord } from '../session/sealedRecovery/recoveryRecord';
import { restorePasskeyEcdsaSealedRecordForWallet } from '../session/passkey/ecdsaRecovery';
import { parseSigningSessionSealKeyVersion } from '../session/keyMaterialBrands';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
} from '../interfaces/ecdsaChainTarget';
import { PasskeyMpcSessionDurableState } from './PasskeyMpcSessionDurableState';
import {
  walletSessionAuthorizations,
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { toWalletId } from '../interfaces/ecdsaChainTarget';
import {
  resolveThresholdEcdsaSigningQueueKey,
  withThresholdEcdsaSigningQueue,
  type ThresholdEcdsaSigningQueueByKey,
} from '../threshold/ecdsa/signingQueue';
import type { resolveActiveEcdsaCapabilityRuntime } from '../session/material/activeEcdsaCapabilityRuntime';

type PendingPasskeyMpcSessionRequest = {
  id: string;
  timeoutId: ReturnType<typeof setTimeout>;
  resolve: (response: UserConfirmWorkerResponse) => void;
  reject: (error: Error) => void;
};

type PasskeyMpcSessionManagerDeps = {
  signingSessionPersistenceMode: 'none' | 'sealed_refresh_v1';
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
  resolveCurrentEcdsaCapabilityRuntime: typeof resolveActiveEcdsaCapabilityRuntime;
};

const PASSKEY_MPC_SESSION_TIMEOUT_MS = 60_000;
const PASSKEY_MPC_SESSION_STARTUP_TIMEOUT_MS = 15_000;
const signingSessionRehydrateSingleFlight = new Map<
  string,
  Promise<WarmSessionStatusResult | null>
>();
const signingSessionDeleteSingleFlight = new Map<string, Promise<void>>();

function restoreSingleFlightKey(args: {
  thresholdSessionId: string;
  chainTarget: RestorePersistedSessionPurpose['chainTarget'];
  materialActivation: RestorePersistedSessionPurpose['materialActivation'];
}): string {
  return [
    'rehydrate',
    'passkey',
    'ecdsa',
    thresholdEcdsaChainTargetKey(args.chainTarget),
    materialActivationKey(args.materialActivation),
    String(args.thresholdSessionId || '').trim(),
  ].join('|');
}

function requirePasskeyEcdsaRestoreOutcome(
  result: WarmSessionStatusResult | null,
  success: Extract<RestoreSealedRecordResult, 'ready' | 'restored'>,
): RestoreSealedRecordResult {
  if (!result) return 'deferred';
  if (result.ok) return success;
  if (result.code === 'exhausted') return 'ready';
  if (result.code === 'expired') return 'deferred';
  throw new Error(
    `[PasskeyMpcSession] sealed-session restore failed (${result.code}): ${result.message}`,
  );
}

async function passkeyEcdsaRestoreMetadataFromRecoveryRecord(
  record: Extract<SealedRecoveryRecord, { authMethod: 'passkey' }>,
  authorization: ActiveWalletSessionAuthorizationProjection,
): Promise<Exclude<SealedSigningSessionEcdsaRestoreMetadata, { source: 'email_otp' }>> {
  return {
    chainTarget: record.chainTarget,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    source: record.source,
    authority: await walletAuthAuthorityRef({ authority: record.authority }),
    roleLocalMaterialRef: record.roleLocalMaterialRef,
    rpId: record.authority.verifier.rpId,
    credentialIdB64u: record.authority.factor.credentialIdB64u,
    keyHandle: record.keyHandle,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    ethereumAddress: record.ethereumAddress,
    relayerKeyId: record.relayerKeyId,
    clientVerifyingShareB64u: record.clientVerifyingShareB64u,
    thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
    participantIds: [...record.participantIds],
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    routerAbEcdsaDerivationNormalSigning: record.routerAbEcdsaDerivationNormalSigning,
    publicCapability: record.publicCapability,
  };
}

async function deleteInvalidPasskeyEcdsaRecord(args: {
  thresholdSessionId: string;
  chainTarget: RestorePersistedSessionPurpose['chainTarget'];
}): Promise<void> {
  const command = createDeleteDurableSealedSessionCommand({
    durableRecord: {
      authMethod: 'passkey',
      curve: 'ecdsa',
      thresholdSessionId: args.thresholdSessionId,
      chainTarget: args.chainTarget,
    },
    deleteReason: 'invalid_persisted_record',
    preserveResolvedIdentity: false,
  });
  const key = [
    'delete',
    'passkey',
    'ecdsa',
    thresholdEcdsaChainTargetKey(args.chainTarget),
    args.thresholdSessionId,
  ].join('|');
  const inFlight = signingSessionDeleteSingleFlight.get(key);
  if (inFlight) return await inFlight;
  const task = deleteDurableSealedSessionRecord(command).finally(() => {
    signingSessionDeleteSingleFlight.delete(key);
  });
  signingSessionDeleteSingleFlight.set(key, task);
  await task;
}

async function listPasskeySealedSessionsForWallet(args: {
  walletId: string;
  authMethod: SigningSessionSealAuthMethod;
  curve: 'ecdsa';
  chainTarget: RestorePersistedSessionPurpose['chainTarget'];
}) {
  return await listExactSealedSessionsForWallet({
    walletId: args.walletId,
    filter: {
      authMethod: 'passkey',
      curve: 'ecdsa',
      chainTarget: args.chainTarget,
    },
  });
}

function logPasskeyRestoreListError(args: {
  walletId: string;
  target: string;
  reason: RestorePersistedSessionForSigningInput['reason'];
  error: unknown;
}): void {
  console.warn('[PasskeyMpcSession] signing-session restore list failed', {
    walletId: args.walletId,
    target: args.target,
    reason: args.reason,
    error: args.error instanceof Error ? args.error.message : String(args.error || 'unknown error'),
  });
}

function logPasskeyRejectedRestoreRecord(args: { walletId: string; rejection: unknown }): void {
  console.warn('[PasskeyMpcSession] signing-session restore rejected record', args);
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function isNonnegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
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
  if (!isNonnegativeSafeInteger(data.remainingUses) || !isPositiveSafeInteger(data.expiresAtMs)) {
    return null;
  }
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
    if (
      !isObjectRecord(entry) ||
      typeof entry.thresholdSessionId !== 'string' ||
      !entry.thresholdSessionId.trim()
    ) {
      return null;
    }
    const result = parseWarmSessionStatusResult(entry.result);
    if (!result) return null;
    results.push({ thresholdSessionId: entry.thresholdSessionId, result });
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
    !data.prfFirstB64u.trim() ||
    !isNonnegativeSafeInteger(data.remainingUses) ||
    !isPositiveSafeInteger(data.expiresAtMs)
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
    !data.sealedSecretB64u.trim() ||
    typeof data.keyVersion !== 'string' ||
    !data.keyVersion.trim() ||
    !isNonnegativeSafeInteger(data.remainingUses) ||
    !isPositiveSafeInteger(data.expiresAtMs)
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
    keyVersion: data.keyVersion.trim(),
    remainingUses: data.remainingUses,
    expiresAtMs: data.expiresAtMs,
    ...(diagnostics ? { diagnostics } : {}),
  };
}

function requirePasskeySealTransport(
  transport: WarmSessionSealTransportInput,
): PasskeyWarmSessionSealTransportInput {
  if (transport.authMethod === 'email_otp' || transport.curve === 'linked_device') {
    throw new Error('Passkey MPC durable owner requires an owner signing-lane transport');
  }
  return transport;
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

class PasskeyMpcSessionManagerImpl implements PasskeyMpcSessionPort {
  private worker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private workerBaseOrigin: string | undefined;
  private messageId = 0;
  private readonly pendingRequests = new Map<string, PendingPasskeyMpcSessionRequest>();
  private readonly boundHandleWorkerMessage = this.handleWorkerMessage.bind(this);
  private readonly boundHandleWorkerError = this.handleWorkerError.bind(this);
  private readonly durableState: PasskeyMpcSessionDurableState;

  constructor(private readonly deps: PasskeyMpcSessionManagerDeps) {
    this.durableState = new PasskeyMpcSessionDurableState({
      signingSessionPersistenceMode: deps.signingSessionPersistenceMode,
      sealAndPersistWarmSessionMaterial: this.sealAndPersistWarmSessionMaterial.bind(this),
      readWarmSessionStatus: this.readWarmSessionStatus.bind(this),
    });
  }

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
    const persistenceResult = args.transport
      ? await this.persistSigningSessionSealForThresholdSession({
          thresholdSessionId: args.thresholdSessionId,
          transport: requirePasskeySealTransport(args.transport),
          ...(diagnostics ? { diagnostics } : {}),
        })
      : null;
    const persisted = persistenceResult;
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
    thresholdSessionId: string;
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

  restorePersistedSessionForSigning = async (
    args: Omit<RestorePersistedSessionForSigningInput, 'authMethod'>,
  ): Promise<RestorePersistedSessionForSigningResult> => {
    if (this.deps.signingSessionPersistenceMode !== 'sealed_refresh_v1') {
      return { kind: 'completed', attempted: 0, restored: 0, deferred: 0 };
    }
    return await restorePersistedSessionForSigningCommand(
      { ...args, authMethod: 'passkey' },
      {
        listExactSealedSessionsForWallet: listPasskeySealedSessionsForWallet,
        restoreSealedRecordForWallet: this.restorePasskeySealedRecordForWallet,
        onListError: logPasskeyRestoreListError,
        onRejectedRecord: logPasskeyRejectedRestoreRecord,
      },
    );
  };

  private readonly restorePasskeySealedRecordForWallet = async (args: {
    walletId: string;
    record: SealedRecoveryRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordResult> => {
    const { record, purpose } = args;
    if (purpose.authMethod !== 'passkey' || record.authMethod !== 'passkey') {
      return 'deferred';
    }
    const thresholdSessionId = String(purpose.thresholdSessionId || '').trim();
    const chainTarget = purpose.chainTarget;
    if (
      !thresholdSessionId ||
      record.curve !== 'ecdsa' ||
      !thresholdEcdsaChainTargetsEqual(record.chainTarget, chainTarget) ||
      !mpcMaterialActivationRefsEqual(
        record.roleLocalMaterialRef.materialActivation,
        purpose.materialActivation,
      )
    ) {
      return 'deferred';
    }
    const singleFlightKey = restoreSingleFlightKey({
      thresholdSessionId,
      chainTarget,
      materialActivation: purpose.materialActivation,
    });
    const inFlight = signingSessionRehydrateSingleFlight.get(singleFlightKey);
    if (inFlight) {
      return requirePasskeyEcdsaRestoreOutcome(await inFlight, 'ready');
    }

    const task = withThresholdEcdsaSigningQueue({
      queueByKey: this.deps.thresholdEcdsaSigningQueueByKey,
      queueKey: resolveThresholdEcdsaSigningQueueKey({
        materialActivation: record.roleLocalMaterialRef.materialActivation,
      }),
      walletId: toWalletId(args.walletId),
      enabled: true,
      task: async () =>
        await this.restorePasskeyEcdsaRecord({
          walletId: args.walletId,
          record,
          purpose: { ...purpose, authMethod: 'passkey' },
        }),
    }).finally(() => {
      signingSessionRehydrateSingleFlight.delete(singleFlightKey);
    });
    signingSessionRehydrateSingleFlight.set(singleFlightKey, task);
    return requirePasskeyEcdsaRestoreOutcome(await task, 'restored');
  };

  private async restorePasskeyEcdsaRecord(args: {
    walletId: string;
    record: Extract<SealedRecoveryRecord, { authMethod: 'passkey'; curve: 'ecdsa' }>;
    purpose: RestorePersistedSessionPurpose & { authMethod: 'passkey' };
  }): Promise<WarmSessionStatusResult | null> {
    const thresholdSessionId = args.purpose.thresholdSessionId;
    const chainTarget = args.purpose.chainTarget;
    const lease = await acquireSigningSessionRestoreLease({
      thresholdSessionId,
      authMethod: 'passkey',
      curve: 'ecdsa',
      chainTarget,
    });
    if (!lease) return null;
    try {
      const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(
        toWalletId(args.walletId),
      );
      const expectedAuthority = await walletAuthAuthorityRef({ authority: args.record.authority });
      if (
        authorizationRead.kind !== 'found' ||
        authorizationRead.projection.authMethod !== 'passkey' ||
        authorizationRead.projection.walletId !== toWalletId(args.walletId) ||
        authorizationRead.projection.authority.authorityDigest !==
          expectedAuthority.authorityDigest ||
        authorizationRead.projection.expiresAtMs <= Date.now()
      ) {
        return null;
      }
      const authorization = authorizationRead.projection;
      const ecdsaRestore = await passkeyEcdsaRestoreMetadataFromRecoveryRecord(
        args.record,
        authorization,
      );
      const walletSessionToken = walletSessionTokenForCurve(authorization, 'ecdsa');
      if (!walletSessionToken) return null;
      const restoreWalletId = String(ecdsaRestore.authority.walletId).trim();
      if (!restoreWalletId || restoreWalletId !== String(args.walletId).trim()) return null;
      const groupId = String(args.record.groupId || '').trim();
      if (!groupId) return null;
      const transport: WarmSessionSealTransportInput = {
        curve: 'ecdsa',
        authMethod: 'passkey',
        walletId: restoreWalletId,
        chainTarget,
        relayerUrl: args.record.relayerUrl,
        signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(args.record.keyVersion),
        groupId,
        walletSessionToken,
        ecdsaRestore,
      };
      return await restorePasskeyEcdsaSealedRecordForWallet({
        record: args.record,
        purpose: args.purpose,
        transport,
        groupId,
        rehydrateWarmSessionMaterial: this.rehydrateWarmSessionMaterial.bind(this),
        deletePersistedRecord: async () =>
          await deleteInvalidPasskeyEcdsaRecord({ thresholdSessionId, chainTarget }),
        recordSessionMaterialRestored: async (status) =>
          await this.recordWarmSessionPolicyResult(
            { curve: 'ecdsa', thresholdSessionId, chainTarget },
            thresholdSessionId,
            status,
          ),
        readWarmSessionStatusFromWorker: async (thresholdSessionId) =>
          await this.readWarmSessionStatus({ thresholdSessionId }),
        resolveCurrentEcdsaCapabilityRuntime: this.deps.resolveCurrentEcdsaCapabilityRuntime,
        updatePersistedPolicy: async (policy) =>
          await this.durableState.updatePersistedPolicy({
            thresholdSessionId,
            purpose: { curve: 'ecdsa', thresholdSessionId, chainTarget },
            ...policy,
          }),
      });
    } finally {
      await releaseSigningSessionRestoreLease(lease);
    }
  }

  getWarmSessionStatuses = async (args: {
    thresholdSessionIds: string[];
  }): Promise<WarmSessionStatusBatchResult> => {
    const thresholdSessionIds = Array.from(
      new Set(args.thresholdSessionIds.map((value) => String(value || '').trim()).filter(Boolean)),
    );
    if (!thresholdSessionIds.length) return { results: [] };
    const response = await this.sendMessage({
      type: 'WARM_SESSION_STATUS_BATCH_READ',
      id: this.generateMessageId(),
      payload: { thresholdSessionIds },
    });
    const parsed = parseWarmSessionStatusBatchResult(response.data);
    if (response.success && parsed) return parsed;
    return {
      results: thresholdSessionIds.map((thresholdSessionId) => ({
        thresholdSessionId,
        result: {
          ok: false,
          code: 'worker_error',
          message: String(response.error || 'Warm-session batch status read failed'),
        },
      })),
    };
  };

  claimWarmSessionMaterial = async (
    args: WarmSessionMaterialOperationTarget & {
      uses?: number;
      consume?: boolean;
    },
  ): Promise<WarmSessionClaimResult> => {
    const thresholdSessionId = warmSessionProtocolSessionId(args);
    const response = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CLAIM',
      id: this.generateMessageId(),
      payload: {
        thresholdSessionId,
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
    await this.recordWarmSessionPolicyResult(args.purpose, thresholdSessionId, parsed);
    return parsed;
  };

  consumeWarmSessionUses = async (
    args: WarmSessionMaterialOperationTarget & {
      uses?: number;
    },
  ): Promise<WarmSessionStatusResult> => {
    const thresholdSessionId = warmSessionProtocolSessionId(args);
    const response = await this.sendMessage({
      type: 'WARM_SESSION_MATERIAL_CONSUME',
      id: this.generateMessageId(),
      payload: {
        thresholdSessionId,
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
    await this.recordWarmSessionPolicyResult(args.purpose, thresholdSessionId, parsed);
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

  persistSigningSessionSealForThresholdSession = async (
    args: Parameters<PasskeyMpcSessionPort['persistSigningSessionSealForThresholdSession']>[0],
  ): Promise<WarmSessionSealAndPersistResult> =>
    await this.durableState.persistSigningSessionSealForThresholdSession(args);

  private readonly recordWarmSessionPolicyResult = async (
    purpose: WarmSessionLanePurpose,
    thresholdSessionId: string,
    result: WarmSessionStatusResult | WarmSessionClaimResult,
  ): Promise<void> =>
    await this.durableState.recordPolicyResult(purpose, thresholdSessionId, result);

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
    thresholdSessionId: string;
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
        this.rejectPendingRequest(id, error instanceof Error ? error : new Error(String(error)));
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
): PasskeyMpcSessionPort {
  return new PasskeyMpcSessionManagerImpl(deps);
}
