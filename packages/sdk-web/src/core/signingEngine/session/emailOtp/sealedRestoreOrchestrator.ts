import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  publishResolvedIdentity,
  type acquireSigningSessionRestoreLease,
  type listExactSealedSessionsForWallet,
  type readExactSealedSession,
  type releaseSigningSessionRestoreLease,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { RestoredWarmSessionStatus } from '@/core/signingEngine/session/sealedRecovery/readback';
import {
  createSigningSessionRestoreAttemptRegistry,
  createSigningSessionRestoreCache,
  discoverPersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '@/core/signingEngine/session/sealedRecovery/restoreCoordinator';
import type {
  RestorePersistedEcdsaSessionPurpose,
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestoreSealedRecordResult,
  SigningSessionRestoreAttemptRegistry,
  SigningSessionRestoreCache,
} from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import {
  normalizeSealedRecoveryRecord,
  type EmailOtpEcdsaSealedRecoveryRecord,
  type SealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type {
  EmailOtpEcdsaSealedRecoveryRecordInput,
  EmailOtpThresholdEcdsaRehydrateResult,
} from './ecdsaRecovery';
import { emailOtpAuthContextRetention } from '../identity/laneIdentity';

export type EmailOtpSealedRestoreOrchestratorPorts = {
  sessionPersistenceMode: string;
  listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
  readExactSealedSession: typeof readExactSealedSession;
  acquireSigningSessionRestoreLease: typeof acquireSigningSessionRestoreLease;
  releaseSigningSessionRestoreLease: typeof releaseSigningSessionRestoreLease;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  readWarmSessionStatusFromWorker: (sessionId: string) => Promise<WarmSessionStatusResult>;
  restoreEcdsaSigningSessionMaterialFromSealedRecord: (
    args: EmailOtpEcdsaSealedRecoveryRecordInput,
  ) => Promise<EmailOtpThresholdEcdsaRehydrateResult | null>;
  recordSessionMaterialRestored: (
    sessionId: string,
    status: RestoredWarmSessionStatus,
  ) => Promise<void>;
  shouldLogDiagnostic: (key: string) => boolean;
};

const EMPTY_ACCOUNT_DISCOVERY_RESULT = {
  listed: 0,
  discovered: 0,
  truncated: 0,
} as const;

const EMPTY_SIGNING_RESTORE_RESULT = {
  kind: 'completed',
  attempted: 0,
  restored: 0,
  deferred: 0,
} as const;

function markExistingEmailOtpEcdsaWorkerMaterialRuntimeValidated(
  record: ThresholdEcdsaSessionRecord | null,
): boolean {
  if (!record || record.source !== 'email_otp') return false;
  return markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record);
}

export class EmailOtpSealedRestoreOrchestrator {
  private readonly restoreCache: SigningSessionRestoreCache = createSigningSessionRestoreCache();
  private readonly restoreAttempts: SigningSessionRestoreAttemptRegistry =
    createSigningSessionRestoreAttemptRegistry();

  constructor(private readonly ports: EmailOtpSealedRestoreOrchestratorPorts) {}

  clearCache(): void {
    this.restoreCache.clear();
    this.restoreAttempts.clear();
  }

  shouldAttemptEcdsaSealedRestoreForSessionId(sessionIdRaw: string): boolean {
    const sessionId = String(sessionIdRaw || '').trim();
    if (!sessionId) return false;
    const ecdsaRecord = this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
    if (ecdsaRecord?.source === 'email_otp') return true;
    return true;
  }

  async tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
    sessionId: string,
  ): Promise<WarmSessionStatusResult | null> {
    if (this.ports.sessionPersistenceMode !== 'sealed_refresh_v1') return null;
    const requestedSessionId = String(sessionId || '').trim();
    if (!requestedSessionId) return null;

    const thresholdSessionId = requestedSessionId;
    const sealedRecord = await this.readEcdsaSealedRecord(requestedSessionId);
    if (!sealedRecord) return null;
    if (sealedRecord.remainingUses <= 0 || Date.now() >= sealedRecord.expiresAtMs) {
      console.debug('[EmailOtpSession] sealed refresh restore deferred by durable policy hint', {
        thresholdSessionId,
        remainingUses: sealedRecord.remainingUses,
        expiresAtMs: sealedRecord.expiresAtMs,
      });
      return null;
    }
    if (
      sealedRecord.authMethod !== 'email_otp' ||
      sealedRecord.thresholdSessionId !== thresholdSessionId
    ) {
      console.warn('[EmailOtpSession] sealed refresh restore deferred by store metadata mismatch', {
        thresholdSessionId,
        authMethod: sealedRecord.authMethod,
        ecdsaThresholdSessionId: sealedRecord.thresholdSessionId,
      });
      return null;
    }

    const ecdsaRecord =
      this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    const ecdsaEmailOtpAuthContext =
      ecdsaRecord?.source === 'email_otp' ? ecdsaRecord.emailOtpAuthContext : null;
    const ecdsaEmailOtpRetention = ecdsaEmailOtpAuthContext
      ? emailOtpAuthContextRetention(ecdsaEmailOtpAuthContext)
      : null;
    if (
      (ecdsaRecord && ecdsaRecord.source !== 'email_otp') ||
      (ecdsaRecord && ecdsaEmailOtpRetention !== 'session')
    ) {
      const diagnosticKey = `missing-ecdsa-record:${thresholdSessionId}`;
      if (this.ports.shouldLogDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] sealed refresh restore waiting for ECDSA record', {
          thresholdSessionId,
          source: ecdsaRecord?.source,
          retention: ecdsaEmailOtpRetention,
        });
      }
      return null;
    }

    const lease = await this.ports
      .acquireSigningSessionRestoreLease({
        thresholdSessionId,
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget: sealedRecord.chainTarget,
      })
      .catch(() => null);
    if (!lease) {
      const diagnosticKey = `lease-unavailable:${thresholdSessionId}`;
      if (this.ports.shouldLogDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] sealed refresh restore deferred; lease unavailable', {
          thresholdSessionId,
        });
      }
      return null;
    }

    try {
      console.debug('[EmailOtpSession] sealed refresh restore started', {
        thresholdSessionId,
        signingGrantId: sealedRecord.signingGrantId,
      });
      const restored = await this.ports
        .restoreEcdsaSigningSessionMaterialFromSealedRecord({
          sealedRecord,
          ecdsaRecord,
        })
        .catch((error) => {
          console.warn('[EmailOtpSession] sealed refresh restore failed', {
            thresholdSessionId,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
          return null;
        });
      if (!restored) return null;
      console.debug('[EmailOtpSession] sealed refresh restore succeeded', {
        thresholdSessionId,
        remainingUses: restored.remainingUses,
        expiresAtMs: restored.expiresAtMs,
      });
      const result = {
        ok: true,
        remainingUses: restored.remainingUses,
        expiresAtMs: restored.expiresAtMs,
      } satisfies RestoredWarmSessionStatus;
      const chainTarget = sealedRecord.chainTarget;
      const walletId = String(sealedRecord.walletId || '').trim();
      if (walletId && chainTarget) {
        const restoredAtMs = Date.now();
        publishResolvedIdentity({
          walletId,
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chainTarget,
          signingGrantId: sealedRecord.signingGrantId,
          thresholdSessionId,
          updatedAtMs: restoredAtMs,
        });
      }
      await this.ports.recordSessionMaterialRestored(thresholdSessionId, result);
      return result;
    } finally {
      await this.ports.releaseSigningSessionRestoreLease(lease).catch(() => undefined);
    }
  }

  async discoverPersistedSessionsForWallet(
    args: DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult> {
    if (this.ports.sessionPersistenceMode !== 'sealed_refresh_v1') {
      return { ...EMPTY_ACCOUNT_DISCOVERY_RESULT };
    }
    const walletId = String(toWalletId(args.walletId) || '').trim();
    if (!walletId) {
      return { ...EMPTY_ACCOUNT_DISCOVERY_RESULT };
    }

    const result = await discoverPersistedSessionsForWalletCommand(
      {
        ...args,
        walletId,
      },
      {
        listExactSealedSessionsForWallet: ({ walletId: recordWalletId, ...filter }) =>
          this.ports.listExactSealedSessionsForWallet({
            walletId: recordWalletId,
            filter,
          }),
        onListError: ({ walletId: failedWalletId, error }) => {
          console.warn('[EmailOtpSession] wallet-scoped sealed ECDSA discovery list failed', {
            walletId: failedWalletId,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
      },
    );
    if (!result.listed) {
      const diagnosticKey = `wallet-sealed-ecdsa-empty:${walletId}`;
      if (this.ports.shouldLogDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] no durable sealed ECDSA records for wallet discovery', {
          walletId,
        });
      }
    }
    return result;
  }

  async restorePersistedSessionForSigning(
    args: RestorePersistedSessionForSigningInput,
  ): Promise<RestorePersistedSessionForSigningResult> {
    if (this.ports.sessionPersistenceMode !== 'sealed_refresh_v1') {
      return { ...EMPTY_SIGNING_RESTORE_RESULT };
    }
    const walletId = String(toWalletId(args.walletId) || '').trim();
    if (!walletId) return { ...EMPTY_SIGNING_RESTORE_RESULT };

    return await restorePersistedSessionForSigningCommand(
      {
        ...args,
        walletId,
      },
      {
        listExactSealedSessionsForWallet: ({ walletId: recordWalletId, ...filter }) => {
          if (filter.curve !== 'ecdsa') return Promise.resolve([]);
          return this.ports.listExactSealedSessionsForWallet({
            walletId: recordWalletId,
            filter: {
              authMethod: filter.authMethod,
              curve: 'ecdsa',
              chainTarget: filter.chainTarget,
            },
          });
        },
        restoreSealedRecordForWallet: (restoreArgs) =>
          this.restoreEmailOtpSealedRecordForWallet(restoreArgs),
        cache: this.restoreCache,
        onListError: ({ walletId: failedWalletId, target, reason, error }) => {
          console.warn('[EmailOtpSession] signing-intent sealed ECDSA restore list failed', {
            walletId: failedWalletId,
            target,
            reason,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
      },
    );
  }

  private async readEcdsaSealedRecord(
    thresholdSessionId: string,
  ): Promise<EmailOtpEcdsaSealedRecoveryRecord | null> {
    const ecdsaRecord =
      this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    if (!ecdsaRecord || ecdsaRecord.source !== 'email_otp') return null;
    const chainTarget = ecdsaRecord.chainTarget;
    if (!chainTarget) return null;
    const rawRecord = await this.ports
      .readExactSealedSession(thresholdSessionId, {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget,
      })
      .catch((error) => {
        console.warn('[EmailOtpSession] sealed refresh ECDSA read failed', {
          thresholdSessionId,
          chain: chainTarget.kind,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        return null;
      });
    if (!rawRecord) return null;
    const normalized = normalizeSealedRecoveryRecord(rawRecord);
    return normalized.kind === 'accepted' &&
      normalized.record.authMethod === 'email_otp' &&
      normalized.record.curve === 'ecdsa'
      ? normalized.record
      : null;
  }

  private async restoreEmailOtpSealedRecordForWallet(args: {
    walletId: string;
    record: SealedRecoveryRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordResult> {
    if (args.purpose.authMethod !== 'email_otp') return 'deferred';
    if (args.purpose.curve !== 'ecdsa') return 'deferred';
    if (args.record.authMethod !== 'email_otp' || args.record.curve !== 'ecdsa') {
      return 'deferred';
    }
    return await this.restoreEcdsaSealedRecordForWallet({
      ...args,
      record: args.record,
      purpose: args.purpose,
    });
  }

  private async restoreEcdsaSealedRecordForWallet(args: {
    walletId: string;
    record: EmailOtpEcdsaSealedRecoveryRecord;
    purpose: RestorePersistedEcdsaSessionPurpose;
  }): Promise<RestoreSealedRecordResult> {
    const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return 'deferred';
    if (args.record.authMethod !== args.purpose.authMethod) return 'deferred';
    if (args.record.thresholdSessionId !== thresholdSessionId) return 'deferred';
    if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, args.purpose.chainTarget)) {
      return 'deferred';
    }
    if (args.record.signingGrantId !== args.purpose.signingGrantId) {
      return 'deferred';
    }
    const restoreKey = [
      args.walletId,
      args.purpose.authMethod,
      args.purpose.curve,
      thresholdEcdsaChainTargetKey(args.purpose.chainTarget),
      args.purpose.signingGrantId,
      thresholdSessionId,
    ].join(':');
    if (this.restoreAttempts.hasCompleted(restoreKey)) return 'ready';

    const existing =
      this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    if (existing?.source === 'email_otp') {
      const workerStatus = await this.ports
        .readWarmSessionStatusFromWorker(thresholdSessionId)
        .catch(() => null);
      if (workerStatus?.ok && markExistingEmailOtpEcdsaWorkerMaterialRuntimeValidated(existing)) {
        this.restoreAttempts.rememberCompleted(restoreKey);
        return 'ready';
      }
    }

    const inFlight = this.restoreAttempts.getInFlight(restoreKey);
    if (inFlight) {
      await inFlight;
      return this.restoreAttempts.hasCompleted(restoreKey) ? 'ready' : 'deferred';
    }

    let restoreResult: 'restored' | 'deferred' = 'deferred';
    const task = (async () => {
      const restored = await this.ports.restoreEcdsaSigningSessionMaterialFromSealedRecord({
        sealedRecord: args.record,
        ecdsaRecord: existing,
      });
      if (restored) {
        await this.ports.recordSessionMaterialRestored(thresholdSessionId, {
          ok: true,
          remainingUses: restored.remainingUses,
          expiresAtMs: restored.expiresAtMs,
        });
        this.restoreAttempts.rememberCompleted(restoreKey);
        restoreResult = 'restored';
      }
    })()
      .catch((error) => {
        console.warn('[EmailOtpSession] wallet-scoped sealed ECDSA restore failed', {
          walletId: args.walletId,
          thresholdSessionId,
          signingGrantId: args.purpose.signingGrantId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
      })
      .finally(() => {
        this.restoreAttempts.clearInFlight(restoreKey);
      });
    this.restoreAttempts.setInFlight(restoreKey, task);
    await task;
    return restoreResult;
  }

}
