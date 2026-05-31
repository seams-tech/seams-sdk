import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
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
  restorePersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '@/core/signingEngine/session/sealedRecovery/restoreCoordinator';
import type {
  RestorePersistedEcdsaSessionPurpose,
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestoreSealedRecordResult,
  SigningSessionRestoreAttemptRegistry,
  SigningSessionRestoreCache,
} from '@/core/signingEngine/session/sealedRecovery/types';
import {
  normalizeSealedRecoveryRecord,
  type EmailOtpEcdsaSealedRecoveryRecord,
  type EmailOtpEd25519SealedRecoveryRecord,
  type SealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import {
  restoreEmailOtpEd25519SealedRecordForAccount,
  type EmailOtpEd25519RestorePurpose,
} from './ed25519Recovery';
import type {
  EmailOtpEcdsaSealedRecoveryRecordInput,
  EmailOtpThresholdEcdsaRehydrateResult,
} from './ecdsaRecovery';

export type EmailOtpSealedRestoreOrchestratorPorts = {
  sessionPersistenceMode: string;
  listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
  readExactSealedSession: typeof readExactSealedSession;
  acquireSigningSessionRestoreLease: typeof acquireSigningSessionRestoreLease;
  releaseSigningSessionRestoreLease: typeof releaseSigningSessionRestoreLease;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
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

const EMPTY_ACCOUNT_RESTORE_RESULT = {
  listed: 0,
  attempted: 0,
  restored: 0,
  deferred: 0,
  skipped: 0,
  truncated: 0,
} as const;

const EMPTY_SIGNING_RESTORE_RESULT = { attempted: 0, restored: 0, deferred: 0 } as const;

function isEmailOtpEd25519RestorePurpose(
  purpose: RestorePersistedSessionPurpose,
): purpose is EmailOtpEd25519RestorePurpose {
  return purpose.authMethod === 'email_otp' && purpose.curve === 'ed25519';
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
    const ed25519Record =
      this.ports.getThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
    if (ed25519Record?.source === 'email_otp') return false;
    return true;
  }

  async tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
    sessionId: string,
  ): Promise<WarmSessionStatusResult | null> {
    if (this.ports.sessionPersistenceMode !== 'sealed_refresh_v1') return null;
    const requestedSessionId = String(sessionId || '').trim();
    if (!requestedSessionId) return null;

    let thresholdSessionId = requestedSessionId;
    let sealedRecord: EmailOtpEcdsaSealedRecoveryRecord | null = null;
    const requestedEd25519Record =
      this.ports.getThresholdEd25519SessionRecordByThresholdSessionId(requestedSessionId);
    if (requestedEd25519Record?.source === 'email_otp') {
      const companionRecord = await this.readEd25519CompanionSealedRecord(requestedSessionId);
      const companionEcdsaSessionId = String(
        companionRecord?.companionEcdsaRecovery?.thresholdSessionId || '',
      ).trim();
      if (companionEcdsaSessionId) {
        thresholdSessionId = companionEcdsaSessionId;
        sealedRecord = await this.readEcdsaSealedRecord(companionEcdsaSessionId);
      }
    }
    if (!sealedRecord) {
      sealedRecord = await this.readEcdsaSealedRecord(requestedSessionId);
    }
    if (!sealedRecord) {
      const companionRecord = await this.readEd25519CompanionSealedRecord(requestedSessionId);
      const companionEcdsaSessionId = String(
        companionRecord?.companionEcdsaRecovery?.thresholdSessionId || '',
      ).trim();
      if (companionEcdsaSessionId && companionEcdsaSessionId !== requestedSessionId) {
        thresholdSessionId = companionEcdsaSessionId;
        sealedRecord = await this.readEcdsaSealedRecord(companionEcdsaSessionId);
      }
    }
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
    if (
      (ecdsaRecord && ecdsaRecord.source !== 'email_otp') ||
      (ecdsaRecord && ecdsaEmailOtpAuthContext?.retention !== 'session')
    ) {
      const diagnosticKey = `missing-ecdsa-record:${thresholdSessionId}`;
      if (this.ports.shouldLogDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] sealed refresh restore waiting for ECDSA record', {
          thresholdSessionId,
          source: ecdsaRecord?.source,
          retention: ecdsaEmailOtpAuthContext?.retention,
        });
      }
      return null;
    }

    const sealedEd25519SessionId = String(
      sealedRecord.companionEd25519ThresholdSessionId || '',
    ).trim();
    const ed25519Record = sealedEd25519SessionId
      ? this.ports.getThresholdEd25519SessionRecordByThresholdSessionId(sealedEd25519SessionId)
      : null;
    if (
      sealedEd25519SessionId &&
      (!ed25519Record ||
        ed25519Record.source !== 'email_otp' ||
        ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
        ed25519Record.walletSigningSessionId !== sealedRecord.walletSigningSessionId)
    ) {
      const diagnosticKey = `missing-ed25519-companion:${thresholdSessionId}:${sealedEd25519SessionId}`;
      if (this.ports.shouldLogDiagnostic(diagnosticKey)) {
        console.debug(
          '[EmailOtpSession] sealed refresh restoring ECDSA without Ed25519 companion',
          {
            thresholdSessionId,
            sealedEd25519SessionId,
            ed25519Source: ed25519Record?.source,
            ed25519Retention: ed25519Record?.emailOtpAuthContext?.retention,
            ed25519WalletSigningSessionId: ed25519Record?.walletSigningSessionId,
            walletSigningSessionId: sealedRecord.walletSigningSessionId,
          },
        );
      }
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
        walletSigningSessionId: sealedRecord.walletSigningSessionId,
      });
      const restored = await this.ports
        .restoreEcdsaSigningSessionMaterialFromSealedRecord({
          sealedRecord,
          ecdsaRecord,
          ...(ed25519Record ? { ed25519Record } : {}),
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
        publishResolvedIdentity({
          walletId,
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chainTarget,
          walletSigningSessionId: sealedRecord.walletSigningSessionId,
          thresholdSessionId,
        });
      }
      await this.ports.recordSessionMaterialRestored(thresholdSessionId, result);
      return result;
    } finally {
      await this.ports.releaseSigningSessionRestoreLease(lease).catch(() => undefined);
    }
  }

  async restorePersistedSessionsForWallet(
    args: RestorePersistedSessionsForWalletInput,
  ): Promise<RestorePersistedSessionsForWalletResult> {
    if (this.ports.sessionPersistenceMode !== 'sealed_refresh_v1') {
      return { ...EMPTY_ACCOUNT_RESTORE_RESULT };
    }
    const walletId = String(toAccountId(args.walletId) || '').trim();
    if (!walletId) {
      return { ...EMPTY_ACCOUNT_RESTORE_RESULT };
    }

    const result = await restorePersistedSessionsForWalletCommand(
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
        restoreSealedRecordForWallet: (restoreArgs) =>
          this.restoreEmailOtpSealedRecordForWallet(restoreArgs),
        cache: this.restoreCache,
        onListError: ({ walletId: failedWalletId, error }) => {
          console.warn('[EmailOtpSession] wallet-scoped sealed ECDSA restore list failed', {
            walletId: failedWalletId,
            error: error instanceof Error ? error.message : String(error || 'unknown error'),
          });
        },
      },
    );
    if (!result.listed) {
      const diagnosticKey = `wallet-sealed-ecdsa-empty:${walletId}`;
      if (this.ports.shouldLogDiagnostic(diagnosticKey)) {
        console.debug('[EmailOtpSession] no durable sealed ECDSA records for wallet restore', {
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
    const walletId = String(toAccountId(args.walletId) || '').trim();
    if (!walletId) return { ...EMPTY_SIGNING_RESTORE_RESULT };

    return await restorePersistedSessionForSigningCommand(
      {
        ...args,
        walletId,
      },
      {
        listExactSealedSessionsForWallet: ({ walletId: recordWalletId, ...filter }) => {
          return this.ports.listExactSealedSessionsForWallet({
            walletId: recordWalletId,
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

  private async readEd25519CompanionSealedRecord(
    thresholdSessionId: string,
  ): Promise<EmailOtpEd25519SealedRecoveryRecord | null> {
    const rawRecord = await this.ports
      .readExactSealedSession(thresholdSessionId, {
        authMethod: 'email_otp',
        curve: 'ed25519',
      })
      .catch((error) => {
        console.warn('[EmailOtpSession] sealed refresh Ed25519 companion read failed', {
          thresholdSessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        return null;
      });
    if (!rawRecord) return null;
    const normalized = normalizeSealedRecoveryRecord(rawRecord);
    return normalized.kind === 'accepted' &&
      normalized.record.authMethod === 'email_otp' &&
      normalized.record.curve === 'ed25519'
      ? normalized.record
      : null;
  }

  private async restoreEmailOtpSealedRecordForWallet(args: {
    walletId: string;
    record: SealedRecoveryRecord;
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordResult> {
    if (args.purpose.authMethod !== 'email_otp') return 'deferred';
    if (isEmailOtpEd25519RestorePurpose(args.purpose)) {
      if (args.record.authMethod !== 'email_otp') {
        return 'deferred';
      }
      if (args.record.curve === 'ed25519') {
        return await this.restoreEd25519SealedRecordForAccount({
          accountId: args.walletId,
          record: args.record,
          purpose: args.purpose,
        });
      }
      if (
        args.record.curve !== 'ecdsa' ||
        !args.record.companionEd25519Recovery ||
        args.record.walletSigningSessionId !== args.purpose.walletSigningSessionId ||
        args.record.companionEd25519Recovery.thresholdSessionId !== args.purpose.thresholdSessionId
      ) {
        return 'deferred';
      }
      return await this.restoreEcdsaSealedRecordForWallet({
        walletId: args.walletId,
        record: args.record,
        purpose: {
          walletId: args.walletId,
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chainTarget: args.record.chainTarget,
          walletSigningSessionId: args.record.walletSigningSessionId,
          thresholdSessionId: args.record.thresholdSessionId,
          reason: args.purpose.reason,
        },
      });
    }
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
    if (args.record.walletSigningSessionId !== args.purpose.walletSigningSessionId) {
      return 'deferred';
    }
    const restoreKey = [
      args.walletId,
      args.purpose.authMethod,
      args.purpose.curve,
      thresholdEcdsaChainTargetKey(args.purpose.chainTarget),
      args.purpose.walletSigningSessionId,
      thresholdSessionId,
    ].join(':');
    if (this.restoreAttempts.hasCompleted(restoreKey)) return 'ready';

    const existing =
      this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    if (existing?.source === 'email_otp') {
      const workerStatus = await this.ports
        .readWarmSessionStatusFromWorker(thresholdSessionId)
        .catch(() => null);
      if (workerStatus?.ok) {
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
      const sealedEd25519SessionId = String(
        args.record.companionEd25519ThresholdSessionId || '',
      ).trim();
      const ed25519Record = sealedEd25519SessionId
        ? this.ports.getThresholdEd25519SessionRecordByThresholdSessionId(
            sealedEd25519SessionId,
          )
        : null;
      if (
        sealedEd25519SessionId &&
        (!ed25519Record ||
          ed25519Record.source !== 'email_otp' ||
          ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
          ed25519Record.walletSigningSessionId !== args.purpose.walletSigningSessionId)
      ) {
        const diagnosticKey = `exact-purpose-missing-ed25519-companion:${thresholdSessionId}:${sealedEd25519SessionId}`;
        if (this.ports.shouldLogDiagnostic(diagnosticKey)) {
          console.debug(
            '[EmailOtpSession] exact-purpose ECDSA restore proceeding without Ed25519 companion',
            {
              thresholdSessionId,
              sealedEd25519SessionId,
              walletSigningSessionId: args.purpose.walletSigningSessionId,
            },
          );
        }
      }
      const restored = await this.ports.restoreEcdsaSigningSessionMaterialFromSealedRecord({
        sealedRecord: args.record,
        ecdsaRecord: existing,
        ...(ed25519Record ? { ed25519Record } : {}),
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
          walletSigningSessionId: args.purpose.walletSigningSessionId,
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

  private async restoreEd25519SealedRecordForAccount(args: {
    accountId: string;
    record: EmailOtpEd25519SealedRecoveryRecord;
    purpose: EmailOtpEd25519RestorePurpose;
  }): Promise<RestoreSealedRecordResult> {
    return await restoreEmailOtpEd25519SealedRecordForAccount({
      ...args,
      getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
        this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId),
      readWarmSessionStatusFromWorker: (sessionId) =>
        this.ports.readWarmSessionStatusFromWorker(sessionId),
      recordSessionMaterialRestored: (sessionId, status) =>
        this.ports.recordSessionMaterialRestored(sessionId, status),
      restoreEcdsaSigningSessionMaterialFromSealedRecord: (restoreArgs) =>
        this.ports.restoreEcdsaSigningSessionMaterialFromSealedRecord(restoreArgs),
    });
  }
}
