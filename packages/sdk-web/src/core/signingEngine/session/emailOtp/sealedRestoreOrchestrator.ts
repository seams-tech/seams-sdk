import type { EmailOtpEcdsaSealedRuntimePurpose } from './sealedRuntimePurpose';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type acquireSigningSessionRestoreLease,
  type listExactSealedSessionsForWallet,
  type readExactSealedSession,
  type releaseSigningSessionRestoreLease,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  createSigningSessionRestoreAttemptRegistry,
  createSigningSessionRestoreCache,
  discoverPersistedSessionsForWalletCommand,
  restorePersistedSessionForSigningCommand,
} from '@/core/signingEngine/session/sealedRecovery/restoreCoordinator';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionForSigningResult,
  RestorePersistedSessionPurpose,
  RestoreSealedRecordResult,
  RestoredWarmSessionStatus,
  SigningSessionRestoreAttemptRegistry,
  SigningSessionRestoreCache,
} from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import { materialActivationKey } from '@/core/signingEngine/session/sealedRecovery/materialActivationKey';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  normalizeSealedRecoveryRecord,
  type EmailOtpEcdsaSealedRecoveryRecord,
  type SealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
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
  readWarmSessionStatusFromWorker: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionStatusResult>;
  restoreEcdsaSigningSessionMaterialFromSealedRecord: (
    args: EmailOtpEcdsaSealedRecoveryRecordInput,
  ) => Promise<EmailOtpThresholdEcdsaRehydrateResult | null>;
  recordSessionMaterialRestored: (
    purpose: EmailOtpEcdsaSealedRuntimePurpose,
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

export class EmailOtpSealedRestoreOrchestrator {
  private readonly restoreCache: SigningSessionRestoreCache = createSigningSessionRestoreCache();
  private readonly restoreAttempts: SigningSessionRestoreAttemptRegistry =
    createSigningSessionRestoreAttemptRegistry();

  /** The lane the in-flight restore was requested for. Set from the request's
   * purpose, never guessed, so an identical session id on another target reads
   * that target's record and no other. */
  private requestedChainTarget: ThresholdEcdsaChainTarget | null = null;

  constructor(private readonly ports: EmailOtpSealedRestoreOrchestratorPorts) {}

  clearCache(): void {
    this.restoreCache.clear();
    this.restoreAttempts.clear();
  }

  async tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
    purpose: EmailOtpEcdsaSealedRuntimePurpose,
  ): Promise<WarmSessionStatusResult | null> {
    if (this.ports.sessionPersistenceMode !== 'sealed_refresh_v1') return null;
    const requestedSessionId = String(purpose.thresholdSessionId || '').trim();
    if (!requestedSessionId) return null;
    this.requestedChainTarget = purpose.chainTarget;

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
      });
      const restored = await this.ports
        .restoreEcdsaSigningSessionMaterialFromSealedRecord({
          sealedRecord,
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
      await this.ports.recordSessionMaterialRestored(
        { thresholdSessionId, chainTarget: sealedRecord.chainTarget },
        result,
      );
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
    const chainTarget = this.requestedChainTarget;
    if (!chainTarget) return null;
    return await this.readEcdsaSealedRecordForTarget(thresholdSessionId, chainTarget);
  }

  private async readEcdsaSealedRecordForTarget(
    thresholdSessionId: string,
    chainTarget: ThresholdEcdsaChainTarget,
  ): Promise<EmailOtpEcdsaSealedRecoveryRecord | null> {
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
    purpose: RestorePersistedSessionPurpose;
  }): Promise<RestoreSealedRecordResult> {
    const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return 'deferred';
    if (args.record.authMethod !== args.purpose.authMethod) return 'deferred';
    if (args.record.thresholdSessionId !== thresholdSessionId) return 'deferred';
    if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, args.purpose.chainTarget)) {
      return 'deferred';
    }
    if (
      !mpcMaterialActivationRefsEqual(
        args.record.roleLocalMaterialRef.materialActivation,
        args.purpose.materialActivation,
      )
    ) {
      return 'deferred';
    }
    const restoreKey = [
      args.walletId,
      args.purpose.authMethod,
      args.purpose.curve,
      thresholdEcdsaChainTargetKey(args.purpose.chainTarget),
      materialActivationKey(args.purpose.materialActivation),
      thresholdSessionId,
    ].join(':');
    if (this.restoreAttempts.hasCompleted(restoreKey)) return 'ready';

    const inFlight = this.restoreAttempts.getInFlight(restoreKey);
    if (inFlight) {
      await inFlight;
      return this.restoreAttempts.hasCompleted(restoreKey) ? 'ready' : 'deferred';
    }

    let restoreResult: 'restored' | 'deferred' = 'deferred';
    const task = (async () => {
      const restored = await this.ports.restoreEcdsaSigningSessionMaterialFromSealedRecord({
        sealedRecord: args.record,
      });
      if (restored) {
        await this.ports.recordSessionMaterialRestored(
          { thresholdSessionId, chainTarget: args.record.chainTarget },
          {
            ok: true,
            remainingUses: restored.remainingUses,
            expiresAtMs: restored.expiresAtMs,
          },
        );
        this.restoreAttempts.rememberCompleted(restoreKey);
        restoreResult = 'restored';
      }
    })()
      .catch((error) => {
        console.warn('[EmailOtpSession] wallet-scoped sealed ECDSA restore failed', {
          walletId: args.walletId,
          thresholdSessionId,
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
