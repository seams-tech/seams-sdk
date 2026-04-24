import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import {
  acquireSigningSessionRestoreLease,
  deleteSigningSessionSealedRecord,
  readSigningSessionSealedRecord,
  releaseSigningSessionRestoreLease,
  type SigningSessionRestoreLeaseHandle,
  type SigningSessionSealedStoreRecord,
} from '../api/session/signingSessionSealedStore';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/thresholdActivation';
import type { WarmSessionStatusResult } from '../touchConfirm';
import type { WarmSessionPrfClaim } from './warmSessionTypes';

export type WarmSessionSealedRestoreEvent = {
  accountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  thresholdSessionId: string;
  walletSigningSessionId?: string;
  status: 'started' | 'restored' | 'defer' | 'failed';
};

export type WarmSessionSealedRestoreResult = 'restored' | 'unavailable' | 'defer' | 'failed';

export type WarmSessionSealedStoreOverrides = {
  readRecord?: (thresholdSessionId: string) => Promise<SigningSessionSealedStoreRecord | null>;
  deleteRecord?: (thresholdSessionId: string) => Promise<void>;
  acquireRestoreLease?: (args: {
    thresholdSessionId: string;
    ownerId?: string;
    nowMs?: number;
    ttlMs?: number;
  }) => Promise<SigningSessionRestoreLeaseHandle | null>;
  releaseRestoreLease?: (
    lease: SigningSessionRestoreLeaseHandle | null | undefined,
  ) => Promise<void>;
};

export type RehydrateEmailOtpEcdsaSigningSessionFromSealedRecord = (args: {
  sealedRecord: SigningSessionSealedStoreRecord;
  ecdsaRecord: ThresholdEcdsaSessionRecord;
  ed25519Record?: ThresholdEd25519SessionRecord | null;
}) => Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  remainingUses: number;
  expiresAtMs: number;
} | null>;

export type WarmSessionSealedRefreshRestorerDeps = {
  signingSessionSealedStore?: WarmSessionSealedStoreOverrides;
  rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?: RehydrateEmailOtpEcdsaSigningSessionFromSealedRecord;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  clearEcdsaEphemeralMaterial: (args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId?: string;
    source?: 'email_otp';
  }) => Promise<void>;
  onSealedRestore?: (event: WarmSessionSealedRestoreEvent) => void | Promise<void>;
};

function isSessionRetainedEmailOtpEcdsaRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): record is ThresholdEcdsaSessionRecord {
  return (
    Boolean(record) &&
    record?.source === 'email_otp' &&
    record.emailOtpAuthContext?.retention === 'session'
  );
}

function resolveWalletSigningSessionId(
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord | null,
): string {
  return String(record?.walletSigningSessionId || '').trim();
}

export function createWarmSessionSealedRefreshRestorer(
  deps: WarmSessionSealedRefreshRestorerDeps,
) {
  async function shouldAttemptEmailOtpSealedRestore(args: {
    record: ThresholdEcdsaSessionRecord | null | undefined;
    prfClaim: WarmSessionPrfClaim | null;
  }): Promise<boolean> {
    if (!isSessionRetainedEmailOtpEcdsaRecord(args.record)) return false;
    const state = args.prfClaim?.state;
    if (state === 'missing' || state === 'expired' || state === 'exhausted') return true;
    const handle = args.record.clientAdditiveShareHandle;
    const sessionId =
      handle?.kind === 'email_otp_worker_session' ? String(handle.sessionId || '').trim() : '';
    if (!sessionId || typeof deps.getEmailOtpWarmSessionStatus !== 'function') return false;
    const status = await deps.getEmailOtpWarmSessionStatus(sessionId).catch(() => null);
    return !status?.ok;
  }

  async function deleteSigningSessionSealedRecordBestEffort(
    thresholdSessionId: string,
  ): Promise<void> {
    const deleter =
      deps.signingSessionSealedStore?.deleteRecord || deleteSigningSessionSealedRecord;
    await deleter(thresholdSessionId).catch(() => undefined);
  }

  function emitSealedRestoreEvent(event: WarmSessionSealedRestoreEvent): void {
    try {
      void Promise.resolve(deps.onSealedRestore?.(event)).catch(() => undefined);
    } catch {}
  }

  async function tryRestoreEmailOtpEcdsaCapabilityFromSealedRecord(args: {
    accountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    record: ThresholdEcdsaSessionRecord;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
  }): Promise<WarmSessionSealedRestoreResult> {
    const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return 'unavailable';
    if (typeof deps.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord !== 'function') {
      await deps.clearEcdsaEphemeralMaterial({
        nearAccountId: args.accountId,
        chain: args.chain,
        thresholdSessionId,
        source: 'email_otp',
      });
      return 'unavailable';
    }

    const reader = deps.signingSessionSealedStore?.readRecord || readSigningSessionSealedRecord;
    const sealedRecord = await reader(thresholdSessionId).catch(() => null);
    if (!sealedRecord) {
      await deps.clearEcdsaEphemeralMaterial({
        nearAccountId: args.accountId,
        chain: args.chain,
        thresholdSessionId,
        source: 'email_otp',
      });
      return 'unavailable';
    }
    const clearFailedRestoreArtifacts = async (): Promise<void> => {
      await deleteSigningSessionSealedRecordBestEffort(thresholdSessionId);
      await deps.clearEcdsaEphemeralMaterial({
        nearAccountId: args.accountId,
        chain: args.chain,
        thresholdSessionId,
        source: 'email_otp',
      });
    };
    if (
      sealedRecord.authMethod !== 'email_otp' ||
      sealedRecord.secretKind !== 'signing_session_secret32' ||
      sealedRecord.thresholdSessionIds.ecdsa !== thresholdSessionId
    ) {
      await clearFailedRestoreArtifacts();
      return 'unavailable';
    }
    const sealedEd25519SessionId = String(sealedRecord.thresholdSessionIds.ed25519 || '').trim();
    if (sealedEd25519SessionId) {
      const ed25519Record = args.ed25519Record;
      const ed25519WalletSigningSessionId = resolveWalletSigningSessionId(ed25519Record || null);
      if (
        !ed25519Record ||
        ed25519Record.source !== 'email_otp' ||
        ed25519Record.emailOtpAuthContext?.retention !== 'session' ||
        ed25519Record.thresholdSessionId !== sealedEd25519SessionId ||
        ed25519WalletSigningSessionId !== sealedRecord.walletSigningSessionId
      ) {
        await clearFailedRestoreArtifacts();
        return 'unavailable';
      }
    }

    const acquireLease =
      deps.signingSessionSealedStore?.acquireRestoreLease || acquireSigningSessionRestoreLease;
    const releaseLease =
      deps.signingSessionSealedStore?.releaseRestoreLease || releaseSigningSessionRestoreLease;
    emitSealedRestoreEvent({
      accountId: args.accountId,
      chain: args.chain,
      thresholdSessionId,
      walletSigningSessionId: sealedRecord.walletSigningSessionId,
      status: 'started',
    });
    const lease = await acquireLease({ thresholdSessionId }).catch(() => null);
    if (!lease) {
      emitSealedRestoreEvent({
        accountId: args.accountId,
        chain: args.chain,
        thresholdSessionId,
        walletSigningSessionId: sealedRecord.walletSigningSessionId,
        status: 'defer',
      });
      return 'defer';
    }

    try {
      const restored = await deps.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord({
        sealedRecord,
        ecdsaRecord: args.record,
        ...(args.ed25519Record ? { ed25519Record: args.ed25519Record } : {}),
      });
      if (!restored) {
        await clearFailedRestoreArtifacts();
        emitSealedRestoreEvent({
          accountId: args.accountId,
          chain: args.chain,
          thresholdSessionId,
          walletSigningSessionId: sealedRecord.walletSigningSessionId,
          status: 'failed',
        });
        return 'failed';
      }
      emitSealedRestoreEvent({
        accountId: args.accountId,
        chain: args.chain,
        thresholdSessionId,
        walletSigningSessionId: sealedRecord.walletSigningSessionId,
        status: 'restored',
      });
      return 'restored';
    } catch {
      await clearFailedRestoreArtifacts();
      emitSealedRestoreEvent({
        accountId: args.accountId,
        chain: args.chain,
        thresholdSessionId,
        walletSigningSessionId: sealedRecord.walletSigningSessionId,
        status: 'failed',
      });
      return 'failed';
    } finally {
      await releaseLease(lease).catch(() => undefined);
    }
  }

  return {
    shouldAttemptEmailOtpSealedRestore,
    tryRestoreEmailOtpEcdsaCapabilityFromSealedRecord,
  };
}

export type WarmSessionSealedRefreshRestorer = ReturnType<
  typeof createWarmSessionSealedRefreshRestorer
>;
