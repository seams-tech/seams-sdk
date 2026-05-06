import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { WarmSessionStatusResult } from '../../touchConfirm';
import type {
  ConcreteThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '../signingSession/ecdsaChainTarget';
import {
  readWalletScopedLaneClaimsForAccount as readWalletScopedLaneClaimsForAccountCore,
  resolveEmailOtpEcdsaWorkerSessionId,
} from '../signingSession/readiness';
import {
  readWarmSessionCapabilityRecordsForAccount,
  readWarmSessionEd25519RecordByThresholdSessionId,
  readWarmSessionEcdsaRecordByThresholdSessionId,
} from './store';
import {
  readWarmSessionClaim,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from './readModel';
import type { WarmSessionPrfClaim } from './types';
import type { ThresholdWarmSessionStatusReader, WarmEcdsaSigningSessionStatus } from './types';

type WarmSessionEcdsaPolicyRecordHint = ThresholdEcdsaSessionRecord;

export const THRESHOLD_SESSION_MISSING_ERROR =
  '[chains] Missing threshold signingSessionId; reconnect threshold session before signing';
export const THRESHOLD_SESSION_EXHAUSTED_ERROR =
  '[chains] threshold signingSession is exhausted; reconnect threshold session before signing';
export const THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR =
  '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing';
export const THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR =
  '[chains] threshold signingSession status is unavailable; retry after refreshing the signer runtime';

export function formatThresholdSigningSessionStatusError(code: string): string {
  return `[chains] threshold signingSession is ${code}; reconnect threshold session before signing`;
}

export function formatThresholdSigningSessionAvailabilityError(code?: string): string {
  const suffix = typeof code === 'string' && code.trim() ? ` (${code.trim()})` : '';
  return `${THRESHOLD_SESSION_STATUS_UNAVAILABLE_ERROR}${suffix}`;
}

export function requireThresholdSigningSessionId(sessionIdRaw: unknown): string {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) {
    throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
  }
  return sessionId;
}

export function normalizeUsesNeeded(usesNeededRaw: unknown): number {
  const usesNeeded = Math.floor(Number(usesNeededRaw) || 0);
  return usesNeeded > 0 ? usesNeeded : 1;
}

export type WarmSessionStatusReaderDeps = {
  touchConfirm?: Parameters<typeof readWarmSessionClaim>[0];
  readWalletScopedLaneClaimsForAccount?: typeof readWalletScopedLaneClaimsForAccountCore;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  listConcreteThresholdEcdsaSessionRecordsForSubject?: (args: {
    subjectId: WalletSubjectId;
  }) => ConcreteThresholdEcdsaSessionRecord[];
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
};

export type WarmSessionStatusReader = ThresholdWarmSessionStatusReader & {
  readEcdsaWarmSessionClaimForRecord: (
    record: ThresholdEcdsaSessionRecord,
  ) => Promise<WarmSessionPrfClaim | null>;
  readWalletScopedClaimsForRecords: (
    nearAccountId: AccountId | string,
    records: ReturnType<typeof readWarmSessionCapabilityRecordsForAccount>,
  ) => Promise<{
    ed25519Claim: WarmSessionPrfClaim | null;
    evmClaim: WarmSessionPrfClaim | null;
    tempoClaim: WarmSessionPrfClaim | null;
  }>;
  resolveCurrentEcdsaRecord: (args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => WarmSessionEcdsaPolicyRecordHint | null;
};

export function createWarmSessionStatusReader(
  deps: WarmSessionStatusReaderDeps,
): WarmSessionStatusReader {
  const readWalletScopedLaneClaimsForAccount =
    deps.readWalletScopedLaneClaimsForAccount || readWalletScopedLaneClaimsForAccountCore;

  async function readEcdsaWarmSessionClaimForRecord(
    record: ThresholdEcdsaSessionRecord,
  ): Promise<WarmSessionPrfClaim | null> {
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;
    const workerSessionId =
      record.source === 'email_otp' ? resolveEmailOtpEcdsaWorkerSessionId(record) : '';
    if (workerSessionId) {
      const status = await deps.getEmailOtpWarmSessionStatus(workerSessionId).catch(() => null);
      return status
        ? toWarmSessionClaimFromStatusResult({ sessionId: thresholdSessionId, status })
        : null;
    }
    return await readWarmSessionClaim(deps.touchConfirm, thresholdSessionId);
  }

  async function readWalletScopedClaimsForRecords(
    nearAccountId: AccountId | string,
    records: ReturnType<typeof readWarmSessionCapabilityRecordsForAccount>,
  ): Promise<{
    ed25519Claim: WarmSessionPrfClaim | null;
    evmClaim: WarmSessionPrfClaim | null;
    tempoClaim: WarmSessionPrfClaim | null;
  }> {
    const walletScopedClaims = await readWalletScopedLaneClaimsForAccount({
      deps,
      nearAccountId,
    });
    return {
      ed25519Claim:
        walletScopedClaims.get(String(records.ed25519?.thresholdSessionId || '').trim()) || null,
      evmClaim:
        walletScopedClaims.get(String(records.ecdsa.evm?.thresholdSessionId || '').trim()) || null,
      tempoClaim:
        walletScopedClaims.get(String(records.ecdsa.tempo?.thresholdSessionId || '').trim()) ||
        null,
    };
  }

  function listCurrentEcdsaRecords(args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }): WarmSessionEcdsaPolicyRecordHint[] {
    const chain = args.chainTarget.kind;
    const recordsBySession = new Map<string, WarmSessionEcdsaPolicyRecordHint>();
    if (typeof deps.listConcreteThresholdEcdsaSessionRecordsForSubject === 'function') {
      const subjectId = toWalletSubjectId(args.nearAccountId);
      for (const candidate of deps.listConcreteThresholdEcdsaSessionRecordsForSubject({
        subjectId,
      })) {
        if (!thresholdEcdsaChainTargetsEqual(candidate.chainTarget, args.chainTarget)) continue;
        if (args.source && candidate.source !== args.source) continue;
        const sessionId = String(candidate.thresholdSessionId || '').trim();
        const key = `${thresholdEcdsaChainTargetKey(candidate.chainTarget)}:${candidate.source}:${sessionId}`;
        if (sessionId) recordsBySession.set(key, candidate);
      }
    }
    const fallback = readWarmSessionCapabilityRecordsForAccount(args.nearAccountId).ecdsa[
      chain
    ];
    if (fallback && (!args.source || fallback.source === args.source)) {
      const sessionId = String(fallback.thresholdSessionId || '').trim();
      if (sessionId)
        recordsBySession.set(
          `${thresholdEcdsaChainTargetKey(fallback.chainTarget)}:${fallback.source}:${sessionId}`,
          fallback,
        );
    }
    return [...recordsBySession.values()];
  }

  function resolveCurrentEcdsaRecord(args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }): WarmSessionEcdsaPolicyRecordHint | null {
    return listCurrentEcdsaRecords(args)[0] || null;
  }

  function resolveEcdsaRecordForSigningSession(args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
  }): WarmSessionEcdsaPolicyRecordHint | null {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;

    const directRecord = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    if (
      directRecord?.chainTarget &&
      thresholdEcdsaChainTargetsEqual(directRecord.chainTarget, args.chainTarget)
    ) return directRecord;

    const indexedRecord =
      typeof deps.getThresholdEcdsaSessionRecordByThresholdSessionId === 'function'
        ? deps.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId)
        : null;
    if (
      indexedRecord &&
      indexedRecord.chainTarget &&
      thresholdEcdsaChainTargetsEqual(indexedRecord.chainTarget, args.chainTarget) &&
      String(indexedRecord.nearAccountId || '').trim() === String(args.nearAccountId || '').trim()
    ) {
      return indexedRecord;
    }

    const storedRecord = readWarmSessionCapabilityRecordsForAccount(args.nearAccountId).ecdsa[
      args.chainTarget.kind
    ];
    return String(storedRecord?.thresholdSessionId || '').trim() === thresholdSessionId
      ? storedRecord
      : null;
  }

  async function assertEcdsaSigningSessionReady(args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: unknown;
    usesNeeded?: number;
  }): Promise<Extract<WarmSessionStatusResult, { ok: true }>> {
    const thresholdSessionId = requireThresholdSigningSessionId(args.thresholdSessionId);
    const status = await getEcdsaSigningSessionStatus({
      nearAccountId: args.nearAccountId,
      chainTarget: args.chainTarget,
      thresholdSessionId,
    });
    if (!status || status.status === 'not_found') {
      throw new Error(formatThresholdSigningSessionStatusError('not_found'));
    }
    if (status.status === 'unavailable') {
      throw new Error(formatThresholdSigningSessionAvailabilityError(status.statusCode));
    }
    if (status.status === 'expired') {
      throw new Error(formatThresholdSigningSessionStatusError('expired'));
    }
    if (status.status === 'exhausted') {
      throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
    }

    const remainingUses = Math.floor(Number(status.remainingUses) || 0);
    if (remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
      throw new Error(THRESHOLD_SESSION_EXHAUSTED_ERROR);
    }

    return {
      ok: true,
      remainingUses,
      expiresAtMs: Number(status.expiresAtMs) || Date.now(),
    };
  }

  async function getEd25519SigningSessionStatusForRecord(args: {
    nearAccountId: AccountId | string;
    record: ReturnType<typeof readWarmSessionCapabilityRecordsForAccount>['ed25519'];
  }): Promise<SigningSessionStatus | null> {
    const record = args.record;
    const normalizedThresholdSessionId = String(record?.thresholdSessionId || '').trim();
    if (!normalizedThresholdSessionId) return null;
    const thresholdSessionJwt = String(record?.thresholdSessionJwt || '').trim();
    if (record?.thresholdSessionKind !== 'cookie' && !thresholdSessionJwt) {
      return {
        sessionId: normalizedThresholdSessionId,
        status: 'unavailable',
        statusCode: 'auth_missing',
        authMethod: record?.source === 'email_otp' ? 'email_otp' : 'passkey',
        ...(record?.emailOtpAuthContext?.retention
          ? { retention: record.emailOtpAuthContext.retention }
          : {}),
      };
    }
    const records = readWarmSessionCapabilityRecordsForAccount(toAccountId(args.nearAccountId));
    const { ed25519Claim } = await readWalletScopedClaimsForRecords(args.nearAccountId, records);
    const status = toSigningSessionStatus({
      sessionId: normalizedThresholdSessionId,
      claim: ed25519Claim,
      authMethod: record?.source === 'email_otp' ? 'email_otp' : 'passkey',
      retention: record?.emailOtpAuthContext?.retention || null,
    });
    if (
      (status.status === 'not_found' || status.status === 'exhausted') &&
      record?.source === 'email_otp' &&
      record.emailOtpAuthContext?.retention === 'session' &&
      record.xClientBaseB64u
    ) {
      const remainingUses = Math.floor(Number(record.remainingUses) || 0);
      const expiresAtMs = Math.floor(Number(record.expiresAtMs) || 0);
      // Email OTP Ed25519 material is record-backed, not PRF-claim-backed.
      // Missing/exhausted worker material should not become terminal here:
      // the wallet budget route is the authority for remaining uses and will
      // force step-up when the selected wallet session is actually exhausted.
      return {
        sessionId: normalizedThresholdSessionId,
        status: expiresAtMs > 0 && Date.now() >= expiresAtMs ? 'expired' : 'active',
        authMethod: 'email_otp',
        retention: record.emailOtpAuthContext.retention,
        ...(remainingUses > 0 ? { remainingUses } : {}),
        ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
      };
    }
    return status;
  }

  async function getEd25519SigningSessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    const records = readWarmSessionCapabilityRecordsForAccount(toAccountId(nearAccountId));
    return await getEd25519SigningSessionStatusForRecord({
      nearAccountId,
      record: records.ed25519,
    });
  }

  async function getEd25519SigningSessionStatusForSession(args: {
    nearAccountId: AccountId | string;
    thresholdSessionId: string;
  }): Promise<SigningSessionStatus | null> {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) {
      throw new Error(
        '[WarmSessionStatusReader] thresholdSessionId is required for Ed25519 status',
      );
    }
    const record = readWarmSessionEd25519RecordByThresholdSessionId(thresholdSessionId);
    if (!record || String(record.nearAccountId) !== String(args.nearAccountId)) {
      return {
        sessionId: thresholdSessionId,
        status: 'not_found',
      };
    }
    return await getEd25519SigningSessionStatusForRecord({
      nearAccountId: args.nearAccountId,
      record,
    });
  }

  function toEcdsaSigningSessionStatus(args: {
    record: ThresholdEcdsaSessionRecord;
    claim: WarmSessionPrfClaim | null;
  }): WarmEcdsaSigningSessionStatus {
    return {
      ...toSigningSessionStatus({
        sessionId: String(args.record.thresholdSessionId || '').trim(),
        claim: args.claim,
        authMethod: args.record.source === 'email_otp' ? 'email_otp' : 'passkey',
        retention: args.record.emailOtpAuthContext?.retention || null,
      }),
      chainTarget: args.record.chainTarget,
      source: args.record.source,
      ...(args.record.walletSigningSessionId
        ? { walletSigningSessionId: args.record.walletSigningSessionId }
        : {}),
    };
  }

  async function listEcdsaSigningSessionStatuses(args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<WarmEcdsaSigningSessionStatus[]> {
    const accountId = toAccountId(args.nearAccountId);
    const records = listCurrentEcdsaRecords({ nearAccountId: accountId, chainTarget: args.chainTarget });
    if (!records.length) return [];
    const claimsByThresholdSessionId = await readWalletScopedLaneClaimsForAccount({
      deps,
      nearAccountId: accountId,
    });
    return records.map((record) =>
      toEcdsaSigningSessionStatus({
        record,
        claim:
          claimsByThresholdSessionId.get(String(record.thresholdSessionId || '').trim()) || null,
      }),
    );
  }

  async function getEcdsaSigningSessionStatus(args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
  }): Promise<WarmEcdsaSigningSessionStatus | null> {
    const accountId = toAccountId(args.nearAccountId);
    const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!expectedThresholdSessionId) {
      throw new Error('[WarmSessionStatusReader] thresholdSessionId is required for ECDSA status');
    }
    const record = resolveEcdsaRecordForSigningSession({
      nearAccountId: accountId,
      chainTarget: args.chainTarget,
      thresholdSessionId: expectedThresholdSessionId,
    });
    if (!record) {
      return {
        sessionId: expectedThresholdSessionId,
        status: 'not_found',
        chainTarget: args.chainTarget,
      };
    }
    const claimsByThresholdSessionId = await readWalletScopedLaneClaimsForAccount({
      deps,
      nearAccountId: accountId,
    });
    return toEcdsaSigningSessionStatus({
      record,
      claim:
        claimsByThresholdSessionId.get(String(record.thresholdSessionId || '').trim()) ||
        (await readEcdsaWarmSessionClaimForRecord(record)),
    });
  }

  return {
    assertEcdsaSigningSessionReady,
    getEd25519SigningSessionStatus,
    getEd25519SigningSessionStatusForSession,
    getEcdsaSigningSessionStatus,
    listEcdsaSigningSessionStatuses,
    readEcdsaWarmSessionClaimForRecord,
    readWalletScopedClaimsForRecords,
    resolveCurrentEcdsaRecord,
  };
}
