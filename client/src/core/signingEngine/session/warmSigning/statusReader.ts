import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type { WarmSessionStatusResult } from '../../touchConfirm';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaActivationChain } from '../../orchestration/thresholdActivation';
import { SigningSessionCoordinator } from '../SigningSessionCoordinator';
import { resolveEmailOtpEcdsaWorkerSessionId } from '../signingSession/readiness';
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
import type {
  ThresholdWarmSessionStatusReader,
  WarmEcdsaSigningSessionStatus,
} from './types';

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
  signingSessionCoordinator?: Pick<SigningSessionCoordinator, 'getLaneClaimsForAccount'>;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  listThresholdEcdsaSessionRecordsForLookup?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => WarmSessionEcdsaPolicyRecordHint[];
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
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => WarmSessionEcdsaPolicyRecordHint | null;
};

export function createWarmSessionStatusReader(
  deps: WarmSessionStatusReaderDeps,
): WarmSessionStatusReader {
  const signingSessionCoordinator =
    deps.signingSessionCoordinator ||
    new SigningSessionCoordinator({
      touchConfirm: deps.touchConfirm,
      getEmailOtpWarmSessionStatus: deps.getEmailOtpWarmSessionStatus,
      listThresholdEcdsaSessionRecordsForLookup: deps.listThresholdEcdsaSessionRecordsForLookup,
    });

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
    const walletScopedClaims = await signingSessionCoordinator.getLaneClaimsForAccount(
      nearAccountId,
    );
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
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }): WarmSessionEcdsaPolicyRecordHint[] {
    const recordsBySession = new Map<string, WarmSessionEcdsaPolicyRecordHint>();
    if (typeof deps.listThresholdEcdsaSessionRecordsForLookup === 'function') {
      try {
        for (const candidate of deps.listThresholdEcdsaSessionRecordsForLookup({
            nearAccountId: args.nearAccountId,
            chain: args.chain,
        })) {
          if (args.source && candidate.source !== args.source) continue;
          const sessionId = String(candidate.thresholdSessionId || '').trim();
          const key = `${candidate.chain}:${candidate.source}:${sessionId}`;
          if (sessionId) recordsBySession.set(key, candidate);
        }
      } catch {}
    }
    const fallback = readWarmSessionCapabilityRecordsForAccount(args.nearAccountId).ecdsa[
      args.chain
    ];
    if (fallback && (!args.source || fallback.source === args.source)) {
      const sessionId = String(fallback.thresholdSessionId || '').trim();
      if (sessionId) recordsBySession.set(`${fallback.chain}:${fallback.source}:${sessionId}`, fallback);
    }
    return [...recordsBySession.values()];
  }

  function resolveCurrentEcdsaRecord(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }): WarmSessionEcdsaPolicyRecordHint | null {
    return listCurrentEcdsaRecords(args)[0] || null;
  }

  function resolveEcdsaRecordForSigningSession(args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId: string;
  }): WarmSessionEcdsaPolicyRecordHint | null {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;

    const directRecord = readWarmSessionEcdsaRecordByThresholdSessionId(thresholdSessionId);
    if (directRecord?.chain === args.chain) return directRecord;

    if (typeof deps.listThresholdEcdsaSessionRecordsForLookup === 'function') {
      try {
        const record = deps
          .listThresholdEcdsaSessionRecordsForLookup({
            nearAccountId: args.nearAccountId,
            chain: args.chain,
          })
          .find(
            (candidate) =>
              candidate.chain === args.chain &&
              String(candidate.thresholdSessionId || '').trim() === thresholdSessionId,
          );
        if (record) return record;
      } catch {}
    }

    const storedRecord = readWarmSessionCapabilityRecordsForAccount(args.nearAccountId).ecdsa[
      args.chain
    ];
    return String(storedRecord?.thresholdSessionId || '').trim() === thresholdSessionId
      ? storedRecord
      : null;
  }

  async function assertEcdsaSigningSessionReady(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId: unknown;
    usesNeeded?: number;
  }): Promise<Extract<WarmSessionStatusResult, { ok: true }>> {
    const thresholdSessionId = requireThresholdSigningSessionId(args.thresholdSessionId);
    const status = await getEcdsaSigningSessionStatus({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
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
    return toSigningSessionStatus({
      sessionId: normalizedThresholdSessionId,
      claim: ed25519Claim,
      authMethod: record?.source === 'email_otp' ? 'email_otp' : 'passkey',
      retention: record?.emailOtpAuthContext?.retention || null,
    });
  }

  async function getEd25519SigningSessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    const records = readWarmSessionCapabilityRecordsForAccount(toAccountId(nearAccountId));
    return await getEd25519SigningSessionStatusForRecord({ nearAccountId, record: records.ed25519 });
  }

  async function getEd25519SigningSessionStatusForSession(args: {
    nearAccountId: AccountId | string;
    thresholdSessionId: string;
  }): Promise<SigningSessionStatus | null> {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) {
      throw new Error('[WarmSessionStatusReader] thresholdSessionId is required for Ed25519 status');
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
      chain: args.record.chain,
      source: args.record.source,
      ...(args.record.walletSigningSessionId
        ? { walletSigningSessionId: args.record.walletSigningSessionId }
        : {}),
    };
  }

  async function listEcdsaSigningSessionStatuses(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): Promise<WarmEcdsaSigningSessionStatus[]> {
    const accountId = toAccountId(args.nearAccountId);
    const records = listCurrentEcdsaRecords({ nearAccountId: accountId, chain: args.chain });
    if (!records.length) return [];
    const claimsByThresholdSessionId =
      await signingSessionCoordinator.getLaneClaimsForAccount(accountId);
    return records.map((record) =>
      toEcdsaSigningSessionStatus({
        record,
        claim: claimsByThresholdSessionId.get(String(record.thresholdSessionId || '').trim()) || null,
      }),
    );
  }

  async function getEcdsaSigningSessionStatus(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId: string;
  }): Promise<WarmEcdsaSigningSessionStatus | null> {
    const accountId = toAccountId(args.nearAccountId);
    const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!expectedThresholdSessionId) {
      throw new Error('[WarmSessionStatusReader] thresholdSessionId is required for ECDSA status');
    }
    const record = resolveEcdsaRecordForSigningSession({
      nearAccountId: accountId,
      chain: args.chain,
      thresholdSessionId: expectedThresholdSessionId,
    });
    if (!record) {
      return {
        sessionId: expectedThresholdSessionId,
        status: 'not_found',
        chain: args.chain,
      };
    }
    const claimsByThresholdSessionId =
      await signingSessionCoordinator.getLaneClaimsForAccount(accountId);
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
