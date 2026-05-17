import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../persistence/records';
import {
  selectedEcdsaLane,
  type ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import { buildEvmFamilyEcdsaKeyIdentityFromRecord } from '../identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildDiscoveredLaneForRecord,
  type DiscoveredSigningSessionLane,
  readWalletScopedLaneClaimsForLanes,
  readWalletScopedLaneClaimsForWallet as readWalletScopedLaneClaimsForWalletCore,
  resolveEmailOtpEcdsaWorkerSessionId,
} from '../availability/readiness';
import {
  readWarmSessionCapabilityRecordsForWallet,
  readWarmSessionEd25519RecordByThresholdSessionId,
  readWarmSessionEcdsaRecordByThresholdSessionIdForTarget,
  listWarmSessionEcdsaRecordsForWalletTarget,
} from './store';
import {
  readWarmSessionClaim,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from './readModel';
import {
  buildEcdsaSessionIdentity,
  tryBuildEcdsaSessionIdentity,
} from './ecdsaProvisionPlan';
import type {
  ThresholdWarmSessionStatusReader,
  WarmEcdsaRecordBackedSigningSessionStatus,
  WarmEcdsaSigningSessionStatus,
  WarmSessionPrfClaim,
} from './types';

type WarmSessionEcdsaPolicyRecordHint = ThresholdEcdsaSessionRecord;

function thresholdSessionIdFromEcdsaRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): string | null {
  return record ? tryBuildEcdsaSessionIdentity(record)?.thresholdSessionId || null : null;
}

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
  readWalletScopedLaneClaimsForWallet?: typeof readWalletScopedLaneClaimsForWalletCore;
  readWalletScopedLaneClaimsForLanes?: typeof readWalletScopedLaneClaimsForLanes;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
};

export type WarmSigningStatusReader = ThresholdWarmSessionStatusReader & {
  readEcdsaWarmSessionClaimForRecord: (
    record: ThresholdEcdsaSessionRecord,
  ) => Promise<WarmSessionPrfClaim | null>;
  readWalletScopedClaimsForRecords: (
    records: ReturnType<typeof readWarmSessionCapabilityRecordsForWallet>,
  ) => Promise<{
    ed25519Claim: WarmSessionPrfClaim | null;
    evmClaim: WarmSessionPrfClaim | null;
    tempoClaim: WarmSessionPrfClaim | null;
  }>;
  resolveExactEcdsaRecord: (args: {
    walletId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => WarmSessionEcdsaPolicyRecordHint | null;
};

export function createWarmSessionStatusReader(
  deps: WarmSessionStatusReaderDeps,
): WarmSigningStatusReader {
  const readWalletScopedLaneClaimsForWallet =
    deps.readWalletScopedLaneClaimsForWallet || readWalletScopedLaneClaimsForWalletCore;
  const readWalletScopedLaneClaimsForExactLanes =
    deps.readWalletScopedLaneClaimsForLanes || readWalletScopedLaneClaimsForLanes;

  function buildLanesForRecords(records: Array<ThresholdEcdsaSessionRecord | null>): DiscoveredSigningSessionLane[] {
    return records
      .map((record) => (record ? buildDiscoveredLaneForRecord(record) : null))
      .filter((lane): lane is DiscoveredSigningSessionLane => lane !== null);
  }

  async function readEcdsaWarmSessionClaimForRecord(
    record: ThresholdEcdsaSessionRecord,
  ): Promise<WarmSessionPrfClaim | null> {
    const identity = tryBuildEcdsaSessionIdentity(record);
    if (!identity) return null;
    const workerSessionId =
      record.source === 'email_otp' ? resolveEmailOtpEcdsaWorkerSessionId(record) : '';
    if (workerSessionId) {
      const status = await deps.getEmailOtpWarmSessionStatus(workerSessionId).catch(() => null);
      return status
        ? toWarmSessionClaimFromStatusResult({ sessionId: identity.thresholdSessionId, status })
        : null;
    }
    return await readWarmSessionClaim(deps.touchConfirm, identity.thresholdSessionId);
  }

  async function readWalletScopedClaimsForRecords(
    records: ReturnType<typeof readWarmSessionCapabilityRecordsForWallet>,
  ): Promise<{
    ed25519Claim: WarmSessionPrfClaim | null;
    evmClaim: WarmSessionPrfClaim | null;
    tempoClaim: WarmSessionPrfClaim | null;
  }> {
    const exactLanes = [
      records.ed25519 ? buildDiscoveredLaneForRecord(records.ed25519) : null,
      records.ecdsa.evm ? buildDiscoveredLaneForRecord(records.ecdsa.evm) : null,
      records.ecdsa.tempo ? buildDiscoveredLaneForRecord(records.ecdsa.tempo) : null,
    ].filter((lane): lane is DiscoveredSigningSessionLane => lane !== null);
    const walletScopedClaims = exactLanes.length
      ? await readWalletScopedLaneClaimsForExactLanes({ deps, lanes: exactLanes })
      : new Map<string, WarmSessionPrfClaim | null>();
    return {
      ed25519Claim:
        walletScopedClaims.get(String(records.ed25519?.thresholdSessionId || '').trim()) || null,
      evmClaim:
        walletScopedClaims.get(thresholdSessionIdFromEcdsaRecord(records.ecdsa.evm) || '') ||
        null,
      tempoClaim:
        walletScopedClaims.get(thresholdSessionIdFromEcdsaRecord(records.ecdsa.tempo) || '') ||
        null,
    };
  }

  function listCurrentEcdsaRecords(args: {
    walletId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }): WarmSessionEcdsaPolicyRecordHint[] {
    const recordsBySession = new Map<string, WarmSessionEcdsaPolicyRecordHint>();
    for (const candidate of listWarmSessionEcdsaRecordsForWalletTarget({
      walletId: args.walletId,
      chainTarget: args.chainTarget,
    })) {
      if (!thresholdEcdsaChainTargetsEqual(candidate.chainTarget, args.chainTarget)) continue;
      if (args.source && candidate.source !== args.source) continue;
      const sessionId = thresholdSessionIdFromEcdsaRecord(candidate);
      const key = `${thresholdEcdsaChainTargetKey(candidate.chainTarget)}:${candidate.source}:${sessionId}`;
      if (sessionId) recordsBySession.set(key, candidate);
    }
    return [...recordsBySession.values()];
  }

  function resolveExactEcdsaRecord(args: {
    walletId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }): WarmSessionEcdsaPolicyRecordHint | null {
    const record = resolveEcdsaRecordForSigningSession(args);
    if (!record) return null;
    if (args.source && record.source !== args.source) return null;
    return record;
  }

  function resolveEcdsaRecordForSigningSession(args: {
    walletId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
  }): WarmSessionEcdsaPolicyRecordHint | null {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!thresholdSessionId) return null;

    const directRecord = readWarmSessionEcdsaRecordByThresholdSessionIdForTarget({
      thresholdSessionId,
      chainTarget: args.chainTarget,
    });
    if (directRecord && String(directRecord.walletId || '').trim() === String(args.walletId || '').trim()) {
      return directRecord;
    }

    const indexedRecord =
      typeof deps.getThresholdEcdsaSessionRecordByThresholdSessionId === 'function'
        ? deps.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId)
        : null;
    if (
      indexedRecord &&
      indexedRecord.chainTarget &&
      thresholdEcdsaChainTargetsEqual(indexedRecord.chainTarget, args.chainTarget) &&
        String(indexedRecord.walletId || '').trim() === String(args.walletId || '').trim()
    ) {
      return indexedRecord;
    }
    return null;
  }

  function hasRecordBackedEd25519Status(
    record: ThresholdEd25519SessionRecord | null | undefined,
  ): record is ThresholdEd25519SessionRecord {
    if (!record || !String(record.xClientBaseB64u || '').trim()) return false;
    if (record.source === 'email_otp') {
      return record.emailOtpAuthContext?.retention === 'session';
    }
    return record.thresholdSessionKind === 'cookie';
  }

  function toRecordBackedEd25519Status(
    record: ThresholdEd25519SessionRecord,
    thresholdSessionId: string,
  ): SigningSessionStatus {
    const remainingUses = Math.floor(Number(record.remainingUses) || 0);
    const expiresAtMs = Math.floor(Number(record.expiresAtMs) || 0);
    return {
      sessionId: thresholdSessionId,
      status: expiresAtMs > 0 && Date.now() >= expiresAtMs ? 'expired' : 'active',
      authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
      ...(record.emailOtpAuthContext?.retention
        ? { retention: record.emailOtpAuthContext.retention }
        : {}),
      ...(remainingUses > 0 ? { remainingUses } : {}),
      ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
    };
  }

  async function assertEcdsaSigningSessionReady(args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: unknown;
    usesNeeded?: number;
  }): Promise<Extract<WarmSessionStatusResult, { ok: true }>> {
    const thresholdSessionId = requireThresholdSigningSessionId(args.thresholdSessionId);
    const status = await getEcdsaSigningSessionStatus({
      walletId: args.walletId,
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
    record: ReturnType<typeof readWarmSessionCapabilityRecordsForWallet>['ed25519'];
  }): Promise<SigningSessionStatus | null> {
    const record = args.record;
    const normalizedThresholdSessionId = String(record?.thresholdSessionId || '').trim();
    if (!normalizedThresholdSessionId) return null;
    const thresholdSessionAuthToken = String(record?.thresholdSessionAuthToken || '').trim();
    if (record?.thresholdSessionKind !== 'cookie' && !thresholdSessionAuthToken) {
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
    const records = readWarmSessionCapabilityRecordsForWallet(toAccountId(args.nearAccountId));
    const { ed25519Claim } = await readWalletScopedClaimsForRecords(records);
    const status = toSigningSessionStatus({
      sessionId: normalizedThresholdSessionId,
      claim: ed25519Claim,
      authMethod: record?.source === 'email_otp' ? 'email_otp' : 'passkey',
      retention: record?.emailOtpAuthContext?.retention || null,
    });
    if (
      (status.status === 'not_found' || status.status === 'exhausted') &&
      hasRecordBackedEd25519Status(record)
    ) {
      return toRecordBackedEd25519Status(record, normalizedThresholdSessionId);
    }
    return status;
  }

  async function getEd25519SigningSessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    const records = readWarmSessionCapabilityRecordsForWallet(toAccountId(nearAccountId));
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
  }): WarmEcdsaRecordBackedSigningSessionStatus {
    const identity = buildEcdsaSessionIdentity(args.record);
    const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: args.record,
      rpId: args.record.rpId,
    });
    return {
      ...toSigningSessionStatus({
        sessionId: identity.thresholdSessionId,
        claim: args.claim,
        authMethod: args.record.source === 'email_otp' ? 'email_otp' : 'passkey',
        retention: args.record.emailOtpAuthContext?.retention || null,
      }),
      key,
      lane: selectedEcdsaLane({
        key,
        walletId: args.record.walletId,
        authMethod: args.record.source === 'email_otp' ? 'email_otp' : 'passkey',
        walletSigningSessionId: identity.walletSigningSessionId,
        thresholdSessionId: identity.thresholdSessionId,
        subjectId: args.record.subjectId,
        chainTarget: args.record.chainTarget,
        ecdsaThresholdKeyId: args.record.ecdsaThresholdKeyId,
        signingRootId: args.record.signingRootId,
        signingRootVersion: args.record.signingRootVersion,
      }),
      chainTarget: args.record.chainTarget,
      source: args.record.source,
      walletSigningSessionId: identity.walletSigningSessionId,
    };
  }

  async function listEcdsaSigningSessionStatuses(args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<WarmEcdsaRecordBackedSigningSessionStatus[]> {
    const walletId = toAccountId(args.walletId);
    const records = listCurrentEcdsaRecords({ walletId, chainTarget: args.chainTarget });
    if (!records.length) return [];
    const claimsByThresholdSessionId = await readWalletScopedLaneClaimsForExactLanes({
      deps,
      lanes: buildLanesForRecords(records),
    });
    return records.map((record) =>
      toEcdsaSigningSessionStatus({
        record,
        claim:
          claimsByThresholdSessionId.get(buildEcdsaSessionIdentity(record).thresholdSessionId) ||
          null,
      }),
    );
  }

  async function getEcdsaSigningSessionStatus(args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
  }): Promise<WarmEcdsaSigningSessionStatus | null> {
    const walletId = toAccountId(args.walletId);
    const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (!expectedThresholdSessionId) {
      throw new Error('[WarmSessionStatusReader] thresholdSessionId is required for ECDSA status');
    }
    const record = resolveEcdsaRecordForSigningSession({
      walletId,
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
    const claimsByThresholdSessionId = await readWalletScopedLaneClaimsForExactLanes({
      deps,
      lanes: buildLanesForRecords([record]),
    });
    return toEcdsaSigningSessionStatus({
      record,
      claim:
        claimsByThresholdSessionId.get(buildEcdsaSessionIdentity(record).thresholdSessionId) ||
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
    resolveExactEcdsaRecord,
  };
}
