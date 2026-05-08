import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type {
  WarmSessionMaterialConsumer,
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../../uiConfirm/types';
import {
  clearStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type {
  SigningSessionSealedRecordFilter,
  deleteExactSealedSession,
  updateExactSealedSessionPolicy,
} from '../persistence/sealedSessionStore';
import {
  readWarmSessionCapabilityRecordsForAccount,
  readWarmSessionEd25519RecordByThresholdSessionId,
} from '../warmSigning/store';
import type { WarmSessionPrfClaim } from '../warmSigning/types';
import {
  readWarmSessionClaims,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from '../warmSigning/readModel';
import type { SigningSessionBudgetStatusAuth } from '../signingSession/budget';
import type { SigningSessionReadiness } from '../signingSession/planner';
import {
  thresholdEcdsaChainTargetKey,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type SigningSessionLane = {
  curve: 'ed25519' | 'ecdsa';
  chain?: 'near' | 'tempo' | 'evm';
  chainTarget?: ThresholdEcdsaChainTarget;
  source: 'passkey' | 'email_otp';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  backingMaterialSessionId: string;
};

export type DiscoveredSigningSessionLane = SigningSessionLane & {
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord;
  backing: 'touch_confirm' | 'email_otp_worker';
};

export type WalletSigningSessionStatusOverride = {
  nearAccountId: string;
  walletSigningSessionId: string;
  status: SigningSessionStatus;
  thresholdSessionIds: Set<string>;
  updatedAtMs: number;
};

export type WalletSigningSessionReadinessDeps = {
  touchConfirm?: Partial<
    Pick<
      WarmSessionStatusReader &
        WarmSessionStatusBatchReader &
        WarmSessionMaterialConsumer & {
          clearWarmSessionMaterial(args: { sessionId: string }): Promise<void>;
        },
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'consumeWarmSessionUses'
      | 'clearWarmSessionMaterial'
    >
  >;
  listThresholdEcdsaSessionRecordsForSubject?: (args: {
    subjectId: WalletSubjectId;
  }) => ThresholdEcdsaSessionRecord[];
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  consumeEmailOtpWarmSessionUses?: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  clearEmailOtpWarmSessionMaterial?: (args: { sessionId: string }) => Promise<void>;
  clearThresholdEcdsaSessionRecordForLane?: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => void;
  updateExactSealedSessionPolicy?: typeof updateExactSealedSessionPolicy;
  deleteExactSealedSession?: typeof deleteExactSealedSession;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId?: string;
    uses?: number;
  }) => void;
};

export type ConsumeResultEntry = {
  lane: DiscoveredSigningSessionLane;
  result: WarmSessionStatusResult;
  laneIsExplicitTarget: boolean;
};

export type WalletSigningSessionConsumeUseInput = {
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

export type WalletSigningSessionStatusReader = (args: {
  nearAccountId: AccountId | string;
  walletSigningSessionId?: string;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}) => Promise<SigningSessionStatus | null>;

export type SigningSessionReadinessWithBudget = {
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

export function normalizeNonEmpty(value: unknown): string {
  return String(value || '').trim();
}

export function applyWalletBudgetStatusToSigningSessionReadiness(args: {
  status: SigningSessionReadiness['status'];
  thresholdSessionId: SigningSessionReadiness['thresholdSessionId'];
  expiresAtMs: number;
  remainingUses: number;
  walletBudgetStatus?: SigningSessionStatus | null;
  usesNeeded?: number;
  nowMs?: number;
  missingWhenExpiresAtMissing?: boolean;
}): SigningSessionReadinessWithBudget {
  let status = args.status;
  let expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  let remainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const walletBudgetStatus = args.walletBudgetStatus;
  if (walletBudgetStatus) {
    if (walletBudgetStatus.status === 'not_found') {
      status = 'missing_session';
      remainingUses = 0;
    } else if (walletBudgetStatus.status === 'budget_unknown' && status === 'ready') {
      status = 'budget_unknown';
      remainingUses = 0;
    } else if (walletBudgetStatus.status === 'unavailable') {
      status = 'status_unavailable';
      remainingUses = 0;
    } else if (walletBudgetStatus.status === 'expired') {
      status = 'expired';
      remainingUses = 0;
    } else if (walletBudgetStatus.status === 'exhausted') {
      status = 'exhausted';
      remainingUses = 0;
    } else if (walletBudgetStatus.status === 'active') {
      const budgetRemainingUses = Math.max(
        0,
        Math.floor(Number(walletBudgetStatus.remainingUses) || 0),
      );
      const budgetExpiresAtMs = Math.floor(Number(walletBudgetStatus.expiresAtMs) || 0);
      // Local/session-store counters are availability hints after restore. The
      // wallet budget service is the trusted source for terminal budget state.
      // Same-projection local availability can gate admission, but it must not
      // turn a server-active session into step-up reauth.
      remainingUses = budgetRemainingUses;
      if (budgetExpiresAtMs > 0) expiresAtMs = budgetExpiresAtMs;
      if (status === 'exhausted') {
        status = 'ready';
      }
    }
  }
  const usesNeeded = Math.max(1, Math.floor(Number(args.usesNeeded) || 1));
  if (status === 'ready' && remainingUses < usesNeeded) status = 'exhausted';
  if (status === 'ready' && args.missingWhenExpiresAtMissing && expiresAtMs <= 0) {
    status = 'missing_session';
  }
  if (status === 'ready' && expiresAtMs <= (args.nowMs ?? Date.now())) status = 'expired';
  const readiness: SigningSessionReadiness =
    status === 'ready'
      ? { status: 'ready', thresholdSessionId: args.thresholdSessionId }
      : { status, thresholdSessionId: args.thresholdSessionId };
  return {
    readiness,
    expiresAtMs,
    remainingUses,
  };
}

function resolveWalletSigningSessionId(
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord | null | undefined,
): string {
  return normalizeNonEmpty(record?.walletSigningSessionId);
}

function toLaneSource(
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord,
): 'passkey' | 'email_otp' {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

export function resolveEmailOtpEcdsaWorkerSessionId(record: ThresholdEcdsaSessionRecord): string {
  const thresholdSessionId = normalizeNonEmpty(record.thresholdSessionId);
  if (record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session') {
    const workerSessionId = normalizeNonEmpty(record.clientAdditiveShareHandle.sessionId);
    const ed25519Companion =
      workerSessionId && workerSessionId !== thresholdSessionId
        ? readWarmSessionEd25519RecordByThresholdSessionId(workerSessionId)
        : null;
    if (ed25519Companion?.source === 'email_otp') {
      // A stale cross-curve companion id here causes sealed restore to read the
      // Ed25519 half of the seal as if it were the ECDSA lane.
      console.debug(
        '[SigningSessionCoordinator] ignoring mismatched Email OTP ECDSA worker session id',
        {
          thresholdSessionId,
          workerSessionId,
        },
      );
    } else if (workerSessionId) {
      return workerSessionId;
    }
  }
  return thresholdSessionId;
}

function addLane(
  lanes: DiscoveredSigningSessionLane[],
  lane: DiscoveredSigningSessionLane | null,
): void {
  if (!lane) return;
  if (!lane.thresholdSessionId || !lane.walletSigningSessionId || !lane.backingMaterialSessionId) {
    return;
  }
  lanes.push(lane);
}

export function discoverLanesForAccount(
  deps: WalletSigningSessionReadinessDeps,
  nearAccountId: AccountId | string,
): DiscoveredSigningSessionLane[] {
  const records = readWarmSessionCapabilityRecordsForAccount(nearAccountId);
  const lanes: DiscoveredSigningSessionLane[] = [];
  const ed25519Record = records.ed25519;
  if (ed25519Record) {
    const thresholdSessionId = normalizeNonEmpty(ed25519Record.thresholdSessionId);
    addLane(lanes, {
      curve: 'ed25519',
      chain: 'near',
      source: toLaneSource(ed25519Record),
      thresholdSessionId,
      walletSigningSessionId: resolveWalletSigningSessionId(ed25519Record),
      backingMaterialSessionId: thresholdSessionId,
      backing: 'touch_confirm',
      record: ed25519Record,
    });
  }

  const candidateRecords: ThresholdEcdsaSessionRecord[] =
    deps.listThresholdEcdsaSessionRecordsForSubject?.({
      subjectId: toWalletSubjectId(nearAccountId),
    }) ||
    [records.ecdsa.evm, records.ecdsa.tempo].filter(
      (record): record is ThresholdEcdsaSessionRecord => Boolean(record),
    );
  const seen = new Set<string>();
  for (const record of candidateRecords) {
    const thresholdSessionId = normalizeNonEmpty(record.thresholdSessionId);
    const chainTarget = record.chainTarget;
    const key = [
      record.subjectId,
      thresholdEcdsaChainTargetKey(chainTarget),
      record.source,
      record.ecdsaThresholdKeyId,
      record.walletSigningSessionId,
      thresholdSessionId,
    ].join(':');
    if (!thresholdSessionId || seen.has(key)) continue;
    seen.add(key);
    const source = toLaneSource(record);
    addLane(lanes, {
      curve: 'ecdsa',
      chain: chainTarget.kind,
      chainTarget,
      source,
      thresholdSessionId,
      walletSigningSessionId: resolveWalletSigningSessionId(record),
      backingMaterialSessionId:
        source === 'email_otp'
          ? resolveEmailOtpEcdsaWorkerSessionId(record)
          : normalizeNonEmpty(record.thresholdSessionId),
      backing: source === 'email_otp' ? 'email_otp_worker' : 'touch_confirm',
      record,
    });
  }
  return lanes;
}

export function getLanesForWalletSession(args: {
  deps: WalletSigningSessionReadinessDeps;
  nearAccountId: AccountId | string;
  walletSigningSessionId?: string;
}): DiscoveredSigningSessionLane[] {
  const walletSigningSessionId = normalizeNonEmpty(args.walletSigningSessionId);
  return discoverLanesForAccount(args.deps, args.nearAccountId).filter(
    (lane) => !walletSigningSessionId || lane.walletSigningSessionId === walletSigningSessionId,
  );
}

export function walletScopedClaimsForLanes(args: {
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, WalletSigningSessionStatusOverride>;
}): Map<string, WarmSessionPrfClaim | null> {
  const grouped = new Map<string, DiscoveredSigningSessionLane[]>();
  for (const lane of args.lanes) {
    const group = grouped.get(lane.walletSigningSessionId) || [];
    group.push(lane);
    grouped.set(lane.walletSigningSessionId, group);
  }

  const scoped = new Map<string, WarmSessionPrfClaim | null>();
  for (const group of grouped.values()) {
    const walletSigningSessionId = group[0]?.walletSigningSessionId || '';
    const nearAccountId = group[0]?.record.nearAccountId || '';
    const override = args.statusOverrides?.get(
      walletSigningSessionStatusOverrideKey(nearAccountId, walletSigningSessionId),
    );
    const applicableOverride = override
      ? resolveApplicableWalletSigningSessionStatusOverride({
          override,
          lanes: group,
          claimsByThresholdSessionId: args.claimsByThresholdSessionId,
          statusOverrides: args.statusOverrides,
        })
      : null;
    const entries = group.map((lane) => ({
      lane,
      claim: args.claimsByThresholdSessionId.get(lane.thresholdSessionId) || null,
    }));
    const applyRawScopedClaims = (
      rawEntries: Array<{
        lane: DiscoveredSigningSessionLane;
        claim: WarmSessionPrfClaim | null;
      }>,
    ): void => {
      if (!rawEntries.length) return;
      const terminal =
        rawEntries.find((entry) => entry.claim?.state === 'expired')?.claim ||
        rawEntries.find((entry) => entry.claim?.state === 'exhausted')?.claim ||
        null;
      const warmClaims = rawEntries
        .map((entry) => entry.claim)
        .filter(
          (claim): claim is WarmSessionPrfClaim & { state: 'warm' } => claim?.state === 'warm',
        );
      const walletRemainingUses = warmClaims.length
        ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.remainingUses) || 0)))
        : undefined;
      const walletExpiresAtMs = warmClaims.length
        ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.expiresAtMs) || 0)))
        : undefined;

      for (const entry of rawEntries) {
        if (terminal) {
          scoped.set(entry.lane.thresholdSessionId, {
            ...terminal,
            sessionId: entry.lane.thresholdSessionId,
          });
          continue;
        }
        if (entry.claim?.state === 'warm') {
          scoped.set(entry.lane.thresholdSessionId, {
            state: 'warm',
            sessionId: entry.lane.thresholdSessionId,
            remainingUses: walletRemainingUses ?? entry.claim.remainingUses,
            expiresAtMs: walletExpiresAtMs ?? entry.claim.expiresAtMs,
          });
          continue;
        }
        scoped.set(entry.lane.thresholdSessionId, entry.claim);
      }
    };
    if (applicableOverride) {
      const overrideClaim = claimFromWalletSigningSessionStatusOverride(applicableOverride);
      const overrideEntries = entries.filter((entry) =>
        applicableOverride.thresholdSessionIds.has(normalizeNonEmpty(entry.lane.thresholdSessionId)),
      );
      const rawEntries = entries.filter(
        (entry) =>
          !applicableOverride.thresholdSessionIds.has(
            normalizeNonEmpty(entry.lane.thresholdSessionId),
          ),
      );
      if (overrideEntries.length === entries.length) {
        for (const entry of entries) {
          scoped.set(
            entry.lane.thresholdSessionId,
            overrideClaim ? { ...overrideClaim, sessionId: entry.lane.thresholdSessionId } : null,
          );
        }
        continue;
      }
      for (const entry of overrideEntries) {
        scoped.set(
          entry.lane.thresholdSessionId,
          overrideClaim ? { ...overrideClaim, sessionId: entry.lane.thresholdSessionId } : null,
        );
      }
      applyRawScopedClaims(rawEntries);
      continue;
    }
    applyRawScopedClaims(entries);
  }
  return scoped;
}

export function walletSigningSessionStatusOverrideKey(
  nearAccountId: AccountId | string,
  walletSigningSessionId: string,
): string {
  return `${normalizeNonEmpty(nearAccountId)}:${normalizeNonEmpty(walletSigningSessionId)}`;
}

export function rememberWalletSigningSessionStatusOverride(args: {
  overrides: Map<string, WalletSigningSessionStatusOverride>;
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
}): void {
  const walletSigningSessionId = normalizeNonEmpty(args.walletSigningSessionId);
  if (!walletSigningSessionId) return;
  const now = Date.now();
  args.overrides.set(
    walletSigningSessionStatusOverrideKey(args.nearAccountId, walletSigningSessionId),
    {
      nearAccountId: normalizeNonEmpty(args.nearAccountId),
      walletSigningSessionId,
      status: {
        ...args.status,
        sessionId: walletSigningSessionId,
      },
      thresholdSessionIds: new Set(
        args.lanes.map((lane) => normalizeNonEmpty(lane.thresholdSessionId)).filter(Boolean),
      ),
      updatedAtMs: now,
    },
  );
}

function resolveApplicableWalletSigningSessionStatusOverride(args: {
  override: WalletSigningSessionStatusOverride;
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, WalletSigningSessionStatusOverride>;
}): WalletSigningSessionStatusOverride | null {
  if (!args.lanes.length) return null;
  const freshActiveLane = args.lanes.find((lane) => {
    const thresholdSessionId = normalizeNonEmpty(lane.thresholdSessionId);
    if (args.override.thresholdSessionIds.has(thresholdSessionId)) return false;
    const recordUpdatedAtMs = Math.floor(Number(lane.record.updatedAtMs) || 0);
    if (recordUpdatedAtMs <= args.override.updatedAtMs) return false;
    const claim = args.claimsByThresholdSessionId.get(thresholdSessionId) || null;
    return claim?.state === 'warm';
  });
  if (freshActiveLane) {
    args.statusOverrides?.delete(
      walletSigningSessionStatusOverrideKey(
        freshActiveLane.record.nearAccountId,
        args.override.walletSigningSessionId,
      ),
    );
    return null;
  }
  return args.override;
}

function claimFromWalletSigningSessionStatusOverride(
  override: WalletSigningSessionStatusOverride,
): WarmSessionPrfClaim | null {
  const status = override.status;
  if (status.status === 'active') {
    const remainingUses = Math.max(0, Math.floor(Number(status.remainingUses) || 0));
    const expiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
    if (remainingUses <= 0 || expiresAtMs <= Date.now()) {
      return {
        state: remainingUses <= 0 ? 'exhausted' : 'expired',
        sessionId: override.walletSigningSessionId,
      };
    }
    return {
      state: 'warm',
      sessionId: override.walletSigningSessionId,
      remainingUses,
      expiresAtMs,
    };
  }
  if (status.status === 'expired') {
    return { state: 'expired', sessionId: override.walletSigningSessionId };
  }
  if (status.status === 'exhausted') {
    return { state: 'exhausted', sessionId: override.walletSigningSessionId };
  }
  if (status.status === 'unavailable') {
    return {
      state: 'unavailable',
      sessionId: override.walletSigningSessionId,
      code: status.statusCode || 'wallet_budget_status_override',
    };
  }
  return null;
}

export async function readClaimsForLanes(args: {
  deps: WalletSigningSessionReadinessDeps;
  lanes: DiscoveredSigningSessionLane[];
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const claims = new Map<string, WarmSessionPrfClaim | null>();
  const touchConfirmLanes = args.lanes.filter((lane) => lane.backing === 'touch_confirm');
  const touchConfirmClaims = await readWarmSessionClaims({
    touchConfirm: args.deps.touchConfirm,
    sessionIds: touchConfirmLanes.map((lane) => lane.backingMaterialSessionId),
  });
  for (const lane of touchConfirmLanes) {
    const backingClaim = touchConfirmClaims.get(lane.backingMaterialSessionId) || null;
    claims.set(
      lane.thresholdSessionId,
      backingClaim ? { ...backingClaim, sessionId: lane.thresholdSessionId } : null,
    );
  }

  await Promise.all(
    args.lanes
      .filter((lane) => lane.backing === 'email_otp_worker')
      .map(async (lane) => {
        if (typeof args.deps.getEmailOtpWarmSessionStatus !== 'function') {
          claims.set(lane.thresholdSessionId, null);
          return;
        }
        const status = await args.deps
          .getEmailOtpWarmSessionStatus(lane.backingMaterialSessionId)
          .catch(() => null);
        claims.set(
          lane.thresholdSessionId,
          status
            ? toWarmSessionClaimFromStatusResult({
                sessionId: lane.thresholdSessionId,
                status,
              })
            : null,
        );
      }),
  );

  return claims;
}

export async function readWalletScopedLaneClaimsForAccount(args: {
  deps: WalletSigningSessionReadinessDeps;
  nearAccountId: AccountId | string;
  statusOverrides?: Map<string, WalletSigningSessionStatusOverride>;
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const lanes = discoverLanesForAccount(args.deps, args.nearAccountId);
  const rawClaims = await readClaimsForLanes({ deps: args.deps, lanes });
  return walletScopedClaimsForLanes({
    lanes,
    claimsByThresholdSessionId: rawClaims,
    statusOverrides: args.statusOverrides,
  });
}

export async function readDirectSigningSessionStatusForTargets(args: {
  deps: WalletSigningSessionReadinessDeps;
  walletSigningSessionId: string;
  targetBackingMaterialSessionIds?: Iterable<string>;
  targetThresholdSessionIds?: Iterable<string>;
}): Promise<SigningSessionStatus | null> {
  const walletSigningSessionId = normalizeNonEmpty(args.walletSigningSessionId);
  if (!walletSigningSessionId) return null;
  const targetSessionIds = Array.from(
    new Set(
      [
        ...(args.targetBackingMaterialSessionIds || []),
        ...(args.targetThresholdSessionIds || []),
      ]
        .map(normalizeNonEmpty)
        .filter(Boolean),
    ),
  );
  if (!targetSessionIds.length) return null;

  const claims = await Promise.all(
    targetSessionIds.map(async (sessionId) => {
      const status = await args.deps.touchConfirm
        ?.getWarmSessionStatus?.({ sessionId })
        .catch(() => null);
      return status
        ? toWarmSessionClaimFromStatusResult({ sessionId, status })
        : null;
    }),
  );
  const claim =
    claims.find((candidate) => candidate?.state === 'expired') ||
    claims.find((candidate) => candidate?.state === 'exhausted') ||
    claims.find((candidate) => candidate?.state === 'unavailable') ||
    claims.find((candidate) => candidate?.state === 'warm') ||
    null;
  return toSigningSessionStatus({
    sessionId: walletSigningSessionId,
    claim,
  });
}

export function statusFromClaim(args: {
  walletSigningSessionId: string;
  lanes: DiscoveredSigningSessionLane[];
  claim: WarmSessionPrfClaim | null;
}): SigningSessionStatus {
  const emailOtpLane = args.lanes.find((lane) => lane.source === 'email_otp');
  return toSigningSessionStatus({
    sessionId: args.walletSigningSessionId,
    claim: args.claim,
    authMethod: emailOtpLane ? 'email_otp' : 'passkey',
    retention: emailOtpLane?.record.emailOtpAuthContext?.retention || null,
  });
}

export function statusFromConsumedLanes(args: {
  walletSigningSessionId: string;
  lanes: DiscoveredSigningSessionLane[];
}): SigningSessionStatus {
  const emailOtpLane = args.lanes.find((lane) => lane.source === 'email_otp');
  return {
    sessionId: args.walletSigningSessionId,
    status: 'exhausted',
    remainingUses: 0,
    ...(emailOtpLane ? { authMethod: 'email_otp' as const } : { authMethod: 'passkey' as const }),
    ...(emailOtpLane?.record.emailOtpAuthContext?.retention
      ? { retention: emailOtpLane.record.emailOtpAuthContext.retention }
      : {}),
  };
}

export function assertConsumeResult(args: {
  result: WarmSessionStatusResult | undefined;
  backing: 'touch_confirm' | 'email_otp_worker';
  required: boolean;
}): void {
  const result = args.result;
  if (!result || result.ok || result.code === 'exhausted') return;
  if (!args.required && result.code === 'not_found') return;
  throw new Error(
    `[SigningSessionCoordinator] ${args.backing} signing-session consume returned ${result.code}`,
  );
}

export function statusFromConsumeResults(args: {
  walletSigningSessionId: string;
  lanes: DiscoveredSigningSessionLane[];
  results: ConsumeResultEntry[];
  hasExplicitTarget: boolean;
}): SigningSessionStatus | null {
  const relevantEntries = args.hasExplicitTarget
    ? args.results.filter((entry) => entry.laneIsExplicitTarget)
    : args.results;
  const relevantResults = relevantEntries.map((entry) => entry.result);
  const relevantLanes = relevantEntries.map((entry) => entry.lane);
  const statusLanes = relevantLanes.length ? relevantLanes : args.lanes;
  if (relevantResults.some((result) => !result.ok && result.code === 'exhausted')) {
    return statusFromConsumedLanes({
      walletSigningSessionId: args.walletSigningSessionId,
      lanes: statusLanes,
    });
  }
  const okResults = relevantResults.filter(
    (result): result is Extract<WarmSessionStatusResult, { ok: true }> => result.ok,
  );
  if (!okResults.length) return null;
  const remainingUses = Math.min(
    ...okResults.map((result) => Math.max(0, Math.floor(Number(result.remainingUses) || 0))),
  );
  if (remainingUses <= 0) {
    return statusFromConsumedLanes({
      walletSigningSessionId: args.walletSigningSessionId,
      lanes: statusLanes,
    });
  }
  return statusFromClaim({
    walletSigningSessionId: args.walletSigningSessionId,
    lanes: statusLanes,
    claim: {
      state: 'warm',
      sessionId: args.walletSigningSessionId,
      remainingUses,
      expiresAtMs: Math.min(
        ...okResults.map((result) => Math.floor(Number(result.expiresAtMs) || 0)),
      ),
    },
  });
}

export function resolveStatusAfterConsume(args: {
  walletSigningSessionId: string;
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
  consumedStatus: SigningSessionStatus | null;
  skippedAlreadyConsumedBacking: boolean;
}): SigningSessionStatus {
  if (args.consumedStatus?.status === 'exhausted') return args.consumedStatus;
  if (args.status.status === 'not_found' && args.skippedAlreadyConsumedBacking) {
    return statusFromConsumedLanes(args);
  }
  if (args.consumedStatus?.status === 'active') {
    if (args.status.status !== 'active') return args.consumedStatus;
    const statusRemainingUses = Math.floor(Number(args.status.remainingUses) || 0);
    const consumedRemainingUses = Math.floor(Number(args.consumedStatus.remainingUses) || 0);
    if (consumedRemainingUses < statusRemainingUses) return args.consumedStatus;
  }
  return args.status;
}

export async function consumeWalletSigningSessionUse(args: {
  deps: WalletSigningSessionReadinessDeps;
  statusOverrides: Map<string, WalletSigningSessionStatusOverride>;
  readStatus: WalletSigningSessionStatusReader;
  input: WalletSigningSessionConsumeUseInput;
}): Promise<SigningSessionStatus> {
  const input = args.input;
  const walletSigningSessionId = normalizeNonEmpty(input.walletSigningSessionId);
  if (!walletSigningSessionId) {
    throw new Error('[SigningSessionCoordinator] walletSigningSessionId is required');
  }
  const uses = Math.max(1, Math.floor(Number(input.uses) || 1));
  const alreadyConsumedBacking = new Set(
    (input.alreadyConsumedBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
  );
  const alreadyConsumedThreshold = new Set(
    (input.alreadyConsumedThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
  );
  const targetBacking = new Set(
    (input.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
  );
  const targetThreshold = new Set(
    (input.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
  );
  const lanes = getLanesForWalletSession({
    deps: args.deps,
    nearAccountId: input.nearAccountId,
    walletSigningSessionId,
  });
  const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
  const alreadyConsumedCoversExplicitTarget =
    hasExplicitTarget &&
    Array.from(targetBacking).every((sessionId) => alreadyConsumedBacking.has(sessionId)) &&
    Array.from(targetThreshold).every((sessionId) => alreadyConsumedThreshold.has(sessionId));
  if (!lanes.length && !alreadyConsumedCoversExplicitTarget) {
    throw new Error(
      '[SigningSessionCoordinator] wallet signing-session has no matching signing lanes for account',
    );
  }
  const hasMatchingTarget =
    !hasExplicitTarget ||
    lanes.some(
      (lane) =>
        targetBacking.has(lane.backingMaterialSessionId) ||
        targetThreshold.has(lane.thresholdSessionId),
    );
  if (!hasMatchingTarget && !alreadyConsumedCoversExplicitTarget) {
    throw new Error(
      '[SigningSessionCoordinator] wallet signing-session has no matching target signing lane for account',
    );
  }
  const consumedBacking = new Set<string>();
  let skippedAlreadyConsumedBacking = false;
  const consumeResults: ConsumeResultEntry[] = [];
  for (const lane of lanes) {
    const laneIsExplicitTarget =
      !hasExplicitTarget ||
      targetBacking.has(lane.backingMaterialSessionId) ||
      targetThreshold.has(lane.thresholdSessionId);
    if (!laneIsExplicitTarget) {
      // Explicit spend targets are the operation boundary. Companion lanes may
      // share a wallet session id, but spending them locally here can create a
      // false exhausted state while the server still reports the requested lane
      // as active.
      continue;
    }
    const thresholdAlreadyConsumed = alreadyConsumedThreshold.has(lane.thresholdSessionId);
    const backingAlreadyConsumed =
      thresholdAlreadyConsumed || alreadyConsumedBacking.has(lane.backingMaterialSessionId);
    if (backingAlreadyConsumed) {
      skippedAlreadyConsumedBacking = true;
      consumedBacking.add(lane.backingMaterialSessionId);
      continue;
    }
    if (consumedBacking.has(lane.backingMaterialSessionId)) continue;

    if (lane.backing === 'email_otp_worker') {
      const result = await args.deps.consumeEmailOtpWarmSessionUses?.({
        sessionId: lane.backingMaterialSessionId,
        uses,
      });
      if (result) consumeResults.push({ lane, result, laneIsExplicitTarget });
      assertConsumeResult({
        result,
        backing: lane.backing,
        required: laneIsExplicitTarget,
      });
    } else {
      const result = await args.deps.touchConfirm?.consumeWarmSessionUses?.({
        sessionId: lane.backingMaterialSessionId,
        uses,
        curve: lane.curve,
        ...(lane.curve === 'ecdsa' && lane.chainTarget
          ? { chainTarget: lane.chainTarget }
          : lane.curve === 'ed25519' && lane.chain === 'near'
            ? { chain: lane.chain }
            : {}),
      });
      if (result) consumeResults.push({ lane, result, laneIsExplicitTarget });
      assertConsumeResult({
        result,
        backing: lane.backing,
        required: laneIsExplicitTarget,
      });
    }
    consumedBacking.add(lane.backingMaterialSessionId);
  }

  const consumedOrTargetedLanes = hasExplicitTarget
    ? lanes.filter(
        (lane) =>
          targetBacking.has(lane.backingMaterialSessionId) ||
          targetThreshold.has(lane.thresholdSessionId),
      )
    : lanes;
  const ed25519EmailOtpLane = consumedOrTargetedLanes.find(
    (lane) =>
      lane.curve === 'ed25519' &&
      lane.source === 'email_otp' &&
      !alreadyConsumedThreshold.has(lane.thresholdSessionId),
  );
  if (ed25519EmailOtpLane) {
    args.deps.markThresholdEd25519EmailOtpSessionConsumedForAccount?.({
      nearAccountId: input.nearAccountId,
      thresholdSessionId: ed25519EmailOtpLane.thresholdSessionId,
      uses,
    });
  }

  const status = (await args.readStatus({
    nearAccountId: input.nearAccountId,
    walletSigningSessionId,
    targetBackingMaterialSessionIds: input.targetBackingMaterialSessionIds,
    targetThresholdSessionIds: input.targetThresholdSessionIds,
    trustedStatusAuth: input.trustedStatusAuth,
  })) || {
    sessionId: walletSigningSessionId,
    status: 'not_found',
  };
  const consumedStatus = statusFromConsumeResults({
    walletSigningSessionId,
    lanes,
    results: consumeResults,
    hasExplicitTarget,
  });
  const resolvedStatus = resolveStatusAfterConsume({
    walletSigningSessionId,
    lanes,
    status,
    consumedStatus,
    skippedAlreadyConsumedBacking,
  });
  rememberWalletSigningSessionStatusOverride({
    overrides: args.statusOverrides,
    nearAccountId: input.nearAccountId,
    walletSigningSessionId,
    lanes: consumedOrTargetedLanes,
    status: resolvedStatus,
  });
  await syncSealedRefreshPolicyForLanes({
    lanes: consumedOrTargetedLanes,
    status: resolvedStatus,
    updatePolicy: args.deps.updateExactSealedSessionPolicy,
    deleteRecord: args.deps.deleteExactSealedSession,
  });
  return resolvedStatus;
}

export async function clearWalletSigningSession(args: {
  deps: WalletSigningSessionReadinessDeps;
  statusOverrides: Map<string, WalletSigningSessionStatusOverride>;
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
}): Promise<void> {
  const lanes = getLanesForWalletSession({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    walletSigningSessionId: args.walletSigningSessionId,
  });
  args.statusOverrides.delete(
    walletSigningSessionStatusOverrideKey(args.nearAccountId, args.walletSigningSessionId),
  );
  const cleared = new Set<string>();
  let clearEd25519Record = false;
  const ecdsaLanesToClear = new Map<
    string,
    {
      chainTarget: ThresholdEcdsaChainTarget;
      source: ThresholdEcdsaSessionStoreSource;
    }
  >();
  await Promise.all(
    lanes.map(async (lane) => {
      if (lane.curve === 'ed25519') clearEd25519Record = true;
      if (lane.curve === 'ecdsa' && lane.chainTarget) {
        const source = (lane.record as ThresholdEcdsaSessionRecord).source;
        ecdsaLanesToClear.set(`${thresholdEcdsaChainTargetKey(lane.chainTarget)}:${source}`, {
          chainTarget: lane.chainTarget,
          source,
        });
      }
      if (cleared.has(lane.backingMaterialSessionId)) return;
      cleared.add(lane.backingMaterialSessionId);
      if (lane.backing === 'email_otp_worker') {
        await args.deps
          .clearEmailOtpWarmSessionMaterial?.({ sessionId: lane.backingMaterialSessionId })
          .catch(() => undefined);
        return;
      }
      await args.deps.touchConfirm
        ?.clearWarmSessionMaterial?.({ sessionId: lane.backingMaterialSessionId })
        .catch(() => undefined);
    }),
  );
  if (clearEd25519Record) {
    clearStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  }
  for (const lane of ecdsaLanesToClear.values()) {
    args.deps.clearThresholdEcdsaSessionRecordForLane?.({
      subjectId: toWalletSubjectId(args.nearAccountId),
      chainTarget: lane.chainTarget,
      source: lane.source,
    });
  }
}

export async function syncSealedRefreshPolicyForLanes(args: {
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
  updatePolicy?: typeof updateExactSealedSessionPolicy;
  deleteRecord?: typeof deleteExactSealedSession;
}): Promise<void> {
  const seen = new Set<string>();
  const filterForLane = (
    lane: DiscoveredSigningSessionLane,
  ): SigningSessionSealedRecordFilter | null => {
    if (lane.curve === 'ecdsa') {
      const chainTarget = lane.chainTarget;
      if (!chainTarget) return null;
      return { authMethod: lane.source, curve: 'ecdsa', chainTarget };
    }
    return { authMethod: lane.source, curve: 'ed25519' };
  };
  const sealedLanes = args.lanes
    .filter((lane) => lane.thresholdSessionId)
    .filter((lane) => Boolean(filterForLane(lane)))
    .filter((lane) => {
      const laneTarget =
        lane.curve === 'ecdsa' && lane.chainTarget
          ? thresholdEcdsaChainTargetKey(lane.chainTarget)
          : 'near';
      const key = `${lane.source}:${lane.curve}:${laneTarget}:${lane.thresholdSessionId}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  if (!sealedLanes.length) return;
  const updatePolicy = args.updatePolicy;
  const deleteRecord = args.deleteRecord;
  if (!updatePolicy || !deleteRecord) return;
  const remainingUses = Math.floor(Number(args.status.remainingUses) || 0);
  const expiresAtMs = Math.floor(Number(args.status.expiresAtMs) || 0);
  const nowMs = Date.now();
  const laneExpiresAtMs = Math.min(
    ...sealedLanes
      .map((lane) => Math.floor(Number(lane.record.expiresAtMs) || 0))
      .filter((value) => value > 0),
  );
  const policyExpiresAtMs =
    expiresAtMs > 0
      ? expiresAtMs
      : Number.isFinite(laneExpiresAtMs) && laneExpiresAtMs > 0
        ? laneExpiresAtMs
        : 0;
  if (args.status.status === 'expired' || (expiresAtMs > 0 && expiresAtMs <= nowMs)) {
    await Promise.all(
      sealedLanes.map((lane) =>
        deleteRecord(lane.thresholdSessionId, filterForLane(lane)!).catch(() => undefined),
      ),
    );
    return;
  }
  if (args.status.status !== 'active' || remainingUses <= 0) {
    if (policyExpiresAtMs <= nowMs) return;
    // Exhaustion is a budget state, not a restore-identity lifecycle event.
    // Keep durable lane identity so the next command can select the exact
    // step-up auth lane after page reload or worker-memory loss.
    await Promise.all(
      sealedLanes.map((lane) =>
        updatePolicy({
          thresholdSessionId: lane.thresholdSessionId,
          filter: filterForLane(lane)!,
          remainingUses: 0,
          expiresAtMs: policyExpiresAtMs,
          updatedAtMs: Date.now(),
        }).catch(() => undefined),
      ),
    );
    return;
  }
  await Promise.all(
    sealedLanes.map((lane) =>
      updatePolicy({
        thresholdSessionId: lane.thresholdSessionId,
        filter: filterForLane(lane)!,
        remainingUses,
        expiresAtMs,
        updatedAtMs: Date.now(),
      }).catch(() => undefined),
    ),
  );
}
