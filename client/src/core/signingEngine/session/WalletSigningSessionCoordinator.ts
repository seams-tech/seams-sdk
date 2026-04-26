import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type {
  WarmSessionMaterialConsumer,
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../touchConfirm';
import {
  clearStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreSource,
  type ThresholdEd25519SessionRecord,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import {
  deleteSigningSessionSealedRecord,
  updateSigningSessionSealedRecordPolicy,
} from '../api/session/signingSessionSealedStore';
import { readWarmSessionCapabilityRecordsForAccount } from './WarmSessionStore';
import type { ThresholdEcdsaActivationChain } from '../orchestration/thresholdActivation';
import type { WarmSessionPrfClaim } from './warmSessionTypes';
import {
  readWarmSessionClaims,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from './warmSessionReadModel';
import type { SigningOperationIntent } from './signingSessionTypes';

export type SigningSessionLane = {
  curve: 'ed25519' | 'ecdsa';
  chain?: 'near' | 'tempo' | 'evm';
  source: 'passkey' | 'email_otp';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  backingMaterialSessionId: string;
};

type DiscoveredSigningSessionLane = SigningSessionLane & {
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord;
  backing: 'touch_confirm' | 'email_otp_worker';
};

type WalletSigningSessionStatusOverride = {
  nearAccountId: string;
  walletSigningSessionId: string;
  status: SigningSessionStatus;
  thresholdSessionIds: Set<string>;
  updatedAtMs: number;
};

export type WalletSigningSessionConsumeUseArgs = {
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: SigningOperationIntent;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
};

export type WalletSigningSessionCoordinator = {
  getStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
  }): Promise<SigningSessionStatus | null>;
  getLaneClaimsForAccount(
    nearAccountId: AccountId | string,
  ): Promise<Map<string, WarmSessionPrfClaim | null>>;
  consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus>;
  clear(args: { nearAccountId: AccountId | string; walletSigningSessionId: string }): Promise<void>;
};

export type WalletSigningSessionCoordinatorDeps = {
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
  listThresholdEcdsaSessionRecordsForLookup?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => ThresholdEcdsaSessionRecord[];
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  consumeEmailOtpWarmSessionUses?: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  clearEmailOtpWarmSessionMaterial?: (args: { sessionId: string }) => Promise<void>;
  clearThresholdEcdsaSessionRecordForLane?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => void;
  updateSigningSessionSealedRecordPolicy?: typeof updateSigningSessionSealedRecordPolicy;
  deleteSigningSessionSealedRecord?: typeof deleteSigningSessionSealedRecord;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    thresholdSessionId?: string;
    uses?: number;
  }) => void;
};

function normalizeNonEmpty(value: unknown): string {
  return String(value || '').trim();
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

function ecdsaWorkerSessionId(record: ThresholdEcdsaSessionRecord): string {
  if (record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session') {
    return normalizeNonEmpty(record.clientAdditiveShareHandle.sessionId);
  }
  return normalizeNonEmpty(record.thresholdSessionId);
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

function discoverLanesForAccount(
  deps: WalletSigningSessionCoordinatorDeps,
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

  for (const chain of ['evm', 'tempo'] as const) {
    const candidateRecords: ThresholdEcdsaSessionRecord[] = [];
    const addCandidateRecord = (record: ThresholdEcdsaSessionRecord | null | undefined): void => {
      if (!record) return;
      if (record.chain !== chain) return;
      candidateRecords.push(record);
    };
    if (typeof deps.listThresholdEcdsaSessionRecordsForLookup === 'function') {
      try {
        for (const record of deps.listThresholdEcdsaSessionRecordsForLookup({
          nearAccountId,
          chain,
        })) {
          addCandidateRecord(record);
        }
      } catch {}
    }
    addCandidateRecord(records.ecdsa[chain]);

    const seen = new Set<string>();
    for (const record of candidateRecords) {
      const thresholdSessionId = normalizeNonEmpty(record.thresholdSessionId);
      const key = `${chain}:${record.source}:${thresholdSessionId}`;
      if (!thresholdSessionId || seen.has(key)) continue;
      seen.add(key);
      const source = toLaneSource(record);
      addLane(lanes, {
        curve: 'ecdsa',
        chain,
        source,
        thresholdSessionId,
        walletSigningSessionId: resolveWalletSigningSessionId(record),
        backingMaterialSessionId:
          source === 'email_otp'
            ? ecdsaWorkerSessionId(record)
            : normalizeNonEmpty(record.thresholdSessionId),
        backing: source === 'email_otp' ? 'email_otp_worker' : 'touch_confirm',
        record,
      });
    }
  }
  return lanes;
}

function walletScopedClaimsForLanes(args: {
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
    if (applicableOverride) {
      const overrideClaim = claimFromWalletSigningSessionStatusOverride(applicableOverride);
      for (const entry of entries) {
        scoped.set(
          entry.lane.thresholdSessionId,
          overrideClaim ? { ...overrideClaim, sessionId: entry.lane.thresholdSessionId } : null,
        );
      }
      continue;
    }
    const terminal =
      entries.find((entry) => entry.claim?.state === 'expired')?.claim ||
      entries.find((entry) => entry.claim?.state === 'exhausted')?.claim ||
      null;
    const warmClaims = entries
      .map((entry) => entry.claim)
      .filter((claim): claim is WarmSessionPrfClaim & { state: 'warm' } => claim?.state === 'warm');
    const walletRemainingUses = warmClaims.length
      ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.remainingUses) || 0)))
      : undefined;
    const walletExpiresAtMs = warmClaims.length
      ? Math.min(...warmClaims.map((claim) => Math.floor(Number(claim.expiresAtMs) || 0)))
      : undefined;

    for (const entry of entries) {
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
  }
  return scoped;
}

function walletSigningSessionStatusOverrideKey(
  nearAccountId: AccountId | string,
  walletSigningSessionId: string,
): string {
  return `${normalizeNonEmpty(nearAccountId)}:${normalizeNonEmpty(walletSigningSessionId)}`;
}

function rememberWalletSigningSessionStatusOverride(args: {
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

async function readClaimsForLanes(args: {
  deps: WalletSigningSessionCoordinatorDeps;
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

type ConsumeResultEntry = {
  lane: DiscoveredSigningSessionLane;
  result: WarmSessionStatusResult;
  laneIsExplicitTarget: boolean;
};

function statusFromClaim(args: {
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

function statusFromConsumedLanes(args: {
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

function assertConsumeResult(args: {
  result: WarmSessionStatusResult | undefined;
  backing: 'touch_confirm' | 'email_otp_worker';
  required: boolean;
}): void {
  const result = args.result;
  if (!result || result.ok || result.code === 'exhausted') return;
  if (!args.required && result.code === 'not_found') return;
  throw new Error(
    `[WalletSigningSessionCoordinator] ${args.backing} signing-session consume returned ${result.code}`,
  );
}

function statusFromConsumeResults(args: {
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

function resolveStatusAfterConsume(args: {
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

async function syncSealedRefreshPolicyForLanes(args: {
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
  updatePolicy?: typeof updateSigningSessionSealedRecordPolicy;
  deleteRecord?: typeof deleteSigningSessionSealedRecord;
}): Promise<void> {
  const thresholdSessionIds = Array.from(
    new Set(args.lanes.map((lane) => lane.thresholdSessionId).filter(Boolean)),
  );
  if (!thresholdSessionIds.length) return;
  const updatePolicy = args.updatePolicy || updateSigningSessionSealedRecordPolicy;
  const deleteRecord = args.deleteRecord || deleteSigningSessionSealedRecord;
  const remainingUses = Math.floor(Number(args.status.remainingUses) || 0);
  const expiresAtMs = Math.floor(Number(args.status.expiresAtMs) || 0);
  if (args.status.status !== 'active' || remainingUses <= 0 || expiresAtMs <= Date.now()) {
    await Promise.all(
      thresholdSessionIds.map((thresholdSessionId) =>
        deleteRecord(thresholdSessionId).catch(() => undefined),
      ),
    );
    return;
  }
  await Promise.all(
    thresholdSessionIds.map((thresholdSessionId) =>
      updatePolicy({
        thresholdSessionId,
        remainingUses,
        expiresAtMs,
        updatedAtMs: Date.now(),
      }).catch(() => undefined),
    ),
  );
}

export function createWalletSigningSessionCoordinator(
  deps: WalletSigningSessionCoordinatorDeps = {},
): WalletSigningSessionCoordinator {
  const statusOverrides = new Map<string, WalletSigningSessionStatusOverride>();
  const getLanesForWalletSession = (args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
  }): DiscoveredSigningSessionLane[] => {
    const walletSigningSessionId = normalizeNonEmpty(args.walletSigningSessionId);
    return discoverLanesForAccount(deps, args.nearAccountId).filter(
      (lane) => !walletSigningSessionId || lane.walletSigningSessionId === walletSigningSessionId,
    );
  };

  const coordinator: WalletSigningSessionCoordinator = {
    async getLaneClaimsForAccount(
      nearAccountId: AccountId | string,
    ): Promise<Map<string, WarmSessionPrfClaim | null>> {
      const lanes = discoverLanesForAccount(deps, nearAccountId);
      const rawClaims = await readClaimsForLanes({ deps, lanes });
      return walletScopedClaimsForLanes({
        lanes,
        claimsByThresholdSessionId: rawClaims,
        statusOverrides,
      });
    },

    async getStatus(args: {
      nearAccountId: AccountId | string;
      walletSigningSessionId?: string;
      targetBackingMaterialSessionIds?: string[];
      targetThresholdSessionIds?: string[];
    }): Promise<SigningSessionStatus | null> {
      const lanes = getLanesForWalletSession(args);
      if (!lanes.length) return null;
      const walletSigningSessionId =
        normalizeNonEmpty(args.walletSigningSessionId) || lanes[0].walletSigningSessionId;
      const targetBacking = new Set(
        (args.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const targetThreshold = new Set(
        (args.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
      const statusLanes = hasExplicitTarget
        ? lanes.filter(
            (lane) =>
              targetBacking.has(lane.backingMaterialSessionId) ||
              targetThreshold.has(lane.thresholdSessionId),
          )
        : lanes;
      if (hasExplicitTarget && !statusLanes.length) {
        return {
          sessionId: walletSigningSessionId,
          status: 'not_found',
        };
      }
      const rawClaims = await readClaimsForLanes({ deps, lanes: statusLanes });
      const scopedClaims = walletScopedClaimsForLanes({
        lanes: statusLanes,
        claimsByThresholdSessionId: rawClaims,
        statusOverrides,
      });
      const claims = statusLanes
        .map((lane) => scopedClaims.get(lane.thresholdSessionId) || null)
        .filter(Boolean);
      const claim =
        claims.find((candidate) => candidate?.state === 'expired') ||
        claims.find((candidate) => candidate?.state === 'exhausted') ||
        claims.find((candidate) => candidate?.state === 'unavailable') ||
        claims.find((candidate) => candidate?.state === 'warm') ||
        null;
      return statusFromClaim({ walletSigningSessionId, lanes: statusLanes, claim });
    },

    async consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus> {
      const walletSigningSessionId = normalizeNonEmpty(args.walletSigningSessionId);
      if (!walletSigningSessionId) {
        throw new Error('[WalletSigningSessionCoordinator] walletSigningSessionId is required');
      }
      const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
      const alreadyConsumedBacking = new Set(
        (args.alreadyConsumedBackingMaterialSessionIds || [])
          .map(normalizeNonEmpty)
          .filter(Boolean),
      );
      const alreadyConsumedThreshold = new Set(
        (args.alreadyConsumedThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const targetBacking = new Set(
        (args.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const targetThreshold = new Set(
        (args.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const lanes = getLanesForWalletSession({
        nearAccountId: args.nearAccountId,
        walletSigningSessionId,
      });
      if (!lanes.length) {
        throw new Error(
          '[WalletSigningSessionCoordinator] wallet signing-session has no matching signing lanes for account',
        );
      }
      const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
      const hasMatchingTarget =
        !hasExplicitTarget ||
        lanes.some(
          (lane) =>
            targetBacking.has(lane.backingMaterialSessionId) ||
            targetThreshold.has(lane.thresholdSessionId),
        );
      if (!hasMatchingTarget) {
        throw new Error(
          '[WalletSigningSessionCoordinator] wallet signing-session has no matching target signing lane for account',
        );
      }
      const lanesToConsume = lanes;
      const consumedBacking = new Set<string>();
      let skippedAlreadyConsumedBacking = false;
      const consumeResults: ConsumeResultEntry[] = [];
      for (const lane of lanesToConsume) {
        const laneIsExplicitTarget =
          !hasExplicitTarget ||
          targetBacking.has(lane.backingMaterialSessionId) ||
          targetThreshold.has(lane.thresholdSessionId);
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
          const result = await deps.consumeEmailOtpWarmSessionUses?.({
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
          const result = await deps.touchConfirm?.consumeWarmSessionUses?.({
            sessionId: lane.backingMaterialSessionId,
            uses,
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

      const ed25519EmailOtpLane = lanesToConsume.find(
        (lane) => lane.curve === 'ed25519' && lane.source === 'email_otp',
      );
      if (ed25519EmailOtpLane) {
        deps.markThresholdEd25519EmailOtpSessionConsumedForAccount?.({
          nearAccountId: args.nearAccountId,
          thresholdSessionId: ed25519EmailOtpLane.thresholdSessionId,
          uses,
        });
      }

      const status = (await coordinator.getStatus({
        nearAccountId: args.nearAccountId,
        walletSigningSessionId,
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
      // Wallet signing-session budget is shared across Ed25519 and ECDSA lanes.
      // A previous targeted consume only decremented the lane that signed, leaving
      // sibling lanes locally warm after the server-side wallet budget was spent.
      // That made exhausted Passkey Ed25519 signing show a stale confirmation first,
      // then retry into a second confirmation for passkey reauth.
      const resolvedStatus = resolveStatusAfterConsume({
        walletSigningSessionId,
        lanes,
        status,
        consumedStatus,
        skippedAlreadyConsumedBacking,
      });
      // The server-side wallet budget is authoritative, but client status reads
      // still come from per-lane local warm-session material. After a successful
      // spend, remember the wallet-level result here so sibling lanes and UI
      // polling cannot keep showing stale remaining uses until every local lane
      // independently refreshes.
      rememberWalletSigningSessionStatusOverride({
        overrides: statusOverrides,
        nearAccountId: args.nearAccountId,
        walletSigningSessionId,
        lanes,
        status: resolvedStatus,
      });
      await syncSealedRefreshPolicyForLanes({
        lanes,
        status: resolvedStatus,
        updatePolicy: deps.updateSigningSessionSealedRecordPolicy,
        deleteRecord: deps.deleteSigningSessionSealedRecord,
      });
      return resolvedStatus;
    },

    async clear(args: {
      nearAccountId: AccountId | string;
      walletSigningSessionId: string;
    }): Promise<void> {
      const lanes = getLanesForWalletSession(args);
      statusOverrides.delete(
        walletSigningSessionStatusOverrideKey(args.nearAccountId, args.walletSigningSessionId),
      );
      const cleared = new Set<string>();
      let clearEd25519Record = false;
      const ecdsaLanesToClear = new Map<
        string,
        { chain: ThresholdEcdsaActivationChain; source: ThresholdEcdsaSessionStoreSource }
      >();
      await Promise.all(
        lanes.map(async (lane) => {
          if (lane.curve === 'ed25519') clearEd25519Record = true;
          if (lane.curve === 'ecdsa' && (lane.chain === 'evm' || lane.chain === 'tempo')) {
            const source = (lane.record as ThresholdEcdsaSessionRecord).source;
            ecdsaLanesToClear.set(`${lane.chain}:${source}`, {
              chain: lane.chain,
              source,
            });
          }
          if (cleared.has(lane.backingMaterialSessionId)) return;
          cleared.add(lane.backingMaterialSessionId);
          if (lane.backing === 'email_otp_worker') {
            await deps
              .clearEmailOtpWarmSessionMaterial?.({ sessionId: lane.backingMaterialSessionId })
              .catch(() => undefined);
            return;
          }
          await deps.touchConfirm
            ?.clearWarmSessionMaterial?.({ sessionId: lane.backingMaterialSessionId })
            .catch(() => undefined);
        }),
      );
      if (clearEd25519Record) {
        clearStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
      }
      for (const lane of ecdsaLanesToClear.values()) {
        deps.clearThresholdEcdsaSessionRecordForLane?.({
          nearAccountId: args.nearAccountId,
          chain: lane.chain,
          source: lane.source,
        });
      }
    },
  };
  return coordinator;
}
