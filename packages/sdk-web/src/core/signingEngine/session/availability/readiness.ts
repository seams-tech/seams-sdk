import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import { classifyThresholdEcdsaSessionRecordRoleLocalState } from '../persistence/ecdsaRoleLocalRecords';
import type { VolatileWarmMaterialPort, WarmSessionStatusResult } from '../../uiConfirm/types';
import {
  clearStoredThresholdEd25519SessionRecordForAccount,
  listStoredThresholdEcdsaSessionRecordsForWallet,
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
  readWarmSessionCapabilityRecordsForWallet,
  readWarmSessionEd25519RecordByThresholdSessionId,
} from '../warmCapabilities/store';
import { parseRouterAbEcdsaHssSigningWalletSessionFromRecord } from '../routerAbSigningWalletSession';
import { createClearVolatileWarmSessionMaterialCommand } from '../warmCapabilities/volatileWarmMaterialCommands';
import { parseVolatileWarmSessionId } from '../warmCapabilities/volatileWarmSessionId';
import type { WarmSessionPrfClaim } from '../warmCapabilities/types';
import {
  normalizeWarmSessionReadPorts,
  readWarmSessionClaim,
  readWarmSessionClaims,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
  type WarmSessionReadPortsInput,
} from '../warmCapabilities/readModel';
import {
  ecdsaWalletBudgetOwner,
  ed25519WalletBudgetOwner,
  isEcdsaLaneBudgetStatusCheck,
  thresholdSessionIdsForBudgetStatusCheck,
  walletBudgetOwnerId,
  walletBudgetOwnerKey,
  type SigningSessionBudgetStatusAuth,
  type SigningSessionBudgetStatusCheck,
  type WalletBudgetOwner,
} from '../budget/budget';
import type { SigningSessionReadiness } from '../planning/planner';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type SigningSessionLane = {
  curve: 'ed25519' | 'ecdsa';
  chain?: 'near' | 'tempo' | 'evm';
  chainTarget?: ThresholdEcdsaChainTarget;
  source: 'passkey' | 'email_otp';
  thresholdSessionId: string;
  signingGrantId: string;
  backingMaterialSessionId: string;
};

export type DiscoveredSigningSessionLane = SigningSessionLane & {
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord;
  backing: 'touch_confirm' | 'email_otp_worker' | 'record_policy';
};

export type SigningGrantStatusOverride = {
  owner: WalletBudgetOwner;
  signingGrantId: string;
  status: SigningSessionStatus;
  thresholdSessionIds: Set<string>;
  updatedAtMs: number;
};

export type SigningGrantReadinessDeps = {
  touchConfirm?: Partial<
    Pick<
      VolatileWarmMaterialPort,
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'consumeWarmSessionUses'
      | 'clearVolatileWarmSessionMaterial'
    >
  >;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  consumeEmailOtpWarmSessionUses?: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  clearEmailOtpWarmSessionMaterial?: (args: { sessionId: string }) => Promise<void>;
  clearThresholdEcdsaSessionRecordForWalletTarget?: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => void;
  updateExactSealedSessionPolicy?: typeof updateExactSealedSessionPolicy;
  deleteExactSealedSession?: typeof deleteExactSealedSession;
  markThresholdEd25519EmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId;
    thresholdSessionId?: string;
    uses?: number;
  }) => void;
};

export type SigningGrantClaimReaderDeps = {
  touchConfirm?: WarmSessionReadPortsInput;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
};

export type ConsumeResultEntry = {
  lane: DiscoveredSigningSessionLane;
  result: WarmSessionStatusResult;
  laneIsExplicitTarget: boolean;
};

export type SigningGrantConsumeUseInput = {
  owner: WalletBudgetOwner;
  signingGrantId: string;
  uses: number;
  budgetStatusCheck: SigningSessionBudgetStatusCheck;
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
};

export type SigningGrantStatusReader = (
  args: SigningSessionBudgetStatusCheck,
) => Promise<SigningSessionStatus | null>;

export type SigningSessionReadinessWithBudget = {
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

export function normalizeNonEmpty(value: unknown): string {
  return String(value || '').trim();
}

export function warmClaimFromRecordPolicy(args: {
  sessionId: string;
  remainingUses: number;
  expiresAtMs: number;
}): WarmSessionPrfClaim {
  const sessionId = normalizeNonEmpty(args.sessionId);
  const remainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (remainingUses <= 0) return { state: 'exhausted', sessionId };
  if (expiresAtMs <= Date.now()) return { state: 'expired', sessionId };
  return {
    state: 'warm',
    sessionId,
    remainingUses,
    expiresAtMs,
  };
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
    status === 'ready' || status === 'exhausted'
      ? { status, thresholdSessionId: args.thresholdSessionId, remainingUses, expiresAtMs }
      : status === 'expired'
        ? { status, thresholdSessionId: args.thresholdSessionId, expiresAtMs }
        : { status, thresholdSessionId: args.thresholdSessionId };
  return {
    readiness,
    expiresAtMs,
    remainingUses,
  };
}

function resolveSigningGrantId(
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord | null | undefined,
): string {
  return normalizeNonEmpty(record?.signingGrantId);
}

function toLaneSource(
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord,
): 'passkey' | 'email_otp' {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function resolveRecordWalletOwnerId(
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord,
): WalletBudgetOwner {
  return 'walletId' in record
    ? ecdsaWalletBudgetOwner(toWalletId(record.walletId))
    : ed25519WalletBudgetOwner(toAccountId(record.nearAccountId));
}

export function resolveEmailOtpEcdsaWorkerSessionId(
  record: ThresholdEcdsaSessionRecord,
): string | null {
  if (record.source !== 'email_otp') return null;
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
      return null;
    } else if (workerSessionId) {
      return workerSessionId;
    }
  }
  return null;
}

function buildEmailOtpEcdsaDiscoveredLaneForRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  chain: 'tempo' | 'evm';
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  signingGrantId: string;
}): DiscoveredSigningSessionLane | null {
  const roleLocalState = classifyThresholdEcdsaSessionRecordRoleLocalState({
    record: args.record,
    nowMs: Date.now(),
  });
  switch (roleLocalState.kind) {
    case 'ready_email_otp_role_local_material_v1':
      switch (roleLocalState.inlineSigningMaterial.kind) {
        case 'email_otp_worker_share': {
          const workerSessionId = resolveEmailOtpEcdsaWorkerSessionId(args.record);
          if (!workerSessionId) return null;
          return {
            curve: 'ecdsa',
            chain: args.chain,
            chainTarget: args.chainTarget,
            source: 'email_otp',
            thresholdSessionId: args.thresholdSessionId,
            signingGrantId: args.signingGrantId,
            backingMaterialSessionId: workerSessionId,
            backing: 'email_otp_worker',
            record: args.record,
          };
        }
        case 'role_local_ready_state_blob':
          return {
            curve: 'ecdsa',
            chain: args.chain,
            chainTarget: args.chainTarget,
            source: 'email_otp',
            thresholdSessionId: args.thresholdSessionId,
            signingGrantId: args.signingGrantId,
            backingMaterialSessionId: args.thresholdSessionId,
            backing: 'record_policy',
            record: args.record,
          };
      }
      roleLocalState.inlineSigningMaterial satisfies never;
      return null;
    case 'reauth_required_role_local_material_v1':
      if (
        roleLocalState.authMethod.kind === 'email_otp' &&
        (roleLocalState.reason === 'expired' || roleLocalState.reason === 'exhausted')
      ) {
        return {
          curve: 'ecdsa',
          chain: args.chain,
          chainTarget: args.chainTarget,
          source: 'email_otp',
          thresholdSessionId: args.thresholdSessionId,
          signingGrantId: args.signingGrantId,
          backingMaterialSessionId: args.thresholdSessionId,
          backing: 'record_policy',
          record: args.record,
        };
      }
      return null;
    case 'ready_passkey_role_local_material_v1':
    case 'cleanup_only_raw_role_local_record_v1':
      return null;
  }
  roleLocalState satisfies never;
  return null;
}

function addLane(
  lanes: DiscoveredSigningSessionLane[],
  lane: DiscoveredSigningSessionLane | null,
): void {
  if (!lane) return;
  if (!lane.thresholdSessionId || !lane.signingGrantId || !lane.backingMaterialSessionId) {
    return;
  }
  lanes.push(lane);
}

export function buildDiscoveredLaneForRecord(
  record: ThresholdEd25519SessionRecord | ThresholdEcdsaSessionRecord,
): DiscoveredSigningSessionLane | null {
  if ('chainTarget' in record) {
    const thresholdSessionId = normalizeNonEmpty(record.thresholdSessionId);
    if (!thresholdSessionId) return null;
    const source = toLaneSource(record);
    const chain = record.chainTarget.kind;
    const chainTarget = record.chainTarget;
    const signingGrantId = resolveSigningGrantId(record);
    if (source === 'email_otp') {
      return buildEmailOtpEcdsaDiscoveredLaneForRecord({
        record,
        chain,
        chainTarget,
        thresholdSessionId,
        signingGrantId,
      });
    }
    if (!parseRouterAbEcdsaHssSigningWalletSessionFromRecord(record).ok) return null;
    return {
      curve: 'ecdsa',
      chain,
      chainTarget,
      source,
      thresholdSessionId,
      signingGrantId,
      backingMaterialSessionId: thresholdSessionId,
      backing: 'record_policy',
      record,
    };
  }

  const thresholdSessionId = normalizeNonEmpty(record.thresholdSessionId);
  if (!thresholdSessionId) return null;
  return {
    curve: 'ed25519',
    chain: 'near',
    source: toLaneSource(record),
    thresholdSessionId,
    signingGrantId: resolveSigningGrantId(record),
    backingMaterialSessionId: thresholdSessionId,
    backing: 'touch_confirm',
    record,
  };
}

export function discoverLanesForWallet(
  deps: SigningGrantReadinessDeps,
  walletId: WalletId,
): DiscoveredSigningSessionLane[] {
  const records = readWarmSessionCapabilityRecordsForWallet(toAccountId(walletId));
  const lanes: DiscoveredSigningSessionLane[] = [];
  const ed25519Record = records.ed25519;
  if (ed25519Record) {
    addLane(lanes, buildDiscoveredLaneForRecord(ed25519Record));
  }

  const candidateRecords = listStoredThresholdEcdsaSessionRecordsForWallet(walletId);
  const seen = new Set<string>();
  for (const record of candidateRecords) {
    const thresholdSessionId = normalizeNonEmpty(record.thresholdSessionId);
    const chainTarget = record.chainTarget;
    const key = [
      String(record.walletId),
      thresholdEcdsaChainTargetKey(chainTarget),
      record.source,
      record.keyHandle,
      record.signingGrantId,
      thresholdSessionId,
    ].join(':');
    if (!thresholdSessionId || seen.has(key)) continue;
    seen.add(key);
    addLane(lanes, buildDiscoveredLaneForRecord(record));
  }
  return lanes;
}

export function getLanesForWalletSession(args: {
  deps: SigningGrantReadinessDeps;
  walletId: WalletId;
  signingGrantId?: string;
}): DiscoveredSigningSessionLane[] {
  const signingGrantId = normalizeNonEmpty(args.signingGrantId);
  return discoverLanesForWallet(args.deps, args.walletId).filter(
    (lane) => !signingGrantId || lane.signingGrantId === signingGrantId,
  );
}

export function walletScopedClaimsForLanes(args: {
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): Map<string, WarmSessionPrfClaim | null> {
  const grouped = new Map<string, DiscoveredSigningSessionLane[]>();
  for (const lane of args.lanes) {
    const group = grouped.get(lane.signingGrantId) || [];
    group.push(lane);
    grouped.set(lane.signingGrantId, group);
  }

  const scoped = new Map<string, WarmSessionPrfClaim | null>();
  for (const group of grouped.values()) {
    const firstLane = group[0];
    if (!firstLane) continue;
    const signingGrantId = firstLane.signingGrantId;
    const owner = resolveRecordWalletOwnerId(firstLane.record);
    const override = args.statusOverrides?.get(
      walletOwnerSigningSessionStatusOverrideKey(owner, signingGrantId),
    );
    const applicableOverride = override
      ? resolveApplicableSigningGrantStatusOverride({
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
      const overrideClaim = claimFromSigningGrantStatusOverride(applicableOverride);
      const overrideEntries = entries.filter((entry) =>
        applicableOverride.thresholdSessionIds.has(
          normalizeNonEmpty(entry.lane.thresholdSessionId),
        ),
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

export function walletOwnerSigningSessionStatusOverrideKey(
  owner: WalletBudgetOwner,
  signingGrantId: string,
): string {
  return `${walletBudgetOwnerKey(owner)}:${normalizeNonEmpty(signingGrantId)}`;
}

function signingGrantStatusOverrideOwners(args: {
  owner: WalletBudgetOwner;
  lanes: DiscoveredSigningSessionLane[];
}): WalletBudgetOwner[] {
  const ownersByKey = new Map<string, WalletBudgetOwner>();
  ownersByKey.set(walletBudgetOwnerKey(args.owner), args.owner);
  for (const lane of args.lanes) {
    const owner = resolveRecordWalletOwnerId(lane.record);
    ownersByKey.set(walletBudgetOwnerKey(owner), owner);
  }
  return [...ownersByKey.values()];
}

export function rememberSigningGrantStatusOverride(args: {
  overrides: Map<string, SigningGrantStatusOverride>;
  owner: WalletBudgetOwner;
  signingGrantId: string;
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
}): void {
  const signingGrantId = normalizeNonEmpty(args.signingGrantId);
  if (!signingGrantId) return;
  const now = Date.now();
  const thresholdSessionIds = new Set(
    args.lanes.map((lane) => normalizeNonEmpty(lane.thresholdSessionId)).filter(Boolean),
  );
  for (const owner of signingGrantStatusOverrideOwners({
    owner: args.owner,
    lanes: args.lanes,
  })) {
    args.overrides.set(
      walletOwnerSigningSessionStatusOverrideKey(owner, signingGrantId),
      {
        owner,
        signingGrantId,
        status: {
          ...args.status,
          sessionId: signingGrantId,
        },
        thresholdSessionIds,
        updatedAtMs: now,
      },
    );
  }
}

function resolveApplicableSigningGrantStatusOverride(args: {
  override: SigningGrantStatusOverride;
  lanes: DiscoveredSigningSessionLane[];
  claimsByThresholdSessionId: Map<string, WarmSessionPrfClaim | null>;
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): SigningGrantStatusOverride | null {
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
    for (const lane of args.lanes) {
      args.statusOverrides?.delete(
        walletOwnerSigningSessionStatusOverrideKey(
          resolveRecordWalletOwnerId(lane.record),
          args.override.signingGrantId,
        ),
      );
    }
    return null;
  }
  return args.override;
}

function claimFromSigningGrantStatusOverride(
  override: SigningGrantStatusOverride,
): WarmSessionPrfClaim | null {
  const status = override.status;
  if (status.status === 'active') {
    const remainingUses = Math.max(0, Math.floor(Number(status.remainingUses) || 0));
    const expiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
    if (remainingUses <= 0 || expiresAtMs <= Date.now()) {
      return {
        state: remainingUses <= 0 ? 'exhausted' : 'expired',
        sessionId: override.signingGrantId,
      };
    }
    return {
      state: 'warm',
      sessionId: override.signingGrantId,
      remainingUses,
      expiresAtMs,
    };
  }
  if (status.status === 'expired') {
    return { state: 'expired', sessionId: override.signingGrantId };
  }
  if (status.status === 'exhausted') {
    return { state: 'exhausted', sessionId: override.signingGrantId };
  }
  if (status.status === 'unavailable') {
    return {
      state: 'unavailable',
      sessionId: override.signingGrantId,
      code: status.statusCode || 'wallet_budget_status_override',
    };
  }
  return null;
}

export async function readClaimsForLanes(args: {
  deps: SigningGrantClaimReaderDeps;
  lanes: DiscoveredSigningSessionLane[];
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const claims = new Map<string, WarmSessionPrfClaim | null>();
  for (const lane of args.lanes.filter((candidate) => candidate.backing === 'record_policy')) {
    const record = lane.record;
    if (!('chainTarget' in record)) {
      claims.set(lane.thresholdSessionId, null);
      continue;
    }
    claims.set(
      lane.thresholdSessionId,
      warmClaimFromRecordPolicy({
        sessionId: lane.thresholdSessionId,
        remainingUses: record.remainingUses,
        expiresAtMs: record.expiresAtMs,
      }),
    );
  }
  const touchConfirm = normalizeWarmSessionReadPorts(args.deps.touchConfirm);
  const touchConfirmLanes = args.lanes.filter((lane) => lane.backing === 'touch_confirm');
  const touchConfirmClaims = await readWarmSessionClaims({
    touchConfirm,
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

export async function readWalletScopedLaneClaimsForWallet(args: {
  deps: SigningGrantReadinessDeps;
  walletId: WalletId;
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const lanes = discoverLanesForWallet(args.deps, args.walletId);
  return readWalletScopedLaneClaimsForLanes({
    deps: args.deps,
    lanes,
    statusOverrides: args.statusOverrides,
  });
}

export async function readWalletScopedLaneClaimsForLanes(args: {
  deps: SigningGrantClaimReaderDeps;
  lanes: DiscoveredSigningSessionLane[];
  statusOverrides?: Map<string, SigningGrantStatusOverride>;
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const rawClaims = await readClaimsForLanes({ deps: args.deps, lanes: args.lanes });
  return walletScopedClaimsForLanes({
    lanes: args.lanes,
    claimsByThresholdSessionId: rawClaims,
    statusOverrides: args.statusOverrides,
  });
}

function targetSessionSetsForBudgetStatusCheck(check: SigningSessionBudgetStatusCheck): {
  backingMaterialSessionIds: Set<string>;
  thresholdSessionIds: Set<string>;
} {
  return {
    backingMaterialSessionIds:
      check.kind === 'backing_material_budget_status_check'
        ? new Set(check.targetBackingMaterialSessionIds.map(normalizeNonEmpty).filter(Boolean))
        : new Set<string>(),
    thresholdSessionIds:
      check.kind === 'threshold_budget_status_check' ||
      check.kind === 'authenticated_threshold_budget_status_check' ||
      isEcdsaLaneBudgetStatusCheck(check)
        ? new Set(
            thresholdSessionIdsForBudgetStatusCheck(check).map(normalizeNonEmpty).filter(Boolean),
          )
        : new Set<string>(),
  };
}

export async function readDirectSigningSessionStatusForTargets(args: {
  deps: SigningGrantReadinessDeps;
  signingGrantId: string;
  targetBackingMaterialSessionIds?: Iterable<string>;
  targetThresholdSessionIds?: Iterable<string>;
}): Promise<SigningSessionStatus | null> {
  const signingGrantId = normalizeNonEmpty(args.signingGrantId);
  if (!signingGrantId) return null;
  const targetSessionIds = Array.from(
    new Set(
      [...(args.targetBackingMaterialSessionIds || []), ...(args.targetThresholdSessionIds || [])]
        .map(normalizeNonEmpty)
        .filter(Boolean),
    ),
  );
  if (!targetSessionIds.length) return null;

  const touchConfirm = normalizeWarmSessionReadPorts(args.deps.touchConfirm);
  const claims = await Promise.all(
    targetSessionIds.map((sessionId) => readWarmSessionClaim(touchConfirm, sessionId)),
  );
  const claim =
    claims.find((candidate) => candidate?.state === 'expired') ||
    claims.find((candidate) => candidate?.state === 'exhausted') ||
    claims.find((candidate) => candidate?.state === 'unavailable') ||
    claims.find((candidate) => candidate?.state === 'warm') ||
    null;
  return toSigningSessionStatus({
    sessionId: signingGrantId,
    claim,
  });
}

export function statusFromClaim(args: {
  signingGrantId: string;
  lanes: DiscoveredSigningSessionLane[];
  claim: WarmSessionPrfClaim | null;
}): SigningSessionStatus {
  const emailOtpLane = args.lanes.find((lane) => lane.source === 'email_otp');
  const emailOtpRetention =
    emailOtpLane?.record.source === 'email_otp'
      ? emailOtpLane.record.emailOtpAuthContext?.retention || null
      : null;
  return toSigningSessionStatus({
    sessionId: args.signingGrantId,
    claim: args.claim,
    authMethod: emailOtpLane ? 'email_otp' : 'passkey',
    retention: emailOtpRetention,
  });
}

export function statusFromConsumedLanes(args: {
  signingGrantId: string;
  lanes: DiscoveredSigningSessionLane[];
}): SigningSessionStatus {
  const emailOtpLane = args.lanes.find((lane) => lane.source === 'email_otp');
  const emailOtpRetention =
    emailOtpLane?.record.source === 'email_otp'
      ? emailOtpLane.record.emailOtpAuthContext?.retention || null
      : null;
  return {
    sessionId: args.signingGrantId,
    status: 'exhausted',
    remainingUses: 0,
    ...(emailOtpLane ? { authMethod: 'email_otp' as const } : { authMethod: 'passkey' as const }),
    ...(emailOtpRetention ? { retention: emailOtpRetention } : {}),
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
  signingGrantId: string;
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
      signingGrantId: args.signingGrantId,
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
      signingGrantId: args.signingGrantId,
      lanes: statusLanes,
    });
  }
  return statusFromClaim({
    signingGrantId: args.signingGrantId,
    lanes: statusLanes,
    claim: {
      state: 'warm',
      sessionId: args.signingGrantId,
      remainingUses,
      expiresAtMs: Math.min(
        ...okResults.map((result) => Math.floor(Number(result.expiresAtMs) || 0)),
      ),
    },
  });
}

function consumeRecordPolicyLane(args: {
  lane: DiscoveredSigningSessionLane;
  uses: number;
  nowMs: number;
  basisStatus: SigningSessionStatus | null;
}): WarmSessionStatusResult {
  if (args.basisStatus?.status === 'exhausted') {
    return {
      ok: false,
      code: 'exhausted',
      message: 'record-policy signing session exhausted',
    };
  }
  if (args.basisStatus?.status === 'expired') {
    return {
      ok: false,
      code: 'expired',
      message: 'record-policy signing session expired',
    };
  }
  const remainingUses = Math.max(
    0,
    Math.floor(Number(args.basisStatus?.remainingUses ?? args.lane.record.remainingUses) || 0),
  );
  const expiresAtMs = Math.floor(
    Number(args.basisStatus?.expiresAtMs ?? args.lane.record.expiresAtMs) || 0,
  );
  if (expiresAtMs <= args.nowMs) {
    return {
      ok: false,
      code: 'expired',
      message: 'record-policy signing session expired',
    };
  }
  if (remainingUses < args.uses) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'record-policy signing session exhausted',
    };
  }
  return {
    ok: true,
    remainingUses: remainingUses - args.uses,
    expiresAtMs,
  };
}

export function resolveStatusAfterConsume(args: {
  signingGrantId: string;
  lanes: DiscoveredSigningSessionLane[];
  status: SigningSessionStatus;
  consumedStatus: SigningSessionStatus | null;
  skippedAlreadyConsumedBacking: boolean;
}): SigningSessionStatus {
  if (args.consumedStatus?.status === 'exhausted') return args.consumedStatus;
  if (args.status.status === 'not_found' && args.skippedAlreadyConsumedBacking) {
    return statusFromConsumedLanes(args);
  }
  const consumedStatus = args.consumedStatus;
  const trustedStatus = args.status;
  if (consumedStatus?.status === 'active') {
    if (trustedStatus.status !== 'active') return consumedStatus;
    const projectedConsumedStatus = statusWithTrustedBudgetProjection({
      consumedStatus,
      trustedStatus,
    });
    const trustedRemainingUses = Math.floor(Number(trustedStatus.remainingUses) || 0);
    const consumedRemainingUses = Math.floor(Number(projectedConsumedStatus.remainingUses) || 0);
    if (consumedRemainingUses < trustedRemainingUses) return projectedConsumedStatus;
  }
  return trustedStatus;
}

function statusWithTrustedBudgetProjection(args: {
  consumedStatus: SigningSessionStatus;
  trustedStatus: SigningSessionStatus;
}): SigningSessionStatus {
  const projectionVersion = String(args.trustedStatus.projectionVersion || '').trim();
  return projectionVersion ? { ...args.consumedStatus, projectionVersion } : args.consumedStatus;
}

export async function consumeSigningGrantUse(args: {
  deps: SigningGrantReadinessDeps;
  statusOverrides: Map<string, SigningGrantStatusOverride>;
  readStatus: SigningGrantStatusReader;
  input: SigningGrantConsumeUseInput;
}): Promise<SigningSessionStatus> {
  const input = args.input;
  const walletId = toWalletId(walletBudgetOwnerId(input.owner));
  const signingGrantId = normalizeNonEmpty(input.signingGrantId);
  if (!signingGrantId) {
    throw new Error('[SigningSessionCoordinator] signingGrantId is required');
  }
  const uses = Math.max(1, Math.floor(Number(input.uses) || 1));
  const alreadyConsumedBacking = new Set(
    (input.alreadyConsumedBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
  );
  const alreadyConsumedThreshold = new Set(
    (input.alreadyConsumedThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
  );
  const budgetTargets = targetSessionSetsForBudgetStatusCheck(input.budgetStatusCheck);
  const targetBacking = budgetTargets.backingMaterialSessionIds;
  const targetThreshold = budgetTargets.thresholdSessionIds;
  const lanes = getLanesForWalletSession({
    deps: args.deps,
    walletId,
    signingGrantId,
  });
  const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
  const alreadyConsumedCoversExplicitTarget =
    hasExplicitTarget &&
    Array.from(targetBacking).every((sessionId) => alreadyConsumedBacking.has(sessionId)) &&
    Array.from(targetThreshold).every((sessionId) => alreadyConsumedThreshold.has(sessionId));
  if (!lanes.length && !alreadyConsumedCoversExplicitTarget) {
    throw new Error(
      '[SigningSessionCoordinator] wallet signing-session has no matching signing lanes for wallet',
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
      '[SigningSessionCoordinator] wallet signing-session has no matching target signing lane for wallet',
    );
  }
  const consumedBacking = new Set<string>();
  let skippedAlreadyConsumedBacking = false;
  let status: SigningSessionStatus | null = null;
  let statusRead = false;
  const consumeResults: ConsumeResultEntry[] = [];
  for (const lane of lanes) {
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

    switch (lane.backing) {
      case 'email_otp_worker': {
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
        break;
      }
      case 'touch_confirm': {
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
        break;
      }
      case 'record_policy':
        if (!statusRead) {
          status = (await args.readStatus(input.budgetStatusCheck)) || null;
          statusRead = true;
        }
        consumeResults.push({
          lane,
          result: consumeRecordPolicyLane({
            lane,
            uses,
            nowMs: Date.now(),
            basisStatus: status,
          }),
          laneIsExplicitTarget,
        });
        break;
    }
    consumedBacking.add(lane.backingMaterialSessionId);
  }

  const consumedOrTargetedLanes = lanes;
  const ed25519EmailOtpLane = consumedOrTargetedLanes.find(
    (lane) =>
      lane.curve === 'ed25519' &&
      lane.source === 'email_otp' &&
      !alreadyConsumedThreshold.has(lane.thresholdSessionId),
  );
  if (ed25519EmailOtpLane && input.owner.curve === 'ed25519') {
    args.deps.markThresholdEd25519EmailOtpSessionConsumedForAccount?.({
      nearAccountId: input.owner.accountId,
      thresholdSessionId: ed25519EmailOtpLane.thresholdSessionId,
      uses,
    });
  }

  if (!statusRead) {
    status = await args.readStatus(input.budgetStatusCheck);
    statusRead = true;
  }
  const trustedStatus = status || {
    sessionId: signingGrantId,
    status: 'not_found' as const,
  };
  const consumedStatus = statusFromConsumeResults({
    signingGrantId,
    lanes,
    results: consumeResults,
    hasExplicitTarget,
  });
  const resolvedStatus = resolveStatusAfterConsume({
    signingGrantId,
    lanes,
    status: trustedStatus,
    consumedStatus,
    skippedAlreadyConsumedBacking,
  });
  rememberSigningGrantStatusOverride({
    overrides: args.statusOverrides,
    owner: input.owner,
    signingGrantId,
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

export async function clearSigningGrant(args: {
  deps: SigningGrantReadinessDeps;
  statusOverrides: Map<string, SigningGrantStatusOverride>;
  walletId: WalletId;
  signingGrantId: string;
}): Promise<void> {
  const lanes = getLanesForWalletSession({
    deps: args.deps,
    walletId: args.walletId,
    signingGrantId: args.signingGrantId,
  });
  args.statusOverrides.delete(
    walletOwnerSigningSessionStatusOverrideKey(
      ecdsaWalletBudgetOwner(args.walletId),
      args.signingGrantId,
    ),
  );
  args.statusOverrides.delete(
    walletOwnerSigningSessionStatusOverrideKey(
      ed25519WalletBudgetOwner(toAccountId(args.walletId)),
      args.signingGrantId,
    ),
  );
  const cleared = new Set<string>();
  let clearEd25519Record = false;
  const ecdsaLanesToClear = new Map<
    string,
    {
      walletId: AccountId;
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
          walletId: (lane.record as ThresholdEcdsaSessionRecord).walletId,
          chainTarget: lane.chainTarget,
          source,
        });
      }
      if (cleared.has(lane.backingMaterialSessionId)) return;
      cleared.add(lane.backingMaterialSessionId);
      if (lane.backing === 'record_policy') return;
      if (lane.backing === 'email_otp_worker') {
        await args.deps
          .clearEmailOtpWarmSessionMaterial?.({ sessionId: lane.backingMaterialSessionId })
          .catch(() => undefined);
        return;
      }
      const volatileSessionId = parseVolatileWarmSessionId(lane.backingMaterialSessionId);
      if (!volatileSessionId) return;
      await args.deps.touchConfirm
        ?.clearVolatileWarmSessionMaterial?.(
          createClearVolatileWarmSessionMaterialCommand(volatileSessionId),
        )
        .catch(() => undefined);
    }),
  );
  if (clearEd25519Record) {
    clearStoredThresholdEd25519SessionRecordForAccount(args.walletId);
  }
  for (const lane of ecdsaLanesToClear.values()) {
    args.deps.clearThresholdEcdsaSessionRecordForWalletTarget?.({
      walletId: toWalletId(lane.walletId),
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
        deleteRecord(lane.thresholdSessionId, filterForLane(lane)!, {
          deleteResolvedIdentity: false,
        }).catch(() => undefined),
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
