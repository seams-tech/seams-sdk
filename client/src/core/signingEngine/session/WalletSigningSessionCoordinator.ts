import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type {
  WarmSessionMaterialConsumer,
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../touchConfirm';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionRecord,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import { clearStoredThresholdEd25519SessionRecordForAccount } from '../api/thresholdLifecycle/thresholdSessionStore';
import {
  deleteSigningSessionSealedRecord,
  updateSigningSessionSealedRecordPolicy,
} from '../api/session/signingSessionSealedStore';
import { readWarmSessionCapabilityRecordsForAccount } from './warmSessionStore';
import type { ThresholdEcdsaActivationChain } from '../orchestration/thresholdActivation';
import type { WarmSessionPrfClaim } from './warmSessionTypes';
import {
  readWarmSessionClaims,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from './warmSessionReadModel';

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

const THRESHOLD_ECDSA_SESSION_STORE_SOURCES: readonly ThresholdEcdsaSessionStoreSource[] = [
  'email_otp',
  'login',
  'registration',
  'manual-bootstrap',
];

export type WalletSigningSessionConsumeUseArgs = {
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: 'transaction_sign';
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
};

export type WalletSigningSessionCoordinator = {
  getStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
  }): Promise<SigningSessionStatus | null>;
  getLaneClaimsForAccount(
    nearAccountId: AccountId | string,
  ): Promise<Map<string, WarmSessionPrfClaim | null>>;
  consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus>;
  clear(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId: string;
  }): Promise<void>;
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
  getThresholdEcdsaSessionRecordForSigning?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
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
  return normalizeNonEmpty(record?.walletSigningSessionId || record?.thresholdSessionId);
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
    const addCandidateRecord = (
      record: ThresholdEcdsaSessionRecord | null | undefined,
    ): void => {
      if (!record) return;
      if (record.chain !== chain) return;
      candidateRecords.push(record);
    };
    if (typeof deps.getThresholdEcdsaSessionRecordForSigning === 'function') {
      for (const source of THRESHOLD_ECDSA_SESSION_STORE_SOURCES) {
        try {
          addCandidateRecord(
            deps.getThresholdEcdsaSessionRecordForSigning({
              nearAccountId,
              chain,
              source,
            }),
          );
        } catch {}
      }
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
}): Map<string, WarmSessionPrfClaim | null> {
  const grouped = new Map<string, DiscoveredSigningSessionLane[]>();
  for (const lane of args.lanes) {
    const group = grouped.get(lane.walletSigningSessionId) || [];
    group.push(lane);
    grouped.set(lane.walletSigningSessionId, group);
  }

  const scoped = new Map<string, WarmSessionPrfClaim | null>();
  for (const group of grouped.values()) {
    const entries = group.map((lane) => ({
      lane,
      claim: args.claimsByThresholdSessionId.get(lane.thresholdSessionId) || null,
    }));
    const terminal =
      entries.find((entry) => entry.claim?.state === 'expired')?.claim ||
      entries.find((entry) => entry.claim?.state === 'exhausted')?.claim ||
      null;
    const warmClaims = entries
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
      return walletScopedClaimsForLanes({ lanes, claimsByThresholdSessionId: rawClaims });
    },

    async getStatus(args: {
      nearAccountId: AccountId | string;
      walletSigningSessionId?: string;
    }): Promise<SigningSessionStatus | null> {
      const lanes = getLanesForWalletSession(args);
      if (!lanes.length) return null;
      const walletSigningSessionId =
        normalizeNonEmpty(args.walletSigningSessionId) || lanes[0].walletSigningSessionId;
      const rawClaims = await readClaimsForLanes({ deps, lanes });
      const scopedClaims = walletScopedClaimsForLanes({
        lanes,
        claimsByThresholdSessionId: rawClaims,
      });
      const claims = lanes
        .map((lane) => scopedClaims.get(lane.thresholdSessionId) || null)
        .filter(Boolean);
      const claim =
        claims.find((candidate) => candidate?.state === 'expired') ||
        claims.find((candidate) => candidate?.state === 'exhausted') ||
        claims.find((candidate) => candidate?.state === 'unavailable') ||
        claims.find((candidate) => candidate?.state === 'warm') ||
        null;
      return statusFromClaim({ walletSigningSessionId, lanes, claim });
    },

    async consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus> {
      const walletSigningSessionId = normalizeNonEmpty(args.walletSigningSessionId);
      if (!walletSigningSessionId) {
        throw new Error('[WalletSigningSessionCoordinator] walletSigningSessionId is required');
      }
      const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
      const alreadyConsumedBacking = new Set(
        (args.alreadyConsumedBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const alreadyConsumedThreshold = new Set(
        (args.alreadyConsumedThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const lanes = getLanesForWalletSession({
        nearAccountId: args.nearAccountId,
        walletSigningSessionId,
      });
      const consumedBacking = new Set<string>();
      for (const lane of lanes) {
        const thresholdAlreadyConsumed = alreadyConsumedThreshold.has(lane.thresholdSessionId);
        const backingAlreadyConsumed =
          thresholdAlreadyConsumed || alreadyConsumedBacking.has(lane.backingMaterialSessionId);
        if (backingAlreadyConsumed) {
          consumedBacking.add(lane.backingMaterialSessionId);
          continue;
        }
        if (consumedBacking.has(lane.backingMaterialSessionId)) continue;

        if (lane.backing === 'email_otp_worker') {
          const result = await deps.consumeEmailOtpWarmSessionUses?.({
            sessionId: lane.backingMaterialSessionId,
            uses,
          });
          if (result && !result.ok && result.code === 'worker_error') {
            throw new Error(result.message || 'Failed to consume Email OTP warm-session use');
          }
        } else {
          const result = await deps.touchConfirm?.consumeWarmSessionUses?.({
            sessionId: lane.backingMaterialSessionId,
            uses,
          });
          if (result && !result.ok && result.code === 'worker_error') {
            throw new Error(result.message || 'Failed to consume TouchConfirm warm-session use');
          }
        }
        consumedBacking.add(lane.backingMaterialSessionId);
      }

      const ed25519EmailOtpLane = lanes.find(
        (lane) => lane.curve === 'ed25519' && lane.source === 'email_otp',
      );
      if (ed25519EmailOtpLane) {
        deps.markThresholdEd25519EmailOtpSessionConsumedForAccount?.({
          nearAccountId: args.nearAccountId,
          thresholdSessionId: ed25519EmailOtpLane.thresholdSessionId,
          uses,
        });
      }

      const status =
        (await coordinator.getStatus({
          nearAccountId: args.nearAccountId,
          walletSigningSessionId,
        })) || {
          sessionId: walletSigningSessionId,
          status: 'not_found',
        };
      await syncSealedRefreshPolicyForLanes({
        lanes,
        status,
        updatePolicy: deps.updateSigningSessionSealedRecordPolicy,
        deleteRecord: deps.deleteSigningSessionSealedRecord,
      });
      return status;
    },

    async clear(args: {
      nearAccountId: AccountId | string;
      walletSigningSessionId: string;
    }): Promise<void> {
      const lanes = getLanesForWalletSession(args);
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
