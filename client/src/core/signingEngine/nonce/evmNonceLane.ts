import type { EvmNonceChain, NonceLaneStatus } from '@/core/rpcClients/evm/nonceBackend';
import {
  EvmNonceOutcomeReason,
  NonceDurableLeaseState,
  type EvmNonceLane,
  type NonceLease,
} from './nonceTypes';
import { nonceLaneNetworkKey } from './nonceLaneKeys';
import { maxBigint, minBigint, normalizeBigint } from './nonceUtils';

export type EvmNonceLaneState = {
  chainNonce: bigint | null;
  nextCandidate: bigint | null;
  inFlight: Map<string, EvmInFlightNonceRecord>;
  lastRefreshMs: number | null;
  inflightRefresh: Promise<bigint> | null;
};

export type EvmInFlightNonceRecord = {
  nonce: bigint;
  txHash?: `0x${string}`;
  status: 'accepted' | 'replaced';
  acceptedAtMs: number;
  updatedAtMs: number;
};

export function createEvmNonceLaneState(): EvmNonceLaneState {
  return {
    chainNonce: null,
    nextCandidate: null,
    inFlight: new Map<string, EvmInFlightNonceRecord>(),
    lastRefreshMs: null,
    inflightRefresh: null,
  };
}

export function getOrCreateEvmNonceLaneState(
  states: Map<string, EvmNonceLaneState>,
  laneKey: string,
): EvmNonceLaneState {
  const existing = states.get(laneKey);
  if (existing) return existing;
  const created = createEvmNonceLaneState();
  states.set(laneKey, created);
  return created;
}

export function indexEvmNonceLaneBySubject(input: {
  accountLaneKeys: Map<string, Set<string>>;
  lane: EvmNonceLane;
  laneKey: string;
}): void {
  const accountId = String(input.lane.subjectId || '').trim();
  if (!accountId) return;
  const keys = input.accountLaneKeys.get(accountId);
  if (!keys) {
    input.accountLaneKeys.set(accountId, new Set<string>([input.laneKey]));
    return;
  }
  keys.add(input.laneKey);
}

export async function refreshEvmLaneFromChainLocked(input: {
  lane: EvmNonceLane;
  state: EvmNonceLaneState;
  nowMs: number;
  fetchChainNonce: (lane: EvmNonceLane) => Promise<bigint>;
  readActiveLeaseNonces: (input?: {
    chainNextNonce?: bigint;
    excludeLeaseId?: string;
    lane?: EvmNonceLane;
  }) => Promise<Set<string>>;
}): Promise<bigint> {
  const { state } = input;
  if (state.inflightRefresh) {
    return await state.inflightRefresh;
  }
  const refreshTask = (async (): Promise<bigint> => {
    const chainNextNonceRaw = await input.fetchChainNonce(input.lane);
    const chainNextNonce = chainNextNonceRaw >= 0n ? chainNextNonceRaw : 0n;
    const activeLeaseNonces = await input.readActiveLeaseNonces({
      chainNextNonce,
      lane: input.lane,
    });

    let highestActiveLease = 0n;
    for (const nonce of activeLeaseNonces) {
      const value = BigInt(nonce);
      if (value > highestActiveLease) highestActiveLease = value;
    }

    let highestInFlight = 0n;
    const prunedInFlight = new Map<string, EvmInFlightNonceRecord>();
    for (const [key, record] of state.inFlight.entries()) {
      if (record.nonce < chainNextNonce) continue;
      prunedInFlight.set(key, record);
      if (record.nonce > highestInFlight) highestInFlight = record.nonce;
    }
    state.inFlight = prunedInFlight;

    const hasOutstandingLocalNonce = activeLeaseNonces.size > 0 || prunedInFlight.size > 0;
    const nextFromCurrent = hasOutstandingLocalNonce ? state.nextCandidate || 0n : 0n;
    const nextFromActiveLease = highestActiveLease > 0n ? highestActiveLease + 1n : 0n;
    const nextFromInFlight = highestInFlight > 0n ? highestInFlight + 1n : 0n;
    state.nextCandidate = maxBigint(
      0n,
      chainNextNonce,
      nextFromCurrent,
      nextFromActiveLease,
      nextFromInFlight,
    );
    state.chainNonce = chainNextNonce;
    state.lastRefreshMs = input.nowMs;
    return chainNextNonce;
  })();

  state.inflightRefresh = refreshTask;
  try {
    return await refreshTask;
  } finally {
    if (state.inflightRefresh === refreshTask) {
      state.inflightRefresh = null;
    }
  }
}

export async function shouldRefreshEvmLane(input: {
  state: EvmNonceLaneState;
  lane: EvmNonceLane;
  nowMs: number;
  refreshTtlMs: number;
  readActiveLeaseNonces: (input?: { lane?: EvmNonceLane }) => Promise<Set<string>>;
}): Promise<boolean> {
  if (input.state.nextCandidate == null) return true;
  if (input.state.lastRefreshMs == null) return true;
  if (input.state.inFlight.size > 0) return true;
  if ((await input.readActiveLeaseNonces({ lane: input.lane })).size > 0) return false;
  return input.nowMs - input.state.lastRefreshMs >= input.refreshTtlMs;
}

export async function releaseEvmNonceReservationState(input: {
  lease: NonceLease & { lane: EvmNonceLane };
  state?: EvmNonceLaneState;
  removeCoordinationLease: (lease: NonceLease) => Promise<void>;
  readActiveLeaseNonces: (input?: {
    excludeLeaseId?: string;
    lane?: EvmNonceLane;
  }) => Promise<Set<string>>;
}): Promise<void> {
  await input.removeCoordinationLease(input.lease);
  if (!input.state) return;
  const nonce = normalizeBigint(input.lease.nonce, 'nonce');
  input.state.inFlight.delete(nonce.toString());
  const hasOtherActiveLease =
    (
      await input.readActiveLeaseNonces({
        excludeLeaseId: input.lease.leaseId,
        lane: input.lease.lane,
      })
    ).size > 0;
  if (!hasOtherActiveLease && input.state.inFlight.size === 0) {
    input.state.lastRefreshMs = null;
  }
}

export async function markEvmBroadcastAcceptedState(input: {
  lease: NonceLease & { lane: EvmNonceLane };
  state: EvmNonceLaneState;
  txHash?: string;
  nowMs: number;
  staleInFlightThresholdMs: number;
  persistCoordinationLease: (
    lease: NonceLease,
    state: typeof NonceDurableLeaseState.BroadcastAccepted,
    expiresAtMs: number,
  ) => Promise<void>;
}): Promise<void> {
  const nonce = normalizeBigint(input.lease.nonce, 'nonce');
  input.state.inFlight.set(nonce.toString(), {
    nonce,
    ...(input.txHash ? { txHash: input.txHash as `0x${string}` } : {}),
    status: 'accepted',
    acceptedAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  });
  const minNext = nonce + 1n;
  if (input.state.nextCandidate == null || input.state.nextCandidate < minNext) {
    input.state.nextCandidate = minNext;
  }
  await input.persistCoordinationLease(
    input.lease,
    NonceDurableLeaseState.BroadcastAccepted,
    input.nowMs + input.staleInFlightThresholdMs,
  );
}

export async function markEvmFinalizedState(input: {
  lease: NonceLease & { lane: EvmNonceLane };
  state: EvmNonceLaneState;
  nowMs: number;
  removeCoordinationLease: (lease: NonceLease) => Promise<void>;
}): Promise<void> {
  const nonce = normalizeBigint(input.lease.nonce, 'nonce');
  input.state.inFlight.delete(nonce.toString());
  const minNext = nonce + 1n;
  input.state.chainNonce =
    input.state.chainNonce == null ? minNext : maxBigint(input.state.chainNonce, minNext);
  if (input.state.nextCandidate == null || input.state.nextCandidate < minNext) {
    input.state.nextCandidate = minNext;
  }
  input.state.lastRefreshMs = input.nowMs;
  await input.removeCoordinationLease(input.lease);
}

export async function markEvmDroppedOrReplacedState(input: {
  lease: NonceLease & { lane: EvmNonceLane };
  state: EvmNonceLaneState;
  outcome: { reason: EvmNonceOutcomeReason; txHash?: string };
  nowMs: number;
  removeCoordinationLease: (lease: NonceLease) => Promise<void>;
}): Promise<void> {
  const nonce = normalizeBigint(input.lease.nonce, 'nonce');
  if (input.outcome.reason === EvmNonceOutcomeReason.Dropped) {
    input.state.inFlight.delete(nonce.toString());
    if (input.state.chainNonce == null || input.state.chainNonce <= nonce) {
      input.state.nextCandidate =
        input.state.nextCandidate == null ? nonce : minBigint(input.state.nextCandidate, nonce);
    }
  } else {
    const previous = input.state.inFlight.get(nonce.toString());
    input.state.inFlight.set(nonce.toString(), {
      nonce,
      ...(input.outcome.txHash
        ? { txHash: input.outcome.txHash as `0x${string}` }
        : previous?.txHash
          ? { txHash: previous.txHash }
          : {}),
      status: 'replaced',
      acceptedAtMs: previous?.acceptedAtMs ?? input.nowMs,
      updatedAtMs: input.nowMs,
    });
  }
  input.state.lastRefreshMs = null;
  await input.removeCoordinationLease(input.lease);
}

export async function reconcileEvmLaneState(input: {
  lane: EvmNonceLane;
  state: EvmNonceLaneState;
  nowMs: number;
  staleInFlightThresholdMs: number;
  refreshFromChain: (lane: EvmNonceLane, state: EvmNonceLaneState) => Promise<bigint>;
}): Promise<NonceLaneStatus> {
  const chainNextNonce = await input.refreshFromChain(input.lane, input.state);
  const unresolvedInFlightNonces = Array.from(input.state.inFlight.values())
    .map((entry) => entry.nonce)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const blockedState = readBlockedEvmInFlight({
    state: input.state,
    nowMs: input.nowMs,
    staleInFlightThresholdMs: input.staleInFlightThresholdMs,
  });
  return {
    chainNextNonce,
    unresolvedInFlightNonces,
    blocked: !!blockedState,
    ...(blockedState ? { blockedNonce: blockedState.blockedNonce } : {}),
  };
}

export function readBlockedEvmInFlight(input: {
  state: EvmNonceLaneState;
  nowMs: number;
  staleInFlightThresholdMs: number;
}): { blockedNonce: bigint; ageMs: number } | null {
  const { state } = input;
  if (state.inFlight.size === 0) return null;
  if (state.chainNonce == null) return null;
  let oldestNonce: bigint | null = null;
  let oldestUpdatedAtMs: number | null = null;
  for (const record of state.inFlight.values()) {
    if (oldestNonce == null || record.nonce < oldestNonce) {
      oldestNonce = record.nonce;
      oldestUpdatedAtMs = record.updatedAtMs;
    }
  }
  if (oldestNonce == null || oldestUpdatedAtMs == null) return null;
  if (state.chainNonce > oldestNonce) return null;
  const ageMs = Math.max(0, input.nowMs - oldestUpdatedAtMs);
  if (ageMs < input.staleInFlightThresholdMs) return null;
  return { blockedNonce: oldestNonce, ageMs };
}

export function createEvmNonceLaneBlockedError(args: {
  lane: EvmNonceLane;
  blockedNonce: bigint;
  ageMs: number;
}): Error & {
  code: 'nonce_lane_blocked';
  retryable: true;
  details: {
    chain: EvmNonceChain;
    networkKey: string;
    chainId: number;
    blockedNonce: string;
    ageMs: number;
  };
} {
  const error = new Error(
    `[NonceCoordinator] nonce lane blocked on ${nonceLaneNetworkKey(args.lane)} (nonce=${args.blockedNonce.toString()}) for ${args.ageMs}ms; reconcile or replace/dropped report required`,
  ) as Error & {
    code: 'nonce_lane_blocked';
    retryable: true;
    details: {
      chain: EvmNonceChain;
      networkKey: string;
      chainId: number;
      blockedNonce: string;
      ageMs: number;
    };
  };
  error.code = 'nonce_lane_blocked';
  error.retryable = true;
  error.details = {
    chain: args.lane.chainTarget.kind,
    networkKey: nonceLaneNetworkKey(args.lane),
    chainId: args.lane.chainTarget.chainId,
    blockedNonce: args.blockedNonce.toString(),
    ageMs: args.ageMs,
  };
  return error;
}
