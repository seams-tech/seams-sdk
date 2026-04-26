import type {
  EvmNonceChain,
  EvmNonceBackend,
  ManagedNonceReservation,
  NonceLaneStatus,
  ReserveNonceInput,
} from '@/core/rpcClients/evm/nonceBackend';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { TransactionContext } from '@/core/types/rpc';
import type { AccessKeyView, BlockResult } from '@near-js/types';
import { errorMessage } from '@shared/utils/errors';
import { isObject, isString } from '@shared/utils/validation';
import type {
  SigningOperationContext,
  SigningOperationFingerprint,
  SigningOperationId,
} from '../session/signingSessionTypes';

export type NonceLeaseState =
  | 'reserved'
  | 'released'
  | 'expired'
  | 'signed'
  | 'signed_lease_expired'
  | 'broadcast_accepted'
  | 'broadcast_rejected'
  | 'finalized'
  | 'dropped'
  | 'replaced'
  | 'reconciled';

export type EvmNonceLane = {
  family: 'evm';
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey?: bigint;
  accountId?: string;
};

export type NearNonceLane = {
  family: 'near';
  networkKey: string;
  accountId: string;
  publicKey: string;
};

export type NonceLane = EvmNonceLane | NearNonceLane;

export type NonceOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
  accountId: string;
  walletSigningSessionId?: string;
  chainFamily: 'near' | 'evm' | 'tempo';
};

export type NonceLease = {
  leaseId: string;
  lane: NonceLane;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  nonce: bigint | string;
  state: NonceLeaseState;
  reservedAtMs: number;
  expiresAtMs: number;
  batchId?: string;
  txIndex?: number;
};

export type NonceLeaseRef = {
  leaseId: string;
  operationId: string;
  nonce: string;
  batchId?: string;
  txIndex?: number;
};

export type NonceCoordinatorTraceEvent = {
  event:
    | 'nonce_lease_reserved'
    | 'nonce_lease_released'
    | 'nonce_lease_expired'
    | 'nonce_lease_signed'
    | 'nonce_lease_broadcast_accepted'
    | 'nonce_lease_broadcast_rejected'
    | 'nonce_lease_finalized'
    | 'nonce_lease_dropped'
    | 'nonce_lease_replaced'
    | 'nonce_coordinator_metrics'
    | 'nonce_lane_alert'
    | 'nonce_lanes_cleared'
    | 'nonce_lane_reconciled';
  lease?: NonceLease;
  lane?: NonceLane;
  metrics?: NonceCoordinatorAggregateMetrics;
  previousState?: NonceLeaseState;
  nextState?: NonceLeaseState;
  reason?: string;
  txHash?: string;
  accountId?: string;
  alert?: NonceCoordinatorAlert;
};

export type NonceCoordinatorAlert = {
  kind: 'repeated_dropped_or_replaced';
  severity: 'warning';
  lane: NonceLane;
  reason: 'dropped' | 'replaced';
  count: number;
  windowMs: number;
  firstSeenAtMs: number;
  lastSeenAtMs: number;
};

export type NonceCoordinatorSameOriginLockPort = {
  withLock<T>(key: string, task: () => Promise<T>): Promise<T>;
};

export type NonceCoordinatorSameOriginEvmLeaseRecord = {
  laneKey: string;
  leaseId: string;
  nonce: string;
  state: 'reserved' | 'signed' | 'broadcast_accepted';
  reservedAtMs: number;
  expiresAtMs: number;
  updatedAtMs: number;
  accountId?: string;
};

export type NonceCoordinatorSameOriginLeaseStorePort = {
  readLane(laneKey: string): NonceCoordinatorSameOriginEvmLeaseRecord[];
  upsert(record: NonceCoordinatorSameOriginEvmLeaseRecord): void;
  remove(input: { laneKey: string; leaseId: string }): void;
  clearForAccount(accountId: string): void;
  clearAll(): void;
};

export type NonceCoordinatorDeps = {
  evmNonceBackend: EvmNonceBackend;
  nearClient?: NearClient;
  now?: () => number;
  leaseTtlMs?: number;
  signedLeaseTtlMs?: number;
  evmRefreshTtlMs?: number;
  evmStaleInFlightThresholdMs?: number;
  sameOriginLock?: NonceCoordinatorSameOriginLockPort | null;
  sameOriginLeaseStore?: NonceCoordinatorSameOriginLeaseStorePort | null;
  droppedReplacedAlertThreshold?: number;
  droppedReplacedAlertWindowMs?: number;
  onTrace?: (event: NonceCoordinatorTraceEvent) => void;
};

export type NonceCoordinatorAggregateMetrics = {
  atMs: number;
  accountId?: string;
  leaseCount: number;
  laneCount: number;
  oldestLeaseAgeMs: number;
  oldestInFlightLeaseAgeMs: number;
  staleInFlightLeaseCount: number;
  staleInFlightLaneCount: number;
  reservedLeaseCount: number;
  signedLeaseCount: number;
  broadcastAcceptedLeaseCount: number;
  droppedLeaseCount: number;
  replacedLeaseCount: number;
  reconciledLeaseCount: number;
  releasedLeaseCount: number;
};

export type NonceCoordinatorDiagnosticsOptions = {
  accountId?: string;
  emitMetrics?: boolean;
};

export type NonceCoordinatorDiagnostics = {
  leaseCount: number;
  leasesByState: Record<NonceLeaseState, number>;
  laneCount: number;
  metrics: NonceCoordinatorAggregateMetrics;
  lanes: Array<{
    family: NonceLane['family'];
    accountId?: string;
    networkKey: string;
    chain?: EvmNonceChain;
    chainId?: number;
    leaseCount: number;
    states: Partial<Record<NonceLeaseState, number>>;
  }>;
  near: {
    activeAccountId?: string;
    activePublicKey?: string;
    hasContext: boolean;
    reservedNonceCount: number;
    lastReservedNonce?: string;
  };
};

export type NonceCoordinator = {
  reserve(input: {
    lane: NonceLane;
    operation: NonceOperationContext;
  }): Promise<NonceLease>;
  reserveBatch(input: {
    lane: NearNonceLane;
    operation: NonceOperationContext;
    count: number;
  }): Promise<NonceLease[]>;
  reserveNearContext(input: {
    lane: NearNonceLane;
    operation: NonceOperationContext;
    count: number;
    fetchContext?: () => Promise<TransactionContext>;
    nearClient?: NearClient;
    force?: boolean;
  }): Promise<{ context: TransactionContext; leases: NonceLease[] }>;
  initializeNearAccessKey(input: { accountId: string; publicKey: string }): void;
  getActiveNearPublicKey(): string | null;
  fetchNearContext(input: {
    lane: NearNonceLane;
    nearClient?: NearClient;
    force?: boolean;
  }): Promise<TransactionContext>;
  prefetchNearContext(input?: {
    accountId?: string;
    publicKey?: string;
    nearClient?: NearClient;
  }): Promise<void>;
  clearNearAccessKey(): void;
  markSigned(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    signedTxHash?: string;
  }): Promise<void>;
  markBroadcastAccepted(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    txHash?: `0x${string}` | string;
  }): Promise<void>;
  markBroadcastRejected(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    error?: unknown;
  }): Promise<void>;
  markFinalized(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    txHash?: `0x${string}` | string;
  }): Promise<void>;
  markDroppedOrReplaced(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    reason: 'dropped' | 'replaced';
    txHash?: `0x${string}` | string;
  }): Promise<void>;
  release(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    reason: 'cancelled' | 'auth_failed' | 'signing_failed' | 'nonce_failed';
  }): Promise<void>;
  expireLeases(input?: { accountId?: string }): Promise<NonceLease[]>;
  reconcile(input: { lane: NonceLane }): Promise<NonceLaneStatus>;
  clearForAccount(accountId: string): void;
  clearAll(): void;
  getDiagnostics(input?: NonceCoordinatorDiagnosticsOptions): NonceCoordinatorDiagnostics;
};

const DEFAULT_NONCE_LEASE_TTL_MS = 120_000;
const DEFAULT_SIGNED_NONCE_LEASE_TTL_MS = 30_000;
const DEFAULT_EVM_REFRESH_TTL_MS = 5_000;
const DEFAULT_EVM_STALE_INFLIGHT_THRESHOLD_MS = 45_000;
const DEFAULT_DROPPED_REPLACED_ALERT_THRESHOLD = 3;
const DEFAULT_DROPPED_REPLACED_ALERT_WINDOW_MS = 5 * 60_000;
const SAME_ORIGIN_EVM_LEASE_STORAGE_KEY = 'tatchi:nonce-coordinator:v1:evm-leases';
const NEAR_NONCE_FRESHNESS_THRESHOLD_MS = 5_000;
const NEAR_BLOCK_FRESHNESS_THRESHOLD_MS = 20_000;
const NEAR_PREFETCH_DEBOUNCE_MS = 400;
const NONCE_LEASE_STATES: readonly NonceLeaseState[] = [
  'reserved',
  'released',
  'expired',
  'signed',
  'signed_lease_expired',
  'broadcast_accepted',
  'broadcast_rejected',
  'finalized',
  'dropped',
  'replaced',
  'reconciled',
];

export function reduceNonceLeaseState(
  current: NonceLeaseState,
  transition:
    | 'release'
    | 'expire'
    | 'mark_signed'
    | 'broadcast_accepted'
    | 'broadcast_rejected'
    | 'finalize'
    | 'drop'
    | 'replace'
    | 'reconcile',
): NonceLeaseState {
  if (transition === 'release') {
    if (current === 'released') return current;
    if (current === 'reserved') return 'released';
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'expire') {
    if (current === 'reserved') return 'expired';
    if (current === 'signed') return 'signed_lease_expired';
    if (current === 'expired' || current === 'signed_lease_expired') return current;
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'mark_signed') {
    if (current === 'reserved' || current === 'signed') return 'signed';
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'broadcast_accepted') {
    if (
      current === 'reserved' ||
      current === 'signed' ||
      current === 'broadcast_accepted'
    ) {
      return 'broadcast_accepted';
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'broadcast_rejected') {
    if (
      current === 'reserved' ||
      current === 'signed' ||
      current === 'broadcast_rejected'
    ) {
      return 'broadcast_rejected';
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'finalize') {
    if (current === 'broadcast_accepted' || current === 'finalized') return 'finalized';
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'drop') {
    if (current === 'broadcast_accepted' || current === 'dropped') return 'dropped';
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'replace') {
    if (current === 'broadcast_accepted' || current === 'replaced') return 'replaced';
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'reconcile') {
    if (
      current === 'released' ||
      current === 'expired' ||
      current === 'signed_lease_expired' ||
      current === 'broadcast_rejected' ||
      current === 'dropped' ||
      current === 'replaced' ||
      current === 'reconciled'
    ) {
      return 'reconciled';
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  throw createIllegalNonceTransitionError(current, transition);
}

type EvmNonceLaneState = {
  chainNonce: bigint | null;
  nextCandidate: bigint | null;
  inFlight: Map<string, EvmInFlightNonceRecord>;
  lastRefreshMs: number | null;
  inflightRefresh: Promise<bigint> | null;
};

type EvmInFlightNonceRecord = {
  nonce: bigint;
  txHash?: `0x${string}`;
  status: 'accepted' | 'replaced';
  acceptedAtMs: number;
  updatedAtMs: number;
};

type DroppedReplacedAlertWindow = {
  count: number;
  firstSeenAtMs: number;
  lastSeenAtMs: number;
};

export function createNonceCoordinator(deps: NonceCoordinatorDeps): NonceCoordinator {
  const leases = new Map<string, NonceLease>();
  const evmStates = new Map<string, EvmNonceLaneState>();
  const evmAccountLaneKeys = new Map<string, Set<string>>();
  const droppedReplacedAlerts = new Map<string, DroppedReplacedAlertWindow>();
  const laneLocks = new Map<string, Promise<void>>();
  const now = deps.now || Date.now;
  const leaseTtlMs = normalizePositiveInteger(deps.leaseTtlMs, DEFAULT_NONCE_LEASE_TTL_MS);
  const signedLeaseTtlMs = normalizePositiveInteger(
    deps.signedLeaseTtlMs,
    DEFAULT_SIGNED_NONCE_LEASE_TTL_MS,
  );
  const evmRefreshTtlMs = normalizePositiveInteger(
    deps.evmRefreshTtlMs,
    DEFAULT_EVM_REFRESH_TTL_MS,
  );
  const evmStaleInFlightThresholdMs = normalizePositiveInteger(
    deps.evmStaleInFlightThresholdMs,
    DEFAULT_EVM_STALE_INFLIGHT_THRESHOLD_MS,
  );
  const droppedReplacedAlertThreshold = normalizePositiveInteger(
    deps.droppedReplacedAlertThreshold,
    DEFAULT_DROPPED_REPLACED_ALERT_THRESHOLD,
  );
  const droppedReplacedAlertWindowMs = normalizePositiveInteger(
    deps.droppedReplacedAlertWindowMs,
    DEFAULT_DROPPED_REPLACED_ALERT_WINDOW_MS,
  );
  const sameOriginLock =
    deps.sameOriginLock === undefined ? createDefaultSameOriginLock() : deps.sameOriginLock;
  const sameOriginLeaseStore =
    deps.sameOriginLeaseStore === undefined
      ? createDefaultSameOriginLeaseStore()
      : deps.sameOriginLeaseStore;

  const emit = (event: NonceCoordinatorTraceEvent): void => {
    try {
      deps.onTrace?.(event);
    } catch {}
  };

  const readLease = (input: {
    leaseId: string;
    operationId: SigningOperationId | string;
  }): NonceLease => {
    const leaseId = normalizeRequiredString(input.leaseId, 'leaseId');
    const lease = leases.get(leaseId);
    if (!lease) {
      throw new Error('[NonceCoordinator] nonce lease not found');
    }
    assertOperationMatches(lease, input.operationId);
    return lease;
  };

  const transitionLease = (args: {
    lease: NonceLease;
    transition: Parameters<typeof reduceNonceLeaseState>[1];
    event: NonceCoordinatorTraceEvent['event'];
    reason?: string;
    txHash?: string;
    expiresAtMs?: number;
  }): void => {
    const previousState = args.lease.state;
    const nextState = reduceNonceLeaseState(previousState, args.transition);
    args.lease.state = nextState;
    const expiresAtMs = args.expiresAtMs;
    if (typeof expiresAtMs === 'number' && Number.isSafeInteger(expiresAtMs)) {
      args.lease.expiresAtMs = expiresAtMs;
    }
    emit({
      event: args.event,
      lease: args.lease,
      previousState,
      nextState,
      ...(args.reason ? { reason: args.reason } : {}),
      ...(args.txHash ? { txHash: args.txHash } : {}),
    });
  };

  const getOrCreateEvmState = (laneKey: string): EvmNonceLaneState => {
    const existing = evmStates.get(laneKey);
    if (existing) return existing;
    const created: EvmNonceLaneState = {
      chainNonce: null,
      nextCandidate: null,
      inFlight: new Map<string, EvmInFlightNonceRecord>(),
      lastRefreshMs: null,
      inflightRefresh: null,
    };
    evmStates.set(laneKey, created);
    return created;
  };

  const indexEvmLaneByAccount = (lane: EvmNonceLane, laneKey: string): void => {
    const accountId = String(lane.accountId || '').trim();
    if (!accountId) return;
    const keys = evmAccountLaneKeys.get(accountId);
    if (!keys) {
      evmAccountLaneKeys.set(accountId, new Set<string>([laneKey]));
      return;
    }
    keys.add(laneKey);
  };

  const readActiveEvmLeaseNonces = (
    laneKey: string,
    input?: { chainNextNonce?: bigint; excludeLeaseId?: string },
  ): Set<string> => {
    const active = new Set<string>();
    for (const lease of leases.values()) {
      if (input?.excludeLeaseId && lease.leaseId === input.excludeLeaseId) continue;
      if (lease.lane.family !== 'evm') continue;
      if (nonceLaneKey(lease.lane) !== laneKey) continue;
      if (!isActiveEvmLeaseState(lease.state)) continue;
      const nonce = normalizeBigint(lease.nonce, 'nonce');
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    for (const record of sameOriginLeaseStore?.readLane(laneKey) || []) {
      if (input?.excludeLeaseId && record.leaseId === input.excludeLeaseId) continue;
      if (!isSameOriginActiveEvmLeaseRecord(record, now())) continue;
      const nonce = normalizeBigint(record.nonce, 'nonce');
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    return active;
  };

  const persistSameOriginEvmLease = (
    lease: NonceLease & { lane: EvmNonceLane },
    state: NonceCoordinatorSameOriginEvmLeaseRecord['state'],
    expiresAtMs = lease.expiresAtMs,
  ): void => {
    if (!sameOriginLeaseStore) return;
    const laneKey = nonceLaneKey(lease.lane);
    sameOriginLeaseStore.upsert({
      laneKey,
      leaseId: lease.leaseId,
      nonce: String(lease.nonce),
      state,
      reservedAtMs: lease.reservedAtMs,
      expiresAtMs,
      updatedAtMs: now(),
      ...(lease.lane.accountId ? { accountId: lease.lane.accountId } : {}),
    });
  };

  const removeSameOriginEvmLease = (lease: NonceLease & { lane: EvmNonceLane }): void => {
    sameOriginLeaseStore?.remove({
      laneKey: nonceLaneKey(lease.lane),
      leaseId: lease.leaseId,
    });
  };

  const refreshEvmLaneFromChainLocked = async (
    lane: EvmNonceLane,
    state: EvmNonceLaneState,
  ): Promise<bigint> => {
    if (state.inflightRefresh) {
      return await state.inflightRefresh;
    }
    const laneKey = nonceLaneKey(lane);
    const refreshTask = (async (): Promise<bigint> => {
      const chainNextNonceRaw = await deps.evmNonceBackend.fetchChainNonce(
        evmLaneToReserveNonceInput(lane),
      );
      const chainNextNonce = chainNextNonceRaw >= 0n ? chainNextNonceRaw : 0n;
      const activeLeaseNonces = readActiveEvmLeaseNonces(laneKey, { chainNextNonce });

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

      const hasOutstandingLocalNonce =
        activeLeaseNonces.size > 0 || prunedInFlight.size > 0;
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
      state.lastRefreshMs = now();
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
  };

  const readBlockedEvmInFlight = (
    state: EvmNonceLaneState,
  ): { blockedNonce: bigint; ageMs: number } | null => {
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
    const ageMs = Math.max(0, now() - oldestUpdatedAtMs);
    if (ageMs < evmStaleInFlightThresholdMs) return null;
    return { blockedNonce: oldestNonce, ageMs };
  };

  const shouldRefreshEvmLane = (laneKey: string, state: EvmNonceLaneState): boolean => {
    if (state.nextCandidate == null) return true;
    if (state.lastRefreshMs == null) return true;
    if (state.inFlight.size > 0) return true;
    if (readActiveEvmLeaseNonces(laneKey).size > 0) return false;
    return now() - state.lastRefreshMs >= evmRefreshTtlMs;
  };

  const reserveEvmNonceLeaseUnlocked = async (input: {
    lane: EvmNonceLane;
    operation: NonceOperationContext;
  }): Promise<NonceLease> => {
    await expireDueLeases({ accountId: input.operation.accountId });
    const laneKey = nonceLaneKey(input.lane);
    const state = getOrCreateEvmState(laneKey);
    indexEvmLaneByAccount(input.lane, laneKey);
    if (shouldRefreshEvmLane(laneKey, state)) {
      await refreshEvmLaneFromChainLocked(input.lane, state);
    }
    const blocked = readBlockedEvmInFlight(state);
    if (blocked) {
      throw createEvmNonceLaneBlockedError({
        lane: input.lane,
        blockedNonce: blocked.blockedNonce,
        ageMs: blocked.ageMs,
      });
    }

    // Start from the chain-visible nonce and skip only active coordinator-owned
    // leases/in-flight records. Released or expired holes must be reusable; this
    // is the bug class that previously left Tempo/Arc polling transactions that
    // could never enter the pending pool.
    let candidate = state.chainNonce ?? state.nextCandidate ?? 0n;
    const activeLeaseNonces = readActiveEvmLeaseNonces(laneKey);
    while (
      activeLeaseNonces.has(candidate.toString()) ||
      state.inFlight.has(candidate.toString())
    ) {
      candidate += 1n;
    }
    state.nextCandidate = candidate + 1n;
    const reservedAtMs = now();
    const lease: NonceLease = {
      leaseId: createNonceLeaseId({
        operationId: input.operation.operationId,
        chain: input.lane.chain,
        nonce: candidate,
      }),
      lane: input.lane,
      operationId: input.operation.operationId,
      operationFingerprint: input.operation.operationFingerprint,
      nonce: candidate,
      state: 'reserved',
      reservedAtMs,
      expiresAtMs: reservedAtMs + leaseTtlMs,
    };
    leases.set(lease.leaseId, lease);
    persistSameOriginEvmLease(lease as NonceLease & { lane: EvmNonceLane }, 'reserved');
    emit({ event: 'nonce_lease_reserved', lease });
    return { ...lease };
  };

  const releaseEvmNonceReservation = (lease: NonceLease & { lane: EvmNonceLane }): void => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = evmStates.get(laneKey);
    removeSameOriginEvmLease(lease);
    if (!state) return;
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    state.inFlight.delete(nonce.toString());
    const hasOtherActiveLease =
      readActiveEvmLeaseNonces(laneKey, { excludeLeaseId: lease.leaseId }).size > 0;
    if (!hasOtherActiveLease && state.inFlight.size === 0) {
      state.lastRefreshMs = null;
    }
  };

  const markEvmBroadcastAccepted = (
    lease: NonceLease & { lane: EvmNonceLane },
    txHash?: string,
  ): void => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    const atMs = now();
    state.inFlight.set(nonce.toString(), {
      nonce,
      ...(txHash ? { txHash: txHash as `0x${string}` } : {}),
      status: 'accepted',
      acceptedAtMs: atMs,
      updatedAtMs: atMs,
    });
    const minNext = nonce + 1n;
    if (state.nextCandidate == null || state.nextCandidate < minNext) {
      state.nextCandidate = minNext;
    }
    persistSameOriginEvmLease(lease, 'broadcast_accepted', atMs + evmStaleInFlightThresholdMs);
  };

  const markEvmFinalized = (lease: NonceLease & { lane: EvmNonceLane }): void => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    state.inFlight.delete(nonce.toString());
    const minNext = nonce + 1n;
    state.chainNonce = state.chainNonce == null ? minNext : maxBigint(state.chainNonce, minNext);
    if (state.nextCandidate == null || state.nextCandidate < minNext) {
      state.nextCandidate = minNext;
    }
    state.lastRefreshMs = now();
    removeSameOriginEvmLease(lease);
  };

  const markEvmDroppedOrReplaced = (
    lease: NonceLease & { lane: EvmNonceLane },
    input: { reason: 'dropped' | 'replaced'; txHash?: string },
  ): void => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    if (input.reason === 'dropped') {
      state.inFlight.delete(nonce.toString());
      if (state.chainNonce == null || state.chainNonce <= nonce) {
        state.nextCandidate =
          state.nextCandidate == null ? nonce : minBigint(state.nextCandidate, nonce);
      }
    } else {
      const previous = state.inFlight.get(nonce.toString());
      state.inFlight.set(nonce.toString(), {
        nonce,
        ...(input.txHash
          ? { txHash: input.txHash as `0x${string}` }
          : previous?.txHash
            ? { txHash: previous.txHash }
            : {}),
        status: 'replaced',
        acceptedAtMs: previous?.acceptedAtMs ?? now(),
        updatedAtMs: now(),
      });
    }
    state.lastRefreshMs = null;
    removeSameOriginEvmLease(lease);
  };

  const reconcileEvmLaneLocked = async (lane: EvmNonceLane): Promise<NonceLaneStatus> => {
    const laneKey = nonceLaneKey(lane);
    const state = getOrCreateEvmState(laneKey);
    indexEvmLaneByAccount(lane, laneKey);
    const chainNextNonce = await refreshEvmLaneFromChainLocked(lane, state);
    const unresolvedInFlightNonces = Array.from(state.inFlight.values())
      .map((entry) => entry.nonce)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const blockedState = readBlockedEvmInFlight(state);
    return {
      chainNextNonce,
      unresolvedInFlightNonces,
      blocked: !!blockedState,
      ...(blockedState ? { blockedNonce: blockedState.blockedNonce } : {}),
    };
  };

  const recordDroppedReplacedAlert = (args: {
    lane: EvmNonceLane;
    reason: 'dropped' | 'replaced';
  }): void => {
    const atMs = now();
    const key = [nonceLaneKey(args.lane), args.reason].join('|');
    const existing = droppedReplacedAlerts.get(key);
    const windowState =
      existing && atMs - existing.firstSeenAtMs <= droppedReplacedAlertWindowMs
        ? {
            count: existing.count + 1,
            firstSeenAtMs: existing.firstSeenAtMs,
            lastSeenAtMs: atMs,
          }
        : {
            count: 1,
            firstSeenAtMs: atMs,
            lastSeenAtMs: atMs,
          };
    droppedReplacedAlerts.set(key, windowState);
    if (windowState.count < droppedReplacedAlertThreshold) return;

    const alert: NonceCoordinatorAlert = {
      kind: 'repeated_dropped_or_replaced',
      severity: 'warning',
      lane: args.lane,
      reason: args.reason,
      count: windowState.count,
      windowMs: droppedReplacedAlertWindowMs,
      firstSeenAtMs: windowState.firstSeenAtMs,
      lastSeenAtMs: windowState.lastSeenAtMs,
    };
    emit({ event: 'nonce_lane_alert', lane: args.lane, alert });
    console.warn('[NonceCoordinator] repeated EVM-family dropped/replaced nonce outcomes', {
      chain: args.lane.chain,
      networkKey: args.lane.networkKey,
      chainId: args.lane.chainId,
      sender: args.lane.sender,
      nonceKey: args.lane.nonceKey?.toString(),
      accountId: args.lane.accountId,
      reason: args.reason,
      count: windowState.count,
      windowMs: droppedReplacedAlertWindowMs,
    });
  };

  const nearState = {
    accountId: null as string | null,
    publicKey: null as string | null,
    transactionContext: null as TransactionContext | null,
    lastNonceUpdate: null as number | null,
    lastBlockHeightUpdate: null as number | null,
    inflightFetch: null as Promise<TransactionContext> | null,
    inflightId: 0,
    refreshTimer: null as ReturnType<typeof setTimeout> | null,
    prefetchTimer: null as ReturnType<typeof setTimeout> | null,
    reservedNonces: new Set<string>(),
    lastReservedNonce: null as string | null,
  };

  const clearNearRefreshTimer = (): void => {
    if (!nearState.refreshTimer) return;
    clearTimeout(nearState.refreshTimer);
    nearState.refreshTimer = null;
  };

  const clearNearPrefetchTimer = (): void => {
    if (!nearState.prefetchTimer) return;
    clearTimeout(nearState.prefetchTimer);
    nearState.prefetchTimer = null;
  };

  const clearNearTransactionContext = (): void => {
    nearState.transactionContext = null;
    nearState.lastNonceUpdate = null;
    nearState.lastBlockHeightUpdate = null;
    nearState.inflightFetch = null;
    nearState.reservedNonces.clear();
    nearState.lastReservedNonce = null;
    clearNearRefreshTimer();
    clearNearPrefetchTimer();
  };

  const clearNearAccessKeyState = (): void => {
    nearState.accountId = null;
    nearState.publicKey = null;
    clearNearTransactionContext();
  };

  const requireNearClient = (nearClient?: NearClient): NearClient => {
    const resolved = nearClient || deps.nearClient;
    if (!resolved) {
      throw new Error('[NonceCoordinator] NEAR client is not configured');
    }
    return resolved;
  };

  const initializeNearAccessKey = (input: {
    accountId: string;
    publicKey: string;
  }): void => {
    const accountId = normalizeRequiredString(input.accountId, 'accountId');
    const publicKey = normalizeRequiredString(input.publicKey, 'publicKey');
    // Idempotence here is load-bearing: repeated setup for the same NEAR
    // access key must not clear reservations while concurrent signing requests
    // are queued behind the coordinator lane lock.
    if (nearState.accountId === accountId && nearState.publicKey === publicKey) {
      return;
    }
    nearState.accountId = accountId;
    nearState.publicKey = publicKey;
    clearNearTransactionContext();
  };

  const reserveNearNonces = (countInput: number): string[] => {
    if (!nearState.transactionContext) {
      throw new Error(
        'NEAR transaction context not available - call fetchNearContext() first',
      );
    }
    const count = Math.max(0, Math.floor(Number(countInput || 0)));
    if (count <= 0) return [];

    const start = nearState.lastReservedNonce
      ? BigInt(nearState.lastReservedNonce) + 1n
      : BigInt(nearState.transactionContext.nextNonce);
    const planned: string[] = [];
    for (let index = 0; index < count; index += 1) {
      const candidate = (start + BigInt(index)).toString();
      if (nearState.reservedNonces.has(candidate)) {
        throw new Error(`[NonceCoordinator] NEAR nonce ${candidate} is already reserved`);
      }
      planned.push(candidate);
    }
    for (const nonce of planned) {
      nearState.reservedNonces.add(nonce);
    }
    nearState.lastReservedNonce = planned[planned.length - 1] || nearState.lastReservedNonce;
    return planned;
  };

  const releaseNearNonce = (nonce: string): void => {
    if (!nearState.reservedNonces.delete(String(nonce))) return;
    nearState.lastReservedNonce = computeLastReservedNonce(nearState.reservedNonces);
  };

  const releaseAllNearNonces = (): void => {
    nearState.reservedNonces.clear();
    nearState.lastReservedNonce = null;
  };

  const fetchNearFreshData = async (
    nearClient: NearClient,
    force = false,
  ): Promise<TransactionContext> => {
    if (!nearState.accountId || !nearState.publicKey) {
      throw new Error('[NonceCoordinator] NEAR access key is not initialized');
    }
    if (nearState.inflightFetch && !force) {
      return nearState.inflightFetch;
    }

    const capturedAccountId = nearState.accountId;
    const capturedPublicKey = nearState.publicKey;
    const requestId = ++nearState.inflightId;
    const fetchPromise = (async () => {
      try {
        const nowMs = now();
        const isNonceStale =
          force ||
          !nearState.lastNonceUpdate ||
          nowMs - nearState.lastNonceUpdate >= NEAR_NONCE_FRESHNESS_THRESHOLD_MS;
        const isBlockStale =
          force ||
          !nearState.lastBlockHeightUpdate ||
          nowMs - nearState.lastBlockHeightUpdate >= NEAR_BLOCK_FRESHNESS_THRESHOLD_MS;

        let accessKeyInfo = nearState.transactionContext?.accessKeyInfo;
        let txBlockHeight = nearState.transactionContext?.txBlockHeight;
        let txBlockHash = nearState.transactionContext?.txBlockHash;
        const fetchAccessKey = isNonceStale || !accessKeyInfo;
        const fetchBlock = isBlockStale || !txBlockHeight || !txBlockHash;

        let maybeAccessKey: unknown = accessKeyInfo ?? null;
        let maybeBlock: unknown = null;
        let accessKeyError: unknown = null;
        let blockError: unknown = null;
        const tasks: Promise<void>[] = [];

        if (fetchAccessKey) {
          tasks.push(
            (async () => {
              try {
                maybeAccessKey = await nearClient.viewAccessKey(
                  capturedAccountId,
                  capturedPublicKey,
                );
              } catch (error: unknown) {
                const message = errorMessage(error);
                if (isMissingNearAccessKeyError(message)) {
                  maybeAccessKey = null;
                  return;
                }
                accessKeyError = error;
              }
            })(),
          );
        }

        if (fetchBlock) {
          tasks.push(
            (async () => {
              try {
                maybeBlock = await nearClient.viewBlock({ finality: 'final' });
              } catch (error: unknown) {
                blockError = error;
              }
            })(),
          );
        }

        if (tasks.length > 0) {
          await Promise.all(tasks);
        }
        if (accessKeyError) throw accessKeyError;
        if (blockError) throw blockError;

        if (fetchAccessKey) {
          accessKeyInfo = isAccessKeyViewLike(maybeAccessKey)
            ? normalizeAccessKeyView(maybeAccessKey)
            : nearState.transactionContext?.accessKeyInfo || makePlaceholderAccessKey();
        }
        if (fetchBlock) {
          if (!isBlockResultLike(maybeBlock)) {
            throw new Error('[NonceCoordinator] failed to fetch NEAR block info');
          }
          txBlockHeight = String(maybeBlock.header.height);
          txBlockHash = maybeBlock.header.hash;
        }

        const nextCandidate = maxBigint(
          accessKeyInfo?.nonce !== undefined ? BigInt(accessKeyInfo.nonce) + 1n : 0n,
          nearState.transactionContext?.nextNonce
            ? BigInt(nearState.transactionContext.nextNonce)
            : 0n,
          nearState.lastReservedNonce ? BigInt(nearState.lastReservedNonce) + 1n : 0n,
          1n,
        );
        const transactionContext: TransactionContext = {
          nearPublicKeyStr: capturedPublicKey,
          accessKeyInfo: accessKeyInfo!,
          nextNonce: nextCandidate.toString(),
          txBlockHeight: txBlockHeight!,
          txBlockHash: txBlockHash!,
        };

        if (
          capturedAccountId === nearState.accountId &&
          capturedPublicKey === nearState.publicKey &&
          requestId === nearState.inflightId
        ) {
          nearState.transactionContext = transactionContext;
          const commitMs = now();
          if (fetchAccessKey) nearState.lastNonceUpdate = commitMs;
          if (fetchBlock) nearState.lastBlockHeightUpdate = commitMs;
        }
        return transactionContext;
      } finally {
        if (requestId === nearState.inflightId) {
          nearState.inflightFetch = null;
        }
      }
    })();

    nearState.inflightFetch = fetchPromise;
    return fetchPromise;
  };

  const fetchNearContextForLane = async (input: {
    lane: NearNonceLane;
    nearClient?: NearClient;
    force?: boolean;
  }): Promise<TransactionContext> => {
    initializeNearAccessKey({
      accountId: input.lane.accountId,
      publicKey: input.lane.publicKey,
    });
    return {
      ...(await fetchNearFreshData(requireNearClient(input.nearClient), input.force === true)),
    };
  };

  const updateNearNonceFromBlockchain = async (
    nearClient: NearClient,
    actualNonce: string,
  ): Promise<void> => {
    if (!nearState.accountId || !nearState.publicKey) {
      throw new Error('[NonceCoordinator] NEAR access key is not initialized');
    }
    try {
      const accessKeyInfoRaw = await nearClient.viewAccessKey(
        nearState.accountId,
        nearState.publicKey,
      );
      if (!isAccessKeyViewLike(accessKeyInfoRaw)) {
        throw new Error(`Access key not found or invalid for account ${nearState.accountId}`);
      }
      const accessKeyInfo = normalizeAccessKeyView(accessKeyInfoRaw);
      const chainNonce = BigInt(accessKeyInfo.nonce);
      const actual = BigInt(actualNonce);
      const candidateNext = maxBigint(
        chainNonce + 1n,
        actual + 1n,
        nearState.transactionContext?.nextNonce
          ? BigInt(nearState.transactionContext.nextNonce)
          : 0n,
        nearState.lastReservedNonce ? BigInt(nearState.lastReservedNonce) + 1n : 0n,
      );

      if (nearState.transactionContext) {
        nearState.transactionContext = {
          ...nearState.transactionContext,
          accessKeyInfo,
          nextNonce: candidateNext.toString(),
        };
      } else {
        nearState.transactionContext = {
          nearPublicKeyStr: nearState.publicKey,
          accessKeyInfo,
          nextNonce: candidateNext.toString(),
          txBlockHeight: '0',
          txBlockHash: '',
        };
      }
      nearState.lastNonceUpdate = now();
      releaseNearNonce(actualNonce);
      if (nearState.reservedNonces.size > 0) {
        const pruned = pruneReservedNearNonces(chainNonce, nearState.reservedNonces);
        nearState.reservedNonces = pruned.set;
        nearState.lastReservedNonce = pruned.lastReserved;
      }
    } catch (error: unknown) {
      const message = errorMessage(error);
      if (isMissingNearAccessKeyError(message)) {
        const actual = BigInt(actualNonce);
        const candidateNext = maxBigint(
          actual + 1n,
          nearState.transactionContext?.nextNonce
            ? BigInt(nearState.transactionContext.nextNonce)
            : 0n,
          nearState.lastReservedNonce ? BigInt(nearState.lastReservedNonce) + 1n : 0n,
        );
        nearState.transactionContext = {
          ...(nearState.transactionContext || {
            nearPublicKeyStr: nearState.publicKey,
            accessKeyInfo: makePlaceholderAccessKey(),
            txBlockHeight: '0',
            txBlockHash: '',
          }),
          nextNonce: candidateNext.toString(),
        };
        nearState.lastNonceUpdate = now();
      }
    }
  };

  const releaseBackendReservation = async (lease: NonceLease): Promise<void> => {
    if (lease.lane.family === 'evm') {
      releaseEvmNonceReservation(lease as NonceLease & { lane: EvmNonceLane });
      return;
    }
    releaseNearNonce(String(lease.nonce));
  };

  const reconcileAfterSignedLeaseExpiry = async (lease: NonceLease): Promise<void> => {
    await releaseBackendReservation(lease);
    if (lease.lane.family !== 'evm') return;
    await reconcileEvmLaneLocked(lease.lane);
    emit({ event: 'nonce_lane_reconciled', lane: lease.lane });
  };

  const withLocalLaneLock = async <T>(
    laneKey: string,
    fn: () => Promise<T>,
  ): Promise<T> => {
    const previous = laneLocks.get(laneKey) ?? Promise.resolve();
    let releaseCurrent!: () => void;
    const current = new Promise<void>((resolve) => {
      releaseCurrent = resolve;
    });
    const next = previous.catch(() => undefined).then(() => current);
    laneLocks.set(laneKey, next);
    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      releaseCurrent();
      if (laneLocks.get(laneKey) === next) {
        laneLocks.delete(laneKey);
      }
    }
  };

  const withLaneLock = async <T>(lane: NonceLane, fn: () => Promise<T>): Promise<T> => {
    const laneKey = nonceLaneKey(lane);
    const runLocal = async () => await withLocalLaneLock(laneKey, fn);
    if (!sameOriginLock) return await runLocal();
    return await sameOriginLock.withLock(`nonce-coordinator:${laneKey}`, runLocal);
  };

  const expireDueLeases = async (input?: { accountId?: string }): Promise<NonceLease[]> => {
    const nowMs = now();
    const accountId = input?.accountId ? String(input.accountId).trim() : '';
    const expired: NonceLease[] = [];
    for (const lease of Array.from(leases.values())) {
      if (accountId && lease.lane.accountId !== accountId) continue;
      if (lease.expiresAtMs > nowMs) continue;
      if (lease.state !== 'reserved' && lease.state !== 'signed') continue;
      if (lease.state === 'signed') {
        await reconcileAfterSignedLeaseExpiry(lease);
      } else {
        await releaseBackendReservation(lease);
      }
      transitionLease({
        lease,
        transition: 'expire',
        event: 'nonce_lease_expired',
        reason: lease.state === 'signed' ? 'signed_lease_ttl_elapsed' : 'lease_ttl_elapsed',
      });
      expired.push({ ...lease });
    }
    return expired;
  };

  const reserveNearNonceBatchUnlocked = async (input: {
    lane: NearNonceLane;
    operation: NonceOperationContext;
    count: number;
  }): Promise<NonceLease[]> => {
    await expireDueLeases({ accountId: input.operation.accountId });
    const count = Math.max(1, Math.floor(Number(input.count || 1)));
    const nonces = reserveNearNonces(count);
    if (nonces.length !== count) {
      throw new Error('[NonceCoordinator] NEAR nonce reservation returned an incomplete batch');
    }
    const reservedAtMs = now();
    const batchId = createNonceBatchId({
      operationId: input.operation.operationId,
      chain: 'near',
      firstNonce: nonces[0],
      count,
    });
    const batchLeases = nonces.map((nonce, txIndex): NonceLease => ({
      leaseId: createNonceLeaseId({
        operationId: input.operation.operationId,
        chain: 'near',
        nonce,
      }),
      lane: input.lane,
      operationId: input.operation.operationId,
      operationFingerprint: input.operation.operationFingerprint,
      nonce,
      state: 'reserved',
      reservedAtMs,
      expiresAtMs: reservedAtMs + leaseTtlMs,
      batchId,
      txIndex,
    }));
    for (const lease of batchLeases) {
      leases.set(lease.leaseId, lease);
      emit({ event: 'nonce_lease_reserved', lease });
    }
    return batchLeases.map((lease) => ({ ...lease }));
  };

  const createEmptyLeaseStateCounts = (): Record<NonceLeaseState, number> => {
    const counts = {} as Record<NonceLeaseState, number>;
    for (const state of NONCE_LEASE_STATES) {
      counts[state] = 0;
    }
    return counts;
  };

  const readDiagnostics = (input?: NonceCoordinatorDiagnosticsOptions): NonceCoordinatorDiagnostics => {
    const accountId = input?.accountId ? String(input.accountId).trim() : '';
    const atMs = now();
    const leasesByState = createEmptyLeaseStateCounts();
    const lanes = new Map<
      string,
      {
        lane: NonceLane;
        leaseCount: number;
        states: Partial<Record<NonceLeaseState, number>>;
      }
    >();
    const staleInFlightLaneKeys = new Set<string>();
    let leaseCount = 0;
    let oldestLeaseAgeMs = 0;
    let oldestInFlightLeaseAgeMs = 0;
    let staleInFlightLeaseCount = 0;

    for (const lease of leases.values()) {
      if (accountId && lease.lane.accountId !== accountId) continue;
      leaseCount += 1;
      leasesByState[lease.state] += 1;
      const laneKey = nonceLaneKey(lease.lane);
      const leaseAgeMs = Math.max(0, atMs - lease.reservedAtMs);
      oldestLeaseAgeMs = Math.max(oldestLeaseAgeMs, leaseAgeMs);
      if (isInFlightNonceLeaseState(lease.state)) {
        oldestInFlightLeaseAgeMs = Math.max(oldestInFlightLeaseAgeMs, leaseAgeMs);
        if (lease.expiresAtMs <= atMs) {
          staleInFlightLeaseCount += 1;
          staleInFlightLaneKeys.add(laneKey);
        }
      }
      const existing =
        lanes.get(laneKey) ||
        ({
          lane: lease.lane,
          leaseCount: 0,
          states: {},
        } satisfies {
          lane: NonceLane;
          leaseCount: number;
          states: Partial<Record<NonceLeaseState, number>>;
        });
      existing.leaseCount += 1;
      existing.states[lease.state] = (existing.states[lease.state] || 0) + 1;
      lanes.set(laneKey, existing);
    }

    const metrics: NonceCoordinatorAggregateMetrics = {
      atMs,
      ...(accountId ? { accountId } : {}),
      leaseCount,
      laneCount: lanes.size,
      oldestLeaseAgeMs,
      oldestInFlightLeaseAgeMs,
      staleInFlightLeaseCount,
      staleInFlightLaneCount: staleInFlightLaneKeys.size,
      reservedLeaseCount: leasesByState.reserved,
      signedLeaseCount: leasesByState.signed,
      broadcastAcceptedLeaseCount: leasesByState.broadcast_accepted,
      droppedLeaseCount: leasesByState.dropped,
      replacedLeaseCount: leasesByState.replaced,
      reconciledLeaseCount: leasesByState.reconciled,
      releasedLeaseCount: leasesByState.released,
    };

    const diagnostics = {
      leaseCount,
      leasesByState,
      laneCount: lanes.size,
      metrics,
      lanes: Array.from(lanes.values()).map((entry) => ({
        family: entry.lane.family,
        ...(entry.lane.accountId ? { accountId: entry.lane.accountId } : {}),
        networkKey: entry.lane.networkKey,
        ...(entry.lane.family === 'evm'
          ? { chain: entry.lane.chain, chainId: entry.lane.chainId }
          : {}),
        leaseCount: entry.leaseCount,
        states: { ...entry.states },
      })),
      near: {
        ...(nearState.accountId ? { activeAccountId: nearState.accountId } : {}),
        ...(nearState.publicKey ? { activePublicKey: nearState.publicKey } : {}),
        hasContext: !!nearState.transactionContext,
        reservedNonceCount: nearState.reservedNonces.size,
        ...(nearState.lastReservedNonce ? { lastReservedNonce: nearState.lastReservedNonce } : {}),
      },
    };

    if (input?.emitMetrics) {
      emit({
        event: 'nonce_coordinator_metrics',
        metrics,
        ...(accountId ? { accountId } : {}),
      });
    }

    return diagnostics;
  };

  return {
    async reserve(input) {
      if (input.lane.family === 'near') {
        const nearLane = input.lane;
        return await withLaneLock(nearLane, async () => {
          return (await reserveNearNonceBatchUnlocked({
            lane: nearLane,
            operation: input.operation,
            count: 1,
          }))[0];
        });
      }
      const evmLane = input.lane;
      return await withLaneLock(evmLane, async () => {
        return await reserveEvmNonceLeaseUnlocked({
          lane: evmLane,
          operation: input.operation,
        });
      });
    },

    async reserveBatch(input) {
      return await withLaneLock(input.lane, async () => {
        return await reserveNearNonceBatchUnlocked(input);
      });
    },

    async reserveNearContext(input) {
      return await withLaneLock(input.lane, async () => {
        await expireDueLeases({ accountId: input.operation.accountId });
        initializeNearAccessKey({
          accountId: input.lane.accountId,
          publicKey: input.lane.publicKey,
        });
        const context = {
          ...(input.fetchContext
            ? await input.fetchContext()
            : await fetchNearContextForLane({
                lane: input.lane,
                nearClient: input.nearClient,
                force: input.force,
              })),
        };
        nearState.transactionContext = context;
        nearState.lastNonceUpdate = now();
        nearState.lastBlockHeightUpdate = now();
        const leases = await reserveNearNonceBatchUnlocked({
          lane: input.lane,
          operation: input.operation,
          count: input.count,
        });
        if (leases[0]) {
          context.nextNonce = String(leases[0].nonce);
        }
        return { context, leases };
      });
    },

    initializeNearAccessKey,

    getActiveNearPublicKey() {
      return String(nearState.publicKey || '').trim() || null;
    },

    async fetchNearContext(input) {
      return await withLaneLock(input.lane, async () => fetchNearContextForLane(input));
    },

    async prefetchNearContext(input) {
      if (input?.accountId || input?.publicKey) {
        if (!input.accountId || !input.publicKey) {
          throw new Error(
            '[NonceCoordinator] NEAR prefetch requires both accountId and publicKey',
          );
        }
        initializeNearAccessKey({
          accountId: input.accountId,
          publicKey: input.publicKey,
        });
      }
      if (!nearState.accountId || !nearState.publicKey) return;
      clearNearPrefetchTimer();
      const nearClient = requireNearClient(input?.nearClient);
      nearState.prefetchTimer = setTimeout(() => {
        nearState.prefetchTimer = null;
        if (nearState.inflightFetch) return;
        const nowMs = now();
        const blockStale =
          !nearState.lastBlockHeightUpdate ||
          nowMs - nearState.lastBlockHeightUpdate >= NEAR_BLOCK_FRESHNESS_THRESHOLD_MS;
        const missingContext = !nearState.transactionContext;
        if (!blockStale && !missingContext) return;
        void fetchNearFreshData(nearClient).catch(() => undefined);
      }, NEAR_PREFETCH_DEBOUNCE_MS);
    },

    clearNearAccessKey() {
      clearNearAccessKeyState();
      for (const [leaseId, lease] of leases.entries()) {
        if (lease.lane.family === 'near') {
          leases.delete(leaseId);
        }
      }
    },

    async markSigned(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        const expiresAtMs = now() + signedLeaseTtlMs;
        transitionLease({
          lease: lockedLease,
          transition: 'mark_signed',
          event: 'nonce_lease_signed',
          expiresAtMs,
          ...(input.signedTxHash ? { txHash: input.signedTxHash } : {}),
        });
        if (lockedLease.lane.family === 'evm') {
          persistSameOriginEvmLease(
            lockedLease as NonceLease & { lane: EvmNonceLane },
            'signed',
            expiresAtMs,
          );
        }
      });
    },

    async markBroadcastAccepted(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        if (lockedLease.lane.family === 'evm') {
          markEvmBroadcastAccepted(
            lockedLease as NonceLease & { lane: EvmNonceLane },
            input.txHash ? String(input.txHash) : undefined,
          );
        }
        transitionLease({
          lease: lockedLease,
          transition: 'broadcast_accepted',
          event: 'nonce_lease_broadcast_accepted',
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
      });
    },

    async markBroadcastRejected(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        await releaseBackendReservation(lockedLease);
        transitionLease({
          lease: lockedLease,
          transition: 'broadcast_rejected',
          event: 'nonce_lease_broadcast_rejected',
          reason: input.error instanceof Error ? input.error.message : String(input.error || ''),
        });
      });
    },

    async markFinalized(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        if (lockedLease.lane.family === 'evm') {
          markEvmFinalized(lockedLease as NonceLease & { lane: EvmNonceLane });
        } else {
          if (deps.nearClient) {
            await updateNearNonceFromBlockchain(deps.nearClient, String(lockedLease.nonce));
          } else {
            await releaseBackendReservation(lockedLease);
          }
        }
        transitionLease({
          lease: lockedLease,
          transition: 'finalize',
          event: 'nonce_lease_finalized',
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
      });
    },

    async markDroppedOrReplaced(input) {
      const lease = readLease(input);
      assertEvmLease(lease);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        assertEvmLease(lockedLease);
        markEvmDroppedOrReplaced(lockedLease, {
          reason: input.reason,
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
        transitionLease({
          lease: lockedLease,
          transition: input.reason === 'replaced' ? 'replace' : 'drop',
          event:
            input.reason === 'replaced' ? 'nonce_lease_replaced' : 'nonce_lease_dropped',
          reason: input.reason,
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
        recordDroppedReplacedAlert({
          lane: lockedLease.lane,
          reason: input.reason,
        });
      });
    },

    async release(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        await releaseBackendReservation(lockedLease);
        transitionLease({
          lease: lockedLease,
          transition: 'release',
          event: 'nonce_lease_released',
          reason: input.reason,
        });
      });
    },

    async expireLeases(input) {
      return await expireDueLeases(input);
    },

    async reconcile(input) {
      if (input.lane.family !== 'evm') {
        throw new Error('[NonceCoordinator] NEAR nonce reconciliation is not wired yet');
      }
      const evmLane = input.lane;
      return await withLaneLock(evmLane, async () => {
        const status = await reconcileEvmLaneLocked(evmLane);
        emit({ event: 'nonce_lane_reconciled', lane: evmLane });
        return status;
      });
    },

    clearForAccount(accountId) {
      const normalizedAccountId = String(accountId || '').trim();
      if (!normalizedAccountId) return;
      sameOriginLeaseStore?.clearForAccount(normalizedAccountId);
      const evmLaneKeys = evmAccountLaneKeys.get(normalizedAccountId);
      if (evmLaneKeys) {
        for (const key of evmLaneKeys) {
          evmStates.delete(key);
        }
        evmAccountLaneKeys.delete(normalizedAccountId);
      }
      if (nearState.accountId === normalizedAccountId) {
        clearNearAccessKeyState();
      }
      for (const [leaseId, lease] of leases.entries()) {
        if (lease.lane.accountId === normalizedAccountId) {
          leases.delete(leaseId);
        }
      }
      emit({
        event: 'nonce_lanes_cleared',
        accountId: normalizedAccountId,
        reason: 'clear_for_account',
      });
    },

    clearAll() {
      evmStates.clear();
      evmAccountLaneKeys.clear();
      droppedReplacedAlerts.clear();
      sameOriginLeaseStore?.clearAll();
      clearNearAccessKeyState();
      leases.clear();
      laneLocks.clear();
      emit({ event: 'nonce_lanes_cleared', reason: 'clear_all' });
    },

    getDiagnostics(input) {
      return readDiagnostics(input);
    },
  };
}

export function evmReserveNonceInputToLane(input: ReserveNonceInput): EvmNonceLane {
  return {
    family: 'evm',
    chain: input.chain,
    networkKey: normalizeRequiredString(input.networkKey, 'networkKey'),
    chainId: input.chainId,
    sender: input.sender,
    ...(input.nonceKey != null ? { nonceKey: input.nonceKey } : {}),
    ...(input.nearAccountId ? { accountId: input.nearAccountId } : {}),
  };
}

export function evmNonceLeaseToManagedReservation(lease: NonceLease): ManagedNonceReservation {
  assertEvmLease(lease);
  return {
    ...evmLaneToReserveNonceInput(lease.lane),
    nonce: normalizeBigint(lease.nonce, 'nonce'),
    leaseId: lease.leaseId,
    operationId: String(lease.operationId),
    operationFingerprint: String(lease.operationFingerprint),
    reservedAtMs: lease.reservedAtMs,
    expiresAtMs: lease.expiresAtMs,
  };
}

export function evmManagedReservationToLane(reservation: ManagedNonceReservation): EvmNonceLane {
  return evmReserveNonceInputToLane(reservation);
}

export function nonceLeaseToRef(lease: NonceLease): NonceLeaseRef {
  return {
    leaseId: lease.leaseId,
    operationId: String(lease.operationId),
    nonce: String(lease.nonce),
    ...(lease.batchId ? { batchId: lease.batchId } : {}),
    ...(Number.isSafeInteger(lease.txIndex) ? { txIndex: lease.txIndex } : {}),
  };
}

function evmLaneToReserveNonceInput(lane: EvmNonceLane): ReserveNonceInput {
  return {
    chain: lane.chain,
    networkKey: lane.networkKey,
    chainId: lane.chainId,
    sender: lane.sender,
    ...(lane.nonceKey != null ? { nonceKey: lane.nonceKey } : {}),
    ...(lane.accountId ? { nearAccountId: lane.accountId } : {}),
  };
}

function nonceLaneKey(lane: NonceLane): string {
  if (lane.family === 'near') {
    return [
      'near',
      normalizeRequiredString(lane.networkKey, 'networkKey'),
      normalizeRequiredString(lane.accountId, 'accountId'),
      normalizeRequiredString(lane.publicKey, 'publicKey'),
    ].join(':');
  }
  return [
    'evm',
    lane.chain,
    normalizeRequiredString(lane.networkKey, 'networkKey'),
    String(lane.chainId),
    normalizeRequiredString(lane.sender, 'sender').toLowerCase(),
    lane.nonceKey != null ? String(lane.nonceKey) : '',
  ].join(':');
}

function assertEvmLease(lease: NonceLease): asserts lease is NonceLease & { lane: EvmNonceLane } {
  if (lease.lane.family !== 'evm') {
    throw new Error('[NonceCoordinator] expected an EVM-family nonce lease');
  }
}

function assertOperationMatches(
  lease: NonceLease,
  operationId: SigningOperationId | string,
): void {
  if (String(lease.operationId) !== String(operationId || '')) {
    throw new Error('[NonceCoordinator] nonce lease operation mismatch');
  }
}

function createNonceLeaseId(args: {
  operationId: SigningOperationId;
  chain: EvmNonceChain | 'near';
  nonce: bigint | string;
}): string {
  const randomId =
    typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  return `nonce-lease-v1:${args.chain}:${args.operationId}:${String(args.nonce)}:${randomId}`;
}

function createNonceBatchId(args: {
  operationId: SigningOperationId;
  chain: EvmNonceChain | 'near';
  firstNonce: bigint | string;
  count: number;
}): string {
  const randomId =
    typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  return `nonce-batch-v1:${args.chain}:${args.operationId}:${String(args.firstNonce)}:${args.count}:${randomId}`;
}

function normalizeRequiredString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[NonceCoordinator] ${label} is required`);
  }
  return normalized;
}

function normalizeBigint(value: unknown, label: string): bigint {
  try {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
    const normalized = String(value || '').trim();
    if (/^\d+$/.test(normalized)) return BigInt(normalized);
  } catch {}
  throw new Error(`[NonceCoordinator] invalid ${label}`);
}

function normalizePositiveInteger(value: unknown, fallback: number): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function isAccessKeyViewLike(value: unknown): value is AccessKeyView {
  if (!isObject(value)) return false;
  try {
    normalizeBigint((value as { nonce?: unknown }).nonce, 'near access-key nonce');
    return true;
  } catch {
    return false;
  }
}

function normalizeAccessKeyView(value: AccessKeyView): AccessKeyView {
  const permission = (value as { permission?: unknown }).permission;
  return {
    ...value,
    nonce: normalizeBigint((value as { nonce?: unknown }).nonce, 'near access-key nonce'),
    permission:
      permission === 'FullAccess' || isObject(permission)
        ? (permission as AccessKeyView['permission'])
        : 'FullAccess',
    block_hash: String((value as { block_hash?: unknown }).block_hash || ''),
    block_height: Number((value as { block_height?: unknown }).block_height || 0),
  };
}

function isBlockResultLike(value: unknown): value is BlockResult {
  if (!isObject(value)) return false;
  const header = (value as { header?: unknown }).header;
  if (!isObject(header)) return false;
  const height = (header as { height?: unknown }).height;
  const hash = (header as { hash?: unknown }).hash;
  return (typeof height === 'number' || typeof height === 'bigint') && isString(hash);
}

function makePlaceholderAccessKey(): AccessKeyView {
  return {
    nonce: 0n,
    permission: 'FullAccess',
    block_hash: '',
    block_height: 0,
  };
}

function maxBigint(...values: bigint[]): bigint {
  if (values.length === 0) return 0n;
  return values.reduce((max, value) => (max > value ? max : value));
}

function minBigint(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

function computeLastReservedNonce(reserved: Set<string>): string | null {
  let last: bigint | null = null;
  for (const value of reserved) {
    try {
      const parsed = BigInt(value);
      if (last === null || parsed > last) last = parsed;
    } catch {}
  }
  return last === null ? null : last.toString();
}

function pruneReservedNearNonces(
  chainNonce: bigint,
  reserved: Set<string>,
): { set: Set<string>; lastReserved: string | null } {
  const next = new Set<string>();
  let last: bigint | null = null;
  for (const nonce of reserved) {
    try {
      const parsed = BigInt(nonce);
      if (parsed <= chainNonce) continue;
      next.add(nonce);
      if (last === null || parsed > last) last = parsed;
    } catch {}
  }
  return { set: next, lastReserved: last === null ? null : last.toString() };
}

function isInFlightNonceLeaseState(state: NonceLeaseState): boolean {
  return state === 'reserved' || state === 'signed';
}

function isActiveEvmLeaseState(state: NonceLeaseState): boolean {
  return state === 'reserved' || state === 'signed' || state === 'broadcast_accepted';
}

function isSameOriginActiveEvmLeaseRecord(
  record: NonceCoordinatorSameOriginEvmLeaseRecord,
  nowMs: number,
): boolean {
  if (
    record.state !== 'reserved' &&
    record.state !== 'signed' &&
    record.state !== 'broadcast_accepted'
  ) {
    return false;
  }
  return record.expiresAtMs > nowMs;
}

function createDefaultSameOriginLock(): NonceCoordinatorSameOriginLockPort | null {
  const maybeNavigator = globalThis as {
    navigator?: {
      locks?: {
        request<T>(
          name: string,
          options: { mode: 'exclusive' },
          callback: () => Promise<T>,
        ): Promise<T>;
      };
    };
  };
  const locks = maybeNavigator.navigator?.locks;
  if (typeof locks?.request !== 'function') return null;
  return {
    async withLock<T>(key: string, task: () => Promise<T>): Promise<T> {
      return await locks.request(key, { mode: 'exclusive' }, task);
    },
  };
}

function createDefaultSameOriginLeaseStore(): NonceCoordinatorSameOriginLeaseStorePort | null {
  const maybeStorage = globalThis as { localStorage?: Storage };
  const storage = maybeStorage.localStorage;
  if (!storage) return null;
  try {
    const existing = storage.getItem(SAME_ORIGIN_EVM_LEASE_STORAGE_KEY);
    if (existing == null) {
      storage.setItem(SAME_ORIGIN_EVM_LEASE_STORAGE_KEY, '[]');
      storage.removeItem(SAME_ORIGIN_EVM_LEASE_STORAGE_KEY);
    }
  } catch {
    return null;
  }

  const readAll = (): NonceCoordinatorSameOriginEvmLeaseRecord[] => {
    try {
      const parsed = JSON.parse(storage.getItem(SAME_ORIGIN_EVM_LEASE_STORAGE_KEY) || '[]');
      if (!Array.isArray(parsed)) return [];
      return parsed.flatMap((entry) => {
        const record = parseSameOriginEvmLeaseRecord(entry);
        return record ? [record] : [];
      });
    } catch {
      return [];
    }
  };
  const writeAll = (records: NonceCoordinatorSameOriginEvmLeaseRecord[]): void => {
    try {
      storage.setItem(SAME_ORIGIN_EVM_LEASE_STORAGE_KEY, JSON.stringify(records));
    } catch {}
  };

  return {
    readLane(laneKey) {
      const normalizedLaneKey = String(laneKey || '').trim();
      if (!normalizedLaneKey) return [];
      return readAll().filter((record) => record.laneKey === normalizedLaneKey);
    },
    upsert(record) {
      const parsed = parseSameOriginEvmLeaseRecord(record);
      if (!parsed) return;
      const records = readAll().filter(
        (entry) => entry.laneKey !== parsed.laneKey || entry.leaseId !== parsed.leaseId,
      );
      records.push(parsed);
      writeAll(records);
    },
    remove(input) {
      const laneKey = String(input.laneKey || '').trim();
      const leaseId = String(input.leaseId || '').trim();
      if (!laneKey || !leaseId) return;
      writeAll(
        readAll().filter((entry) => entry.laneKey !== laneKey || entry.leaseId !== leaseId),
      );
    },
    clearForAccount(accountId) {
      const normalizedAccountId = String(accountId || '').trim();
      if (!normalizedAccountId) return;
      writeAll(readAll().filter((entry) => entry.accountId !== normalizedAccountId));
    },
    clearAll() {
      try {
        storage.removeItem(SAME_ORIGIN_EVM_LEASE_STORAGE_KEY);
      } catch {}
    },
  };
}

function parseSameOriginEvmLeaseRecord(
  value: unknown,
): NonceCoordinatorSameOriginEvmLeaseRecord | null {
  if (!isObject(value)) return null;
  const laneKey = String((value as { laneKey?: unknown }).laneKey || '').trim();
  const leaseId = String((value as { leaseId?: unknown }).leaseId || '').trim();
  const nonce = String((value as { nonce?: unknown }).nonce || '').trim();
  const state = (value as { state?: unknown }).state;
  const reservedAtMs = Math.floor(Number((value as { reservedAtMs?: unknown }).reservedAtMs));
  const expiresAtMs = Math.floor(Number((value as { expiresAtMs?: unknown }).expiresAtMs));
  const updatedAtMs = Math.floor(Number((value as { updatedAtMs?: unknown }).updatedAtMs));
  const accountId = String((value as { accountId?: unknown }).accountId || '').trim();
  if (!laneKey || !leaseId || !/^\d+$/.test(nonce)) return null;
  if (state !== 'reserved' && state !== 'signed' && state !== 'broadcast_accepted') return null;
  if (!Number.isSafeInteger(reservedAtMs) || !Number.isSafeInteger(expiresAtMs)) return null;
  if (!Number.isSafeInteger(updatedAtMs)) return null;
  return {
    laneKey,
    leaseId,
    nonce,
    state,
    reservedAtMs,
    expiresAtMs,
    updatedAtMs,
    ...(accountId ? { accountId } : {}),
  };
}

function createEvmNonceLaneBlockedError(args: {
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
    `[NonceCoordinator] nonce lane blocked on ${args.lane.networkKey} (nonce=${args.blockedNonce.toString()}) for ${args.ageMs}ms; reconcile or replace/dropped report required`,
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
    chain: args.lane.chain,
    networkKey: args.lane.networkKey,
    chainId: args.lane.chainId,
    blockedNonce: args.blockedNonce.toString(),
    ageMs: args.ageMs,
  };
  return error;
}

function isMissingNearAccessKeyError(message: string): boolean {
  return (
    message.includes('does not exist while viewing') ||
    message.includes('Access key not found') ||
    message.includes('unknown public key') ||
    message.includes('does not exist')
  );
}

function createIllegalNonceTransitionError(
  current: NonceLeaseState,
  transition: string,
): Error {
  return new Error(
    `[NonceCoordinator] illegal nonce lease transition: ${current} -> ${transition}`,
  );
}
