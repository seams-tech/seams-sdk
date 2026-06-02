import type {
  EvmNonceBackend,
  EvmNonceChain,
  NonceLaneStatus,
} from '@/core/rpcClients/evm/nonceBackend';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { TransactionContext } from '@/core/types/rpc';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  SigningOperationContext,
  SigningOperationFingerprint,
  SigningOperationId,
} from '../session/operationState/types';

export const NonceLeaseState = {
  Reserved: 'reserved',
  Released: 'released',
  Expired: 'expired',
  Signed: 'signed',
  SignedLeaseExpired: 'signed_lease_expired',
  BroadcastAccepted: 'broadcast_accepted',
  BroadcastRejected: 'broadcast_rejected',
  Finalized: 'finalized',
  Dropped: 'dropped',
  Replaced: 'replaced',
  Reconciled: 'reconciled',
} as const;

export type NonceLeaseState = (typeof NonceLeaseState)[keyof typeof NonceLeaseState];

export const NonceDurableLeaseState = {
  Reserved: NonceLeaseState.Reserved,
  Signed: NonceLeaseState.Signed,
  BroadcastAccepted: NonceLeaseState.BroadcastAccepted,
} as const;

export type NonceDurableLeaseState =
  (typeof NonceDurableLeaseState)[keyof typeof NonceDurableLeaseState];

export const NonceCoordinatorTraceEventName = {
  LeaseReserved: 'nonce_lease_reserved',
  LeaseReleased: 'nonce_lease_released',
  LeaseExpired: 'nonce_lease_expired',
  LeaseSigned: 'nonce_lease_signed',
  LeaseBroadcastAccepted: 'nonce_lease_broadcast_accepted',
  LeaseBroadcastRejected: 'nonce_lease_broadcast_rejected',
  LeaseFinalized: 'nonce_lease_finalized',
  LeaseDropped: 'nonce_lease_dropped',
  LeaseReplaced: 'nonce_lease_replaced',
  Metrics: 'nonce_coordinator_metrics',
  LaneAlert: 'nonce_lane_alert',
  CoordinationDegraded: 'nonce_coordination_degraded',
  LanesCleared: 'nonce_lanes_cleared',
  LaneReconciled: 'nonce_lane_reconciled',
} as const;

export type NonceCoordinatorTraceEventName =
  (typeof NonceCoordinatorTraceEventName)[keyof typeof NonceCoordinatorTraceEventName];

export const EvmNonceOutcomeReason = {
  Dropped: 'dropped',
  Replaced: 'replaced',
} as const;

export type EvmNonceOutcomeReason =
  (typeof EvmNonceOutcomeReason)[keyof typeof EvmNonceOutcomeReason];

export const NonceLeaseReleaseReason = {
  Cancelled: 'cancelled',
  AuthFailed: 'auth_failed',
  SigningFailed: 'signing_failed',
  NonceFailed: 'nonce_failed',
} as const;

export type NonceLeaseReleaseReason =
  (typeof NonceLeaseReleaseReason)[keyof typeof NonceLeaseReleaseReason];

export const NonceCoordinatorDegradationReason = {
  WebLocksUnavailable: 'web_locks_unavailable',
  IndexedDBUnavailable: 'indexeddb_unavailable',
  DurableLockTimeout: 'durable_lock_timeout',
  DurableStoreError: 'durable_store_error',
  MalformedDurableRecord: 'malformed_durable_record',
} as const;

export type NonceCoordinatorDegradationReason =
  (typeof NonceCoordinatorDegradationReason)[keyof typeof NonceCoordinatorDegradationReason];

export const NonceCoordinatorFallback = {
  InRuntimeLock: 'in_runtime_lock',
  None: 'none',
} as const;

export type NonceCoordinatorFallback =
  (typeof NonceCoordinatorFallback)[keyof typeof NonceCoordinatorFallback];

export const NearNonceOutcomeKind = {
  Finalized: 'finalized',
  AcceptedNonfinal: 'accepted_nonfinal',
  NonceAdvancedHashMissing: 'nonce_advanced_hash_missing',
  ExpiredHashMissingNonceNotAdvanced: 'expired_hash_missing_nonce_not_advanced',
  InvalidOrRejected: 'invalid_or_rejected',
  Unknown: 'unknown',
} as const;

export type NearNonceOutcomeKind = (typeof NearNonceOutcomeKind)[keyof typeof NearNonceOutcomeKind];

export const NearNonceReconcileReason = {
  NonceAdvancedHashMissing: 'near_nonce_advanced_hash_missing',
  HashMissingNonceNotAdvanced: 'near_hash_missing_nonce_not_advanced',
} as const;

export type NearNonceReconcileReason =
  (typeof NearNonceReconcileReason)[keyof typeof NearNonceReconcileReason];

export type EvmNonceLane = {
  family: 'evm';
  chainTarget: ThresholdEcdsaChainTarget;
  subjectId: WalletId;
  sender: `0x${string}`;
  nonceKey?: bigint;
};

export type NearNonceLane = {
  family: 'near';
  networkKey: string;
  accountId: string;
  publicKey: string;
};

export type NonceLane = EvmNonceLane | NearNonceLane;

export type PreparedNonceOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
  accountId: string;
};

type NonceLeaseBase = {
  leaseId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  state: NonceLeaseState;
  reservedAtMs: number;
  expiresAtMs: number;
  batchId?: string;
  txIndex?: number;
};

export type EvmNonceLease = NonceLeaseBase & {
  lane: EvmNonceLane;
  nonce: bigint;
};

export type NearNonceLease = NonceLeaseBase & {
  lane: NearNonceLane;
  nonce: string;
};

export type NonceLease = EvmNonceLease | NearNonceLease;

export type NonceCoordinatorTraceEvent = {
  event: NonceCoordinatorTraceEventName;
  lease?: NonceLease;
  lane?: NonceLane;
  metrics?: NonceCoordinatorAggregateMetrics;
  previousState?: NonceLeaseState;
  nextState?: NonceLeaseState;
  reason?: string;
  txHash?: string;
  accountId?: string;
  alert?: NonceCoordinatorAlert;
  degradation?: NonceCoordinatorDegradation;
};

export type NonceCoordinatorAlert = {
  kind: 'repeated_dropped_or_replaced';
  severity: 'warning';
  lane: NonceLane;
  reason: EvmNonceOutcomeReason;
  count: number;
  windowMs: number;
  firstSeenAtMs: number;
  lastSeenAtMs: number;
};

export type NonceCoordinatorSameOriginLockPort = {
  withLock<T>(key: string, task: () => Promise<T>): Promise<T>;
};

type NonceLaneCoordinationRecordBase = {
  v: 1;
  laneKey: string;
  leaseId: string;
  networkKey: string;
  nonce: bigint;
  state: NonceDurableLeaseState;
  operationId: string;
  operationFingerprint: string;
  reservedAtMs: number;
  expiresAtMs: number;
  updatedAtMs: number;
  runtimeId?: string;
  fencingToken?: string;
  batchId?: string;
  txIndex?: number;
};

export type NonceLaneCoordinationRecord =
  | (NonceLaneCoordinationRecordBase & {
      family: 'evm';
      chainTarget: ThresholdEcdsaChainTarget;
      accountId: WalletId;
      sender: `0x${string}`;
      nonceKey?: bigint;
    })
  | (NonceLaneCoordinationRecordBase & {
      family: 'near';
      accountId: string;
      publicKey: string;
    });

export type ParsedNonceLaneCoordinationRecord =
  | {
      record: Extract<NonceLaneCoordinationRecord, { family: 'evm' }>;
      lane: EvmNonceLane;
      canonicalLaneKey: string;
      nonce: bigint;
    }
  | {
      record: Extract<NonceLaneCoordinationRecord, { family: 'near' }>;
      lane: NearNonceLane;
      canonicalLaneKey: string;
      nonce: bigint;
    };

export type NonceLaneCoordinationReadFailure = {
  ok: false;
  degradation: NonceCoordinatorDegradation;
  laneKey: string;
  leaseId: string;
};

export type NonceLaneCoordinationReadResult =
  | { ok: true; parsed: ParsedNonceLaneCoordinationRecord }
  | NonceLaneCoordinationReadFailure;

export type NonceLaneCoordinationStore = {
  readLane(laneKey: string): Promise<ParsedNonceLaneCoordinationRecord[]>;
  readAll(input?: { accountId?: string }): Promise<ParsedNonceLaneCoordinationRecord[]>;
  readAllForRecovery(input?: { accountId?: string }): Promise<NonceLaneCoordinationReadResult[]>;
  upsert(record: NonceLaneCoordinationRecord): Promise<void>;
  remove(input: { laneKey: string; leaseId: string }): Promise<void>;
  clearForAccount(accountId: string): Promise<void>;
  clearAll(): Promise<void>;
  pruneExpired(nowMs: number): Promise<void>;
  withLock?<T>(
    input: { lockKey: string; ownerId: string; ttlMs: number; waitTimeoutMs?: number },
    task: () => Promise<T>,
  ): Promise<T>;
};

export type NonceCoordinatorDegradation = {
  reason: NonceCoordinatorDegradationReason;
  laneFamily?: NonceLane['family'];
  networkKey?: string;
  accountId?: string;
  fallback: NonceCoordinatorFallback;
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
  nonceLaneCoordinationStore?: NonceLaneCoordinationStore | null;
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
  outcomes: NonceCoordinatorOutcomeMetrics;
};

export type NonceCoordinatorOutcomeMetrics = {
  droppedCount: number;
  replacedCount: number;
  reconciledCount: number;
  releasedCount: number;
  expiredCount: number;
  broadcastRejectedCount: number;
  releaseReasons: Record<string, number>;
  reconcileReasons: Record<string, number>;
  expiryReasons: Record<string, number>;
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
  coordinationWarnings: NonceCoordinatorDegradation[];
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
    operation: PreparedNonceOperationContext;
  }): Promise<NonceLease>;
  reserveBatch(input: {
    lane: NearNonceLane;
    operation: PreparedNonceOperationContext;
    count: number;
  }): Promise<NonceLease[]>;
  reserveNearContext(input: {
    lane: NearNonceLane;
    operation: PreparedNonceOperationContext;
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
    operationFingerprint: SigningOperationFingerprint | string;
    signedTxHash?: string;
  }): Promise<void>;
  markBroadcastAccepted(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    operationFingerprint: SigningOperationFingerprint | string;
    txHash?: `0x${string}` | string;
  }): Promise<void>;
  markBroadcastRejected(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    operationFingerprint: SigningOperationFingerprint | string;
    error?: unknown;
  }): Promise<void>;
  markFinalized(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    operationFingerprint: SigningOperationFingerprint | string;
    txHash?: `0x${string}` | string;
  }): Promise<void>;
  markDroppedOrReplaced(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    operationFingerprint: SigningOperationFingerprint | string;
    reason: EvmNonceOutcomeReason;
    txHash?: `0x${string}` | string;
  }): Promise<void>;
  release(input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    operationFingerprint: SigningOperationFingerprint | string;
    reason: NonceLeaseReleaseReason;
  }): Promise<void>;
  expireLeases(input?: { accountId?: string }): Promise<NonceLease[]>;
  recoverDurableLeases(input?: { accountId?: string }): Promise<void>;
  reconcile(input: { lane: NonceLane }): Promise<NonceLaneStatus>;
  clearForAccount(accountId: string): void;
  clearAll(): void;
  getDiagnostics(input?: NonceCoordinatorDiagnosticsOptions): NonceCoordinatorDiagnostics;
};

export const NONCE_LEASE_STATES: readonly NonceLeaseState[] = Object.values(NonceLeaseState);
