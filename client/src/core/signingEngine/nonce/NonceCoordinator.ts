import type {
  EvmNonceChain,
  EvmNonceManager,
  ManagedNonceReservation,
  NonceLaneStatus,
  ReserveNonceInput,
} from '@/core/rpcClients/evm/nonceManager';
import type {
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

export type NonceOperationContext = {
  operationId: SigningOperationId;
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
};

export type NonceCoordinatorTraceEvent = {
  event:
    | 'nonce_lease_reserved'
    | 'nonce_lease_released'
    | 'nonce_lease_signed'
    | 'nonce_lease_broadcast_accepted'
    | 'nonce_lease_broadcast_rejected'
    | 'nonce_lease_finalized'
    | 'nonce_lease_dropped'
    | 'nonce_lease_replaced'
    | 'nonce_lane_reconciled';
  lease?: NonceLease;
  lane?: NonceLane;
  previousState?: NonceLeaseState;
  nextState?: NonceLeaseState;
  reason?: string;
  txHash?: string;
};

export type NonceCoordinatorDeps = {
  evmNonceManager: EvmNonceManager;
  now?: () => number;
  leaseTtlMs?: number;
  onTrace?: (event: NonceCoordinatorTraceEvent) => void;
};

export type NonceCoordinator = {
  reserve(input: {
    lane: NonceLane;
    operation: NonceOperationContext;
    count?: number;
  }): Promise<NonceLease>;
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
  reconcile(input: { lane: NonceLane }): Promise<NonceLaneStatus>;
  clearForAccount(accountId: string): void;
};

const DEFAULT_NONCE_LEASE_TTL_MS = 120_000;

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

export function createNonceCoordinator(deps: NonceCoordinatorDeps): NonceCoordinator {
  const leases = new Map<string, NonceLease>();
  const now = deps.now || Date.now;
  const leaseTtlMs = normalizePositiveInteger(deps.leaseTtlMs, DEFAULT_NONCE_LEASE_TTL_MS);

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
  }): void => {
    const previousState = args.lease.state;
    const nextState = reduceNonceLeaseState(previousState, args.transition);
    args.lease.state = nextState;
    emit({
      event: args.event,
      lease: args.lease,
      previousState,
      nextState,
      ...(args.reason ? { reason: args.reason } : {}),
      ...(args.txHash ? { txHash: args.txHash } : {}),
    });
  };

  return {
    async reserve(input) {
      if (input.lane.family !== 'evm') {
        throw new Error('[NonceCoordinator] NEAR nonce lanes are not wired yet');
      }
      const count = Math.max(1, Math.floor(Number(input.count || 1)));
      if (count !== 1) {
        throw new Error('[NonceCoordinator] EVM nonce leases support exactly one nonce');
      }
      const reservationInput = evmLaneToReserveNonceInput(input.lane);
      const nonce = await deps.evmNonceManager.reserveNextNonce(reservationInput);
      const reservedAtMs = now();
      const lease: NonceLease = {
        leaseId: createNonceLeaseId({
          operationId: input.operation.operationId,
          chain: input.lane.chain,
          nonce,
        }),
        lane: input.lane,
        operationId: input.operation.operationId,
        operationFingerprint: input.operation.operationFingerprint,
        nonce,
        state: 'reserved',
        reservedAtMs,
        expiresAtMs: reservedAtMs + leaseTtlMs,
      };
      leases.set(lease.leaseId, lease);
      emit({ event: 'nonce_lease_reserved', lease });
      return { ...lease };
    },

    async markSigned(input) {
      const lease = readLease(input);
      transitionLease({
        lease,
        transition: 'mark_signed',
        event: 'nonce_lease_signed',
        ...(input.signedTxHash ? { txHash: input.signedTxHash } : {}),
      });
    },

    async markBroadcastAccepted(input) {
      const lease = readLease(input);
      assertEvmLease(lease);
      await deps.evmNonceManager.markBroadcastAccepted({
        ...evmLaneToReserveNonceInput(lease.lane),
        nonce: normalizeBigint(lease.nonce, 'nonce'),
        ...(input.txHash ? { txHash: input.txHash as `0x${string}` } : {}),
      });
      transitionLease({
        lease,
        transition: 'broadcast_accepted',
        event: 'nonce_lease_broadcast_accepted',
        ...(input.txHash ? { txHash: String(input.txHash) } : {}),
      });
    },

    async markBroadcastRejected(input) {
      const lease = readLease(input);
      assertEvmLease(lease);
      await deps.evmNonceManager.markBroadcastRejected({
        ...evmLaneToReserveNonceInput(lease.lane),
        nonce: normalizeBigint(lease.nonce, 'nonce'),
      });
      transitionLease({
        lease,
        transition: 'broadcast_rejected',
        event: 'nonce_lease_broadcast_rejected',
        reason: input.error instanceof Error ? input.error.message : String(input.error || ''),
      });
    },

    async markFinalized(input) {
      const lease = readLease(input);
      assertEvmLease(lease);
      await deps.evmNonceManager.markFinalized({
        ...evmLaneToReserveNonceInput(lease.lane),
        nonce: normalizeBigint(lease.nonce, 'nonce'),
        ...(input.txHash ? { txHash: input.txHash as `0x${string}` } : {}),
      });
      transitionLease({
        lease,
        transition: 'finalize',
        event: 'nonce_lease_finalized',
        ...(input.txHash ? { txHash: String(input.txHash) } : {}),
      });
    },

    async markDroppedOrReplaced(input) {
      const lease = readLease(input);
      assertEvmLease(lease);
      await deps.evmNonceManager.markDroppedOrReplaced({
        ...evmLaneToReserveNonceInput(lease.lane),
        nonce: normalizeBigint(lease.nonce, 'nonce'),
        reason: input.reason,
        ...(input.txHash ? { txHash: input.txHash as `0x${string}` } : {}),
      });
      transitionLease({
        lease,
        transition: input.reason === 'replaced' ? 'replace' : 'drop',
        event:
          input.reason === 'replaced' ? 'nonce_lease_replaced' : 'nonce_lease_dropped',
        reason: input.reason,
        ...(input.txHash ? { txHash: String(input.txHash) } : {}),
      });
    },

    async release(input) {
      const lease = readLease(input);
      assertEvmLease(lease);
      await deps.evmNonceManager.markBroadcastRejected({
        ...evmLaneToReserveNonceInput(lease.lane),
        nonce: normalizeBigint(lease.nonce, 'nonce'),
      });
      transitionLease({
        lease,
        transition: 'release',
        event: 'nonce_lease_released',
        reason: input.reason,
      });
    },

    async reconcile(input) {
      if (input.lane.family !== 'evm') {
        throw new Error('[NonceCoordinator] NEAR nonce lanes are not wired yet');
      }
      const status = await deps.evmNonceManager.reconcileLane(
        evmLaneToReserveNonceInput(input.lane),
      );
      emit({ event: 'nonce_lane_reconciled', lane: input.lane });
      return status;
    },

    clearForAccount(accountId) {
      deps.evmNonceManager.clearForAccount(accountId);
      for (const [leaseId, lease] of leases.entries()) {
        if (lease.lane.family === 'evm' && lease.lane.accountId === accountId) {
          leases.delete(leaseId);
        }
        if (lease.lane.family === 'near' && lease.lane.accountId === accountId) {
          leases.delete(leaseId);
        }
      }
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
  chain: EvmNonceChain;
  nonce: bigint;
}): string {
  const randomId =
    typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  return `nonce-lease-v1:${args.chain}:${args.operationId}:${args.nonce.toString()}:${randomId}`;
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

function createIllegalNonceTransitionError(
  current: NonceLeaseState,
  transition: string,
): Error {
  return new Error(
    `[NonceCoordinator] illegal nonce lease transition: ${current} -> ${transition}`,
  );
}
