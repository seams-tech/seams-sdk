import {
  fromManagedNonceReservationSnapshot,
  type NonceLaneStatus,
} from '@/core/rpcClients/evm/nonceBackend';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { evmManagedReservationToLane, type NonceCoordinator } from '../../nonce/NonceCoordinator';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import {
  createEvmFamilySigningNonceLaneBlockedError,
  extractErrorCode,
  isNonceConflictRetryableError,
  isNonceLaneBlockedRetryableError,
  mapToRetryableNonceStateError,
} from './errors';
import { emitEvmFamilyBroadcastEvent, type EvmFamilyManagedNonceReservation } from './events';
import type {
  EvmFamilyBroadcastAcceptedArgs,
  EvmFamilyBroadcastRejectedArgs,
  EvmFamilyDroppedOrReplacedArgs,
  EvmFamilyFinalizedArgs,
  EvmFamilyNonceLaneStatus,
  EvmFamilyReconcileLaneArgs,
} from './types';

export type EvmFamilyNonceLifecycleDeps = {
  nonceCoordinator: NonceCoordinator;
};

function toEvmFamilyManagedNonceReservationFromSignedResult(args: {
  signedResult: TempoSignedResult | EvmSignedResult;
  walletId: string;
}): EvmFamilyManagedNonceReservation {
  const snapshot = (args.signedResult as { managedNonce?: unknown }).managedNonce;
  if (!snapshot || typeof snapshot !== 'object') {
    throw new Error('[SigningEngine][evm-family] managedNonce is required for nonce lifecycle');
  }
  try {
    const parsed = fromManagedNonceReservationSnapshot(
      snapshot as Parameters<typeof fromManagedNonceReservationSnapshot>[0],
    );
    void args.walletId;
    return parsed;
  } catch (error: unknown) {
    throw new Error(
      `[SigningEngine][evm-family] invalid managedNonce: ${
        error instanceof Error ? error.message : String(error || 'unknown error')
      }`,
    );
  }
}

export async function releaseEvmFamilyNonceReservation(
  deps: EvmFamilyNonceLifecycleDeps,
  reservation: EvmFamilyManagedNonceReservation,
): Promise<void> {
  const leaseRef = requireManagedNonceLeaseRef(reservation);
  await deps.nonceCoordinator.release({
    ...leaseRef,
    reason: 'signing_failed',
  });
}

function formatNonceLaneStatus(status: NonceLaneStatus): EvmFamilyNonceLaneStatus {
  return {
    chainNextNonce: status.chainNextNonce.toString(),
    unresolvedInFlightNonces: status.unresolvedInFlightNonces.map((value) => value.toString()),
    blocked: status.blocked,
    ...(status.blockedNonce != null ? { blockedNonce: status.blockedNonce.toString() } : {}),
  };
}

export async function reportEvmFamilyBroadcastAccepted(
  deps: EvmFamilyNonceLifecycleDeps,
  args: EvmFamilyBroadcastAcceptedArgs,
): Promise<void> {
  const reservation = toEvmFamilyManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    walletId: args.walletId,
  });

  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
    status: 'running',
    message: 'Marking managed nonce lane as in-flight',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      nonce: reservation.nonce.toString(),
    },
  });
  const txHash = requireEvmFamilyBroadcastTxHash(
    args.txHash || (args.signedResult.chain === 'evm' ? args.signedResult.txHashHex : undefined),
  );
  await deps.nonceCoordinator.markBroadcastAccepted({
    ...requireManagedNonceLeaseRef(reservation),
    txHash,
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
    status: 'succeeded',
    message: 'Managed nonce lane marked in-flight',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      nonce: reservation.nonce.toString(),
      txHash,
    },
  });
}

function requireEvmFamilyBroadcastTxHash(value: unknown): `0x${string}` {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    throw new Error('[SigningEngine][evm-family] broadcast acceptance requires txHash');
  }
  return normalized as `0x${string}`;
}

export async function reportEvmFamilyBroadcastRejected(
  deps: EvmFamilyNonceLifecycleDeps,
  args: EvmFamilyBroadcastRejectedArgs,
): Promise<void> {
  const reservation = toEvmFamilyManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    walletId: args.walletId,
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_12_BROADCAST_REJECTED,
    status: 'running',
    message: 'Marking managed nonce reservation rejected',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      nonce: reservation.nonce.toString(),
    },
  });
  await deps.nonceCoordinator.markBroadcastRejected({
    ...requireManagedNonceLeaseRef(reservation),
    error: args.error,
  });
  const mappedError = mapToRetryableNonceStateError({
    error: args.error,
    chain: reservation.chainTarget.kind,
    networkKey: reservation.chainTarget.networkSlug,
    chainId: reservation.chainTarget.chainId,
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_12_BROADCAST_REJECTED,
    status: 'failed',
    message: 'Managed nonce reservation marked rejected',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      nonce: reservation.nonce.toString(),
    },
  });
  if (
    !isNonceConflictRetryableError(mappedError) &&
    !isNonceLaneBlockedRetryableError(mappedError)
  ) {
    return;
  }

  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
    status: 'running',
    message: 'Reconciling managed nonce lane after broadcast error',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      nonce: reservation.nonce.toString(),
      errorCode: extractErrorCode(mappedError),
    },
  });
  const laneStatus = await deps.nonceCoordinator
    .reconcile({ lane: evmManagedReservationToLane(reservation) })
    .catch(() => null);
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED,
    status: 'succeeded',
    message: 'Managed nonce lane reconciled',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      ...(laneStatus ? { laneStatus: formatNonceLaneStatus(laneStatus) } : {}),
    },
  });
  throw mappedError;
}

export async function reportEvmFamilyFinalized(
  deps: EvmFamilyNonceLifecycleDeps,
  args: EvmFamilyFinalizedArgs,
): Promise<void> {
  void args.receiptStatus;
  const reservation = toEvmFamilyManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    walletId: args.walletId,
  });
  const txHash =
    args.txHash ||
    (args.signedResult.chain === 'evm'
      ? (args.signedResult.txHashHex as `0x${string}`)
      : undefined);
  await deps.nonceCoordinator.markFinalized({
    ...requireManagedNonceLeaseRef(reservation),
    ...(txHash ? { txHash } : {}),
  });
}

export async function reportEvmFamilyDroppedOrReplaced(
  deps: EvmFamilyNonceLifecycleDeps,
  args: EvmFamilyDroppedOrReplacedArgs,
): Promise<void> {
  const reservation = toEvmFamilyManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    walletId: args.walletId,
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase:
      args.reason === 'replaced'
        ? SigningEventPhase.STEP_13_TRANSACTION_REPLACED
        : SigningEventPhase.STEP_13_TRANSACTION_DROPPED,
    status: 'running',
    message:
      args.reason === 'replaced'
        ? 'Marking managed nonce lane replaced'
        : 'Marking managed nonce lane dropped',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      nonce: reservation.nonce.toString(),
      reason: args.reason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
    },
  });
  await deps.nonceCoordinator.markDroppedOrReplaced({
    ...requireManagedNonceLeaseRef(reservation),
    reason: args.reason,
    ...(args.txHash ? { txHash: args.txHash } : {}),
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase:
      args.reason === 'replaced'
        ? SigningEventPhase.STEP_13_TRANSACTION_REPLACED
        : SigningEventPhase.STEP_13_TRANSACTION_DROPPED,
    status: args.reason === 'replaced' ? 'succeeded' : 'failed',
    message:
      args.reason === 'replaced'
        ? 'Managed nonce lane marked replaced'
        : 'Managed nonce lane marked dropped',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      nonce: reservation.nonce.toString(),
      reason: args.reason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
    },
  });
}

export async function reconcileEvmFamilyNonceLane(
  deps: EvmFamilyNonceLifecycleDeps,
  args: EvmFamilyReconcileLaneArgs,
): Promise<EvmFamilyNonceLaneStatus> {
  const reservation = toEvmFamilyManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    walletId: args.walletId,
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
    status: 'running',
    message: 'Reconciling managed nonce lane',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
    },
  });
  const laneStatus = await deps.nonceCoordinator.reconcile({
    lane: evmManagedReservationToLane(reservation),
  });
  const formatted = formatNonceLaneStatus(laneStatus);
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    walletId: args.walletId,
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED,
    status: 'succeeded',
    message: 'Managed nonce lane reconciled',
    data: {
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId.toString(),
      laneStatus: formatted,
    },
  });
  if (laneStatus.blocked) {
    throw createEvmFamilySigningNonceLaneBlockedError({
      chain: reservation.chainTarget.kind,
      networkKey: reservation.chainTarget.networkSlug,
      chainId: reservation.chainTarget.chainId,
      blockedNonce: String(formatted.blockedNonce || 'unknown'),
    });
  }
  return formatted;
}

function requireManagedNonceLeaseRef(reservation: EvmFamilyManagedNonceReservation): {
  leaseId: string;
  operationId: string;
  operationFingerprint: string;
} {
  const leaseId = String(reservation.leaseId || '').trim();
  const operationId = String(reservation.operationId || '').trim();
  const operationFingerprint = String(reservation.operationFingerprint || '').trim();
  if (!leaseId || !operationId || !operationFingerprint) {
    throw new Error('[SigningEngine][evm-family] managedNonce lease metadata is required');
  }
  return { leaseId, operationId, operationFingerprint };
}
