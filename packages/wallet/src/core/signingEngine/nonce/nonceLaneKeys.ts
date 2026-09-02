import type {
  EvmNonceChain,
  ManagedNonceReservation,
  ReserveNonceInput,
} from '@/core/rpcClients/evm/nonceBackend';
import {
  thresholdEcdsaChainTargetKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { secureRandomId } from '@shared/utils/secureRandomId';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '../session/operationState/types';
import type { NonceLeaseRef } from '../interfaces/nonceLease';
import type {
  EvmNonceLane,
  EvmNonceLease,
  NearNonceLane,
  NonceLane,
  NonceLease,
} from './nonceTypes';

export function evmReserveNonceInputToLane(input: ReserveNonceInput): EvmNonceLane {
  return {
    family: 'evm',
    chainTarget: input.chainTarget,
    subjectId: input.subjectId,
    sender: input.sender,
    ...(input.nonceKey != null ? { nonceKey: input.nonceKey } : {}),
  };
}

export function evmNonceLeaseToManagedReservation(lease: NonceLease): ManagedNonceReservation {
  assertEvmLease(lease);
  return {
    ...evmLaneToReserveNonceInput(lease.lane),
    nonce: lease.nonce,
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
    operationFingerprint: String(lease.operationFingerprint),
    nonce: String(lease.nonce),
    ...(lease.batchId ? { batchId: lease.batchId } : {}),
    ...(Number.isSafeInteger(lease.txIndex) ? { txIndex: lease.txIndex } : {}),
  };
}

export function evmLaneToReserveNonceInput(lane: EvmNonceLane): ReserveNonceInput {
  return {
    chainTarget: lane.chainTarget,
    subjectId: lane.subjectId,
    sender: lane.sender,
    ...(lane.nonceKey != null ? { nonceKey: lane.nonceKey } : {}),
  };
}

export function nonceLaneNetworkKey(lane: NonceLane): string {
  if (lane.family === 'near') return lane.networkKey;
  return thresholdEcdsaChainTargetKey(lane.chainTarget);
}

export function nonceLaneSubjectId(lane: NonceLane): string {
  return lane.family === 'near' ? lane.walletId : lane.subjectId;
}

export function nonceLaneKey(lane: NonceLane): string {
  if (lane.family === 'near') {
    return nearNonceLaneKey(lane);
  }
  return encodeNonceKeyParts([
    'evm',
    thresholdEcdsaChainTargetKey(lane.chainTarget),
    lane.subjectId,
    lane.sender.toLowerCase(),
    lane.nonceKey != null ? String(lane.nonceKey) : '',
  ]);
}

export function nearNonceLaneKey(lane: NearNonceLane): string {
  return encodeNonceKeyParts(['near', lane.networkKey, lane.walletId, lane.nearAccountId, lane.publicKey]);
}

export function assertEvmLease(
  lease: NonceLease,
): asserts lease is EvmNonceLease {
  if (lease.lane.family !== 'evm') {
    throw new Error('[NonceCoordinator] expected an EVM-family nonce lease');
  }
}

export function assertOperationMatches(
  lease: NonceLease,
  operationId: SigningOperationId,
  operationFingerprint: SigningOperationFingerprint,
): void {
  if (lease.operationId !== operationId) {
    throw new Error('[NonceCoordinator] nonce lease operation mismatch');
  }
  if (lease.operationFingerprint !== operationFingerprint) {
    throw new Error('[NonceCoordinator] nonce lease operation fingerprint mismatch');
  }
}

export function createNonceLeaseId(args: {
  operationId: SigningOperationId;
  chain: EvmNonceChain | 'near';
  nonce: bigint | string;
}): string {
  const randomId = secureRandomId('nonce-lease', 32, 'nonce lease IDs');
  return `nonce-lease-v1:${encodeNonceKeyParts([
    args.chain,
    args.operationId,
    args.nonce,
    randomId,
  ])}`;
}

export function createNonceBatchId(args: {
  operationId: SigningOperationId;
  chain: EvmNonceChain | 'near';
  firstNonce: bigint | string;
  count: number;
}): string {
  const randomId = secureRandomId('nonce-batch', 32, 'nonce batch IDs');
  return `nonce-batch-v1:${encodeNonceKeyParts([
    args.chain,
    args.operationId,
    args.firstNonce,
    args.count,
    randomId,
  ])}`;
}

export function encodeNonceKeyParts(parts: readonly (string | number | bigint)[]): string {
  return parts
    .map((part) => {
      const value = String(part);
      return `${value.length}:${value}`;
    })
    .join('|');
}

export function createRuntimeId(): string {
  return secureRandomId('nonce-runtime', 32, 'nonce runtime IDs');
}
