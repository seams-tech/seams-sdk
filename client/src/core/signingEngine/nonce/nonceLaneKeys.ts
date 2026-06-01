import type {
  EvmNonceChain,
  ManagedNonceReservation,
  ReserveNonceInput,
} from '@/core/rpcClients/evm/nonceBackend';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { secureRandomId } from '@shared/utils/secureRandomId';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '../session/operationState/types';
import type { NonceLeaseRef } from '../interfaces/nonceLease';
import type {
  EvmNonceLane,
  NearNonceLane,
  NonceLane,
  NonceLaneCoordinationRecord,
  NonceLease,
} from './nonceTypes';
import { normalizeBigint, normalizeRequiredString } from './nonceUtils';

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

export function nonceLaneNetworkKey(lane: NonceLane | undefined): string {
  if (!lane) return '';
  if (lane.family === 'near') return normalizeRequiredString(lane.networkKey, 'networkKey');
  return thresholdEcdsaChainTargetKey(lane.chainTarget);
}

export function nonceLaneSubjectId(lane: NonceLane | undefined): string {
  if (!lane) return '';
  return lane.family === 'near'
    ? normalizeRequiredString(lane.accountId, 'accountId')
    : String(lane.subjectId);
}

export function nonceLaneKey(lane: NonceLane): string {
  if (lane.family === 'near') {
    return nearNonceLaneKey(lane);
  }
  return encodeNonceKeyParts([
    'evm',
    thresholdEcdsaChainTargetKey(lane.chainTarget),
    normalizeRequiredString(lane.subjectId, 'subjectId'),
    normalizeRequiredString(lane.sender, 'sender').toLowerCase(),
    lane.nonceKey != null ? String(lane.nonceKey) : '',
  ]);
}

export function legacyNonceLaneKeys(lane: NonceLane): string[] {
  if (lane.family === 'near') {
    return [
      encodeLegacyPersistenceLaneKey([
        'near',
        normalizeRequiredString(lane.networkKey, 'networkKey'),
        normalizeRequiredString(lane.accountId, 'accountId'),
        normalizeRequiredString(lane.publicKey, 'publicKey'),
      ]),
    ];
  }
  return [
    encodeLegacyPersistenceLaneKey([
      'evm',
      thresholdEcdsaChainTargetKey(lane.chainTarget),
      normalizeRequiredString(lane.subjectId, 'subjectId'),
      normalizeRequiredString(lane.sender, 'sender').toLowerCase(),
      lane.nonceKey != null ? String(lane.nonceKey) : '',
    ]),
    encodeLegacyPersistenceLaneKey([
      'evm',
      lane.chainTarget.kind,
      lane.chainTarget.networkSlug,
      String(lane.chainTarget.chainId),
      normalizeRequiredString(lane.sender, 'sender').toLowerCase(),
      lane.nonceKey != null ? String(lane.nonceKey) : '',
    ]),
  ];
}

export function nearNonceLaneKey(lane: NearNonceLane): string {
  return encodeNonceKeyParts([
    'near',
    normalizeRequiredString(lane.networkKey, 'networkKey'),
    normalizeRequiredString(lane.accountId, 'accountId'),
    normalizeRequiredString(lane.publicKey, 'publicKey'),
  ]);
}

export function assertEvmLease(
  lease: NonceLease,
): asserts lease is NonceLease & { lane: EvmNonceLane } {
  if (lease.lane.family !== 'evm') {
    throw new Error('[NonceCoordinator] expected an EVM-family nonce lease');
  }
}

export function assertOperationMatches(
  lease: NonceLease,
  operationId: SigningOperationId | string,
  operationFingerprint: SigningOperationFingerprint | string,
): void {
  if (String(lease.operationId) !== String(operationId || '')) {
    throw new Error('[NonceCoordinator] nonce lease operation mismatch');
  }
  if (String(lease.operationFingerprint) !== String(operationFingerprint || '')) {
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

export function encodeNonceKeyParts(parts: readonly unknown[]): string {
  return parts
    .map((part) => {
      const value = String(part);
      return `${value.length}:${value}`;
    })
    .join('|');
}

function encodeLegacyPersistenceLaneKey(parts: readonly unknown[]): string {
  let key = '';
  for (const part of parts) {
    key = key ? `${key}:${String(part)}` : String(part);
  }
  return key;
}

export function nonceLaneFromCoordinationRecord(
  record: NonceLaneCoordinationRecord,
): NonceLane | null {
  if (record.family === 'evm') {
    if (!record.chainTarget || !record.sender || !record.accountId) {
      return null;
    }
    return {
      family: 'evm',
      chainTarget: record.chainTarget,
      subjectId: toWalletId(record.accountId),
      sender: normalizeRequiredString(record.sender, 'sender').toLowerCase() as `0x${string}`,
      ...(record.nonceKey ? { nonceKey: normalizeBigint(record.nonceKey, 'nonceKey') } : {}),
    };
  }
  if (record.family === 'near') {
    if (!record.accountId || !record.publicKey) return null;
    return {
      family: 'near',
      networkKey: normalizeRequiredString(record.networkKey, 'networkKey'),
      accountId: record.accountId,
      publicKey: record.publicKey,
    };
  }
  return null;
}

export function createRuntimeId(): string {
  return secureRandomId('nonce-runtime', 32, 'nonce runtime IDs');
}
