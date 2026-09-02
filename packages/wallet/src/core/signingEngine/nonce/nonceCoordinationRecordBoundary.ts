import {
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  NonceCoordinatorDegradationReason,
  NonceCoordinatorFallback,
  NonceDurableLeaseState,
  type NonceCoordinatorDegradation,
  type NonceDurableLeaseLifecycle,
  type EvmNonceLane,
  type NonceLaneCoordinationReadResult,
  type NonceLaneCoordinationRecord,
  type ParsedNonceLaneCoordinationRecord,
} from './nonceTypes';
import { nonceLaneKey } from './nonceLaneKeys';

export type RawNonceLaneCoordinationRecord = Record<string, unknown>;

export function parseNonceLaneCoordinationRecord(value: unknown): NonceLaneCoordinationReadResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return malformedRecordResult({}, '', '', '');
  }

  const obj = value as RawNonceLaneCoordinationRecord;
  const leaseId = rawString(obj.leaseId);
  const laneKey = rawString(obj.laneKey);
  const family = rawString(obj.family);
  const networkKey = rawString(obj.networkKey);
  const accountId = rawString(obj.accountId);
  const nearAccountId = rawString(obj.nearAccountId);

  if (obj.v !== 1) {
    return malformedRecordResult(obj, laneKey, leaseId, family);
  }

  const nonce = parseDecimalBigint(obj.nonce);
  const lifecycle = parseDurableLeaseLifecycle(obj);
  const operationId = rawString(obj.operationId);
  const operationFingerprint = rawString(obj.operationFingerprint);
  const reservedAtMs = parseSafeInteger(obj.reservedAtMs);
  const expiresAtMs = parseSafeInteger(obj.expiresAtMs);
  const updatedAtMs = parseSafeInteger(obj.updatedAtMs);
  if (
    !leaseId ||
    !laneKey ||
    (family !== 'evm' && family !== 'near') ||
    !networkKey ||
    nonce == null ||
    !lifecycle ||
    !operationId ||
    !operationFingerprint ||
    reservedAtMs == null ||
    expiresAtMs == null ||
    updatedAtMs == null
  ) {
    return malformedRecordResult(obj, laneKey, leaseId, family);
  }

  if (family === 'evm') {
    return parseEvmRecord({
      obj,
      leaseId,
      laneKey,
      networkKey,
      accountId,
      nearAccountId,
      nonce,
      lifecycle,
      operationId,
      operationFingerprint,
      reservedAtMs,
      expiresAtMs,
      updatedAtMs,
    });
  }

  return parseNearRecord({
    obj,
    leaseId,
    laneKey,
    networkKey,
    accountId,
    nearAccountId,
    nonce,
    lifecycle,
    operationId,
    operationFingerprint,
    reservedAtMs,
    expiresAtMs,
    updatedAtMs,
  });
}

type ParsedBaseInput = {
  obj: RawNonceLaneCoordinationRecord;
  leaseId: string;
  laneKey: string;
  networkKey: string;
  accountId: string;
  nearAccountId: string;
  nonce: bigint;
  lifecycle: NonceDurableLeaseLifecycle;
  operationId: string;
  operationFingerprint: string;
  reservedAtMs: number;
  expiresAtMs: number;
  updatedAtMs: number;
};

function parseEvmRecord(input: ParsedBaseInput): NonceLaneCoordinationReadResult {
  const chainTarget = parseChainTarget(input.obj.chainTarget);
  const sender = parseEvmAddress(input.obj.sender);
  const lifecycle = normalizeEvmDurableLifecycle(input.lifecycle);
  const nonceKey =
    input.obj.nonceKey === undefined || input.obj.nonceKey === null
      ? undefined
      : parseDecimalBigint(input.obj.nonceKey);
  if (!chainTarget || !input.accountId || !sender || !lifecycle || nonceKey === null) {
    return malformedRecordResult(input.obj, input.laneKey, input.leaseId, 'evm');
  }

  const record: Extract<NonceLaneCoordinationRecord, { family: 'evm' }> = {
    ...buildBaseRecord(input, lifecycle),
    family: 'evm',
    chainTarget,
    accountId: toWalletId(input.accountId),
    sender,
  };
  if (nonceKey !== undefined) {
    record.nonceKey = nonceKey;
  }

  const lane: EvmNonceLane = {
    family: 'evm',
    chainTarget: record.chainTarget,
    subjectId: record.accountId,
    sender: record.sender,
  };
  if (record.nonceKey != null) {
    lane.nonceKey = record.nonceKey;
  }

  return {
    ok: true,
    parsed: {
      record,
      lane,
      canonicalLaneKey: nonceLaneKey(lane),
      nonce: record.nonce,
    },
  };
}

function parseNearRecord(input: ParsedBaseInput): NonceLaneCoordinationReadResult {
  const publicKey = rawString(input.obj.publicKey);
  const walletId = rawString(input.obj.walletId);
  if (!input.nearAccountId || !walletId || !publicKey) {
    return malformedRecordResult(input.obj, input.laneKey, input.leaseId, 'near');
  }

  const record: Extract<NonceLaneCoordinationRecord, { family: 'near' }> = {
    ...buildBaseRecord(input, input.lifecycle),
    family: 'near',
    walletId,
    nearAccountId: input.nearAccountId,
    publicKey,
  };
  const lane = {
    family: 'near' as const,
    networkKey: record.networkKey,
    walletId: record.walletId,
    nearAccountId: record.nearAccountId,
    publicKey: record.publicKey,
  };

  return {
    ok: true,
    parsed: {
      record,
      lane,
      canonicalLaneKey: nonceLaneKey(lane),
      nonce: record.nonce,
    },
  };
}

type NonceLaneCoordinationRecordBaseFieldsWithoutLifecycle = {
  v: 1;
  laneKey: string;
  leaseId: string;
  networkKey: string;
  nonce: bigint;
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

type NonceLaneCoordinationRecordBaseFields<TTransactionHash extends string> =
  NonceLaneCoordinationRecordBaseFieldsWithoutLifecycle &
    NonceDurableLeaseLifecycle<TTransactionHash>;

function buildBaseRecord<TTransactionHash extends string>(
  input: ParsedBaseInput,
  lifecycle: NonceDurableLeaseLifecycle<TTransactionHash>,
): NonceLaneCoordinationRecordBaseFields<TTransactionHash> {
  const base: NonceLaneCoordinationRecordBaseFieldsWithoutLifecycle = {
    v: 1 as const,
    leaseId: input.leaseId,
    laneKey: input.laneKey,
    networkKey: input.networkKey,
    nonce: input.nonce,
    operationId: input.operationId,
    operationFingerprint: input.operationFingerprint,
    reservedAtMs: input.reservedAtMs,
    expiresAtMs: input.expiresAtMs,
    updatedAtMs: input.updatedAtMs,
  };
  const runtimeId = rawString(input.obj.runtimeId);
  if (runtimeId) base.runtimeId = runtimeId;
  const fencingToken = rawString(input.obj.fencingToken);
  if (fencingToken) base.fencingToken = fencingToken;
  const batchId = rawString(input.obj.batchId);
  if (batchId) base.batchId = batchId;
  const txIndex = input.obj.txIndex == null ? null : parseSafeInteger(input.obj.txIndex);
  if (txIndex != null) base.txIndex = txIndex;
  switch (lifecycle.state) {
    case NonceDurableLeaseState.Reserved:
    case NonceDurableLeaseState.Signed:
      return { ...base, state: lifecycle.state };
    case NonceDurableLeaseState.BroadcastAccepted:
      return {
        ...base,
        state: NonceDurableLeaseState.BroadcastAccepted,
        txHash: lifecycle.txHash,
      };
  }
}

function parseDurableLeaseLifecycle(
  obj: RawNonceLaneCoordinationRecord,
): NonceDurableLeaseLifecycle | null {
  if (obj.state === NonceDurableLeaseState.Reserved) {
    return obj.txHash === undefined ? { state: NonceDurableLeaseState.Reserved } : null;
  }
  if (obj.state === NonceDurableLeaseState.Signed) {
    return obj.txHash === undefined ? { state: NonceDurableLeaseState.Signed } : null;
  }
  if (obj.state === NonceDurableLeaseState.BroadcastAccepted) {
    const txHash = rawString(obj.txHash);
    if (txHash) {
      return { state: NonceDurableLeaseState.BroadcastAccepted, txHash };
    }
    // Pre-txHash records remain blocking signed leases until their existing expiry.
    return { state: NonceDurableLeaseState.Signed };
  }
  return null;
}

function normalizeEvmDurableLifecycle(
  lifecycle: NonceDurableLeaseLifecycle,
): NonceDurableLeaseLifecycle<`0x${string}`> {
  if (lifecycle.state !== NonceDurableLeaseState.BroadcastAccepted) {
    return lifecycle;
  }
  const txHash = parseTxHash(lifecycle.txHash);
  return txHash
    ? { state: NonceDurableLeaseState.BroadcastAccepted, txHash }
    : { state: NonceDurableLeaseState.Signed };
}

function parseTxHash(value: unknown): `0x${string}` | null {
  const normalized = rawString(value).toLowerCase();
  return /^0x[0-9a-f]{64}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

function parseChainTarget(value: unknown): ThresholdEcdsaChainTarget | null {
  try {
    return thresholdEcdsaChainTargetFromRequest(
      value && typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {},
    );
  } catch {
    return null;
  }
}

function malformedRecordResult(
  obj: RawNonceLaneCoordinationRecord,
  laneKey: string,
  leaseId: string,
  family: string,
): NonceLaneCoordinationReadResult {
  const degradation: NonceCoordinatorDegradation = {
    reason: NonceCoordinatorDegradationReason.MalformedDurableRecord,
    fallback: NonceCoordinatorFallback.None,
  };
  if (family === 'evm' || family === 'near') {
    degradation.laneFamily = family;
  }
  const networkKey = rawString(obj.networkKey);
  if (networkKey) degradation.networkKey = networkKey;
  const accountId = rawString(obj.walletId) || rawString(obj.accountId);
  if (accountId) degradation.accountId = accountId;
  return {
    ok: false,
    laneKey,
    leaseId,
    degradation,
  };
}

function parseEvmAddress(value: unknown): `0x${string}` | null {
  const sender = rawString(value).toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(sender) ? (sender as `0x${string}`) : null;
}

function rawString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseDecimalBigint(value: unknown): bigint | null {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return null;
  return BigInt(value);
}

function parseSafeInteger(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) ? value : null;
  }
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}
