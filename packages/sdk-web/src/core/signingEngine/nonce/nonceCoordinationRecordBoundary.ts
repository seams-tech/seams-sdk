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
  type EvmNonceLane,
  type NonceLaneCoordinationReadResult,
  type NonceLaneCoordinationRecord,
  type ParsedNonceLaneCoordinationRecord,
} from './nonceTypes';
import { nonceLaneKey } from './nonceLaneKeys';

export type RawNonceLaneCoordinationRecord = Record<string, unknown>;

export function parseNonceLaneCoordinationRecord(
  value: unknown,
): NonceLaneCoordinationReadResult {
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
  const state = parseDurableLeaseState(obj.state);
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
    !state ||
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
      state,
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
    state,
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
  state: NonceLaneCoordinationRecord['state'];
  operationId: string;
  operationFingerprint: string;
  reservedAtMs: number;
  expiresAtMs: number;
  updatedAtMs: number;
};

function parseEvmRecord(input: ParsedBaseInput): NonceLaneCoordinationReadResult {
  const chainTarget = parseChainTarget(input.obj.chainTarget);
  const sender = parseEvmAddress(input.obj.sender);
  const nonceKey =
    input.obj.nonceKey === undefined || input.obj.nonceKey === null
      ? undefined
      : parseDecimalBigint(input.obj.nonceKey);
  if (!chainTarget || !input.accountId || !sender || nonceKey === null) {
    return malformedRecordResult(input.obj, input.laneKey, input.leaseId, 'evm');
  }

  const record: Extract<NonceLaneCoordinationRecord, { family: 'evm' }> = {
    ...buildBaseRecord(input),
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
    ...buildBaseRecord(input),
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

type NonceLaneCoordinationRecordBaseFields = {
  v: 1;
  laneKey: string;
  leaseId: string;
  networkKey: string;
  nonce: bigint;
  state: NonceLaneCoordinationRecord['state'];
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

function buildBaseRecord(input: ParsedBaseInput): NonceLaneCoordinationRecordBaseFields {
  const record: NonceLaneCoordinationRecordBaseFields = {
    v: 1 as const,
    leaseId: input.leaseId,
    laneKey: input.laneKey,
    networkKey: input.networkKey,
    nonce: input.nonce,
    state: input.state,
    operationId: input.operationId,
    operationFingerprint: input.operationFingerprint,
    reservedAtMs: input.reservedAtMs,
    expiresAtMs: input.expiresAtMs,
    updatedAtMs: input.updatedAtMs,
  };
  const runtimeId = rawString(input.obj.runtimeId);
  if (runtimeId) record.runtimeId = runtimeId;
  const fencingToken = rawString(input.obj.fencingToken);
  if (fencingToken) record.fencingToken = fencingToken;
  const batchId = rawString(input.obj.batchId);
  if (batchId) record.batchId = batchId;
  const txIndex = input.obj.txIndex == null ? null : parseSafeInteger(input.obj.txIndex);
  if (txIndex != null) record.txIndex = txIndex;
  return record;
}

function parseDurableLeaseState(value: unknown): NonceLaneCoordinationRecord['state'] | null {
  if (
    value === NonceDurableLeaseState.Reserved ||
    value === NonceDurableLeaseState.Signed ||
    value === NonceDurableLeaseState.BroadcastAccepted
  ) {
    return value;
  }
  return null;
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
  const accountId = rawString(obj.walletId) || rawString(obj.accountId) || rawString(obj.nearAccountId);
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
