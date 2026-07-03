import { toOptionalTrimmedString } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import type {
  RecoveryExecutionRecord,
  RecoveryExecutionStatus,
  RecoveryExecutionStore,
} from '../RecoveryExecutionStore';
import type {
  RecoverySessionRecord,
  RecoverySessionStatus,
  RecoverySessionStore,
} from '../RecoverySessionStore';
import { buildRecoveryExecutionRecord } from '../recoveryExecutionRecords';

export type GetRecoverySessionResult =
  | { ok: true; record: RecoverySessionRecord | null }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

export type UpdateRecoverySessionStatusResult =
  | { ok: true; record: RecoverySessionRecord }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

export type GetRecoveryExecutionResult =
  | { ok: true; record: RecoveryExecutionRecord | null }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

export type ListRecoveryExecutionsResult =
  | { ok: true; records: RecoveryExecutionRecord[] }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

export type RecordRecoveryExecutionResult =
  | { ok: true; record: RecoveryExecutionRecord }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string };

function normalizeRecoverySessionStatus(value: unknown): RecoverySessionStatus | null {
  const normalized = toOptionalTrimmedString(value);
  switch (normalized) {
    case 'prepared':
    case 'verified':
    case 'near_recovered':
    case 'evm_recovering':
    case 'completed':
    case 'failed':
    case 'cancelled':
      return normalized;
    default:
      return null;
  }
}

function normalizePositiveInteger(value: unknown): number | null {
  const normalized = Number(value);
  if (!Number.isFinite(normalized) || normalized <= 0) return null;
  return Math.floor(normalized);
}

function recoverySessionMetadata(input: {
  readonly record: RecoverySessionRecord;
  readonly metadataPatch?: Record<string, unknown> | null;
}): Record<string, unknown> | undefined {
  if (input.metadataPatch) {
    return {
      ...(input.record.metadata || {}),
      ...input.metadataPatch,
    };
  }
  if (input.record.metadata) return { ...input.record.metadata };
  return undefined;
}

function recoverySessionWithStatus(input: {
  readonly record: RecoverySessionRecord;
  readonly status: RecoverySessionStatus;
  readonly updatedAtMs: number;
  readonly metadataPatch?: Record<string, unknown> | null;
}): RecoverySessionRecord {
  const metadata = recoverySessionMetadata({
    record: input.record,
    metadataPatch: input.metadataPatch,
  });
  const record: RecoverySessionRecord = {
    version: 'recovery_session_v1',
    sessionId: input.record.sessionId,
    userId: input.record.userId,
    nearAccountId: input.record.nearAccountId,
    signerSlot: input.record.signerSlot,
    status: input.status,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    newNearPublicKey: input.record.newNearPublicKey,
    newEvmOwnerAddress: input.record.newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds: input.record.recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash: input.record.recoveryEmailPayloadHash,
  };
  if (input.record.verifiedRecoveryPayloadHash) {
    record.verifiedRecoveryPayloadHash = input.record.verifiedRecoveryPayloadHash;
  }
  if (input.record.verifiedRecoveryArtifactHash) {
    record.verifiedRecoveryArtifactHash = input.record.verifiedRecoveryArtifactHash;
  }
  if (input.record.scope) record.scope = input.record.scope;
  if (metadata) record.metadata = metadata;
  return record;
}

function recoveryExecutionStatusQuery(input: {
  readonly status: RecoveryExecutionStatus;
  readonly action: string;
  readonly updatedBeforeMs: number | null;
  readonly limit: number | null;
}): Parameters<RecoveryExecutionStore['listByStatus']>[0] {
  const query: Parameters<RecoveryExecutionStore['listByStatus']>[0] = {
    status: input.status,
  };
  if (input.action) query.action = input.action;
  if (input.updatedBeforeMs !== null) query.updatedBeforeMs = input.updatedBeforeMs;
  if (input.limit !== null) query.limit = input.limit;
  return query;
}

export async function getRecoverySessionWithStore(input: {
  readonly store: RecoverySessionStore;
  readonly sessionId: string;
}): Promise<GetRecoverySessionResult> {
  try {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    const record = await input.store.get(sessionId);
    return { ok: true, record };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || 'Failed to read recovery session',
    };
  }
}

export async function updateRecoverySessionStatusWithStore(input: {
  readonly store: RecoverySessionStore;
  readonly sessionId: string;
  readonly status: RecoverySessionStatus;
  readonly metadataPatch?: Record<string, unknown> | null;
}): Promise<UpdateRecoverySessionStatusResult> {
  try {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const status = normalizeRecoverySessionStatus(input.status);
    if (!sessionId || !status) {
      return { ok: false, code: 'invalid_args', message: 'Invalid recovery session update' };
    }

    const existing = await input.store.get(sessionId);
    if (!existing) {
      return {
        ok: false,
        code: 'invalid_args',
        message: `Unknown recovery session: ${sessionId}`,
      };
    }

    const record = recoverySessionWithStatus({
      record: existing,
      status,
      updatedAtMs: Date.now(),
      metadataPatch: input.metadataPatch,
    });
    await input.store.put(record);
    return { ok: true, record };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || 'Failed to update recovery session',
    };
  }
}

export async function getRecoveryExecutionWithStore(input: {
  readonly store: RecoveryExecutionStore;
  readonly sessionId: string;
  readonly chainIdKey: string;
  readonly accountAddress: string;
  readonly action: string;
}): Promise<GetRecoveryExecutionResult> {
  try {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
    const accountAddress = toOptionalTrimmedString(input.accountAddress);
    const action = toOptionalTrimmedString(input.action);
    if (!sessionId || !chainIdKey || !accountAddress || !action) {
      return { ok: false, code: 'invalid_args', message: 'Missing recovery execution key' };
    }
    const record = await input.store.get({
      sessionId,
      chainIdKey,
      accountAddress,
      action,
    });
    return { ok: true, record };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || 'Failed to read recovery execution',
    };
  }
}

export async function listRecoveryExecutionsWithStore(input: {
  readonly store: RecoveryExecutionStore;
  readonly sessionId: string;
}): Promise<ListRecoveryExecutionsResult> {
  try {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    const records = await input.store.listBySessionId(sessionId);
    return { ok: true, records };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || 'Failed to list recovery executions',
    };
  }
}

export async function listRecoveryExecutionsByStatusWithStore(input: {
  readonly store: RecoveryExecutionStore;
  readonly status: RecoveryExecutionStatus;
  readonly action?: string;
  readonly updatedBeforeMs?: number;
  readonly limit?: number;
}): Promise<ListRecoveryExecutionsResult> {
  try {
    const action = toOptionalTrimmedString(input.action) || '';
    const updatedBeforeMs =
      typeof input.updatedBeforeMs === 'undefined'
        ? null
        : normalizePositiveInteger(input.updatedBeforeMs);
    if (typeof input.updatedBeforeMs !== 'undefined' && updatedBeforeMs === null) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'updatedBeforeMs must be a positive integer',
      };
    }
    const limit = typeof input.limit === 'undefined' ? null : normalizePositiveInteger(input.limit);
    if (typeof input.limit !== 'undefined' && limit === null) {
      return { ok: false, code: 'invalid_args', message: 'limit must be a positive integer' };
    }
    const records = await input.store.listByStatus(
      recoveryExecutionStatusQuery({
        status: input.status,
        action,
        updatedBeforeMs,
        limit,
      }),
    );
    return { ok: true, records };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || 'Failed to list recovery executions by status',
    };
  }
}

export async function recordRecoveryExecutionWithStores(input: {
  readonly recoverySessionStore: RecoverySessionStore;
  readonly recoveryExecutionStore: RecoveryExecutionStore;
  readonly sessionId: string;
  readonly chainIdKey: string;
  readonly accountAddress: string;
  readonly action: string;
  readonly status: RecoveryExecutionStatus;
  readonly transactionHash?: string;
  readonly errorCode?: string;
  readonly errorMessage?: string;
  readonly metadata?: Record<string, unknown>;
}): Promise<RecordRecoveryExecutionResult> {
  try {
    const sessionId = toOptionalTrimmedString(input.sessionId);
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey);
    const accountAddress = toOptionalTrimmedString(input.accountAddress);
    const action = toOptionalTrimmedString(input.action);
    if (!sessionId || !chainIdKey || !accountAddress || !action) {
      return { ok: false, code: 'invalid_args', message: 'Missing recovery execution fields' };
    }

    const recoverySession = await input.recoverySessionStore.get(sessionId);
    if (!recoverySession) {
      return {
        ok: false,
        code: 'invalid_args',
        message: `Unknown recovery session: ${sessionId}`,
      };
    }

    const existing = await input.recoveryExecutionStore.get({
      sessionId,
      chainIdKey,
      accountAddress,
      action,
    });
    const nowMs = Date.now();
    const record = buildRecoveryExecutionRecord({
      sessionId,
      userId: recoverySession.userId,
      nearAccountId: recoverySession.nearAccountId,
      chainIdKey,
      accountAddress,
      action,
      status: input.status,
      createdAtMs: existing?.createdAtMs ?? nowMs,
      nowMs,
      transactionHash: input.transactionHash,
      errorCode: input.errorCode,
      errorMessage: input.errorMessage,
      metadata: input.metadata,
    });
    if (!record) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Invalid recovery execution payload',
      };
    }

    await input.recoveryExecutionStore.put(record);
    return { ok: true, record };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || 'Failed to persist recovery execution',
    };
  }
}
