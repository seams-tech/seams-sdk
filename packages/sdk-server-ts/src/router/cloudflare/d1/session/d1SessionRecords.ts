import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  RecoveryExecutionRecord,
  RecoveryExecutionStatus,
} from '../../core/RecoveryExecutionStore';
import type { RecoverySessionRecord, RecoverySessionStatus } from '../../core/RecoverySessionStore';
import {
  isRecordValue,
  parseJsonObject,
  positiveInteger,
  positiveSafeInteger,
} from './d1RouterApiAuthBoundary';

export type D1SessionRow = {
  readonly session_version?: unknown;
  readonly record_json?: unknown;
};

export type D1RecoverySessionRow = {
  readonly record_json?: unknown;
};

export type D1RecoveryExecutionRow = {
  readonly record_json?: unknown;
};

export type AppSessionVersionRecord = {
  readonly version: 'app_session_version_v1';
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

export function parseAppSessionCreatedAt(input: unknown, fallback: number): number {
  const record = parseJsonObject(input);
  const value = positiveInteger(record?.createdAtMs);
  return value ?? fallback;
}

export function appSessionRecord(input: {
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): AppSessionVersionRecord {
  return {
    version: 'app_session_version_v1',
    userId: input.userId,
    appSessionVersion: input.appSessionVersion,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

export function normalizeAccountAddress(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

export function parseRecoverySessionStatus(input: unknown): RecoverySessionStatus | null {
  const status = toOptionalTrimmedString(input);
  switch (status) {
    case 'prepared':
    case 'verified':
    case 'near_recovered':
    case 'evm_recovering':
    case 'completed':
    case 'failed':
    case 'cancelled':
      return status;
    default:
      return null;
  }
}

export function parseRecoveryExecutionStatus(input: unknown): RecoveryExecutionStatus | null {
  const status = toOptionalTrimmedString(input);
  switch (status) {
    case 'pending':
    case 'submitted':
    case 'confirmed':
    case 'failed':
    case 'skipped':
      return status;
    default:
      return null;
  }
}

export function parseRecoverySessionRecord(input: unknown): RecoverySessionRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const sessionId = toOptionalTrimmedString(record.sessionId);
  const userId = toOptionalTrimmedString(record.userId);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const signerSlot = positiveSafeInteger(record.signerSlot);
  const status = parseRecoverySessionStatus(record.status);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const newNearPublicKey = toOptionalTrimmedString(record.newNearPublicKey);
  const newEvmOwnerAddress = normalizeHexLike(record.newEvmOwnerAddress);
  const recoveryDeadlineEpochSeconds = positiveSafeInteger(record.recoveryDeadlineEpochSeconds);
  const recoveryEmailPayloadHash = toOptionalTrimmedString(record.recoveryEmailPayloadHash);
  const verifiedRecoveryPayloadHash = toOptionalTrimmedString(record.verifiedRecoveryPayloadHash);
  const verifiedRecoveryArtifactHash = toOptionalTrimmedString(record.verifiedRecoveryArtifactHash);
  const scope = toOptionalTrimmedString(record.scope);
  const metadata = parseRecordMetadata(record.metadata);
  if (
    version !== 'recovery_session_v1' ||
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !signerSlot ||
    !status ||
    !createdAtMs ||
    !updatedAtMs ||
    !expiresAtMs ||
    !newNearPublicKey ||
    !newEvmOwnerAddress ||
    !recoveryDeadlineEpochSeconds ||
    !recoveryEmailPayloadHash
  ) {
    return null;
  }
  return {
    version: 'recovery_session_v1',
    sessionId,
    userId,
    nearAccountId,
    signerSlot,
    status,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
    newNearPublicKey,
    newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash,
    ...(verifiedRecoveryPayloadHash ? { verifiedRecoveryPayloadHash } : {}),
    ...(verifiedRecoveryArtifactHash ? { verifiedRecoveryArtifactHash } : {}),
    ...(scope ? { scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

export function parseRecoveryExecutionRecord(input: unknown): RecoveryExecutionRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const sessionId = toOptionalTrimmedString(record.sessionId);
  const userId = toOptionalTrimmedString(record.userId);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const chainIdKey = toOptionalTrimmedString(record.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeAccountAddress(record.accountAddress);
  const action = toOptionalTrimmedString(record.action);
  const status = parseRecoveryExecutionStatus(record.status);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const transactionHash = toOptionalTrimmedString(record.transactionHash);
  const errorCode = toOptionalTrimmedString(record.errorCode);
  const errorMessage = toOptionalTrimmedString(record.errorMessage);
  const metadata = parseRecordMetadata(record.metadata);
  if (
    version !== 'recovery_execution_v1' ||
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !chainIdKey ||
    !accountAddress ||
    !action ||
    !status ||
    !createdAtMs ||
    !updatedAtMs
  ) {
    return null;
  }
  return {
    version: 'recovery_execution_v1',
    sessionId,
    userId,
    nearAccountId,
    chainIdKey,
    accountAddress,
    action,
    status,
    createdAtMs,
    updatedAtMs,
    ...(transactionHash ? { transactionHash } : {}),
    ...(errorCode ? { errorCode } : {}),
    ...(errorMessage ? { errorMessage } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

export function recoverySessionWithStatus(input: {
  readonly record: RecoverySessionRecord;
  readonly status: RecoverySessionStatus;
  readonly updatedAtMs: number;
  readonly metadataPatch?: Record<string, unknown>;
}): RecoverySessionRecord {
  const metadata = nextRecoveryMetadata(input);
  return {
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
    ...(input.record.verifiedRecoveryPayloadHash
      ? { verifiedRecoveryPayloadHash: input.record.verifiedRecoveryPayloadHash }
      : {}),
    ...(input.record.verifiedRecoveryArtifactHash
      ? { verifiedRecoveryArtifactHash: input.record.verifiedRecoveryArtifactHash }
      : {}),
    ...(input.record.scope ? { scope: input.record.scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function normalizeHexLike(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function parseRecordMetadata(input: unknown): Record<string, unknown> | undefined {
  if (!isRecordValue(input)) return undefined;
  return { ...input };
}

function nextRecoveryMetadata(input: {
  readonly record: RecoverySessionRecord;
  readonly metadataPatch?: Record<string, unknown>;
}): Record<string, unknown> | undefined {
  if (input.metadataPatch) return { ...(input.record.metadata || {}), ...input.metadataPatch };
  return input.record.metadata ? { ...input.record.metadata } : undefined;
}
