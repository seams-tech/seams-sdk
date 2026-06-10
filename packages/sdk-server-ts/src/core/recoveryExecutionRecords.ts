import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  RecoveryExecutionRecord,
  RecoveryExecutionStatus,
} from './RecoveryExecutionStore';

function normalizeAccountAddress(value: unknown): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) return '';
  return normalized.startsWith('0x') ? normalized.toLowerCase() : normalized;
}

function normalizeRecoveryExecutionStatus(value: unknown): RecoveryExecutionStatus | null {
  const normalized = toOptionalTrimmedString(value);
  if (
    normalized === 'pending' ||
    normalized === 'submitted' ||
    normalized === 'confirmed' ||
    normalized === 'failed' ||
    normalized === 'skipped'
  ) {
    return normalized;
  }
  return null;
}

export function inferNearRecoveryChainIdKey(nearAccountId: string): string {
  const normalized = toOptionalTrimmedString(nearAccountId)?.toLowerCase() || '';
  if (!normalized) return '';
  return normalized.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
}

export function buildRecoveryExecutionRecord(input: {
  sessionId: string;
  userId: string;
  nearAccountId: string;
  chainIdKey: string;
  accountAddress: string;
  action: string;
  status: RecoveryExecutionStatus;
  createdAtMs?: number;
  nowMs?: number;
  transactionHash?: string;
  errorCode?: string;
  errorMessage?: string;
  metadata?: Record<string, unknown>;
}): RecoveryExecutionRecord | null {
  const sessionId = toOptionalTrimmedString(input.sessionId);
  const userId = toOptionalTrimmedString(input.userId);
  const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
  const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeAccountAddress(input.accountAddress);
  const action = toOptionalTrimmedString(input.action);
  const status = normalizeRecoveryExecutionStatus(input.status);
  const nowMs = Number.isFinite(Number(input.nowMs)) ? Math.floor(Number(input.nowMs)) : Date.now();
  const createdAtMs = Number.isFinite(Number(input.createdAtMs))
    ? Math.floor(Number(input.createdAtMs))
    : nowMs;
  const transactionHash = toOptionalTrimmedString(input.transactionHash);
  const errorCode = toOptionalTrimmedString(input.errorCode);
  const errorMessage = toOptionalTrimmedString(input.errorMessage);

  if (!sessionId || !userId || !nearAccountId || !chainIdKey || !accountAddress || !action || !status) {
    return null;
  }
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(nowMs) || nowMs <= 0 || nowMs < createdAtMs) return null;

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
    updatedAtMs: nowMs,
    ...(transactionHash ? { transactionHash } : {}),
    ...(errorCode ? { errorCode } : {}),
    ...(errorMessage ? { errorMessage } : {}),
    ...(input.metadata ? { metadata: { ...input.metadata } } : {}),
  };
}
