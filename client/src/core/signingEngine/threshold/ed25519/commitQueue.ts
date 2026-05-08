import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  clearThresholdCommitQueue,
  withThresholdCommitQueue,
  type ThresholdCommitQueueByKey,
  type ThresholdCommitQueueCancelledReason,
  type ThresholdCommitQueueError,
  type ThresholdCommitQueueErrorCode,
} from '../commitQueueShared';

export type ThresholdEd25519CommitQueueErrorCode = ThresholdCommitQueueErrorCode;
export type ThresholdEd25519CommitQueueError = ThresholdCommitQueueError;

export type ThresholdEd25519CommitQueueKeyInput = {
  thresholdSessionId: string;
};

export type ThresholdEd25519CommitQueueByKey = ThresholdCommitQueueByKey;

export function createThresholdEd25519CommitQueueOverflowError(
  nearAccountId: AccountId | string,
  queueKey: string,
  maxQueueLength: number,
): ThresholdEd25519CommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const err = new Error(
    `[SigningEngine] threshold Ed25519 commit queue overflow for ${accountId} (queueKey=${queueKey}, max=${maxQueueLength})`,
  ) as ThresholdEd25519CommitQueueError;
  err.code = 'commit_queue_overflow';
  return err;
}

export function createThresholdEd25519CommitQueueTimeoutError(
  nearAccountId: AccountId | string,
  queueKey: string,
  timeoutMs: number,
): ThresholdEd25519CommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const err = new Error(
    `[SigningEngine] threshold Ed25519 commit queue timeout for ${accountId} (queueKey=${queueKey}, waited>${timeoutMs}ms before start)`,
  ) as ThresholdEd25519CommitQueueError;
  err.code = 'commit_queue_timeout';
  return err;
}

export function createThresholdEd25519CommitQueueCancelledError(
  nearAccountId: AccountId | string,
  queueKey: string,
  reason: ThresholdCommitQueueCancelledReason = 'cancelled',
): ThresholdEd25519CommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const message =
    reason === 'queue_cleared'
      ? `[SigningEngine] threshold Ed25519 queued commit cancelled for ${accountId} (queueKey=${queueKey}, queue_cleared)`
      : `[SigningEngine] threshold Ed25519 queued commit cancelled for ${accountId} (queueKey=${queueKey})`;
  const err = new Error(message) as ThresholdEd25519CommitQueueError;
  err.code = 'cancelled';
  return err;
}

export function resolveThresholdEd25519CommitQueueKey(
  args: ThresholdEd25519CommitQueueKeyInput,
): string {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error(
      '[SigningEngine] threshold Ed25519 commit queue requires non-empty thresholdSessionId',
    );
  }
  return `session:ed25519:${thresholdSessionId}`;
}

export function clearThresholdEd25519CommitQueue(
  queueByKey: ThresholdEd25519CommitQueueByKey,
): void {
  clearThresholdCommitQueue(queueByKey);
}

export async function withThresholdEd25519CommitQueue<T>(args: {
  queueByKey: ThresholdEd25519CommitQueueByKey;
  queueKey: string;
  nearAccountId: AccountId | string;
  enabled: boolean;
  shouldAbort?: () => boolean;
  maxQueueLength?: number;
  queueTimeoutMs?: number;
  task: () => Promise<T>;
}): Promise<T> {
  const queueKey = String(args.queueKey || '').trim();
  if (!queueKey) {
    throw new Error('[SigningEngine] threshold Ed25519 commit queue requires non-empty queueKey');
  }
  const accountKey = String(toAccountId(args.nearAccountId));
  return await withThresholdCommitQueue({
    queueByKey: args.queueByKey,
    queueKey,
    enabled: args.enabled,
    shouldAbort: args.shouldAbort,
    maxQueueLength: args.maxQueueLength,
    queueTimeoutMs: args.queueTimeoutMs,
    task: args.task,
    errors: {
      makeOverflowError: (queueKey, maxQueueLength) =>
        createThresholdEd25519CommitQueueOverflowError(accountKey, queueKey, maxQueueLength),
      makeTimeoutError: (queueKey, timeoutMs) =>
        createThresholdEd25519CommitQueueTimeoutError(accountKey, queueKey, timeoutMs),
      makeCancelledError: (queueKey, reason) =>
        createThresholdEd25519CommitQueueCancelledError(accountKey, queueKey, reason),
    },
  });
}
