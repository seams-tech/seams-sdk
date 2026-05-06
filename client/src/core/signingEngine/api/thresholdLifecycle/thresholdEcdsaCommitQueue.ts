import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../../session/signingSession/ecdsaChainTarget';
import {
  clearThresholdCommitQueue,
  withThresholdCommitQueue,
  type ThresholdCommitQueueByKey,
  type ThresholdCommitQueueCancelledReason,
  type ThresholdCommitQueueError,
  type ThresholdCommitQueueErrorCode,
} from './thresholdCommitQueueShared';

export type ThresholdEcdsaCommitQueueErrorCode = ThresholdCommitQueueErrorCode;
export type ThresholdEcdsaCommitQueueError = ThresholdCommitQueueError;

export type ThresholdEcdsaCommitQueueKeyInput = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
};

export type ThresholdEcdsaCommitQueueByKey = ThresholdCommitQueueByKey;

export function createThresholdEcdsaCommitQueueOverflowError(
  nearAccountId: AccountId | string,
  queueKey: string,
  maxQueueLength: number,
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue overflow for ${accountId} (queueKey=${queueKey}, max=${maxQueueLength})`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_overflow';
  return err;
}

export function createThresholdEcdsaCommitQueueTimeoutError(
  nearAccountId: AccountId | string,
  queueKey: string,
  timeoutMs: number,
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue timeout for ${accountId} (queueKey=${queueKey}, waited>${timeoutMs}ms before start)`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_timeout';
  return err;
}

export function createThresholdEcdsaCommitQueueCancelledError(
  nearAccountId: AccountId | string,
  queueKey: string,
  reason: ThresholdCommitQueueCancelledReason = 'cancelled',
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const message =
    reason === 'queue_cleared'
      ? `[SigningEngine] threshold ECDSA queued commit cancelled for ${accountId} (queueKey=${queueKey}, queue_cleared)`
      : `[SigningEngine] threshold ECDSA queued commit cancelled for ${accountId} (queueKey=${queueKey})`;
  const err = new Error(message) as ThresholdEcdsaCommitQueueError;
  err.code = 'cancelled';
  return err;
}

export function resolveThresholdEcdsaCommitQueueKey(args: ThresholdEcdsaCommitQueueKeyInput): string {
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const thresholdSessionId = String(args.thresholdSessionId).trim();
  if (!thresholdSessionId) {
    throw new Error(
      '[SigningEngine] threshold ECDSA commit queue requires non-empty thresholdSessionId',
    );
  }
  return `session:${targetKey}:${thresholdSessionId}`;
}

export function clearThresholdEcdsaCommitQueue(
  queueByKey: ThresholdEcdsaCommitQueueByKey,
): void {
  clearThresholdCommitQueue(queueByKey);
}

export async function withThresholdEcdsaCommitQueue<T>(args: {
  queueByKey: ThresholdEcdsaCommitQueueByKey;
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
    throw new Error('[SigningEngine] threshold ECDSA commit queue requires non-empty queueKey');
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
        createThresholdEcdsaCommitQueueOverflowError(accountKey, queueKey, maxQueueLength),
      makeTimeoutError: (queueKey, timeoutMs) =>
        createThresholdEcdsaCommitQueueTimeoutError(accountKey, queueKey, timeoutMs),
      makeCancelledError: (queueKey, reason) =>
        createThresholdEcdsaCommitQueueCancelledError(accountKey, queueKey, reason),
    },
  });
}
