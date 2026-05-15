import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearThresholdCommitQueue,
  withThresholdCommitQueue,
  type ThresholdCommitQueueByKey,
  type ThresholdCommitQueueCancelledReason,
  type ThresholdCommitQueueError,
  type ThresholdCommitQueueErrorCode,
} from '../commitQueueShared';

export type ThresholdEcdsaCommitQueueErrorCode = ThresholdCommitQueueErrorCode;
export type ThresholdEcdsaCommitQueueError = ThresholdCommitQueueError;

export type ThresholdEcdsaCommitQueueKeyInput = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
};

export type ThresholdEcdsaCommitQueueByKey = ThresholdCommitQueueByKey;

export function createThresholdEcdsaCommitQueueOverflowError(
  walletId: AccountId | string,
  queueKey: string,
  maxQueueLength: number,
): ThresholdEcdsaCommitQueueError {
  const normalizedWalletId = String(toAccountId(walletId));
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue overflow for ${normalizedWalletId} (queueKey=${queueKey}, max=${maxQueueLength})`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_overflow';
  return err;
}

export function createThresholdEcdsaCommitQueueTimeoutError(
  walletId: AccountId | string,
  queueKey: string,
  timeoutMs: number,
): ThresholdEcdsaCommitQueueError {
  const normalizedWalletId = String(toAccountId(walletId));
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue timeout for ${normalizedWalletId} (queueKey=${queueKey}, waited>${timeoutMs}ms before start)`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_timeout';
  return err;
}

export function createThresholdEcdsaCommitQueueCancelledError(
  walletId: AccountId | string,
  queueKey: string,
  reason: ThresholdCommitQueueCancelledReason = 'cancelled',
): ThresholdEcdsaCommitQueueError {
  const normalizedWalletId = String(toAccountId(walletId));
  const message =
    reason === 'queue_cleared'
      ? `[SigningEngine] threshold ECDSA queued commit cancelled for ${normalizedWalletId} (queueKey=${queueKey}, queue_cleared)`
      : `[SigningEngine] threshold ECDSA queued commit cancelled for ${normalizedWalletId} (queueKey=${queueKey})`;
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
  walletId: AccountId | string;
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
  const walletKey = String(toAccountId(args.walletId));
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
        createThresholdEcdsaCommitQueueOverflowError(walletKey, queueKey, maxQueueLength),
      makeTimeoutError: (queueKey, timeoutMs) =>
        createThresholdEcdsaCommitQueueTimeoutError(walletKey, queueKey, timeoutMs),
      makeCancelledError: (queueKey, reason) =>
        createThresholdEcdsaCommitQueueCancelledError(walletKey, queueKey, reason),
    },
  });
}
