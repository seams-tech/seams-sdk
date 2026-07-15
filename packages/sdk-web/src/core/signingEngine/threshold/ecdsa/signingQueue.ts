import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearThresholdCommitQueue,
  withThresholdCommitQueue,
  type ThresholdCommitQueueByKey,
  type ThresholdCommitQueueCancelledReason,
  type ThresholdCommitQueueError,
  type ThresholdCommitQueueErrorCode,
} from '../commitQueueShared';

export type ThresholdEcdsaSigningQueueErrorCode = ThresholdCommitQueueErrorCode;
export type ThresholdEcdsaSigningQueueError = ThresholdCommitQueueError;

export type ThresholdEcdsaSigningQueueKeyInput = {
  walletId: WalletId;
};

export type ThresholdEcdsaSigningQueueByKey = ThresholdCommitQueueByKey;

function ecdsaSigningQueueWalletIdLabel(walletId: WalletId): string {
  return String(walletId).trim();
}

export function createThresholdEcdsaSigningQueueOverflowError(
  walletId: WalletId,
  queueKey: string,
  maxQueueLength: number,
): ThresholdEcdsaSigningQueueError {
  const normalizedWalletId = ecdsaSigningQueueWalletIdLabel(walletId);
  const err = new Error(
    `[SigningEngine] threshold ECDSA signing queue overflow for ${normalizedWalletId} (queueKey=${queueKey}, max=${maxQueueLength})`,
  ) as ThresholdEcdsaSigningQueueError;
  err.code = 'commit_queue_overflow';
  return err;
}

export function createThresholdEcdsaSigningQueueTimeoutError(
  walletId: WalletId,
  queueKey: string,
  timeoutMs: number,
): ThresholdEcdsaSigningQueueError {
  const normalizedWalletId = ecdsaSigningQueueWalletIdLabel(walletId);
  const err = new Error(
    `[SigningEngine] threshold ECDSA signing queue timeout for ${normalizedWalletId} (queueKey=${queueKey}, waited>${timeoutMs}ms before start)`,
  ) as ThresholdEcdsaSigningQueueError;
  err.code = 'commit_queue_timeout';
  return err;
}

export function createThresholdEcdsaSigningQueueCancelledError(
  walletId: WalletId,
  queueKey: string,
  reason: ThresholdCommitQueueCancelledReason = 'cancelled',
): ThresholdEcdsaSigningQueueError {
  const normalizedWalletId = ecdsaSigningQueueWalletIdLabel(walletId);
  const message =
    reason === 'queue_cleared'
      ? `[SigningEngine] threshold ECDSA queued signing operation cancelled for ${normalizedWalletId} (queueKey=${queueKey}, queue_cleared)`
      : `[SigningEngine] threshold ECDSA queued signing operation cancelled for ${normalizedWalletId} (queueKey=${queueKey})`;
  const err = new Error(message) as ThresholdEcdsaSigningQueueError;
  err.code = 'cancelled';
  return err;
}

export function resolveThresholdEcdsaSigningQueueKey(
  args: ThresholdEcdsaSigningQueueKeyInput,
): string {
  return `wallet:${ecdsaSigningQueueWalletIdLabel(args.walletId)}:evm-family-ecdsa`;
}

export function clearThresholdEcdsaSigningQueue(
  queueByKey: ThresholdEcdsaSigningQueueByKey,
): void {
  clearThresholdCommitQueue(queueByKey);
}

export async function withThresholdEcdsaSigningQueue<T>(args: {
  queueByKey: ThresholdEcdsaSigningQueueByKey;
  queueKey: string;
  walletId: WalletId;
  enabled: boolean;
  shouldAbort?: () => boolean;
  maxQueueLength?: number;
  queueTimeoutMs?: number;
  task: () => Promise<T>;
}): Promise<T> {
  const queueKey = String(args.queueKey || '').trim();
  if (!queueKey) {
    throw new Error('[SigningEngine] threshold ECDSA signing queue requires non-empty queueKey');
  }
  const walletKey = args.walletId;
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
        createThresholdEcdsaSigningQueueOverflowError(walletKey, queueKey, maxQueueLength),
      makeTimeoutError: (queueKey, timeoutMs) =>
        createThresholdEcdsaSigningQueueTimeoutError(walletKey, queueKey, timeoutMs),
      makeCancelledError: (queueKey, reason) =>
        createThresholdEcdsaSigningQueueCancelledError(walletKey, queueKey, reason),
    },
  });
}
