import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { normalizeBoundedPositiveInteger } from '@shared/utils/normalize';

export type ThresholdEcdsaCommitQueueErrorCode =
  | 'commit_queue_overflow'
  | 'commit_queue_timeout'
  | 'cancelled';

export type ThresholdEcdsaCommitQueueError = Error & { code: ThresholdEcdsaCommitQueueErrorCode };

export type ThresholdEcdsaCommitQueueKeyInput = {
  nearAccountId: AccountId | string;
  chain: 'tempo' | 'evm';
  thresholdSessionId?: string;
  relayerUrl?: string;
  relayerKeyId?: string;
  clientVerifyingShareB64u?: string;
};

type ThresholdEcdsaCommitQueueItem = {
  enqueuedAtMs: number;
  timeoutMs: number;
  shouldAbort?: () => boolean;
  nearAccountId: string;
  timeoutHandle: ReturnType<typeof setTimeout> | null;
  isSettled: () => boolean;
  run: () => Promise<void>;
  reject: (error: unknown) => void;
};

type ThresholdEcdsaCommitQueueState = {
  running: boolean;
  items: ThresholdEcdsaCommitQueueItem[];
};

export type ThresholdEcdsaCommitQueueByKey = Map<string, ThresholdEcdsaCommitQueueState>;

const DEFAULT_MAX_QUEUE_LENGTH = 8;
const DEFAULT_QUEUE_TIMEOUT_MS = 45_000;

export function createThresholdEcdsaCommitQueueOverflowError(
  nearAccountId: AccountId | string,
  queueKeyRaw: string,
  maxQueueLength: number,
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const queueKey = String(queueKeyRaw || '').trim() || `account:${accountId}`;
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue overflow for ${accountId} (queueKey=${queueKey}, max=${maxQueueLength})`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_overflow';
  return err;
}

export function createThresholdEcdsaCommitQueueTimeoutError(
  nearAccountId: AccountId | string,
  queueKeyRaw: string,
  timeoutMs: number,
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const queueKey = String(queueKeyRaw || '').trim() || `account:${accountId}`;
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue timeout for ${accountId} (queueKey=${queueKey}, waited>${timeoutMs}ms before start)`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_timeout';
  return err;
}

export function createThresholdEcdsaCommitQueueCancelledError(
  nearAccountId: AccountId | string,
  queueKeyRaw: string,
  reason: 'cancelled' | 'queue_cleared' = 'cancelled',
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const queueKey = String(queueKeyRaw || '').trim() || `account:${accountId}`;
  const message =
    reason === 'queue_cleared'
      ? `[SigningEngine] threshold ECDSA queued commit cancelled for ${accountId} (queueKey=${queueKey}, queue_cleared)`
      : `[SigningEngine] threshold ECDSA queued commit cancelled for ${accountId} (queueKey=${queueKey})`;
  const err = new Error(message) as ThresholdEcdsaCommitQueueError;
  err.code = 'cancelled';
  return err;
}

function encodeQueueToken(valueRaw: unknown): string {
  return encodeURIComponent(String(valueRaw || '').trim());
}

export function resolveThresholdEcdsaCommitQueueKey(args: ThresholdEcdsaCommitQueueKeyInput): string {
  const nearAccountId = String(toAccountId(args.nearAccountId));
  const chain = args.chain === 'evm' ? 'evm' : 'tempo';
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (thresholdSessionId) {
    return `session:${chain}:${thresholdSessionId}`;
  }

  const relayerUrl = String(args.relayerUrl || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  if (relayerUrl && relayerKeyId && clientVerifyingShareB64u) {
    return `lane:${chain}:${encodeQueueToken(relayerUrl)}|${encodeQueueToken(relayerKeyId)}|${encodeQueueToken(clientVerifyingShareB64u)}`;
  }

  return `account:${nearAccountId}`;
}

function normalizeQueueLimit(value: unknown, fallback: number): number {
  return normalizeBoundedPositiveInteger(value, {
    fallback,
    min: 1,
  });
}

function getOrCreateQueueState(
  queueByKey: ThresholdEcdsaCommitQueueByKey,
  queueKey: string,
): ThresholdEcdsaCommitQueueState {
  const existing = queueByKey.get(queueKey);
  if (existing) return existing;
  const created: ThresholdEcdsaCommitQueueState = {
    running: false,
    items: [],
  };
  queueByKey.set(queueKey, created);
  return created;
}

function clearQueueItemTimeout(item: ThresholdEcdsaCommitQueueItem): void {
  if (item.timeoutHandle) {
    clearTimeout(item.timeoutHandle);
    item.timeoutHandle = null;
  }
}

async function drainQueueForKey(
  queueByKey: ThresholdEcdsaCommitQueueByKey,
  queueKey: string,
): Promise<void> {
  const state = queueByKey.get(queueKey);
  if (!state || state.running) return;

  state.running = true;
  try {
    while (state.items.length > 0) {
      const item = state.items.shift();
      if (!item) continue;
      if (item.isSettled()) continue;
      clearQueueItemTimeout(item);

      if (item.shouldAbort?.()) {
        item.reject(createThresholdEcdsaCommitQueueCancelledError(item.nearAccountId, queueKey));
        continue;
      }
      if (Date.now() - item.enqueuedAtMs > item.timeoutMs) {
        item.reject(
          createThresholdEcdsaCommitQueueTimeoutError(item.nearAccountId, queueKey, item.timeoutMs),
        );
        continue;
      }

      try {
        await item.run();
      } catch (error: unknown) {
        item.reject(error);
      }
    }
  } finally {
    state.running = false;
    if (state.items.length === 0 && queueByKey.get(queueKey) === state) {
      queueByKey.delete(queueKey);
    }
  }
}

function scheduleQueueDrain(
  queueByKey: ThresholdEcdsaCommitQueueByKey,
  queueKey: string,
): void {
  void drainQueueForKey(queueByKey, queueKey);
}

export function clearThresholdEcdsaCommitQueue(
  queueByKey: ThresholdEcdsaCommitQueueByKey,
): void {
  for (const [queueKey, state] of queueByKey.entries()) {
    for (const item of state.items) {
      clearQueueItemTimeout(item);
      item.reject(
        createThresholdEcdsaCommitQueueCancelledError(
          item.nearAccountId,
          queueKey,
          'queue_cleared',
        ),
      );
    }
    state.items.length = 0;
  }
  queueByKey.clear();
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
  if (!args.enabled) return await args.task();

  const queueKey = String(args.queueKey || '').trim();
  if (!queueKey) {
    throw new Error('[SigningEngine] threshold ECDSA commit queue requires non-empty queueKey');
  }
  const accountKey = String(toAccountId(args.nearAccountId));
  const maxQueueLength = normalizeQueueLimit(args.maxQueueLength, DEFAULT_MAX_QUEUE_LENGTH);
  const queueTimeoutMs = normalizeQueueLimit(args.queueTimeoutMs, DEFAULT_QUEUE_TIMEOUT_MS);
  const state = getOrCreateQueueState(args.queueByKey, queueKey);
  const queueDepth = state.items.length + (state.running ? 1 : 0);
  if (queueDepth >= maxQueueLength) {
    throw createThresholdEcdsaCommitQueueOverflowError(accountKey, queueKey, maxQueueLength);
  }

  return await new Promise<T>((resolve, reject) => {
    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
    let settled = false;
    const clearTimeoutHandle = (): void => {
      if (!timeoutHandle) return;
      clearTimeout(timeoutHandle);
      timeoutHandle = null;
    };
    const rejectOnce = (error: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeoutHandle();
      reject(error);
    };
    const resolveOnce = (value: T): void => {
      if (settled) return;
      settled = true;
      clearTimeoutHandle();
      resolve(value);
    };
    const item: ThresholdEcdsaCommitQueueItem = {
      enqueuedAtMs: Date.now(),
      timeoutMs: queueTimeoutMs,
      shouldAbort: args.shouldAbort,
      nearAccountId: accountKey,
      timeoutHandle: null,
      isSettled: () => settled,
      reject: rejectOnce,
      run: async () => {
        if (args.shouldAbort?.()) {
          throw createThresholdEcdsaCommitQueueCancelledError(accountKey, queueKey);
        }
        const result = await args.task();
        resolveOnce(result);
      },
    };
    timeoutHandle = setTimeout(() => {
      if (item.isSettled()) return;
      const idx = state.items.indexOf(item);
      if (idx >= 0) {
        state.items.splice(idx, 1);
      }
      rejectOnce(createThresholdEcdsaCommitQueueTimeoutError(accountKey, queueKey, queueTimeoutMs));
      if (
        !state.running &&
        state.items.length === 0 &&
        args.queueByKey.get(queueKey) === state
      ) {
        args.queueByKey.delete(queueKey);
      }
    }, queueTimeoutMs);
    item.timeoutHandle = timeoutHandle;
    state.items.push(item);
    scheduleQueueDrain(args.queueByKey, queueKey);
  });
}
