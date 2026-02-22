import { toAccountId, type AccountId } from '@/core/types/accountIds';

export type ThresholdEcdsaCommitQueueErrorCode =
  | 'commit_queue_overflow'
  | 'commit_queue_timeout'
  | 'cancelled';

export type ThresholdEcdsaCommitQueueError = Error & { code: ThresholdEcdsaCommitQueueErrorCode };

type ThresholdEcdsaCommitQueueItem = {
  enqueuedAtMs: number;
  timeoutMs: number;
  shouldAbort?: () => boolean;
  timeoutHandle: ReturnType<typeof setTimeout> | null;
  isSettled: () => boolean;
  run: () => Promise<void>;
  reject: (error: unknown) => void;
};

type ThresholdEcdsaCommitQueueState = {
  running: boolean;
  items: ThresholdEcdsaCommitQueueItem[];
};

export type ThresholdEcdsaCommitQueueByAccount = Map<string, ThresholdEcdsaCommitQueueState>;

const DEFAULT_MAX_QUEUE_LENGTH = 8;
const DEFAULT_QUEUE_TIMEOUT_MS = 45_000;

export function createThresholdEcdsaCommitQueueOverflowError(
  nearAccountId: AccountId | string,
  maxQueueLength: number,
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue overflow for ${accountId} (max=${maxQueueLength})`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_overflow';
  return err;
}

export function createThresholdEcdsaCommitQueueTimeoutError(
  nearAccountId: AccountId | string,
  timeoutMs: number,
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const err = new Error(
    `[SigningEngine] threshold ECDSA commit queue timeout for ${accountId} (waited>${timeoutMs}ms before start)`,
  ) as ThresholdEcdsaCommitQueueError;
  err.code = 'commit_queue_timeout';
  return err;
}

export function createThresholdEcdsaCommitQueueCancelledError(
  nearAccountId: AccountId | string,
  reason: 'cancelled' | 'queue_cleared' = 'cancelled',
): ThresholdEcdsaCommitQueueError {
  const accountId = String(toAccountId(nearAccountId));
  const message = reason === 'queue_cleared'
    ? `[SigningEngine] threshold ECDSA queued commit cancelled for ${accountId} (queue_cleared)`
    : `[SigningEngine] threshold ECDSA queued commit cancelled for ${accountId}`;
  const err = new Error(message) as ThresholdEcdsaCommitQueueError;
  err.code = 'cancelled';
  return err;
}

function normalizeQueueLimit(value: unknown, fallback: number): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1, Math.floor(n));
}

function getOrCreateQueueState(
  queueByAccount: ThresholdEcdsaCommitQueueByAccount,
  accountKey: string,
): ThresholdEcdsaCommitQueueState {
  const existing = queueByAccount.get(accountKey);
  if (existing) return existing;
  const created: ThresholdEcdsaCommitQueueState = {
    running: false,
    items: [],
  };
  queueByAccount.set(accountKey, created);
  return created;
}

function clearQueueItemTimeout(item: ThresholdEcdsaCommitQueueItem): void {
  if (item.timeoutHandle) {
    clearTimeout(item.timeoutHandle);
    item.timeoutHandle = null;
  }
}

async function drainQueueForAccount(
  queueByAccount: ThresholdEcdsaCommitQueueByAccount,
  accountKey: string,
): Promise<void> {
  const state = queueByAccount.get(accountKey);
  if (!state || state.running) return;

  state.running = true;
  try {
    while (state.items.length > 0) {
      const item = state.items.shift();
      if (!item) continue;
      if (item.isSettled()) continue;
      clearQueueItemTimeout(item);

      if (item.shouldAbort?.()) {
        item.reject(createThresholdEcdsaCommitQueueCancelledError(accountKey));
        continue;
      }
      if (Date.now() - item.enqueuedAtMs > item.timeoutMs) {
        item.reject(createThresholdEcdsaCommitQueueTimeoutError(accountKey, item.timeoutMs));
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
    if (state.items.length === 0 && queueByAccount.get(accountKey) === state) {
      queueByAccount.delete(accountKey);
    }
  }
}

function scheduleQueueDrain(
  queueByAccount: ThresholdEcdsaCommitQueueByAccount,
  accountKey: string,
): void {
  void drainQueueForAccount(queueByAccount, accountKey);
}

export function clearThresholdEcdsaCommitQueue(
  queueByAccount: ThresholdEcdsaCommitQueueByAccount,
): void {
  for (const [accountKey, state] of queueByAccount.entries()) {
    for (const item of state.items) {
      clearQueueItemTimeout(item);
      item.reject(createThresholdEcdsaCommitQueueCancelledError(accountKey, 'queue_cleared'));
    }
    state.items.length = 0;
  }
  queueByAccount.clear();
}

export async function withThresholdEcdsaCommitQueue<T>(args: {
  queueByAccount: ThresholdEcdsaCommitQueueByAccount;
  nearAccountId: AccountId | string;
  enabled: boolean;
  shouldAbort?: () => boolean;
  maxQueueLength?: number;
  queueTimeoutMs?: number;
  task: () => Promise<T>;
}): Promise<T> {
  if (!args.enabled) return await args.task();

  const accountKey = String(toAccountId(args.nearAccountId));
  const maxQueueLength = normalizeQueueLimit(args.maxQueueLength, DEFAULT_MAX_QUEUE_LENGTH);
  const queueTimeoutMs = normalizeQueueLimit(args.queueTimeoutMs, DEFAULT_QUEUE_TIMEOUT_MS);
  const state = getOrCreateQueueState(args.queueByAccount, accountKey);
  const queueDepth = state.items.length + (state.running ? 1 : 0);
  if (queueDepth >= maxQueueLength) {
    throw createThresholdEcdsaCommitQueueOverflowError(accountKey, maxQueueLength);
  }

  return await new Promise<T>((resolve, reject) => {
    let item!: ThresholdEcdsaCommitQueueItem;
    let settled = false;
    const rejectOnce = (error: unknown): void => {
      if (settled) return;
      settled = true;
      clearQueueItemTimeout(item);
      reject(error);
    };
    const resolveOnce = (value: T): void => {
      if (settled) return;
      settled = true;
      clearQueueItemTimeout(item);
      resolve(value);
    };
    item = {
      enqueuedAtMs: Date.now(),
      timeoutMs: queueTimeoutMs,
      shouldAbort: args.shouldAbort,
      timeoutHandle: null,
      isSettled: () => settled,
      reject: rejectOnce,
      run: async () => {
        if (args.shouldAbort?.()) {
          throw createThresholdEcdsaCommitQueueCancelledError(accountKey);
        }
        const result = await args.task();
        resolveOnce(result);
      },
    };
    item.timeoutHandle = setTimeout(() => {
      if (item.isSettled()) return;
      const idx = state.items.indexOf(item);
      if (idx >= 0) {
        state.items.splice(idx, 1);
      }
      rejectOnce(createThresholdEcdsaCommitQueueTimeoutError(accountKey, queueTimeoutMs));
      if (!state.running && state.items.length === 0 && args.queueByAccount.get(accountKey) === state) {
        args.queueByAccount.delete(accountKey);
      }
    }, queueTimeoutMs);
    state.items.push(item);
    scheduleQueueDrain(args.queueByAccount, accountKey);
  });
}
