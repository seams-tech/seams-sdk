import { normalizeBoundedPositiveInteger } from '@shared/utils/normalize';

export type ThresholdCommitQueueErrorCode =
  | 'commit_queue_overflow'
  | 'commit_queue_timeout'
  | 'cancelled';

export type ThresholdCommitQueueCancelledReason = 'cancelled' | 'queue_cleared';

export type ThresholdCommitQueueError = Error & { code: ThresholdCommitQueueErrorCode };

type ThresholdCommitQueueItem = {
  enqueuedAtMs: number;
  timeoutMs: number;
  shouldAbort?: () => boolean;
  timeoutHandle: ReturnType<typeof setTimeout> | null;
  isSettled: () => boolean;
  run: () => Promise<void>;
  reject: (error: unknown) => void;
  makeCancelledError: (reason: ThresholdCommitQueueCancelledReason) => unknown;
  makeTimeoutError: (timeoutMs: number) => unknown;
};

type ThresholdCommitQueueState = {
  running: boolean;
  items: ThresholdCommitQueueItem[];
};

export type ThresholdCommitQueueByKey = Map<string, ThresholdCommitQueueState>;

export type ThresholdCommitQueueErrorFactory = {
  makeOverflowError: (queueKey: string, maxQueueLength: number) => unknown;
  makeTimeoutError: (queueKey: string, timeoutMs: number) => unknown;
  makeCancelledError: (queueKey: string, reason: ThresholdCommitQueueCancelledReason) => unknown;
};

const DEFAULT_MAX_QUEUE_LENGTH = 8;
const DEFAULT_QUEUE_TIMEOUT_MS = 45_000;

function normalizeQueueLimit(value: unknown, fallback: number): number {
  return normalizeBoundedPositiveInteger(value, {
    fallback,
    min: 1,
  });
}

function getOrCreateQueueState(
  queueByKey: ThresholdCommitQueueByKey,
  queueKey: string,
): ThresholdCommitQueueState {
  const existing = queueByKey.get(queueKey);
  if (existing) return existing;
  const created: ThresholdCommitQueueState = {
    running: false,
    items: [],
  };
  queueByKey.set(queueKey, created);
  return created;
}

function clearQueueItemTimeout(item: ThresholdCommitQueueItem): void {
  if (!item.timeoutHandle) return;
  clearTimeout(item.timeoutHandle);
  item.timeoutHandle = null;
}

async function drainQueueForKey(
  queueByKey: ThresholdCommitQueueByKey,
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
        item.reject(item.makeCancelledError('cancelled'));
        continue;
      }
      if (Date.now() - item.enqueuedAtMs > item.timeoutMs) {
        item.reject(item.makeTimeoutError(item.timeoutMs));
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

export function clearThresholdCommitQueue(queueByKey: ThresholdCommitQueueByKey): void {
  for (const state of queueByKey.values()) {
    for (const item of state.items) {
      clearQueueItemTimeout(item);
      item.reject(item.makeCancelledError('queue_cleared'));
    }
    state.items.length = 0;
  }
  queueByKey.clear();
}

export async function withThresholdCommitQueue<T>(args: {
  queueByKey: ThresholdCommitQueueByKey;
  queueKey: string;
  enabled: boolean;
  shouldAbort?: () => boolean;
  maxQueueLength?: number;
  queueTimeoutMs?: number;
  task: () => Promise<T>;
  errors: ThresholdCommitQueueErrorFactory;
}): Promise<T> {
  if (!args.enabled) return await args.task();

  const queueKey = String(args.queueKey || '').trim();
  if (!queueKey) {
    throw new Error('[SigningEngine] threshold commit queue requires non-empty queueKey');
  }
  const maxQueueLength = normalizeQueueLimit(args.maxQueueLength, DEFAULT_MAX_QUEUE_LENGTH);
  const queueTimeoutMs = normalizeQueueLimit(args.queueTimeoutMs, DEFAULT_QUEUE_TIMEOUT_MS);
  const state = getOrCreateQueueState(args.queueByKey, queueKey);
  const queueDepth = state.items.length + (state.running ? 1 : 0);
  if (queueDepth >= maxQueueLength) {
    throw args.errors.makeOverflowError(queueKey, maxQueueLength);
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

    const makeCancelledError = (reason: ThresholdCommitQueueCancelledReason): unknown =>
      args.errors.makeCancelledError(queueKey, reason);
    const makeTimeoutError = (timeoutMs: number): unknown =>
      args.errors.makeTimeoutError(queueKey, timeoutMs);

    const item: ThresholdCommitQueueItem = {
      enqueuedAtMs: Date.now(),
      timeoutMs: queueTimeoutMs,
      shouldAbort: args.shouldAbort,
      timeoutHandle: null,
      isSettled: () => settled,
      reject: rejectOnce,
      makeCancelledError,
      makeTimeoutError,
      run: async () => {
        if (args.shouldAbort?.()) {
          throw makeCancelledError('cancelled');
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
      rejectOnce(makeTimeoutError(queueTimeoutMs));
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
    void drainQueueForKey(args.queueByKey, queueKey);
  });
}
