import { expect, test } from '@playwright/test';
import {
  clearThresholdEcdsaCommitQueue,
  type ThresholdEcdsaCommitQueueByAccount,
  withThresholdEcdsaCommitQueue,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue';

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value?: T) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value?: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = (value?: T) => res(value as T);
    reject = rej;
  });
  return { promise, resolve, reject };
}

test.describe('threshold ECDSA commit queue gate', () => {
  test('serializes concurrent same-account signing requests in FIFO order', async () => {
    const queueByAccount: ThresholdEcdsaCommitQueueByAccount = new Map();
    const blocker = deferred<void>();
    const order: string[] = [];

    const first = withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        order.push('first:start');
        await blocker.promise;
        order.push('first:end');
        return 'first-ok';
      },
    });

    const second = withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        order.push('second:start');
        order.push('second:end');
        return 'second-ok';
      },
    });

    await Promise.resolve();
    expect(order).toEqual(['first:start']);

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
    await expect(second).resolves.toBe('second-ok');
    expect(order).toEqual([
      'first:start',
      'first:end',
      'second:start',
      'second:end',
    ]);
  });

  test('allows concurrent requests for different accounts', async () => {
    const queueByAccount: ThresholdEcdsaCommitQueueByAccount = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'alice-ok';
      },
    });

    await Promise.resolve();
    await expect(withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'bob.testnet',
      enabled: true,
      task: async () => 'bob-ok',
    })).resolves.toBe('bob-ok');

    blocker.resolve();
    await expect(first).resolves.toBe('alice-ok');
  });

  test('continues queue processing after a failed request', async () => {
    const queueByAccount: ThresholdEcdsaCommitQueueByAccount = new Map();

    await expect(withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        throw new Error('boom');
      },
    })).rejects.toThrow('boom');

    await expect(withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => 'after-failure',
    })).resolves.toBe('after-failure');
  });

  test('fails fast with commit_queue_overflow when queue depth exceeds max', async () => {
    const queueByAccount: ThresholdEcdsaCommitQueueByAccount = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      maxQueueLength: 1,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await expect(withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      maxQueueLength: 1,
      task: async () => 'second-ok',
    })).rejects.toMatchObject({ code: 'commit_queue_overflow' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });

  test('fails queued requests with commit_queue_timeout before task start', async () => {
    const queueByAccount: ThresholdEcdsaCommitQueueByAccount = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await expect(withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      queueTimeoutMs: 10,
      task: async () => 'second-ok',
    })).rejects.toMatchObject({ code: 'commit_queue_timeout' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });

  test('clearing queue cancels pending requests', async () => {
    const queueByAccount: ThresholdEcdsaCommitQueueByAccount = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });
    const second = withThresholdEcdsaCommitQueue({
      queueByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => 'second-ok',
    });

    clearThresholdEcdsaCommitQueue(queueByAccount);
    await expect(second).rejects.toMatchObject({ code: 'cancelled' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });
});
