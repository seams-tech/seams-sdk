import { expect, test } from '@playwright/test';
import {
  clearThresholdEd25519CommitQueue,
  resolveThresholdEd25519CommitQueueKey,
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from '@/core/signingEngine/threshold/ed25519/commitQueue';

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

test.describe('threshold Ed25519 commit queue gate', () => {
  test('serializes concurrent requests sharing the same queueKey in FIFO order', async () => {
    const queueByKey: ThresholdEd25519CommitQueueByKey = new Map();
    const blocker = deferred<void>();
    const order: string[] = [];

    const first = withThresholdEd25519CommitQueue({
      queueByKey,
      queueKey: 'session:ed25519:tsess-1',
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        order.push('first:start');
        await blocker.promise;
        order.push('first:end');
        return 'first-ok';
      },
    });

    const second = withThresholdEd25519CommitQueue({
      queueByKey,
      queueKey: 'session:ed25519:tsess-1',
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
    expect(order).toEqual(['first:start', 'first:end', 'second:start', 'second:end']);
  });

  test('allows concurrent requests for different session keys on the same account', async () => {
    const queueByKey: ThresholdEd25519CommitQueueByKey = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEd25519CommitQueue({
      queueByKey,
      queueKey: 'session:ed25519:tsess-1',
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await Promise.resolve();
    await expect(
      withThresholdEd25519CommitQueue({
        queueByKey,
        queueKey: 'session:ed25519:tsess-2',
        nearAccountId: 'alice.testnet',
        enabled: true,
        task: async () => 'second-ok',
      }),
    ).resolves.toBe('second-ok');

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });

  test('clearing queue cancels pending requests', async () => {
    const queueByKey: ThresholdEd25519CommitQueueByKey = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEd25519CommitQueue({
      queueByKey,
      queueKey: 'session:ed25519:tsess-1',
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });
    const second = withThresholdEd25519CommitQueue({
      queueByKey,
      queueKey: 'session:ed25519:tsess-1',
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => 'second-ok',
    });

    clearThresholdEd25519CommitQueue(queueByKey);
    await expect(second).rejects.toMatchObject({ code: 'cancelled' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });
});

test.describe('threshold Ed25519 commit queue key resolver', () => {
  test('uses strict session-only key format', async () => {
    const key = resolveThresholdEd25519CommitQueueKey({
      thresholdSessionId: 'tsess-abc',
    });
    expect(key).toBe('session:ed25519:tsess-abc');
  });

  test('throws when thresholdSessionId is missing', async () => {
    expect(() =>
      resolveThresholdEd25519CommitQueueKey({
        thresholdSessionId: '',
      }),
    ).toThrow(
      '[SigningEngine] threshold Ed25519 commit queue requires non-empty thresholdSessionId',
    );
  });
});
