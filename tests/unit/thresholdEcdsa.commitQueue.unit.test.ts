import { expect, test } from '@playwright/test';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearThresholdEcdsaCommitQueue,
  resolveThresholdEcdsaCommitQueueKey,
  type ThresholdEcdsaCommitQueueByKey,
  withThresholdEcdsaCommitQueue,
} from '@/core/signingEngine/threshold/ecdsa/commitQueue';

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
  test('serializes concurrent requests sharing the same queueKey in FIFO order', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();
    const order: string[] = [];

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      walletId,
      enabled: true,
      task: async () => {
        order.push('first:start');
        await blocker.promise;
        order.push('first:end');
        return 'first-ok';
      },
    });

    const second = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      walletId,
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

  test('allows concurrent requests for different queueKeys even on the same account', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      walletId,
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'tempo-ok';
      },
    });

    await Promise.resolve();
    await expect(
      withThresholdEcdsaCommitQueue({
        queueByKey,
        queueKey: 'session:evm:tsess-2',
        walletId,
        enabled: true,
        task: async () => 'evm-ok',
      }),
    ).resolves.toBe('evm-ok');

    blocker.resolve();
    await expect(first).resolves.toBe('tempo-ok');
  });

  test('continues queue processing after a failed request', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');

    await expect(
      withThresholdEcdsaCommitQueue({
        queueByKey,
        queueKey: 'session:tempo:tsess-1',
        walletId,
        enabled: true,
        task: async () => {
          throw new Error('boom');
        },
      }),
    ).rejects.toThrow('boom');

    await expect(
      withThresholdEcdsaCommitQueue({
        queueByKey,
        queueKey: 'session:tempo:tsess-1',
        walletId,
        enabled: true,
        task: async () => 'after-failure',
      }),
    ).resolves.toBe('after-failure');
  });

  test('fails fast with commit_queue_overflow when queue depth exceeds max for a queueKey', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      walletId,
      enabled: true,
      maxQueueLength: 1,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await expect(
      withThresholdEcdsaCommitQueue({
        queueByKey,
        queueKey: 'session:tempo:tsess-1',
        walletId,
        enabled: true,
        maxQueueLength: 1,
        task: async () => 'second-ok',
      }),
    ).rejects.toMatchObject({ code: 'commit_queue_overflow' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });

  test('fails queued requests with commit_queue_timeout before task start', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      walletId,
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await expect(
      withThresholdEcdsaCommitQueue({
        queueByKey,
        queueKey: 'session:tempo:tsess-1',
        walletId,
        enabled: true,
        queueTimeoutMs: 10,
        task: async () => 'second-ok',
      }),
    ).rejects.toMatchObject({ code: 'commit_queue_timeout' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });

  test('clearing queue cancels pending requests', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      walletId,
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });
    const second = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      walletId,
      enabled: true,
      task: async () => 'second-ok',
    });

    clearThresholdEcdsaCommitQueue(queueByKey);
    await expect(second).rejects.toMatchObject({ code: 'cancelled' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });
});

test.describe('threshold ECDSA commit queue key resolver', () => {
  test('prefers session key when thresholdSessionId exists', async () => {
    const key = resolveThresholdEcdsaCommitQueueKey({
      chainTarget: { kind: 'tempo', chainId: 1, networkSlug: 'tempo-1' },
      thresholdSessionId: 'tsess-abc',
    });
    expect(key).toBe('session:tempo:1:tsess-abc');
  });

  test('throws when thresholdSessionId is missing', async () => {
    expect(() =>
      resolveThresholdEcdsaCommitQueueKey({
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'evm-1' },
        thresholdSessionId: '',
      }),
    ).toThrow('[SigningEngine] threshold ECDSA commit queue requires non-empty thresholdSessionId');
  });

  test('derivation is deterministic for identical inputs', async () => {
    const input = {
      chainTarget: { kind: 'tempo' as const, chainId: 1, networkSlug: 'tempo-1' },
      thresholdSessionId: 'tsess-abc',
    };
    const first = resolveThresholdEcdsaCommitQueueKey(input);
    const second = resolveThresholdEcdsaCommitQueueKey(input);
    expect(first).toBe(second);
  });
});
