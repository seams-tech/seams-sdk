import { expect, test } from '@playwright/test';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearThresholdEcdsaSigningQueue,
  resolveThresholdEcdsaSigningQueueKey,
  type ThresholdEcdsaSigningQueueByKey,
  withThresholdEcdsaSigningQueue,
} from '@/core/signingEngine/threshold/ecdsa/signingQueue';

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

test.describe('threshold ECDSA signing operation queue', () => {
  test('accepts overlapping Tempo and Arc requests for one wallet in FIFO order', async () => {
    const queueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const queueKey = resolveThresholdEcdsaSigningQueueKey({ walletId });
    const blocker = deferred<void>();
    const order: string[] = [];

    const first = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey,
      walletId,
      enabled: true,
      task: async () => {
        order.push('first:start');
        await blocker.promise;
        order.push('first:end');
        return 'tempo-ok';
      },
    });

    const second = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey,
      walletId,
      enabled: true,
      task: async () => {
        order.push('second:start');
        order.push('second:end');
        return 'arc-ok';
      },
    });

    await Promise.resolve();
    expect(order).toEqual(['first:start']);

    blocker.resolve();
    await expect(first).resolves.toBe('tempo-ok');
    await expect(second).resolves.toBe('arc-ok');
    expect(order).toEqual(['first:start', 'first:end', 'second:start', 'second:end']);
  });

  test('allows concurrent requests for different wallets', async () => {
    const queueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
    const firstWalletId = toWalletId('alice.testnet');
    const secondWalletId = toWalletId('bob.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey: resolveThresholdEcdsaSigningQueueKey({ walletId: firstWalletId }),
      walletId: firstWalletId,
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'tempo-ok';
      },
    });

    await Promise.resolve();
    await expect(
      withThresholdEcdsaSigningQueue({
        queueByKey,
        queueKey: resolveThresholdEcdsaSigningQueueKey({ walletId: secondWalletId }),
        walletId: secondWalletId,
        enabled: true,
        task: async () => 'evm-ok',
      }),
    ).resolves.toBe('evm-ok');

    blocker.resolve();
    await expect(first).resolves.toBe('tempo-ok');
  });

  test('continues queue processing after a failed request', async () => {
    const queueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');

    await expect(
      withThresholdEcdsaSigningQueue({
        queueByKey,
        queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
        walletId,
        enabled: true,
        task: async () => {
          throw new Error('boom');
        },
      }),
    ).rejects.toThrow('boom');

    await expect(
      withThresholdEcdsaSigningQueue({
        queueByKey,
        queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
        walletId,
        enabled: true,
        task: async () => 'after-failure',
      }),
    ).resolves.toBe('after-failure');
  });

  test('fails fast with commit_queue_overflow when queue depth exceeds max for a queueKey', async () => {
    const queueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
      walletId,
      enabled: true,
      maxQueueLength: 1,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await expect(
      withThresholdEcdsaSigningQueue({
        queueByKey,
        queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
        walletId,
        enabled: true,
        maxQueueLength: 1,
        task: async () => 'second-ok',
      }),
    ).rejects.toMatchObject({ code: 'commit_queue_overflow' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });

  test('formats server-allocated wallet ids in queue errors without NEAR account validation', async () => {
    const queueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
    const walletId = toWalletId('frost-vermillion-k7p9m2');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
      walletId,
      enabled: true,
      maxQueueLength: 1,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await expect(
      withThresholdEcdsaSigningQueue({
        queueByKey,
        queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
        walletId,
        enabled: true,
        maxQueueLength: 1,
        task: async () => 'second-ok',
      }),
    ).rejects.toThrow('frost-vermillion-k7p9m2');

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });

  test('fails queued requests with commit_queue_timeout before task start', async () => {
    const queueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
      walletId,
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await expect(
      withThresholdEcdsaSigningQueue({
        queueByKey,
        queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
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
    const queueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
    const walletId = toWalletId('alice.testnet');
    const blocker = deferred<void>();

    const first = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
      walletId,
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });
    const second = withThresholdEcdsaSigningQueue({
      queueByKey,
      queueKey: 'wallet:alice.testnet:evm-family-ecdsa',
      walletId,
      enabled: true,
      task: async () => 'second-ok',
    });

    clearThresholdEcdsaSigningQueue(queueByKey);
    await expect(second).rejects.toMatchObject({ code: 'cancelled' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
  });
});

test.describe('threshold ECDSA signing queue key resolver', () => {
  test('binds every EVM-family chain to the wallet lifecycle queue', async () => {
    const key = resolveThresholdEcdsaSigningQueueKey({
      walletId: toWalletId('alice.testnet'),
    });
    expect(key).toBe('wallet:alice.testnet:evm-family-ecdsa');
  });

  test('derivation is deterministic for one wallet across concurrent chain requests', async () => {
    const input = {
      walletId: toWalletId('alice.testnet'),
    };
    const first = resolveThresholdEcdsaSigningQueueKey(input);
    const second = resolveThresholdEcdsaSigningQueueKey(input);
    expect(first).toBe(second);
  });
});
