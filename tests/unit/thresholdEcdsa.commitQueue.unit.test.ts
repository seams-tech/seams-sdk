import { expect, test } from '@playwright/test';
import {
  clearThresholdEcdsaCommitQueue,
  resolveThresholdEcdsaCommitQueueKey,
  type ThresholdEcdsaCommitQueueByKey,
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
  test('serializes concurrent requests sharing the same queueKey in FIFO order', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const blocker = deferred<void>();
    const order: string[] = [];

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
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
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
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

  test('allows concurrent requests for different queueKeys even on the same account', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      nearAccountId: 'alice.testnet',
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
        nearAccountId: 'alice.testnet',
        enabled: true,
        task: async () => 'evm-ok',
      }),
    ).resolves.toBe('evm-ok');

    blocker.resolve();
    await expect(first).resolves.toBe('tempo-ok');
  });

  test('continues queue processing after a failed request', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();

    await expect(
      withThresholdEcdsaCommitQueue({
        queueByKey,
        queueKey: 'session:tempo:tsess-1',
        nearAccountId: 'alice.testnet',
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
        nearAccountId: 'alice.testnet',
        enabled: true,
        task: async () => 'after-failure',
      }),
    ).resolves.toBe('after-failure');
  });

  test('fails fast with commit_queue_overflow when queue depth exceeds max for a queueKey', async () => {
    const queueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      nearAccountId: 'alice.testnet',
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
        nearAccountId: 'alice.testnet',
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
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      nearAccountId: 'alice.testnet',
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
        nearAccountId: 'alice.testnet',
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
    const blocker = deferred<void>();

    const first = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });
    const second = withThresholdEcdsaCommitQueue({
      queueByKey,
      queueKey: 'session:tempo:tsess-1',
      nearAccountId: 'alice.testnet',
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
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      thresholdSessionId: 'tsess-abc',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'share',
    });
    expect(key).toBe('session:tempo:tsess-abc');
  });

  test('falls back to lane tuple when sessionId is missing', async () => {
    const key = resolveThresholdEcdsaCommitQueueKey({
      nearAccountId: 'alice.testnet',
      chain: 'evm',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'share+with/slash',
    });
    expect(key).toBe(
      `lane:evm:${encodeURIComponent('https://relay.example')}|${encodeURIComponent('relayer-key')}|${encodeURIComponent('share+with/slash')}`,
    );
  });

  test('falls back to account key when lane metadata is incomplete', async () => {
    const key = resolveThresholdEcdsaCommitQueueKey({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      relayerUrl: 'https://relay.example',
      relayerKeyId: '',
      clientVerifyingShareB64u: 'share',
    });
    expect(key).toBe('account:alice.testnet');
  });

  test('derivation is deterministic for identical inputs', async () => {
    const input = {
      nearAccountId: 'alice.testnet',
      chain: 'tempo' as const,
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'share',
    };
    const first = resolveThresholdEcdsaCommitQueueKey(input);
    const second = resolveThresholdEcdsaCommitQueueKey(input);
    expect(first).toBe(second);
  });
});
