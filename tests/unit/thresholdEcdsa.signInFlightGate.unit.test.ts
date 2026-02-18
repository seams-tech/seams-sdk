import { expect, test } from '@playwright/test';
import {
  withThresholdEcdsaSignInFlightGate,
} from '@/core/signing/api/thresholdEcdsaSignInFlightGate';

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

test.describe('threshold ECDSA sign in-flight gate', () => {
  test('fails fast with signing_in_progress for concurrent same-account signing', async () => {
    const inFlightByAccount = new Set<string>();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaSignInFlightGate({
      inFlightByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'first-ok';
      },
    });

    await Promise.resolve();
    expect(inFlightByAccount.has('alice.testnet')).toBe(true);

    await expect(withThresholdEcdsaSignInFlightGate({
      inFlightByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => 'second-ok',
    })).rejects.toMatchObject({ code: 'signing_in_progress' });

    blocker.resolve();
    await expect(first).resolves.toBe('first-ok');
    expect(inFlightByAccount.size).toBe(0);
  });

  test('releases lock after failure so later request can proceed', async () => {
    const inFlightByAccount = new Set<string>();

    await expect(withThresholdEcdsaSignInFlightGate({
      inFlightByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        throw new Error('boom');
      },
    })).rejects.toThrow('boom');

    await expect(withThresholdEcdsaSignInFlightGate({
      inFlightByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => 'after-failure',
    })).resolves.toBe('after-failure');
  });

  test('allows concurrent requests for different accounts', async () => {
    const inFlightByAccount = new Set<string>();
    const blocker = deferred<void>();

    const first = withThresholdEcdsaSignInFlightGate({
      inFlightByAccount,
      nearAccountId: 'alice.testnet',
      enabled: true,
      task: async () => {
        await blocker.promise;
        return 'alice-ok';
      },
    });

    await Promise.resolve();
    await expect(withThresholdEcdsaSignInFlightGate({
      inFlightByAccount,
      nearAccountId: 'bob.testnet',
      enabled: true,
      task: async () => 'bob-ok',
    })).resolves.toBe('bob-ok');

    blocker.resolve();
    await expect(first).resolves.toBe('alice-ok');
  });
});
