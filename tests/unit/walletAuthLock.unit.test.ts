import { expect, test } from '@playwright/test';
import {
  lockDomain,
  type WalletLockDomainDeps,
} from '../../packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth';

type LockFixture = {
  deps: WalletLockDomainDeps;
  calls: {
    clearNonce: number;
    clearEcdsaQueue: number;
    clearEcdsaRecords: number;
    clearWarmMaterial: number;
    hostLock: number;
  };
};

function createLockFixture(args: {
  useWalletIframe: boolean;
  hostLock: () => Promise<unknown>;
}): LockFixture {
  const calls = {
    clearNonce: 0,
    clearEcdsaQueue: 0,
    clearEcdsaRecords: 0,
    clearWarmMaterial: 0,
    hostLock: 0,
  };
  const deps: WalletLockDomainDeps = {
    getContext: () => ({
      signingEngine: {
        getNonceCoordinator: () => ({
          clearAll(): void {
            calls.clearNonce += 1;
          },
        }),
        clearThresholdEcdsaSigningQueue(): void {
          calls.clearEcdsaQueue += 1;
        },
        clearAllThresholdEcdsaSessionRecords(): void {
          calls.clearEcdsaRecords += 1;
        },
        async clearVolatileWarmSigningMaterial(): Promise<void> {
          calls.clearWarmMaterial += 1;
        },
      },
    }),
    walletIframe: {
      shouldUseWalletIframe: () => args.useWalletIframe,
      requireRouter: async () => ({
        lock: async () => {
          calls.hostLock += 1;
          return await args.hostLock();
        },
      }),
    },
  };
  return { deps, calls };
}

test.describe('wallet lock lifecycle', () => {
  test('clears local runtime state before acknowledging direct-mode lock', async () => {
    const fixture = createLockFixture({
      useWalletIframe: false,
      hostLock: async () => undefined,
    });

    await lockDomain(fixture.deps);

    expect(fixture.calls).toEqual({
      clearNonce: 1,
      clearEcdsaQueue: 1,
      clearEcdsaRecords: 1,
      clearWarmMaterial: 1,
      hostLock: 0,
    });
  });

  test('propagates wallet-host lock failure after local cleanup', async () => {
    const fixture = createLockFixture({
      useWalletIframe: true,
      hostLock: async () => {
        throw new Error('wallet host lock failed');
      },
    });

    await expect(lockDomain(fixture.deps)).rejects.toThrow('wallet host lock failed');
    expect(fixture.calls).toEqual({
      clearNonce: 1,
      clearEcdsaQueue: 1,
      clearEcdsaRecords: 1,
      clearWarmMaterial: 1,
      hostLock: 1,
    });
  });
});
