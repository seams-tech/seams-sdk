import { expect, test } from '@playwright/test';
import {
  lockDomain,
  type WalletLockDomainDeps,
} from '../../packages/wallet/src/SeamsWeb/operations/auth/walletAuth';

type LockFixture = {
  deps: WalletLockDomainDeps;
  calls: {
    clearNonce: number;
    clearLinkedRefresh: number;
    clearAuthentication: number;
    clearEcdsaQueue: number;
    clearWarmMaterial: number;
    hostLock: number;
  };
};

function createLockFixture(args: {
  useWalletIframe: boolean;
  hostLock: () => Promise<unknown>;
  clearLinkedRefresh?: () => Promise<void>;
  clearWarmMaterial?: () => Promise<void>;
}): LockFixture {
  const calls = {
    clearNonce: 0,
    clearLinkedRefresh: 0,
    clearAuthentication: 0,
    clearEcdsaQueue: 0,
    clearWarmMaterial: 0,
    hostLock: 0,
  };
  const deps: WalletLockDomainDeps = {
    getContext: () => ({
      signingEngine: {
        async clearLinkedDeviceRefreshMaterial(): Promise<void> {
          calls.clearLinkedRefresh += 1;
          await args.clearLinkedRefresh?.();
        },
        clearWalletAuthentication(): void {
          calls.clearAuthentication += 1;
        },
        getNonceCoordinator: () => ({
          clearAll(): void {
            calls.clearNonce += 1;
          },
        }),
        clearThresholdEcdsaSigningQueue(): void {
          calls.clearEcdsaQueue += 1;
        },
        async clearVolatileWarmSigningMaterial(): Promise<void> {
          calls.clearWarmMaterial += 1;
          await args.clearWarmMaterial?.();
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
      clearLinkedRefresh: 1,
      clearAuthentication: 1,
      clearEcdsaQueue: 1,
      clearWarmMaterial: 1,
      hostLock: 0,
    });
  });

  test('propagates wallet-host lock failure while local cleanup continues', async () => {
    const fixture = createLockFixture({
      useWalletIframe: true,
      hostLock: async () => {
        throw new Error('wallet host lock failed');
      },
    });

    await expect(lockDomain(fixture.deps)).rejects.toThrow('wallet host lock failed');
    expect(fixture.calls.clearLinkedRefresh).toBe(1);
    expect(fixture.calls.clearAuthentication).toBe(1);
    expect(fixture.calls.hostLock).toBe(1);
    await expect.poll(() => fixture.calls.clearNonce).toBe(1);
    await expect.poll(() => fixture.calls.clearEcdsaQueue).toBe(1);
    await expect.poll(() => fixture.calls.clearWarmMaterial).toBe(1);
  });

  test('acknowledges wallet-host lock before slow linked-device cleanup completes', async () => {
    let releaseLinkedRefresh!: () => void;
    let releaseWarmMaterial!: () => void;
    let warmMaterialCompleted = false;
    const linkedRefreshCleanup = new Promise<void>((resolve) => {
      releaseLinkedRefresh = resolve;
    });
    const warmMaterialCleanup = new Promise<void>((resolve) => {
      releaseWarmMaterial = resolve;
    });
    const fixture = createLockFixture({
      useWalletIframe: true,
      clearLinkedRefresh: () => linkedRefreshCleanup,
      clearWarmMaterial: async () => {
        await warmMaterialCleanup;
        warmMaterialCompleted = true;
      },
      hostLock: async () => undefined,
    });

    const lockPromise = lockDomain(fixture.deps);
    await expect.poll(() => fixture.calls.hostLock).toBe(1);
    expect(fixture.calls.clearLinkedRefresh).toBe(1);
    expect(fixture.calls.clearAuthentication).toBe(1);

    await lockPromise;
    expect(fixture.calls.clearWarmMaterial).toBe(1);
    expect(warmMaterialCompleted).toBe(false);

    releaseLinkedRefresh();
    expect(warmMaterialCompleted).toBe(false);
    releaseWarmMaterial();
    await expect.poll(() => warmMaterialCompleted).toBe(true);
  });
});
