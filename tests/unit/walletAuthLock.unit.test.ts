import { expect, test } from '@playwright/test';
import {
  lockDomain,
  type WalletLockDomainDeps,
} from '../../packages/wallet/src/SeamsWeb/operations/auth/walletAuth';
import {
  passkeyAuthenticatedWalletStateFixture,
  signedOutWalletStateFixture,
} from './helpers/walletAuthenticationState.fixtures';

type LockFixture = {
  deps: WalletLockDomainDeps;
  calls: {
    clearNonce: number;
    clearAuthentication: number;
    advanceLockGeneration: number;
    retireAuthorization: number;
    retiredWalletId: string | null;
    retirementCompleted: boolean;
    clearEcdsaQueue: number;
    clearWarmMaterial: number;
    hostLock: number;
  };
};

function createLockFixture(args: {
  useWalletIframe: boolean;
  hostLock: () => Promise<unknown>;
  authenticatedWalletId?: string;
  advanceLockGeneration?: (walletId: string) => Promise<number>;
  retireAuthorization?: () => Promise<void>;
  clearWarmMaterial?: () => Promise<void>;
}): LockFixture {
  const calls = {
    clearNonce: 0,
    clearAuthentication: 0,
    advanceLockGeneration: 0,
    retireAuthorization: 0,
    retiredWalletId: null,
    retirementCompleted: false,
    clearEcdsaQueue: 0,
    clearWarmMaterial: 0,
    hostLock: 0,
  };
  const authentication = args.authenticatedWalletId
    ? passkeyAuthenticatedWalletStateFixture(args.authenticatedWalletId)
    : signedOutWalletStateFixture();
  const deps: WalletLockDomainDeps = {
    getContext: () => ({
      signingEngine: {
        readWalletAuthenticationState() {
          return authentication;
        },
        clearWalletAuthentication(): void {
          calls.clearAuthentication += 1;
        },
        async advanceWalletLockGeneration(walletId): Promise<number> {
          calls.advanceLockGeneration += 1;
          if (args.advanceLockGeneration) return await args.advanceLockGeneration(String(walletId));
          return 1;
        },
        async retireActiveWalletSessionAuthorizationForLock(walletId): Promise<void> {
          calls.retireAuthorization += 1;
          calls.retiredWalletId = String(walletId);
          await args.retireAuthorization?.();
          calls.retirementCompleted = true;
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
    let releaseRetirement!: () => void;
    const retirement = new Promise<void>((resolve) => {
      releaseRetirement = resolve;
    });
    const fixture = createLockFixture({
      useWalletIframe: false,
      authenticatedWalletId: 'lock-target-wallet',
      retireAuthorization: () => retirement,
      hostLock: async () => undefined,
    });

    const lockPromise = lockDomain(fixture.deps);
    await expect.poll(() => fixture.calls.retireAuthorization).toBe(1);
    expect(fixture.calls.retiredWalletId).toBe('lock-target-wallet');
    expect(fixture.calls.clearAuthentication).toBe(0);

    releaseRetirement();
    await lockPromise;

    expect(fixture.calls).toEqual({
      clearNonce: 1,
      clearAuthentication: 1,
      advanceLockGeneration: 1,
      retireAuthorization: 1,
      retiredWalletId: 'lock-target-wallet',
      retirementCompleted: true,
      clearEcdsaQueue: 1,
      clearWarmMaterial: 1,
      hostLock: 0,
    });
  });

  test('clears runtime authentication and surfaces a lock-generation failure', async () => {
    const generationError = new Error('lock generation advance failed');
    const fixture = createLockFixture({
      useWalletIframe: false,
      authenticatedWalletId: 'lock-generation-failure-wallet',
      advanceLockGeneration: async () => {
        throw generationError;
      },
      hostLock: async () => undefined,
    });

    await expect(lockDomain(fixture.deps)).rejects.toBe(generationError);
    expect(fixture.calls.clearAuthentication).toBe(1);
    expect(fixture.calls.clearNonce).toBe(1);
    expect(fixture.calls.clearEcdsaQueue).toBe(1);
    expect(fixture.calls.clearWarmMaterial).toBe(1);
    expect(fixture.calls.retireAuthorization).toBe(0);
  });

  test('clears runtime authentication and surfaces session-retirement failure', async () => {
    const fixture = createLockFixture({
      useWalletIframe: false,
      authenticatedWalletId: 'session-retirement-failure-wallet',
      retireAuthorization: async () => {
        throw new Error('session retirement failed');
      },
      hostLock: async () => undefined,
    });

    await expect(lockDomain(fixture.deps)).rejects.toThrow('session retirement failed');
    expect(fixture.calls.advanceLockGeneration).toBe(1);
    expect(fixture.calls.retireAuthorization).toBe(1);
    expect(fixture.calls.clearAuthentication).toBe(1);
    expect(fixture.calls.clearNonce).toBe(1);
    expect(fixture.calls.clearEcdsaQueue).toBe(1);
    expect(fixture.calls.clearWarmMaterial).toBe(1);
  });

  test('propagates wallet-host lock failure while local cleanup continues', async () => {
    const fixture = createLockFixture({
      useWalletIframe: true,
      hostLock: async () => {
        throw new Error('wallet host lock failed');
      },
    });

    await expect(lockDomain(fixture.deps)).rejects.toThrow('wallet host lock failed');
    expect(fixture.calls.clearAuthentication).toBe(1);
    expect(fixture.calls.hostLock).toBe(1);
    await expect.poll(() => fixture.calls.clearNonce).toBe(1);
    await expect.poll(() => fixture.calls.clearEcdsaQueue).toBe(1);
    await expect.poll(() => fixture.calls.clearWarmMaterial).toBe(1);
  });

  test('acknowledges wallet-host lock before slow linked-device cleanup completes', async () => {
    let releaseWarmMaterial!: () => void;
    let warmMaterialCompleted = false;
    const warmMaterialCleanup = new Promise<void>((resolve) => {
      releaseWarmMaterial = resolve;
    });
    const fixture = createLockFixture({
      useWalletIframe: true,
      clearWarmMaterial: async () => {
        await warmMaterialCleanup;
        warmMaterialCompleted = true;
      },
      hostLock: async () => undefined,
    });

    const lockPromise = lockDomain(fixture.deps);
    await expect.poll(() => fixture.calls.hostLock).toBe(1);
    expect(fixture.calls.clearAuthentication).toBe(1);

    await lockPromise;
    expect(fixture.calls.clearWarmMaterial).toBe(1);
    expect(warmMaterialCompleted).toBe(false);

    releaseWarmMaterial();
    await expect.poll(() => warmMaterialCompleted).toBe(true);
  });
});
