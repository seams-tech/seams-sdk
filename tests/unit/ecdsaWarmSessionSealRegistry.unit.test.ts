import { expect, test } from '@playwright/test';
import {
  awaitEcdsaWarmSessionSeal,
  readEcdsaWarmSessionSealState,
  resetEcdsaWarmSessionSealRegistryForTests,
  runSingleFlightEcdsaWarmSessionSeal,
} from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaWarmSessionSealRegistry';

/**
 * Refactor 94C. The passkey warm-session seal is deferred off the blocking
 * registration path; this registry is the typed pending state that replaces
 * awaiting it inline. Same-tab readers of sealed records await the attempt;
 * a failed seal degrades to re-auth and never faults the wallet.
 */

const WALLET = 'seal-wallet.testnet';

test('a deferred seal publishes pending, then sealed', async () => {
  resetEcdsaWarmSessionSealRegistryForTests();
  let release: (() => void) | null = null;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  const settled = runSingleFlightEcdsaWarmSessionSeal({
    walletId: WALLET,
    attempt: () => gate,
  });
  expect(readEcdsaWarmSessionSealState(WALLET)).toEqual({ status: 'seal_pending' });

  release?.();
  await expect(settled).resolves.toEqual({ status: 'sealed' });
  expect(readEcdsaWarmSessionSealState(WALLET)).toEqual({ status: 'sealed' });
});

test('concurrent seal requests join one attempt', async () => {
  resetEcdsaWarmSessionSealRegistryForTests();
  let attempts = 0;
  let release: (() => void) | null = null;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const attempt = async () => {
    attempts += 1;
    await gate;
  };

  const first = runSingleFlightEcdsaWarmSessionSeal({ walletId: WALLET, attempt });
  const second = runSingleFlightEcdsaWarmSessionSeal({ walletId: WALLET, attempt });
  expect(second).toBe(first);

  release?.();
  await first;
  expect(attempts).toBe(1);
});

test('a throwing seal settles as reauth-required instead of rejecting', async () => {
  resetEcdsaWarmSessionSealRegistryForTests();
  const settled = await runSingleFlightEcdsaWarmSessionSeal({
    walletId: WALLET,
    attempt: async () => {
      throw new Error('seal transport died');
    },
  });
  /* The wallet is already durable; a missing seal only means the next reload
     re-authenticates. The failure is typed, never thrown. */
  expect(settled).toEqual({
    status: 'seal_failed_reauth_required',
    errorCode: 'warm_session_seal_failed',
  });
  expect(readEcdsaWarmSessionSealState(WALLET)).toEqual(settled);
});

test('awaiting resolves through the pending attempt and null when never scheduled', async () => {
  resetEcdsaWarmSessionSealRegistryForTests();
  await expect(awaitEcdsaWarmSessionSeal('never-registered.testnet')).resolves.toBeNull();

  let release: (() => void) | null = null;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  void runSingleFlightEcdsaWarmSessionSeal({ walletId: WALLET, attempt: () => gate });

  const awaited = awaitEcdsaWarmSessionSeal(WALLET);
  release?.();
  await expect(awaited).resolves.toEqual({ status: 'sealed' });
});

test('the restore coordinator waits out a pending seal before listing sealed records', async () => {
  resetEcdsaWarmSessionSealRegistryForTests();
  const { restorePersistedSessionForSigningCommand } = await import(
    '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator'
  );

  let sealSettled = false;
  let release: (() => void) | null = null;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  void runSingleFlightEcdsaWarmSessionSeal({
    walletId: WALLET,
    attempt: async () => {
      await gate;
      sealSettled = true;
    },
  });

  let listedAfterSeal: boolean | null = null;
  const restore = restorePersistedSessionForSigningCommand(
    {
      walletId: WALLET,
      authMethod: 'passkey',
      curve: 'ecdsa',
      chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1 },
      reason: 'transaction',
    } as never,
    {
      listExactSealedSessionsForWallet: async () => {
        /* The coordinator must not look for the record while the seal that
           writes it is still in flight. */
        listedAfterSeal = sealSettled;
        return [];
      },
      restoreSealedRecordForWallet: async () => 'deferred',
    } as never,
  );

  /* Give the coordinator a chance to run ahead wrongly before releasing. */
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(listedAfterSeal).toBeNull();
  release?.();
  await restore;
  expect(listedAfterSeal).toBe(true);
});
