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
