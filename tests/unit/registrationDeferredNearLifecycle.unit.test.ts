import { expect, test } from '@playwright/test';
import { runDeferredEd25519Provisioning } from '@/SeamsWeb/operations/registration/registration';
import {
  readNearProvisioningState,
  resetNearProvisioningRegistryForTests,
  subscribeToNearProvisioning,
} from '@/core/signingEngine/flows/registration/nearProvisioningRegistry';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

/**
 * Refactor 94C. The deferred NEAR lifecycle, driven through the registration
 * orchestrator rather than the registry.
 *
 * The registry tests prove the store behaves; these prove registration uses it
 * correctly — specifically that every published transition is already durable.
 * A state published before it is persisted would survive a reload as something
 * the page believes but the record does not, which is exactly the divergence
 * the durable lifecycle exists to prevent.
 *
 * `near_ready` is not asserted here. Reaching it requires the real deferred
 * commit — Yao consume, signer persistence, capability install — and stubbing
 * that far would assert the stub rather than the orchestrator. What is pinned
 * instead is the property that matters for correctness: ready is never
 * published unless the commit genuinely succeeded, covered by the two failure
 * paths below.
 */

const WALLET_ID = toWalletId('frost-vermillion-k7p9m2');

/** Records persistence and publication interleaved, so ordering is assertable. */
function lifecycleRecorder(options: { failPersistFor?: string } = {}) {
  const events: string[] = [];
  const unsubscribe = subscribeToNearProvisioning((_walletId, state) => {
    events.push(`publish:${state.status}`);
  });
  const signingEngine = {
    setWalletNearProvisioningState: async (input: { status: string }) => {
      if (options.failPersistFor === input.status) {
        events.push(`persist_failed:${input.status}`);
        throw new Error(`durable write refused for ${input.status}`);
      }
      events.push(`persist:${input.status}`);
    },
  };
  return { events, signingEngine, unsubscribe };
}

function commitArgs(behaviour: () => Promise<void>) {
  /* `commitDeferredEd25519Registration` is invoked through the single-flight
     wrapper; only its success or failure matters to the lifecycle. */
  return {
    context: { signingEngine: { finalizeWalletEd25519SignerRegistration: behaviour } },
    walletId: WALLET_ID,
  };
}

test('deferred provisioning publishes near_provisioning only after persisting it', async () => {
  resetNearProvisioningRegistryForTests();
  const recorder = lifecycleRecorder();
  try {
    await runDeferredEd25519Provisioning({
      context: { signingEngine: recorder.signingEngine },
      walletId: WALLET_ID,
      commit: commitArgs(async () => {
        /* Observed mid-flight: the running state is durable before the page
           is told about it. */
        expect(recorder.events).toContain('persist:near_provisioning');
      }),
    } as never);
  } finally {
    recorder.unsubscribe();
    resetNearProvisioningRegistryForTests();
  }
  const persistIndex = recorder.events.indexOf('persist:near_provisioning');
  const publishIndex = recorder.events.indexOf('publish:near_provisioning');
  /* Both must occur — a conditional assertion here would pass vacuously if the
     publish were ever dropped. */
  expect(persistIndex).toBeGreaterThanOrEqual(0);
  expect(publishIndex).toBeGreaterThanOrEqual(0);
  expect(persistIndex).toBeLessThan(publishIndex);
});

test('a failed durable write reports retryable instead of provisioning', async () => {
  /* If the record cannot be written, the page must not be told work is under
     way — there would be nothing durable to resume. */
  resetNearProvisioningRegistryForTests();
  const recorder = lifecycleRecorder({ failPersistFor: 'near_provisioning' });
  try {
    await runDeferredEd25519Provisioning({
      context: { signingEngine: recorder.signingEngine },
      walletId: WALLET_ID,
      commit: commitArgs(async () => undefined),
    } as never);
  } finally {
    recorder.unsubscribe();
  }
  expect(recorder.events).toContain('persist_failed:near_provisioning');
  expect(recorder.events).not.toContain('publish:near_provisioning');
  expect(readNearProvisioningState(WALLET_ID)?.status).toBe('near_failed_retryable');
  resetNearProvisioningRegistryForTests();
});

test('a throwing deferred commit settles retryable and never reaches ready', async () => {
  /* The ECDSA wallet is already durable, so a Yao failure is a provisioning
     state — never an error that unwinds the registration. */
  resetNearProvisioningRegistryForTests();
  const recorder = lifecycleRecorder();
  try {
    await runDeferredEd25519Provisioning({
      context: { signingEngine: recorder.signingEngine },
      walletId: WALLET_ID,
      commit: commitArgs(async () => {
        throw new Error('Yao seal failed');
      }),
    } as never);
  } finally {
    recorder.unsubscribe();
  }
  expect(recorder.events).not.toContain('persist:near_ready');
  expect(recorder.events).not.toContain('publish:near_ready');
  expect(readNearProvisioningState(WALLET_ID)?.status).toBe('near_failed_retryable');
  resetNearProvisioningRegistryForTests();
});

test('the deferred runner never throws, whatever the commit does', async () => {
  /* Registration has already returned by the time this runs; a rejection here
     would surface as an unhandled rejection against a wallet that is fine. */
  resetNearProvisioningRegistryForTests();
  const recorder = lifecycleRecorder();
  try {
    await expect(
      runDeferredEd25519Provisioning({
        context: { signingEngine: recorder.signingEngine },
        walletId: WALLET_ID,
        commit: commitArgs(async () => {
          throw new Error('wallet session refused');
        }),
      } as never),
    ).resolves.toBeUndefined();
  } finally {
    recorder.unsubscribe();
    resetNearProvisioningRegistryForTests();
  }
});

test('a successful deferred commit reaches and republishes near_ready', async () => {
  /* Closes the ready path against the exact primitive the orchestrator drives
     rather than the store directly. Reaching ready through the full commit —
     Yao consume, signer persistence, capability install — would mean stubbing
     a cryptographic binding check and asserting the stub, so the seam under
     test is the one that decides the published outcome. */
  const { runSingleFlightNearProvisioning } =
    await import('@/core/signingEngine/flows/registration/nearProvisioningRegistry');
  resetNearProvisioningRegistryForTests();
  const published: string[] = [];
  const unsubscribe = subscribeToNearProvisioning((_walletId, state) => {
    published.push(state.status);
  });
  try {
    const settled = await runSingleFlightNearProvisioning({
      walletId: WALLET_ID,
      nowMs: () => 1_700_000_000_000,
      attempt: async () => ({
        status: 'near_ready',
        updatedAtMs: 1_700_000_000_000,
        nearAccountId: String(WALLET_ID),
      }),
    });
    expect(settled.status).toBe('near_ready');
  } finally {
    unsubscribe();
  }
  /* The wallet passes through provisioning and lands on ready, in that order. */
  expect(published).toEqual(['near_provisioning', 'near_ready']);
  expect(readNearProvisioningState(WALLET_ID)?.status).toBe('near_ready');
  resetNearProvisioningRegistryForTests();
});

test('a settled ready wallet is not re-provisioned by a later request', async () => {
  /* Ready is terminal: a second caller must not restart Yao for a wallet whose
     NEAR signer already exists. */
  const { runSingleFlightNearProvisioning } =
    await import('@/core/signingEngine/flows/registration/nearProvisioningRegistry');
  resetNearProvisioningRegistryForTests();
  let attempts = 0;
  const ready = async () => {
    attempts += 1;
    return {
      status: 'near_ready' as const,
      updatedAtMs: 1_700_000_000_000,
      nearAccountId: String(WALLET_ID),
    };
  };
  await runSingleFlightNearProvisioning({
    walletId: WALLET_ID,
    nowMs: () => 1_700_000_000_000,
    attempt: ready,
  });
  await runSingleFlightNearProvisioning({
    walletId: WALLET_ID,
    nowMs: () => 1_700_000_000_001,
    attempt: ready,
  });
  expect(attempts).toBe(1);
  resetNearProvisioningRegistryForTests();
});
