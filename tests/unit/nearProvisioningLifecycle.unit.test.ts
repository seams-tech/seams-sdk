import { expect, test } from '@playwright/test';
import {
  getWalletNearProvisioningState,
  setWalletNearProvisioningState,
} from '../../packages/wallet/src/core/signingEngine/flows/registration/accountLifecycle';
import {
  publishNearProvisioningState,
  readNearProvisioningState,
  reconcileNearProvisioningOnLoad,
  resetNearProvisioningRegistryForTests,
  runSingleFlightNearProvisioning,
  subscribeToNearProvisioning,
} from '../../packages/wallet/src/core/signingEngine/flows/registration/nearProvisioningRegistry';
import type {
  NearProvisioningState,
  NearProvisioningWriteV1,
} from '../../packages/wallet/src/core/types/seams';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import type { ProfileRecord } from '../../packages/wallet/src/core/indexedDB/passkeyClientDB.types';
import {
  createNearProvisioningStateChangedEvent,
  parseSdkLifecycleEvent,
} from '../../packages/wallet/src/core/types/sdkSentEvents';
import { createNearProvisioningProfileRecordFixture } from './helpers/nearProvisioningLifecycle.fixtures';

/**
 * Refactor 94 Phase 6. The durable wallet-profile record is authoritative for
 * NEAR provisioning; the page registry mirrors it and owns only the live
 * same-tab promise. These cover the durable write, and what a reload must make
 * of a record that was still in flight when the tab died.
 */

/** Stands in for the wallet profile store, merging like `profileRow` does. */
function createProfileStore() {
  const rows = new Map<string, ProfileRecord>();
  return {
    rows,
    async getProfile(profileId: string): Promise<ProfileRecord | undefined> {
      return rows.get(profileId);
    },
    async upsertProfile(input: {
      profileId: string;
      nearProvisioning?: NearProvisioningState;
    }): Promise<ProfileRecord> {
      const existing = rows.get(input.profileId);
      const next = createNearProvisioningProfileRecordFixture({
        profileId: input.profileId,
        nearProvisioning: input.nearProvisioning ?? existing?.nearProvisioning,
        existing,
      });
      rows.set(input.profileId, next);
      return next;
    },
  };
}

function depsFor(store: ReturnType<typeof createProfileStore>) {
  return { accountStore: store } as unknown as Parameters<typeof setWalletNearProvisioningState>[0];
}

const WALLET_ID = walletIdFromString('provisioning-wallet.testnet');

test('the public lifecycle boundary parses NEAR provisioning events precisely', () => {
  const event = createNearProvisioningStateChangedEvent({
    walletId: WALLET_ID,
    state: {
      status: 'near_ready',
      updatedAtMs: 1_700_000_000_000,
      nearAccountId: String(WALLET_ID),
    },
  });
  expect(parseSdkLifecycleEvent({ ...event, privateKey: 'must-not-cross' })).toEqual(event);
  expect(
    parseSdkLifecycleEvent({
      ...event,
      state: { status: 'near_ready', updatedAtMs: 1_700_000_000_000 },
    }),
  ).toBeNull();
});

test('each provisioning status is written durably to the wallet profile', async () => {
  resetNearProvisioningRegistryForTests();
  const store = createProfileStore();
  const deps = depsFor(store);

  await setWalletNearProvisioningState(deps, {
    walletId: String(WALLET_ID),
    status: 'near_pending',
  });
  expect(store.rows.get(String(WALLET_ID))?.nearProvisioning?.status).toBe('near_pending');

  await setWalletNearProvisioningState(deps, {
    walletId: String(WALLET_ID),
    status: 'near_provisioning',
  });
  expect(store.rows.get(String(WALLET_ID))?.nearProvisioning?.status).toBe('near_provisioning');

  await setWalletNearProvisioningState(deps, {
    walletId: String(WALLET_ID),
    status: 'near_ready',
    nearAccountId: String(WALLET_ID),
  });
  const ready = store.rows.get(String(WALLET_ID))?.nearProvisioning;
  expect(ready).toMatchObject({ status: 'near_ready', nearAccountId: String(WALLET_ID) });

  await setWalletNearProvisioningState(deps, {
    walletId: String(WALLET_ID),
    status: 'near_failed_retryable',
    errorCode: 'near_seal_failed',
  });
  expect(store.rows.get(String(WALLET_ID))?.nearProvisioning).toMatchObject({
    status: 'near_failed_retryable',
    errorCode: 'near_seal_failed',
  });
});

test('the public read survives loss of page-owned registry state', async () => {
  const store = createProfileStore();
  const deps = depsFor(store);
  await setWalletNearProvisioningState(deps, {
    walletId: String(WALLET_ID),
    status: 'near_pending',
  });
  resetNearProvisioningRegistryForTests();

  await expect(getWalletNearProvisioningState(deps, WALLET_ID)).resolves.toMatchObject({
    status: 'near_pending',
  });
});

for (const interrupted of ['near_pending', 'near_provisioning'] as const) {
  test(`a reload converts a persisted ${interrupted} record to a durable retryable failure`, async () => {
    /* Tab #1 gets as far as `interrupted` and then goes away. */
    const store = createProfileStore();
    const deps = depsFor(store);
    await setWalletNearProvisioningState(deps, {
      walletId: String(WALLET_ID),
      status: interrupted,
    });
    expect(store.rows.get(String(WALLET_ID))?.nearProvisioning?.status).toBe(interrupted);

    /* Tab #2: a fresh registry against the same store. Neither the live factor
       nor the in-flight promise survived, so nothing can finish that attempt. */
    resetNearProvisioningRegistryForTests();
    expect(readNearProvisioningState(WALLET_ID)).toBeNull();

    const converged = await reconcileNearProvisioningOnLoad({
      walletId: WALLET_ID,
      persisted: store.rows.get(String(WALLET_ID))?.nearProvisioning,
      nowMs: 1_700_000_000_000,
      persist: (write: NearProvisioningWriteV1) => setWalletNearProvisioningState(deps, write),
    });

    /* Converged in the registry... */
    expect(converged).toMatchObject({
      status: 'near_failed_retryable',
      errorCode: 'near_provisioning_interrupted',
    });
    expect(readNearProvisioningState(WALLET_ID)?.status).toBe('near_failed_retryable');
    /* ...and durably, so a third load does not see the stale in-flight status. */
    expect(store.rows.get(String(WALLET_ID))?.nearProvisioning).toMatchObject({
      status: 'near_failed_retryable',
      errorCode: 'near_provisioning_interrupted',
    });
  });
}

test('a reload leaves a settled record alone', async () => {
  const store = createProfileStore();
  const deps = depsFor(store);
  await setWalletNearProvisioningState(deps, {
    walletId: String(WALLET_ID),
    status: 'near_ready',
    nearAccountId: String(WALLET_ID),
  });
  resetNearProvisioningRegistryForTests();

  const converged = await reconcileNearProvisioningOnLoad({
    walletId: WALLET_ID,
    persisted: store.rows.get(String(WALLET_ID))?.nearProvisioning,
    nowMs: 1_700_000_000_000,
    persist: (write: NearProvisioningWriteV1) => setWalletNearProvisioningState(deps, write),
  });

  expect(converged).toMatchObject({ status: 'near_ready', nearAccountId: String(WALLET_ID) });
  expect(store.rows.get(String(WALLET_ID))?.nearProvisioning?.status).toBe('near_ready');
});

test('concurrent first-NEAR requests join one provisioning attempt', async () => {
  resetNearProvisioningRegistryForTests();
  let attempts = 0;
  let release: (() => void) | null = null;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const attempt = async (): Promise<NearProvisioningState> => {
    attempts += 1;
    await gate;
    return { status: 'near_ready', updatedAtMs: 1, nearAccountId: String(WALLET_ID) };
  };

  const first = runSingleFlightNearProvisioning({
    walletId: WALLET_ID,
    nowMs: () => 1,
    attempt,
  });
  const second = runSingleFlightNearProvisioning({
    walletId: WALLET_ID,
    nowMs: () => 1,
    attempt,
  });
  /* Joined, not raced: two commits against one ceremony would be a duplicate
     side effect. */
  expect(second).toBe(first);
  expect(readNearProvisioningState(WALLET_ID)?.status).toBe('near_provisioning');

  release?.();
  const [a, b] = await Promise.all([first, second]);
  expect(attempts).toBe(1);
  expect(a).toBe(b);
  expect(readNearProvisioningState(WALLET_ID)?.status).toBe('near_ready');
});

test('a throwing attempt settles as retryable rather than rejecting', async () => {
  resetNearProvisioningRegistryForTests();
  const observed: string[] = [];
  const unsubscribe = subscribeToNearProvisioning((_walletId, state) =>
    observed.push(state.status),
  );
  try {
    const settled = await runSingleFlightNearProvisioning({
      walletId: WALLET_ID,
      nowMs: () => 1,
      attempt: async () => {
        throw new Error('ceremony died');
      },
    });
    expect(settled.status).toBe('near_failed_retryable');
    expect(observed).toEqual(['near_provisioning', 'near_failed_retryable']);
  } finally {
    unsubscribe();
  }
});

test('a failing subscriber does not stop the others from observing', async () => {
  resetNearProvisioningRegistryForTests();
  const seen: string[] = [];
  const unsubscribeBad = subscribeToNearProvisioning(() => {
    throw new Error('subscriber exploded');
  });
  const unsubscribeGood = subscribeToNearProvisioning((_walletId, state) =>
    seen.push(state.status),
  );
  try {
    publishNearProvisioningState(WALLET_ID, { status: 'near_pending', updatedAtMs: 1 });
    expect(seen).toEqual(['near_pending']);
  } finally {
    unsubscribeBad();
    unsubscribeGood();
  }
});
