import { expect, test } from '@playwright/test';
import {
  publishNearProvisioningState,
  resetNearProvisioningRegistryForTests,
} from '@/core/signingEngine/flows/registration/nearProvisioningRegistry';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  AVAILABLE_LANES_ECDSA_TARGET as ECDSA_TARGET,
  AVAILABLE_LANES_WALLET_ID as WALLET_ID,
  canonicalEcdsaAvailableLane,
  readAvailableLanesFixture as readAvailableLanes,
} from './helpers/availableSigningLanes.fixtures';

/**
 * Refactor 94C. An ECDSA wallet signs while its NEAR provisioning is unresolved.
 *
 * This is what deferring NEAR is *for*: registration returns a usable wallet
 * and NEAR settles afterwards. If lane availability ever started consulting
 * provisioning state, a mixed-plan wallet would go unsignable for the whole
 * window between activate and `near_ready` — the regression this guards.
 *
 * The reader is given no provisioning input today, so these pass structurally.
 * They are written against the public registry rather than the reader's
 * arguments precisely so that wiring provisioning in later fails here.
 */

const CANONICAL_LANE = canonicalEcdsaAvailableLane({
  chainTarget: ECDSA_TARGET,
  ecdsaThresholdKeyId: 'near-pending-material',
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
  authMethod: 'passkey',
});

/** The lane for the fixture's chain target, or null when none is available. */
async function readEcdsaLane(): Promise<unknown> {
  const lanes = await readAvailableLanes({ canonicalEcdsaLanes: [CANONICAL_LANE] });
  return lanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(ECDSA_TARGET)] ?? null;
}

test('an ECDSA lane stays available while NEAR provisioning is unresolved', async () => {
  resetNearProvisioningRegistryForTests();
  const baseline = await readEcdsaLane();
  expect(baseline).not.toBeNull();

  /* Every unresolved state a mixed-plan wallet passes through after activate. */
  for (const status of ['near_pending', 'near_provisioning'] as const) {
    publishNearProvisioningState(toWalletId(WALLET_ID), {
      status,
      updatedAtMs: 1_700_000_000_000,
    } as never);
    expect(await readEcdsaLane()).toEqual(baseline);
  }
  resetNearProvisioningRegistryForTests();
});

test('a retryable NEAR failure does not withdraw the ECDSA lane', async () => {
  /* The NEAR branch can fail and be retried without costing the user the
     ECDSA wallet they already registered. */
  resetNearProvisioningRegistryForTests();
  const baseline = await readEcdsaLane();
  expect(baseline).not.toBeNull();

  publishNearProvisioningState(toWalletId(WALLET_ID), {
    status: 'near_failed_retryable',
    updatedAtMs: 1_700_000_000_000,
    error: 'yao transport died',
    errorCode: 'near_provisioning_failed',
  } as never);

  expect(await readEcdsaLane()).toEqual(baseline);
  resetNearProvisioningRegistryForTests();
});
