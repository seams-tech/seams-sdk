import { expect, test } from '@playwright/test';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { LocalRouterAbEcdsaHssNormalSigningSeedResult } from '../../packages/sdk-server-ts/src/core/routerAbSigning/RouterAbLocalSigningSeedRuntime';
import { walletSigningBudgetSessionId } from '../../packages/sdk-server-ts/src/core/ThresholdService/walletSigningBudget';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdServiceTestUtils';

const walletId = 'cedar-zenith-pghgtw';
const signingRootId = 'proj_mqykdxtp_o2hgej:dev';
const signingRootVersion = 'default';
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId,
  signingRootId,
  signingRootVersion,
});

function assertSeedOk(
  result: LocalRouterAbEcdsaHssNormalSigningSeedResult,
): asserts result is Extract<LocalRouterAbEcdsaHssNormalSigningSeedResult, { ok: true }> {
  expect(result, JSON.stringify(result)).toMatchObject({ ok: true });
}

async function ecdsaSeedBase(): Promise<{
  walletId: string;
  evmFamilySigningKeySlotId: typeof evmFamilySigningKeySlotId;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  walletKeyVersion: string;
  derivationVersion: 1;
  relayerKeyId: string;
  participantIds: readonly [1, 2];
  remainingUses: 3;
}> {
  return {
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: await computeEcdsaHssRoleLocalThresholdKeyId({
      walletId,
      evmFamilySigningKeySlotId,
      signingRootId,
      signingRootVersion,
    }),
    signingRootId,
    signingRootVersion,
    walletKeyVersion: 'threshold-ecdsa-hss-v1',
    derivationVersion: 1,
    relayerKeyId: await computeEcdsaHssRoleLocalRelayerKeyId({
      walletId,
      evmFamilySigningKeySlotId,
    }),
    participantIds: [1, 2],
    remainingUses: 3,
  };
}

async function allowsMultipleExactEcdsaSessionsForOneWalletKeySlot(): Promise<void> {
  const { routerAbLocalSigningSeedRuntime, walletBudgetSessionStore } =
    createThresholdSigningServiceForUnitTests({});
  const base = await ecdsaSeedBase();
  const signingGrantId = 'wss_exact_ecdsa_wallet_budget';
  const first = await routerAbLocalSigningSeedRuntime.seedLocalRouterAbEcdsaHssNormalSigningSession(
    {
      ...base,
      signingGrantId,
      thresholdSessionId: 'tehss_exact_budget_first',
      thresholdExpiresAtMs: Date.now() + 60_000,
    },
  );
  assertSeedOk(first);

  const second =
    await routerAbLocalSigningSeedRuntime.seedLocalRouterAbEcdsaHssNormalSigningSession({
      ...base,
      signingGrantId,
      thresholdSessionId: 'tehss_exact_budget_second',
      thresholdExpiresAtMs: Date.now() + 60_000,
    });
  assertSeedOk(second);

  await expect(
    walletBudgetSessionStore.getSession(walletSigningBudgetSessionId({ signingGrantId })),
  ).resolves.toMatchObject({
    bindings: {
      kind: 'ecdsa_only',
      ecdsa: [
        {
          thresholdSessionId: 'tehss_exact_budget_first',
          evmFamilySigningKeySlotId,
        },
        {
          thresholdSessionId: 'tehss_exact_budget_second',
          evmFamilySigningKeySlotId,
        },
      ],
    },
  });
}

async function rejectsDifferentEcdsaKeySlotWithoutOrphaningState(): Promise<void> {
  const { routerAbLocalSigningSeedRuntime, ecdsaWalletSessionStore } =
    createThresholdSigningServiceForUnitTests({});
  const base = await ecdsaSeedBase();
  const signingGrantId = 'wss_rejects_different_ecdsa_key_slot';
  const first = await routerAbLocalSigningSeedRuntime.seedLocalRouterAbEcdsaHssNormalSigningSession(
    {
      ...base,
      signingGrantId,
      thresholdSessionId: 'tehss_key_slot_first',
      thresholdExpiresAtMs: Date.now() + 60_000,
    },
  );
  assertSeedOk(first);

  const substitutedSlotId = deriveEvmFamilySigningKeySlotId({
    walletId,
    signingRootId: 'proj_different_signing_root:dev',
    signingRootVersion,
  });
  const rejected =
    await routerAbLocalSigningSeedRuntime.seedLocalRouterAbEcdsaHssNormalSigningSession({
      ...base,
      evmFamilySigningKeySlotId: substitutedSlotId,
      ecdsaThresholdKeyId: await computeEcdsaHssRoleLocalThresholdKeyId({
        walletId,
        evmFamilySigningKeySlotId: substitutedSlotId,
        signingRootId,
        signingRootVersion,
      }),
      relayerKeyId: await computeEcdsaHssRoleLocalRelayerKeyId({
        walletId,
        evmFamilySigningKeySlotId: substitutedSlotId,
      }),
      signingGrantId,
      thresholdSessionId: 'tehss_key_slot_substituted',
      thresholdExpiresAtMs: Date.now() + 60_000,
    });
  expect(rejected).toMatchObject({ ok: false, code: 'unauthorized' });
  await expect(
    ecdsaWalletSessionStore.getSession('tehss_key_slot_substituted'),
  ).resolves.toBeNull();
}

test(
  'ECDSA signing grants bind multiple exact sessions for one wallet key slot',
  allowsMultipleExactEcdsaSessionsForOneWalletKeySlot,
);
test(
  'ECDSA signing grants reject a different key slot without orphaning session state',
  rejectsDifferentEcdsaKeySlotWithoutOrphaningState,
);
