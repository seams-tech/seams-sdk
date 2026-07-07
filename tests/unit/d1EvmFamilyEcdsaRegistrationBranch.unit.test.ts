import { expect, test } from '@playwright/test';

import { buildD1EvmFamilyEcdsaRegistrationPrepare } from '../../packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch';
import type { ThresholdEcdsaChainTarget } from '../../packages/sdk-server-ts/src/core/types';

const tempoTarget: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

const arcTarget: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

test.describe('D1 EVM-family ECDSA registration prepare', () => {
  test('uses one signing grant for all chain targets in one registration', async () => {
    const prepared = await buildD1EvmFamilyEcdsaRegistrationPrepare({
      registrationCeremonyId: 'wrc_shared_budget',
      walletId: 'test-wallet',
      signingRootId: 'signing-root:dev',
      signingRootVersion: 'default',
      chainTargets: [tempoTarget, arcTarget],
      participantIds: [1, 2],
    });

    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;

    const targets = prepared.ecdsa.targets;
    expect(targets).toHaveLength(2);
    expect(new Set(targets.map((target) => target.prepare.signingGrantId)).size).toBe(1);
    expect(new Set(targets.map((target) => target.prepare.thresholdSessionId)).size).toBe(2);
    expect(targets.map((target) => target.prepare.remainingUses)).toEqual([3, 3]);
  });
});
