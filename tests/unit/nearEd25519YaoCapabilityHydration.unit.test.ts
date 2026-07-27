import { expect, test } from '@playwright/test';
import {
  nearEd25519YaoMaterialActivationFromPublicFacts,
  nearEd25519YaoRuntimeRef,
  resolveNearEd25519YaoCapabilityHydrationV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { buildRestorableMpcMaterialRefInternal } from '../../packages/sdk-web/src/core/signingEngine/session/material/restorableMpcMaterialRef.internal';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { requireNearOperationStepUpMaterialActivation } from '../../packages/sdk-web/src/core/signingEngine/flows/signNear/shared/operationStepUpPreparation';

function authorityFixture(digest: string): WalletAuthAuthorityRef {
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: 'wallet-near-hydration',
    authorityDigest: digest,
  });
  if (!authority) throw new Error('Near hydration authority fixture is invalid');
  return authority;
}

test('prepares an expired sealed Near operation for the same activation', () => {
  const authority = authorityFixture('authority-near-hydration');
  const materialActivation = nearEd25519YaoMaterialActivationFromPublicFacts({
    activationId: 'material-activation-before-refresh',
    activeCapabilityBinding: new Uint8Array(32).fill(3),
    walletId: 'wallet-near-hydration',
    registeredPublicKey: new Uint8Array(32).fill(7),
    lifecycleId: 'material-lifecycle-before-refresh',
    signingWorkerId: 'signing-worker-near-hydration',
  });
  const publicLocator = {
    kind: 'available' as const,
    walletId: 'wallet-near-hydration',
    nearAccountId: 'wallet-near-hydration.testnet',
    signerSlot: 1,
    materialActivation,
    authority,
  };
  const sealed = {
    kind: 'available' as const,
    authority,
    materialActivation,
    sealedMaterial: buildRestorableMpcMaterialRefInternal('sealed-near-active-client'),
  };

  const refreshPlan = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator,
    sealed,
    runtime: { kind: 'absent' },
    unlockSource: { kind: 'available', authority },
  });
  expect(refreshPlan).toMatchObject({
    kind: 'rehydrate_material_activation',
    authority,
    materialActivation,
  });
  expect(
    refreshPlan.kind === 'rehydrate_material_activation' && refreshPlan.materialActivation,
  ).toBe(materialActivation);
  if (refreshPlan.kind !== 'rehydrate_material_activation') {
    throw new Error('expired sealed activation must be rehydratable');
  }
  requireNearOperationStepUpMaterialActivation({
    expected: materialActivation,
    actual: refreshPlan.materialActivation,
  });

  const differentActivation = nearEd25519YaoMaterialActivationFromPublicFacts({
    activationId: 'different-material-activation',
    activeCapabilityBinding: new Uint8Array(32).fill(4),
    walletId: 'wallet-near-hydration',
    registeredPublicKey: new Uint8Array(32).fill(7),
    lifecycleId: 'different-material-lifecycle',
    signingWorkerId: 'signing-worker-near-hydration',
  });
  expect(() =>
    requireNearOperationStepUpMaterialActivation({
      expected: materialActivation,
      actual: differentActivation,
    }),
  ).toThrow('operation assertion changed material activation');

  const livePlan = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator,
    sealed,
    runtime: {
      kind: 'live',
      runtime: nearEd25519YaoRuntimeRef(materialActivation),
      materialActivation,
    },
    unlockSource: { kind: 'unavailable' },
  });
  expect(livePlan).toMatchObject({
    kind: 'use_live_runtime',
    materialActivation,
  });

  const mismatched = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator,
    sealed,
    runtime: { kind: 'absent' },
    unlockSource: {
      kind: 'available',
      authority: authorityFixture('different-authority'),
    },
  });
  expect(mismatched).toEqual({
    kind: 'blocked',
    capability: materialActivation.capability,
    reason: 'binding_mismatch',
  });

  const mismatchedPublicActivation = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator: {
      ...publicLocator,
      materialActivation: differentActivation,
    },
    sealed,
    runtime: { kind: 'absent' },
    unlockSource: { kind: 'available', authority },
  });
  expect(mismatchedPublicActivation).toEqual({
    kind: 'blocked',
    capability: materialActivation.capability,
    reason: 'binding_mismatch',
  });
});
