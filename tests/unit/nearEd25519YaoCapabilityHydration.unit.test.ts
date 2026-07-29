import { expect, test } from '@playwright/test';
import {
  nearEd25519YaoMaterialActivationFromPublicFacts,
  resolveNearEd25519YaoCapabilityHydrationV1,
  type NearEd25519YaoCapabilityHydrationInputV1,
} from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { requireNearOperationStepUpMaterialActivation } from '@/core/signingEngine/flows/signNear/shared/operationStepUpPreparation';
import { nearEd25519YaoCapabilityHydrationFixture } from './helpers/nearEd25519YaoCapabilityHydration.fixtures';

test('maps the seven canonical Near hydration states to shared outcomes', () => {
  const fixture = nearEd25519YaoCapabilityHydrationFixture();
  const cases = [
    {
      state: 'live',
      input: {
        publicLocator: fixture.publicLocator,
        sealed: fixture.sealed,
        runtime: fixture.runtime,
        unlockSource: { kind: 'unavailable' },
      },
      expected: { kind: 'use_live_runtime' },
    },
    {
      state: 'sealed-active',
      input: {
        publicLocator: fixture.publicLocator,
        sealed: fixture.sealed,
        runtime: { kind: 'absent' },
        unlockSource: { kind: 'available', authority: fixture.authority },
      },
      expected: { kind: 'rehydrate_material_activation' },
    },
    {
      state: 'retired',
      input: {
        publicLocator: {
          kind: 'retired',
          retirement: 'expired',
          publicReauthAnchor: fixture.publicReauthAnchor,
        },
        sealed: { kind: 'missing' },
        runtime: { kind: 'absent' },
        unlockSource: { kind: 'unavailable' },
      },
      expected: { kind: 'reauthorize_public_anchor', retirement: 'expired' },
    },
    {
      state: 'missing',
      input: {
        publicLocator: { kind: 'missing' },
        sealed: { kind: 'missing' },
        runtime: { kind: 'absent' },
        unlockSource: { kind: 'unavailable' },
      },
      expected: { kind: 'blocked', reason: 'missing_capability' },
    },
    {
      state: 'corrupt',
      input: {
        publicLocator: { kind: 'corrupt' },
        sealed: fixture.sealed,
        runtime: { kind: 'absent' },
        unlockSource: { kind: 'unavailable' },
      },
      expected: { kind: 'blocked', reason: 'corrupt' },
    },
    {
      state: 'conflicting',
      input: {
        publicLocator: { kind: 'conflict' },
        sealed: fixture.sealed,
        runtime: { kind: 'absent' },
        unlockSource: { kind: 'unavailable' },
      },
      expected: { kind: 'blocked', reason: 'exact_record_conflict' },
    },
    {
      state: 'unavailable',
      input: {
        publicLocator: {
          kind: 'unavailable',
          capability: fixture.materialActivation.capability,
        },
        sealed: { kind: 'missing' },
        runtime: { kind: 'absent' },
        unlockSource: { kind: 'unavailable' },
      },
      expected: { kind: 'blocked', reason: 'persistence_unavailable' },
    },
  ] as const satisfies readonly {
    state: string;
    input: NearEd25519YaoCapabilityHydrationInputV1;
    expected: Readonly<Record<string, unknown>>;
  }[];

  for (const matrixCase of cases) {
    expect(
      resolveNearEd25519YaoCapabilityHydrationV1(matrixCase.input),
      matrixCase.state,
    ).toMatchObject(matrixCase.expected);
  }
});

test('Near operation step-up preserves the exact sealed material activation', () => {
  const fixture = nearEd25519YaoCapabilityHydrationFixture();
  const plan = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator: fixture.publicLocator,
    sealed: fixture.sealed,
    runtime: { kind: 'absent' },
    unlockSource: { kind: 'available', authority: fixture.authority },
  });
  if (plan.kind !== 'rehydrate_material_activation') {
    throw new Error('sealed active Near material must be rehydratable');
  }
  requireNearOperationStepUpMaterialActivation({
    expected: fixture.materialActivation,
    actual: plan.materialActivation,
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
      expected: fixture.materialActivation,
      actual: differentActivation,
    }),
  ).toThrow('operation assertion changed material activation');
});
