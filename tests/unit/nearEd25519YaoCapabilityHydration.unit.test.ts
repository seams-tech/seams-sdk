import { expect, test } from '@playwright/test';
import {
  resolveNearEd25519YaoCapabilityHydrationV1,
  type NearEd25519YaoCapabilityHydrationInputV1,
} from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { requireNearOperationStepUpMaterialActivation } from '@/core/signingEngine/flows/signNear/shared/operationStepUpPreparation';
import { nearEd25519YaoCapabilityHydrationFixture } from './helpers/nearEd25519YaoCapabilityHydration.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildAuthorizationRequiredNearEd25519YaoSigningPreparation } from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import { resolveNearSigningSessionAuthContext } from '@/core/signingEngine/flows/signNear/shared/signingSessionAuthMode';
import { selectedEd25519Lane } from '@/core/signingEngine/session/identity/laneIdentity';
import { planSigningSession } from '@/core/signingEngine/session/planning/planner';
import { SigningSessionPlanKind } from '@/core/signingEngine/session/operationState/types';
import {
  nearAccountRefFromAccountId,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';

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

  const differentActivation = buildMpcMaterialActivationRefFixture(
    'different-near-hydration',
    'wallet-near-hydration',
  );
  expect(() =>
    requireNearOperationStepUpMaterialActivation({
      expected: fixture.materialActivation,
      actual: differentActivation,
    }),
  ).toThrow('operation assertion changed material activation');
});

test('Near hydration uses an exact live runtime when the local sealed locator is absent', () => {
  const fixture = nearEd25519YaoCapabilityHydrationFixture();
  const plan = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator: fixture.publicLocator,
    sealed: { kind: 'missing' },
    runtime: fixture.runtime,
    unlockSource: { kind: 'unavailable' },
  });

  expect(plan).toMatchObject({
    kind: 'use_live_runtime',
    materialActivation: fixture.materialActivation,
  });
});

test('Near material hydration remains independent from reusable authorization', () => {
  const fixture = nearEd25519YaoCapabilityHydrationFixture();
  const hydration = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator: fixture.publicLocator,
    sealed: fixture.sealed,
    runtime: { kind: 'absent' },
    unlockSource: { kind: 'available', authority: fixture.authority },
  });
  const preparation = buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
    hydration,
    requirement: {
      kind: 'email_otp',
      providerSubjectId: 'provider-subject-near-hydration',
    },
  });

  expect(preparation.hydration.kind).toBe('rehydrate_material_activation');
  expect(preparation.authorization).toEqual({
    kind: 'authorization_required',
    requirement: {
      kind: 'email_otp',
      providerSubjectId: 'provider-subject-near-hydration',
    },
  });
  expect('hydrate' in preparation).toBe(false);
  expect('prepareOperationStepUp' in preparation).toBe(false);
});

test('authorization-required Near material plans same-method step-up without a session record', () => {
  const fixture = nearEd25519YaoCapabilityHydrationFixture();
  const hydration = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator: fixture.publicLocator,
    sealed: fixture.sealed,
    runtime: { kind: 'absent' },
    unlockSource: { kind: 'available', authority: fixture.authority },
  });
  const requirement = {
    kind: 'email_otp' as const,
    providerSubjectId: 'provider-subject-near-hydration',
  };
  const preparation = buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
    hydration,
    requirement,
  });
  const walletId = toWalletId('wallet-near-hydration');
  const nearAccountId = toAccountId('wallet-near-hydration.testnet');
  const selectedLane = selectedEd25519Lane({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('near-key-hydration'),
    signerSlot: 1,
    auth: requirement,
    walletSessionId: 'wallet-session-near-hydration',
    quotaId: 'quota-near-hydration',
    thresholdSessionId: 'threshold-session-near-hydration',
  });
  const context = resolveNearSigningSessionAuthContext({
    commandSubject: {
      walletSession: {
        walletId,
        walletSessionUserId: 'wallet-near-hydration',
      },
      nearAccount: nearAccountRefFromAccountId(nearAccountId),
    },
    selectedLane,
    preparation,
    forceFreshAuth: false,
    requiredSignatureUses: 1,
  });

  expect(context.coordinatorInput.forceFreshAuth).toBe(true);
  expect(context.coordinatorInput.readiness.status).toBe('missing_session');
  expect(
    planSigningSession({
      lane: context.coordinatorInput.lane,
      readiness: context.coordinatorInput.readiness,
      forceFreshAuth: context.coordinatorInput.forceFreshAuth,
    }).kind,
  ).toBe(SigningSessionPlanKind.EmailOtpReauth);
});
