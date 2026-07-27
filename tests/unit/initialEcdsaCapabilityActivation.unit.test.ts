import { expect, test } from '@playwright/test';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  buildInitialEcdsaCapabilityActivationPlan,
  type InitialEcdsaCapabilityActivationPlan,
} from '@/core/signingEngine/session/material/initialEcdsaCapabilityActivation';
import { initialEcdsaCapabilityActivationFixture } from './helpers/initialEcdsaCapabilityActivation.fixtures';

function plannedIdentityValues(plan: InitialEcdsaCapabilityActivationPlan): string[] {
  const binding = plan.activationBinding;
  return [
    binding.signer.capability,
    binding.signer.signerId,
    binding.signer.materialOwner,
    binding.targetManifest.manifestId,
    binding.activationId,
    binding.durableMaterialRef,
  ];
}

test('initial ECDSA activation planner owns fresh independent identities', async () => {
  const fixture = await initialEcdsaCapabilityActivationFixture();
  const first = await buildInitialEcdsaCapabilityActivationPlan(fixture.input);
  const second = await buildInitialEcdsaCapabilityActivationPlan(fixture.input);
  const plannedIdentities = [...plannedIdentityValues(first), ...plannedIdentityValues(second)];

  expect(new Set(plannedIdentities).size).toBe(plannedIdentities.length);
  for (const forbiddenAlias of fixture.forbiddenAliases) {
    expect(plannedIdentities).not.toContain(forbiddenAlias);
  }
  expect(plannedIdentities).not.toContain(first.activationBinding.roleLocalBinding.keyHandle);
  expect(first.activationBinding.targetManifest.manifestRevision).toBe(1);
  expect(first.expectedManifest.kind).toBe('no_current_manifest');
  expect(first.expectedGeneration.kind).toBe('no_current_generation');
  expect(first.activationBinding.signer.authority).toEqual(fixture.input.authority);
  expect('pendingPayloadB64u' in first).toBe(false);
  expect('pendingStateBlobB64u' in first).toBe(false);
});

test('initial ECDSA activation planner derives the canonical key handle', async () => {
  const fixture = await initialEcdsaCapabilityActivationFixture();
  const plan = await buildInitialEcdsaCapabilityActivationPlan(fixture.input);
  const expectedKeyHandle = await deriveThresholdEcdsaKeyHandle({
    ecdsaThresholdKeyId: fixture.input.ecdsaThresholdKeyId,
    signingRootId: fixture.input.signingRootId,
    signingRootVersion: fixture.input.signingRootVersion,
  });

  expect(plan.activationBinding.roleLocalBinding.keyHandle).toBe(expectedKeyHandle);
  expect(plan.activationBinding.bindingDigest).toBe(fixture.input.bindingDigest);
});
