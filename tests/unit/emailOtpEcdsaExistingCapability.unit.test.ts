import { expect, test } from '@playwright/test';
import { resolveEmailOtpExistingEcdsaKey } from '@/core/signingEngine/session/emailOtp/ecdsaPublication';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';

const runtimePolicyScope = {
  orgId: 'fixture-org',
  projectId: 'fixture',
  envId: 'dev',
  signingRootVersion: 'v1',
};

test('resolves Email OTP unlock material from the active capability manifest', async () => {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;

  const existing = await resolveEmailOtpExistingEcdsaKey({
    walletId: manifest.signer.walletId,
    chainTarget: publicFacts.chainTarget,
    runtimePolicyScope,
    keyHandle: String(publicFacts.keyHandle),
    listActiveEcdsaCapabilityManifestsForWallet: async () => [manifest],
  });

  expect(existing).not.toBeNull();
  expect(existing?.keyHandle).toBe(String(publicFacts.keyHandle));
  expect(existing?.publicCapability).toEqual(publicFacts.publicCapability);
  expect(existing?.persistedRoleLocalMaterial.materialActivation).toEqual(
    manifest.activation.materialActivation,
  );
});

test('does not synthesize Email OTP unlock material without an active manifest', async () => {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;

  const existing = await resolveEmailOtpExistingEcdsaKey({
    walletId: manifest.signer.walletId,
    chainTarget: publicFacts.chainTarget,
    runtimePolicyScope,
    keyHandle: String(publicFacts.keyHandle),
    listActiveEcdsaCapabilityManifestsForWallet: async () => [],
  });

  expect(existing).toBeNull();
});
