import { expect, test } from '@playwright/test';
import { resolveEmailOtpExistingEcdsaKey } from '@/core/signingEngine/session/emailOtp/ecdsaPublication';
import {
  ecdsaCapabilityActivationLookupFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';

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
    scope: {
      kind: 'exact',
      runtimePolicyScope,
      authorityRef: manifest.signer.authority,
    },
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

test('resolves shared Email OTP unlock material for a sibling target membership', async () => {
  const primaryTarget = {
    kind: 'evm' as const,
    namespace: 'eip155',
    chainId: 1,
    networkSlug: 'ethereum',
  };
  const siblingTarget = {
    kind: 'tempo' as const,
    chainId: 42431,
    networkSlug: 'tempo-testnet',
  };
  const manifest = ecdsaCapabilityActivationLookupFixture({
    targetMemberships: [primaryTarget, siblingTarget],
  }).manifest;
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;

  const existing = await resolveEmailOtpExistingEcdsaKey({
    walletId: manifest.signer.walletId,
    chainTarget: siblingTarget,
    scope: {
      kind: 'exact',
      runtimePolicyScope,
      authorityRef: manifest.signer.authority,
    },
    keyHandle: String(publicFacts.keyHandle),
    listActiveEcdsaCapabilityManifestsForWallet: async () => [manifest],
  });

  expect(existing).not.toBeNull();
  expect(existing?.persistedRoleLocalMaterial.materialActivation).toEqual(
    manifest.activation.materialActivation,
  );
  expect(existing?.persistedRoleLocalMaterial.publicFacts.chainTarget).toEqual(siblingTarget);
  expect(existing?.publicCapability).toEqual(publicFacts.publicCapability);
});

test('does not synthesize Email OTP unlock material without an active manifest', async () => {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;

  const existing = await resolveEmailOtpExistingEcdsaKey({
    walletId: manifest.signer.walletId,
    chainTarget: publicFacts.chainTarget,
    scope: {
      kind: 'exact',
      runtimePolicyScope,
      authorityRef: manifest.signer.authority,
    },
    keyHandle: String(publicFacts.keyHandle),
    listActiveEcdsaCapabilityManifestsForWallet: async () => [],
  });

  expect(existing).toBeNull();
});
