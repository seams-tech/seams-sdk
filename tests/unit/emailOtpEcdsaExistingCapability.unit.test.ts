import { expect, test } from '@playwright/test';
import { resolveEmailOtpExistingEcdsaKey } from '@/core/signingEngine/session/emailOtp/ecdsaPublication';
import { bindEmailOtpEcdsaSessionPolicyToUnlockChallenge } from '@/core/signingEngine/session/emailOtp/ecdsaUnlockChallengeBinding';
import {
  ecdsaCapabilityActivationLookupFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { createEcdsaSessionActivationFixture } from './helpers/ecdsaBootstrap.fixtures';

const runtimePolicyScope = {
  orgId: 'fixture-org',
  projectId: 'fixture',
  envId: 'dev',
  signingRootVersion: 'v1',
};

test('binds a combined Email OTP unlock policy to its exact method challenge', () => {
  const activation = createEcdsaSessionActivationFixture({
    walletId: 'wallet:added-email-combined-unlock',
    chain: 'tempo',
  });
  const preparedPolicy = {
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1' as const,
    key_handle: 'ecdsa-key-handle:added-email-combined-unlock',
    session_policy: activation.request.session_policy,
  };
  const exactAddedMethod = {
    kind: 'wallet_auth_method' as const,
    walletAuthMethodId: 'wallet-auth-method:added-email',
  };

  const verifyCapability = {
    authoritySelector: exactAddedMethod,
    ecdsaSessionPolicy: bindEmailOtpEcdsaSessionPolicyToUnlockChallenge(
      {
        kind: 'wallet_unlock_capabilities',
        ecdsa: { sessionPolicy: preparedPolicy },
      },
      'challenge:added-email-combined-unlock',
    ),
  };

  expect(verifyCapability).toEqual({
    authoritySelector: exactAddedMethod,
    ecdsaSessionPolicy: {
      ...preparedPolicy,
      session_policy: {
        ...preparedPolicy.session_policy,
        wallet_session_mint_id: 'challenge:added-email-combined-unlock',
      },
    },
  });
});

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
