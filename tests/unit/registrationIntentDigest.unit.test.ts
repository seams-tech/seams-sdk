import { expect, test } from '@playwright/test';
import {
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  serializeAddSignerIntentV1,
  serializeRegistrationIntentV1,
  walletIdFromString,
  type AddSignerIntentV1,
  type RegistrationIntentV1,
  type RuntimePolicyScopeLike,
  type ThresholdEd25519RegistrationSpec,
} from '../../shared/src/utils/registrationIntent';
import {
  computeAddSignerIntentDigest,
  computeRegistrationIntentDigest,
} from '../../client/src/utils/intentDigest';

const runtimePolicyScope: RuntimePolicyScopeLike = {
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
  signingRootVersion: 'root_v1',
};

const ed25519Spec: ThresholdEd25519RegistrationSpec = {
  nearAccountId: 'alice.testnet',
  signerSlot: 1,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
  createNearAccount: true,
};

const baseIntent: RegistrationIntentV1 = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  runtimePolicyScope,
  authMethod: { kind: 'passkey' },
  signerSelection: {
    mode: 'ed25519_only',
    ed25519: ed25519Spec,
  },
  nonceB64u: 'nonce',
};

const baseAddSignerIntent: AddSignerIntentV1 = {
  version: 'add_signer_intent_v1',
  walletId: walletIdFromString('wallet_alice'),
  rpId: 'wallet.example.test',
  runtimePolicyScope,
  signerSelection: {
    mode: 'ed25519',
    ed25519: {
      mode: 'create_near_account',
      nearAccountId: 'alice.testnet',
      signerSlot: 2,
      participantIds: [1, 2],
      keyPurpose: 'near_tx',
      keyVersion: 'threshold-ed25519-hss-v1',
      derivationVersion: 1,
    },
  },
  nonceB64u: 'add-signer-nonce',
};

test.describe('registration intent digest canonicalization', () => {
  test('serializes object keys canonically and matches the client helper', async () => {
    const reordered = {
      nonceB64u: baseIntent.nonceB64u,
      signerSelection: {
        ed25519: {
          keyVersion: ed25519Spec.keyVersion,
          participantIds: ed25519Spec.participantIds,
          createNearAccount: ed25519Spec.createNearAccount,
          nearAccountId: ed25519Spec.nearAccountId,
          derivationVersion: ed25519Spec.derivationVersion,
          signerSlot: ed25519Spec.signerSlot,
          keyPurpose: ed25519Spec.keyPurpose,
        },
        mode: 'ed25519_only',
      },
      runtimePolicyScope: {
        signingRootVersion: runtimePolicyScope.signingRootVersion,
        envId: runtimePolicyScope.envId,
        projectId: runtimePolicyScope.projectId,
        orgId: runtimePolicyScope.orgId,
      },
      rpId: baseIntent.rpId,
      authMethod: baseIntent.authMethod,
      walletId: baseIntent.walletId,
      version: baseIntent.version,
    } satisfies RegistrationIntentV1;

    expect(serializeRegistrationIntentV1(reordered)).toBe(
      serializeRegistrationIntentV1(baseIntent),
    );
    await expect(computeRegistrationIntentDigestB64u(reordered)).resolves.toBe(
      await computeRegistrationIntentDigestB64u(baseIntent),
    );
    await expect(computeRegistrationIntentDigest(baseIntent)).resolves.toBe(
      await computeRegistrationIntentDigestB64u(baseIntent),
    );
  });

  test('binds participant order, signer mode, and runtime policy scope', async () => {
    const baseDigest = await computeRegistrationIntentDigestB64u(baseIntent);
    const reorderedParticipants: RegistrationIntentV1 = {
      ...baseIntent,
      signerSelection: {
        mode: 'ed25519_only',
        ed25519: {
          ...ed25519Spec,
          participantIds: [2, 1],
        },
      },
    };
    const differentRuntimeScope: RegistrationIntentV1 = {
      ...baseIntent,
      runtimePolicyScope: {
        ...baseIntent.runtimePolicyScope!,
        signingRootVersion: 'root_v2',
      },
    };
    const ecdsaOnly: RegistrationIntentV1 = {
      ...baseIntent,
      signerSelection: {
        mode: 'ecdsa_only',
        ecdsa: {
          chainTargets: [{ chain: 'tempo', chainId: 978 }],
          participantIds: [1, 2],
        },
      },
    };

    await expect(computeRegistrationIntentDigestB64u(reorderedParticipants)).resolves.not.toBe(
      baseDigest,
    );
    await expect(computeRegistrationIntentDigestB64u(differentRuntimeScope)).resolves.not.toBe(
      baseDigest,
    );
    await expect(computeRegistrationIntentDigestB64u(ecdsaOnly)).resolves.not.toBe(baseDigest);
  });
});

test.describe('add-signer intent digest canonicalization', () => {
  test('serializes object keys canonically and matches the client helper', async () => {
    const reordered = {
      nonceB64u: baseAddSignerIntent.nonceB64u,
      signerSelection: {
        ed25519: {
          participantIds: [1, 2],
          signerSlot: 2,
          nearAccountId: 'alice.testnet',
          keyPurpose: 'near_tx',
          keyVersion: 'threshold-ed25519-hss-v1',
          derivationVersion: 1,
          mode: 'create_near_account',
        },
        mode: 'ed25519',
      },
      runtimePolicyScope: {
        signingRootVersion: runtimePolicyScope.signingRootVersion,
        envId: runtimePolicyScope.envId,
        projectId: runtimePolicyScope.projectId,
        orgId: runtimePolicyScope.orgId,
      },
      rpId: baseAddSignerIntent.rpId,
      walletId: baseAddSignerIntent.walletId,
      version: baseAddSignerIntent.version,
    } satisfies AddSignerIntentV1;

    expect(serializeAddSignerIntentV1(reordered)).toBe(
      serializeAddSignerIntentV1(baseAddSignerIntent),
    );
    await expect(computeAddSignerIntentDigestB64u(reordered)).resolves.toBe(
      await computeAddSignerIntentDigestB64u(baseAddSignerIntent),
    );
    await expect(computeAddSignerIntentDigest(baseAddSignerIntent)).resolves.toBe(
      await computeAddSignerIntentDigestB64u(baseAddSignerIntent),
    );
  });

  test('binds signer family, participant order, target account, and runtime scope', async () => {
    const baseDigest = await computeAddSignerIntentDigestB64u(baseAddSignerIntent);
    const reorderedParticipants: AddSignerIntentV1 = {
      ...baseAddSignerIntent,
      signerSelection: {
        mode: 'ed25519',
        ed25519: {
          mode: 'create_near_account',
          nearAccountId: 'alice.testnet',
          signerSlot: 2,
          participantIds: [2, 1],
          keyPurpose: 'near_tx',
          keyVersion: 'threshold-ed25519-hss-v1',
          derivationVersion: 1,
        },
      },
    };
    const differentNearAccount: AddSignerIntentV1 = {
      ...baseAddSignerIntent,
      signerSelection: {
        mode: 'ed25519',
        ed25519: {
          mode: 'create_near_account',
          nearAccountId: 'bob.testnet',
          signerSlot: 2,
          participantIds: [1, 2],
          keyPurpose: 'near_tx',
          keyVersion: 'threshold-ed25519-hss-v1',
          derivationVersion: 1,
        },
      },
    };
    const differentRuntimeScope: AddSignerIntentV1 = {
      ...baseAddSignerIntent,
      runtimePolicyScope: {
        ...baseAddSignerIntent.runtimePolicyScope!,
        signingRootVersion: 'root_v2',
      },
    };
    const ecdsaSigner: AddSignerIntentV1 = {
      ...baseAddSignerIntent,
      signerSelection: {
        mode: 'ecdsa',
        ecdsa: {
          chainTargets: [{ chain: 'tempo', chainId: 978 }],
          participantIds: [1, 2],
        },
      },
    };

    await expect(computeAddSignerIntentDigestB64u(reorderedParticipants)).resolves.not.toBe(
      baseDigest,
    );
    await expect(computeAddSignerIntentDigestB64u(differentNearAccount)).resolves.not.toBe(
      baseDigest,
    );
    await expect(computeAddSignerIntentDigestB64u(differentRuntimeScope)).resolves.not.toBe(
      baseDigest,
    );
    await expect(computeAddSignerIntentDigestB64u(ecdsaSigner)).resolves.not.toBe(baseDigest);
  });
});
