import { expect, test } from '@playwright/test';
import {
  computeAddSignerIntentDigestB64u,
  computeRegistrationNearEd25519SigningKeyId,
  computeRegistrationIntentDigestB64u,
  implicitNearAccountProvisioning,
  parseGeneratedImplicitWalletId,
  requireGeneratedImplicitWalletId,
  serializeAddSignerIntentV1,
  serializeRegistrationIntentV1,
  sponsoredNamedNearAccountProvisioning,
  walletIdFromString,
  type AddSignerIntentV1,
  type RegistrationIntentV1,
  type RuntimePolicyScopeLike,
  type ThresholdEd25519RegistrationSpec,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseNamedNearAccountId } from '../../packages/shared-ts/src/utils/near';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  computeAddSignerIntentDigest,
  computeRegistrationIntentDigest,
} from '../../packages/sdk-web/src/utils/intentDigest';

const runtimePolicyScope: RuntimePolicyScopeLike = {
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
  signingRootVersion: 'root_v1',
};
const signingRootVersion = 'root_v1';

function namedProvisioning(accountId: string) {
  const parsed = parseNamedNearAccountId(accountId);
  if (!parsed.ok) throw new Error(parsed.message);
  return sponsoredNamedNearAccountProvisioning(parsed.value);
}

function webAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

const ed25519Spec: ThresholdEd25519RegistrationSpec = {
  accountProvisioning: namedProvisioning('alice.testnet'),
  signerSlot: 1,
  participantIds: [1, 2],
  keyPurpose: 'near_tx',
  keyVersion: 'threshold-ed25519-hss-v1',
  derivationVersion: 1,
};

const implicitEd25519Spec: ThresholdEd25519RegistrationSpec = {
  ...ed25519Spec,
  accountProvisioning: implicitNearAccountProvisioning(),
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
const baseWebAuthnRpId = webAuthnRpId(baseIntent.rpId);

const generatedImplicitWalletId = requireGeneratedImplicitWalletId('frost-vermillion-k7p9m2');

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
          accountProvisioning: ed25519Spec.accountProvisioning,
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
    const implicitProvisioning: RegistrationIntentV1 = {
      ...baseIntent,
      signerSelection: {
        mode: 'ed25519_only',
        ed25519: implicitEd25519Spec,
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
    await expect(computeRegistrationIntentDigestB64u(implicitProvisioning)).resolves.not.toBe(
      baseDigest,
    );
    await expect(computeRegistrationIntentDigestB64u(differentRuntimeScope)).resolves.not.toBe(
      baseDigest,
    );
    await expect(computeRegistrationIntentDigestB64u(ecdsaOnly)).resolves.not.toBe(baseDigest);
  });

  test('derives implicit NEAR Ed25519 signing key from pre-finalize registration scope', async () => {
    const keyScope = await computeRegistrationNearEd25519SigningKeyId({
      walletId: generatedImplicitWalletId,
      rpId: baseWebAuthnRpId,
      signingRootId: 'project_1:env_1',
      signingRootVersion,
      ed25519: implicitEd25519Spec,
    });
    const sameKeyScope = await computeRegistrationNearEd25519SigningKeyId({
      walletId: generatedImplicitWalletId,
      rpId: baseWebAuthnRpId,
      signingRootId: 'project_1:env_1',
      signingRootVersion,
      ed25519: implicitEd25519Spec,
    });
    const differentKeyScope = await computeRegistrationNearEd25519SigningKeyId({
      walletId: generatedImplicitWalletId,
      rpId: baseWebAuthnRpId,
      signingRootId: 'project_1:env_2',
      signingRootVersion,
      ed25519: implicitEd25519Spec,
    });

    expect(String(keyScope)).toMatch(/^ed25519ks_[A-Za-z0-9_-]+$/);
    expect(String(keyScope)).not.toBe(String(generatedImplicitWalletId));
    expect(sameKeyScope).toBe(keyScope);
    expect(differentKeyScope).not.toBe(keyScope);
  });

  test('accepts only generated implicit wallet-id shape for implicit key scope', () => {
    expect(parseGeneratedImplicitWalletId('frost-vermillion-k7p9m2')).toEqual({
      ok: true,
      value: generatedImplicitWalletId,
    });
    expect(parseGeneratedImplicitWalletId('alice.testnet')).toMatchObject({
      ok: false,
      error: { code: 'invalid' },
    });
    expect(parseGeneratedImplicitWalletId('wallet_alice')).toMatchObject({
      ok: false,
      error: { code: 'invalid' },
    });
    expect(parseGeneratedImplicitWalletId('a'.repeat(64))).toMatchObject({
      ok: false,
      error: { code: 'invalid' },
    });
  });

  test('keeps sponsored NEAR Ed25519 signing key on the durable wallet identity', async () => {
    await expect(
      computeRegistrationNearEd25519SigningKeyId({
        walletId: baseIntent.walletId,
        rpId: baseWebAuthnRpId,
        signingRootId: 'project_1:env_1',
        signingRootVersion,
        ed25519: ed25519Spec,
      }),
    ).resolves.toBe(baseIntent.walletId);
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
