import { expect, test } from '@playwright/test';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { resolveEmailOtpEcdsaRoleLocalKeyIdentityForHandle } from '../../client/src/core/signingEngine/session/emailOtp/ecdsaRoleLocalIdentity';
import { deriveEvmFamilyEcdsaKeyHandle } from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const runtimePolicyScope = {
  orgId: 'org-1',
  projectId: 'project-1',
  envId: 'dev',
  signingRootVersion: 'default',
};

test.describe('Email OTP ECDSA role-local identity', () => {
  test('derives concrete role-local key identity and verifies the key handle', async () => {
    const walletSessionUserId = 'wallet-1';
    const rpId = 'wallet.example.test';
    const subjectId = 'wallet-1';
    const signingRoot = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
    const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
      walletSessionUserId,
      rpId,
      subjectId,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: signingRoot.signingRootVersion!,
    });
    const keyHandle = await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: signingRoot.signingRootVersion,
    });

    await expect(
      resolveEmailOtpEcdsaRoleLocalKeyIdentityForHandle({
        keyHandle,
        walletSessionUserId,
        rpId,
        subjectId,
        runtimePolicyScope,
      }),
    ).resolves.toEqual({
      ecdsaThresholdKeyId,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: signingRoot.signingRootVersion,
      relayerKeyId: await computeEcdsaHssRoleLocalRelayerKeyId({
        walletSessionUserId,
        rpId,
      }),
    });
  });

  test('rejects a handle that does not match the runtime policy identity', async () => {
    await expect(
      resolveEmailOtpEcdsaRoleLocalKeyIdentityForHandle({
        keyHandle: 'ehss-key-wrong',
        walletSessionUserId: 'wallet-1',
        rpId: 'wallet.example.test',
        subjectId: 'wallet-1',
        runtimePolicyScope,
      }),
    ).rejects.toThrow('keyHandle does not match runtime policy key identity');
  });
});
