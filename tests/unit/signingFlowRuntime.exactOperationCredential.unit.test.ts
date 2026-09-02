import { expect, test } from '@playwright/test';
import { resolveExactEcdsaOperationStepUpCredential } from '@/core/signingEngine/flows/signEvmFamily/signingFlowRuntime';
import { canonicalEcdsaSealedRuntimeFixture } from './helpers/ecdsaOperationStepUp.fixtures';
import { buildExactPasskeyEvmFamilyWalletSessionAuthorizationFromRuntimeFixture } from './helpers/exactEvmFamilyWalletSessionAuthorization.fixtures';

test('ECDSA operation step-up reads the selected canonical exact-session credential', async () => {
  const canonicalRuntime = await canonicalEcdsaSealedRuntimeFixture('passkey');
  const authorization =
    await buildExactPasskeyEvmFamilyWalletSessionAuthorizationFromRuntimeFixture({
      label: 'operation-step-up',
      walletSessionLabel: 'operation-step-up',
      authorizationLabel: 'operation-step-up',
      quotaLabel: 'operation-step-up',
      canonicalRuntime,
    });
  const capability = canonicalRuntime.fixture.capability;
  const chainTarget = capability.manifest.signer.scope.targetMemberships[0];
  if (!chainTarget) throw new Error('canonical ECDSA fixture has no chain target');
  let exactReadCount = 0;

  const credential = await resolveExactEcdsaOperationStepUpCredential({
    ports: {
      resolveSelectedWalletAuthority: async (walletId) => {
        expect(walletId).toBe(String(authorization.session.walletId));
        return {
          kind: 'resolved',
          selection: {
            kind: 'wallet_selection_v1',
            walletId: authorization.session.walletId,
            walletAuthMethodId: authorization.selectedAuthMethod.walletAuthMethodId,
            lockGeneration: 1,
            lockState: 'unlocked',
            updatedAtMs: Date.now(),
          },
          authMethod: authorization.selectedAuthMethod,
          authority: authorization.selectedAuthority,
          signerMaterials: [],
          exportRoot: null,
        };
      },
      readExactWithOperationCredential: async (input) => {
        exactReadCount += 1;
        expect(input).toEqual({
          walletId: authorization.session.walletId,
          authorityId: authorization.selectedAuthority.authorityId,
          authMethodId: authorization.selectedAuthMethod.walletAuthMethodId,
        });
        return {
          kind: 'found',
          record: authorization.session,
          operationCredential: authorization.operationCredential,
        };
      },
    },
    scope: {
      walletId: authorization.session.walletId,
      chainTarget,
      materialActivation: capability.manifest.activation.materialActivation,
    },
    capability,
  });

  expect(exactReadCount).toBe(1);
  expect(credential).toEqual(authorization.operationCredential);
});
