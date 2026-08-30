import { expect, test } from '@playwright/test';
import type { WebAuthnAuthenticationCredential } from '../../packages/wallet/src/core/types/webauthn';
import {
  buildEcdsaSessionIdentity,
  buildEcdsaSessionProvisionPlan,
  buildPasskeyEcdsaProvisionSecretSource,
} from '../../packages/wallet/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import { buildBaseEvmFamilyEcdsaKeyIdentity } from '../../packages/wallet/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  createThresholdEcdsaBootstrapFixture,
  thresholdEcdsaBootstrapPublicFactsFixture,
} from './helpers/ecdsaBootstrap.fixtures';

const TEST_WEBAUTHN_CREDENTIAL = {
  id: 'credential-id',
  rawId: 'credential-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: 'first-prf',
        second: undefined,
      },
    },
  },
} satisfies WebAuthnAuthenticationCredential;

test('passkey ECDSA provision plans carry the exact operation credential', () => {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'plan-passkey',
    chain: 'evm',
  });
  const publicFacts = thresholdEcdsaBootstrapPublicFactsFixture(bootstrap);
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: publicFacts.walletId,
    ecdsaThresholdKeyId: publicFacts.ecdsaThresholdKeyId,
    signingRootId: publicFacts.signingRootId,
    signingRootVersion: publicFacts.signingRootVersion,
    participantIds: publicFacts.participantIds,
    thresholdOwnerAddress: publicFacts.ethereumAddress,
  });
  const plan = buildEcdsaSessionProvisionPlan({
    kind: 'passkey_ecdsa_session_provision',
    key,
    chainTarget: bootstrap.thresholdEcdsaKeyRef.chainTarget,
    sessionIdentity: buildEcdsaSessionIdentity({
      thresholdSessionId: bootstrap.session.thresholdSessionId,
    }),
    signingKeyContext: {
      ecdsaThresholdKeyId: String(publicFacts.ecdsaThresholdKeyId),
      participantIds: publicFacts.participantIds,
    },
    sessionKind: 'opaque',
    sessionBudgetUses: bootstrap.session.remainingUses,
    requestId: 'passkey-provision-plan',
    provisionSecretSource: buildPasskeyEcdsaProvisionSecretSource({
      passkeyPrfFirstB64u: 'first-prf',
      webauthnAuthentication: TEST_WEBAUTHN_CREDENTIAL,
    }),
    activationMaterial: { kind: 'session_record' },
    operationCredential: bootstrap.session.operationCredential,
    runtimePolicyScope: bootstrap.session.runtimePolicyScope,
  });

  expect(plan.kind).toBe('passkey_ecdsa_session_provision');
  expect(plan.operationCredential).toBe(bootstrap.session.operationCredential);
  expect(plan).not.toHaveProperty('walletSessionRouteAuth');
});
