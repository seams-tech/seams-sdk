import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildEcdsaOperationStepUpPreparation } from '@/core/signingEngine/threshold/ecdsa/operationStepUp';
import { buildPersistedEcdsaRoleLocalMaterial } from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import { exportEcdsaKeyWithDurableAuthorization } from '@/core/signingEngine/session/emailOtp/exportRecovery';
import { WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';
import {
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaWalletSessionRefFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';

function digest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}

test('ECDSA Email OTP export verifies its challenge with the originating app session lane', async () => {
  const { authority, manifest } =
    await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp');
  const chainTarget = manifest.signer.scope.targetMemberships[0];
  if (!chainTarget) throw new Error('ECDSA fixture is missing a target membership');
  const publicFacts = manifest.signer.registeredPublicFacts;
  const roleLocalBinding = manifest.durableMaterial.roleLocalBinding;
  const participantIds = roleLocalBinding.participantIds;
  if (participantIds.length !== 2) throw new Error('ECDSA fixture requires two participants');
  const prepared = buildEcdsaOperationStepUpPreparation({
    walletId: String(manifest.signer.walletId),
    operationKind: 'evm.export_key',
    operationId: 'ecdsa-email-otp-export-operation',
    operationDigests: {
      laneDigest: digest(1),
      intentDigest: digest(2),
      displayDigest: digest(3),
    },
    materialActivation: manifest.durableMaterial.materialActivation,
    normalSigningScope: manifest.durableMaterial.routerAbEcdsaDerivationNormalSigning.scope,
    keyHandle: String(roleLocalBinding.keyHandle),
    relayerKeyId: String(roleLocalBinding.relayerKeyId),
    participantIds: [Number(participantIds[0]), Number(participantIds[1])],
    expiresAtMs: Date.now() + 60_000,
  });
  const appSessionJwt = 'originating-app-session-jwt';
  const persistedMaterial = buildPersistedEcdsaRoleLocalMaterial({
    authority: manifest.signer.authority,
    materialActivation: manifest.durableMaterial.materialActivation,
    publicFacts: manifest.durableMaterial.roleLocalPublicFacts,
  });
  const explicitExportAuthorization = {
    kind: 'verified_step_up' as const,
    evidenceSetDigest: digest(4),
    operation: prepared,
    sessionAuth: { kind: 'app_session' as const, jwt: appSessionJwt },
    expiresAtMs: Date.now() + 60_000,
    quotaUse: 'none' as const,
    unseal: {
      kind: 'email_otp_grant' as const,
      grant: 'grant-1',
      challenge_id: 'challenge-1',
    },
  };
  let capturedRoutePlan: unknown;
  await expect(
    exportEcdsaKeyWithDurableAuthorization(
      {
        getSignerWorkerContext: () => {
          throw new Error('worker context should not be reached');
        },
        requireRelayUrl: () => 'https://relay.example',
      },
      {
        walletSession: ecdsaWalletSessionRefFixture(manifest),
        chainTarget,
        challengeId: 'email-otp-export-challenge',
        otpCode: '123456',
        publicFacts,
        runtimePolicyScope: {
          orgId: 'fixture-org',
          projectId: 'fixture-project',
          envId: 'fixture-env',
          signingRootVersion: String(manifest.signer.signingRootVersion),
        },
        authority,
        persistedMaterial,
        explicitExportAuthorization,
        prepareEcdsaExportCapability: async (input) => {
          capturedRoutePlan = input.routePlan;
          throw new Error('captured before worker execution');
        },
      },
    ),
  ).rejects.toThrow('captured before worker execution');
  expect(capturedRoutePlan).toEqual({
    routeFamily: 'login',
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
});
