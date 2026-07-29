import { expect, test } from '@playwright/test';
import { parseCapabilityGrantId } from '@shared/authorization/capabilityKinds';
import {
  buildEcdsaExportActivation,
  provisionPasskeyEcdsaExplicitExportSession,
  type ProvisionThresholdEcdsaSessionDeps,
} from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { buildEcdsaOperationStepUpPreparation } from '@/core/signingEngine/threshold/ecdsa/operationStepUp';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  buildMpcMaterialActivationRef,
  parseMpcSigningWorkerRef,
} from '@shared/utils/domainIds';

function exportGrantId() {
  const parsed = parseCapabilityGrantId('ecdsa-export-operation-grant');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function unexpectedDependencyUse(): never {
  throw new Error('auth-neutral export provision used a session dependency');
}

function fixtureDigest(byte: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(byte)));
}

function exportProvisionDeps(): ProvisionThresholdEcdsaSessionDeps {
  return {
    queueByWallet: new Map(),
    activationDeps: {
      credentialStore: {
        resolveProfileAccountContext: async () => unexpectedDependencyUse(),
        listProfileAuthenticators: async () => unexpectedDependencyUse(),
        listAccountSigners: async () => unexpectedDependencyUse(),
        selectProfileAuthenticatorsForPrompt: async () => unexpectedDependencyUse(),
      },
      touchIdPrompt: {
        getRpId: () => unexpectedDependencyUse(),
        getAuthenticationCredentialsSerializedForChallengeB64u: async () =>
          unexpectedDependencyUse(),
      },
      touchConfirm: { putWarmSessionMaterial: async () => unexpectedDependencyUse() },
      getSignerWorkerContext: () => unexpectedDependencyUse(),
      routerAbNormalSigning: { mode: 'enabled', signingWorkerId: 'unused-signing-worker' },
      getOrCreateActiveThresholdEcdsaSessionId: () => unexpectedDependencyUse(),
      defaultRelayerUrl: 'https://relay.example',
      persistThresholdEcdsaBootstrapForWalletTarget: async () => unexpectedDependencyUse(),
    },
    touchConfirm: undefined,
    persistEcdsaRoleLocalReadyRecord: async () => unexpectedDependencyUse(),
    resolveSealTransport: async () => unexpectedDependencyUse(),
  };
}

test('dedicated ECDSA export provision keeps material auth-neutral and quota-neutral', async () => {
  const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: String(fixture.capability.material.publicFacts.walletId),
    chain: 'evm',
  });
  const publicFacts = fixture.capability.material.publicFacts;
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!backendBinding || backendBinding.materialKind !== 'role_local_worker_handle') {
    throw new Error('ECDSA bootstrap fixture requires role-local material');
  }
  const signingWorker = parseMpcSigningWorkerRef(
    bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning.scope.signing_worker
      .server_id,
  );
  if (!signingWorker.ok) throw new Error(signingWorker.error.message);
  const fixtureActivation = backendBinding.roleLocalMaterialRef.materialActivation;
  const materialActivation = buildMpcMaterialActivationRef({
    activationId: fixtureActivation.activationId,
    capability: fixtureActivation.capability,
    materialOwner: fixtureActivation.materialOwner,
    keyBinding: fixtureActivation.keyBinding,
    lifecycleBinding: fixtureActivation.lifecycleBinding,
    signingWorker: signingWorker.value,
  });
  const operation = buildEcdsaOperationStepUpPreparation({
    walletId: String(publicFacts.walletId),
    operationKind: 'evm.export_key',
    operationId: 'explicit-export-operation',
    operationDigests: {
      laneDigest: fixtureDigest(1),
      intentDigest: fixtureDigest(2),
      displayDigest: fixtureDigest(3),
    },
    materialActivation,
    normalSigningScope:
      bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning.scope,
    keyHandle: backendBinding.publicFacts.keyHandle,
    relayerKeyId: backendBinding.relayerKeyId,
    participantIds: backendBinding.publicFacts.participantIds,
    expiresAtMs: Date.now() + 60_000,
  });
  const expiresAtMs = Date.now() + 60_000;
  const result = await provisionPasskeyEcdsaExplicitExportSession(
    exportProvisionDeps(),
    buildEcdsaExportActivation({
      relayerUrl: 'https://relay.example',
      existingRoleLocalMaterial: fixture.capability.material,
      authorization: {
        kind: 'operation_step_up',
        grantId: exportGrantId(),
        operation,
        sessionAuth: { kind: 'cookie' },
        expiresAtMs,
        quotaUse: 'none',
      },
    }),
  );

  expect(result).toEqual({
    kind: 'explicit_key_export_ecdsa_activation_result',
    purpose: 'explicit_key_export',
    material: {
      kind: 'auth_neutral_ecdsa_export_material_v1',
      relayerUrl: 'https://relay.example',
      persistedMaterial: fixture.capability.material,
    },
    authorization: {
      kind: 'operation_step_up',
      grantId: exportGrantId(),
      operation,
      sessionAuth: { kind: 'cookie' },
      expiresAtMs,
      quotaUse: 'none',
    },
  });
  expect(Object.keys(result)).not.toContain('walletSessionJwt');
  expect(Object.keys(result)).not.toContain('thresholdSessionId');
  expect(Object.keys(result)).not.toContain('signingGrantId');
});
