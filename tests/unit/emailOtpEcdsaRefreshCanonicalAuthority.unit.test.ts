import { expect, test } from '@playwright/test';
import { resolveCanonicalEmailOtpEcdsaExportMaterialForLane } from '@/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import type { ExactEcdsaExportLane } from '@/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { buildBaseEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import {
  refreshEmailOtpSigningSession,
  type EmailOtpEcdsaSigningSessionDeps,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import { buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture } from './helpers/exactEvmFamilyWalletSessionAuthorization.fixtures';
import { resolveThresholdEcdsaSigningQueueKey } from '@/core/signingEngine/threshold/ecdsa/signingQueue';
import type { ExactEvmFamilyWalletSessionAuthorization } from '@/core/signingEngine/session/material/ecdsaSigningCapability';

// Email OTP refresh renews authorization over material that already exists. It
// resolves the exact manifest plus sealed runtime, takes the Email OTP binding
// from the runtime, and completes the signing-session lane with the reusable
// Wallet Session resolved independently. Refresh must not move the material
// activation, and must never reach for recovery or device linking.

function resolvedRuntime(
  overrides: {
    manifest?: Awaited<
      ReturnType<typeof canonicalEvmFamilyEcdsaSigningCapabilityFixture>
    >['manifest'];
    thresholdSessionId?: string;
  } = {},
) {
  const manifest = overrides.manifest ?? ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
    manifest,
    ...(overrides.thresholdSessionId ? { thresholdSessionId: overrides.thresholdSessionId } : {}),
  });
  const walletId = toWalletId(String(manifest.signer.walletId));
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId,
    chainTarget: record.ecdsaRestore.chainTarget,
    sealedRecords: [record],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`sealed runtime fixture did not resolve: ${resolution.reason}`);
  }
  return { manifest, walletId, runtime: resolution.runtime, record };
}

function canonicalEmailOtpExportLaneFixture(args: {
  capability: Awaited<
    ReturnType<typeof canonicalEvmFamilyEcdsaSigningCapabilityFixture>
  >['capability'];
  authorization: ExactEvmFamilyWalletSessionAuthorization;
  chainTarget: ThresholdEcdsaChainTarget;
}): ExactEcdsaExportLane {
  const manifest = args.capability.manifest;
  const facts = manifest.signer.registeredPublicFacts;
  const durable = manifest.durableMaterial;
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: manifest.signer.walletId,
    ecdsaThresholdKeyId: durable.roleLocalBinding.ecdsaThresholdKeyId,
    signingRootId: manifest.signer.signingRootId,
    signingRootVersion: manifest.signer.signingRootVersion,
    participantIds: facts.participantIds,
    thresholdOwnerAddress: facts.thresholdOwnerAddress,
  });
  return {
    curve: 'ecdsa',
    laneIdentity: exactEcdsaSigningLaneIdentity({
      signer: buildEvmFamilyEcdsaSignerBinding({
        walletId: manifest.signer.walletId,
        chainTarget: args.chainTarget,
        keyHandle: facts.keyHandle,
        key,
        materialActivation: manifest.activation.materialActivation,
      }),
      auth: {
        kind: 'email_otp',
        providerSubjectId: args.capability.authority.factor.providerUserId,
      },
    }),
    key,
    publicFacts: facts,
    chainTarget: args.chainTarget,
    authMethod: 'email_otp',
    material: { kind: 'material_pending', reason: 'email_otp_route_auth' },
    state: 'ready',
    source: 'canonical_capability',
    capability: args.capability,
    authorizationState: 'authorized',
    authorization: args.authorization,
  };
}

test.describe('Email OTP ECDSA refresh canonical authority', () => {
  test('prepares immediate post-registration ECDSA export from canonical material', async () => {
    const { capability, manifest } = await canonicalEvmFamilyEcdsaSigningCapabilityFixture(
      'email_otp',
      {
        targetMemberships: [
          {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 1,
            networkSlug: 'ethereum',
          },
          {
            kind: 'tempo',
            chainId: 42431,
            networkSlug: 'tempo-testnet',
          },
        ],
      },
    );
    const tempoTarget = manifest.signer.scope.targetMemberships[1];
    if (!tempoTarget) throw new Error('ECDSA fixture must have a sibling Tempo target');
    const { runtime } = resolvedRuntime({ manifest });
    const authorization = await buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture({
      capability,
      runtime,
      label: 'canonical-export',
    });
    const lane = canonicalEmailOtpExportLaneFixture({
      capability,
      authorization,
      chainTarget: tempoTarget,
    });
    const material = resolveCanonicalEmailOtpEcdsaExportMaterialForLane({
      deps: {
        exportArtifactsByLane: new Map(),
        relayerUrl: 'https://relay.example.test',
      },
      exportLane: lane,
    });

    expect(material.persistedMaterial.materialActivation).toEqual(
      capability.manifest.activation.materialActivation,
    );
    expect(material.chainTarget).toEqual(tempoTarget);
    expect(material.authorization).toEqual({
      kind: 'fresh_operation_authorization_required',
      authority: capability.authority,
    });
    expect(material.normalSigning.scope.ecdsa_threshold_key_id).toBe(
      String(capability.manifest.durableMaterial.roleLocalBinding.ecdsaThresholdKeyId),
    );
  });

  test('refresh keeps the same material activation across a rotated session id', () => {
    const before = resolvedRuntime({ thresholdSessionId: 'ec-session-before' });
    const after = resolvedRuntime({ thresholdSessionId: 'ec-session-after' });

    // A refresh rotates session identity while the material underneath is
    // unchanged; that is exactly what the post-refresh activation check allows.
    expect(after.runtime.sealedRecord.thresholdSessionId).not.toBe(
      before.runtime.sealedRecord.thresholdSessionId,
    );
    expect(after.runtime.materialActivation.activationId).toBe(
      before.runtime.materialActivation.activationId,
    );
    expect(String(after.runtime.roleLocalMaterialRef.durableMaterialRef)).toBe(
      String(before.runtime.roleLocalMaterialRef.durableMaterialRef),
    );
  });

  test('rechecks the exact activation inside its owner queue before consuming refresh', async () => {
    const capability = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp');
    const initial = resolvedRuntime({ manifest: capability.manifest });
    const exactAuthorization = await buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture({
      capability: capability.capability,
      runtime: initial.runtime,
      label: 'refresh-fence',
    });
    let resolutionCalls = 0;
    let queueCalls = 0;
    let loginCalls = 0;
    const deps: EmailOtpEcdsaSigningSessionDeps = {
      resolveSigningSessionAuth: async () => {
        resolutionCalls += 1;
        if (resolutionCalls === 1) {
          return {
            manifest: initial.manifest,
            runtime: initial.runtime,
            authority: exactAuthorization,
          };
        }
        throw new Error('capability disappeared while queued');
      },
      withThresholdEcdsaSigningQueue: async (queueArgs) => {
        queueCalls += 1;
        expect(queueArgs.queueKey).toBe(
          resolveThresholdEcdsaSigningQueueKey({
            materialActivation: initial.runtime.materialActivation,
          }),
        );
        return await queueArgs.task();
      },
      emailOtpSessions: {
        requestTransactionSigningChallenge: async () => {
          throw new Error('challenge is not part of refresh fencing');
        },
        loginWithEcdsaCapabilityInternal: async () => {
          loginCalls += 1;
          throw new Error('refresh must not consume after supersession');
        },
      },
    };

    await expect(
      refreshEmailOtpSigningSession(deps, {
        walletSession: {
          walletId: initial.walletId,
          walletSessionUserId: String(initial.walletId),
        },
        chainTarget: initial.runtime.chainTarget,
        challengeId: 'challenge-refresh-fence',
        otpCode: '123456',
      }),
    ).rejects.toThrow('superseded before use');
    expect(queueCalls).toBe(1);
    expect(resolutionCalls).toBe(2);
    expect(loginCalls).toBe(0);
  });
});
