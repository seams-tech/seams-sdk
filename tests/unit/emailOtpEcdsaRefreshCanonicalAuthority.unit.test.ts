import { expect, test } from '@playwright/test';
import {
  resolveEmailOtpEcdsaSigningSessionAuthorityFromCapability,
  resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime,
} from '@/core/signingEngine/session/emailOtp/ecdsaSigningSessionAuthority';
import { resolveCanonicalEmailOtpEcdsaExportMaterialForLane } from '@/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import type { ExactEcdsaExportLane } from '@/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { buildBaseEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  activeEvmFamilyWalletSessionAuthorizationFixture,
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import {
  refreshEmailOtpSigningSession,
  type EmailOtpEcdsaSigningSessionDeps,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import { resolveThresholdEcdsaSigningQueueKey } from '@/core/signingEngine/threshold/ecdsa/signingQueue';
import { buildActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
} from '@shared/utils/domainIds';

// Email OTP refresh renews authorization over material that already exists. It
// resolves the exact manifest plus sealed runtime, takes the Email OTP binding
// from the runtime, and completes the signing-session lane with the reusable
// Wallet Session resolved independently. Refresh must not move the material
// activation, and must never reach for recovery or device linking.

function resolvedRuntime(overrides: { thresholdSessionId?: string } = {}) {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
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

function activeAuthorization(walletSessionId: string) {
  return activeEvmFamilyWalletSessionAuthorizationFixture({
    manifest: ecdsaCapabilityHydrationLookupFixture().active.manifest,
    walletSessionId,
    authMethod: 'email_otp',
  }).projection;
}

function requiredParsed<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('focused authorization fixture identity is invalid');
  return result.value;
}

function activeAuthorizationWithoutEcdsa(walletSessionId: string) {
  const active = activeAuthorization(walletSessionId);
  if (active.walletSessionTokens.kind !== 'evm_family_ecdsa') {
    throw new Error('ECDSA authorization fixture must carry an ECDSA token');
  }
  const ecdsaToken = active.walletSessionTokens.ecdsa.walletSessionToken;
  const [header, payload, signature] = ecdsaToken.split('.');
  if (!header || !payload || !signature) throw new Error('invalid ECDSA JWT fixture');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  claims.kind = ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND;
  const nearJwt = `${header}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature}`;
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: active.walletId,
    walletSessionId: active.walletSessionId,
    quotaId: active.quotaId,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId: active.walletSessionTokens.ecdsa.authorizationId,
        walletSessionToken: nearJwt,
        thresholdSessionId: requiredParsed(
          parseThresholdEd25519SessionId('ed25519-fixture-threshold-session'),
        ),
      },
    },
    authMethod: active.authMethod,
    authority: active.authority,
    expiresAtMs: active.expiresAtMs,
  });
}

function activeCanonicalAuthorization(
  manifest: Awaited<ReturnType<typeof canonicalEvmFamilyEcdsaSigningCapabilityFixture>>['manifest'],
  thresholdSessionId: string,
) {
  const active = activeEvmFamilyWalletSessionAuthorizationFixture({
    manifest,
    authMethod: 'email_otp',
  }).projection;
  if (active.walletSessionTokens.kind !== 'evm_family_ecdsa') {
    throw new Error('ECDSA authorization fixture must carry an ECDSA token');
  }
  const [header, payload, signature] =
    active.walletSessionTokens.ecdsa.walletSessionToken.split('.');
  if (!header || !payload || !signature) throw new Error('invalid ECDSA JWT fixture');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  claims.thresholdSessionId = thresholdSessionId;
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: active.walletId,
    walletSessionId: active.walletSessionId,
    quotaId: active.quotaId,
    walletSessionTokens: {
      kind: 'evm_family_ecdsa',
      ecdsa: {
        authorizationId: active.walletSessionTokens.ecdsa.authorizationId,
        walletSessionToken: `${header}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature}`,
        thresholdSessionId: requiredParsed(parseThresholdEcdsaSessionId(thresholdSessionId)),
      },
    },
    authMethod: active.authMethod,
    authority: active.authority,
    expiresAtMs: active.expiresAtMs,
  });
}

function canonicalEmailOtpExportLaneFixture(args: {
  capability: Awaited<
    ReturnType<typeof canonicalEvmFamilyEcdsaSigningCapabilityFixture>
  >['capability'];
  authorization: ReturnType<typeof activeEvmFamilyWalletSessionAuthorizationFixture>;
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
  test('builds a post-registration lane from the canonical capability without a sealed record', async () => {
    const { capability, manifest } =
      await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp');
    const [chainTarget] = manifest.signer.scope.targetMemberships;
    if (!chainTarget) throw new Error('ECDSA fixture must have a target membership');
    const authorization = activeCanonicalAuthorization(manifest, 'ec-session-registration');
    const resolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromCapability({
      capability,
      authorization,
      chainTarget,
    });

    expect(resolution.kind).toBe('ready');
    if (resolution.kind !== 'ready') return;
    expect(resolution.authority.authority).toEqual(capability.authority);
    expect(resolution.authority.authLane.thresholdSessionId).toBe('ec-session-registration');
    expect(resolution.authority.authLane.chainTarget).toEqual(chainTarget);
  });

  test('projects shared ECDSA material onto a sibling Tempo target', async () => {
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
    const authorization = activeCanonicalAuthorization(manifest, 'ec-session-tempo');
    const resolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromCapability({
      capability,
      authorization,
      chainTarget: tempoTarget,
    });

    expect(resolution.kind).toBe('ready');
    if (resolution.kind !== 'ready') return;
    expect(resolution.authority.authLane.chainTarget).toEqual(tempoTarget);
  });

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
    const active = activeEvmFamilyWalletSessionAuthorizationFixture({
      manifest,
      authMethod: 'email_otp',
    });
    const authorization = {
      ...active,
      projection: activeCanonicalAuthorization(manifest, 'ec-session-registration-export'),
    };
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

  test('builds the signing-session lane from runtime binding and active authorization', () => {
    const { runtime } = resolvedRuntime();
    const resolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
      runtime,
      authorization: activeAuthorization('wallet-session-refresh'),
    });

    expect(resolution.kind).toBe('ready');
    if (resolution.kind !== 'ready') return;
    const authLane = resolution.authority.authLane;
    expect(authLane.kind).toBe('signing_session');
    expect(authLane.curve).toBe('ecdsa');
    // The Email OTP lane names the sealed threshold session. Reusable Wallet
    // Session identity remains on the independent authorization projection.
    expect(authLane.thresholdSessionId).toBe(runtime.sealedRecord.thresholdSessionId);
    expect(authLane.walletSessionToken).toMatch(/^eyJ/);
  });

  test('an absent Wallet Session is a typed unavailable, not a throw', () => {
    const { runtime } = resolvedRuntime();
    const resolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
      runtime,
      authorization: activeAuthorizationWithoutEcdsa('wallet-session-refresh'),
    });

    expect(resolution.kind).toBe('wallet_session_auth_unavailable');
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
    const initial = resolvedRuntime();
    const authorityResolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
      runtime: initial.runtime,
      authorization: activeAuthorization('wallet-session-refresh'),
    });
    if (authorityResolution.kind !== 'ready') {
      throw new Error('refresh fixture requires an active Email OTP authority');
    }
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
            authority: authorityResolution.authority,
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
