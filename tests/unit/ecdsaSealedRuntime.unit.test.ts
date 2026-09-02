import { expect, test } from '@playwright/test';
import {
  resolveExactEcdsaSealedRuntime,
  resolveExactInactiveEcdsaMaterialRuntime,
} from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import {
  type CurrentEcdsaSealedSessionRecord,
  type EcdsaInactiveSealedMaterialRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  ecdsaCapabilityActivationLookupFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildEmailOtpEcdsaSealedRuntimeRecordFixture,
  buildEmailOtpInactiveEcdsaMaterialRecordFixture,
  buildPasskeyEcdsaSealedRuntimeRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import {
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { parseWalletAuthMethodId } from '@shared/utils/domainIds';

// The manifest owns the exact capability, public facts and material activation;
// the sealed record owns session-scoped runtime state. This correlation is what
// prefill, Email OTP refresh and provisioning all need, so it has to match on
// stable material identity alone and fail closed on anything else.

function activeManifest(): ActiveEcdsaCapabilityManifest {
  return ecdsaCapabilityHydrationLookupFixture().active.manifest;
}

function resolve(
  manifest: ActiveEcdsaCapabilityManifest,
  sealedRecords: readonly CurrentEcdsaSealedSessionRecord[],
) {
  return resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: toWalletId(String(manifest.signer.walletId)),
    chainTarget: sealedRecords[0]?.ecdsaRestore.chainTarget ?? {
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    },
    sealedRecords,
  });
}

function buildInactiveRecord(
  manifest: ActiveEcdsaCapabilityManifest,
  corruption?: Parameters<typeof buildEmailOtpEcdsaSealedRuntimeRecordFixture>[0]['corruption'],
): EcdsaInactiveSealedMaterialRecord {
  return buildEmailOtpInactiveEcdsaMaterialRecordFixture({
    manifest,
    corruption,
  });
}

function resolveInactive(
  manifest: ActiveEcdsaCapabilityManifest,
  inactiveRecords: readonly EcdsaInactiveSealedMaterialRecord[],
  authMethod: 'passkey' | 'email_otp' = 'email_otp',
) {
  return resolveExactInactiveEcdsaMaterialRuntime({
    manifest,
    walletId: toWalletId(String(manifest.signer.walletId)),
    chainTarget: inactiveRecords[0]?.ecdsaRestore.chainTarget ?? {
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    },
    authMethod,
    inactiveRecords,
  });
}

test.describe('exact ECDSA sealed runtime resolution', () => {
  test('rebinds a sealed Email OTP runtime to the manifest V2 auth-method id', async () => {
    const walletId = toWalletId('ecdsa-manifest-fixture-wallet');
    const baseAuthority = buildEmailOtpWalletAuthAuthority({
      walletId,
      provider: 'google',
      providerUserId: `google:${String(walletId)}`,
      emailHashHex: 'email-hash',
    });
    const walletAuthMethodId = parseWalletAuthMethodId(
      `email_otp:${String(walletId)}:canonical-method`,
    );
    if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
    const authority = {
      walletId: baseAuthority.walletId,
      factor: baseAuthority.factor,
      verifier: baseAuthority.verifier,
      bindingId: walletAuthMethodId.value,
    };
    const authorityRef = await walletAuthAuthorityRef({ authority });
    const manifest = ecdsaCapabilityActivationLookupFixture({ authority: authorityRef }).manifest;
    const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
    const resolution = resolveExactEcdsaSealedRuntime({
      manifest,
      walletId,
      chainTarget: record.ecdsaRestore.chainTarget,
      sealedRecords: [record],
    });

    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;
    expect(resolution.runtime.authBinding.kind).toBe('email_otp');
    if (resolution.runtime.authBinding.kind !== 'email_otp') return;
    expect(resolution.runtime.authBinding.emailOtpAuthority.bindingId).toBe(
      walletAuthMethodId.value,
    );
    await expect(
      walletAuthAuthorityRef({ authority: resolution.runtime.authBinding.emailOtpAuthority }),
    ).resolves.toEqual(manifest.signer.authority);
  });

  test('resolves runtime facts from the sealed record bound to the manifest material', () => {
    const manifest = activeManifest();
    const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
    const resolution = resolve(manifest, [record]);

    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;
    const runtime = resolution.runtime;

    // Material identity comes from the activation both sides agree on.
    expect(runtime.materialActivation.activationId).toBe(
      manifest.durableMaterial.materialActivation.activationId,
    );
    // Session-scoped runtime state comes from the sealed record.
    expect(runtime.normalSigning).toBe(record.ecdsaRestore.routerAbEcdsaDerivationNormalSigning);
    expect(runtime.remainingUses).toBe(4);
    expect(runtime.expiresAtMs).toBe(record.expiresAtMs);
    // The exact record is carried back so allowance writes target it.
    expect(runtime.sealedRecord.storeKey).toBe(record.storeKey);
    expect(runtime.sealedRecord.thresholdSessionId).toBe(record.thresholdSessionIds.ecdsa);
    // Durable material is exposed in the canonical persisted form, naming the
    // same activation, so callers never re-derive it from the sealed shape.
    expect(runtime.roleLocalMaterialRef.materialActivation.activationId).toBe(
      manifest.durableMaterial.materialActivation.activationId,
    );
    expect(String(runtime.roleLocalMaterialRef.durableMaterialRef)).toBe(
      String(manifest.durableMaterial.durableMaterialRef),
    );
  });

  test('resolves a family target whose sealed projection differs from the manifest anchor target', () => {
    const tempoTarget = {
      kind: 'tempo' as const,
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    };
    const arcTarget = {
      kind: 'evm' as const,
      namespace: 'eip155' as const,
      chainId: 5042002,
      networkSlug: 'arc-testnet',
    };
    const manifest = ecdsaCapabilityActivationLookupFixture({
      targetMemberships: [tempoTarget, arcTarget],
    }).manifest;
    const record = buildPasskeyEcdsaSealedRuntimeRecordFixture({
      manifest,
      chainTarget: arcTarget,
    });

    const resolution = resolve(manifest, [record]);

    expect(resolution.kind).toBe('resolved');
  });

  test('blocks when the sealed material ref is not canonical persisted material', () => {
    const manifest = activeManifest();
    const malformed = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: { kind: 'blank_binding_digest' },
    });
    expect(resolve(manifest, [malformed])).toEqual({ kind: 'blocked', reason: 'corrupt' });
  });

  test('blocks when no sealed record names the manifest material activation', () => {
    const manifest = activeManifest();
    const foreign = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: {
        kind: 'foreign_material_activation',
        materialActivation: buildMpcMaterialActivationRefFixture(
          'other-material',
          String(manifest.durableMaterial.materialActivation.materialOwner),
        ),
      },
    });
    expect(resolve(manifest, [foreign])).toEqual({
      kind: 'blocked',
      reason: 'missing_material',
    });
    expect(resolve(manifest, [])).toEqual({ kind: 'blocked', reason: 'missing_material' });
  });

  test('blocks on conflict rather than choosing between two records for one material', () => {
    const manifest = activeManifest();
    const first = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      thresholdSessionId: 'ec-session-a',
    });
    const second = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      thresholdSessionId: 'ec-session-b',
    });
    expect(resolve(manifest, [first, second])).toEqual({
      kind: 'blocked',
      reason: 'exact_record_conflict',
    });
  });

  test('blocks when the bound record cannot supply complete runtime facts', () => {
    const manifest = activeManifest();
    const corrupt = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: { kind: 'blank_relayer_url' },
    });
    expect(resolve(manifest, [corrupt])).toEqual({ kind: 'blocked', reason: 'corrupt' });
  });

  test('blocks sealed facts that disagree with the selected manifest', () => {
    const manifest = activeManifest();
    const mismatchedAuthority = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: {
        kind: 'authority_mismatch',
        authority: buildWalletAuthAuthorityRefFixture({
          walletId: String(manifest.signer.walletId),
          label: 'other-authority',
        }),
      },
    });
    const mismatchedNormalSigning = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: { kind: 'normal_signing_wallet_id', walletId: 'other-wallet' },
    });
    const mismatchedRelayer = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: { kind: 'relayer_key_id', relayerKeyId: 'other-relayer' },
    });

    expect(resolve(manifest, [mismatchedAuthority])).toEqual({
      kind: 'blocked',
      reason: 'binding_mismatch',
    });
    expect(resolve(manifest, [mismatchedNormalSigning])).toEqual({
      kind: 'blocked',
      reason: 'binding_mismatch',
    });
    expect(resolve(manifest, [mismatchedRelayer])).toEqual({
      kind: 'blocked',
      reason: 'binding_mismatch',
    });
  });

  test('rejects synthesized or mismatched exact worker and auth identities', () => {
    const manifest = activeManifest();
    const identityMismatches = [
      { kind: 'auth_method', authMethod: 'passkey' },
      { kind: 'binding_digest', bindingDigest: 'synthesized-binding-digest' },
      { kind: 'key_handle', keyHandle: 'synthesized-key-handle' },
      { kind: 'ecdsa_threshold_key_id', thresholdKeyId: 'synthesized-threshold-key' },
      { kind: 'threshold_public_key', publicKeyB64u: 'synthesized-threshold-public-key' },
      { kind: 'client_verifying_share', shareB64u: 'synthesized-client-verifying-share' },
      { kind: 'signing_root_id', signingRootId: 'synthesized:signing-root' },
      { kind: 'signing_root_version', signingRootVersion: 'synthesized-version' },
      { kind: 'ethereum_address', ethereumAddress: '0x0000000000000000000000000000000000000001' },
      {
        kind: 'normal_signing_worker_id',
        signingWorkerId: 'wallet-session:synthesized-worker',
      },
      {
        kind: 'normal_signing_context',
        applicationBindingDigestB64u: 'synthesized-application-binding',
      },
      {
        kind: 'normal_signing_server_public_key',
        publicKeyB64u: 'synthesized-server-public-key',
      },
      {
        kind: 'public_capability_signer_id',
        signerId: 'authorization:synthesized-signer',
      },
      { kind: 'public_capability_router_id', routerId: 'synthesized-router' },
      { kind: 'relayer_key_id', relayerKeyId: 'synthesized-relayer-key' },
    ] as const;

    for (const corruption of identityMismatches) {
      const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
        manifest,
        corruption,
      });
      expect(resolve(manifest, [record]), corruption.kind).toEqual({
        kind: 'blocked',
        reason: 'binding_mismatch',
      });
    }
  });

  test('rejects malformed two-party runtime facts', () => {
    const manifest = activeManifest();
    const invalidParticipantSets: readonly number[][] = [[1], [-1, 2], [1, 1], [1, 2, 3]];
    const negativeAllowance = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: { kind: 'remaining_uses', remainingUses: -1 },
    });
    const invalidExpiry = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      corruption: { kind: 'expires_at_ms', expiresAtMs: 0 },
    });

    for (const participantIds of invalidParticipantSets) {
      const malformedParticipants = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
        manifest,
        corruption: { kind: 'participant_ids', participantIds },
      });
      expect(resolve(manifest, [malformedParticipants])).toEqual({
        kind: 'blocked',
        reason: 'corrupt',
      });
    }
    expect(resolve(manifest, [negativeAllowance])).toEqual({
      kind: 'blocked',
      reason: 'corrupt',
    });
    expect(resolve(manifest, [invalidExpiry])).toEqual({
      kind: 'blocked',
      reason: 'corrupt',
    });
  });

  test('a rotating threshold-session id never selects the record', () => {
    const manifest = activeManifest();
    const rotated = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      thresholdSessionId: 'ec-session-rotated',
    });
    const resolution = resolve(manifest, [rotated]);

    // Same material, different session id: still the right record.
    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;
    expect(resolution.runtime.sealedRecord.thresholdSessionId).toBe('ec-session-rotated');
  });

  test('resolves inactive material without reusable authorization or session state', () => {
    const manifest = activeManifest();
    const record = buildInactiveRecord(manifest);
    const resolution = resolveInactive(manifest, [record]);

    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;
    expect(resolution.runtime.materialActivation).toEqual(
      manifest.durableMaterial.materialActivation,
    );
    expect(resolution.runtime.authBinding.kind).toBe('email_otp');
    expect(resolution.runtime.inactiveMaterialRecord).toEqual({
      storeKey: record.storeKey,
      authMethod: 'email_otp',
      authorizationRetirementReason: 'expired',
    });
    expect('sealedRecord' in resolution.runtime).toBe(false);
    expect('expiresAtMs' in resolution.runtime).toBe(false);
    expect('remainingUses' in resolution.runtime).toBe(false);
    expect('thresholdSessionId' in resolution.runtime).toBe(false);
    expect('authorization' in resolution.runtime).toBe(false);
  });

  test('correlates inactive material against its exact factor and manifest binding', () => {
    const manifest = activeManifest();
    const record = buildInactiveRecord(manifest);
    const mismatchedAuthority = buildInactiveRecord(manifest, {
      kind: 'authority_mismatch',
      authority: buildWalletAuthAuthorityRefFixture({
        walletId: String(manifest.signer.walletId),
        label: 'other-authority',
      }),
    });

    expect(resolveInactive(manifest, [record], 'passkey')).toEqual({
      kind: 'blocked',
      reason: 'missing_material',
    });
    expect(resolveInactive(manifest, [mismatchedAuthority])).toEqual({
      kind: 'blocked',
      reason: 'binding_mismatch',
    });
  });
});
