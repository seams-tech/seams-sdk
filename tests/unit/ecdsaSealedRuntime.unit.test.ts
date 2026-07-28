import { expect, test } from '@playwright/test';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import type { CurrentEcdsaSealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { seedEmailOtpEcdsaSealedSigningSessionRecord } from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

// The manifest owns the exact capability, public facts and material activation;
// the sealed record owns session-scoped runtime state. This correlation is what
// prefill, Email OTP refresh and provisioning all need, so it has to match on
// stable material identity alone and fail closed on anything else.

function activeManifest(): ActiveEcdsaCapabilityManifest {
  return ecdsaCapabilityHydrationLookupFixture().active.manifest;
}

/** A sealed record whose role-local material ref names the manifest's exact
 * durable material, which is the only thing that makes it the right record. */
function sealedRecordForManifest(
  manifest: ActiveEcdsaCapabilityManifest,
  overrides: { storeKey?: string } = {},
): CurrentEcdsaSealedSessionRecord {
  const base = seedEmailOtpEcdsaSealedSigningSessionRecord();
  const durable = manifest.durableMaterial;
  return {
    ...base,
    ...(overrides.storeKey ? { storeKey: overrides.storeKey } : {}),
    walletId: String(durable.materialActivation.materialOwner),
    expiresAtMs: Date.now() + 5 * 60_000,
    remainingUses: 4,
    ecdsaRestore: {
      ...base.ecdsaRestore,
      keyHandle: String(durable.roleLocalPublicFacts.keyHandle),
      roleLocalMaterialRef: {
        ...base.ecdsaRestore.roleLocalMaterialRef,
        durableMaterialRef: String(durable.durableMaterialRef),
        materialActivation: durable.materialActivation,
      },
    },
  } as CurrentEcdsaSealedSessionRecord;
}

function resolve(
  manifest: ActiveEcdsaCapabilityManifest,
  sealedRecords: readonly CurrentEcdsaSealedSessionRecord[],
) {
  return resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: toWalletId(String(manifest.durableMaterial.materialActivation.materialOwner)),
    chainTarget: sealedRecords[0]?.ecdsaRestore.chainTarget ?? {
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    },
    sealedRecords,
  });
}

test.describe('exact ECDSA sealed runtime resolution', () => {
  test('resolves runtime facts from the sealed record bound to the manifest material', () => {
    const manifest = activeManifest();
    const record = sealedRecordForManifest(manifest);
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

  test('blocks when the sealed material ref is not canonical persisted material', () => {
    const manifest = activeManifest();
    const bound = sealedRecordForManifest(manifest);
    const malformed = {
      ...bound,
      ecdsaRestore: {
        ...bound.ecdsaRestore,
        roleLocalMaterialRef: {
          ...bound.ecdsaRestore.roleLocalMaterialRef,
          bindingDigest: '',
        },
      },
    } as CurrentEcdsaSealedSessionRecord;
    expect(resolve(manifest, [malformed])).toEqual({ kind: 'blocked', reason: 'corrupt' });
  });

  test('blocks when no sealed record names the manifest material activation', () => {
    const manifest = activeManifest();
    const bound = sealedRecordForManifest(manifest);
    const foreign = {
      ...bound,
      ecdsaRestore: {
        ...bound.ecdsaRestore,
        roleLocalMaterialRef: {
          ...bound.ecdsaRestore.roleLocalMaterialRef,
          materialActivation: buildMpcMaterialActivationRefFixture(
            'other-material',
            String(manifest.durableMaterial.materialActivation.materialOwner),
          ),
        },
      },
    } as CurrentEcdsaSealedSessionRecord;
    expect(resolve(manifest, [foreign])).toEqual({
      kind: 'blocked',
      reason: 'missing_material',
    });
    expect(resolve(manifest, [])).toEqual({ kind: 'blocked', reason: 'missing_material' });
  });

  test('blocks on conflict rather than choosing between two records for one material', () => {
    const manifest = activeManifest();
    const first = sealedRecordForManifest(manifest, { storeKey: 'sealed:a' });
    const second = sealedRecordForManifest(manifest, { storeKey: 'sealed:b' });
    expect(resolve(manifest, [first, second])).toEqual({
      kind: 'blocked',
      reason: 'exact_record_conflict',
    });
  });

  test('blocks when the bound record cannot supply complete runtime facts', () => {
    const manifest = activeManifest();
    const record = sealedRecordForManifest(manifest);
    const corrupt = {
      ...record,
      relayerUrl: '   ',
    } as CurrentEcdsaSealedSessionRecord;
    expect(resolve(manifest, [corrupt])).toEqual({ kind: 'blocked', reason: 'corrupt' });
  });

  test('a rotating threshold-session id never selects the record', () => {
    const manifest = activeManifest();
    const record = sealedRecordForManifest(manifest);
    const rotated = {
      ...record,
      thresholdSessionIds: { ecdsa: 'ec-session-rotated' },
    } as CurrentEcdsaSealedSessionRecord;
    const resolution = resolve(manifest, [rotated]);

    // Same material, different session id: still the right record.
    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;
    expect(resolution.runtime.sealedRecord.thresholdSessionId).toBe('ec-session-rotated');
  });
});
