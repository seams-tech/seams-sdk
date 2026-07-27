import { expect, test } from '@playwright/test';
import type { EcdsaCapabilityManifestLookup } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { resolveEcdsaCapabilityHydration } from '@/core/signingEngine/session/material/ecdsaCapabilityHydration';
import { parseMpcCapabilityRuntimeRef, type DomainIdParseResult } from '@shared/utils/domainIds';
import { parseCorrelationId } from '@shared/utils/canonicalPrimitives';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';

function unwrap<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function resolveAbsentEcdsaHydration(
  lookup: EcdsaCapabilityManifestLookup,
  entryPoint: 'post_registration' | 'post_wallet_unlock' | 'post_page_refresh',
) {
  return resolveEcdsaCapabilityHydration({
    entryPoint,
    lookup,
    runtime: { kind: 'absent' },
  });
}

function resolveBlockedPlan(lookup: EcdsaCapabilityManifestLookup) {
  return resolveAbsentEcdsaHydration(lookup, 'post_page_refresh').plan;
}

function planKind(plan: ReturnType<typeof resolveBlockedPlan>): string {
  return plan.kind;
}

function blockedReason(plan: ReturnType<typeof resolveBlockedPlan>): string | null {
  return plan.kind === 'blocked' ? plan.reason : null;
}

test('normalizes exact active ECDSA material into live and rehydration plans', () => {
  const fixture = ecdsaCapabilityHydrationLookupFixture();
  const absent = resolveAbsentEcdsaHydration(fixture.active, 'post_page_refresh');
  expect(absent.plan).toMatchObject({
    kind: 'rehydrate_material_activation',
    capability: fixture.active.manifest.signer.capability,
    materialOwner: fixture.active.manifest.signer.materialOwner,
    authority: fixture.active.manifest.signer.authority,
    materialActivation: fixture.active.manifest.activation.materialActivation,
    sealedMaterial: {
      kind: 'restorable_mpc_material_ref',
      durableMaterialRef: fixture.active.manifest.durableMaterial.durableMaterialRef,
    },
  });

  const live = resolveEcdsaCapabilityHydration({
    entryPoint: 'post_wallet_unlock',
    lookup: fixture.active,
    runtime: {
      kind: 'live',
      runtime: unwrap(parseMpcCapabilityRuntimeRef('ecdsa-runtime-fixture')),
      materialActivation: fixture.active.manifest.activation.materialActivation,
    },
  });
  expect(live.plan).toMatchObject({
    kind: 'use_live_runtime',
    capability: fixture.active.manifest.signer.capability,
    materialOwner: fixture.active.manifest.signer.materialOwner,
    materialActivation: fixture.active.manifest.activation.materialActivation,
  });
});

test('selects the same ECDSA hydration decision for every entry point', () => {
  const fixture = ecdsaCapabilityHydrationLookupFixture();
  const decisions = [
    resolveAbsentEcdsaHydration(fixture.active, 'post_registration').plan.kind,
    resolveAbsentEcdsaHydration(fixture.active, 'post_wallet_unlock').plan.kind,
    resolveAbsentEcdsaHydration(fixture.active, 'post_page_refresh').plan.kind,
  ];
  expect(decisions).toEqual([
    'rehydrate_material_activation',
    'rehydrate_material_activation',
    'rehydrate_material_activation',
  ]);
});

test('maps canonical ECDSA lookup failures to exact blocked outcomes', () => {
  const fixture = ecdsaCapabilityHydrationLookupFixture();
  const selector = fixture.selectors.active;
  const failureDigest = fixture.active.manifest.activation.serverActivation.activationRequestDigest;
  const retryCorrelation = parseCorrelationId('ecdsa-hydration-retry');
  const lookups: readonly EcdsaCapabilityManifestLookup[] = [
    fixture.retired,
    {
      kind: 'missing',
      selector,
      subject: 'capability',
    },
    {
      kind: 'missing',
      selector,
      subject: 'material',
    },
    {
      kind: 'exact_binding_mismatch',
      selector,
      failureDigest,
    },
    {
      kind: 'exact_record_conflict',
      selector,
      conflictDigest: failureDigest,
    },
    {
      kind: 'corrupt',
      selector,
      corruptionDigest: failureDigest,
    },
    {
      kind: 'persistence_unavailable',
      selector,
      retryCorrelation,
    },
  ];
  const blocked = lookups.map(resolveBlockedPlan);
  expect(blocked.map(planKind)).toEqual(new Array(lookups.length).fill('blocked'));
  expect(blocked.map(blockedReason)).toEqual([
    'replaced',
    'missing_capability',
    'missing_material',
    'binding_mismatch',
    'exact_record_conflict',
    'corrupt',
    'persistence_unavailable',
  ]);
  expect(blocked[1]).toMatchObject({
    kind: 'blocked',
    capability: null,
    reason: 'missing_capability',
  });
});
