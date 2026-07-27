import type { MpcCapabilityRuntimeRef, MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { EcdsaCapabilityManifestLookup } from '../../../indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  buildBlockedMpcCapabilityHydrationPlan,
  buildMpcCapabilityHydrationResolution,
  buildRehydrateMaterialActivationHydrationPlan,
  buildUseLiveRuntimeHydrationPlan,
  type MpcCapabilityHydrationEntryPoint,
  type MpcCapabilityHydrationPlan,
  type MpcCapabilityHydrationResolution,
} from './mpcCapabilityHydration';
import { buildRestorableMpcMaterialRefInternal } from './restorableMpcMaterialRef.internal';

export type EcdsaCapabilityRuntimeObservation =
  | {
      readonly kind: 'live';
      readonly runtime: MpcCapabilityRuntimeRef;
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'absent';
      readonly runtime?: never;
      readonly materialActivation?: never;
    };

function materialActivationsMatch(
  left: MpcMaterialActivationRef,
  right: MpcMaterialActivationRef,
): boolean {
  return (
    left.activationId === right.activationId &&
    left.capability === right.capability &&
    left.materialOwner === right.materialOwner &&
    left.keyBinding === right.keyBinding &&
    left.lifecycleBinding === right.lifecycleBinding &&
    left.signingWorker === right.signingWorker
  );
}

function blockedPlanFromLookup(
  lookup: Exclude<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }>,
): MpcCapabilityHydrationPlan {
  switch (lookup.kind) {
    case 'retired':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: lookup.manifest.signer.capability,
        reason: 'replaced',
      });
    case 'missing':
      return lookup.subject === 'capability'
        ? buildBlockedMpcCapabilityHydrationPlan({
            capability: null,
            reason: 'missing_capability',
          })
        : buildBlockedMpcCapabilityHydrationPlan({
            capability: lookup.selector.capability,
            reason: 'missing_material',
          });
    case 'exact_binding_mismatch':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: lookup.selector.capability,
        reason: 'binding_mismatch',
      });
    case 'exact_record_conflict':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: lookup.selector.capability,
        reason: 'exact_record_conflict',
      });
    case 'corrupt':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: lookup.selector.capability,
        reason: 'corrupt',
      });
    case 'persistence_unavailable':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: lookup.selector.capability,
        reason: 'persistence_unavailable',
      });
  }
}

function activePlanFromLookup(input: {
  readonly lookup: Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }>;
  readonly runtime: EcdsaCapabilityRuntimeObservation;
}): MpcCapabilityHydrationPlan {
  const materialActivation = input.lookup.manifest.activation.materialActivation;
  if (
    !materialActivationsMatch(
      materialActivation,
      input.lookup.material.binding.materialActivation,
    ) ||
    input.lookup.manifest.signer.capability !== materialActivation.capability ||
    input.lookup.manifest.signer.materialOwner !== materialActivation.materialOwner
  ) {
    return buildBlockedMpcCapabilityHydrationPlan({
      capability: input.lookup.manifest.signer.capability,
      reason: 'binding_mismatch',
    });
  }
  switch (input.runtime.kind) {
    case 'live':
      if (!materialActivationsMatch(materialActivation, input.runtime.materialActivation)) {
        return buildBlockedMpcCapabilityHydrationPlan({
          capability: input.lookup.manifest.signer.capability,
          reason: 'binding_mismatch',
        });
      }
      return buildUseLiveRuntimeHydrationPlan({
        authority: input.lookup.manifest.signer.authority,
        runtime: input.runtime.runtime,
        materialActivation,
      });
    case 'absent':
      return buildRehydrateMaterialActivationHydrationPlan({
        authority: input.lookup.manifest.signer.authority,
        materialActivation,
        sealedMaterial: buildRestorableMpcMaterialRefInternal(
          input.lookup.material.binding.durableMaterialRef,
        ),
      });
  }
}

export function resolveEcdsaCapabilityHydration(input: {
  readonly entryPoint: MpcCapabilityHydrationEntryPoint;
  readonly lookup: EcdsaCapabilityManifestLookup;
  readonly runtime: EcdsaCapabilityRuntimeObservation;
}): MpcCapabilityHydrationResolution {
  const plan =
    input.lookup.kind === 'active'
      ? activePlanFromLookup({
          lookup: input.lookup,
          runtime: input.runtime,
        })
      : blockedPlanFromLookup(input.lookup);
  return buildMpcCapabilityHydrationResolution({
    entryPoint: input.entryPoint,
    plan,
  });
}
