import {
  mpcMaterialActivationRefsEqual,
  type MpcCapabilityRuntimeRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type {
  EcdsaCapabilityManifestLookup,
  EcdsaCapabilityMaterialRefLookup,
} from '../../../indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  buildBlockedMpcCapabilityHydrationPlan,
  buildRehydrateMaterialActivationHydrationPlan,
  buildUseLiveRuntimeHydrationPlan,
  type MpcCapabilityHydrationPlan,
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

type EcdsaCapabilityHydrationLookup =
  | EcdsaCapabilityManifestLookup
  | EcdsaCapabilityMaterialRefLookup;

function blockedLookupCapability(
  lookup: Exclude<EcdsaCapabilityHydrationLookup, { readonly kind: 'active' | 'retired' }>,
) {
  return 'selector' in lookup ? lookup.selector.capability : lookup.capability;
}

function blockedPlanFromLookup(
  lookup: Exclude<EcdsaCapabilityHydrationLookup, { readonly kind: 'active' }>,
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
            capability: blockedLookupCapability(lookup),
            reason: 'missing_material',
          });
    case 'exact_binding_mismatch':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: blockedLookupCapability(lookup),
        reason: 'binding_mismatch',
      });
    case 'exact_record_conflict':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: blockedLookupCapability(lookup),
        reason: 'exact_record_conflict',
      });
    case 'corrupt':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: blockedLookupCapability(lookup),
        reason: 'corrupt',
      });
    case 'persistence_unavailable':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: blockedLookupCapability(lookup),
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
    !mpcMaterialActivationRefsEqual(
      materialActivation,
      input.lookup.material.binding.materialActivation,
    ) ||
    input.lookup.manifest.signer.materialOwner !== materialActivation.materialOwner
  ) {
    return buildBlockedMpcCapabilityHydrationPlan({
      capability: input.lookup.manifest.signer.capability,
      reason: 'binding_mismatch',
    });
  }
  switch (input.runtime.kind) {
    case 'live':
      if (!mpcMaterialActivationRefsEqual(materialActivation, input.runtime.materialActivation)) {
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

export type EcdsaCapabilityHydrationInput = {
  readonly lookup: EcdsaCapabilityHydrationLookup;
  readonly runtime: EcdsaCapabilityRuntimeObservation;
  readonly entryPoint?: never;
  readonly provenance?: never;
};

export function resolveEcdsaCapabilityHydration(
  input: EcdsaCapabilityHydrationInput,
): MpcCapabilityHydrationPlan {
  return input.lookup.kind === 'active'
    ? activePlanFromLookup({
        lookup: input.lookup,
        runtime: input.runtime,
      })
    : blockedPlanFromLookup(input.lookup);
}
