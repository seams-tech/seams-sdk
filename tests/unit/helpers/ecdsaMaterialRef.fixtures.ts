import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';

function unwrapDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function buildEcdsaRoleLocalPersistedMaterialRefFixture(args: {
  durableMaterialRef: string;
  bindingDigest: string;
  label?: string;
}): EcdsaRoleLocalPersistedMaterialRef {
  const label = args.label ?? args.durableMaterialRef;
  return parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(args.durableMaterialRef),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(args.bindingDigest),
    materialActivation: buildMpcMaterialActivationRef({
      activationId: unwrapDomainId(parseMpcMaterialActivationId(`activation:${label}`)),
      capability: unwrapDomainId(parseCapabilityInstanceRef(`capability:${label}`)),
      materialOwner: unwrapDomainId(parseMpcMaterialOwnerRef(`owner:${label}`)),
      keyBinding: unwrapDomainId(parseMpcKeyBindingRef(`key:${label}`)),
      lifecycleBinding: unwrapDomainId(parseMpcLifecycleBindingRef(`lifecycle:${label}`)),
      signingWorker: unwrapDomainId(parseMpcSigningWorkerRef(`worker:${label}`)),
    }),
  });
}
