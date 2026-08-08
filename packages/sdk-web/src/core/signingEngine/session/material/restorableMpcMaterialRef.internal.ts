class RestorableMpcMaterialReference {
  readonly kind = 'restorable_mpc_material_ref';
  readonly durableMaterialRef: string;
  private readonly protocolProof = true;

  private constructor(durableMaterialRef: string) {
    this.durableMaterialRef = durableMaterialRef;
    void this.protocolProof;
  }

  static build(durableMaterialRef: string): RestorableMpcMaterialReference {
    const normalized = String(durableMaterialRef || '').trim();
    if (!normalized) {
      throw new Error('Restorable MPC material reference is required');
    }
    return new RestorableMpcMaterialReference(normalized);
  }
}

export type RestorableMpcMaterialRef = RestorableMpcMaterialReference;

export function buildRestorableMpcMaterialRefInternal(
  durableMaterialRef: string,
): RestorableMpcMaterialRef {
  return RestorableMpcMaterialReference.build(durableMaterialRef);
}
