import type {
  CapabilityInstanceRef,
  MpcCapabilityRuntimeRef,
  MpcKeyBindingRef,
  MpcLifecycleBindingRef,
  MpcMaterialActivationRef,
  MpcMaterialOwnerRef,
  MpcReauthorizationPolicyRef,
  MpcRegisteredPublicKeyBindingRef,
} from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { RestorableMpcMaterialRef } from './restorableMpcMaterialRef.internal';

export type { RestorableMpcMaterialRef } from './restorableMpcMaterialRef.internal';

abstract class MpcHydrationProof {
  private retainProof(): true {
    return true;
  }

  constructor() {
    void this.retainProof();
  }
}

type MpcCapabilityPublicReauthAnchorFields = {
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly reauthorizationPolicy: MpcReauthorizationPolicyRef;
  readonly registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;
  readonly secretMaterial?: never;
  readonly sealedMaterial?: never;
  readonly bearerSessionCredential?: never;
  readonly runtime?: never;
  readonly materialActivation?: never;
  readonly operationGrant?: never;
  readonly quotaState?: never;
  readonly nonceState?: never;
};

class MpcCapabilityPublicReauthAnchorProof extends MpcHydrationProof {
  readonly kind = 'mpc_capability_public_reauth_anchor';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly reauthorizationPolicy: MpcReauthorizationPolicyRef;
  readonly registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;

  constructor(fields: MpcCapabilityPublicReauthAnchorFields) {
    super();
    this.capability = fields.capability;
    this.materialOwner = fields.materialOwner;
    this.authority = fields.authority;
    this.keyBinding = fields.keyBinding;
    this.lifecycleBinding = fields.lifecycleBinding;
    this.reauthorizationPolicy = fields.reauthorizationPolicy;
    this.registeredPublicKeyBinding = fields.registeredPublicKeyBinding;
  }
}

export type MpcCapabilityPublicReauthAnchor = MpcCapabilityPublicReauthAnchorProof &
  MpcCapabilityPublicReauthAnchorFields;

type MpcUseLiveRuntimeHydrationPlanFields = {
  readonly authority: WalletAuthAuthorityRef;
  readonly runtime: MpcCapabilityRuntimeRef;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly sealedMaterial?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

type MpcUseLiveRuntimeHydrationPlanInput = MpcUseLiveRuntimeHydrationPlanFields & {
  readonly capability?: never;
  readonly materialOwner?: never;
};

class MpcUseLiveRuntimeHydrationPlanProof extends MpcHydrationProof {
  readonly kind = 'use_live_runtime';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly runtime: MpcCapabilityRuntimeRef;
  readonly materialActivation: MpcMaterialActivationRef;

  constructor(fields: MpcUseLiveRuntimeHydrationPlanInput) {
    super();
    this.capability = fields.materialActivation.capability;
    this.materialOwner = fields.materialActivation.materialOwner;
    this.authority = fields.authority;
    this.runtime = fields.runtime;
    this.materialActivation = fields.materialActivation;
  }
}

export type MpcUseLiveRuntimeHydrationPlan = MpcUseLiveRuntimeHydrationPlanProof &
  MpcUseLiveRuntimeHydrationPlanFields;

type MpcRehydrateMaterialActivationHydrationPlanFields = {
  readonly authority: WalletAuthAuthorityRef;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly sealedMaterial: RestorableMpcMaterialRef;
  readonly runtime?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

type MpcRehydrateMaterialActivationHydrationPlanInput =
  MpcRehydrateMaterialActivationHydrationPlanFields & {
    readonly capability?: never;
    readonly materialOwner?: never;
  };

class MpcRehydrateMaterialActivationHydrationPlanProof extends MpcHydrationProof {
  readonly kind = 'rehydrate_material_activation';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly sealedMaterial: RestorableMpcMaterialRef;

  constructor(fields: MpcRehydrateMaterialActivationHydrationPlanInput) {
    super();
    this.capability = fields.materialActivation.capability;
    this.materialOwner = fields.materialActivation.materialOwner;
    this.authority = fields.authority;
    this.materialActivation = fields.materialActivation;
    this.sealedMaterial = fields.sealedMaterial;
  }
}

export type MpcRehydrateMaterialActivationHydrationPlan =
  MpcRehydrateMaterialActivationHydrationPlanProof &
    MpcRehydrateMaterialActivationHydrationPlanFields;

type MpcReauthorizePublicAnchorHydrationPlanFields = {
  readonly retirement: 'expired' | 'exhausted';
  readonly publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
  readonly runtime?: never;
  readonly materialActivation?: never;
  readonly sealedMaterial?: never;
};

type MpcReauthorizePublicAnchorHydrationPlanInput =
  MpcReauthorizePublicAnchorHydrationPlanFields & {
    readonly capability?: never;
    readonly materialOwner?: never;
    readonly authority?: never;
  };

class MpcReauthorizePublicAnchorHydrationPlanProof extends MpcHydrationProof {
  readonly kind = 'reauthorize_public_anchor';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly retirement: 'expired' | 'exhausted';
  readonly publicReauthAnchor: MpcCapabilityPublicReauthAnchor;

  constructor(fields: MpcReauthorizePublicAnchorHydrationPlanInput) {
    super();
    this.capability = fields.publicReauthAnchor.capability;
    this.materialOwner = fields.publicReauthAnchor.materialOwner;
    this.authority = fields.publicReauthAnchor.authority;
    this.retirement = fields.retirement;
    this.publicReauthAnchor = fields.publicReauthAnchor;
  }
}

export type MpcReauthorizePublicAnchorHydrationPlan = MpcReauthorizePublicAnchorHydrationPlanProof &
  MpcReauthorizePublicAnchorHydrationPlanFields;

export type MpcCapabilityHydrationBlockedReason =
  | 'missing_capability'
  | 'missing_material'
  | 'revoked'
  | 'replaced'
  | 'authority_ambiguous'
  | 'binding_mismatch'
  | 'exact_record_conflict'
  | 'corrupt'
  | 'persistence_unavailable';

abstract class MpcBlockedCapabilityHydrationPlanProof extends MpcHydrationProof {
  readonly kind = 'blocked';
}

type MpcBlockedCapabilityHydrationPlanFields = {
  readonly materialOwner?: never;
  readonly authority?: never;
  readonly runtime?: never;
  readonly materialActivation?: never;
  readonly sealedMaterial?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

class MpcMissingCapabilityHydrationPlanProof extends MpcBlockedCapabilityHydrationPlanProof {
  readonly capability = null;
  readonly reason = 'missing_capability';
}

type MpcKnownCapabilityBlockedHydrationPlanFields = {
  readonly capability: CapabilityInstanceRef;
  readonly reason: Exclude<MpcCapabilityHydrationBlockedReason, 'missing_capability'>;
} & MpcBlockedCapabilityHydrationPlanFields;

type MpcMissingCapabilityHydrationPlanFields = {
  readonly capability: null;
  readonly reason: 'missing_capability';
} & MpcBlockedCapabilityHydrationPlanFields;

class MpcKnownCapabilityBlockedHydrationPlanProof extends MpcBlockedCapabilityHydrationPlanProof {
  readonly capability: CapabilityInstanceRef;
  readonly reason: Exclude<MpcCapabilityHydrationBlockedReason, 'missing_capability'>;

  constructor(fields: MpcKnownCapabilityBlockedHydrationPlanFields) {
    super();
    this.capability = fields.capability;
    this.reason = fields.reason;
  }
}

export type MpcBlockedCapabilityHydrationPlan =
  | (MpcMissingCapabilityHydrationPlanProof & MpcBlockedCapabilityHydrationPlanFields)
  | (MpcKnownCapabilityBlockedHydrationPlanProof & MpcBlockedCapabilityHydrationPlanFields);

export type MpcCapabilityHydrationPlan =
  | MpcUseLiveRuntimeHydrationPlan
  | MpcRehydrateMaterialActivationHydrationPlan
  | MpcReauthorizePublicAnchorHydrationPlan
  | MpcBlockedCapabilityHydrationPlan;

export function buildMpcCapabilityPublicReauthAnchor(
  fields: MpcCapabilityPublicReauthAnchorFields,
): MpcCapabilityPublicReauthAnchor {
  return new MpcCapabilityPublicReauthAnchorProof(fields);
}

export function buildUseLiveRuntimeHydrationPlan(
  fields: MpcUseLiveRuntimeHydrationPlanInput,
): MpcUseLiveRuntimeHydrationPlan {
  return new MpcUseLiveRuntimeHydrationPlanProof(fields);
}

export function buildRehydrateMaterialActivationHydrationPlan(
  fields: MpcRehydrateMaterialActivationHydrationPlanInput,
): MpcRehydrateMaterialActivationHydrationPlan {
  return new MpcRehydrateMaterialActivationHydrationPlanProof(fields);
}

export function buildReauthorizePublicAnchorHydrationPlan(
  fields: MpcReauthorizePublicAnchorHydrationPlanInput,
): MpcReauthorizePublicAnchorHydrationPlan {
  return new MpcReauthorizePublicAnchorHydrationPlanProof(fields);
}

export function buildBlockedMpcCapabilityHydrationPlan(
  fields: MpcMissingCapabilityHydrationPlanFields | MpcKnownCapabilityBlockedHydrationPlanFields,
): MpcBlockedCapabilityHydrationPlan {
  if (fields.reason === 'missing_capability') {
    return new MpcMissingCapabilityHydrationPlanProof();
  }
  return new MpcKnownCapabilityBlockedHydrationPlanProof(fields);
}
