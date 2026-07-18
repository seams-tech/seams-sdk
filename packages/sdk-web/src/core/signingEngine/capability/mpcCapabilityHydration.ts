import type { DomainId } from '@shared/utils/domainIds';

const hydrationPlanBrand: unique symbol = Symbol('mpc-capability-hydration-plan');
const publicReauthAnchorBrand: unique symbol = Symbol('mpc-capability-public-reauth-anchor');

export type CapabilityInstanceRef = DomainId<'CapabilityInstanceRef'>;
export type MpcMaterialOwnerRef = DomainId<'MpcMaterialOwnerRef'>;
export type WalletAuthAuthorityRef = DomainId<'WalletAuthAuthorityRef'>;
export type MpcCapabilityRuntimeRef = DomainId<'MpcCapabilityRuntimeRef'>;
export type ActiveMpcMaterialSessionRef = DomainId<'ActiveMpcMaterialSessionRef'>;
export type RestorableMpcMaterialRef = DomainId<'RestorableMpcMaterialRef'>;
export type MpcKeyBindingRef = DomainId<'MpcKeyBindingRef'>;
export type MpcLifecycleBindingRef = DomainId<'MpcLifecycleBindingRef'>;
export type MpcPolicyBindingRef = DomainId<'MpcPolicyBindingRef'>;
export type MpcRegisteredPublicKeyBindingRef = DomainId<'MpcRegisteredPublicKeyBindingRef'>;

function parseMpcDomainRef<T extends string>(
  value: unknown,
  label: string,
): DomainId<T> {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized as DomainId<T>;
}

export function capabilityInstanceRef(value: unknown): CapabilityInstanceRef {
  return parseMpcDomainRef<'CapabilityInstanceRef'>(value, 'capability instance ref');
}

export function mpcMaterialOwnerRef(value: unknown): MpcMaterialOwnerRef {
  return parseMpcDomainRef<'MpcMaterialOwnerRef'>(value, 'MPC material owner ref');
}

export function walletAuthAuthorityRef(value: unknown): WalletAuthAuthorityRef {
  return parseMpcDomainRef<'WalletAuthAuthorityRef'>(value, 'wallet auth authority ref');
}

export function mpcCapabilityRuntimeRef(value: unknown): MpcCapabilityRuntimeRef {
  return parseMpcDomainRef<'MpcCapabilityRuntimeRef'>(value, 'MPC capability runtime ref');
}

export function activeMpcMaterialSessionRef(value: unknown): ActiveMpcMaterialSessionRef {
  return parseMpcDomainRef<'ActiveMpcMaterialSessionRef'>(
    value,
    'active MPC material session ref',
  );
}

export function restorableMpcMaterialRef(value: unknown): RestorableMpcMaterialRef {
  return parseMpcDomainRef<'RestorableMpcMaterialRef'>(
    value,
    'restorable MPC material ref',
  );
}

export function mpcKeyBindingRef(value: unknown): MpcKeyBindingRef {
  return parseMpcDomainRef<'MpcKeyBindingRef'>(value, 'MPC key binding ref');
}

export function mpcLifecycleBindingRef(value: unknown): MpcLifecycleBindingRef {
  return parseMpcDomainRef<'MpcLifecycleBindingRef'>(
    value,
    'MPC lifecycle binding ref',
  );
}

export function mpcPolicyBindingRef(value: unknown): MpcPolicyBindingRef {
  return parseMpcDomainRef<'MpcPolicyBindingRef'>(value, 'MPC policy binding ref');
}

export function mpcRegisteredPublicKeyBindingRef(
  value: unknown,
): MpcRegisteredPublicKeyBindingRef {
  return parseMpcDomainRef<'MpcRegisteredPublicKeyBindingRef'>(
    value,
    'MPC registered public-key binding ref',
  );
}

export type MpcCapabilityHydrationEntryPoint =
  | 'post_registration'
  | 'post_wallet_unlock'
  | 'post_page_refresh';

export type MpcCapabilityRetirement = 'expired' | 'exhausted';

export type MpcCapabilityHydrationBlockedReason =
  | 'missing_capability'
  | 'missing_material'
  | 'revoked'
  | 'ambiguous_authority'
  | 'binding_mismatch'
  | 'corrupt_persistence'
  | 'persistence_unavailable';

export type MpcCapabilityPublicReauthAnchor = {
  readonly [publicReauthAnchorBrand]: true;
  readonly kind: 'mpc_capability_public_reauth_anchor_v1';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly policyBinding: MpcPolicyBindingRef;
  readonly registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;
  readonly secretMaterial?: never;
  readonly sealedMaterial?: never;
  readonly bearerSessionCredential?: never;
  readonly runtime?: never;
  readonly activeMaterialSession?: never;
  readonly operationGrant?: never;
  readonly quotaState?: never;
  readonly nonceState?: never;
};

export type UseLiveMpcCapabilityRuntimePlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'use_live_runtime';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly runtime: MpcCapabilityRuntimeRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
  readonly sealedMaterial?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

export type RehydrateActiveMpcMaterialSessionPlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'rehydrate_active_session';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
  readonly sealedMaterial: RestorableMpcMaterialRef;
  readonly runtime?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

export type ReauthorizeMpcCapabilityPublicAnchorPlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'reauthorize_public_anchor';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly retirement: MpcCapabilityRetirement;
  readonly publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
  readonly runtime?: never;
  readonly activeMaterialSession?: never;
  readonly sealedMaterial?: never;
};

export type BlockedMpcCapabilityHydrationPlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'blocked';
  readonly capability: CapabilityInstanceRef | null;
  readonly reason: MpcCapabilityHydrationBlockedReason;
  readonly materialOwner?: never;
  readonly authority?: never;
  readonly runtime?: never;
  readonly activeMaterialSession?: never;
  readonly sealedMaterial?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

export type MpcCapabilityHydrationPlan =
  | UseLiveMpcCapabilityRuntimePlan
  | RehydrateActiveMpcMaterialSessionPlan
  | ReauthorizeMpcCapabilityPublicAnchorPlan
  | BlockedMpcCapabilityHydrationPlan;

export type MpcCapabilityHydrationResolution = {
  readonly provenance: {
    readonly entryPoint: MpcCapabilityHydrationEntryPoint;
  };
  readonly plan: MpcCapabilityHydrationPlan;
};

export function buildMpcCapabilityPublicReauthAnchor(input: {
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly policyBinding: MpcPolicyBindingRef;
  readonly registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;
}): MpcCapabilityPublicReauthAnchor {
  return {
    [publicReauthAnchorBrand]: true,
    kind: 'mpc_capability_public_reauth_anchor_v1',
    capability: input.capability,
    materialOwner: input.materialOwner,
    authority: input.authority,
    keyBinding: input.keyBinding,
    lifecycleBinding: input.lifecycleBinding,
    policyBinding: input.policyBinding,
    registeredPublicKeyBinding: input.registeredPublicKeyBinding,
  };
}

export function buildUseLiveMpcCapabilityRuntimePlan(input: {
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly runtime: MpcCapabilityRuntimeRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
}): UseLiveMpcCapabilityRuntimePlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'use_live_runtime',
    capability: input.capability,
    materialOwner: input.materialOwner,
    authority: input.authority,
    runtime: input.runtime,
    activeMaterialSession: input.activeMaterialSession,
  };
}

export function buildRehydrateActiveMpcMaterialSessionPlan(input: {
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
  readonly sealedMaterial: RestorableMpcMaterialRef;
}): RehydrateActiveMpcMaterialSessionPlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'rehydrate_active_session',
    capability: input.capability,
    materialOwner: input.materialOwner,
    authority: input.authority,
    activeMaterialSession: input.activeMaterialSession,
    sealedMaterial: input.sealedMaterial,
  };
}

export function buildReauthorizeMpcCapabilityPublicAnchorPlan(input: {
  readonly retirement: MpcCapabilityRetirement;
  readonly publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
}): ReauthorizeMpcCapabilityPublicAnchorPlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'reauthorize_public_anchor',
    capability: input.publicReauthAnchor.capability,
    materialOwner: input.publicReauthAnchor.materialOwner,
    authority: input.publicReauthAnchor.authority,
    retirement: input.retirement,
    publicReauthAnchor: input.publicReauthAnchor,
  };
}

export function buildBlockedMpcCapabilityHydrationPlan(input: {
  readonly capability: CapabilityInstanceRef | null;
  readonly reason: MpcCapabilityHydrationBlockedReason;
}): BlockedMpcCapabilityHydrationPlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'blocked',
    capability: input.capability,
    reason: input.reason,
  };
}

export function buildMpcCapabilityHydrationResolution(input: {
  readonly entryPoint: MpcCapabilityHydrationEntryPoint;
  readonly plan: MpcCapabilityHydrationPlan;
}): MpcCapabilityHydrationResolution {
  return {
    provenance: { entryPoint: input.entryPoint },
    plan: input.plan,
  };
}
